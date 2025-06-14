const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const User = require('../models/user.model');
const File = require('../models/file.model');
const cloudinary = require('cloudinary').v2;
const multer = require('multer');
const fs = require('fs').promises;

// Debug: Log the File model to verify it's a Mongoose model
console.log('File model:', File);
console.log('File.find is a function:', typeof File.find === 'function');

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    cb(null, `${Date.now()}-${file.originalname}`);
  },
});

const fileFilter = (req, file, cb) => {
  const allowedTypes = [
    'image/jpeg',
    'image/png',
    'image/gif',
    'application/pdf',
    'video/mp4',
    'video/webm',
  ];
  if (allowedTypes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error('Invalid file type. Allowed types: JPEG, PNG, GIF, PDF, MP4, WebM'), false);
  }
};

const upload = multer({
  storage,
  fileFilter,
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB limit
});

const verifyToken = (req, res, next) => {
  const token = req.cookies.token;
  if (!token) return res.redirect('/user/login');
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    res.clearCookie('token');
    res.redirect('/user/login');
  }
};

router.get('/register', (req, res) => {
  res.render('register', { message: null });
});

router.post('/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.render('register', { message: 'User already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ username, email, password: hashedPassword });
    await user.save();

    res.redirect('/user/login');
  } catch (error) {
    res.render('register', { message: 'Registration failed: ' + error.message });
  }
});

router.get('/login', (req, res) => {
  res.render('login', { message: null });
});

router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) {
      return res.render('login', { message: 'User not found' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.render('login', { message: 'Invalid password' });
    }

    const token = jwt.sign(
      { userID: user._id, email: user.email, username: user.username },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.cookie('token', token, { httpOnly: true });
    console.log(`User logged in: ${user.username} ID: ${user._id}`);

    res.redirect('/user/home');
  } catch (error) {
    res.render('login', { message: 'Login failed: ' + error.message });
  }
});

router.get('/home', verifyToken, async (req, res) => {
  try {
    const files = await File.find({ userId: req.user.userID });
    res.render('home', { user: req.user, files, message: null });
  } catch (error) {
    console.error('Error in /home route:', error.message);
    res.render('error', { message: `Something went wrong! Details: ${error.message}` });
  }
});

router.post('/upload', verifyToken, upload.single('file'), async (req, res) => {
  try {
    const file = req.file;
    if (!file) {
      return res.status(400).send('No file uploaded');
    }

    // Check for existing file with the same name and userId
    const existingFile = await File.findOne({
      name: file.originalname,
      userId: req.user.userID,
    });
    if (existingFile) {
      await fs.unlink(file.path).catch(() => {});
      return res.status(400).send('File already exists');
    }

    console.log('Attempting to upload file to Cloudinary:', file.path);
    const result = await cloudinary.uploader.upload(file.path, {
      folder: 'drive-clone',
      resource_type: 'auto',
    });
    console.log('File uploaded to Cloudinary:', result.secure_url);

    const newFile = new File({
      name: file.originalname,
      url: result.secure_url,
      size: file.size,
      userId: req.user.userID,
      uploadedAt: new Date(),
    });

    await newFile.save();
    console.log('File metadata saved to MongoDB for user:', req.user.username);

    await fs.unlink(file.path);

    // For AJAX requests (fetch), return a success response
    if (req.xhr || req.headers.accept.includes('json')) {
      return res.status(200).send('File uploaded successfully!');
    }

    // For regular form submissions, redirect with a message
    res.redirect('/user/home?message=File uploaded successfully!');
  } catch (error) {
    console.error('Upload error:', error);
    let message = error.message;
    if (error.code === 'LIMIT_FILE_SIZE') {
      message = 'File size exceeds 10MB limit';
    }
    if (file) await fs.unlink(file.path).catch(() => {});
    
    if (req.xhr || req.headers.accept.includes('json')) {
      return res.status(500).send(message);
    }

    res.redirect(`/user/home?message=Upload failed: ${message}`);
  }
});

router.post('/delete-file/:id', verifyToken, async (req, res) => {
  try {
    console.log('Delete route hit for file ID:', req.params.id);
    const fileId = req.params.id;
    const userId = req.user.userID;

    const file = await File.findOne({ _id: fileId, userId });
    if (!file) {
      console.log('File not found for ID:', fileId);
      return res.redirect('/user/home?message=File not found');
    }

    console.log('File found:', file.name, 'URL:', file.url);
    const urlParts = file.url.split('/');
    const fileName = urlParts[urlParts.length - 1].split('.')[0];
    const publicId = `drive-clone/${fileName}`;
    console.log('Attempting to delete from Cloudinary, publicId:', publicId);

    await cloudinary.uploader.destroy(publicId);
    console.log('File deleted from Cloudinary');

    await File.deleteOne({ _id: fileId });
    console.log('File deleted from MongoDB');

    res.redirect('/user/home?message=File deleted successfully!');
  } catch (error) {
    console.error('Delete error:', error.message);
    res.redirect(`/user/home?message=Delete failed: ${error.message}`);
  }
});

router.get('/logout', (req, res) => {
  res.clearCookie('token');
  res.redirect('/user/login');
});

module.exports = router;