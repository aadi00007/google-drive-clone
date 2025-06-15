const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const User = require('../models/user.model');
const File = require('../models/file.model');
const cloudinary = require('cloudinary').v2;
const multer = require('multer');
const fs = require('fs').promises;
const os = require('os'); // Add this to use os.tmpdir()

console.log('File model:', File);
console.log('File.find is a function:', typeof File.find === 'function');

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    console.log('Saving file to temp directory:', os.tmpdir());
    cb(null, os.tmpdir()); // Use system temp directory
  },
  filename: (req, file, cb) => {
    const filename = `${Date.now()}-${file.originalname}`;
    console.log('Generated filename:', filename);
    cb(null, filename);
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
    User.findById(decoded.userID).then(user => {
      if (!user) return res.redirect('/user/login');
      next();
    });
  } catch (error) {
    res.clearCookie('token');
    res.redirect('/user/login');
  }
};

// Other routes (register, login, etc.) remain unchanged

router.post('/upload', verifyToken, upload.single('file'), async (req, res) => {
  try {
    console.log('Received file upload request for user:', req.user.username);
    const file = req.file;
    if (!file) {
      console.log('No file uploaded');
      if (req.xhr || req.headers.accept.includes('json')) {
        return res.status(400).send('No file uploaded');
      }
      return res.redirect('/user/home?message=No file uploaded');
    }

    console.log('File received:', file.originalname, 'Size:', file.size, 'Path:', file.path);

    const user = await User.findById(req.user.userID);
    if (!user) {
      console.log('User not found for ID:', req.user.userID);
      if (file) await fs.unlink(file.path).catch(() => {});
      throw new Error('User not found');
    }

    const today = new Date().setHours(0, 0, 0, 0);
    const lastUploadDate = user.lastUploadDate ? new Date(user.lastUploadDate).setHours(0, 0, 0, 0) : null;
    if (!lastUploadDate || today > lastUploadDate) {
      user.dailyUploadCount = 0;
      user.dailyUploadSize = 0;
      user.lastUploadDate = new Date();
    }

    const DAILY_FILE_LIMIT = 5;
    const DAILY_SIZE_LIMIT = 50 * 1024 * 1024; // 50MB
    console.log('Checking daily limits - Files:', user.dailyUploadCount, 'Size:', user.dailyUploadSize);
    if (user.dailyUploadCount >= DAILY_FILE_LIMIT) {
      if (file) await fs.unlink(file.path).catch(() => {});
      throw new Error('Daily upload limit reached (5 files per day)');
    }
    if (user.dailyUploadSize + file.size > DAILY_SIZE_LIMIT) {
      if (file) await fs.unlink(file.path).catch(() => {});
      throw new Error('Daily upload size limit reached (50MB per day)');
    }

    const TOTAL_STORAGE_LIMIT = 100 * 1024 * 1024; // 100MB
    console.log('Checking total storage - Used:', user.totalStorageUsed, 'File size:', file.size);
    if (user.totalStorageUsed + file.size > TOTAL_STORAGE_LIMIT) {
      if (file) await fs.unlink(file.path).catch(() => {});
      throw new Error('Total storage limit reached (100MB per user)');
    }

    const forbiddenKeywords = ['porn', 'illegal', 'explicit', 'hack', 'virus'];
    const fileNameLower = file.originalname.toLowerCase();
    if (forbiddenKeywords.some(keyword => fileNameLower.includes(keyword))) {
      await fs.unlink(file.path).catch(() => {});
      throw new Error('File name contains inappropriate content');
    }

    const existingFile = await File.findOne({
      name: file.originalname,
      userId: req.user.userID,
    });
    if (existingFile) {
      await fs.unlink(file.path).catch(() => {});
      if (req.xhr || req.headers.accept.includes('json')) {
        return res.status(400).send('File already exists');
      }
      return res.redirect('/user/home?message=File already exists');
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

    user.dailyUploadCount += 1;
    user.dailyUploadSize += file.size;
    user.totalStorageUsed += file.size;
    user.lastUploadDate = new Date();
    await user.save();

    await fs.unlink(file.path);

    if (req.xhr || req.headers.accept.includes('json')) {
      return res.status(200).send('File uploaded successfully!');
    }

    res.redirect('/user/home?message=File uploaded successfully!');
  } catch (error) {
    console.error('Upload error:', error.message);
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

// Other routes remain unchanged

module.exports = router;
