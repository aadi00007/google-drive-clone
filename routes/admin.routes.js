const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const User = require('../models/user.model');
const File = require('../models/file.model');
const cloudinary = require('cloudinary').v2;

// Ensure the admin user exists on server startup
const setupAdminUser = async () => {
  try {
    const adminUser = await User.findOne({ username: 'aditya0007' });
    if (!adminUser) {
      const hashedPassword = await bcrypt.hash('Hello@aadi007', 10);
      const newAdmin = new User({
        username: 'aditya0007',
        email: 'aditya0007@example.com',
        password: hashedPassword,
      });
      await newAdmin.save();
      console.log('Admin user created: aditya0007');
    } else {
      // Update the password to ensure it matches
      const hashedPassword = await bcrypt.hash('Hello@aadi007', 10);
      await User.updateOne(
        { username: 'aditya0007' },
        { $set: { password: hashedPassword } }
      );
      console.log('Admin user password updated: aditya0007');
    }
  } catch (error) {
    console.error('Error setting up admin user:', error.message);
  }
};
setupAdminUser();

const verifyAdmin = (req, res, next) => {
  const adminToken = req.cookies.adminToken;
  if (!adminToken) return res.redirect('/admin/login');
  try {
    const decoded = jwt.verify(adminToken, process.env.JWT_SECRET);
    if (decoded.username !== 'aditya0007') {
      res.clearCookie('adminToken');
      return res.redirect('/admin/login');
    }
    req.admin = decoded;
    next();
  } catch (error) {
    res.clearCookie('adminToken');
    res.redirect('/admin/login');
  }
};

router.get('/login', (req, res) => {
  res.render('admin-login', { message: null });
});

router.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user) {
      return res.render('admin-login', { message: 'Admin not found' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch || username !== 'aditya0007' || password !== 'Hello@aadi007') {
      return res.render('admin-login', { message: 'Invalid admin credentials' });
    }

    const adminToken = jwt.sign(
      { username: user.username },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.cookie('adminToken', adminToken, { httpOnly: true });
    console.log(`Admin logged in: ${user.username}`);

    res.redirect('/admin/files');
  } catch (error) {
    res.render('admin-login', { message: 'Admin login failed: ' + error.message });
  }
});

router.get('/files', verifyAdmin, async (req, res) => {
  try {
    const files = await File.find().populate('userId', 'username');
    res.render('admin-files', { user: req.admin, files, message: req.query.message || null });
  } catch (error) {
    console.error('Error in /admin/files route:', error.message);
    res.render('error', { message: `Something went wrong! Details: ${error.message}` });
  }
});

router.post('/delete-file/:id', verifyAdmin, async (req, res) => {
  try {
    console.log('Admin delete route hit for file ID:', req.params.id);
    const fileId = req.params.id;

    const file = await File.findById(fileId);
    if (!file) {
      console.log('File not found for ID:', fileId);
      return res.redirect('/admin/files?message=File not found');
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

    const fileOwner = await User.findById(file.userId);
    if (fileOwner) {
      fileOwner.totalStorageUsed = Math.max(0, fileOwner.totalStorageUsed - file.size);
      await fileOwner.save();
    }

    res.redirect('/admin/files?message=File deleted successfully!');
  } catch (error) {
    console.error('Admin delete error:', error.message);
    res.redirect(`/admin/files?message=Delete failed: ${error.message}`);
  }
});

router.get('/logout', (req, res) => {
  res.clearCookie('adminToken');
  res.redirect('/admin/login');
});

module.exports = router;