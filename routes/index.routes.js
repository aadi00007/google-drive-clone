const express = require('express');
const router = express.Router();
const userModel = require('../models/user.model');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const multer = require('multer');
const cloudinary = require('cloudinary').v2;
const fs = require('fs').promises;
const path = require('path');

// Configure multer with file size limit (10MB) and temporary storage
const upload = multer({
  dest: 'uploads/',
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB limit
});

// Middleware to verify JWT token
const verifyToken = (req, res, next) => {
  const token = req.cookies.token;
  if (!token) {
    return res.status(401).json({ message: 'Authentication required' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    console.error('Token verification error:', error);
    res.clearCookie('token');
    return res.status(401).json({ message: 'Invalid or expired token' });
  }
};

// File upload route
router.post('/upload-file', verifyToken, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).render('home', {
        message: 'No file selected',
        user: req.user,
        files: [],
      });
    }

    // Upload to Cloudinary
    const result = await cloudinary.uploader.upload(req.file.path, {
      folder: `drive-clone/${req.user.userID}`,
      resource_type: 'auto',
    });

    // Clean up temporary file
    await fs.unlink(req.file.path).catch((err) => console.error('Error deleting temp file:', err));

    // Store file metadata in database
    const updatedUser = await userModel.findByIdAndUpdate(
      req.user.userID,
      {
        $push: {
          files: {
            name: req.file.originalname,
            url: result.secure_url,
            size: req.file.size,
            public_id: result.public_id,
            uploadedAt: new Date(),
          },
        },
      },
      { new: true }
    );

    // Fetch updated file list
    const files = updatedUser.files || [];

    res.render('home', {
      message: 'File uploaded successfully!',
      user: req.user,
      files,
    });
  } catch (error) {
    console.error('Upload error:', error);
    // Clean up temporary file in case of error
    if (req.file) {
      await fs.unlink(req.file.path).catch((err) => console.error('Error deleting temp file:', err));
    }

    res.status(500).render('home', {
      message: `Upload failed: ${error.message}`,
      user: req.user,
      files: [],
    });
  }
});

// Home route with file list
router.get('/home', verifyToken, async (req, res) => {
  try {
    const user = await userModel.findById(req.user.userID).select('files username email');
    res.render('home', {
      message: null,
      user: req.user,
      files: user.files || [],
    });
  } catch (error) {
    console.error('Home route error:', error);
    res.status(500).render('home', {
      message: 'Failed to load files',
      user: req.user,
      files: [],
    });
  }
});

// Register route
router.get('/register', (req, res) => {
  res.render('register', {
    message: null,
    errors: [],
    success: req.query.success === 'true',
  });
});

router.post(
  '/register',
  [
    body('email').trim().isEmail().normalizeEmail().withMessage('Invalid email address'),
    body('password').trim().isLength({ min: 5 }).withMessage('Password must be at least 5 characters'),
    body('username')
      .trim()
      .isLength({ min: 3 })
      .matches(/^[a-zA-Z0-9_]+$/)
      .withMessage('Username must be at least 3 characters and contain only letters, numbers, or underscores'),
  ],
  async (req, res) => {
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
      return res.status(400).render('register', {
        errors: errors.array(),
        message: 'Please fix the validation errors',
        success: false,
      });
    }

    try {
      const { email, username, password } = req.body;

      // Check if user already exists
      const existingUser = await userModel.findOne({
        $or: [{ email }, { username }],
      });

      if (existingUser) {
        return res.status(400).render('register', {
          message: 'Username or email already exists',
          errors: [],
          success: false,
        });
      }

      // Hash password
      const hashedPassword = await bcrypt.hash(password, 10);

      const newUser = await userModel.create({
        email,
        username,
        password: hashedPassword,
        files: [], // Initialize files array
      });

      console.log('User created successfully:', newUser.username);
      res.redirect('/user/register?success=true');
    } catch (error) {
      console.error('Registration error:', error);
      res.status(500).render('register', {
        message: 'Registration failed. Please try again.',
        errors: [],
        success: false,
      });
    }
  }
);

// Login route
router.get('/login', (req, res) => {
  res.render('login', {
    message: null,
    errors: [],
    success: false,
  });
});

router.post(
  '/login',
  [
    body('username').trim().isLength({ min: 3 }).withMessage('Username must be at least 3 characters'),
    body('password').trim().isLength({ min: 5 }).withMessage('Password must be at least 5 characters'),
  ],
  async (req, res) => {
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
      return res.status(400).render('login', {
        errors: errors.array(),
        message: 'Please enter valid credentials',
        success: false,
      });
    }

    try {
      const { username, password } = req.body;

      const user = await userModel.findOne({ username });
      if (!user) {
        return res.status(400).render('login', {
          message: 'Invalid username or password',
          errors: [],
          success: false,
        });
      }

      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        return res.status(400).render('login', {
          message: 'Invalid username or password',
          errors: [],
          success: false,
        });
      }

      const token = jwt.sign(
        {
          userID: user._id,
          email: user.email,
          username: user.username,
        },
        process.env.JWT_SECRET,
        { expiresIn: '24h' }
      );

      res.cookie('token', token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'Strict', // Add CSRF protection
        maxAge: 24 * 60 * 60 * 1000, // 24 hours
      });

      res.redirect('/user/home');
    } catch (error) {
      console.error('Login error:', error);
      return res.status(500).render('login', {
        message: 'Login failed. Please try again.',
        errors: [],
        success: false,
      });
    }
  }
);

// Logout route
router.get('/logout', (req, res) => {
  res.clearCookie('token');
  res.redirect('/user/login');
});

// Dashboard route
router.get('/dashboard', verifyToken, (req, res) => {
  res.send(`Welcome to the dashboard, ${req.user.username}! You are logged in.`);
});

module.exports = router;