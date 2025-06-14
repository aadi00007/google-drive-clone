const express = require('express');
const mongoose = require('mongoose');
const cookieParser = require('cookie-parser');
const path = require('path');
const cloudinary = require('cloudinary').v2;
require('dotenv').config();

const app = express();

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// Set EJS as the view engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Log environment variables (mask sensitive info)
console.log('Environment Variables Loaded:');
console.log('MONGODB_URI:', process.env.MONGODB_URI ? '[Sensitive - Masked]' : 'Not Set');
console.log('CLOUDINARY_CLOUD_NAME:', process.env.CLOUDINARY_CLOUD_NAME);
console.log('CLOUDINARY_API_KEY:', process.env.CLOUDINARY_API_KEY ? '[Sensitive - Masked]' : 'Not Set');
console.log('CLOUDINARY_API_SECRET:', process.env.CLOUDINARY_API_SECRET ? '[Sensitive - Masked]' : 'Not Set');
console.log('JWT_SECRET:', process.env.JWT_SECRET ? '[Sensitive - Masked]' : 'Not Set');
console.log('PORT:', process.env.PORT);
console.log('NODE_ENV:', process.env.NODE_ENV);

// MongoDB Connection
mongoose
  .connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => {
    console.log('✅ MongoDB connected successfully');
    // Load models after connection
    const User = require('./models/user.model');
    const File = require('./models/file.model');
    console.log('Models loaded after MongoDB connection:');
    console.log('User model:', User);
    console.log('File model:', File);
  })
  .catch((err) => console.log('❌ MongoDB connection error:', err));

// Cloudinary Configuration
try {
  cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET,
  });
  console.log('✅ Cloudinary configured successfully');
} catch (error) {
  console.log('❌ Cloudinary configuration error:', error.message);
}

// Routes
const userRoutes = require('./routes/user.routes');
app.use('/user', userRoutes);

// Default Route
app.get('/', (req, res) => {
  res.redirect('/user/login');
});

// Error Handling Middleware
app.use((err, req, res, next) => {
  console.error('Server Error:', err.stack);
  res.status(500).render('error', { message: 'Something went wrong!' });
});

// Start Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});