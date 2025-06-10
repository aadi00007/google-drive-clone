const express = require('express');
const app = express();
const userRouter = require('./routes/user.routes');
const dotenv = require('dotenv');
const connectToDB = require('./config/db');

// Load environment variables first
dotenv.config();

// Connect to database
connectToDB();

// Add this debugging
const mongoose = require('mongoose');
mongoose.connection.on('connected', () => {
    console.log('✅ MongoDB connected successfully');
});

mongoose.connection.on('error', (err) => {
    console.error('❌ MongoDB connection error:', err);
});

mongoose.connection.on('disconnected', () => {
    console.log('❌ MongoDB disconnected');
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use('/user', userRouter);

app.set('view engine', 'ejs');
app.listen(3000, () => {
    console.log('server is running on port 3000');
});