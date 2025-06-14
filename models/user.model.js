const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    trim: true,
  },
  email: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true,
  },
  password: {
    type: String,
    required: true,
  },
  dailyUploadCount: {
    type: Number,
    default: 0,
  },
  dailyUploadSize: {
    type: Number,
    default: 0,
  },
  totalStorageUsed: {
    type: Number,
    default: 0,
  },
  lastUploadDate: {
    type: Date,
  },
});

module.exports = mongoose.model('User', userSchema);