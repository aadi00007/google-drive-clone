const mongoose = require('mongoose');

function connectToDB() {
    mongoose.connect(process.env.MONGO_URI, {});
}

module.exports = connectToDB;