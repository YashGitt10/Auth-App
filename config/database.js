
const mongoose = require('mongoose');

require("dotenv").config();


exports.connect = () => {
    mongoose.connect(process.env.MONGODB_URL)
    .then(() => {
        console.log("Connection Successful");
    })
    .catch((error) => {
        console.log("ERRORS", error);
        process.exit(1);
    });
}

