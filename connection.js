const mongoose = require("mongoose");
const dotenv = require('dotenv');
dotenv.config();

const mongoDB = process.env.MONGOURL;

// const mongoDB = "mongodb://localhost:27017/my_database";

mongoose.connect(mongoDB);

mongoose.connection.on('connected', () => {

    console.log('Mongo has connected successfully');
});

mongoose.connection.on('reconnected', () => {
    console.log('Mongo has reconnected');

});
mongoose.connection.on('error', error => {
    console.log('Mongo connection has an error', error);

    mongoose.disconnect();
});