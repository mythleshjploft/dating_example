const mongoose = require('mongoose');
const MetaData = require('./MetaData');
const crypto = require('../lib/crypto');
const Schema = mongoose.Schema;
ObjectId = Schema.ObjectId;

const UserModelSchema = new Schema({
    firstName: String,
    lastName: String,
    local: {
        email: {
            type: String,
            lowercase: true
        },
        password: {
            type: String,
            set: crypto.hash
        },
    },
    gender: {
        type: String,
        enum: ['Male', 'Female', 'Other']
    },
    status: {
        type: String,
        enum: ['Active', 'Inactive', 'Deleted', 'Deactive'],
        default: 'Active'
    },
    metaData: MetaData.schema,
    loginHistory: [{
        lastLogin: Date,
        os: String,
        browser: String,
        token: String,
        status: Boolean
    }],
    lastLogin: Date,
    os: String,
    browser: String,
    phoneNo: String,
    resetPassStatus: Boolean,
    resetPassExpire: Date,
});

// checking if password is valid
UserModelSchema.methods.isPasswordValid = function (password) {
    return crypto.checkHash(password, this.local.password);
};

/**
* Updates the users lastLogin field to current date
*/
UserModelSchema.statics.updateLastLogin = function updateLastLogin(userId, browser, os) {
    return this.findById(userId).exec().then((user) => {
        user.lastLogin = new Date();
        user.os = os;
        user.browser = browser;
        user.loginHistory.push({
            lastLogin: new Date(),
            os: os,
            browser: browser,
            status: true
        })
        return user.save().then((savedUser) => {
            return ({ sessionId: savedUser.loginHistory.pop()._id });
        });
    })
};

// ADD USER
UserModelSchema.statics.addUserData = async function (data, res) {
    const User = mongoose.model('User', UserModelSchema);
    const newUser = new User();
    newUser.metaData = new MetaData();
    // newSlider.metaData.createdBy = data.userId;
    newUser.metaData.createdAt = Date();

    newUser.firstName = data.firstName;
    newUser.lastName = data.lastName;
    newUser.local.email = data.email;
    data.password ? newUser.local.password = data.password : newUser.local.password = '';
    newUser.gender = data.gender;

    return newUser.save().then((savedUser) => {
        return ({ user: savedUser });
    }).catch(function (err) {
        return res.send({ status: 'error', message: err.message });
    });
}

module.exports = mongoose.model("User", UserModelSchema);