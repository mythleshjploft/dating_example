const UserModel = require('../models/User');
const auth = require('../lib/auth');
const mongoose = require('mongoose');
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const { promisify } = require("util");
const unlinkAsync = promisify(fs.unlink);

const jwt = require("jsonwebtoken");
const passport = require("passport");
const { authenticator } = require("otplib");
var config = require('../config');
const useragent = require('useragent');
const { createTransport } = require('nodemailer');
const dotenv = require('dotenv');
// const axios = require('axios');

dotenv.config();
const otpAttempts = new Map();
const enable2FAOtpAttempts = new Map();
const usedOTPs = new Set();

// Login
module.exports.login = auth.authenticate.localLogin;

module.exports.loginStep2 = async (req, res) => {
    const ip = req.ip; // Get the IP address from the request
    const userLimitLoginId = 1;
    // Check if the IP address has exceeded the limit
    if ((otpAttempts.has(userLimitLoginId) && otpAttempts.get(userLimitLoginId).count >= 3) || (otpAttempts.has(ip) && otpAttempts.get(ip).count >= 3)) {
        return res.status(400).json({ status: "error", message: 'Too many requests, please try again after 10 minutes.' });
    }

    // If not exceeded, update the attempt count or initialize a new entry
    if (otpAttempts.has(ip)) {
        otpAttempts.get(ip).count += 1;
    } else {
        otpAttempts.set(ip, { count: 1 });
    }

    // Set a timeout to reset the attempt count after 1 minute
    setTimeout(() => {
        otpAttempts.delete(ip);
    }, 10 * 60 * 1000); // 10 minutes timeout

    let loginStep2VerificationToken = null;
    try {
        loginStep2VerificationToken = jwt.verify(
            req.body.loginStep2VerificationToken,
            config.jwtSecret
        );
    } catch (err) {
        return res.status(401).json({
            message: "You are not authorized to perform login step-2",
        });
    }

    const token = req.body.twofaToken;
    const user = await UserModel.findOne({
        "local.email": loginStep2VerificationToken.loginStep2Verification.email,
    });

    if (usedOTPs.has(token)) {
        return res.status(400).json({
            message: "OTP is invalid or has already been used!",
        });
    }

    if (!authenticator.check(token, user.twofaSecret)) {
        return res.status(400).json({
            message: "OTP verification failed: Invalid token",
        });
    } else {
        usedOTPs.add(token);
        const userAgentString = req.headers['user-agent'];
        const agent = useragent.parse(userAgentString);

        const browser = agent.family; // Browser name
        const version = agent.toVersion(); // Browser version
        const os = agent.os.family + ' ' + agent.toVersion(); // Operating system

        const filter = { _id: user._id };
        // Check User Already login or not
        var isLogin = false;
        let loginStatus = await UserModel.findOne({
            _id: user._id,
            loginHistory: { $elemMatch: { status: true } }
        });
        if (loginStatus) {
            isLogin = true;
        } else {
            isLogin = false;
        }
        // Logout if already user login
        let doc = await UserModel.updateMany(filter, { $set: { 'loginHistory.$[].status': false } });
        //Update the user last Login date
        const data = await UserModel.updateLastLogin(user._id, browser, os);
        if (loginStep2VerificationToken.loginStep2Verification.rememberme == 'true') {
            var expirationTime = '7d'; // 7 day
        } else {
            var expirationTime = '1d'; // 1 day
        }

        var payload = {
            id: user._id,
            permission: user.userType,
            status: user.status,
            sessionId: data.sessionId
        };
        var tokenNew = jwt.sign(payload, config.jwtSecret, { expiresIn: expirationTime });

        var returnUserData = {
            local: {
                email: user.local.email,
            },
            _id: user._id,
            status: user.status,
            firstName: user.firstName,
            lastName: user.lastName,
            permission: user.userType,
            email: user.local.email,
            token: tokenNew,
            twofaEnabled: true,
            isLogin: isLogin,
            planStatus: planStatus
        }
        otpAttempts.delete(ip);
        otpAttempts.delete(userLimitLoginId);
        return res.send({ 'status': 'success', message: 'Login Successfully', user: returnUserData });
    }
};

// Add User
module.exports.addUser = async function (req, res) {
    try {
        const ip = req.ip; // Get the IP address from the request
        const userLimitNewId = 3;
        // Check if the IP address has exceeded the limit
        if ((loginAttempts.has(userLimitNewId) && loginAttempts.get(userLimitNewId).count >= 3) || (loginAttempts.has(ip) && loginAttempts.get(ip).count >= 3)) {
            return res.status(400).json({ status: "error", message: 'Too many requests, please try again after 10 minutes.' });
        }

        // If not exceeded, update the attempt count or initialize a new entry
        if (loginAttempts.has(ip)) {
            loginAttempts.get(ip).count += 1;
        } else {
            loginAttempts.set(ip, { count: 1 });
        }

        // Set a timeout to reset the attempt count after 1 minute
        setTimeout(() => {
            loginAttempts.delete(ip);
        }, 10 * 60 * 1000); // 10 minutes timeout

        if ((!req.body.firstName) || (!req.body.email) || (!req.body.password)) {
            console.log(req.body.firstName, req.body.email, req.body.password)
            return res.send({ status: 'error', message: "Mandatory fields missing." });
        }

        var firstName = req.body.firstName;
        var lastName = req.body.lastName;
        var email = req.body.email;
        var password = req.body.password;
        // const userResponseToken = req.body.hcaptchaResponseToken;
        const nameRegex = /^[A-Za-z\s]+$/;
        const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&.,-/])[A-Za-z\d@$!%*?&.,-/]{8,}$/;


        if (firstName.length > 50) {
            return res.send({ status: 'error', message: "First name must be limited to 50 characters!" });
        } else if (!nameRegex.test(firstName)) {
            return res.send({ status: 'error', message: "Invalid first name!" });
        }

        if (lastName != '') {
            if (lastName.length > 50) {
                return res.send({ status: 'error', message: "Last name must be limited to 50 characters!" });
            } else if (!nameRegex.test(lastName)) {
                return res.send({ status: 'error', message: "Invalid last name!" });
            }
        }

        if (!/^[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,4}$/i.test(email)) {
            return res.send({ status: 'error', message: "Invalid email address!" });
        } else if (email.length > 100) {
            return res.send({ status: 'error', message: "Email must be limited to 100 characters!" });
        }

        if (!passwordRegex.test(password)) {
            return res.send({ status: 'error', message: "Password must be at least 8 characters long with 1 uppercase, 1 lowercase, 1 special character, and 1 number!" });
        } else if (password.length > 64) {
            return res.send({ status: 'error', message: "Email must be limited to 64 characters!" });
        }

        var getData = await UserModel.findOne({ "local.email": req.body.email });
        if (getData) {
            return res.send({ status: 'error', message: "User Already exists." });
        }

        var userData = {};
        userData = req.body;
        const newUser = await UserModel.addUserData(userData, res);
        if (newUser) {
            const returnUserData = {
                _id: newUser.user._id,
            };
            loginAttempts.delete(ip);
            loginAttempts.delete(userLimitNewId);
            return res.send({ status: 'success', message: 'User Added Successfully', data: returnUserData });
        } else {
            return res.send({ status: 'error', message: "Unable To Add User" });
        }
    } catch (err) {
        return res.send({ status: 'error', message: 'Something went wrong' });
    }
}

// GET MEMBER LIST
module.exports.getMember = async (req, res) => {
    try {
        const pageNumber = parseInt(req.body.currentPage) || 1;
        const limit = parseInt(req.body.limit) || 10;
        const filter = req.body.filter || "";
        const sortBy = req.body.sortBy || "-1";
        let startIndex = (pageNumber - 1) * limit;
        var getData = await UserModel.aggregate([{ $sort: { _id: sortBy === '-1' ? -1 : 1 } },
        {
            $match: {
                userType: 'Member',
                $or: [
                    { firstName: { $regex: filter, $options: 'i' } },
                    { lastName: { $regex: filter, $options: 'i' } }
                ]
            }
        },
        {
            $lookup: {
                from: 'userplans', // Replace with your actual collection name
                let: { userId: "$_id" },
                pipeline: [
                    {
                        $match: {
                            $expr: { $eq: ["$userId", "$$userId"] },
                            status: "Active" // Add the match condition for Active status
                        }
                    }
                ],
                as: 'userPlanInfo'
            }
        },
        {
            $lookup: {
                from: 'plans', // Replace with your actual collection name for plans
                localField: 'userPlanInfo.planId', // Field from UserPlan collection
                foreignField: '_id', // Field from plans collection
                as: 'planInfo'
            }
        },
        {
            $facet: {
                memberList: [{
                    $match: {
                        status: {
                            $in: ['Active', 'Inactive', 'Deactive']
                        }
                    }
                },
                { $skip: startIndex }, { $limit: limit },
                { $project: { '_id': 1, 'firstName': 1, 'lastName': 1, 'email': '$local.email', 'joiningDate': '$metaData.createdAt', 'status': 1, 'planInfo': 1, 'enterprisePlan': 1 } }],
                totalCount: [
                    {
                        $count: 'count'
                    }
                ],
            },
        },
        {
            $project: {
                memberList: '$memberList',
                total: { "$ifNull": [{ "$arrayElemAt": ["$totalCount.count", 0] }, 0] }
            }
        }]);

        res.send({ 'status': 'success', 'data': getData[0], 'message': 'Member List Send Successfully.' });
    } catch (err) {
        return res.send({ status: 'error', message: 'Something went wrong' });
    }

};

// GET INDIVIDUAL MEMBER
module.exports.individualMember = async (req, res) => {
    var getData = await UserModel.findOne({ _id: req.params._id });


    var data = {
        userData: getData,

    }

    res.status(200).send({ 'status': 'success', 'data': data, 'message': 'Individual Member Send Successfully.' });
};

// UPDATE FEATURE
module.exports.updateMember = async function (req, res) {
    try {
        // Check Validation
        if ((!req.body._id) || (!req.body.firstName) || (!req.body.email) || (!req.body.status)) {
            return res.status(400).send({ status: 'error', message: "Mandatory fields missing." });
        }

        const filter = { _id: req.body._id };
        const update = {
            firstName: req.body.firstName,
            lastName: req.body.lastName,
            enterprisePlan: req.body.enterprisePlan,
            'local.email': req.body.email,
            status: req.body.status,
            "metaData.updatedAt": Date(),
            "metaData.updatedBy": req.body.jwtInfo.userId
        };

        let doc = await UserModel.findOneAndUpdate(filter, update);
        if (doc) {
            return res.status(200).send({ status: 'success', message: 'Member Updated Successfully.' });
        } else {
            return res.status(400).send({ status: 'error', message: "Unable To Update Member." });
        }
    } catch (err) {
        return res.send({ status: 'error', message: 'Something went wrong' });
    }
}

// CHANGE STATUS MEMBER
module.exports.statusChange = async function (req, res) {
    try {
        // Check Validation
        if ((!req.body._id) || (!req.body.status)) {
            return res.send({ status: 'error', message: "Mandatory fields missing." });
        }

        if (req.body.status != 'Deactive') {
            if (req.body.jwtInfo.permission != 'Admin') {
                return res.send({ status: 'error', message: "You are not an Admin." });
            }
        }

        const filter = { _id: req.body._id };
        const update = {
            status: req.body.status,
            "metaData.updatedAt": Date(),
            "metaData.updatedBy": req.body.jwtInfo.userId,
            $set: { 'loginHistory.$[].status': false }
        };

        let doc = await UserModel.findOneAndUpdate(filter, update);
        if (doc) {
            return res.send({ status: 'success', message: 'Status Change Successfully.' });
        } else {
            return res.send({ status: 'error', message: "Unable To Change Status." });
        }
    } catch (err) {
        return res.send({ status: 'error', message: 'Something went wrong' });
    }
}

// ENABLED TWO FACTOR AUTHENTICATION
module.exports.twoFAEnabled = async function (req, res) {
    try {
        // Check Validation
        if (!req.body.status || !req.body.token) {
            return res.send({ status: 'error', message: "Mandatory fields missing." });
        }

        const ip = req.ip; // Get the IP address from the request
        const userLimitOTPId = 2;
        // Check if the IP address has exceeded the limit
        if ((enable2FAOtpAttempts.has(userLimitOTPId) && enable2FAOtpAttempts.get(userLimitOTPId).count >= 3) || (enable2FAOtpAttempts.has(ip) && enable2FAOtpAttempts.get(ip).count >= 3)) {
            return res.status(400).json({ status: "error", message: 'Too many requests, please try again after 10 minutes.' });
        }

        // If not exceeded, update the attempt count or initialize a new entry
        if (enable2FAOtpAttempts.has(ip)) {
            enable2FAOtpAttempts.get(ip).count += 1;
        } else {
            enable2FAOtpAttempts.set(ip, { count: 1 });
        }

        // Set a timeout to reset the attempt count after 1 minute
        setTimeout(() => {
            enable2FAOtpAttempts.delete(ip);
        }, 10 * 60 * 1000); // 10 minutes timeout\

        const user = await UserModel.findOne({ _id: req.body.jwtInfo.userId });
        if (user.twofaEnabled == false) {
            return res.json({
                status: "success",
                message: "2FA already disabled",
                twofaEnabled: user.twofaEnabled,
            });
        }

        const token = req.body.token;

        if (usedOTPs.has(token)) {
            return res.status(400).json({
                message: "OTP is invalid or has already been used!",
            });
        }

        if (!authenticator.check(token, user.twofaSecret)) {
            return res.status(400).json({
                status: "error",
                message: "OTP verification failed: Invalid token",
                twofaEnabled: user.twofaEnabled,
            });
        } else {
            const filter = { _id: req.body.jwtInfo.userId };
            const update = {
                twofaEnabled: req.body.status,
                "metaData.updatedAt": Date(),
                "metaData.updatedBy": req.body.jwtInfo.userId
            };

            let doc = await UserModel.findOneAndUpdate(filter, update);
            if (doc) {
                enable2FAOtpAttempts.delete(ip);
                enable2FAOtpAttempts.delete(userLimitOTPId);
                return res.send({ status: 'success', message: '2FA off successfully.' });
            } else {
                return res.send({ status: 'error', message: "Unable To Change Two Factor." });
            }
        }
    } catch (err) {
        return res.send({ status: 'error', message: 'Something went wrong' });
    }
}

// module.exports.generate2faSecret = async (req, res) => {
//     try {

//         const user = await UserModel.findOne({ _id: req.body.jwtInfo.userId });
//         if (req.body.status) {

//             if (user.twofaEnabled) {
//                 return res.status(400).json({
//                     message: "2FA already verified and enabled",
//                     twofaEnabled: user.twofaEnabled,
//                 });
//             }

//             const secret = authenticator.generateSecret();
//             user.twofaSecret = secret;
//             user.save();
//             const appName = "Malsearch";

//             return res.json({
//                 status: "success",
//                 message: "2FA secret generation successful",
//                 secret: secret,
//                 qrImageDataUrl: await qrcode.toDataURL(
//                     authenticator.keyuri(user.local.email, appName, secret)
//                 ),
//                 twofaEnabled: user.twofaEnabled,
//             });
//         } else {

//             user.twofaEnabled = false;
//             user.twofaSecret = "";
//             await user.save();

//             return res.json({
//                 message: "2FA disabled successfully",
//                 twofaEnabled: user.twofaEnabled,
//             });
//         }


//     } catch (error) {
//         return res.send({ status: 'error', message: 'Something went wrong' });
//     }

// };

module.exports.verifyOtp = async (req, res) => {
    try {
        const ip = req.ip; // Get the IP address from the request
        const userLimitOTPId = 2;
        // Check if the IP address has exceeded the limit
        if ((enable2FAOtpAttempts.has(userLimitOTPId) && enable2FAOtpAttempts.get(userLimitOTPId).count >= 3) || (enable2FAOtpAttempts.has(ip) && enable2FAOtpAttempts.get(ip).count >= 3)) {
            return res.status(400).json({ status: "error", message: 'Too many requests, please try again after 10 minutes.' });
        }

        // If not exceeded, update the attempt count or initialize a new entry
        if (enable2FAOtpAttempts.has(ip)) {
            enable2FAOtpAttempts.get(ip).count += 1;
        } else {
            enable2FAOtpAttempts.set(ip, { count: 1 });
        }

        // Set a timeout to reset the attempt count after 1 minute
        setTimeout(() => {
            enable2FAOtpAttempts.delete(ip);
        }, 10 * 60 * 1000); // 10 minutes timeout

        const user = await UserModel.findOne({ _id: req.body.jwtInfo.userId });
        if (user.twofaEnabled) {
            return res.json({
                status: "success",
                message: "2FA already verified and enabled",
                twofaEnabled: user.twofaEnabled,
            });
        }

        const token = req.body.token;

        if (usedOTPs.has(token)) {
            return res.status(400).json({
                message: "OTP is invalid or has already been used!",
            });
        }

        if (!authenticator.check(token, user.twofaSecret)) {
            return res.status(400).json({
                status: "error",
                message: "OTP verification failed: Invalid token",
                twofaEnabled: user.twofaEnabled,
            });
        } else {
            usedOTPs.add(token);
            user.twofaEnabled = true;
            user.save();
            enable2FAOtpAttempts.delete(ip);
            enable2FAOtpAttempts.delete(userLimitOTPId);
            return res.json({
                status: "success",
                message: "OTP verification successful",
                twofaEnabled: user.twofaEnabled,
            });
        }
    } catch (error) {
        return res.status(400).json({
            status: "error",
            message: 'Something went wrong'
        });
    }

};

// UPDATE PASSWORD
module.exports.changePassword = async function (req, res) {
    try {
        const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&.,-/])[A-Za-z\d@$!%*?&.,-/]{8,}$/;
        // Check Validation
        if (!req.body.password || !req.body.currentPassword) {
            return res.status(400).send({ status: 'error', message: "Mandatory fields missing." });
        }

        if (!passwordRegex.test(req.body.password)) {
            return res.send({ status: 'error', message: "Password must be at least 8 characters long with 1 uppercase, 1 lowercase, 1 special character, and 1 number!" });
        } else if (req.body.password.length > 64) {
            return res.send({ status: 'error', message: "Password must be limited to 64 characters!" });
        }

        // Find the user by userId
        const user = await UserModel.findById(req.body.jwtInfo.userId);

        // If the user doesn't exist, handle the case appropriately
        if (!user) {
            return res.status(400).json({ status: 'error', message: 'Invalid credentials. Please check your email and try again.' });
        }

        if (!user.isPasswordValid(req.body.currentPassword)) {
            return res.status(400).json({ status: 'error', message: 'Current password is incorrect.' });
        }

        // // Compare the current password with the stored hashed password
        // const passwordMatch = await bcrypt.compare(currentPassword, user.password);

        // if (!passwordMatch) {
        //     return res.status(401).json({ message: 'Current password is incorrect.' });
        // }

        const filter = { _id: req.body.jwtInfo.userId };
        const update = {
            "local.password": req.body.password,
            "metaData.updatedAt": Date(),
            "metaData.updatedBy": req.body.jwtInfo.userId
        };

        let doc = await UserModel.findOneAndUpdate(filter, update);
        if (doc) {
            return res.status(200).send({ status: 'success', message: 'Password Updated Successfully.' });
        } else {
            return res.status(400).send({ status: 'error', message: "Unable To Update Password." });
        }
    } catch (err) {
        return res.send({ status: 'error', message: 'Something went wrong' });
    }
}

// FORGOT PASSWORD
module.exports.forgotPassword = async function (req, res) {
    try {
        // Check Validation
        if (!req.body.email) {
            return res.status(400).send({ status: 'error', message: "Mandatory fields missing." });
        }
        var getData = await UserModel.findOne({ "local.email": req.body.email });
        if (!getData) {
            return res.status(400).send({ 'status': 'error', 'message': 'Invalid credentials. Please check your email and try again!.' });
        }
        const expireDate = new Date(getData.resetPassExpire);
        const currentDate = new Date();

        if (getData.resetPassStatus == true && expireDate > currentDate) {
            res.send({ 'status': 'error', 'message': 'Link already send on mail!.' });
        } else {
            const transporter = createTransport({
                host: process.env.SMTP_HOST,
                port: config.smtp.port,
                auth: {
                    user: process.env.SMTP_USER,
                    pass: process.env.SMTP_PASS,
                },
            });


            var resetLink = `${process.env.WEB_LINK}/reset-password/${getData._id}`;

            var html = "";

            html += `<!doctype html>
        <html lang="en-US">
        
        <head>
            <meta content="text/html; charset=utf-8" http-equiv="Content-Type" />
            <title>Reset Password Email Template</title>
            <meta name="description" content="Reset Password Email Template.">
            <style type="text/css">
                a:hover {text-decoration: underline !important;}
            </style>
        </head>
        
        <body marginheight="0" topmargin="0" marginwidth="0" style="margin: 0px; background-color: #f2f3f8;" leftmargin="0">
            <!--100% body table-->
            <table cellspacing="0" border="0" cellpadding="0" width="100%" bgcolor="#f2f3f8"
                style="@import url(https://fonts.googleapis.com/css?family=Rubik:300,400,500,700|Open+Sans:300,400,600,700); font-family: 'Open Sans', sans-serif;">
                <tr>
                    <td>
                        <table style="background-color: #f2f3f8; max-width:670px;  margin:0 auto;" width="100%" border="0"
                            align="center" cellpadding="0" cellspacing="0">
                            <tr>
                                <td style="height:80px;">&nbsp;</td>
                            </tr>
                            <tr>
                                <td style="text-align:center;">
                                  <a href="http://3.14.175.22:4748" title="logo" target="_blank">
                                    <img width="60" src='http://3.14.175.22:4748/uploads/Logo.png' title="logo" alt="logo">
                                  </a>
                                </td>
                            </tr>
                            <tr>
                                <td style="height:20px;">&nbsp;</td>
                            </tr>
                            <tr>
                                <td>
                                    <table width="95%" border="0" align="center" cellpadding="0" cellspacing="0"
                                        style="max-width:670px;background:#fff; border-radius:3px; text-align:center;-webkit-box-shadow:0 6px 18px 0 rgba(0,0,0,.06);-moz-box-shadow:0 6px 18px 0 rgba(0,0,0,.06);box-shadow:0 6px 18px 0 rgba(0,0,0,.06);">
                                        <tr>
                                            <td style="height:40px;">&nbsp;</td>
                                        </tr>
                                        <tr>
                                            <td style="padding:0 35px;">
                                                <h1 style="color:#1e1e2d; font-weight:500; margin:0;font-size:32px;font-family:'Rubik',sans-serif;">You have
                                                    requested to reset your password</h1>
                                                <span
                                                    style="display:inline-block; vertical-align:middle; margin:29px 0 26px; border-bottom:1px solid #cecece; width:100px;"></span>
                                                <p style="color:#455056; font-size:15px;line-height:24px; margin:0;">
                                                    We cannot simply send you your old password. A unique link to reset your
                                                    password has been generated for you. To reset your password, click the
                                                    following link and follow the instructions.
                                                </p>
                                                <a href="${resetLink}"
                                                    style="background:#20e277;text-decoration:none !important; font-weight:500; margin-top:35px; color:#fff;text-transform:uppercase; font-size:14px;padding:10px 24px;display:inline-block;border-radius:50px;">Reset
                                                    Password</a>
                                            </td>
                                        </tr>
                                        <tr>
                                            <td style="height:40px;">&nbsp;</td>
                                        </tr>
                                    </table>
                                </td>
                            <tr>
                                <td style="height:20px;">&nbsp;</td>
                            </tr>
                            <tr>
                                <td style="text-align:center;">
                                    <p style="font-size:14px; color:rgba(69, 80, 86, 0.7411764705882353); line-height:18px; margin:0 0 0;">&copy; <strong>www.weblink.com</strong></p>
                                </td>
                            </tr>
                            <tr>
                                <td style="height:80px;">&nbsp;</td>
                            </tr>
                        </table>
                    </td>
                </tr>
            </table>
            <!--/100% body table-->
        </body>
        
        </html>`;

            const mailOptions = {
                from: process.env.SMTP_USER,
                to: req.body.email,
                subject: `Forgot Password`,
                html: html
            };

            transporter.sendMail(mailOptions, async function (error, info) {
                if (error) {
                    return res.status(400).send({ status: 'error', message: 'Something went wrong' });
                } else {
                    const filter = { "local.email": req.body.email };
                    const update = {
                        "resetPassStatus": true,
                        "resetPassExpire": new Date(Date.now() + (5 * 60 * 1000))
                    };

                    let doc = await UserModel.findOneAndUpdate(filter, update);
                    console.log('Email sent: ' + info.response);
                    return res.status(200).send({ status: 'success', message: 'Email Send Successfully.' });

                }
            });
        }
    } catch (err) {
        return res.send({ status: 'error', message: 'Something went wrong' });
    }
}

// RESET PASSWORD
module.exports.resetPassword = async function (req, res) {
    try {
        // Check Validation
        if ((!req.body.password) || (!req.body.userId)) {
            return res.status(400).send({ status: 'error', message: "Mandatory fields missing." });
        }

        var getData = await UserModel.findOne({ _id: req.body.userId });
        if (!getData) {
            res.send({ 'status': 'error', 'message': 'Invalid credentials. Please check your email and try again!.' });
        }

        const expireDate = new Date(getData.resetPassExpire);
        const currentDate = new Date();

        if (getData.resetPassStatus == true && expireDate > currentDate) {
            const filter = { _id: req.body.userId };
            const update = {
                "local.password": req.body.password,
                "resetPassExpire": "",
                "resetPassStatus": false,
                "metaData.updatedAt": Date(),
                "metaData.updatedBy": req.body.userId
            };

            let doc = await UserModel.findOneAndUpdate(filter, update);
            if (doc) {
                return res.status(200).send({ status: 'success', message: 'Password Updated Successfully.' });
            } else {
                return res.status(400).send({ status: 'error', message: "Unable To Update Password." });
            }
        } else {
            res.send({ 'status': 'error', 'message': 'Token expire please resend link.' });
        }
    } catch (err) {
        return res.send({ status: 'error', message: 'Something went wrong' });
    }
}