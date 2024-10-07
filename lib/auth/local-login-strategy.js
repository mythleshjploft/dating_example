'use strict';

var LocalStrategy = require('passport-local').Strategy;
var User = require('../../models/User');
var logger = require('../utils/logger')(module);
// var emailSender = require('../../lib/email-sender');
// var emailGen = require('../../lib/email-template-generator').emailTemplateGenerator;
var config = require('../../config');

module.exports = function (passport) {
    passport.use('local-login', new LocalStrategy({
        usernameField: 'email',
        passwordField: 'password',
        passReqToCallback: true
    },
        function (req, email, password, done) {
            logger.debug('Executing Local Login Strategy', email, password);
            if (email) email = email.toLowerCase();
            // asynchronous
            process.nextTick(function () {
                //User.findOne({'local.email': email}, function (err, user) {
                //to allow user to login from his mail or any of the secondary emails
                User.findOne({ "local.email": email }, function (err, user) {
                    // if there are any errors, return the error
                    if (err) return done(err);

                    // if no user is found, return the message
                    //if (!user) return done(null, false, req.flash('error', 'Email does not exist.'));
                    if (!user) {
                        return done('Invalid credentials. Please check your email and try again');
                    } else if (user && user.local.password == null || user.local.password == undefined) {
                        logger.error('User has not set any password yet');
                        return done('Your email was not verify yet so please verify it');
                    }

                    if (user.status == 'Active') {
                        if (email == user.local.email) {
                            if (!user.isPasswordValid(password)) return done('Invalid password. Please check your password and try again.');
                            // all is well, return user
                            else return done(null, user, 'Login successful!');
                        } else {
                            // user.secondary.forEach((data) => {
                            if (email == data.emails) {
                                if (data.status == 'verified') {
                                    if (!user.isPasswordValid(password)) return done('Invalid password. Please check your password and try again.');
                                    // all is well, return user
                                    else return done(null, user, 'Login successful!');
                                } else {
                                    return done('Oops! This Email is not verified with your account yet,Please try with another one.')
                                }
                            }
                            // });
                        }

                    } else if (user.status == 'Deactive') {
                        return done('Your account has been de-activated, please contact us for more information');
                    } else {
                        return done('Oops ! Wrong email id');
                    }

                    //if (!user.isPasswordValid(password)) return done(null, false, req.flash('error', 'Oops! Wrong password.'));

                });
            });
        }));
};
