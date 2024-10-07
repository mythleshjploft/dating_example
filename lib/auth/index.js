'use strict';

var logger = require('../utils/logger')(module);
var config = require('../../config');
const ObjectID = require('mongodb').ObjectId
// Login Strategies:
var localLogin = require('./local-login-strategy');
var jwtLogin = require('./jwt-login-strategy');
var User = require('../../models/User');

const browser = require('browser-detect');
var passport = require('passport');
var jwt = require('jsonwebtoken');
const useragent = require('useragent');

// const loginAttempts = new Map();

var exports = module.exports = {};
if (!Object.entries)
    Object.entries = function (obj) {
        var ownProps = Object.keys(obj),
            i = ownProps.length,
            resArray = new Array(i); // preallocate the Array
        while (i--)
            resArray[i] = [ownProps[i], obj[ownProps[i]]];

        return resArray;
    };

///////////////////////////////////////////////////////////
// Keep configuration localized here instead of server.js
//
// Set up Auth middleware
//////////////////////////////////////

exports.configureMiddleware = function (app) {
    // used to serialize the user for the session
    passport.serializeUser(function (user, done) {
        done(null, user.id);
    });

    // used to deserialize the user
    passport.deserializeUser(function (id, done) {
        User.findById(id, done);
    });

    // Install Login Strategies:

    jwtLogin(passport);
    localLogin(passport);
    // facebookLogin(passport);
    // facebookLoginMb(passport);
    // googleLogin(passport);
    // googleLoginMb(passport);

    app.use(passport.initialize());
    app.use(passport.session());
    // logger.info('Auth middleware configured.')
};

// Pass Through the Auth routes:
exports.authenticate = {
    // Email/Password:

    localLogin: function (req, res, next) {
        return passport.authenticate('local-login', authenticationStrategyCallback(req, res, next))(req, res, next);
    },
    // JWT Strategy
    jwt_auth: async function (req, res, next) {
        if (!req.headers.authorization) {
            let data = {
                status: 'error',
                message: 'Authorization Token Missing'
            }
            return res.status(401).json(data);
        }


        let JWT = req.headers.authorization.substr(7);
        jwt.verify(JWT, config.jwtSecret, async (err, decoded) => {
            if (err) {
                let data = {
                    status: 'error',
                    message: 'Invalid Token. Please Login Again !!'
                }
                return res.status(403).json(data);
            }

            const usernew = await User.findOne({ _id: decoded.id, loginHistory: { "$elemMatch": { _id: decoded.sessionId, status: true } } }, 'loginHistory');
            if (usernew) {
                return passport.authenticate('jwt', { session: false }, authenticationStrategyCallbackJwt(req, res, next))(req, res, next);
            } else {
                return res.status(403).json({ status: 401, message: 'You’ve been signed in from a different device' });
            }
        })

    },
    // Etc.
};
/*
* Disable for Social Media Module
exports.authenticationRequired = function (req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  } else {
    if (!req.xhr) req.session.redirectTo = req.originalUrl;
    res.redirect(ROUTES.USERS.LOGIN_PATH);
  }
}
*/
// Check User Authenticated or Not
exports.CheckAuthentication = function (req, res, next) {
    if (req.isAuthenticated()) {
        return res.status(200).send({ status: 200, data: 'Authenticated' });
    } else {
        return res.status(401).send({ status: 401, data: 'NotAuthenticated' });
    }
}
//////////////////////////////////////
// END Set up Auth middleware
//////////////////////////////////////

/**
 * Enforces group permissions for required routes
 * @param {Array} routePermissions
 * @returns {Function} route handler to process request
 * @Example use: permisssionsRequire(["PlateRate Admin"])
 */
/*
* Disable for Social Media Module
exports.isAuthorized = (routePermissions = []) => {
  return (req, res, next) => {
    if (req.session.user) {
      if (req.session.user.profile) {
        const userPermissions = req.session.user.profile.permissionGroups;
        const userHasPermission = userPermissions.reduce((isGranted, userPermission) => {
          if (routePermissions.includes(userPermission)) isGranted = true;
          return isGranted;
        }, false);

        if (userHasPermission) next();
        else res.status(403).render('403');

      } else {
        res.redirect(ROUTES.USERS.PROFILE_PATH)
      }
    } else {
      res.redirect(ROUTES.USERS.LOGIN_PATH);
    }
  }
};
*/

// JWT Respone
function authenticationStrategyCallbackJwt(req, res, next) {
    return async (err, jwtInfo, info) => {
        if (err) {
            return res.send({ status: 'error', message: err });
        }
        if (jwtInfo) {
            req.body.jwtInfo = jwtInfo.jwtInfo;
            return next();
        }
    }
}

////////////////////////////////////
// PRIVATE METHODS
////////////////////////////////////
function authenticationStrategyCallback(req, res, next) {
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

    const userAgentString = req.headers['user-agent'];
    const agent = useragent.parse(userAgentString);
    const browser = agent.family; // Browser name
    const version = agent.toVersion(); // Browser version
    const os = agent.os.family + ' ' + agent.toVersion(); // Operating system
    // Wrapping this anonymous function to pass req, res, and next:
    return async (err, user, info) => {
        if (err) {
            return res.send({ status: 404, message: err });
        }

        // Check User's Profile and registration status:

        if (user) {
            // if (!user.twofaEnabled) {
            const filter = { _id: user._id };

            // Check User Already login or not
            var isLogin = false;
            let loginStatus = await User.findOne({
                _id: user._id,
                loginHistory: { $elemMatch: { status: true } }
            });
            if (loginStatus) {
                isLogin = true;
            } else {
                isLogin = false;
            }
            // Logout if already user login
            let doc = await User.updateMany(filter, { $set: { 'loginHistory.$[].status': false } });
            //Update the user last Login date
            const data = await User.updateLastLogin(user._id, browser, os);


            var payload = {
                id: user._id,
                permission: user.userType,
                status: user.status,
                sessionId: data.sessionId
            };
            if (req.body.rememberme == 'true' || req.body.rememberme == true) {
                var expirationTime = '7d'; // 7 day
            } else {
                var expirationTime = '1d'; // 1 day
            }

            var token = jwt.sign(payload, config.jwtSecret, { expiresIn: expirationTime });

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
                token: token,
                twofaEnabled: false,
                isLogin: isLogin,
                planStatus: planStatus
            }
            req.logIn(user, function (err) {
                if (err) {
                    return res.send({ 'status': 'error', 'message': err.message });
                }
            });
            loginAttempts.delete(ip);
            loginAttempts.delete(userLimitNewId);
            return res.send({ 'status': 'success', message: 'Login Successfully', user: returnUserData });
            // } else {


            //     var returnUserData = {
            //         twofaEnabled: true,
            //         loginStep2VerificationToken: jwt.sign(
            //             {
            //                 // important to keep this payload different from a real/proper
            //                 // authentication token payload so that this token cannot be used
            //                 // for real/proper authentication defeating the whole point of
            //                 // 2-factor authentication
            //                 loginStep2Verification: { email: user.local.email, rememberme: req.body.rememberme },
            //             },
            //             config.jwtSecret,
            //             { expiresIn: "5m" }
            //         ),
            //     }
            //     loginAttempts.delete(ip);
            //     loginAttempts.delete(userLimitNewId);
            //     return res.send({ 'status': 'success', message: 'Please complete 2-factor authentication', user: returnUserData });
            // }

        } else {
            return next('No User Data. Not sure why.');
        }
    }
}
