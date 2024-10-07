const express = require('express');
const app = express();
const router = require('./router');
const db = require('./connection');
const dotenv = require('dotenv');
// const cron = require('node-cron');
const bodyParser = require('body-parser');
// const multer = require('multer');
const session = require('express-session');
// const MongoStore = require('connect-mongo');
const auth = require('./lib/auth');
const cors = require('cors');
const jwt = require('jsonwebtoken');
// var upload = multer({ dest: 'uploads/' });
// var config = require('./config');
// const planCron = require("./cron/PlanCron");

var path = require('path');
global.__basedir = __dirname;
global.loginAttempts = new Map();
dotenv.config();
app.use(bodyParser.raw({ type: 'application/json' }));
app.use(cors(), bodyParser.json({ limit: '50mb' }));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
// Global error handler middleware
app.use(function (req, res, next) {
    var err = null;
    try {
        decodeURIComponent(req.path)
    }
    catch (e) {
        err = e;
    }
    if (err) {
        // console.log(err, req.url);
        res.status(500).send('Unknown error happened');
    }
    next();
});

// Middleware to check JWT token
const authenticateToken = (req, res, next) => {
    if (!req.headers.authorization) {
        let data = {
            status: 'error',
            message: 'Authorization Token Missing'
        }
        return res.status(401).json(data);
    }

    let JWT = req.headers.authorization.substr(7);

    if (!JWT) {
        return res.sendStatus(401); // Unauthorized
    }

    jwt.verify(JWT, config.jwtSecret, (err, user) => {
        console.log('err', err);
        if (err) {
            return res.sendStatus(403); // Forbidden
        }

        req.user = user;
        next();
    });
};

// // Schedule the cron job to run twice a day at specific times (e.g., 10:00 AM and 6:00 PM)
// cron.schedule('0 10,18 * * *', () => {
//     // Execute the updateStatus function at the scheduled times
//     planCron.updateCancelStatus();
// }, {
//     timezone: 'America/New_York', // Replace with your timezone (e.g., 'America/New_York')
// });

// Apply middleware for authentication
// app.use('/resources', authenticateToken);

// Serve static resources
// app.use('/resources', express.static(path.join(__dirname, 'resources')));
// app.use('/resources/uploads', express.static(path.join(__dirname, 'resources/uploads')));
// app.use("/uploads", express.static(path.join(__dirname, 'uploads')));

// Setup app session
app.use(session({
    name: 'session',
    secret: 'VcsFa3jI4IN4EEDbGRRo',
    // Forces the session to be saved back to the session store,
    // even if the session was never modified during the request
    resave: true,
    // Forces a session that is "uninitialized" to be saved to the store
    saveUninitialized: false,
    duration: 3 * 60 * 60 * 1000, // how long the session will stay valid in ms
    cookie: {
        path: '/',
        httpOnly: true,
        secure: false,
        ephemeral: true, //cookie expires when the browser closes
        maxAge: 3 * 60 * 60 * 1000 //set the max age in case ephemeral not used
    },
}));
// setup authentication
auth.configureMiddleware(app);

app.use(router);
let PORT = process.env.PORT || 8000;
app.listen(PORT, () => {
    console.log(`listening on http://localhost:${PORT}`);
})