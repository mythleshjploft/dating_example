/*
* Desc: Config.js contains all configuration variables and keys needed in the application
* Usage: To create a new config key, use config.<your key name >. Then import the config.js in your module
*
*/

var config = module.exports;
const PRATE_ENV = process.env.PRATE_ENV; //The PRATE_ENV is set by the platerate.env on the AWS instances('test', 'staging', 'production')
const RUNNING_ON_AWS = (PRATE_ENV && PRATE_ENV !== '');


config.express = {
    port: process.env.PORT || 3000,
    ip: '127.0.0.1'
};



config.dbConnection = {
    mongoURI: process.env.DB_PR,
    string: process.env.DB_PR,

};

config.mailgun = {
    key: process.env.MAILGUN_API_KEY,
    attachment_dir: './dist/public/email_attachments/',
};

// Email Provider
config.emailProvider = {
    name: 'PureSMTP',
}

config.webLink = process.env.WEB_LINK;

// YOUR_STRIPE_SECRET_KEY
config.STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY;

// Sender Email Credentials and configurations
config.smtp = {
    port: "465",
    host: process.env.SMTP_HOST,
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS
}

config.email = {
    feedback: ''
}

//defaults
config.defaults = {

}

config.jwtSecret = process.env.JWT_SECRET || 'sdfasdf348fj5586';
config.jwtExpireTime = process.env.JWT_EXPIRE_TIME_ADMIN || '24h';

//Set configs based on production env
if (PRATE_ENV === 'production') {
    config.express.ip = '0.0.0.0'
    config.express.isOnProduction = true;
} else {
    config.express.isOnProduction = false;
}