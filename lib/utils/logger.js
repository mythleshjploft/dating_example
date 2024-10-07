'use strict';

var winston = require('winston');
var appRoot = require('app-root-path');

process.setMaxListeners(50);

var fs = require('fs');
var env = process.env.NODE_ENV || 'development';
var logDir = process.env.LOGDIR || appRoot + '/logs';

// Create the log directory if it does not exist
if (!fs.existsSync(logDir)) {
    fs.mkdirSync(logDir);
}

// Return the last folder name in the path and the calling module's filename.
var getLabel = function (callingModule) {
    var parts = callingModule.filename.split('/');
    return parts[parts.length - 2] + '/' + parts.pop();
};

module.exports = function (callingModule) {
    return new winston.Logger({
        transports: [
            new winston.transports.File({
                level: env === 'development' ? 'verbose' : 'info',
                filename: `${logDir}/all-logs.log`,
                label: getLabel(callingModule),
                handleExceptions: env !== 'development',
                json: true,
                maxsize: 5242880, //5MB
                maxFiles: 5,
                colorize: false,
                timestamp: true
            }),
            new winston.transports.Console({
                level: 'info',
                json: false,
                colorize: true,
                timestamp: true,
                handleExceptions: env !== 'development',
            })
        ],
        // Application continue to execution even after an exception is caught
        exitOnError: false
    });
};


// module.exports.stream = {
//     write: function(message, encoding){
//         logger.info(message);
//     }
// };