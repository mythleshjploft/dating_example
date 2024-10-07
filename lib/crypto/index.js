'use strict';
// Abstracting Crypto implementation
// var randomstring = require("randomstring");
var bcrypt   = require('bcryptjs');
var SALT_ROUNDS = 10;

var exports = module.exports = {};

/**
 * Generate a secure crypto hash, using provided salt rounds
 * @param {String} text - value to encrypt
 * @return {String} secure hash
 */
exports.hash = function(text) {
  return bcrypt.hashSync(text, SALT_ROUNDS);
}

/**
 * Verifies provided string against a hashed one, making sure they match.
 * @param {String} text - value to check
 * @param {String} hashedText - original to check against
 * @return {Boolean} true when matches, false otherwise
 */
exports.checkHash = function(text, hashedText) {
  return bcrypt.compareSync(text, hashedText);
}

/**
 * Generate a random string of requested length.  Not meant to be checked against.  Good for temporary passwords and
 * verification tokens
 * @param {Number} size - the length of generated string.  Default is 0, meaning crypto library's default will be used.
 * @return {String} random string sized as required
 */
// exports.randomString = function(size = 32) {
//   // Validate input:
//   if(size < 0) {
//     size = 32;
//   }
//   return randomstring.generate(size);
// }