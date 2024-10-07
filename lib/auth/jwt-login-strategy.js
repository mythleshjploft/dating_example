const ObjectID = require("mongodb").ObjectID;
const JWTStrategy = require('passport-jwt').Strategy;
const Extract = require('passport-jwt').ExtractJwt;
// const User = require('../../models/user');
const config = require('../../config');
// const Device = require('../../models/device');


const opts = {
    jwtFromRequest: Extract.fromAuthHeaderAsBearerToken(),
    secretOrKey: config.jwtSecret
  };

  module.exports = function(passport) {

    passport.use(
      "jwt",
      new JWTStrategy(opts, async(jwt_payload, done) => {
        try {
          if(jwt_payload.deviceId) {

            // let deviceDetails = await Device.findById({_id: ObjectID(jwt_payload.deviceId)});

            // if(!deviceDetails.status)
            //   return done('Device Logged Out');
          }
          let returnData = {
            jwtInfo: {
              userId: jwt_payload.id,
              sessionId: jwt_payload.sessionId,
              permission: jwt_payload.permission,
              status: jwt_payload.status
            }
          }

        return done(null, returnData)
        } catch (err) {
          return done(err);
        }
      })
    );
  };


