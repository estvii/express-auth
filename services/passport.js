const passport = require('passport');
const UserModel = require('../models/user');
const config = require('../config');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt; 
const LocalStrategy = require('passport-local');

// Create local strategy
const localOptions = { usernameField: 'email'}
const localLogin = new LocalStrategy(localOptions, function(email, password, done) {
    // Verify this email and password, call done with the user
    // if it is the correct email and password
    // otherwise, call done with false
    UserModel.findOne({email} , function(err,user) {
        if (err) { return done(err); }
        if (!user) { return done(null,false); }

        // compare passwords - is `password` equal to user.password (in the DB)?
        user.comparePassword(password, function(err, isMatch) {
            if (err) { return done(err); }
            if (!isMatch) { return done(null,false); }

            return done(null,user);
        })

    })
});

// Setup options for JWT strategy
const jwtOptions = {
    jwtFromRequest: ExtractJwt.fromHeader('authorization'),
    secretOrKey: config.secret
};

// Create JWT Strategy
// The payload comes from our authentication.js, jwt.encode({sub: user.id, iat: timestamp) the object is the payload, we also need to decode
// the done is a call back function 
const jwtLogin = new JwtStrategy(jwtOptions, function(payload, done) {
    // See if the user ID in the payload exist in our database
    // If it does, all 'done' with that user
    // Otherwise, call done without a user object
    UserModel.findById(payload.sub, function(err, user) {
        if (err) { return done(err,false); } 

        if (user) {
            done(null, user);
        } else {
            done(null, false); //false return no user found, null is no errors
        }
    });

});

// Tell passport to use this strategy
passport.use(jwtLogin);
passport.use(localLogin);