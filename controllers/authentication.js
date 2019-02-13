const jwt = require('jwt-simple');
const UserModel = require('../models/user');
const config = require('../config');

function tokenForUser(user) {
    // sub is subject in question, in this case the user
    // iat = issued at time
    const timestamp = new Date().getTime();
    return jwt.encode( { sub: user.id, iat: timestamp } , config.secret);
}

exports.signin = function(req,res,next) {
    // user has already had their email and password auth'd
    // we need to need to give them a token
    res.send({ token: tokenForUser(req.user)})
}

exports.signup = function(req,res,next) {
    const { email, password } = req.body

    if(!email || !password) {
        return res.status(422).send({error: 'You must provide email and password'})
    }

    // See if a user with the given email exists
    UserModel.findOne({email}, function(err, existingUser){
        if (err) { 
            return next(err); 
        }

        // If a user with email does exist in DB, return an error
        if (existingUser) {
            return res.status(422).send({error: 'Email is in use'});
        }

        // If a user with email does NOT exist, create and save user record
        const user = new UserModel({
            email,
            password
        });
        user.save(function(err) {
            if (err) {
                return next(err)
            }
            // Response to request indicating the user was created
            res.json({ token: tokenForUser(user) });

        });
        


    });



    // Respond to request indicating the user was created
}