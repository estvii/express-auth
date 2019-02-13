const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const bcrypt = require('bcrypt-nodejs');

// Define our model
const userSchema = new Schema({
    email: {
        type: String,
        unique: true,
        lowercase: true
    },
    password: String
});

// On Save Hook, encrypt password
// Before saving a model, run this function
userSchema.pre('save', function(next) {
    // get access to the user model of the instance of the user that was created
    const user = this;

    // generate a salt
    bcrypt.genSalt(10, function(err,salt) {
        if (err) { return next(err); }

        // hash (encrypt) our password using the salt
        bcrypt.hash(user.password, salt, null, function(err, hash) {
            if(err) { return next(err);}

            // overwrite plain text password with encrypted password
            user.password = hash;
            next();
        })
    })
});
//this.password refers to userModel password
userSchema.methods.comparePassword = function (candidatePassword, callback) {
    bcrypt.compare(candidatePassword, this.password, function(err, isMatch) { //ismatch returns true, or false
        if (err) { return callback(err); }

        callback(null, isMatch)
    }) 
}

// Create the model class
const ModelClass = mongoose.model('user', userSchema) // loads the schma into our model

// Export the model
module.exports = ModelClass;