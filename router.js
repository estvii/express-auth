const Authentication = require('./controllers/authentication');
const passportService = require('./services/passport'); //even though its not being used we need it or it wont work
const passport = require('passport');

// the 'jwt' below looks inside our services/passport.js file
const requireAuth = passport.authenticate('jwt', { session: false }) //session: false prevents it from generating a cookie, since we're using webtokens we dont need it
const requireSignin = passport.authenticate('local', { session: false})


module.exports = function(app) {
    //Our auth route at '/', if token sends back hi there, in this case it would be our protected resource
    app.get('/', requireAuth, function(req,res) {
        res.send({hi: 'there'});
    }); 
    app.post('/signin', requireSignin, Authentication.signin)
    app.post('/signup', Authentication.signup)
}