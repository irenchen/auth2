// config/passport.js

var LocalStrategy = require('passport-local').Strategy;
var FacebookStrategy = require('passport-facebook').Strategy;
var TwitterStrategy = require('passport-twitter').Strategy;
var GoogleStrategy = require('passport-google-oauth20').Strategy;

// load the user model
var User = require('../models/user');

// load the auth variables
var configAuth = require('../../auth');

var uuid = require('uuid-v4');

module.exports = function(passport) {
    // =========================================================================
    // passport session setup ==================================================
    // =========================================================================
    // required for persistent login sessions
    // passport needs ability to serialize and unserialize users out of session

    passport.serializeUser(function(user, done) {
        done(null, user.id);
    });

    // used to deserialize user
    passport.deserializeUser(function(id, done) {
        User.findById(id, function(err, user) {
            done(err, user);
        });
    });

    // =========================================================================
    // LOCAL SIGNUP ============================================================
    // =========================================================================
    // we are using named strategies since we have one for login and one for signup
    // by default, if there was no name, it would just be called 'local'

    passport.use('local-signup', new LocalStrategy({
        // by default, local strategy uses username and password, we will override with email
        usernameField: 'email',
        passwordField: 'password',
        passReqToCallback: true // allows us to pass back the entire request to the callback
    }, function(req, email, password, done) {
        // asynchronous
        // User.findOne wont fire unless data is sent back
        process.nextTick(function() {
            User.findOne({ 'local.email': email }, function(err, user) {
                if(err) return done(err);
                // check to see if theres already a user with that email
                if(user) {
                    return done(null, false, req.flash('signupMessage', 'That email is already taken.'));

                } else {
                    // create new user
                    var newUser = new User();
                    newUser.local.email = email;
                    newUser.local.password = newUser.generateHash(password);
                    newUser.local.token = uuid();
                    // save the user
                    newUser.save(function(err) {
                        if(err) throw err;
                        return done(null, newUser);
                    });
                }
            });
        });   
    }));
    
    passport.use('local-login', new LocalStrategy({
        usernameField: 'email',
        passwordField: 'password',
        passReqToCallback: true,
    }, function(req, email, password, done) {
        User.findOne({ 'local.email': email }, function(err, user) {
            if(err) return done(err, null);
            if(!user) {
                return done(null, false, req.flash('loginMessage', 'no user found'));
            }
            if(!user.validPassword(password)) {
                return done(null, false, req.flash('loginMessage', 'wrong password'));
            }
            // all is well, return successful user
            user.local.token = uuid();
            user.save(function(err) {
                if(err) throw err;
                return done(null, user);
            });            
        });
    }));

    // =========================================================================
    // GOOGLE ==================================================================
    // =========================================================================
    passport.use(new GoogleStrategy({
        clientID: configAuth.googleAuth.clientID,
        clientSecret: configAuth.googleAuth.clientSecret,
        callbackURL: configAuth.googleAuth.callbackURL,
        passReqToCallback: true,
    },
    function(req, token, refreshToken, profile, done) {
        console.log("profile : " + JSON.stringify(profile, null, 2));
        // make the call async
        process.nextTick(function() {
            // check if the user is already logged in
            if(!req.user) {
                // find the user in the database based on their google id
                User.findOne({ 'google.id' : profile.id}, function(err, user) {
                    // if there is an error, stop everything and return that
                    // ie an error connecting to the database
                    if(err) return done(err, null);
                    // if the user is found, then log them in
                    if(user) {
                        // if there is a user id already but no token (user was linked at one point and then removed)
                        // just add our token and profile information 
                        if(!user.google.token) {
                            user.google.token = token;
                            user.google.name = profile.name.familyName + profile.name.givenName;
                            user.google.email = profile.emails[0].value;

                            user.save(err => {
                                if(err) throw err;
                                return done(null, user);
                            });
                        } else {
                            // user found, return that user
                            return done(null, user);
                        }                    
                        
                    } else {
                        // if there is no user found with that google id, create them
                        var newUser = new User();
                        // set user properties
                        newUser.google.id = profile.id;
                        newUser.google.token = token;
                        newUser.google.name = profile.name.familyName + profile.name.givenName;
                        newUser.google.email = profile.emails[0].value;

                        // save the user
                        newUser.save(err => {
                            if(err) throw err;
                            return done(null, newUser);
                        });
                    }
                });
            } else {
                // user already exists and is logged in, we have to link accounts
                var user = req.user;
                 // update the current users google credentials
                user.google.id = profile.id;
                user.google.token = token;
                user.google.name = profile.name.familyName + profile.name.givenName;
                user.google.email = profile.emails[0].value;
                user.save(function(err) {
                    if(err) throw err;
                    return done(null, user);
                })
            }

        });
    }));

    // =========================================================================
    // FACEBOOK ================================================================
    // =========================================================================
    passport.use(new FacebookStrategy({
        clientID: configAuth.facebookAuth.clientID,
        clientSecret: configAuth.facebookAuth.clientSecret,
        callbackURL: configAuth.facebookAuth.callbackURL,
        passReqToCallback: true,
    }, 
        // facebook will send back the token and profile
        function(req, token, refreshToken, profile, done) {
            console.log(JSON.stringify(profile, null, 2));
            // asynchronous
            process.nextTick(function() {
                // check if the user is already logged in
                if(!req.user) {
                    User.findOne({ 'facebook.id': profile.id }, function(err, user) {
                        if(err) done(err);
                        if(user) {
                            // if there is a user id already but no token (user was linked at one point and then removed)
                            // just add our token and profile information 
                            if(!user.facebook.token) {
                                user.facebook.token = token;
                                user.facebook.name = profile.displayName;
                                user.save(err => {
                                    if(err) throw err;
                                    return done(null, user);
                                });
                            } else {
                                // user found, return that user
                                return done(null, user);
                            } 
                        } else {
                            var newUser = new User();
                            newUser.facebook.id = profile.id;
                            newUser.facebook.token = token;
                            newUser.facebook.name = profile.displayName;
                            // newUser.facebook.email = profile.emails[0].value;
                            
                            newUser.save(function(err) {
                                if(err) return done(err);
                                return(null, newUser);
                            });
                        }
                    });
                } else {
                    // user already exists and is logged in, we have to link accounts
                    var user = req.user;
                    user.facebook.id = profile.id;
                    user.facebook.token = token;
                    user.facebook.name = profile.displayName;

                    user.save(function(err) {
                        if(err) throw err;
                        return done(null, user);
                    });
                }
            });
    }));
};

