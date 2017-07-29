// routes/routes.js
module.exports = function(app, passport) {

  // HOME PAGE (with login links)
  app.get('/', function(req, res) {
    res.render('index.ejs'); 
  });

  // LOGIN PAGE
  app.get('/login', function(req, res) {
    res.render('login.ejs', { message: req.flash('loginMessage')});
  });

  app.post('/login', passport.authenticate('local-login', {
    successRedirect: '/profile',
    failureRedirect: '/login',
    failureFlash: true,
  }));

  // SIGNUP
  app.get('/signup', function(req, res) {
    res.render('signup.ejs', { message: req.flash('signupMessage')});
  });

  // process the signup form
  app.post('/signup', passport.authenticate('local-signup', {
    successRedirect: '/profile',
    failureRedirect: '/signup',
    failureFlash: true // allow flash message
  }));

  // Profile Section
  app.get('/profile', isLoggedIn, function(req, res) {
    res.render('profile.ejs', {
      user: req.user // get the user out of session and pass to template
    });
  });

  // LOGOUT
  app.get('/logout', function(req, res) {
    req.logout(); // provided by passport
    res.redirect('/');
  });

  // route middleware to make sure a user is logged in 
  // before get into Profile page
  function isLoggedIn(req, res, next) {
    // if user is authenticated in the session,
    if(req.isAuthenticated()) {
      return next();
    } else {
      // redirect user to home page
      res.redirect('/');
    }
  }


  // =====================================
  // GOOGLE ROUTES =======================
  // =====================================
  // send to google to do the authentication
  // profile gets us their basic information including their name
  // email gets their emails
  app.get('/auth/google', passport.authenticate('google', {
    scope: ['profile', 'email'],
  }));


  app.get('/auth/google/callback', passport.authenticate('google', {
    successRedirect: '/profile',
    failureRedirect: '/',
  }));

  // =====================================
  // FACEBOOK ROUTES =======================
  // =====================================  
  app.get('/auth/facebook', passport.authenticate('facebook', {
    scope: 'email',
  }));

  app.get('/auth/facebook/callback', passport.authenticate('facebook', {
    successRedirect: '/profile',
    failureRedirect: '/',
  }))
};

