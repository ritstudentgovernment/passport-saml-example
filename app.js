var http = require('http');
var fs = require('fs');
var express = require("express");
var bodyParser = require('body-parser');
var cookieParser = require('cookie-parser');
var session = require('express-session');
var passport = require('passport');
var saml = require('passport-saml');

passport.serializeUser(function(user, done) {
  done(null, user);
});

passport.deserializeUser(function(user, done) {
  done(null, user);
});

var samlStrategy = new saml.Strategy({
  callbackUrl: 'https://evals-test.rit.edu/login/callback',
  entryPoint: 'https://shibboleth.main.ad.rit.edu/idp/profile/SAML2/Redirect/SSO',
  issuer: 'https://evals-test.rit.edu/shibboleth',
  identifierFormat: null,
  decryptionPvk: fs.readFileSync(__dirname + '/key.pem'),
  cert: fs.readFileSync(__dirname + '/idp_cert.pem')
}, function(profile, done) {
  return done(null, profile); 
});

passport.use(samlStrategy);

var app = express();
app.use(bodyParser.urlencoded({extended: true}));
app.use(cookieParser());
app.use(passport.initialize());
app.use(passport.session());

app.get('/',
  passport.authenticate('saml', {failureRedirect: '/login/fail'}),  
  function(req, res) {
    res.send('Authenticated');
  }
);

app.post('/login/callback',
   passport.authenticate('saml', { failureRedirect: '/login/fail' }),
  function(req, res) {
    res.redirect('/');
  }
);

app.get('/login/fail', 
  function(req, res) {
    res.send(401, 'Login failed');
  }
);

app.get('/Shibboleth.sso/Metadata', 
  function(req, res) {
    res.type('application/xml');
    res.send(200, samlStrategy.generateServiceProviderMetadata(fs.readFileSync(__dirname + '/cert.pem')));
  }
);

//general error handler
app.use(function(err, req, res, next) {
  console.log("Fatal error: " + JSON.stringify(err));
  next(err);
});

var server = app.listen(4006, function () {
  console.log('Listening on port %d', server.address().port)
});

