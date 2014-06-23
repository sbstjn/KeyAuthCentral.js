(function() {
  'use strict';

  var express = require('express');
  var fs = require('fs');
  var http = require('http');
  var querystring = require('querystring');
  var ursa = require('ursa');

  /**
   * Temporary in-Memory storage for tokens
   */
  var TokenStorage = function() {
    this.data = {};
  };

  TokenStorage.prototype.validateRequest = function(site, token, callback) {
    callback(this.data[site] && this.data[site].request === token && this.data[site].auth === null);
  };

  TokenStorage.prototype.setAuth = function(site, auth, callback) {
    this.data[site].auth = auth;

    callback(auth);
  };

  TokenStorage.prototype.createToken = function(site, token, callback) {
    this.data[site] = {request: token, auth: null, created: new Date()};

    callback(token);
  };

  TokenStorage.prototype.checkSession = function(site, token, callback) {
    callback(this.data[site] && this.data[site].auth === token);
  };

  var KeyAuthCentral = function(data) {
    this.http = 'http';
    this.name = data.name;
    this.about = data.about;
    this.tokens = {};
    this.storage = new TokenStorage();

    // Load private RSA key
    fs.readFile(data.key + '.pub', function(err, data) {
      this.keyPublic = data;
    }.bind(this));

    // Load private RSA key
    fs.readFile(data.key, function(err, data) {
      this.keyPrivate = data;
    }.bind(this));

    // Load avatar
    fs.readFile(data.avatar, function(err, data) {
      this.avatar = data;
    }.bind(this));
  };

  /**
   * Generate redirect URL for given provider
   */
  KeyAuthCentral.prototype.providerURL = function(name) {
    return this.http + '://' + name + '/auth?client_id=' + this.name + '&response_type=token&scope=auth';
  };

  /**
   * Helper for sending HTTP post request
   */
  KeyAuthCentral.prototype.postHTTP = function(options, data, callback) {
    var handle = function(response) {
      var data = '';

      response.on('data', function(chunk) {
        data += chunk;
      });

      response.on('end', function() {
        callback(data);
      });
    };

    var req = http.request(options, handle);
    req.write(data);
    req.end();
  };

  /**
   * Handle callback from KeyAuthCentral
   */
  KeyAuthCentral.prototype.validateCallback = function(provider, token, callback) {
    // Provider parsing
    var prov = provider.split(':');
    var provName = prov.shift();
    var provPort = prov.shift();

    // Post request data
    var data = querystring.stringify({token: token, 'client_id': this.name});

    // Post request options
    var options = {
      host: provName,
      path: '/auth/validate',
      port: provPort || 80,
      method: 'post',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': Buffer.byteLength(data)
      }
    };

    this.postHTTP(options, data, function(data) {
      var json = {};
      try {
        json = JSON.parse(data);
      } catch (e) { }

      callback(!!json.valid, json.token);
    });
  };

  /**
   * Request session from KeyAuthCentral after handling auth callback
   */
  KeyAuthCentral.prototype.getSession = function(provider, token, callback) {
    // Provider parsing
    var prov = provider.split(':');
    var provName = prov.shift();
    var provPort = prov.shift();

    // Post request data
    var data = querystring.stringify({token: token, 'client_id': this.name});

    var options = {
      host: provName,
      path: '/auth/session',
      port: provPort || 80,
      method: 'post',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': Buffer.byteLength(data)
      }
    };

    this.postHTTP(options, data, function(data) {
      var json = {};
      try {
        json = JSON.parse(data);
      } catch (e) { }

      callback(json.name ? null : true, json);
    });
  };

  /**
   * Set up express routes for handling login
   */
  KeyAuthCentral.prototype.handleLogin = function() {
    var router = express.Router();

    // Redirect user to given KeyAuth provider
    router.post('/', function(req, res) {
      res.redirect(this.providerURL(req.body.username));
    }.bind(this));

    // Handle redirect from KeyAuth provider
    router.get('/callback', function(req, res) {
      // Check given token
      this.validateCallback(req.param('provider'), req.param('token'), function(valid, token) {
        if (valid && token) {
          // Validate user session
          this.getSession(req.param('provider'), token, function(err, user) {
            // Check session response
            if (!err && user) {
              req.session.keyauth = {valid: true, user: user};

              res.redirect('/');
            } else {
              res.end('Cannot fetch session. Too bad!');
            }
          }.bind(this));
        } else {
          res.end('Cannot validate token. I\'m sorry!');
        }
      }.bind(this));
    }.bind(this));

    return router;
  };

  /**
   * Handle /about request with information about this consumer instance
   */
  KeyAuthCentral.prototype.handleAbout = function() {
    return function(req, res) {
      res.json({
        name: this.name,
        about: this.about,
        key: '/key',
        avatar: '/avatar'
      });
    }.bind(this);
  };

  /**
   * Handle request for consumer avatar
   */
  KeyAuthCentral.prototype.handleAvatar = function() {
    return function(req, res) {
      res.write(this.avatar);
      res.end();
    }.bind(this);
  };

  /**
   * Handle request for consumer rsa public key
   */
  KeyAuthCentral.prototype.handleKey = function() {
    return function(req, res) {
      res.write(this.keyPublic);
      res.end();
    }.bind(this);
  };

  /**
   * Export session data to response locals
   */
  KeyAuthCentral.prototype.exportSession = function() {
    return function(req, res, next) {
      if (req.session.keyauth && req.session.keyauth.valid) {
        res.locals.user = req.session.keyauth.user;
      }

      next();
    };
  };

  /**
   * Export logout handler
   */
  KeyAuthCentral.prototype.exportLogout = function() {
    return function(req, res, next) {
      if (!res.keyauth) {
        res.keyauth = {};
      }

      // Export method on response object
      res.keyauth.logout = function(path) {
        req.session.keyauth = {valid: false, user: null};

        if (path) {
          res.redirect(path);
        }
      };

      next();
    };
  };


  /**
   * Get information from KeyAuthConsumer
   */
  KeyAuthCentral.prototype.getConsumerInfo = function(name, callback) {
    var client = name.split(':');

    var options = {
      host: client.shift(),
      path: '/about',
      port: client.shift() || 80
    };

    var handle = function(response) {
      var str = '';

      //another chunk of data has been recieved, so append it to `str`
      response.on('data', function (chunk) {
        str += chunk;
      });

      //the whole response has been recieved, so we just print it out here
      response.on('end', function () {
        var data = {};
        try {
          data = JSON.parse(str);
        } catch (e) { }

        callback(data);
      });
    };

    http.request(options, handle).end();
  };

  /**
   * Create Auth Token for consumer
   */
  KeyAuthCentral.prototype.createAuth = function(site, token, callback) {
    this.storage.validateRequest(site, token, function(valid) {
      if (!valid) {
        callback(null);
      } else {
        this.storage.setAuth(site, Math.random().toString(36).slice(2), function(auth) {
          callback(auth);
        });
      }
    }.bind(this));
  };

  /**
   * Create first Token for handshake with consumer
   */
  KeyAuthCentral.prototype.createToken = function(site, callback) {
    this.storage.createToken(site, Math.random().toString(36).slice(2), function(token) {
      callback(token);
    });
  };

  /**
   * Check password for private RSA key
   */
  KeyAuthCentral.prototype.checkPassword = function(password, callback) {
    var valid = false;
    try {
      ursa.createPrivateKey(this.keyPrivate, password);

      valid = true;
    } catch (e) { }

    callback(valid);
  };

  /**
   * Show login form
   */
  KeyAuthCentral.prototype.showLogin = function(req, res) {
    this.getConsumerInfo(req.param('client_id'), function(data) {
      req.session.client = data;

      res.render('auth', {client: req.session.client});
    }.bind(this));
  };

  /**
   * Process login data
   */
  KeyAuthCentral.prototype.processData = function(req, res) {
    this.getConsumerInfo(req.param('client_id'), function(data) {
      req.session.client = data;

      this.checkPassword(req.body.password || '', function(valid) {
        req.session.keyauth = {valid: valid};

        if (valid) {
          this.createToken(req.session.client.name, function(token) {
            res.redirect('http://' + req.session.client.name + '/login/callback?token=' + token + '&provider=' + this.name);
          }.bind(this));
        } else {
          res.render('auth', {client: req.session.client, keyauth: {failed: !valid, valid: valid}});
        }
      }.bind(this));
    }.bind(this));
  };

  /**
   * Wrapper for auth request handling
   **/
  KeyAuthCentral.prototype.handleAuth = function() {
    var router = express.Router();

    // Draw login form
    router.all('/', function(req, res, next) {
      var method = req.method.toUpperCase();

      switch(method) {
      case 'GET':
        this.showLogin(req, res, next);
        break;
      case 'POST':
        this.processData(req, res, next);
        break;
      }
    }.bind(this));

    // Handle token validation
    router.post('/validate', function(req, res) {
      this.createAuth(req.param('client_id'), req.param('token'), function(token) {
        res.json({
          valid: !!token,
          token: token
        });
      });
    }.bind(this));

    // Get basic user information with token
    router.post('/session', function(req, res) {
      this.storage.checkSession(req.param('client_id'), req.param('token'), function(valid) {
        res.json(valid ? {name: this.name} : {});
      }.bind(this));
    }.bind(this));

    return router;
  };

  KeyAuthCentral.prototype.expressBinding = function() {
    var router = express.Router();

    // Basic profile JSON
    router.get('/about',   this.handleAbout());

    // Routing for authentication
    router.use('/auth',    this.handleAuth());

    // Avatar image
    router.get('/avatar',  this.handleAvatar());

    // Public RSA key
    router.get('/key',     this.handleKey());

    // Bind routing for login handling
    router.use('/login',   this.handleLogin());

    // Export session data to locals
    router.use(this.exportSession());

    // Export logout function
    router.use(this.exportLogout());

    return router;
  };

  module.exports = KeyAuthCentral;
})();
