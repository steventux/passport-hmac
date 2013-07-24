var passport = require('passport')
  , util = require('util');

var lookup = function(obj, field) {
  if (!obj) { return null; }
  var chain = field.split(']').join('').split('[');
  for (var i = 0, len = chain.length; i < len; i++) {
    var prop = obj[chain[i]];
    if (typeof(prop) === 'undefined') { return null; }
    if (typeof(prop) !== 'object') { return prop; }
    obj = prop;
  }
  return null;
}
/**
 * Default HMAC verification.
 * Finds the User by API key and tests the hashed parameters.
 *
 */
var hmacVerify = function(req, apiKey, hmacValue, verified) {
 // TODO: Process params in a framework agnostic way...?
 // Find User for apiKey
 var user = User.findByApiKey(apiKey);
 // test hmac val against params hashed with user secret salt.

 // Call verified with the appropriate params.
 
}

function Strategy(options, verify) {
  if (typeof options == 'function') {
    verify = options;
    options = {};
  }

  this._apiKeyField = options.apiKeyField || 'apiKey';
  this._hmacField = options.hmacField || 'hmacValue';
  this._verify = verify || hmacVerify;

  passport.Strategy.call(this);

  this.name = 'hmac';
  this._passReqToCallback = options.passReqToCallback;
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(Strategy, passport.Strategy);

Strategy.prototype.authenticate = function(req, options) {
  options = options || {};
  
  var apiKey = lookup(req.body, this._apiKeyField) || lookup(req.query, this._apiKeyField);
  var hmacValue = lookup(req.body, this._hmacField) || lookup(req.query, this._hmacField);
  
  if (!apiKey) {
    return this.fail(new Error('Missing API key'));
  }
  if (!hmacValue) {
    return this.fail(new Error('Missing HMAC value'))
  }

  var self = this;
  
  function verified(err, user, info) {
    if (err) { return self.fail(err); }
    if (!user) { return self.fail(info); }
    self.success(user, info);
  }
  this._verify(req, apiKey, hmacValue, verified);
}

/**
 * Expose `Strategy`.
 */ 
module.exports = Strategy;
