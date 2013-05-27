var passport = require('passport')
  , util = require('util');

function Strategy(options, verify) {
  if (typeof options == 'function') {
    verify = options;
    options = {};
  }

  if (!verify) throw new Error('hmac authentication strategy requires a verify function');

  this._apiKeyField = options.apiKeyField || 'apiKey';

  passport.Strategy.call(this);
  this.name = 'hmac';
  this._verify = verify;
  this._passReqToCallback = options.passReqToCallback;
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(Strategy, passport.Strategy);

Strategy.prototype.authenticate = function(req, options) {
  options = options || {};
  
  var apiKey = lookup(req.body, this._apiKeyField) || lookup(req.query, this._apiKeyField);
  if (!apiKey) {
    return this.fail(new Error(options.badRequestMessage || 'Missing API key'));
    // throw new Error('Missing API key');
  }

  var self = this;
  
  function verified(err, user, info) {
    if (err) { return self.error(err); }
    if (!user) { return self.fail(info); }
    self.success(user, info);
  }
  
  if (self._passReqToCallback) {
    this._verify(req, apiKey, verified);
  } else {
    this._verify(apiKey, verified);
  }
  
  function lookup(obj, field) {
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
}

/**
 * Expose `Strategy`.
 */ 
module.exports = Strategy;
