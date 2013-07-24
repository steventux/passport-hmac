require('mocha');
require('should');
var passport = require('passport')
  , Strategy = require('./../lib/passport-hmac/strategy');

describe("HMAC Strategy", function() {

  describe("constructor", function() {

    it("should have a name", function(done){
      new Strategy(function(){}).name.should.equal('hmac');
      done();
    });
    
    it("should fallback to the default apiKey field", function(done){
      new Strategy(function(){})._apiKeyField.should.equal('apiKey');
      done();
    });
    
    it("should use the apiKey field when specified", function(done){
      new Strategy({apiKeyField: 'myFunkyField'}, function(){})._apiKeyField.should.equal('myFunkyField');
      done();
    });

    it("should assign a verify function", function(done){
      var myVerify = function(){};
      new Strategy(myVerify)._verify.should.equal(myVerify);
      done();
    });

  });

  describe("authenticate", function(){
    it("should fail with no apiKey value", function(done){
      
      var strategy = new Strategy(function(){});
      
      strategy.success = function(user) {
        this.test.error("This should never happen");
      }
      
      strategy.fail = function(info) {
        info.toString().should.equal('Error: Missing API key')
        done(null, info);
      }
      
      strategy.authenticate("");
    });
    
    it("should fail with no HMAC value", function(done){
      
      var strategy = new Strategy(function(){});
      
      strategy.success = function(user) {
        this.test.error("This should never happen");
      }
      
      strategy.fail = function(info) {
        info.toString().should.equal('Error: Missing HMAC value')
        done(null, info);
      }
      
      strategy.authenticate({ body : { apiKey : '1a2b3c4d5e'} });
    });
    
    it("should succeed with an apiKey and a verify function", function(done){
      
      var strategy = new Strategy(function(req, key, hmacStr, verified){
        verified(null, {apiKey: '1a2b3c4d5e'});
      });
      
      strategy.success = function(user) {
        user.apiKey.should.equal('1a2b3c4d5e');
        done(null, user);
      }
      
      strategy.fail = function(info) {
        throw new Error("This should never happen"); 
      }
      
      strategy.authenticate(
        { body: { apiKey : '1a2b3c4d5e', hmacValue: 'b342b3l2b352b35'}});
    });
  });

});
