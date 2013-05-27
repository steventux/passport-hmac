require('mocha');
require('should');
var passport = require('passport')
  , Strategy = require('./../lib/passport-hmac/strategy');

describe("HMAC Strategy", function() {

  describe("constructor", function() {

    it("should fail to initialize when no verify function is supplied", function(done){
      (function(){
        new Strategy();
      }).should.throw("hmac authentication strategy requires a verify function");
      done();
    });

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
    
    it("should succeed with an apiKey and a verify function", function(done){
      
      var strategy = new Strategy(function(key, callback){
        callback(null, { apiKey : '1a2b3c4d5e'});
      });
      
      strategy.success = function(user) {
        user.apiKey.should.equal('1a2b3c4d5e');
        done(null, user);
      }
      
      strategy.fail = function(info) {
        console.log("This should never happen"); 
        done(null, info);
      }
      
      strategy.authenticate({ body: { apiKey : '1a2b3c4d5e'} });
    });
  });

});
