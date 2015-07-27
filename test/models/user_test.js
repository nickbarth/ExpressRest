/* Dependencies */
const mongoose = require("mongoose");
const assert = require('assert');
const User = require("../../models/users");

describe("User", () => {
  var testUser;

  before((done) => {
    mongoose.connect("mongodb://localhost/test", { safe: true }, done);
  });

  after((done) => {
    mongoose.connection.close(done);
  });

  beforeEach((done) => {
    User.register("john doe", "john.doe@example.com", "password", (err, user) => {
      testUser = user;
      done();
    });
  });

  afterEach((done) => {
    User.remove({}, () => done());
  });

  describe("static method", () => {
    describe("#register", () => {
      it("registers a new user", function (done) {
        User.register("jane doe", "jane.doe@example.com", "password", function (err, user) {
          assert.equal(null, err);
          assert.equal('object', typeof user);
          assert.equal('jane.doe@example.com', user.email);
          done();
        });
      });
      it("fails on invalid emails", function (done) {
        User.register("john doe", "john.doeexample.com", "password", function (err, user) {
          assert.equal(null, err);
          done();
        });
      });
      it("fails on nonunique emails", (done) => {
        User.register("john doe", "john.doe@example.com", "password", (err, user) => {
          should(user).be.null;
          done();
        });
      });
    });
    describe("#findByReset", () => {
      it("finds a user by their reset token and email", (done) => {
        User.findByReset(testUser.email, testUser.resetToken, (err, user) => {
          user.email.should.equal("john.doe@example.com");
          user.resetToken.should.not.equal(testUser.resetToken);
          done();
        });
      });
      it("fails if resetTime is more than 5 minutes ago", (done) => {
        testUser.resetTime = (new Date()) - (5*60000);
        testUser.save(function (err) {
          User.findByReset(testUser.email, testUser.resetToken, (err, user) => {
            user.should.equal(null);
            done();
          });
        });
      });
    });
    describe("#authenticate", () => {
      it("returns user with valid login", (done) => {
        User.authenticate(testUser.email, "password", (err, user) => {
          user.email.should.equal("john.doe@example.com");
          done();
        });
      });
      it("fails with invalid login", (done) => {
        User.authenticate(testUser.email, "invalid_password", (err, user) => {
          user.should.equal(null);
          done();
        });
      });
    });
  });

  describe("instance method", () => {
    describe("#updateSettings", () => {
      it("returns true with successful update", (done) => {
        testUser.updateSettings("new name", "new.email@example.com", "new password", () => {
          testUser.name.should.equal("new name");
          testUser.email.should.equal("new.email@example.com");
          testUser.verifyPassword("new password", (err, passwordCorrect) => {
            passwordCorrect.should.equal(true);
            done();
          });
        });
      });
      it("fails with invalid data", (done) => {
        testUser.updateSettings("", "", "", () => {
          testUser.name.should.equal("john doe");
          testUser.email.should.equal("john.doe@example.com");
          testUser.verifyPassword("", (err, passwordCorrect) => {
            passwordCorrect.should.equal(false);
            done();
          });
          done();
        });
      });
    });
  });
});
