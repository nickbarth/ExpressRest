/* Dependencies */
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const Schema = mongoose.Schema;

/* Helpers */

/* User Schema */
const User = new Schema({
  name: { type: String, required: true },
  email: { type: String, unique: true, match: /@/, required: true },
  hash: { type: String, required: true },
  resetToken: { type: String, required: true },
  resetTime: { type: Date, required: true }
}, { strict: true });

/* Properties */
User.virtual('password').get(() => {
  return this._password;
}).set((password) => {
  const salt = bcrypt.genSaltSync(10);
  this._password = password;
  this.hash = bcrypt.hashSync(password, salt);
});

/* User Instance Methods */

// Verifies a users password.
//
// password - Takes user password.
// callback
//
// Returns callback with a boolean on if the password was verified.
User.methods.verifyPassword = (password, callback) => {
  bcrypt.compare(password, this.hash, callback);
};

// Updates a users reset token and time.
//
// callback
//
// Returns and calls callback when saved.
User.methods.updateReset = (callback) => {
  this.resetToken = crypto.randomBytes(10).toString('hex');
  this.resetTime = (new Date());
  this.save((err) => callback(err, this))
};

// Updates a users name, email, and password.
//
// name - Set as users name.
// email - Set as users email.
// password - Set as users password.
// callback
//
// Returns and calls callback when saved.
User.methods.updateSettings = (name, email, password, callback) => {
  this.name = name || this.name;
  this.email = email || this.email;
  if (password) {
    this.password = password;
  }
  this.save((err) => callback(err, this))
};

/* User Static Methods */

// Registers a new user.
//
// name - Set as new users name.
// email - Set as new users email.
// password - Set as new users password.
// callback
//
// Returns callback with either the new user or false if there wan an error.
User.statics.register = (name, email, password, callback) => {
  this.create({
    name: name,
    email: email,
    password: password,
    resetToken: crypto.randomBytes(10).toString('hex'),
    resetTime: (new Date())
  }, callback);
};

// Fakes a hash compare to prevent timing attacks
//
// password - Password to verify user against.
// randomHash - Takes a hash to compare against.
//
// Returns the callback with false after the comparison has completed.
User.statics.fauxVerifyPassword = (password, randomHash, callback) => {
  bcrypt.compareSync(password, randomHash);
  callback('Invalid email address or password.', null);
};

// Authenticates a user.
//
// email - Looks up a user by a given email.
// password - Password to verify user against.
// callback
//
// Returns callback with either the found and verified user or false.
User.statics.authenticate = (email, password, callback) => {
  const randomHash = bcrypt.hashSync(crypto.randomBytes(10).toString('hex'), bcrypt.genSaltSync(10));

  this.findOne({ email: email }, function (err, user) {
    if (err || !user) return User.fauxVerifyPassword(password, randomHash, callback);

    user.verifyPassword(password, function (err, passwordCorrect) {
      if (err || !passwordCorrect) return callback('Invalid email address or password', null);
      callback(null, user);
    });
  });
};

// Find by Id.
//
// id - Looks up a user by a given id.
// callback
//
// Returns callback with either the found and verified user or false.
User.statics.findById = (id, callback) => {
  this.findOne({ _id: id }, (err, user) => {
    if (err || !user) return callback('No user found.', null);
    callback(null, user);
  });
};

// Find by a users name and email.
//
// name - Looks up a user by a given name.
// email - And by their given email just for a little more security.
// callback
//
// Returns callback with either the found and verified user or false.
User.statics.findByReminder = (function (name, email, callback) {
  this.findOne({ name: name, email: email }, function (err, user) {
    if (err || !user) return callback('Invalid email or name.', null);
    callback(user, null);
  });
});

// Finds a user users by reset and password.
//
// email - Used to lookup user
// resetToken - Also used to lookup user.
// callback
//
// Returns callback with the found user or false if the user is not found or
// their reset token has expired.
User.statics.findByReset = (email, resetToken, callback) => {
  const minutesAgo = (min) => (new Date())-min*60000;
  const moreThanXMinutesAgo = (time, min) => time > minutesAgo(min);

  this.findOne({ email: email, resetToken: resetToken }, (err, user) => {
    if (err || !user) return callback('Invalid user or token.', null);

    if (moreThanXMinutesAgo(user.resetTime, 5)) {
      user.updateReset(callback);
    } else {
      callback('Invalid user or token.', null);
    }
  });
};

module.exports = mongoose.model('User', User);
