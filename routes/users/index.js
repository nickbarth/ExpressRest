// Dependencies
const express = require("express");
const router = express.Router();

// Models
const Mailer = require("../../models/extensions/mailer");
const User = require("../../models/users");

/* Auth Middleware */

// Authenticate user.
//
// Returns an error if not signed in.
const authenticate = ((req, res, next) => {
  if (!req.session.userId) {
    res.status(403);
    res.send("Please login to access this page.");
  } else {
    next();
  }
});

// Sets CSRF token.
//
// Sets the csrf token so it can be used for CSRF form protection.
router.use((req, res, next) => {
  res.locals.csrf = req.session._csrf;
  next();
});

// Sets current user.
//
// Sets the current user variable for views.
router.use((req, res, next) => {
  res.locals.currentUser = null;
  if (!req.session.userId) return next();

  User.findById(req.session.userId, (err, user) => {
    res.locals.currentUser = user;
    next();
  });
});

router.get("/me", authenticate, (req, res) => {
  User.findById(req.session.userId, (err, user) => {
    res.json({ "error": err, "user": user });
  });
});

router.put("/me", authenticate, (req, res) => {
  User.findById(req.session.userId, (err, user) => {
    if (err) return res.json({ "error": err, "user": null });

    user.updateSettings(req.body.name, req.body.email, req.body.password, (err, user) => {
      res.json({ "error": err, "user": user });
    });
  });
});

router.post("/signup", (req, res) => {
  User.register(req.body.name, req.body.email, req.body.password, (err, user) => {
    if (err || !user) return res.json({ "error": "Invalid email or password.", "user": null });

    Mailer(user).sendWelcomeMessage();
    req.session.userId = user._id;
    res.json({ "error": null, "user": user });
  });
});

router.post("/login", (req, res) => {
  User.authenticate(req.body.email, req.body.password, (err, user) => {
    if (err || !user) return res.json({ "error": "Invalid email or password.", "user": null });
    req.session.userId = user._id;
    res.json({ "error": null, "user": user });
  });
});

router.get("/logout", (req, res) => {
  req.session.userId = undefined;
  res.json({ "error": null, "user": null });
});

router.get("/reset/:email/:reset_token", authenticate, (req, res) => {
  User.findByReset(req.params.email, req.params.resetToken, (err, user) => {
    if (err) return res.json({ "error": err, "user": null });
    req.session.userId = user._id;
    res.json({ "error": null, "user": user });
  });
});

router.post("/reminder", (req, res) => {
  User.findByReminder(req.body.name, req.body.email, (err, user) => {
    if (err) return res.json({ "error": err, "user": null });
    user.updateReset();
    Mailer(user).sendPasswordReset();
    res.json({ "error": null, "user": user });
  });
});

router.post("/reset", (req, res) => {
  User.findById(req.session.userId, (err, user) => {
    if (err) return res.json({ "error": err, "user": null });

    user.updateSettings(user.name, user.email, req.body.password, (err, user) => {
      if (err) return res.json({ "error": err, "user": null });
      res.json({ "error": null, "user": user });
    });
  });
});

router.authenticate = authenticate;
module.exports = router
