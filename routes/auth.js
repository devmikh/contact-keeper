const express = require("express");
const router = express.Router();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const config = require("config");
const auth = require("../middleware/auth");
const { check, validationResult } = require("express-validator");

const User = require("../models/User");

// @route     GET api/auth
// @desc      Get logged in user
// @access    Private
router.get("/", auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select("-password");
    res.json(user);
  } catch (err) {
    console.error(err.message);
    res.status(500).send("Server Error");
  }
});

// @route     POST api/auth
// @desc      Auth user & get token
// @access    Public
router.post(
  "/",
  [
    // Check request body for possible errors
    check("email", "Please include a valid email").isEmail(),
    check("password", "Password is required").exists()
  ],
  async (req, res) => {
    // If any errors exist, show them in the response
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    // Pull out variables from request body
    const { email, password } = req.body;

    try {
      // Find user with same email
      let user = await User.findOne({ email });

      // If there's no such user, respond with this message
      if (!user) {
        return res.status(400).json({ msg: "Invalid Credentials" });
      }

      // Compare entered password with password in a db and assign the boolean value to isMatch variable
      const isMatch = await bcrypt.compare(password, user.password);

      // If passwords don't match, respond with this message
      if (!isMatch) {
        return res.status(400).json({ msg: "Invalid Credentials" });
      }

      // Create payload which includes user's id
      const payload = {
        user: {
          id: user.id
        }
      };

      // Create json web token and send it as a response
      jwt.sign(
        payload,
        config.get("jwtSecret"),
        {
          expiresIn: 360000
        },
        (err, token) => {
          if (err) throw err;
          res.json({ token });
        }
      );
    } catch (err) {
      console.error(err.message);
      res.status(500).send("Server error");
    }
  }
);

module.exports = router;
