const express = require("express");
const router = express.Router();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const config = require("config");
const { check, validationResult } = require("express-validator");

const User = require("../models/User");

// @route     POST api/users
// @desc      Register a user
// @access    Public
router.post(
  "/",
  [
    // Check request body for possible errors
    check("name", "Please add a name")
      .not()
      .isEmpty(),
    check("email", "Please include a valid email").isEmail(),
    check(
      "password",
      "Please enter a password with 6 or more characters"
    ).isLength({ min: 6 })
  ],
  async (req, res) => {
    // If any errors exist, show them in the response
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    // Pull out variables from request body
    const { name, email, password } = req.body;

    try {
      // Find user with same email
      let user = await User.findOne({ email });

      // If such user exists, respond with this message
      if (user) {
        return res.status(400).json({ msg: "User already exists" });
      }

      // If such user doesn't exists, create new user with these credentials
      user = new User({
        name,
        email,
        password
      });

      // Create salt for hashing
      const salt = await bcrypt.genSalt(10);

      // Assign encrypted password instead of the literal one
      user.password = await bcrypt.hash(password, salt);

      // Add user to the db
      await user.save();

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
      res.status(500).send("Server Error");
    }
  }
);

module.exports = router;
