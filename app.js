//jshint esversion:6
require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const app = express();
const mongoose = require("mongoose");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
mongoose.set("strictQuery", true);
const bcrypt = require("bcrypt");
const saltRounds = 10;
app.use(express.static("public"));
app.use(bodyParser.urlencoded({ extended: true }));
app.set("view engine", "ejs");
app.use(cookieParser());

mongoose.connect("mongodb://localhost:27017/userdb");

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
});
const User = mongoose.model("User", userSchema);
// const cookies = new Cookies();
app.get("/", function (req, res) {
  res.render("home");
});
//=======================register============================
app.get("/register", function (req, res) {
  res.render("register");
});
app.post("/register", function (req, res) {
  bcrypt.hash(req.body.password, saltRounds, function (err, hash) {
    const newUser = new User({
      email: req.body.username,
      password: hash,
    });
    newUser.save(function (err) {
      if (!err) {
        res.render("secrets");
      }
    });
  });
});

//=========================login=================================
app.get("/login", function (req, res) {
  const token = req.cookies.jwt;
  if (token) {
    const decoded = jwt.verify(token, process.env.SECRET);
    User.findOne({ email: decoded.username }, function (err, found) {
      if (!err) {
        if (found) {
          if (decoded.username === found.email);
          res.render("secrets");
        }
      }
    });
  } else {
    res.render("login");
  }
});
app.post("/login", function (req, res) {
  const username = req.body.username;
  const password = req.body.password;
  User.findOne({ email: username }, function (err, foundUser) {
    if (!err) {
      if (foundUser) {
        bcrypt.compare(password, foundUser.password, function (err, result) {
          if (result) {
            const coupon = jwt.sign({ username: username }, process.env.SECRET);
            res.cookie("jwt", coupon, { maxAge: 300000 });
            res.render("secrets");
          }
        });
      }
    }
  });
});

//=======================secrets=================================
app.get("/secrets", function (req, res) {
  res.redirect("/login");
});

//=========================logout================================
app.get("/logout", function (req, res) {
  res.clearCookie("jwt");
  res.redirect("/");
});
//===========================submit==============================
app.get("/submit", function (req, res) {
  res.render("submit");
});
//==========================submit_now===========================
app.get("/submit_now", function (req, res) {
  res.render("submit_now");
});



app.listen(3000, function () {
  console.log("server started on port 3000");
});
