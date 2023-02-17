import  { createRequire } from "module";
const require=createRequire(import.meta.url);
require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const MemoryStore = require('memorystore')(session)
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const findOrCreate = require("mongoose-findorcreate");
import fetch from 'node-fetch';
const app = express();

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({
  cookie: { maxAge: 86400000 },
    store: new MemoryStore({
      checkPeriod: 86400000 // prune expired entries every 24h
    }),
    secret: "This is my Secret",
    resave: false,
    saveUninitialized: false,
  })
);
app.use(passport.initialize());
app.use(passport.session());
mongoose.set("strictQuery", false);
const url=process.env.DB_URL;
mongoose.connect(url, { useNewUrlParser: true });
const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  secret: String,
});
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);
const User = mongoose.model("User", userSchema);
passport.use(User.createStrategy());
passport.serializeUser(function (user, done) {
  done(null, user.id);
});

passport.deserializeUser(function (id, done) {
  User.findById(id, function (err, user) {
    done(err, user);
  });
});

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.CLIENT_ID,
      clientSecret: process.env.CLIENT_SECRET,
      callbackURL: "https://secrets-23pe.onrender.com/auth/google/secrets",
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    },
    function (accessToken, refreshToken, profile, cb) {
      User.findOrCreate(
        { googleId: profile.id, username: profile.id },
        function (err, user) {
          return cb(err, user);
        }
      );
    }
  )
);

app.get("/", function (req, res) {
  res.render("home");
});
app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile"] })
);
app.get(
  "/auth/google/secrets",
  passport.authenticate("google", { failureRedirect: "/login" }),
  function (req, res) {
    // Successful authentication, redirect to secrets.
    res.redirect("/secrets");
  }
);

app.get("/login", function (req, res) {
  res.render("login");
});
app.get("/register", function (req, res) {
  res.render("register");
});
app.get("/secrets", function (req, res) {
  User.find({ secret: { $ne: null } }, function (err, foundUsers) {
    if (err) {
      console.log(err);
    } else {
      if (foundUsers) {
        res.render("secrets", { usersWithSecret: foundUsers });
      }
    }
  });
});
app.get("/submit", function (req, res) {
  if (req.isAuthenticated()) {
    res.render("submit");
  } else {
    res.redirect("/login");
  }
});

app.get("/logout", function (req, res) {
  req.logout(function (err) {
    if (err) {
      console.log(err);
    } else {
      res.redirect("/");
    }
  });
});
const secretKey=process.env.SECRET_KEY;
app.post("/register", function (req, res){
  const resKey = req.body['g-recaptcha-response'];
  const url = `https://www.google.com/recaptcha/api/siteverify?secret=${secretKey}&response=${resKey}`

  fetch(url, {
    method: 'post',
  })
    .then((response) => response.json())
    .then((google_response) => {
      if (google_response.success == true) {
        User.register(
          { username: req.body.username },
          req.body.password,
          function (err, user) {
            if (err) {
              console.log(err);
              res.redirect("/register");
            } else {
              passport.authenticate("local")(req, res, function () {
                res.redirect("/secrets");
              });
            }
          }
        );
      } else {
        res.redirect("/");
      }
    })
    .catch((error) => {
      return res.json({ error });
    });
});
app.post("/submit", function (req, res) {
  const submitSecret = req.body.secret;
  User.findById(req.user._id, function (err, foundUser) {
    if (err) {
      console.log(err);
    } else {
      if (foundUser) {
      foundUser.secret = submitSecret;
      foundUser.save(function () {
        res.redirect("/secrets");
      });
    }
    }
  });
});
app.post("/login", function (req, res) {
  const resKey = req.body['g-recaptcha-response'];
  const url = `https://www.google.com/recaptcha/api/siteverify?secret=${secretKey}&response=${resKey}`

  fetch(url, {
    method: 'post',
  })
    .then((response) => response.json())
    .then((google_response) => {
      if (google_response.success == true) {
        const user = new User({
          username: req.body.username,
          password: req.body.password,
        });
        req.login(user, function (err) {
          if (err) {
            console.log(err);
          } else {
            passport.authenticate("local")(req, res, function () {
              res.redirect("/secrets");
            });
          }
        });
      } else {
        res.redirect("/");
      }
    })
    .catch((error) => {
      return res.json({ error });
    });
  
});
const port=process.env.PORT || 3000;
app.listen(port, function () {
  console.log("Server started");
});
