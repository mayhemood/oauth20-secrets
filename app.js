require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const { Pool } = require("pg");
const bcrypt = require("bcrypt");
const session = require("express-session");
const flash = require('connect-flash');
const GoogleStrategy = require("passport-google-oauth20").Strategy; 
const saltRounds = parseInt(process.env.SALT_ROUNDS);


const app = express();

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));

const pool = new Pool({
  user: process.env.PG_USER,
  host: process.env.PG_HOST,
  database: process.env.PG_DATABASE,
  password: process.env.PG_PASSWORD,
  port: process.env.PG_PORT,
});

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    expires: false, 
    httpOnly: true, 
  }
}));

app.use(passport.initialize());
app.use(passport.session());
app.use(flash());

passport.use(new LocalStrategy((username, password, done) => {
  const findUserQuery = `
    SELECT * FROM users
    WHERE email = $1;
  `;

  pool.query(findUserQuery, [username], (err, result) => {
    if (err) {
      return done(err);
    } else {
      const foundUser = result.rows[0];
      if (foundUser) {
        bcrypt.compare(password, foundUser.password, (err, result) => {
          if (result) {
            return done(null, foundUser);
          } else {
            return done(null, false, { message: "Incorrect password." });
          }
        });
      } else {
        return done(null, false, { message: "User not found." });
      }
    }
  });
}));

passport.use(new GoogleStrategy({
  clientID: process.env.CLIENT_ID,
  clientSecret: process.env.CLIENT_SECRET,
  callbackURL: "http://localhost:3000/auth/google/secrets"
},
async function (accessToken, refreshToken, profile, done) {
  try {
    if (!profile || !profile.emails || profile.emails.length === 0) {
      return done(new Error('Invalid Google profile'));
    }

    let lastGoogleId = 0;
    function generateUniqueEmail() {
      lastGoogleId++;
      return `user${lastGoogleId}@googleauth.com`;
    }

    const userEmail = generateUniqueEmail();
    const googleId = profile.id;

    const result = await pool.query('SELECT * FROM users WHERE email = $1', [userEmail]);

    if (result.rows.length > 0) {
      const user = result.rows[0];
      return done(null, user);
    } else {
      const newUser = {
        email: userEmail,
        password: "******",
      };

      const insertUserQuery = `
        INSERT INTO users (email, password, googleid)
        VALUES ($1, $2, $3)
        RETURNING *;
      `;

      const values = [newUser.email, newUser.password, googleId];

      const insertResult = await pool.query(insertUserQuery, values);

      const user = insertResult.rows[0];
      return done(null, user);
    }
  } catch (error) {
    return done(error);
  }
}));


passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser((id, done) => {
  const findUserByIdQuery = `
    SELECT * FROM users
    WHERE id = $1;
  `;

  pool.query(findUserByIdQuery, [id], (err, result) => {
    if (err) {
      return done(err);
    } else {
      const user = result.rows[0];
      return done(null, user);
    }
  });
});

app.get("/", (req, res) => {
  res.render("home", { user: req.user });
});

app.get("/login", (req, res) => {
  const errorMessages = req.flash("error");

  res.render("login", { errorMessages });
});

app.post("/login", passport.authenticate("local", {
  successRedirect: "/secrets",
  failureRedirect: "/login",
  failureFlash: true
}));

app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/auth/google/secrets',passport.authenticate('google', { failureRedirect: '/login' }),
  function (req, res) {
    res.redirect("/secrets");
  }
);

app.get("/register", (req, res) => {
  res.render("register", { error: null });
});

app.post("/register", async (req, res) => {
  const email = req.body.username;

  try {
    const userExists = await pool.query('SELECT * FROM users WHERE email = $1', [email]);

    if (userExists.rows.length > 0) {
      return res.render('register', { error: 'Email already registered. Choose another email.' });
    }

    const hash = await bcrypt.hash(req.body.password, saltRounds);

    const newUser = {
      email: email,
      password: hash
    };

    const result = await pool.query('INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *;', [newUser.email, newUser.password]);

    console.log('User registered:', result.rows[0]);

    req.login(result.rows[0], (err) => {
      if (err) {
        console.error('Error during login after registration', err);
        return res.status(500).send('Internal Server Error: ' + err.message);
      }
      return res.redirect("/secrets");
    });
  } catch (error) {
    console.error('Unexpected error in registration', error);
    return res.status(500).send('Internal Server Error: ' + error.message);
  }
});


app.get("/logout", (req, res) => {
  req.logout(function(err) {
    if (err) {
      console.error("Error during logout:", err);
      return res.redirect("/");
    }
    res.redirect("/");
  });
});

app.get("/secrets", async (req, res) => {
  try {
    let secrets = [];

    // Check if the user is authenticated
    if (req.isAuthenticated()) {
      // Get all secrets from the database
      const secretsQuery = `
        SELECT secrets.*, users.email
        FROM secrets
        JOIN users ON secrets.user_id = users.id;
      `;

      const result = await pool.query(secretsQuery);

      secrets = result.rows;
    } else {
      req.flash('error', 'Please log in to view secrets');
      return res.redirect("/login");
    }

    res.render("secrets", { user: req.user, secrets });
  } catch (error) {
    console.error('Error fetching secrets', error);
    res.status(500).send('Internal Server Error: ' + error.message);
  }
});

app.get("/submit", (req, res) => {
  if (req.isAuthenticated()) {
    res.render("submit", { user: req.user });
  } else {
    req.flash('error', 'Please log in to view secrets');
    res.redirect("/login");
  }
});

app.post("/submit", async (req, res) => {
  try {
    const { secret } = req.body;
    
    // Check if the user is authenticated
    if (req.isAuthenticated()) {
      const userId = req.user.id;

      // Insert the secret into the database
      const insertSecretQuery = `
        INSERT INTO secrets (secret, user_id)
        VALUES ($1, $2)
        RETURNING *;
      `;

      const values = [secret, userId];

      const result = await pool.query(insertSecretQuery, values);

      console.log('Secret submitted:', result.rows[0]);
      res.redirect("/secrets");
    } else {
      // User is not authenticated, handle accordingly
      res.redirect("/login");
    }
  } catch (error) {
    console.error('Error submitting secret', error);
    res.status(500).send('Internal Server Error');
  }
});

app.listen(3000, () => {
  console.log("Server started at port 3000");
});