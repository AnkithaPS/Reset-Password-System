const express = require("express");
const mongoose = require("mongoose");
const nodemailer = require("nodemailer");
require("dotenv").config();
const User = require("./models/User");
const expressLayout = require("express-ejs-layouts");
const path = require("path");
const bcrypt = require("bcrypt");
const session = require("express-session");
const MongoStore = require("connect-mongo").default;
const app = express();

//Email transporter
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PaSS,
  },
});
//middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
//authentication middleware
const authenticate = async (req, res, next) => {
  if (req.session.userId) {
    return next();
  } else {
    res.redirect("/login");
  }
};
//session middleware
app.use(
  session({
    secret: process.env.JWT_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: process.env.NODE_ENV === "production",
      maxAge: 24 * 60 * 60 * 1000, //24hr
    },
    store: MongoStore.create({
      mongoUrl: process.env.MONGODB_URI,
      ttl: 24 * 60 * 60, //24hr
    }),
  }),
);

//view engine setup
app.use(expressLayout);
app.set("layout", "layout");
app.set("layout extractScript", true);
app.set("layout extractStyles", true);
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

//connect to database
mongoose
  .connect(process.env.MONGODB_URI)
  .then(() => {
    console.log("Mongodb connected");
  })
  .catch((err) => {
    console.log(`Failed to connect to mongodb: ${err.message}`);
  });

//Routes
//home page
app.get("/", async (req, res) => {
  res.render("index");
});

//login page
app.get("/login", async (req, res) => {
  if (req.session.userId) {
    return res.redirect("/dashboard");
  }
  res.render("login");
});

//login logic
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    //find user by email
    const user = await User.findOne({ email });
    if (!user) {
      return res.render("login", { error: "Invalid email/password", email });
    }
    //compare password

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.render("login", { error: "Password doesn't match!", email });
    }
    //Set session
    req.session.userId = user._id;
    //redirect
    return res.redirect("/dashboard");
  } catch (error) {}
  res.render("error", {
    error: "Error during login. Please try again",
    email: req.body.email,
  });
});

//register form page
app.get("/register", async (req, res) => {
  res.render("register");
});

//register logic
app.post("/register", async (req, res) => {
  try {
    const { email, password, confirmPassword } = req.body;
    if (password !== confirmPassword) {
      res.render("register", { error: "Password do not match", email });
    }
    //check if user exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      res.render("register", { error: "Email is already exists", email });
    }
    //Hash password
    const hashedPassword = await bcrypt.hash(password, 10);
    //create user
    const user = await User.create({
      email,
      password: hashedPassword,
    });
    //send email
    const mailOptions = {
      to: user.email,
      subject: "Welcome to password reset system",
      html: `
  <h2>Welcome to Password Reset System</h2>
  <p>Your account has been successfully created.</p>
   <p>If you ever forget your password,you can use our password reset system</p>
  `,
    };
    await transporter.sendMail(mailOptions);
    res.render("register", { success: "Registration successful!" });
  } catch (error) {
    res.render("error", {
      error: "Error during registration. Please try again",
      email: req.body.email,
    });
  }
});

//dashboard page
app.get("/dashboard", authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.session.userId);
    res.render("dashboard", { user });
  } catch (error) {
    res.render("error", {
      error: "Error",
    });
  }
});

//logout
app.get("/logout", async (req, res) => {
  req.session.destroy((error) => {
    if (error) {
      console.log("Error logout", error);
    }
  });
  res.redirect("/login");
});
//Start the server
const PORT = process.env.PORT;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
