const express = require("express");
const mongoose = require("mongoose");
const nodemailer = require("nodemailer");
require("dotenv").config();
const User = require("./models/User");
const expressLayout = require("express-ejs-layouts");
const path = require("path");
const bcrypt = require("bcrypt");
const session = require("express-session");
const jwt = require("jsonwebtoken");
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

//forgot password page
app.get("/forgot-password", async (req, res) => {
  res.render("forgot-password");
});

//forgot password logic
app.post("/forgot-password", async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email });
    if (!user) {
      return res.render("forgot-password", {
        error: "No account found for this email",
        email,
      });
    }
    //generate reset token
    const resetToken = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
      expiresIn: "1hr",
    });
    //save token to user
    user.resetPasswordToken = resetToken;
    user.resetPasswordExpire = Date.now() + 3600000; //1hr
    await user.save();
    //generate reset url
    const resetUrl = `http://${req.headers.host}/reset-password/${resetToken}`;
    //send mail
    const mailOptions = {
      to: user.email,
      subject: "Password reset",
      html: `
      <h2>Password reset request</h2>
      <p>You requested password reset. Click below link to reset the password</p>
      <a href="${resetUrl}">${resetUrl}</a>
      <p>This link will expire in 1 hour</p>`,
    };
    await transporter.sendMail(mailOptions);
    res.render("forgot-password", {
      success: "Password reset email sent. Please check your inbox",
    });
  } catch (error) {
    res.render("forgot-password", {
      error: "Error processing request. Please try again",
      email: req.body.email,
    });
  }
});

//reset password form page
app.get("/reset-password/:token", async (req, res) => {
  res.render("reset-password", { token: req.params.token });
});

//reset password logic
app.post("/reset-password/:token", async (req, res) => {
  try {
    const { password, confirmPassword } = req.body;
    const { token } = req.params;
    if (password !== confirmPassword) {
      return res.render("reset-password", {
        token,
        error: "Password do not match",
      });
    }

    //decode token
    const decodedToken = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findOne({
      _id: decodedToken.id,
      resetPasswordToken: token,
      resetPasswordExpire: { $gt: Date.now() },
    });
    if (!user) {
      return res.render("reset-password", {
        token,
        error: "Invalid or expired token. Please request new password reset",
      });
    }
    //update new password
    const newPassword = await bcrypt.hash(password, 10);
    user.password = newPassword;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpire = undefined;
    await user.save();
    res.render("reset-password", {
      token,
      success:
        "Password has been reset successfully!. Please login with new password",
    });
  } catch (error) {
    res.render(
      "reset-password",
      { token: req.params.token },
      {
        error: "Error resetting password. Please try again",
      },
    );
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
