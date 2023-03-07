const User = require("../models/userModel");
const validator = require("validator");
const bcrypt = require("bcrypt");
const sendMail = require("../utils/email");
const crypto = require("crypto");
exports.signUp = async (req, res) => {
  try {
    //1- check if the email entered is valid
    let email = req.body.email;
    if (!validator.isEmail(email)) {
      return res.status(400).json({ message: "Invalid email" });
    }
    // 2- check if the email is already in use
    const checkEmail = await User.findOne({ email: req.body.email });
    if (checkEmail) {
      return res.status(409).json({ message: "Email already in use" });
    }
    //3 - check if the password & password confirm are the same
    let pass = req.body.password;
    let passConfirm = req.body.passwordConfirm;

    if (pass !== passConfirm) {
      return res
        .status(400)
        .json({ message: "password and passwordConfirm are not the same" });
    }

    //const hashedPassword = await bcrypt.hash(pass, 12);
    // create the new user
    const newUser = await User.create({
      fullName: req.body.fullName,
      email: req.body.email,
      password: req.body.password,
    });
    return res
      .status(201)
      .json({ message: "User created successfully", data: { newUser } });
    // if everything is ok , we created the new user
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
};

exports.login = async (req, res) => {
  try {
    //1: check if the user email exist in the DB
    const user = await User.findOne({ email: req.body.email });
    if (!user) {
      return res.status(404).json({ message: "the user does not exist" });
    }
    //2: check if the entered password is matching with the hashed stored password
    if (!(await user.checkPassword(req.body.password, user.password))) {
      return res.status(401).json({ message: "incorrect email or password" });
    }
    //3: if everything is ok, log the user in
    return res.status(200).json({ message: "you are logged in successfully" });
  } catch (err) {
    console.log(err);
  }
};

exports.forgotPassword = async (req, res) => {
  try {
    // 1- check if the user withthe provided email exist
    const user = await User.findOne({ email: req.body.email });
    if (!user) {
      return res
        .status(404)
        .json({ message: "the user with the provided email does not exist." });
    }
    // 2- create the reset token to be sended via email
    const resetToken = user.generatePasswordResetToken();
    await user.save({ validateBeforeSave: false });

    // 3- send the token via email
    // http://127.0.0.1:3000/api/auth/resetPassword/dnksnsdfnhaydnaskjnasdn
    //3.1 : create this url

    const url = `${req.protocol}://${req.get(
      "host"
    )}/api/auth/resetPassword/${resetToken}`;

    const msg = `Forgot your password? Reset it by visiting the following link: ${url}`;

    // hon 3melne trycatch jdide b2alb haydik trycatch . leh? lsabab houwwe anno nahna hon ra7 neb3at l email fa yemkin hayda lemail ye5la2lna mechkil bass la2anno hon 3amna3mel await inside await fa mna3mella trycatch wa7da 7atta ma t2asser 3a chi lli akbar menna
    try {
      await sendMail({
        email: user.email,
        subject: "your password reset token: (valid for 10 min)",
        message: msg,
      });
      res.status(200).json({
        status: "success",
        message: "the reset link was delivered to your email successful",
      });
    } catch (error) {
      user.passwordResetToken = undefined;
      user.passwordResetExpires = undefined;
      await user.save({ validateBeforeSave: false });

      res.status(500).json({
        message:
          "an error occured while sending the email, please try again in a moment",
      });
    }
  } catch (err) {
    console.log(err);
  }
};

exports.resetPassword = async (req, res) => {
  try {
    const hashedToken = crypto
      .createHash("sha256")
      .update(req.params.token)
      .digest("hex");

    const user = await User.findOne({
      passwordResetToken: hashedToken,
      passwordResetExpires: { $gt: Date.now() },
    });

    if (!user) {
      return res.status(400).json({
        message: "the token is invalid, or expired. please request a new one",
      });
    }

    if (req.body.password.length < 8) {
      return res.status(400).json({ message: "password length is too short" });
    }

    if (req.body.password !== req.body.passwordConfirm) {
      return res
        .status(400)
        .json({ message: "password & password Confirm are not the same " });
    }

    user.password = req.body.password;
    user.passwordConfirm = req.body.passwordConfirm;
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    user.passwordChangeAt = Date.now();
    await user.save();

    return res.status(200).json({ message: "password changed successfully" });
  } catch (err) {
    console.log(err);
  }
};
