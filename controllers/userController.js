const User = require("../models/userModel");
const validator = require("validator");
const bcrypt = require("bcrypt");
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
