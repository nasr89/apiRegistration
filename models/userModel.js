const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const userSchema = new mongoose.Schema(
  {
    fullName: {
      type: String,
      required: [true, "please enter your fullname"],
      trim: true,
    },
    email: {
      type: String,
      required: [true, "please enter your email"],
      trim: true,
      unique: true,
      lowercase: true,
    },
    password: {
      type: String,
      trim: true,
      minLength: 8,
      maxLength: 30,
    },
    passwordConfirm: {
      type: String,
      trim: true,
      minLength: 8,
      maxLength: 30,
    },
  },
  { timestamps: true }
);

// automated function
userSchema.pre("save", async function (next) {
  try {
    if (!this.isModified("password")) {
      return next();
    }

    this.password = await bcrypt.hash(this.password, 12);
    this.passwordConfirm = undefined;
  } catch (err) {
    console.log(err);
  }
});

// this function wil always return 1 value: true or false
userSchema.methods.checkPassword = async function (
  candidatePassword, //coming from the front end as a plain text
  userPassword // coming from the database as a hashed value
) {
  return await bcrypt.compare(candidatePassword, userPassword);
};

module.exports = mongoose.model("User", userSchema);
