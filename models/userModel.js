const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const crypto = require("crypto"); // lal 2esas l5afife whiyye built in bel nodejs

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
    passwordChangeAt: Date,
    passwordResetToken: String,
    passwordResetExpires: Date,
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

// this function will create a random reset token
userSchema.methods.generatePasswordResetToken = function(){
  const resetToken = crypto.randomBytes(32).toString("hex"); // will be sent via email

  // saved in the DB in a hashed way
  this.passwordResetToken = crypto
  .createHash("sha256")
  .update(resetToken)
  .digest("hex");

  // 10 min of validity
  this.passwordResetExpires = Date.now() + 10 * 60 * 1000;

  return resetToken;
}
module.exports = mongoose.model("User", userSchema);
