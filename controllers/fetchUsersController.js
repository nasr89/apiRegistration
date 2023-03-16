const User = require("../models/userModel");

exports.getAllUsers = async (req, res) => {
  try {
    const users = await User.find();
    if (users.length > 0) {
      return res.status(200).json(users);
    } else {
      return res
        .status(404)
        .json({ message: "Users does not exist in the DB" });
    }
  } catch (err) {}
};
