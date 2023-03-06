const mongoose = require("mongoose");
const dotenv = require("dotenv");
mongoose.set("strictQuery", true);

dotenv.config();

exports.connectDB = async () => {
  // trycatch : error handling method
  try {
    await mongoose.connect(process.env.DB_URL);
    console.log("connect to the database");
  } catch (err) {
    console.log(err);
    process.exit(1);
  }
};
