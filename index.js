const express = require("express");

const app = express();

const DB = require("./database").connectDB;

// Routes
const authRouter = require("./routes/authRoutes");
// connect to our DB
DB();

app.use(express.json());
app.use("/api/auth", authRouter);

app.listen(process.env.PORT, () => {
  console.log(`listening on port : ${process.env.PORT}`);
});
