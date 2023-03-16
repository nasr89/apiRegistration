const express = require("express");

const app = express();

const DB = require("./database").connectDB;

// Routes
const authRouter = require("./routes/authRoutes");
const userRouter = require("./routes/userRoutes");
// connect to our DB
DB();

app.use(express.json());
app.use("/api/auth", authRouter);
app.use("/api/users", userRouter);

app.listen(process.env.PORT, () => {
  console.log(`listening on port : ${process.env.PORT}`);
});
