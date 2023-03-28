const express = require("express");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");

const app = express();

app.use(express.json());

mongoose
  .connect("mongodb://localhost:27017/income-expense", {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("Connected to MongoDB"))
  .catch((err) => console.error(err));

const userSchema = new mongoose.Schema({
  username: String,
  password: String,
});

const User = mongoose.model("User", userSchema);

const secret = "mysecretkey";

app.post("/api/register", async (req, res) => {
  const { username, password } = req.body;

  const existingUser = await User.findOne({ username });

  if (existingUser) {
    return res.status(409).json({ message: "Username already exists" });
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  const user = new User({ username, password: hashedPassword });

  await user.save();

  res.json({ message: "User registered successfully" });
});

app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;

  const user = await User.findOne({ username });

  if (!user) {
    return res.status(401).json({ message: "Invalid username or password" });
  }

  const match = await bcrypt.compare(password, user.password);

  if (!match) {
    return res.status(401).json({ message: "Invalid username or password" });
  }

  const token = jwt.sign({ id: user._id }, secret, { expiresIn: "1h" });

  res.json({ token });
});

function authenticate(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return res.status(401).json({ message: "Missing authorization header" });
  }

  const [type, token] = authHeader.split(" ");

  if (type !== "Bearer") {
    return res.status(401).json({ message: "Invalid authorization header" });
  }

  try {
    const decoded = jwt.verify(token, secret);

    req.userId = decoded.id;

    next();
  } catch (err) {
    return res.status(401).json({ message: "Invalid or expired token" });
  }
}

app.get("/api/logout", authenticate, (req, res) => {
  res.json({ message: "Logged out successfully" });
});

const expenseSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  description: String,
  amount: Number,
  date: { type: Date, default: Date.now },
});

const Expense = mongoose.model("Expense", expenseSchema);

app.get("/api/expenses", authenticate, async (req, res) => {
  const expenses = await Expense.find({ user: req.userId });

  res.json({ expenses });
});

app.post("/api/expenses", authenticate, async (req, res) => {
  const { description, amount } = req.body;
});
