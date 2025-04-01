require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const cookieParser = require("cookie-parser");

const app = express();
app.use(express.json());
app.use(cors({ origin: "http://localhost:3000", credentials: true }));
app.use(cookieParser());

mongoose.connect("mongodb://127.0.0.1:27017/authDB", {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const UserSchema = new mongoose.Schema({
  firstName: { type: String, required: true },
  lastName: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
});

const User = mongoose.model("User", UserSchema);

const generateToken = (userId) => {
  return jwt.sign({ userId }, process.env.JWT_SECRET, { expiresIn: "1h" });
};

// ✅ Register a new user
app.post("/api/auth/register", async (req, res) => {
  const { firstName, lastName, email, password } = req.body;

  if (!firstName || !lastName || !email || !password) {
    return res.status(400).json({ message: "All fields are required" });
  }

  try {
    const userExists = await User.findOne({ email });
    if (userExists) {
      return res.status(400).json({ message: "User already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ firstName, lastName, email, password: hashedPassword });

    await user.save();
    res.json({ message: "User registered successfully" });
  } catch (err) {
    res.status(500).json({ message: "Error registering user" });
  }
});


// ✅ Login user
app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: "All fields are required" });
  }

  const user = await User.findOne({ email });
  if (!user) {
    return res.status(400).json({ message: "User not found" });
  }

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) {
    return res.status(400).json({ message: "Invalid credentials" });
  }

  const token = generateToken(user._id);
  res.cookie("token", token, { httpOnly: true, secure: false, maxAge: 3600000 });

  res.json({ message: "Login successful", token });
});

// ✅ Logout user
app.get("/api/auth/logout", (req, res) => {
  res.clearCookie("token");
  res.json({ message: "Logout successful" });
});

// ✅ Middleware to verify JWT token
const authMiddleware = (req, res, next) => {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ message: "Unauthorized" });

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).json({ message: "Invalid token" });
    req.userId = decoded.userId;
    next();
  });
};

// ✅ Fetch user details
app.get("/api/auth/user", authMiddleware, async (req, res) => {
  const user = await User.findById(req.userId).select("-password");
  if (!user) return res.status(404).json({ message: "User not found" });

  res.json({ firstName: user.firstName, lastName: user.lastName, email: user.email });
});

app.listen(5000, () => console.log("Server running on port 5000"));
