const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
require("dotenv").config();

const app = express();
app.use(cors({ origin: "*" }));
app.use(express.json());

// Middleware to check Content-Type
app.use((req, res, next) => {
    if (req.method === "POST" && req.headers["content-type"] !== "application/json") {
      return res.status(400).json({ message: "Invalid Content-Type. Use application/json" });
    }
    next();
  });

  app.use((req, res) => {
    res.status(404).json({ message: "Route not found" });
  });
  

  mongoose.connect("mongodb://127.0.0.1:27017/testdb", {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => console.log("Connected to MongoDB"))
.catch(err => console.error("MongoDB connection error:", err));
const UserSchema = new mongoose.Schema({
    email: String,
    password: String
});

const User = mongoose.model("User", UserSchema, "c1");

// Register API
app.post("/api/auth/register", async (req, res) => {
    try {
      const { email, password } = req.body;
      if (!email || !password) {
        return res.status(400).json({ message: "Email and password are required" });
      }
      // Save user logic here...
      res.status(201).json({ message: "User registered successfully" });
    } catch (error) {
      res.status(500).json({ message: "Server error" });
    }
  });
  

// Login API
app.post("/api/auth/login", async (req, res) => {
    const { email, password } = req.body;
    const user = await User.findOne({ email });

    if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.status(401).json({ message: "Invalid credentials" });
    }

    const token = jwt.sign({ email: user.email }, "SECRET_KEY", { expiresIn: "1h" });

    res.json({ message: "Login successful", token });
});

// Logout API (Just a dummy response)
app.get("/api/auth/logout", (req, res) => {
    res.json({ message: "User logged out" });
});

// Get User Details
app.get("/api/auth/user", (req, res) => {
    const token = req.headers.authorization?.split(" ")[1];

    if (!token) {
        return res.status(401).json({ message: "Unauthorized" });
    }

    try {
        const decoded = jwt.verify(token, "SECRET_KEY");
        res.json({ email: decoded.email });
    } catch (error) {
        res.status(401).json({ message: "Invalid token" });
    }
});

app.listen(5000, () => console.log("Server running on port 5000"));
