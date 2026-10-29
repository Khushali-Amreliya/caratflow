
require("dotenv").config();

const authMiddleware = require("./middleware/authMiddleware");
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");

const authRoutes = require("./routes/auth");

const app = express();

if (!process.env.MONGO_URI || !process.env.JWT_SECRET) {
  throw new Error("MONGO_URI and JWT_SECRET must be configured.");
}

if (process.env.JWT_SECRET.length < 32) {
  throw new Error("JWT_SECRET must contain at least 32 characters.");
}

app.use(helmet());

app.use(
  cors({
    origin: process.env.CLIENT_URL || "http://localhost:3000",
  })
);

app.use(express.json({ limit: "10kb" }));

app.get("/", (req, res) => {
  res.json({
    message: "CaratFlow Authentication API is running.",
  });
});
app.get("/api/auth-test", authMiddleware, (req, res) => {
  res.json({
    message: "Authentication successful.",
    firmId: req.firmId,
  });
});

// Limit repeated attempts on authentication endpoints.
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  standardHeaders: "draft-8",
  legacyHeaders: false,
  message: {
    message: "Too many attempts. Please try again later.",
  },
});

app.use("/api/auth", authLimiter, authRoutes);

const PORT = process.env.PORT || 5000;

async function startServer() {
  try {
    await mongoose.connect(process.env.MONGO_URI);

    console.log("MongoDB connected successfully.");

    app.listen(PORT, () => {
      console.log(`CaratFlow API running on port ${PORT}`);
    });
  } catch (error) {
    console.error("Startup failed:", error.message);
    process.exit(1);
  }
}

startServer();
