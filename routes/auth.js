
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { OAuth2Client } = require("google-auth-library");
const mongoose = require("mongoose");
const Firm = require("../models/Firm");

const router = express.Router();

const googleClient = new OAuth2Client(
  process.env.GOOGLE_CLIENT_ID
);

// Generate our application's login token.
function createToken(firm) {
  return jwt.sign(
    {
      sub: firm._id.toString(),
    },
    process.env.JWT_SECRET,
    {
      expiresIn: "1h",
      issuer: "caratflow-api",
      audience: "caratflow-erp",
    }
  );
}

// Return only safe user details.
function publicUser(firm) {
  return {
    id: firm._id,
    companyName: firm.companyName,
    ownerName: firm.ownerName,
    mobile: firm.mobile,
    email: firm.email,
    authProvider: firm.authProvider,
  };
}

// 1. REGISTER FIRM
router.post("/register", async (req, res) => {
  try {
    const {
      companyName,
      ownerName,
      mobile,
      email,
      password,
    } = req.body;

    if (
      typeof companyName !== "string" ||
      typeof ownerName !== "string" ||
      typeof mobile !== "string" ||
      typeof email !== "string" ||
      typeof password !== "string"
    ) {
      return res.status(400).json({
        message: "Please provide all required fields.",
      });
    }

    if (
      !companyName.trim() ||
      !ownerName.trim() ||
      !mobile.trim() ||
      !email.trim()
    ) {
      return res.status(400).json({
        message: "All fields are required.",
      });
    }

    const normalizedEmail = email.trim().toLowerCase();

    if (
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalizedEmail)
    ) {
      return res.status(400).json({
        message: "Please enter a valid email address.",
      });
    }

    if (!/^[0-9]{10,15}$/.test(mobile.trim())) {
      return res.status(400).json({
        message: "Enter a valid mobile number with 10-15 digits.",
      });
    }

    if (password.length < 8 || password.length > 72) {
      return res.status(400).json({
        message: "Password must be 8-72 characters long.",
      });
    }

    const existingFirm = await Firm.findOne({
      email: normalizedEmail,
    });

    if (existingFirm) {
      return res.status(409).json({
        message: "An account with this email already exists.",
      });
    }

    // Never save a plain-text password.
    const hashedPassword = await bcrypt.hash(password, 12);

    const firm = await Firm.create({
      companyName: companyName.trim(),
      ownerName: ownerName.trim(),
      mobile: mobile.trim(),
      email: normalizedEmail,
      password: hashedPassword,
      authProvider: "local",
    });

    return res.status(201).json({
      message: "Firm registered successfully.",
      token: createToken(firm),
      user: publicUser(firm),
    });
  } catch (error) {
    if (error.code === 11000) {
      return res.status(409).json({
        message: "An account with this email or Google ID already exists.",
      });
    }

    console.error("Registration error:", error.message);

    return res.status(500).json({
      message: "Registration failed.",
    });
  }
});

// 2. SIGN IN WITH EMAIL AND PASSWORD
router.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (
      typeof email !== "string" ||
      typeof password !== "string" ||
      !email.trim() ||
      !password
    ) {
      return res.status(400).json({
        message: "Email and password are required.",
      });
    }

    const firm = await Firm.findOne({
      email: email.trim().toLowerCase(),
    }).select("+password");

    // Use the same error for an unknown email or wrong password.
    if (!firm || !firm.password) {
      return res.status(401).json({
        message: "Invalid email or password.",
      });
    }

    const passwordMatches = await bcrypt.compare(
      password,
      firm.password
    );

    if (!passwordMatches) {
      return res.status(401).json({
        message: "Invalid email or password.",
      });
    }

    return res.status(200).json({
      message: "Sign in successful.",
      token: createToken(firm),
      user: publicUser(firm),
    });
  } catch (error) {
    console.error("Login error:", error.message);

    return res.status(500).json({
      message: "Sign in failed.",
    });
  }
});

// 3. SIGN IN WITH GOOGLE (NO FIREBASE)
router.post("/google", async (req, res) => {
  try {
    const { credential } = req.body;

    if (
      typeof credential !== "string" ||
      !credential
    ) {
      return res.status(400).json({
        message: "Google credential is required.",
      });
    }

    // Verify the Google ID token with Google.
    const ticket = await googleClient.verifyIdToken({
      idToken: credential,
      audience: process.env.GOOGLE_CLIENT_ID,
    });

    const payload = ticket.getPayload();

    if (
      !payload ||
      !payload.sub ||
      !payload.email ||
      payload.email_verified !== true
    ) {
      return res.status(401).json({
        message: "Google account could not be verified.",
      });
    }

    const googleId = payload.sub;
    const email = payload.email.toLowerCase();

    // Find an existing Google-linked account.
    let firm = await Firm.findOne({ googleId });

    if (!firm) {
      // Never silently link a Google account to an existing
      // password account just because the email matches.
      const existingFirm = await Firm.findOne({ email });

      if (existingFirm) {
        return res.status(409).json({
          message:
            "An account already exists with this email. Please use your existing sign-in method.",
        });
      }

      // A new Google user must complete firm details later.
      firm = await Firm.create({
        companyName: "Pending firm details",
        ownerName: payload.name || email.split("@")[0],
        mobile: "",
        email,
        googleId,
        authProvider: "google",
      });
    }

    return res.status(200).json({
      message: "Google sign-in successful.",
      token: createToken(firm),
      user: publicUser(firm),
      requiresFirmDetails:
        firm.companyName === "Pending firm details",
    });
  } catch (error) {
    console.error("Google sign-in error:", error.message);

    return res.status(401).json({
      message: "Invalid or expired Google credential.",
    });
  }
});

module.exports = router;
