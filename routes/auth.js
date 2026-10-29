
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { OAuth2Client } = require("google-auth-library");
const Firm = require("../models/Firm");
const authMiddleware = require("../middleware/authMiddleware");

const router = express.Router();

const googleClient = new OAuth2Client(
  process.env.GOOGLE_CLIENT_ID
);

// Generate JWT.
function createToken(firm) {
  return jwt.sign(
    { sub: firm._id.toString() },
    process.env.JWT_SECRET,
    {
      expiresIn: "1h",
      issuer: "caratflow-api",
      audience: "caratflow-erp",
    }
  );
}

// Return safe user details.
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

// 1. REGISTER WITH EMAIL AND PASSWORD
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

    const normalizedEmail = email.trim().toLowerCase();

    if (
      !companyName.trim() ||
      !ownerName.trim() ||
      !mobile.trim() ||
      !normalizedEmail
    ) {
      return res.status(400).json({
        message: "All fields are required.",
      });
    }

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalizedEmail)) {
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

    const firm = await Firm.create({
      companyName: companyName.trim(),
      ownerName: ownerName.trim(),
      mobile: mobile.trim(),
      email: normalizedEmail,
      password: await bcrypt.hash(password, 12),
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
        message: "An account with this email already exists.",
      });
    }

    console.error("Registration error:", error.message);
    return res.status(500).json({
      message: "Registration failed.",
    });
  }
});

// 2. LOGIN WITH EMAIL AND PASSWORD
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

    if (!firm || !firm.password) {
      return res.status(401).json({
        message: "Invalid email or password.",
      });
    }

    const matches = await bcrypt.compare(password, firm.password);

    if (!matches) {
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

// 3. GOOGLE SIGN-IN: NEW AND EXISTING USERS

 // 3. GOOGLE SIGN-IN: NEW AND EXISTING USERS
router.post("/google", async (req, res) => {
  try {
    const { credential } = req.body;

    if (typeof credential !== "string" || !credential.trim()) {
      return res.status(400).json({
        message: "Google credential is required.",
      });
    }

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
    const email = payload.email.trim().toLowerCase();

    // 1. Check whether this Google account is already linked.
    let firm = await Firm.findOne({ googleId });

    if (firm) {
      // Do not sign in if the Google account's email does not match.
      if (firm.email !== email) {
        return res.status(409).json({
          message: "Google account email does not match the linked account.",
        });
      }

      return res.status(200).json({
        message: "Google sign-in successful.",
        token: createToken(firm),
        user: publicUser(firm),
        isNewUser: false,
        requiresFirmDetails:
          firm.companyName === "Pending firm details",
      });
    }

    // 2. Check whether this email already has an account.
    firm = await Firm.findOne({ email });

    if (firm) {
      // Link the verified Google account to the existing account.
      // The existing password remains unchanged.
      firm.googleId = googleId;
      await firm.save();

      return res.status(200).json({
        message: "Google account linked. Sign-in successful.",
        token: createToken(firm),
        user: publicUser(firm),
        isNewUser: false,
        requiresFirmDetails:
          firm.companyName === "Pending firm details",
      });
    }

    // 3. Create an account for a completely new Google user.
    firm = await Firm.create({
      companyName: "Pending firm details",
      ownerName: payload.name || email.split("@")[0],
      mobile: "",
      email,
      googleId,
      authProvider: "google",
    });

    return res.status(201).json({
      message: "Google account created and sign-in successful.",
      token: createToken(firm),
      user: publicUser(firm),
      isNewUser: true,
      requiresFirmDetails: true,
      requiresPasswordSetup: true,
    });
  } catch (error) {
    if (error.code === 11000) {
      return res.status(409).json({
        message: "This Google account is already linked to another account.",
      });
    }

    console.error("Google sign-in error:", error.message);

    return res.status(401).json({
      message: "Google sign-in failed. Please try again.",
    });
  }
});


// 4. SET PASSWORD FOR A GOOGLE-CREATED ACCOUNT
router.post("/set-password", authMiddleware, async (req, res) => {
  try {
    const { password } = req.body;

    if (
      typeof password !== "string" ||
      password.length < 8 ||
      password.length > 72
    ) {
      return res.status(400).json({
        message: "Password must be 8-72 characters long.",
      });
    }

    const firm = await Firm.findById(req.firmId).select("+password");

    if (!firm) {
      return res.status(404).json({
        message: "Account not found.",
      });
    }

    if (firm.password) {
      return res.status(409).json({
        message: "This account already has a password.",
      });
    }

    firm.password = await bcrypt.hash(password, 12);
    await firm.save();

    return res.status(200).json({
      message: "Password set successfully. You can now sign in using email and password.",
    });
  } catch (error) {
    console.error("Set password error:", error.message);
    return res.status(500).json({
      message: "Could not set password.",
    });
  }
});

module.exports = router;
