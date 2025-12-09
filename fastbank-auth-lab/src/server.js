const express = require("express");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const helmet = require("helmet");
const crypto = require("crypto");
const bcrypt = require("bcrypt");
const rateLimit = require("express-rate-limit");

const app = express();
const PORT = 3001;

// ----------------------
// SECURITY HEADERS
// ----------------------
app.disable("x-powered-by"); // remove X-Powered-By
app.use(helmet());

// Strong CSP
app.use(
  helmet.contentSecurityPolicy({
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'"],
      imgSrc: ["'self'", "data:"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"],
      formAction: ["'self'"],
      baseUri: ["'self'"],
      workerSrc: ["'self'"],
      manifestSrc: ["'self'"],
    },
  })
);

// Permissions Policy using Helmet
app.use(
  helmet.permissionsPolicy({
    features: {
      geolocation: ["'none'"],
      camera: ["'none'"],
      microphone: ["'none'"],
      fullscreen: ["'self'"],
      payment: ["'none'"],
      usb: ["'none'"],
      speaker: ["'none'"],
    },
  })
);

// Cache control
app.use((req, res, next) => {
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, private");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");
  next();
});

// ----------------------
// BODY / COOKIE PARSERS
// ----------------------
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(cookieParser());
app.use(express.static("public"));

// ----------------------
// RATE LIMITING
// ----------------------
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
});

// ----------------------
// IN-MEMORY STORAGE (DEMO ONLY)
// ----------------------
const users = [{ id: 1, username: "student", passwordHash: "" }];
const sessions = {}; // token -> { userId, expires }

// ----------------------
// SECURE HELPERS
// ----------------------
async function hashPassword(password) {
  return bcrypt.hash(password, 12);
}

async function verifyPassw
