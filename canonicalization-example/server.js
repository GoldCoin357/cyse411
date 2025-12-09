// server.js
const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const path = require("path");
const fs = require("fs");
const https = require("https");

const app = express();

// ---------------------
// Disable X-Powered-By
// ---------------------
app.disable("x-powered-by");
app.use((req, res, next) => {
  res.removeHeader("X-Powered-By");
  next();
});

// ---------------------
// Helmet security
// ---------------------
app.use(helmet());

// Strong CSP
app.use(
  helmet.contentSecurityPolicy({
    useDefaults: false,
    directives: {
      "default-src": ["'none'"],
      "script-src": ["'self'"],
      "style-src": ["'self'"],
      "img-src": ["'self'"],
      "connect-src": ["'self'"],
      "font-src": ["'self'"],
      "frame-ancestors": ["'none'"],
      "base-uri": ["'none'"],
      "form-action": ["'self'"],
      "manifest-src": ["'self'"]
    }
  })
);

// Permissions-Policy
app.use((req, res, next) => {
  res.setHeader("Permissions-Policy", "geolocation=(), microphone=(), camera=()");
  next();
});

// No cache
app.use((req, res, next) => {
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, private");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");
  next();
});

// Rate limit
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
});
app.use(limiter);

// Static
app.use(express.static("public"));

// Default route
app.get("/", (req, res) => res.send("Secure HTTPS server running."));

// HTTPS setup
const options = {
  key: fs.readFileSync(path.join(__dirname, "certs", "key.pem")),
  cert: fs.readFileSync(path.join(__dirname, "certs", "cert.pem"))
};

https.createServer(options, app).listen(4000, () =>
  console.log("HTTPS server running on port 4000")
);
