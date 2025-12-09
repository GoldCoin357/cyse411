// server.js
const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const path = require("path");
const fs = require("fs");
const https = require("https");

const app = express();

// ---------------------
// 1. Global Security Middleware
// ---------------------
app.disable("x-powered-by"); // remove Express header

app.use((req, res, next) => {
  // Remove X-Powered-By again to be sure
  res.removeHeader("X-Powered-By");

  // ---------------------
  // 2. Strong CSP
  // ---------------------
  const csp = `
    default-src 'none';
    script-src 'self';
    style-src 'self';
    img-src 'self' data:;
    connect-src 'self';
    font-src 'self';
    object-src 'none';
    frame-ancestors 'none';
    form-action 'self';
    base-uri 'none';
    worker-src 'self';
    manifest-src 'self';
    frame-src 'none';
  `;
  res.setHeader("Content-Security-Policy", csp.replace(/\s+/g, " ").trim());

  // ---------------------
  // 3. Permissions Policy
  // ---------------------
  res.setHeader(
    "Permissions-Policy",
    "camera=(), microphone=(), geolocation=(), fullscreen=(), payment=()"
  );

  // ---------------------
  // 4. Cross-Origin
  // ---------------------
  res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
  res.setHeader("Cross-Origin-Embedder-Policy", "require-corp");

  // ---------------------
  // 5. Cache-Control
  // ---------------------
  if (req.path.endsWith("robots.txt") || req.path.endsWith("sitemap.xml")) {
    res.setHeader("Cache-Control", "public, max-age=3600, immutable");
  } else {
    res.setHeader(
      "Cache-Control",
      "no-store, no-cache, must-revalidate, private"
    );
    res.setHeader("Pragma", "no-cache");
    res.setHeader("Expires", "0");
  }

  next();
});

// ---------------------
// 6. Helmet Enhancements
// ---------------------
app.use(
  helmet({
    crossOriginEmbedderPolicy: true,
    crossOriginOpenerPolicy: { policy: "same-origin" },
    frameguard: { action: "deny" },
    referrerPolicy: { policy: "no-referrer" },
    noSniff: true,
  })
);

// ---------------------
// 7. Rate Limiting
// ---------------------
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(limiter);

// ---------------------
// 8. Serve Static Files (public folder)
// ---------------------
app.use(express.static(path.join(__dirname, "public")));

// ---------------------
// 9. Default Route
// ---------------------
app.get("/", (req, res) => {
  res.send("Secure HTTPS server running.");
});

// ---------------------
// 10. HTTPS Setup
// ---------------------
const options = {
  key: fs.readFileSync(path.join(__dirname, "certs", "key.pem")),
  cert: fs.readFileSync(path.join(__dirname, "certs", "cert.pem")),
};

const PORT = process.env.PORT || 4000;
https.createServer(options, app).listen(PORT, () => {
  console.log(`Secure HTTPS server running on port ${PORT}`);
});
