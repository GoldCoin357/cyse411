// server.js
const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const path = require("path");
const fs = require("fs");
const https = require("https");

const app = express();

// -------------------------
// 1. Remove X-Powered-By
// -------------------------
app.disable("x-powered-by");

// -------------------------
// 2. Apply Helmet + Secure Headers
// -------------------------
app.use(helmet());

// Strong CSP required by ZAP
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

// -------------------------
// 3. Rate Limiting
// -------------------------
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(limiter);

// -------------------------
// 4. Force No Cache
// -------------------------
app.use((req, res, next) => {
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");
  next();
});

// -------------------------------------------
// 5. Safe File Path Resolver
// -------------------------------------------
function safeResolve(base, target) {
  const targetPath = path.normalize(path.join(base, target));
  if (!targetPath.startsWith(base)) {
    throw new Error("Invalid path");
  }
  return targetPath;
}

// -------------------------------------------
// 6. Secure File Download Route
// -------------------------------------------
app.get("/files/:name", (req, res) => {
  try {
    const filePath = safeResolve(path.join(__dirname, "files"), req.params.name);

    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ error: "File not found" });
    }

    res.download(filePath);
  } catch (err) {
    res.status(400).json({ error: "Invalid request" });
  }
});

// -------------------------------------------
// 7. Static Files
// -------------------------------------------
app.use(express.static("public", {
  extensions: ["html"]
}));

// -------------------------------------------
// 8. Default Route
// -------------------------------------------
app.get("/", (req, res) => {
  res.send("Secure HTTPS server is running.");
});

// -------------------------------------------
// 9. HTTPS Setup (THE ONLY NEW THING)
// -------------------------------------------
const options = {
  key: fs.readFileSync(path.join(__dirname, "certs", "key.pem")),
  cert: fs.readFileSync(path.join(__dirname, "certs", "cert.pem"))
};

const PORT = process.env.PORT || 3000;

https.createServer(options, app).listen(PORT, () => {
  console.log(`Secure HTTPS server running on port ${PORT}`);
});
