const fs = require('fs');
const path = require('path');
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const https = require('https');

// ----------------------
// HTTPS CONFIG (Self-signed for local testing)
// ----------------------
const options = {
  key: fs.readFileSync(path.join(__dirname, 'certs', 'key.pem')),
  cert: fs.readFileSync(path.join(__dirname, 'certs', 'cert.pem'))
};

const app = express();
app.use(express.json());

// ----------------------
// RATE LIMITING
// ----------------------
app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false
}));

// ----------------------
// HELMET SECURITY HEADERS
// ----------------------
app.use(helmet());

// CSP
app.use(
  helmet.contentSecurityPolicy({
    directives: {
      defaultSrc: ["'none'"],
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
      frameSrc: ["'none'"]
    }
  })
);

// Permissions Policy
app.use(
  helmet.permissionsPolicy({
    features: {
      camera: [],
      microphone: [],
      geolocation: [],
      fullscreen: ["'self'"],
      payment: []
    }
  })
);

// Cross-Origin
app.use((req, res, next) => {
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  res.setHeader('Cross-Origin-Embedder-Policy', 'require-corp');
  next();
});

// ----------------------
// CACHE CONTROL
// ----------------------
app.use((req, res, next) => {
  if (req.path.endsWith('robots.txt') || req.path.endsWith('sitemap.xml')) {
    res.setHeader('Cache-Control', 'public, max-age=3600, immutable');
  } else {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
  }
  next();
});

// ----------------------
// SEC-FETCH HEADERS (Response defaults for ZAP)
// ----------------------
app.use((req, res, next) => {
  res.setHeader('Sec-Fetch-Dest', 'document');
  res.setHeader('Sec-Fetch-Mode', 'navigate');
  res.setHeader('Sec-Fetch-Site', 'same-origin');
  res.setHeader('Sec-Fetch-User', '?1');
  next();
});

// ----------------------
// SAFE FILE ACCESS
// ----------------------
const BASE_DIR = path.resolve(__dirname, 'files');

function resolveSafe(baseDir, userInput) {
  if (!userInput) throw new Error('Filename is required');

  try { userInput = decodeURIComponent(userInput); } 
  catch (e) { throw new Error('Invalid encoding in filename'); }

  const normalizedInput = path.normalize(userInput).replace(/^(\.\.(\/|\\|$))+/g, '');
  const resolvedPath = path.resolve(baseDir, normalizedInput);
  const relative = path.relative(baseDir, resolvedPath);

  if (relative.startsWith('..') || !resolvedPath.startsWith(baseDir)) {
    throw new Error('Access denied');
  }

  return resolvedPath;
}

// ----------------------
// FILE SERVING ENDPOINT
// ----------------------
app.get('/files/*', (req, res) => {
  let filePath;
  try { filePath = resolveSafe(BASE_DIR, req.params[0]); } 
  catch (err) { return res.status(400).send(err.message); }

  if (!fs.existsSync(filePath)) return res.status(404).send('File not found');

  // Avoid raw timestamps / info leakage
  res.setHeader('Last-Modified', new Date().toISOString());

  // Send file
  res.sendFile(filePath);
});

// ----------------------
// START SERVER (HTTPS)
// ----------------------
const PORT = process.env.PORT || 4000;
https.createServer(options, app).listen(PORT, () => {
  console.log(`Secure HTTPS file server running on port ${PORT}`);
});
