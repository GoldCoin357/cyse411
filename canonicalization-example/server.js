const path = require('path');
const fs = require('fs');
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();
app.use(express.json());

// ----------------------
// RATE LIMITING
// ----------------------
app.use(rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  standardHeaders: true,
  legacyHeaders: false
}));

// ----------------------
// GLOBAL SECURITY HEADERS
// ----------------------
const CSP_HEADER =
  "default-src 'none'; " +
  "script-src 'self'; style-src 'self'; img-src 'self' data:; " +
  "connect-src 'self'; font-src 'self'; object-src 'none'; " +
  "frame-ancestors 'none'; form-action 'self'; base-uri 'self'; " +
  "worker-src 'self'; manifest-src 'self'; frame-src 'none'";

const PERMISSIONS_POLICY_HEADER =
  'camera=(), microphone=(), geolocation=(), fullscreen=(self), payment=()';

// Middleware to force all security headers
app.use((req, res, next) => {
  // Remove X-Powered-By
  res.removeHeader('X-Powered-By');

  // Security headers
  res.setHeader('Content-Security-Policy', CSP_HEADER);
  res.setHeader('Permissions-Policy', PERMISSIONS_POLICY_HEADER);
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  res.setHeader('Cross-Origin-Embedder-Policy', 'require-corp');

  // Cache headers
  if (req.path.endsWith('robots.txt') || req.path.endsWith('sitemap.xml')) {
    res.setHeader('Cache-Control', 'public, max-age=3600, immutable');
  } else {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
  }

  // Sec-Fetch headers defaults
  res.setHeader('Sec-Fetch-Dest', req.get('Sec-Fetch-Dest') || 'document');
  res.setHeader('Sec-Fetch-Mode', req.get('Sec-Fetch-Mode') || 'navigate');
  res.setHeader('Sec-Fetch-Site', req.get('Sec-Fetch-Site') || 'same-origin');
  res.setHeader('Sec-Fetch-User', req.get('Sec-Fetch-User') || '?1');

  next();
});

// ----------------------
// HELMET ENHANCEMENTS
// ----------------------
app.use(helmet({
  crossOriginEmbedderPolicy: true,
  crossOriginOpenerPolicy: { policy: 'same-origin' },
  frameguard: { action: 'deny' },
  referrerPolicy: { policy: 'no-referrer' },
  noSniff: true
}));

// ----------------------
// SAFE FILE ACCESS
// ----------------------
const BASE_DIR = path.resolve(__dirname, 'files');

function resolveSafe(baseDir, userInput) {
  if (!userInput) throw new Error('Filename is required');

  try {
    userInput = decodeURIComponent(userInput);
  } catch (e) {
    throw new Error('Invalid encoding in filename');
  }

  const normalizedInput = path.normalize(userInput).replace(/^(\.\.(\/|\\|$))+/g, '');
  const resolvedPath = path.resolve(baseDir, normalizedInput);
  const relative = path.relative(baseDir, resolvedPath);

  if (relative.startsWith('..') || !resolvedPath.startsWith(baseDir)) {
    throw new Error('Access denied');
  }

  return resolvedPath;
}

// ----------------------
// SERVE FILES
// ----------------------
app.get('/files/*', (req, res) => {
  let filePath;
  try {
    filePath = resolveSafe(BASE_DIR, req.params[0]);
  } catch (err) {
    return res.status(400).send(err.message);
  }

  if (!fs.existsSync(filePath)) {
    return res.status(404).send('File not found');
  }

  // Hide raw timestamps
  const stats = fs.statSync(filePath);
  res.setHeader('Last-Modified', stats.mtime.toISOString());

  res.sendFile(filePath);
});

// ----------------------
// SERVE STATIC FILES (robots.txt, sitemap.xml)
// ----------------------
app.use(express.static(BASE_DIR, {
  setHeaders: (res, path) => {
    res.removeHeader('X-Powered-By');
    res.setHeader('Content-Security-Policy', CSP_HEADER);
    res.setHeader('Permissions-Policy', PERMISSIONS_POLICY_HEADER);
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
    res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
    res.setHeader('Cross-Origin-Embedder-Policy', 'require-corp');

    if (path.endsWith('robots.txt') || path.endsWith('sitemap.xml')) {
      res.setHeader('Cache-Control', 'public, max-age=3600, immutable');
    } else {
      res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
      res.setHeader('Pragma', 'no-cache');
      res.setHeader('Expires', '0');
    }
  }
}));

// ----------------------
// START SERVER
// ----------------------
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`Secure file server running on port ${PORT}`);
});
