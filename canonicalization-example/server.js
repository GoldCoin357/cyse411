// secure-file-server.js
const path = require('path');
const fs = require('fs');
const express = require('express');
const helmet = require('helmet');

const app = express();
app.use(express.json());

// ----------------------
// SECURITY HEADERS (GLOBAL)
// ----------------------
const CSP_HEADER =
  "default-src 'none'; " +
  "script-src 'self'; style-src 'self'; img-src 'self' data:; " +
  "connect-src 'self'; font-src 'self'; object-src 'none'; " +
  "frame-ancestors 'none'; form-action 'self'; base-uri 'self'; " +
  "worker-src 'self'; manifest-src 'self'; frame-src 'none'";

const PERMISSIONS_POLICY_HEADER =
  'camera=(), microphone=(), geolocation=(), fullscreen=(self), payment=()';

// Apply to all responses
app.use((req, res, next) => {
  res.removeHeader('X-Powered-By');
  res.setHeader('Content-Security-Policy', CSP_HEADER);
  res.setHeader('Permissions-Policy', PERMISSIONS_POLICY_HEADER);

  if (req.path.endsWith('robots.txt') || req.path.endsWith('sitemap.xml')) {
    res.set('Cache-Control', 'public, max-age=3600, immutable');
  } else {
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    res.set('Pragma', 'no-cache');
    res.set('Expires', '0');
  }

  next();
});

// Helmet for extra headers
app.use(
  helmet({
    crossOriginEmbedderPolicy: true,
    crossOriginOpenerPolicy: true,
    crossOriginResourcePolicy: { policy: 'same-origin' },
    referrerPolicy: { policy: 'no-referrer' },
    hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
    noSniff: true,
    frameguard: { action: 'deny' },
  })
);

// ----------------------
// FETCH METADATA PROTECTION
// ----------------------
app.use((req, res, next) => {
  const site = req.get('Sec-Fetch-Site');
  if (site && site !== 'same-origin' && site !== 'same-site') {
    console.warn(`Blocked request: ${req.method} ${req.originalUrl} from ${site}`);
    return res.status(400).send('Blocked by Fetch Metadata policy');
  }
  next();
});

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

  if (relative.startsWith('..') || path
