// secure-file-server.js
const path = require('path');
const fs = require('fs');
const express = require('express');
const helmet = require('helmet');

const app = express();
app.use(express.json());

// ----------------------
// SECURITY HEADERS
// ----------------------

// Remove X-Powered-By immediately
app.disable('x-powered-by');
app.use((req, res, next) => {
  res.removeHeader('X-Powered-By');
  next();
});

// Helmet defaults + HSTS + other protections
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

// Canonical CSP
app.use((req, res, next) => {
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'none'; " +
      "script-src 'self'; " +
      "style-src 'self'; " +
      "img-src 'self' data:; " +
      "connect-src 'self'; " +
      "font-src 'self'; " +
      "object-src 'none'; " +
      "frame-ancestors 'none'; " +
      "form-action 'none'; " +
      "base-uri 'none'; " +
      "worker-src 'self'; " +
      "manifest-src 'self'; " +
      "child-src 'none'; " +
      "frame-src 'none'"
  );
  next();
});

// Permissions Policy (canonical form)
app.use(
  helmet.permissionsPolicy({
    policy: {
      accelerometer: [],
      autoplay: [],
      camera: [],
      encryptedMedia: [],
      fullscreen: ["self"],
      geolocation: [],
      gyroscope: [],
      magnetometer: [],
      microphone: [],
      payment: [],
      usb: [],
      speaker: [],
      vr: [],
      interestCohort: [],
    },
  })
);

// Cache-control: no-store for HTML, allow robots/sitemap caching
app.use((req, res, next) => {
  if (req.path.endsWith('robots.txt') || req.path.endsWith('sitemap.xml')) {
    res.set('Cache-Control', 'public, max-age=3600, immutable');
  } else {
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    res.set('Pragma', 'no-cache');
    res.set('Expires', '0');
  }
  next();
});

// Fetch Metadata protection
app.use((req, res, next) => {
  const site = req.get('Sec-Fetch-Site');
  const mode = req.get('Sec-Fetch-Mode');
  const dest = req.get('Sec-Fetch-Dest');

  const isSameOrigin = site === 'same-origin' || site === 'same-site';
  const isTopNav = mode === 'navigate' && dest === 'document';

  if (site && !isSameOrigin && !isTopNav) {
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

  if (relative.startsWith('..') || path.isAbsolute(relative)) {
    throw new Error('Path traversal attempt detected');
  }

  return resolvedPath;
}

app.post('/read', (req, res) => {
  const filename = req.body.filename;

  let safePath;
  try {
    safePath = resolveSafe(BASE_DIR, filename);
  } catch (err) {
    return res.status(403).json({ error: err.message });
  }

  if (!fs.existsSync(safePath)) {
    return res.status(404).json({ error: 'File not found' });
  }

  try {
    const content = fs.readFileSync(safePath, 'utf8');
    res.json({ path: path.relative(BASE_DIR, safePath), content });
  } catch (err) {
    res.status(500).json({ error: 'Failed to read file' });
  }
});

// Serve static files securely
app.use(
  '/files',
  express.static(BASE_DIR, {
    etag: false,
    lastModified: false,
    setHeaders: (res, filePath) => {
      if (filePath.endsWith('robots.txt') || filePath.endsWith('sitemap.xml')) {
        res.set('Cache-Control', 'public, max-age=3600, immutable');
      } else {
        res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
        res.set('Pragma', 'no-cache');
        res.set('Expires', '0');
      }
    },
  })
);

// ----------------------
// START SERVER
// ----------------------
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`Secure file server running on http://localhost:${PORT}`);
});
