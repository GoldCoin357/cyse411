const path = require('path');
const fs = require('fs');
const express = require('express');
const helmet = require('helmet');

const app = express();
app.use(express.json());

// ----------------------
// SECURITY HEADERS
// ----------------------

// Remove X-Powered-By completely
app.disable('x-powered-by');

// Enable secure headers
app.use(helmet()); // sets multiple secure headers (HSTS, X-Frame-Options, etc.)

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
      manifestSrc: ["'self'"]
    }
  })
);

// Permissions Policy (new name for Feature-Policy)
app.use(
  helmet.permissionsPolicy({
    features: {
      geolocation: ["'none'"],
      camera: ["'none'"],
      microphone: ["'none'"],
      fullscreen: ["'self'"],
      payment: ["'none'"],
      usb: ["'none'"],
      speaker: ["'none'"]
    }
  })
);

// Prevent caching of sensitive content
app.use((req, res, next) => {
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  res.set('Pragma', 'no-cache');
  res.set('Expires', '0');
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

// ----------------------
// START SERVER
// ----------------------
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`Secure file server running on http://localhost:${PORT}`);
});
