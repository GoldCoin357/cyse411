const path = require('path');
const fs = require('fs');
const express = require('express');
const helmet = require('helmet');

const app = express();
app.use(express.json());

// Add security headers
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'"],
        imgSrc: ["'self'"],
        connectSrc: ["'self'"],
        fontSrc: ["'self'"],
        objectSrc: ["'none'"],
        formAction: ["'self'"],
        frameAncestors: ["'none'"]
      }
    },
    permissionsPolicy: {
      features: {
        geolocation: ["'none'"],
        camera: ["'none'"],
        microphone: ["'none'"]
      }
    },
    hidePoweredBy: true
  })
);

// Prevent caching sensitive responses
app.use((req, res, next) => {
  res.set('Cache-Control', 'no-cache, no-store, must-revalidate, private');
  res.set('Pragma', 'no-cache');
  res.set('Expires', '0');
  next();
});

const BASE_DIR = path.resolve(__dirname, 'files');

function resolveSafe(baseDir, userInput) {
  try {
    userInput = decodeURIComponent(userInput);
  } catch (e) {
    // Ignore invalid encoding
  }

  const normalizedInput = path
    .normalize(userInput)
    .replace(/^(\.\.(\/|\\|$))+/g, '');

  const resolvedPath = path.resolve(baseDir, normalizedInput);
  const relative = path.relative(baseDir, resolvedPath);

  if (relative.startsWith('..') || path.isAbsolute(relative)) {
    throw new Error('Path traversal attempt detected');
  }

  return resolvedPath;
}

app.post('/read', (req, res) => {
  const filename = req.body.filename || '';
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
    res.json({ path: safePath, content });
  } catch (err) {
    res.status(500).json({ error: 'Failed to read file' });
  }
});

const PORT = 4000;
app.listen(PORT, () => {
  console.log(`Secure file server running on http://localhost:${PORT}`);
});
