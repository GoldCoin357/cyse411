const path = require('path');
const fs = require('fs');

const BASE_DIR = path.resolve(__dirname, 'files');

function resolveSafe(baseDir, userInput) {
  try {
    userInput = decodeURIComponent(userInput);
  } catch (e) {
    // Ignore decoding errors
  }

  const resolvedPath = path.resolve(baseDir, userInput);

  // Ensure the resolved path is within the base directory
  if (!resolvedPath.startsWith(baseDir + path.sep)) {
    throw new Error('Path traversal attempt detected');
  }

  return resolvedPath;
}

// Usage in route
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

  const content = fs.readFileSync(safePath, 'utf8');
  res.json({ path: safePath, content });
});
