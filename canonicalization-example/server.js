const path = require('path');
const fs = require('fs');
const express = require('express');
const app = express();

app.use(express.json());

const BASE_DIR = path.resolve(__dirname, 'files');

function resolveSafe(baseDir, userInput) {
  try {
    userInput = decodeURIComponent(userInput);
  } catch (e) {
    // Ignore invalid encoding
  }

  // Normalize user input and block ".." patterns
  const normalizedInput = path
    .normalize(userInput)
    .replace(/^(\.\.(\/|\\|$))+/, '');

  // Resolve final absolute path
  const resolvedPath = path.resolve(baseDir, normalizedInput);

  // Validate using path.relative() (safest method)
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
    safePa
