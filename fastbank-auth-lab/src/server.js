// fastbank-auth-secure.js
const express = require("express");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const helmet = require("helmet");
const crypto = require("crypto");
const bcrypt = require("bcrypt");
const rateLimit = require("express-rate-limit");

const app = express();
const PORT = 3001;

// ---------- Middleware ----------
app.use(helmet()); // secure headers
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(cookieParser());
app.use(express.static("public"));

// Limit login attempts to reduce brute force
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false
});

// ---------- In-memory storage (demo only) ----------
const users = [
  {
    id: 1,
    username: "student",
    passwordHash: "" // will be initialized securely below
  }
];

// token -> { userId, expires }
const sessions = {};

// ---------- Secure helpers ----------
async function hashPassword(password) {
  const saltRounds = 12; // adjust for your environment/perf
  return bcrypt.hash(password, saltRounds);
}

async function verifyPassword(password, hash) {
  return bcrypt.compare(password, hash);
}

function createSession(userId, ttlMs = 30 * 60 * 1000) {
  const token = crypto.randomBytes(32).toString("hex");
  sessions[token] = { userId, expires: Date.now() + ttlMs };
  return token;
}

function getSession(token) {
  const s = token ? sessions[token] : null;
  if (!s || s.expires < Date.now()) {
    if (token) delete sessions[token]; // cleanup expired
    return null;
  }
  return s;
}

// ---------- Routes ----------
app.get("/api/me", (req, res) => {
  const token = req.cookies.session;
  const session = getSession(token);
  if (!session) return res.status(401).json({ authenticated: false });

  const user = users.find((u) => u.id === session.userId);
  if (!user) return res.status(401).json({ authenticated: false });

  res.json({ authenticated: true, username: user.username });
});

app.post("/api/login", loginLimiter, async (req, res) => {
  const { username, password } = req.body;

  // Uniform error responses to avoid user enumeration
  const invalid = () =>
    res.status(401).json({ success: false, message: "Invalid credentials" });

  // Basic input validation
  if (typeof username !== "string" || typeof password !== "string") return invalid();

  const user = users.find((u) => u.username === username);
  if (!user) return invalid();

  const valid = await verifyPassword(password, user.passwordHash);
  if (!valid) return invalid();

  // Create secure, random session with expiration
  const token = createSession(user.id);

  // Secure cookie flags (set secure: true in HTTPS/prod)
  res.cookie("session", token, {
    httpOnly: true,
    secure: true, // requires HTTPS; set false only in local dev
    sameSite: "lax",
    maxAge: 30 * 60 * 1000
  });

  res.json({ success: true });
});

app.post("/api/logout", (req, res) => {
  const token = req.cookies.session;
  if (token) delete sessions[token];
  res.clearCookie("session");
  res.json({ success: true });
});

// ---------- Startup ----------
(async function start() {
  // Initialize demo user securely (one-time, for baseline)
  users[0].passwordHash = await hashPassword("password123");

  app.listen(PORT, () => {
    console.log(`FastBank Auth (secure) running at http://localhost:${PORT}`);
    console.log("NOTE: Cookies use secure:true — run behind HTTPS in production.");
  });
})();
