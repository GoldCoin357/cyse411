// server.js
const express = require("express");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const helmet = require("helmet");
const bcrypt = require("bcrypt");
const crypto = require("crypto");
const rateLimit = require("express-rate-limit");

const app = express();
const PORT = 3001;


app.disable("x-powered-by");
app.use(helmet());


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
      manifestSrc: ["'self'"],
      frameSrc: ["'none'"],
    },
  })
);


app.use(
  helmet.permissionsPolicy({
    features: {
      geolocation: ["'none'"],
      camera: ["'none'"],
      microphone: ["'none'"],
      fullscreen: ["'self'"],
      payment: ["'none'"],
      usb: ["'none'"],
      speaker: ["'none'"],
    },
  })
);


app.use((req, res, next) => {
  res.setHeader("Sec-Fetch-Dest", "document");
  res.setHeader("Sec-Fetch-Mode", "navigate");
  res.setHeader("Sec-Fetch-Site", "same-origin");
  res.setHeader("Sec-Fetch-User", "?1");
  next();
});


app.use((req, res, next) => {
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, private");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");
  next();
});

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(cookieParser());
app.use(express.static("public"));


const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
});


const users = [
  { id: 1, username: "student", passwordHash: "" }, // hashed later
];
const sessions = {}; // token -> { userId, expires }


async function hashPassword(password) {
  return bcrypt.hash(password, 12);
}

async function verifyPassword(password, hash) {
  return bcrypt.compare(password, hash);
}

function generateToken() {
  return crypto.randomBytes(32).toString("hex");
}


(async () => {
  users[0].passwordHash = await hashPassword("securepassword123");
})();


app.post("/login", loginLimiter, async (req, res) => {
  const { username, password } = req.body;
  const user = users.find((u) => u.username === username);
  if (!user) return res.status(401).json({ error: "Invalid credentials" });

  const valid = await verifyPassword(password, user.passwordHash);
  if (!valid) return res.status(401).json({ error: "Invalid credentials" });

  const token = generateToken();
  sessions[token] = { userId: user.id, expires: Date.now() + 3600000 }; // 1hr

  res.json({ token });
});


function auth(req, res, next) {
  const token = req.header("Authorization")?.replace("Bearer ", "");
  const session = sessions[token];
  if (!session || session.expires < Date.now()) return res.status(401).json({ error: "Unauthorized" });

  req.user = users.find((u) => u.id === session.userId);
  next();
}


app.get("/profile", auth, (req, res) => {
  res.json({ username: req.user.username, id: req.user.id });
});


app.listen(PORT, () => console.log(`Secure server running on http://localhost:${PORT}`));
