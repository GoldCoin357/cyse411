const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");

const app = express();
app.use(express.json());

// ----------------------
// SECURITY HEADERS
// ----------------------
app.disable("x-powered-by"); // remove X-Powered-By

app.use(helmet()); // default secure headers

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
      manifestSrc: ["'self'"],
    },
  })
);

// Permissions Policy via Helmet
app.use(
  helmet.permissionsPolicy({
    features: {
      geolocation: ["'none'"],
      camera: ["'none'"],
      microphone: ["'none'"],
      fullscreen: ["'self'"],
    },
  })
);

// Prevent caching of sensitive responses
app.use((req, res, next) => {
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, private");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");
  next();
});

// ----------------------
// RATE LIMITING
// ----------------------
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(limiter);

// ----------------------
// FAKE "DATABASE"
// ----------------------
const users = [
  { id: 1, name: "Alice", role: "customer", department: "north" },
  { id: 2, name: "Bob", role: "customer", department: "south" },
  { id: 3, name: "Charlie", role: "support", department: "north" },
];

const orders = [
  { id: 1, userId: 1, item: "Laptop", region: "north", total: 2000 },
  { id: 2, userId: 1, item: "Mouse", region: "north", total: 40 },
  { id: 3, userId: 2, item: "Monitor", region: "south", total: 300 },
  { id: 4, userId: 2, item: "Keyboard", region: "south", total: 60 },
];

// Demo token authentication
const DEMO_TOKENS = {
  "token-alice": 1,
  "token-bob": 2,
  "token-charlie": 3,
};

// ----------------------
// AUTH MIDDLEWARE
// ----------------------
function auth(req, res, next) {
  const token = req.header("Authorization")?.replace("Bearer ", "");
  const userId = DEMO_TOKENS[token];
  if (!userId) return res.status(401).json({ error: "Invalid token" });

  req.user = users.find((u) => u.id === userId);
  next();
}

app.use(auth);

// ----------------------
// ORDERS ENDPOINT
// ----------------------
app.get("/orders/:id", (req, res) => {
  const orderId = parseInt(req.params.id, 10);
  const order = orders.find((o) => o.id === orderId);
  if (!order) return res.status(404).json({ error: "Order not found" });

  const user = req.user;

  // Role/ownership checks
  if (user.role === "customer" && order.userId !== user.id)
    return res.status(403).json({ error: "Forbidden: not your order" });

  if (user.role === "support" && order.region !== user.department)
    return res.status(403).json({ error: "Forbidden: outside your department" });

  res.json(order);
});

// Health check
app.get("/", (req, res) => {
  res.json({ message: "Secure Orders API", currentUser: req.user.name });
});

// ----------------------
// START SERVER
// ----------------------
const PORT = 3000;
app.listen(PORT, () => console.log(`Secure API running at http://localhost:${PORT}`));
