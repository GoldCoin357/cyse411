const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");

const app = express();
app.use(express.json());
app.use(helmet()); // Secure headers

// Rate limiter for all requests
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(limiter);

// Fake "database"
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

// Demo static token authentication
const DEMO_TOKENS = {
  "token-alice": 1,
  "token-bob": 2,
  "token-charlie": 3,
};

// Auth middleware
function auth(req, res, next) {
  const token = req.header("Authorization")?.replace("Bearer ", "");
  const userId = DEMO_TOKENS[token];
  if (!userId) return res.status(401).json({ error: "Invalid token" });

  const user = users.find((u) => u.id === userId);
  req.user = user;
  next();
}

app.use(auth);

// Secure orders endpoint
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

// Start server
const PORT = 3000;
app.listen(PORT, () => console.log(`Secure API running at http://localhost:${PORT}`));
