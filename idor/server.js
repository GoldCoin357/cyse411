const express = require("express");
const app = express();

app.use(express.json());

// Fake "database"
const users = [
  { id: 1, name: "Alice", role: "customer", department: "north" },
  { id: 2, name: "Bob", role: "customer", department: "south" },
  { id: 3, name: "Charlie", role: "support", department: "north" }
];

const orders = [
  { id: 1, userId: 1, item: "Laptop", region: "north", total: 2000 },
  { id: 2, userId: 1, item: "Mouse", region: "north", total: 40 },
  { id: 3, userId: 2, item: "Monitor", region: "south", total: 300 },
  { id: 4, userId: 2, item: "Keyboard", region: "south", total: 60 }
];

// -------- Secure Authentication (No ID in Headers) --------
// Using a static demo token instead of header-based IDOR
const DEMO_TOKENS = {
  "token-alice": 1,
  "token-bob": 2,
