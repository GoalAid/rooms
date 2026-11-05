require("dotenv").config();

const express = require("express");
const path = require("path");
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();

const publicDir = path.join(__dirname, "public");

app.use(express.json());
app.use(express.static(publicDir));

const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET) {
  throw new Error("Set JWT_SECRET in your .env file");
}

const { Pool } = require('pg');
const fs = require('fs');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    ca: fs.readFileSync('./ca.pem', 'utf8'),
    rejectUnauthorized: true,
  },
});

async function createTables() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
      username TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      email TEXT,
      phone TEXT,
      hotel_name TEXT,
      address TEXT,
      trial_ends_at TIMESTAMPTZ NOT NULL,
      subscription_ends_at TIMESTAMPTZ
    )
  `);

  await pool.query(`
  CREATE TABLE IF NOT EXISTS payment_requests (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id),
    plan TEXT NOT NULL,
    transaction_reference TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    received_at TIMESTAMPTZ,
    approved_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL
  )
`);
}

createTables().catch((error) => {
  console.error('Database initialization failed:', error);
  process.exit(1);
});


function addDays(date, days) {
  const result = new Date(date);
  result.setUTCDate(result.getUTCDate() + days);
  return result;
}

function createToken(user) {
  return jwt.sign(
    { userId: user.id },
    process.env.JWT_SECRET,
    { expiresIn: "7d" }
  );
}

function requireLogin(req, res, next) {
  const header = req.get("Authorization") || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";

  if (!token) {
    return res.status(401).json({ error: "Authentication required." });
  }

  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);

    if (!payload.userId) {
      return res.status(401).json({ error: "Invalid token." });
    }

    req.auth = payload;
    return next();
  } catch {
    return res.status(401).json({ error: "Invalid or expired token." });
  }
}

async function getUser(userId) {
  const result = await pool.query(
    'SELECT * FROM users WHERE id = $1',
    [userId]
  );
  return result.rows[0] ?? null;
}

function hasServiceAccess(user) {
  const now = Date.now();
  const trialEnd = Date.parse(user.trial_ends_at);
  const subscriptionEnd = user.subscription_ends_at
    ? Date.parse(user.subscription_ends_at)
    : 0;

  return now < trialEnd || now < subscriptionEnd;
}

// Serve the two HTML pages explicitly.
  app.get("/", (req, res) => {
  res.sendFile(path.join(publicDir, "index.html"));
});

  app.get("/dashboard", (req, res) => {
     return res.sendFile(path.join(publicDir, "dashboard.html"));

  if (!user) {
    return res.redirect("/login");
  }

  const account = getAccountStatus(user);

  res.render("dashboard", { user, account });
});

// Register.
app.post("/api/register", async (req, res) => {
  const { username, password, hotel_name, address, email = null, phone = null } = req.body || {};

  if (
    typeof username !== "string" ||
    username.trim().length < 3 ||
    typeof password !== "string" ||
    password.length < 6
  ) {
    return res.status(400).json({
      error: "Username must be at least 3 characters; password at least 6.",
    });
  }

  try {
    const passwordHash = await bcrypt.hash(password, 12);
    const trialEndsAt = addDays(new Date(), 7).toISOString();

    const result = await pool.query(
  `INSERT INTO users
     (username, password_hash, hotel_name, address, email, phone, trial_ends_at)
   VALUES ($1, $2, $3, $4, $5, $6, $7)
   RETURNING id`,
  [
    username.trim(),
    passwordHash,
    hotel_name,
    address,
    email || null,
    phone || null,
    trialEndsAt,
  ]
);

const user = await getUser(result.rows[0].id);

    return res.status(201).json({
      token: createToken(user),
      username: user.username,
      trialEndsAt: user.trial_ends_at,
    });
  } catch (error) {
    if (String(error).includes("UNIQUE")) {
      return res.status(409).json({ error: "That username is already taken." });
    }

    console.error("Registration error:", error);
    return res.status(500).json({ error: "Could not create account." });
  }
});

// Login.
app.post("/api/login", async (req, res) => {
  const { username, password } = req.body || {};

  if (typeof username !== "string" || typeof password !== "string") {
    return res.status(400).json({
      error: "Username and password are required.",
    });
  }

  try {
    const result = await pool.query(
      "SELECT * FROM users WHERE username = $1",
      [username.trim()]
    );
    const user = result.rows[0];

    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({
        error: "Incorrect username or password.",
      });
    }

    return res.json({
      token: createToken(user),
      username: user.username,
    });
  } catch (error) {
    console.error("Login failed:", error);
    return res.status(500).json({ error: "Login failed." });
  }
});

// Protected dashboard API.
app.get("/api/hotel/dashboard", requireLogin, (req, res) => {
   if (!req.auth?.userId) {
    return res.status(401).json({ error: "Authentication required." });
  }

   const user = getUser(req.auth.userId);

   if (!user) {
    return res.status(401).json({ error: "User not found." });
  }

  const now = Date.now();
  const subscriptionExpiry = Date.parse(user.subscription_ends_at || "");
  const trialExpiry = Date.parse(user.trial_ends_at || "");

  const paidActive =
    Number.isFinite(subscriptionExpiry) && subscriptionExpiry > now;
  const trialActive =
    Number.isFinite(trialExpiry) && trialExpiry > now;

  if (!paidActive && !trialActive) {
    return res.status(403).json({
      error: "Your trial or subscription has expired.",
    });
  }

  return res.json({
    username: user.username,
    hotelName: user.hotel_name,
    status: paidActive ? "Active" : "Trial",
    expiresAt: paidActive
      ? user.subscription_ends_at
      : user.trial_ends_at,
  });
});


function getAccountStatus(user) {
  const now = Date.now();

  if (user.subscription_ends_at) {
    const subscriptionExpiry = Date.parse(user.subscription_ends_at);

    if (Number.isFinite(subscriptionExpiry) && subscriptionExpiry > now) {
      return {
        status: "Active",
        access: true,
        expiryDate: user.subscription_ends_at,
        message: `Your plan is active until ${user.subscription_ends_at}`,
      };
    }
  }

  const trialExpiry = Date.parse(user.trial_ends_at);

  if (Number.isFinite(trialExpiry) && trialExpiry > now) {
    return {
      status: "Trial",
      access: true,
      expiryDate: user.trial_ends_at,
      message: `Your 7-day trial ends on ${user.trial_ends_at}`,
    };
  }

  return {
    status: "Expired",
    access: false,
    expiryDate: null,
    message: "Your trial has ended. Choose a plan to continue.",
  };
}

// Unknown API paths should return JSON, not the HTML page.
app.use("/api", (req, res) => {
  res.status(404).json({ error: "API endpoint not found." });
});

// Unknown page paths.
app.use((req, res) => {
  res.status(404).send("Page not found.");
});

const port = Number(process.env.PORT || 3000);

app.listen(port, "0.0.0.0", () => {
  console.log(`Server listening on http://localhost:${port}`);
});
