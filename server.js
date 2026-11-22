require("dotenv").config();

const express = require("express");
const path = require("path");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
//const app = require("../server");

//module.exports = app;
const app = express();

const publicDir = path.join(__dirname, "public");

app.use(express.json());
app.use(express.static(publicDir));

const { Pool } = require('pg');
const fs = require('fs');
let pool;
let initialization;

function getPool() {
  if (!pool) {
    if (!process.env.DATABASE_URL) throw new Error('Missing database configuration');
    pool = new Pool({
      connectionString: process.env.DATABASE_URL,
      connectionTimeoutMillis: 4000,
      query_timeout: 8000,
      ssl: { ca: fs.readFileSync(path.join(__dirname, 'ca.pem'), 'utf8'), rejectUnauthorized: true },
    });
    pool.on('error', logDatabaseError);
  }
  return pool;
}

function logDatabaseError(error) {
  console.error('Database unavailable:', error.code || error.name);
}

async function createTables(pool) {
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

class DatabaseUnavailable extends Error {}

async function query(text, values) {
  try {
    if (!initialization) {
      initialization = createTables(getPool()).catch(error => {
        initialization = undefined;
        throw new DatabaseUnavailable('Database setup failed', { cause: error });
      });
    }
    await initialization;
    return await pool.query(text, values);
  } catch (error) {
    if (error instanceof DatabaseUnavailable || !pool || /^(08|53|57P0|28|E|CERT_|DEPTH_|SELF_SIGNED)/.test(error.code || '') || /connection|query read timeout|connect timeout/i.test(error.message)) {
      logDatabaseError(error.cause || error);
      throw new DatabaseUnavailable();
    }
    throw error;
  }
}

function unavailable(res) {
  return res.set('Cache-Control', 'no-store').set('Retry-After', '5').status(503).json({ error: '服务暂时不可用，请稍后重试。' });
}

if (process.env.VERCEL_ENV === 'preview' || require.main === module) {
  app.get('/api/health/database', async (_req, res) => {
    try {
      await getPool().query('SELECT 1');
      res.set('Cache-Control', 'no-store').json({ ok: true });
    } catch (error) {
      logDatabaseError(error);
      unavailable(res);
    }
  });
}

app.use('/api', (_req, res, next) => process.env.JWT_SECRET ? next() : unavailable(res));

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
  const result = await query(
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
      error: "用户名不少于3个字符，密码至少6位",
    });
  }

  try {
    const passwordHash = await bcrypt.hash(password, 12);
    const trialEndsAt = addDays(new Date(), 7).toISOString();

    const result = await query(
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
    if (error instanceof DatabaseUnavailable) return unavailable(res);
    if (String(error).includes("UNIQUE")) {
      return res.status(409).json({ error: "用户名已被注册" });
    }

    console.error("Registration error:", error);
    return res.status(500).json({ error: "无法创建账号" });
  }
});

// Login.
app.post("/api/login", async (req, res) => {
  const { username, password } = req.body || {};

  if (typeof username !== "string" || typeof password !== "string") {
    return res.status(400).json({ error: "请输入用户名和密码" });
  }

  try {
    const result = await query(
      "SELECT * FROM users WHERE username = $1",
      [username.trim()]
    );
   const user = result.rows[0];

  if (!user || !(await bcrypt.compare(password, user.password_hash))) {
    return res.status(401).json({ error: "❗️用户名或密码不正确" });
  }

  return res.json({
      token: createToken(user),
      username: user.username,
    });
  } catch (error) {
    if (error instanceof DatabaseUnavailable) return unavailable(res);
    console.error("Login failed:", error);
    return res.status(500).json({ error: "Login failed." });
  }
});

app.get("/api/subscription/status", requireLogin, async (req, res) => {
  try {
    const user = await getUser(req.auth.userId);
    if (!user) return res.status(401).json({ error: "⚠️该用户不存在" });

    const now = Date.now();
    const trialEnd = Date.parse(user.trial_ends_at);
    const paidEnd = Date.parse(user.subscription_ends_at || "");

    const entitled =
      (Number.isFinite(trialEnd) && now < trialEnd) ||
      (Number.isFinite(paidEnd) && now < paidEnd);

    res.json({
      entitled,
      hotelName: user.hotel_name,
      trialEndsAt: user.trial_ends_at,
      subscriptionEndsAt: user.subscription_ends_at
    });
  } catch (error) {
    if (error instanceof DatabaseUnavailable) return unavailable(res);
    console.error("Subscription status error:", error);
    res.status(500).json({ error: "Could not verify subscription." });
  }
});

  app.get("/api/hotel/dashboard", requireLogin, async (req, res) => {
  try {
    if (!req.auth?.userId) {
      return res.status(401).json({ error: "Authentication required." });
    }

    const user = await getUser(req.auth.userId);

    if (!user) {
      return res.status(401).json({ error: "⚠️该用户不存在" });
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
        error: "⚠️您的试用/订阅已过期",
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
  } catch (error) {
    if (error instanceof DatabaseUnavailable) return unavailable(res);
    console.error("Dashboard API error:", error);
    return res.status(500).json({ error: "Could not load account status." });
  }
});


// Unknown API paths should return JSON, not the HTML page.
app.use("/api", (req, res) => {
  res.status(404).json({ error: "API endpoint not found." });
});

// Unknown page paths.
app.use((req, res) => {
  res.status(404).send("Page not found.");
});

const port = Number(process.env.PORT || 3000);

if (require.main === module) {
  app.listen(port, "0.0.0.0", () => {
    console.log(`Server listening on http://localhost:${port}`);
  });
}

module.exports = app;
