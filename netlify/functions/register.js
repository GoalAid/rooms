const { Pool } = require("pg");
const bcrypt = require("bcryptjs");

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    ca: process.env.DATABASE_CA?.replace(/\\n/g, "\n").trim(),
    rejectUnauthorized: true,
  },
});

function json(statusCode, data) {
  return {
    statusCode,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data),
  };
}

exports.handler = async (event) => {
  if (event.httpMethod !== "POST") {
    return json(405, { error: "Method not allowed." });
  }

  let body;
  try {
    body = JSON.parse(event.body || "{}");
  } catch {
    return json(400, { error: "Invalid request body." });
  }

  const {
    username, password, hotel_name, address,
    email = null, phone = null,
  } = body || {};

  if (
    typeof username !== "string" || username.trim().length < 3 ||
    typeof password !== "string" || password.length < 6
  ) {
    return json(400, { error: "用户名不少于3个字符，密码至少6位" });
  }

  try {
    const passwordHash = await bcrypt.hash(password, 12);
    const trialEndsAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

    await pool.query(
      `INSERT INTO users
        (username, password_hash, hotel_name, address, email, phone, trial_ends_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [
        username.trim(), passwordHash, hotel_name, address,
        email || null, phone || null, trialEndsAt,
      ]
    );

    return json(201, { message: "注册成功！" });
  } catch (error) {
    if (error.code === "23505") {
      return json(409, { error: "用户名已被注册" });
    }
    console.error("Registration function failed:", error);
    return json(500, { error: "无法创建账号" });
  }
};
