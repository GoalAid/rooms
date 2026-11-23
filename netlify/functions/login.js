const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const ca = process.env.DATABASE_CA?.replace(/\\n/g, "\n").trim();

let sslParams = [];
try {
  const url = new URL(process.env.DATABASE_URL);
  sslParams = [...url.searchParams.keys()].filter((key) =>
    /ssl|cert/i.test(key)
  );
} catch {
  sslParams = ["invalid or missing DATABASE_URL"];
}

console.log("DB TLS diagnostics", {
  hasCa: Boolean(ca),
  caLength: ca?.length ?? 0,
  hasPemMarkers:
    Boolean(ca?.includes("-----BEGIN CERTIFICATE-----")) &&
    Boolean(ca?.includes("-----END CERTIFICATE-----")),
  sslParams,
});

// Reuse the pool while this function instance stays warm.
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    ca: process.env.DATABASE_CA?.replace(/\\n/g, "\n"),
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

  if (!process.env.DATABASE_URL || !process.env.JWT_SECRET) {
    console.error("Missing DATABASE_URL or JWT_SECRET.");
    return json(500, { error: "Server configuration error." });
  }

  let body;
  try {
    const rawBody = event.isBase64Encoded
      ? Buffer.from(event.body || "", "base64").toString("utf8")
      : event.body || "{}";
    body = JSON.parse(rawBody);
  } catch {
    return json(400, { error: "Invalid request body." });
  }

  const { username, password } = body || {};
  if (typeof username !== "string" || typeof password !== "string") {
    return json(400, { error: "请输入用户名和密码" });
  }

  try {
    const result = await pool.query(
      "SELECT * FROM users WHERE username = $1",
      [username.trim()]
    );

    const user = result.rows[0];
    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return json(401, { error: "❗️用户名或密码不正确" });
    }

    const token = jwt.sign(
      { userId: user.id },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    return json(200, { token, username: user.username });
  } catch (error) {
    console.error("Login function failed:", error);
    return json(500, { error: "Login failed." });
  }
};
