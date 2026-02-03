const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");
const { Pool } = require("pg");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3001;
const DATABASE_URL = process.env.DATABASE_URL;
const JWT_SECRET = process.env.JWT_SECRET;

if (!DATABASE_URL) throw new Error("DATABASE_URL missing in .env");
if (!JWT_SECRET) throw new Error("JWT_SECRET missing in .env");

const pool = new Pool({ connectionString: DATABASE_URL });

app.get("/", (req, res) => res.send("Backend running"));

function signToken(user) {
  return jwt.sign(
    { id: user.id, role: user.role, email: user.email },
    JWT_SECRET,
    { expiresIn: "7d" }
  );
}

function auth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: "No token" });

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: "Invalid token" });
  }
}

function adminOnly(req, res, next) {
  if (req.user.role !== "admin") return res.status(403).json({ error: "Admin only" });
  next();
}

// ✅ Register
app.post("/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: "email & password required" });

    const hash = await bcrypt.hash(password, 10);
    const r = await pool.query(
      "INSERT INTO users(name,email,password_hash) VALUES($1,$2,$3) RETURNING id,name,email,role,created_at",
      [name || null, email.toLowerCase(), hash]
    );

    res.json({ user: r.rows[0] });
  } catch (e) {
    if (String(e.message).includes("duplicate key")) {
      return res.status(409).json({ error: "Email already exists" });
    }
    res.status(500).json({ error: e.message });
  }
});

// ✅ Login
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: "email & password required" });

  const r = await pool.query("SELECT * FROM users WHERE email=$1", [email.toLowerCase()]);
  const user = r.rows[0];
  if (!user) return res.status(401).json({ error: "Invalid credentials" });

  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) return res.status(401).json({ error: "Invalid credentials" });

  res.json({ token: signToken(user), role: user.role });
});

// ✅ Current user
app.get("/me", auth, async (req, res) => {
  const r = await pool.query("SELECT id,name,email,role,created_at FROM users WHERE id=$1", [req.user.id]);
  res.json({ user: r.rows[0] });
});

// ✅ Admin: list users
app.get("/admin/users", auth, adminOnly, async (req, res) => {
  const r = await pool.query("SELECT id,name,email,role,created_at FROM users ORDER BY id DESC");
  res.json({ users: r.rows });
});

app.listen(PORT, () => console.log(`✅ Server listening on http://localhost:${PORT}`));
app.post("/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: "email & password required" });
    }

    const hash = await bcrypt.hash(password, 10);

    const r = await pool.query(
      "INSERT INTO users(name,email,password_hash) VALUES ($1,$2,$3) RETURNING id,name,email,role,status,created_at",
      [name || null, email.toLowerCase(), hash]
    );

    return res.status(201).json({ user: r.rows[0] });

  } catch (e) {
    // duplicate email
    if (e.code === "23505") {
      return res.status(409).json({ error: "Email already exists" });
    }

    console.error("REGISTER ERROR:", e);
    return res.status(500).json({ error: e.message });
  }
});

app.listen(PORT, "0.0.0.0", () => console.log(`Server running on ${PORT}`));


