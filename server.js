import express from "express";
import pg from "pg";
import bcrypt from "bcryptjs";
import cookieParser from "cookie-parser";
import rateLimit from "express-rate-limit";
import crypto from "node:crypto";
import fs from "node:fs";

const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL });
await pool.query(fs.readFileSync(new URL("./schema.sql", import.meta.url), "utf8"));

const app = express();
app.set("trust proxy", 1);                       // Railway sits behind a proxy
app.use(express.json({ limit: "2mb" }));
app.use(cookieParser());
app.use(express.static("public", { extensions: ["html"] }));

const sha = (s) => crypto.createHash("sha256").update(s).digest("hex");
const COOKIE = { httpOnly: true, sameSite: "lax", secure: !!process.env.RAILWAY_ENVIRONMENT, maxAge: 30 * 864e5 };
const isMobile = (m) => /^\+\d{8,15}$/.test(m);
const isPin = (p) => /^\d{4}$/.test(p);
const authLimit = rateLimit({ windowMs: 15 * 60 * 1000, limit: 20 });

async function startSession(res, userId) {
  const token = crypto.randomBytes(32).toString("hex");
  await pool.query("INSERT INTO sessions (token, user_id, expires_at) VALUES ($1, $2, now() + interval '30 days')", [sha(token), userId]);
  res.cookie("sid", token, COOKIE);
}

// checks a PIN; 5 wrong tries lock the account for 15 minutes. Returns an error or null.
async function checkPin(u, pin, wrongMsg) {
  if (u.locked_until > new Date()) return { status: 429, error: "Too many wrong tries. Try again in a few minutes." };
  if (isPin(pin) && await bcrypt.compare(pin, u.pin_hash)) {
    await pool.query("UPDATE users SET failed_tries = 0, locked_until = NULL WHERE id = $1", [u.id]);
    return null;
  }
  await pool.query(
    `UPDATE users SET failed_tries = CASE WHEN failed_tries >= 4 THEN 0 ELSE failed_tries + 1 END,
       locked_until = CASE WHEN failed_tries >= 4 THEN now() + interval '15 minutes' ELSE locked_until END
     WHERE id = $1`, [u.id]);
  return { status: 401, error: wrongMsg };
}

async function auth(req, res, next) {
  const t = req.cookies.sid;
  const { rows } = t ? await pool.query(
    `SELECT u.id, u.name, u.mobile FROM sessions s JOIN users u ON u.id = s.user_id
     WHERE s.token = $1 AND s.expires_at > now()`, [sha(t)]) : { rows: [] };
  if (!rows[0]) return res.status(401).json({ error: "Please log in." });
  req.user = rows[0];
  next();
}

app.post("/api/signup", authLimit, async (req, res) => {
  const { name, mobile, pin } = req.body ?? {};
  if (!name?.trim() || !isMobile(mobile) || !isPin(pin)) return res.status(400).json({ error: "Check your name, number and PIN." });
  try {
    const { rows } = await pool.query(
      "INSERT INTO users (name, mobile, pin_hash) VALUES ($1, $2, $3) RETURNING id, name, mobile",
      [name.trim(), mobile, await bcrypt.hash(pin, 10)]);
    await startSession(res, rows[0].id);
    res.json({ user: rows[0] });
  } catch (e) {
    if (e.code === "23505") return res.status(409).json({ error: "An account with this number already exists." });
    throw e;
  }
});

app.post("/api/login", authLimit, async (req, res) => {
  const { mobile, pin } = req.body ?? {};
  const { rows } = await pool.query("SELECT * FROM users WHERE mobile = $1", [mobile]);
  const u = rows[0];
  const wrong = "Mobile number or PIN is incorrect.";
  if (!u) return res.status(401).json({ error: wrong });
  const err = await checkPin(u, pin, wrong);
  if (err) return res.status(err.status).json({ error: err.error });
  await startSession(res, u.id);
  res.json({ user: { id: u.id, name: u.name, mobile: u.mobile } });
});

app.post("/api/pin", authLimit, auth, async (req, res) => {
  const { pin, newPin } = req.body ?? {};
  if (!isPin(newPin)) return res.status(400).json({ error: "Your new PIN needs exactly 4 digits." });
  const { rows } = await pool.query("SELECT * FROM users WHERE id = $1", [req.user.id]);
  const err = await checkPin(rows[0], pin, "That’s not your current PIN.");
  if (err) return res.status(err.status).json({ error: err.error });
  await pool.query("UPDATE users SET pin_hash = $1 WHERE id = $2", [await bcrypt.hash(newPin, 10), req.user.id]);
  res.json({ ok: true });
});

app.post("/api/logout", async (req, res) => {
  if (req.cookies.sid) await pool.query("DELETE FROM sessions WHERE token = $1", [sha(req.cookies.sid)]);
  res.clearCookie("sid").json({ ok: true });
});

app.get("/api/me", auth, (req, res) => res.json({ user: req.user }));

app.get("/api/state", auth, async (req, res) => {
  const { rows } = await pool.query("SELECT state FROM user_data WHERE user_id = $1", [req.user.id]);
  res.json({ state: rows[0]?.state ?? null });
});

app.put("/api/state", auth, async (req, res) => {
  const state = req.body?.state;
  if (!state || !Array.isArray(state.trips)) return res.status(400).json({ error: "Bad data." });
  await pool.query(
    `INSERT INTO user_data (user_id, state, updated_at) VALUES ($1, $2, now())
     ON CONFLICT (user_id) DO UPDATE SET state = EXCLUDED.state, updated_at = now()`,
    [req.user.id, state]);
  res.json({ ok: true });
});

app.delete("/api/account", authLimit, auth, async (req, res) => {
  const { rows } = await pool.query("SELECT * FROM users WHERE id = $1", [req.user.id]);
  const err = await checkPin(rows[0], req.body?.pin, "That’s not your PIN.");
  if (err) return res.status(err.status).json({ error: err.error });
  await pool.query("DELETE FROM users WHERE id = $1", [req.user.id]);   // cascades to sessions + trips
  res.clearCookie("sid").json({ ok: true });
});

app.listen(process.env.PORT || 3000, () => console.log("Karo Split running"));
