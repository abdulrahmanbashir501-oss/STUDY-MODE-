require("dotenv").config();
const express = require("express");
const session = require("express-session");
const SQLiteStore = require("connect-sqlite3")(session);
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const path = require("path");
const fs = require("fs");

const app = express();
const PORT = Number(process.env.PORT || 3000);
const isProd = process.env.NODE_ENV === "production";
const dataDir = path.join(__dirname, "data");
fs.mkdirSync(dataDir, { recursive: true });
const db = new Database(path.join(dataDir, "study-mode.sqlite"));
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS tasks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  title TEXT NOT NULL,
  subject TEXT NOT NULL DEFAULT 'عام',
  due_date TEXT,
  done INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS vocab (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  word TEXT NOT NULL,
  meaning TEXT NOT NULL DEFAULT '',
  example TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`);
if (isProd && (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32)) {
  throw new Error("In production, SESSION_SECRET must be at least 32 characters.");
}
app.disable("x-powered-by");
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "https://cdn.jsdelivr.net", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "blob:"],
      connectSrc: ["'self'", "https://cdn.jsdelivr.net"],
      workerSrc: ["'self'", "blob:", "https://cdn.jsdelivr.net"]
    }
  }
}));
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: false, limit: "1mb" }));
app.use(session({
  store: new SQLiteStore({ db: "sessions.sqlite", dir: dataDir }),
  name: "study.sid",
  secret: process.env.SESSION_SECRET || "development-only-change-this-secret-please",
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: isProd,
    maxAge: 1000 * 60 * 60 * 24 * 7
  }
}));
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 12, standardHeaders: true, legacyHeaders: false });
const usernameValid = s => typeof s === "string" && /^[a-zA-Z0-9_]{3,24}$/.test(s);
const getUser = req => req.session.userId || null;
function requireAuth(req, res, next) {
  if (!getUser(req)) return res.status(401).json({ error: "سجّل الدخول أولاً." });
  next();
}
app.post("/api/register", authLimiter, async (req, res) => {
  const { username, password } = req.body || {};
  if (!usernameValid(username)) return res.status(400).json({ error: "اسم المستخدم يجب أن يكون 3–24 حرفًا إنجليزيًا أو رقمًا أو _." });
  if (typeof password !== "string" || password.length < 10 || password.length > 128)
    return res.status(400).json({ error: "كلمة المرور يجب أن تكون من 10 أحرف على الأقل." });
  const hash = await bcrypt.hash(password, 12);
  try {
    const result = db.prepare("INSERT INTO users (username, password_hash) VALUES (?, ?)").run(username, hash);
    req.session.regenerate(err => {
      if (err) return res.status(500).json({ error: "تعذر إنشاء الجلسة." });
      req.session.userId = Number(result.lastInsertRowid);
      res.json({ ok: true, username });
    });
  } catch (e) {
    if (String(e.message).includes("UNIQUE")) return res.status(409).json({ error: "اسم المستخدم مستخدم بالفعل." });
    res.status(500).json({ error: "حدث خطأ غير متوقع." });
  }
});
app.post("/api/login", authLimiter, (req, res) => {
  const { username, password } = req.body || {};
  if (!usernameValid(username) || typeof password !== "string") return res.status(400).json({ error: "بيانات الدخول غير صحيحة." });
  const user = db.prepare("SELECT id, username, password_hash FROM users WHERE username = ?").get(username);
  if (!user) return res.status(401).json({ error: "اسم المستخدم أو كلمة المرور غير صحيحة." });
  bcrypt.compare(password, user.password_hash).then(ok => {
    if (!ok) return res.status(401).json({ error: "اسم المستخدم أو كلمة المرور غير صحيحة." });
    req.session.regenerate(err => {
      if (err) return res.status(500).json({ error: "تعذر بدء الجلسة." });
      req.session.userId = user.id;
      res.json({ ok: true, username: user.username });
    });
  });
});
app.post("/api/logout", (req, res) => req.session.destroy(() => {
  res.clearCookie("study.sid", { httpOnly: true, sameSite: "lax", secure: isProd });
  res.json({ ok: true });
}));
app.get("/api/me", (req, res) => {
  if (!getUser(req)) return res.json({ user: null });
  const user = db.prepare("SELECT username FROM users WHERE id = ?").get(getUser(req));
  res.json({ user: user || null });
});
app.get("/api/tasks", requireAuth, (req, res) => {
  res.json(db.prepare("SELECT id,title,subject,due_date,done,created_at FROM tasks WHERE user_id = ? ORDER BY done, id DESC").all(getUser(req)));
});
app.post("/api/tasks", requireAuth, (req, res) => {
  const { title, subject, due_date } = req.body || {};
  if (typeof title !== "string" || !title.trim() || title.trim().length > 180) return res.status(400).json({ error: "اكتب اسم مهمة صحيحًا." });
  const result = db.prepare("INSERT INTO tasks (user_id,title,subject,due_date) VALUES (?,?,?,?)")
    .run(getUser(req), title.trim(), String(subject || "عام").slice(0, 50), typeof due_date === "string" ? due_date.slice(0, 10) : null);
  res.json(db.prepare("SELECT id,title,subject,due_date,done,created_at FROM tasks WHERE id=? AND user_id=?").get(result.lastInsertRowid, getUser(req)));
});
app.patch("/api/tasks/:id", requireAuth, (req, res) => {
  const done = req.body && req.body.done;
  if (typeof done !== "boolean") return res.status(400).json({ error: "حالة المهمة غير صحيحة." });
  const result = db.prepare("UPDATE tasks SET done=? WHERE id=? AND user_id=?").run(done ? 1 : 0, Number(req.params.id), getUser(req));
  if (!result.changes) return res.status(404).json({ error: "المهمة غير موجودة." });
  res.json({ ok: true });
});
app.delete("/api/tasks/:id", requireAuth, (req, res) => {
  const result = db.prepare("DELETE FROM tasks WHERE id=? AND user_id=?").run(Number(req.params.id), getUser(req));
  if (!result.changes) return res.status(404).json({ error: "المهمة غير موجودة." });
  res.json({ ok: true });
});
app.get("/api/vocab", requireAuth, (req, res) => {
  res.json(db.prepare("SELECT id,word,meaning,example,created_at FROM vocab WHERE user_id=? ORDER BY id DESC").all(getUser(req)));
});
app.post("/api/vocab", requireAuth, (req, res) => {
  const { word, meaning, example } = req.body || {};
  if (typeof word !== "string" || !word.trim() || word.trim().length > 120) return res.status(400).json({ error: "الكلمة غير صحيحة." });
  const result = db.prepare("INSERT INTO vocab (user_id,word,meaning,example) VALUES (?,?,?,?)")
    .run(getUser(req), word.trim(), String(meaning || "").slice(0, 240), String(example || "").slice(0, 500));
  res.json(db.prepare("SELECT id,word,meaning,example,created_at FROM vocab WHERE id=? AND user_id=?").get(result.lastInsertRowid, getUser(req)));
});
app.delete("/api/vocab/:id", requireAuth, (req, res) => {
  const result = db.prepare("DELETE FROM vocab WHERE id=? AND user_id=?").run(Number(req.params.id), getUser(req));
  if (!result.changes) return res.status(404).json({ error: "الكلمة غير موجودة." });
  res.json({ ok: true });
});
app.use(express.static(path.join(__dirname, "public")));
app.get("*", (_req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));
app.listen(PORT, () => console.log(`STUDY MODE running at http://localhost:${PORT}`));
