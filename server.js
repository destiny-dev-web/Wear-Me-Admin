"use strict";
/*
  WEAR ME server
  - Stores the shop data (products, settings, orders, sewing requests, ledger) in data/db.json
  - Stores uploaded pictures and videos in uploads/
  - One admin account (email + password), password kept as a salted scrypt hash in data/admin.json
  Nothing to install: it uses only what comes with Node (version 18 or newer).
*/
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const http = require("http");

/* ---------- settings ---------- */
function loadEnv() {
  try {
    fs.readFileSync(path.join(__dirname, ".env"), "utf8").split(/\r?\n/).forEach((l) => {
      const m = l.match(/^\s*([A-Z_]+)\s*=\s*(.*?)\s*$/);
      if (m && !l.trim().startsWith("#") && process.env[m[1]] === undefined) process.env[m[1]] = m[2];
    });
  } catch (e) { /* no .env file, defaults apply */ }
}
loadEnv();
const PORT = Number(process.env.PORT) || 4000;
const ORIGINS = (process.env.ALLOWED_ORIGINS || "*").split(",").map((s) => s.trim()).filter(Boolean);
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || "").trim().toLowerCase();
const SESSION_MS = (Number(process.env.SESSION_HOURS) || 12) * 3600 * 1000;
const MAX_UPLOAD = (Number(process.env.MAX_UPLOAD_MB) || 25) * 1048576;
const PUBLIC_IMAGE_MAX = 10 * 1048576;
const DATA_DIR = path.resolve(__dirname, process.env.DATA_DIR || "data");
const UPLOAD_DIR = path.resolve(__dirname, process.env.UPLOAD_DIR || "uploads");
const TRUST_PROXY = process.env.TRUST_PROXY === "1";
const SITE_DIR = process.env.SITE_DIR ? path.resolve(__dirname, process.env.SITE_DIR) : "";
fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

/* ---------- tiny file database ---------- */
const DB_FILE = path.join(DATA_DIR, "db.json");
const ADMIN_FILE = path.join(DATA_DIR, "admin.json");
function readJson(file, fallback) {
  try { return JSON.parse(fs.readFileSync(file, "utf8")); } catch (e) { return fallback; }
}
const docs = readJson(DB_FILE, {}); // { "products/1": {...}, "settings/site": {...} }
let admin = readJson(ADMIN_FILE, null); // { email, salt, hash, profile, createdAt }
let saveTimer = null;
function writeAtomic(file, text) {
  const tmp = file + ".tmp";
  fs.writeFileSync(tmp, text);
  fs.renameSync(tmp, file);
}
function saveDb() {
  clearTimeout(saveTimer);
  saveTimer = setTimeout(() => {
    try { writeAtomic(DB_FILE, JSON.stringify(docs)); } catch (e) { console.error("Could not save data:", e.message); }
  }, 150);
}
function flush() { try { writeAtomic(DB_FILE, JSON.stringify(docs)); } catch (e) { /* ignore */ } }
process.on("SIGINT", () => { flush(); process.exit(0); });
process.on("SIGTERM", () => { flush(); process.exit(0); });

const COLLECTIONS = ["products", "settings", "orders", "styling", "ledger"];
const PUBLIC_READ = ["products", "settings"];
const DOC_PATH = /^([a-z]+)\/([A-Za-z0-9_-]{1,64})$/;
function parsePath(p) {
  const m = DOC_PATH.exec(String(p || ""));
  if (!m || !COLLECTIONS.includes(m[1])) return null;
  return { col: m[1], id: m[2], path: m[0] };
}
function colDocs(col) {
  const out = [];
  const prefix = col + "/";
  for (const k of Object.keys(docs)) if (k.startsWith(prefix)) out.push({ id: k.slice(prefix.length), data: docs[k] });
  return out;
}

/* ---------- passwords and sessions ---------- */
function hashPassword(pw, saltHex) {
  const salt = saltHex ? Buffer.from(saltHex, "hex") : crypto.randomBytes(16);
  const hash = crypto.scryptSync(pw, salt, 64, { N: 16384, r: 8, p: 1 });
  return { salt: salt.toString("hex"), hash: hash.toString("hex") };
}
function checkPassword(pw, acc) {
  const h = hashPassword(pw, acc.salt).hash;
  const a = Buffer.from(h, "hex"), b = Buffer.from(acc.hash, "hex");
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
const sessions = new Map(); // sha256(token) -> expiry
const sha = (s) => crypto.createHash("sha256").update(s).digest("hex");
function newSession() {
  const token = crypto.randomBytes(32).toString("hex");
  sessions.set(sha(token), Date.now() + SESSION_MS);
  return token;
}
function tokenOf(req) {
  const h = req.headers.authorization || "";
  return h.startsWith("Bearer ") ? h.slice(7) : "";
}
function isAdmin(req) {
  const t = tokenOf(req);
  if (!t || !admin) return false;
  const k = sha(t), exp = sessions.get(k);
  if (!exp) return false;
  if (exp < Date.now()) { sessions.delete(k); return false; }
  return true;
}
setInterval(() => { const n = Date.now(); for (const [k, v] of sessions) if (v < n) sessions.delete(k); }, 600000).unref();

/* ---------- small rate limiter ---------- */
const hits = new Map();
function clientIp(req) {
  if (TRUST_PROXY) { const f = String(req.headers["x-forwarded-for"] || "").split(",")[0].trim(); if (f) return f; }
  return req.socket.remoteAddress || "?";
}
function limited(req, name, max, windowMs) {
  const key = name + ":" + clientIp(req), now = Date.now();
  let h = hits.get(key);
  if (!h || h.reset < now) h = { n: 0, reset: now + windowMs };
  h.n++; hits.set(key, h);
  return h.n > max;
}
setInterval(() => { const n = Date.now(); for (const [k, v] of hits) if (v.reset < n) hits.delete(k); }, 600000).unref();

/* ---------- http helpers ---------- */
class HttpError extends Error { constructor(code, msg) { super(msg); this.code = code; } }
const bad = (code, msg) => { throw new HttpError(code, msg); };
function send(res, code, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(code, { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" });
  res.end(body);
}
function readBody(req, max) {
  return new Promise((resolve, reject) => {
    const chunks = []; let n = 0;
    req.on("data", (c) => { n += c.length; if (n > max) { reject(new HttpError(413, "That is too big.")); req.destroy(); } else chunks.push(c); });
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}
async function readBodyJson(req, max = 8 * 1048576) {
  const buf = await readBody(req, max);
  try { const v = JSON.parse(buf.toString("utf8") || "{}"); return v; } catch (e) { return bad(400, "Send valid JSON."); }
}
function cors(req, res) {
  const origin = req.headers.origin;
  if (origin && (ORIGINS.includes("*") || ORIGINS.includes(origin))) {
    res.setHeader("Access-Control-Allow-Origin", ORIGINS.includes("*") ? "*" : origin);
    res.setHeader("Vary", "Origin");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, X-File-Name");
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS");
    res.setHeader("Access-Control-Max-Age", "600");
    return true;
  }
  return !origin;
}
const MIME = { ".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".json": "application/json", ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".webp": "image/webp", ".gif": "image/gif", ".svg": "image/svg+xml", ".ico": "image/x-icon", ".mp4": "video/mp4", ".webm": "video/webm", ".txt": "text/plain; charset=utf-8", ".md": "text/plain; charset=utf-8" };
function sendFile(req, res, file, extra) {
  fs.stat(file, (err, st) => {
    if (err || !st.isFile()) { res.writeHead(404); return res.end(); }
    const type = MIME[path.extname(file).toLowerCase()] || "application/octet-stream";
    const headers = Object.assign({ "Content-Type": type, "Accept-Ranges": "bytes" }, extra || {});
    const m = /^bytes=(\d*)-(\d*)$/.exec(String(req.headers.range || ""));
    if (m && (m[1] || m[2])) {
      let start = m[1] ? Number(m[1]) : st.size - Number(m[2]), end = m[1] && m[2] ? Number(m[2]) : st.size - 1;
      end = Math.min(end, st.size - 1);
      if (start > end || start < 0) { res.writeHead(416, { "Content-Range": "bytes */" + st.size }); return res.end(); }
      res.writeHead(206, Object.assign(headers, { "Content-Range": "bytes " + start + "-" + end + "/" + st.size, "Content-Length": end - start + 1 }));
      return fs.createReadStream(file, { start, end }).pipe(res);
    }
    res.writeHead(200, Object.assign(headers, { "Content-Length": st.size }));
    fs.createReadStream(file).pipe(res);
  });
}

/* ---------- rules ---------- */
const clip = (v, n) => String(v == null ? "" : v).slice(0, n);
const isObj = (b) => b && typeof b === "object" && !Array.isArray(b);
function cleanNewOrder(o) {
  o = Object.assign({}, o);
  o.status = "New";
  o.payStatus = o.payStatus === "Proof sent" ? "Proof sent" : "Unpaid";
  delete o.refund; delete o.paidAt; delete o.statusAt; delete o.trackNote; delete o.cancelReason;
  o.createdAt = new Date().toISOString();
  return o;
}
function cleanNewStyling(s) {
  s = Object.assign({}, s);
  s.status = "New"; s.paid = false;
  delete s.quote; delete s.paidAt;
  s.createdAt = new Date().toISOString();
  return s;
}
function publicAccount() { return admin ? { email: admin.email, profile: admin.profile || {} } : null; }

/* ---------- routes ---------- */
const routes = {};
const route = (method, p, fn) => { routes[method + " " + p] = fn; };

route("GET", "/api/health", (req, res) => send(res, 200, { ok: true }));

route("GET", "/api/doc", (req, res, q) => {
  const p = parsePath(q.get("path"));
  if (!p) bad(400, "Bad path");
  if (!PUBLIC_READ.includes(p.col) && !isAdmin(req)) bad(403, "Not allowed");
  const data = docs[p.path];
  send(res, 200, { exists: data !== undefined, data: data === undefined ? null : data });
});
route("GET", "/api/col", (req, res, q) => {
  const name = String(q.get("name") || "");
  if (!COLLECTIONS.includes(name)) bad(400, "Unknown collection");
  let list = colDocs(name);
  const where = String(q.get("where") || "").split(",");
  if (!isAdmin(req)) {
    if (PUBLIC_READ.includes(name)) { /* anyone may read */ }
    else if (name === "orders") {
      if (where.length < 3 || where[0] !== "email" || where[1] !== "==") bad(403, "Not allowed");
      const em = where.slice(2).join(",").trim().toLowerCase();
      if (!/^\S+@\S+\.\S+$/.test(em)) bad(400, "Bad email");
      list = list.filter((d) => String(d.data.email || "").toLowerCase() === em);
    } else bad(403, "Not allowed");
  } else if (where.length >= 3 && where[1] === "==") {
    const v = where.slice(2).join(",");
    list = list.filter((d) => String(d.data[where[0]]) === v);
  }
  send(res, 200, { docs: list });
});
route("PUT", "/api/doc", async (req, res, q) => {
  if (limited(req, "write", 600, 3600000)) bad(429, "Too many requests.");
  const p = parsePath(q.get("path"));
  if (!p) bad(400, "Bad path");
  const body = await readBodyJson(req);
  if (!isObj(body)) bad(400, "Send an object.");
  if (isAdmin(req)) { docs[p.path] = body; saveDb(); return send(res, 200, { ok: true }); }
  if (docs[p.path] !== undefined) bad(403, "Not allowed");
  if (p.col === "orders") { docs[p.path] = cleanNewOrder(Object.assign({}, body, { id: p.id })); saveDb(); return send(res, 200, { ok: true }); }
  if (p.col === "styling") { docs[p.path] = cleanNewStyling(Object.assign({}, body, { id: p.id })); saveDb(); return send(res, 200, { ok: true }); }
  bad(403, "Not allowed");
});
route("PATCH", "/api/doc", async (req, res, q) => {
  if (limited(req, "write", 600, 3600000)) bad(429, "Too many requests.");
  const p = parsePath(q.get("path"));
  if (!p) bad(400, "Bad path");
  const body = await readBodyJson(req);
  if (!isObj(body)) bad(400, "Send an object.");
  if (isAdmin(req)) { docs[p.path] = Object.assign({}, docs[p.path] || {}, body); saveDb(); return send(res, 200, { ok: true }); }
  const cur = docs[p.path], keys = Object.keys(body);
  if (p.col === "orders" && cur && !cur.refund && keys.length === 1 && keys[0] === "refund" && isObj(body.refund) && body.refund.status === "Requested" && cur.status !== "Cancelled" && cur.payStatus !== "Unpaid") {
    cur.refund = { status: "Requested", reason: clip(body.refund.reason, 80), note: clip(body.refund.note, 1000), at: new Date().toISOString() };
    saveDb();
    return send(res, 200, { ok: true });
  }
  bad(403, "Not allowed");
});
route("DELETE", "/api/doc", (req, res, q) => {
  const p = parsePath(q.get("path"));
  if (!p) bad(400, "Bad path");
  if (!isAdmin(req)) bad(403, "Not allowed");
  delete docs[p.path]; saveDb();
  send(res, 200, { ok: true });
});

/* admin account */
route("GET", "/api/admin/status", (req, res) => {
  const ok = isAdmin(req);
  send(res, 200, { exists: !!admin, loggedIn: ok, account: ok ? publicAccount() : null });
});
route("POST", "/api/admin/create", async (req, res) => {
  if (limited(req, "create", 10, 3600000)) bad(429, "Too many tries. Wait a little and try again.");
  const b = await readBodyJson(req, 65536);
  if (admin) bad(403, "An admin account already exists.");
  const email = clip(b.email, 200).trim().toLowerCase(), pw = String(b.password || "");
  if (!/^\S+@\S+\.\S+$/.test(email)) bad(400, "Enter a valid email address.");
  if (pw.length < 8) bad(400, "Use at least 8 characters for the password.");
  if (ADMIN_EMAIL && email !== ADMIN_EMAIL) bad(403, "That email is not allowed to create the admin account.");
  const h = hashPassword(pw);
  admin = { email, salt: h.salt, hash: h.hash, profile: {}, createdAt: new Date().toISOString() };
  writeAtomic(ADMIN_FILE, JSON.stringify(admin));
  send(res, 200, { ok: true, token: newSession(), account: publicAccount() });
});
route("POST", "/api/admin/login", async (req, res) => {
  if (limited(req, "login", 8, 900000)) bad(429, "Too many tries. Wait 15 minutes and try again.");
  const b = await readBodyJson(req, 65536);
  if (!admin) bad(400, "No admin account yet.");
  const email = clip(b.email, 200).trim().toLowerCase(), pw = String(b.password || "");
  if (email !== admin.email || !checkPassword(pw, admin)) bad(401, "That email and password do not match.");
  send(res, 200, { ok: true, token: newSession(), account: publicAccount() });
});
route("POST", "/api/admin/logout", (req, res) => {
  const t = tokenOf(req); if (t) sessions.delete(sha(t));
  send(res, 200, { ok: true });
});
route("PUT", "/api/admin/profile", async (req, res) => {
  if (!isAdmin(req)) bad(401, "Log in first.");
  const b = await readBodyJson(req, 65536);
  admin.profile = { name: clip(b.name, 120).trim(), dob: clip(b.dob, 20), phone: clip(b.phone, 40).trim(), role: clip(b.role, 80).trim() };
  writeAtomic(ADMIN_FILE, JSON.stringify(admin));
  send(res, 200, { ok: true, account: publicAccount() });
});
route("POST", "/api/admin/password", async (req, res) => {
  if (!isAdmin(req)) bad(401, "Log in first.");
  if (limited(req, "pw", 10, 900000)) bad(429, "Too many tries. Wait a little and try again.");
  const b = await readBodyJson(req, 65536), old = String(b.old || ""), pw = String(b.password || "");
  if (!checkPassword(old, admin)) bad(400, "Your current password is not right.");
  if (pw.length < 8) bad(400, "Use at least 8 characters.");
  const h = hashPassword(pw);
  admin.salt = h.salt; admin.hash = h.hash;
  writeAtomic(ADMIN_FILE, JSON.stringify(admin));
  const keep = sha(tokenOf(req));
  for (const k of [...sessions.keys()]) if (k !== keep) sessions.delete(k);
  send(res, 200, { ok: true });
});

/* uploads */
const TYPES = {
  "image/jpeg": ["jpg", (b) => b[0] === 0xff && b[1] === 0xd8],
  "image/png": ["png", (b) => b.slice(0, 4).toString("hex") === "89504e47"],
  "image/webp": ["webp", (b) => b.slice(0, 4).toString() === "RIFF" && b.slice(8, 12).toString() === "WEBP"],
  "image/gif": ["gif", (b) => b.slice(0, 3).toString() === "GIF"],
  "video/mp4": ["mp4", (b) => b.slice(4, 8).toString() === "ftyp"],
  "video/webm": ["webm", (b) => b.slice(0, 4).toString("hex") === "1a45dfa3"]
};
route("POST", "/api/upload", async (req, res) => {
  if (limited(req, "upload", 60, 3600000)) bad(429, "Too many uploads. Try again later.");
  const type = String(req.headers["content-type"] || "").split(";")[0].trim().toLowerCase();
  const t = TYPES[type];
  if (!t) bad(415, "Use a JPG, PNG, WebP, MP4 or WebM file.");
  const adm = isAdmin(req);
  const buf = await readBody(req, adm ? MAX_UPLOAD : PUBLIC_IMAGE_MAX);
  if (buf.length < 12 || !t[1](buf)) bad(415, "That file does not look like a " + type + ".");
  if (!adm && type.startsWith("video/")) bad(403, "Not allowed.");
  const id = crypto.randomBytes(12).toString("hex");
  fs.writeFileSync(path.join(UPLOAD_DIR, id + "." + t[0]), buf);
  send(res, 200, { id, url: "/blob/" + id, contentType: type });
});

/* ---------- server ---------- */
const server = http.createServer(async (req, res) => {
  try {
    const u = new URL(req.url, "http://localhost");
    if (!cors(req, res)) return send(res, 403, { error: "This website is not allowed to use the server." });
    res.setHeader("X-Content-Type-Options", "nosniff");
    if (req.method === "OPTIONS") { res.writeHead(204); return res.end(); }
    const fn = routes[req.method + " " + u.pathname];
    if (fn) return await fn(req, res, u.searchParams);
    if (req.method === "GET" && u.pathname.startsWith("/blob/")) {
      const id = u.pathname.slice(6).replace(/[^a-f0-9]/g, "");
      const file = id.length === 24 && fs.readdirSync(UPLOAD_DIR).find((f) => f.startsWith(id + "."));
      if (!file) { res.writeHead(404); return res.end(); }
      return sendFile(req, res, path.join(UPLOAD_DIR, file), { "Cross-Origin-Resource-Policy": "cross-origin", "Cache-Control": "public, max-age=31536000, immutable" });
    }
    if (u.pathname.startsWith("/api/")) bad(404, "Not found");
    if (SITE_DIR && (req.method === "GET" || req.method === "HEAD")) {
      let rel = decodeURIComponent(u.pathname);
      if (rel.endsWith("/")) rel += "index.html";
      const file = path.join(SITE_DIR, path.normalize(rel));
      if (file.startsWith(SITE_DIR + path.sep) || file === SITE_DIR) return sendFile(req, res, file);
    }
    res.writeHead(404, { "Content-Type": "text/plain" }); res.end("Not found");
  } catch (e) {
    if (e instanceof HttpError) { if (!res.headersSent) send(res, e.code, { error: e.message }); else res.end(); return; }
    console.error(e);
    if (!res.headersSent) send(res, 500, { error: "Server error" }); else res.end();
  }
});
server.listen(PORT, () => {
  console.log("WEAR ME server running on port " + PORT);
  console.log(admin ? "Admin account: set up" : "Admin account: not created yet (open admin.html to create it)");
  if (SITE_DIR) console.log("Also serving the website from " + SITE_DIR);
});
