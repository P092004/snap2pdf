const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { URL } = require("url");

const PORT = process.env.PORT || 4173;
const ROOT = __dirname;
const DB_PATH = path.join(ROOT, "data.json");

function defaultDb() {
  return { users: [], sessions: {}, guestUsage: {} };
}

function readDb() {
  if (!fs.existsSync(DB_PATH)) return defaultDb();
  try {
    return JSON.parse(fs.readFileSync(DB_PATH, "utf8"));
  } catch {
    return defaultDb();
  }
}

function writeDb(db) {
  fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2));
}

function hash(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function makeToken() {
  return crypto.randomBytes(24).toString("hex");
}

function json(res, status, payload) {
  res.writeHead(status, {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS"
  });
  res.end(JSON.stringify(payload));
}

function sendFile(res, filePath) {
  if (!fs.existsSync(filePath)) {
    res.writeHead(404);
    res.end("Not found");
    return;
  }

  const ext = path.extname(filePath);
  const types = {
    ".html": "text/html",
    ".js": "text/javascript",
    ".css": "text/css",
    ".json": "application/json",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".svg": "image/svg+xml"
  };

  res.writeHead(200, {
    "Content-Type": types[ext] || "text/plain",
    "Access-Control-Allow-Origin": "*"
  });

  fs.createReadStream(filePath).pipe(res);
}

function getToken(req) {
  const header = req.headers.authorization || "";
  return header.startsWith("Bearer ") ? header.slice(7) : "";
}

function getIp(req) {
  const forwarded = req.headers["x-forwarded-for"];
  if (typeof forwarded === "string") return forwarded.split(",")[0].trim();
  return req.socket.remoteAddress || "local";
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = "";
    req.on("data", (chunk) => {
      body += chunk;
      if (body.length > 1_000_000) {
        reject(new Error("Payload too large"));
      }
    });
    req.on("end", () => {
      if (!body) return resolve({});
      try {
        resolve(JSON.parse(body));
      } catch {
        reject(new Error("Invalid JSON"));
      }
    });
    req.on("error", reject);
  });
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);

  if (req.method === "OPTIONS") {
    return json(res, 200, { ok: true });
  }

  if (url.pathname === "/api/health" && req.method === "GET") {
    return json(res, 200, { ok: true, service: "snap2pdf-api" });
  }

  if (url.pathname === "/api/auth/signup" && req.method === "POST") {
    try {
      const { name, email, password } = await readBody(req);
      if (!name || !email || !password) return json(res, 400, { message: "Name, email and password are required." });

      const db = readDb();
      const normalized = String(email).toLowerCase().trim();
      if (db.users.some((user) => user.email === normalized)) {
        return json(res, 409, { message: "Email already registered." });
      }

      db.users.push({
        id: crypto.randomUUID(),
        name: String(name).trim(),
        email: normalized,
        passwordHash: hash(password),
        isPro: false,
        usage: 0
      });
      writeDb(db);
      return json(res, 201, { message: "Signup successful. Please login." });
    } catch {
      return json(res, 400, { message: "Invalid request." });
    }
  }

  if (url.pathname === "/api/auth/login" && req.method === "POST") {
    try {
      const { email, password } = await readBody(req);
      const normalized = String(email || "").toLowerCase().trim();
      const db = readDb();
      const user = db.users.find((candidate) => candidate.email === normalized);
      if (!user || user.passwordHash !== hash(password || "")) {
        return json(res, 401, { message: "Invalid email or password." });
      }

      const token = makeToken();
      db.sessions[token] = user.id;
      writeDb(db);
      return json(res, 200, {
        message: "Login successful",
        token,
        user: { name: user.name, email: user.email, isPro: user.isPro, usage: user.usage }
      });
    } catch {
      return json(res, 400, { message: "Invalid request." });
    }
  }

  if (url.pathname === "/api/me" && req.method === "GET") {
    const token = getToken(req);
    if (!token) return json(res, 401, { message: "Missing token" });

    const db = readDb();
    const userId = db.sessions[token];
    const user = db.users.find((candidate) => candidate.id === userId);
    if (!user) return json(res, 401, { message: "Invalid token" });

    return json(res, 200, { user: { name: user.name, email: user.email, isPro: user.isPro, usage: user.usage } });
  }

  if (url.pathname === "/api/usage" && req.method === "GET") {
    const db = readDb();
    const token = getToken(req);
    if (token && db.sessions[token]) {
      const user = db.users.find((candidate) => candidate.id === db.sessions[token]);
      return json(res, 200, { usage: user?.usage || 0, isPro: Boolean(user?.isPro), mode: "user" });
    }

    const ip = getIp(req);
    return json(res, 200, { usage: db.guestUsage[ip] || 0, isPro: false, mode: "guest" });
  }

  if (url.pathname === "/api/usage/increment" && req.method === "POST") {
    const db = readDb();
    const token = getToken(req);

    if (token && db.sessions[token]) {
      const user = db.users.find((candidate) => candidate.id === db.sessions[token]);
      if (!user) return json(res, 404, { message: "User not found" });
      if (!user.isPro) user.usage += 1;
      writeDb(db);
      return json(res, 200, { usage: user.usage, isPro: user.isPro, mode: "user" });
    }

    const ip = getIp(req);
    db.guestUsage[ip] = (db.guestUsage[ip] || 0) + 1;
    writeDb(db);
    return json(res, 200, { usage: db.guestUsage[ip], isPro: false, mode: "guest" });
  }

  if (url.pathname === "/api/pro/activate" && req.method === "POST") {
    const token = getToken(req);
    if (!token) return json(res, 401, { message: "Missing token" });

    const db = readDb();
    const user = db.users.find((candidate) => candidate.id === db.sessions[token]);
    if (!user) return json(res, 401, { message: "Invalid token" });

    user.isPro = true;
    writeDb(db);
    return json(res, 200, { message: "Pro activated", isPro: true });
  }

  const requested = path.join(ROOT, decodeURIComponent(url.pathname));
  if (requested.startsWith(ROOT) && fs.existsSync(requested) && fs.statSync(requested).isFile()) {
    return sendFile(res, requested);
  }

  return sendFile(res, path.join(ROOT, "index.html"));
});

server.listen(PORT, () => {
  console.log(`Snap2PDF running on http://localhost:${PORT}`);
});
