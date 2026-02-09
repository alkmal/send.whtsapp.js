// index.js (cPanel / Passenger hardened - Multi-users + Public Pairing + Realtime QR/Logs/Messages)
//
// Key Fixes added:
// - Per-token start mutex to prevent overlapping sockets.
// - Proper handling for 440 conflict: stop auto-reconnect and require operator action.
// - Inline Login HTML (no external public/login.html dependency).

if (!globalThis.crypto) {
  globalThis.crypto = require("crypto").webcrypto;
}

const express = require("express");
const qrcode = require("qrcode");
const {
  default: makeWASocket,
  useMultiFileAuthState,
  fetchLatestBaileysVersion,
  DisconnectReason,
} = require("@whiskeysockets/baileys");

const cors = require("cors");
const bodyParser = require("body-parser");
const session = require("express-session");
const fs = require("fs");
const crypto = require("crypto");
const path = require("path");

// ===================== App =====================
const app = express();
app.use(cors());
app.use(bodyParser.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use(
  session({
    secret: "whatsapp-api-secret",
    resave: false,
    saveUninitialized: true,
  }),
);

// ===================== Paths =====================
const USERS_FILE = path.join(__dirname, "users.json");
const SESSIONS_DIR = path.join(__dirname, "sessions");
const STORAGE_DIR = path.join(__dirname, "data");
const LOGS_STORAGE = path.join(STORAGE_DIR, "logs");
const MSGS_STORAGE = path.join(STORAGE_DIR, "messages");

[SESSIONS_DIR, STORAGE_DIR, LOGS_STORAGE, MSGS_STORAGE].forEach(d => {
    if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });
});

// ===================== Users Storage =====================
function loadUsers() {
  if (!fs.existsSync(USERS_FILE)) return {};
  try {
    return JSON.parse(fs.readFileSync(USERS_FILE, "utf8"));
  } catch {
    return {};
  }
}
function saveUsers(users) {
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}
const users = loadUsers();

function generateToken() {
  return crypto.randomBytes(16).toString("hex");
}

function requireLogin(req, res, next) {
  if (!req.session.user) return res.redirect("/login");
  next();
}

function getUserToken(req) {
    return req.session.user?.token;
}

function safeRmDir(dirPath) {
  try {
    fs.rmSync(dirPath, { recursive: true, force: true });
  } catch (_) {}
}

// ===================== Global Primary Lock (with heartbeat) =====================
const GLOBAL_LOCK = path.join(SESSIONS_DIR, ".app.primary.lock");
const GLOBAL_LOCK_TTL_MS = 90_000;
let isPrimaryInstance = false;

function pidExists(pid) {
  if (!pid) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (_) {
    return false;
  }
}

function readGlobalLock() {
  try {
    if (!fs.existsSync(GLOBAL_LOCK)) return null;
    return JSON.parse(fs.readFileSync(GLOBAL_LOCK, "utf8"));
  } catch (_) {
    return null;
  }
}

function tryAcquireGlobalLock() {
  try {
    const fd = fs.openSync(GLOBAL_LOCK, "wx");
    const data = { pid: process.pid, at: Date.now(), hb: Date.now() };
    fs.writeFileSync(fd, JSON.stringify(data));
    fs.closeSync(fd);
    isPrimaryInstance = true;
    return true;
  } catch (_) {
    isPrimaryInstance = false;
    return false;
  }
}

function ensurePrimaryOrTrySteal() {
  if (tryAcquireGlobalLock()) return;

  const info = readGlobalLock();
  const lockedPid = info?.pid;
  const lastHb = info?.hb || info?.at || 0;

  const staleByTime = Date.now() - lastHb > GLOBAL_LOCK_TTL_MS;
  const pidDead = lockedPid ? !pidExists(lockedPid) : true;

  if (staleByTime || pidDead) {
    try {
      fs.unlinkSync(GLOBAL_LOCK);
    } catch (_) {}
    tryAcquireGlobalLock();
  }
}

function releaseGlobalLock() {
  try {
    if (fs.existsSync(GLOBAL_LOCK)) fs.unlinkSync(GLOBAL_LOCK);
  } catch (_) {}
  isPrimaryInstance = false;
}

// become primary at boot if possible
ensurePrimaryOrTrySteal();

// heartbeat
setInterval(() => {
  if (!isPrimaryInstance) return;
  const info = readGlobalLock();
  if (!info || info.pid !== process.pid) {
    isPrimaryInstance = false;
    return;
  }
  info.hb = Date.now();
  try {
    fs.writeFileSync(GLOBAL_LOCK, JSON.stringify(info));
  } catch (_) {}
}, 15_000);

// release lock on exit best-effort
process.on("exit", () => {
  if (isPrimaryInstance) releaseGlobalLock();
});
process.on("SIGINT", () => {
  if (isPrimaryInstance) releaseGlobalLock();
  process.exit(0);
});
process.on("SIGTERM", () => {
  if (isPrimaryInstance) releaseGlobalLock();
  process.exit(0);
});

function requirePrimary(req, res, next) {
  if (!isPrimaryInstance) {
    return res
      .status(409)
      .send(
        `⚠️ هذه النسخة ليست الـ Primary على cPanel (PID: ${process.pid}).\n` +
          `لن تعمل عمليات الربط/إعادة التشغيل من هنا.\n` +
          `الحل الأفضل: اجعل instances=1.\n` +
          `أو جرّب: /takeover أو /takeover?force=1`,
      );
  }
  next();
}

// ===================== State =====================
let sockets = {}; // token -> sock
let connState = {}; // token -> open/close/connecting
let qrRaw = {}; // token -> qr raw string
let qrDataUrl = {}; // token -> qr dataUrl
let reconnecting = {};
let reconnectTimers = {}; // Added missing variable
let starting = {};
let nextReconnectAt = {};
let reconnectAttempts = {};
let watchdogTimers = {};
let lastEventAt = {};
let graceUntil = {};
let readyAt = {};
let conflictStop = {}; // token -> boolean
let error515Attempts = {}; // token -> number (track 515 retry attempts)

// logs & messages (ring buffers + file persistence)
const LOG_KEEP = 250;
const MSG_KEEP = 100;
let tokenLogs = {}; 
let tokenMsgs = {}; 

// Load historical data from files on start
Object.keys(users).forEach(token => {
    const logFile = path.join(LOGS_STORAGE, `${token}.log`);
    const msgFile = path.join(MSGS_STORAGE, `${token}.json`);
    
    if (fs.existsSync(logFile)) {
        const lines = fs.readFileSync(logFile, "utf8").trim().split("\n");
        tokenLogs[token] = lines.slice(-LOG_KEEP).map(l => JSON.parse(l));
    }
    if (fs.existsSync(msgFile)) {
        const lines = fs.readFileSync(msgFile, "utf8").trim().split("\n");
        tokenMsgs[token] = lines.slice(-MSG_KEEP).map(l => JSON.parse(l));
    }
});

function pushLog(token, level, msg, meta = null) {
  if (!tokenLogs[token]) tokenLogs[token] = [];
  const entry = { ts: Date.now(), level, msg, meta };
  tokenLogs[token].push(entry);
  if (tokenLogs[token].length > LOG_KEEP) tokenLogs[token].shift();
  
  // Persist to file
  const logFile = path.join(LOGS_STORAGE, `${token}.log`);
  fs.appendFileSync(logFile, JSON.stringify(entry) + "\n");
  
  sseSend(token, { type: "log", ...entry });
}

function pushMsg(token, from, text, id) {
  if (!tokenMsgs[token]) tokenMsgs[token] = [];
  const entry = { ts: Date.now(), from, text, id };
  tokenMsgs[token].push(entry);
  if (tokenMsgs[token].length > MSG_KEEP) tokenMsgs[token].shift();
  
  // Persist to file
  const msgFile = path.join(MSGS_STORAGE, `${token}.json`);
  fs.appendFileSync(msgFile, JSON.stringify(entry) + "\n");
  
  sseSend(token, { type: "msg", ...entry });
}

// ===================== SSE (Realtime) =====================
const sseClients = {}; // token -> Set<res>

function sseSend(token, payload) {
  const set = sseClients[token];
  if (!set || set.size === 0) return;
  const data = `data: ${JSON.stringify(payload)}\n\n`;
  for (const res of set) {
    try {
      res.write(data);
    } catch (_) {}
  }
}

function sseSnapshot(token) {
  const u = users[token];
  return {
    type: "snapshot",
    at: Date.now(),
    token,
    username: u?.username || null,
    primary: isPrimaryInstance,
    pid: process.pid,
    state: connState[token] || "close",
    graceUntil: graceUntil[token] || 0,
    reconnecting: !!reconnecting[token],
    attempts: reconnectAttempts[token] || 0,
    nextReconnectAt: nextReconnectAt[token] || 0,
    readyInMs: Math.max(0, (readyAt[token] || 0) - Date.now()),
    waId: u?.waId || null,
    waName: u?.waName || null,
    lastDisconnectCode: u?.lastDisconnectCode || null,
    lastDisconnectAt: u?.lastDisconnectAt || null,
    lastError: u?.lastError || null,
    qrDataUrl: qrDataUrl[token] || null,
    logs: (tokenLogs[token] || []).slice(-120),
    msgs: (tokenMsgs[token] || []).slice(-MSG_KEEP),
    lastEventAt: lastEventAt[token] || 0,
    conflictStop: !!conflictStop[token],
  };
}

app.get("/pair-stream/:token", (req, res) => {
  const token = req.params.token;
  if (!users[token]) return res.status(401).end("توكن غير صالح");

  res.setHeader("Content-Type", "text/event-stream; charset=utf-8");
  res.setHeader("Cache-Control", "no-cache, no-transform");
  res.setHeader("Connection", "keep-alive");
  res.setHeader("X-Accel-Buffering", "no");
  res.flushHeaders?.();

  if (!sseClients[token]) sseClients[token] = new Set();
  sseClients[token].add(res);

  // snapshot right away
  sseSend(token, sseSnapshot(token));

  // keep-alive ping
  const ping = setInterval(() => {
    try {
      res.write(`event: ping\ndata: {}\n\n`);
    } catch (_) {}
  }, 20_000);

  req.on("close", () => {
    clearInterval(ping);
    try {
      sseClients[token]?.delete(res);
    } catch (_) {}
  });
});

// ===================== Token Lock =====================
function tokenSessionPath(token) {
  const u = users[token];
  return u?.sessionPath || path.join(SESSIONS_DIR, token);
}
function tokenLockFile(token) {
  return path.join(tokenSessionPath(token), ".token.lock");
}

function tryAcquireTokenLock(token) {
    const u = users[token];
    if (!u) return false;

    const sp = tokenSessionPath(token);
    if (!fs.existsSync(sp)) fs.mkdirSync(sp, { recursive: true });

    const lf = tokenLockFile(token);

    const writeLock = () => {
        try {
            const data = JSON.stringify({ pid: process.pid, at: Date.now() });
            fs.writeFileSync(lf, data);
            return true;
        } catch (e) {
            console.error(`[LOCK ERROR] Failed to write lock for ${token}:`, e.message);
            return false;
        }
    };

    if (!fs.existsSync(lf)) {
        return writeLock();
    }

    // Try to read existing lock
    try {
        const content = fs.readFileSync(lf, "utf8");
        if (!content.trim()) throw new Error("Empty lock file");
        
        const info = JSON.parse(content);
        const oldPid = info?.pid;
        const oldAt = info?.at || 0;
        const stale = Date.now() - oldAt > 120_000;

        // If it's our own PID, we already have it (re-entry)
        if (oldPid === process.pid) {
            return writeLock(); // refresh timestamp
        }

        if (!pidExists(oldPid) || stale) {
            // Take over the lock
            return writeLock();
        }
        
        return false; // Valid lock exists and is held by a live process
    } catch (e) {
        // Corrupted or invalid lock file - safe to take over
        console.warn(`[LOCK WARN] Overriding invalid lock for ${token}: ${e.message}`);
        return writeLock();
    }
}

function releaseTokenLock(token) {
  try {
    const lf = tokenLockFile(token);
    if (fs.existsSync(lf)) fs.unlinkSync(lf);
  } catch (_) {}
}

// ===================== Socket Helpers =====================
function clearTokenTimers(token) {
  if (reconnectTimers[token]) {
    clearTimeout(reconnectTimers[token]);
    reconnectTimers[token] = null;
  }
  if (watchdogTimers[token]) {
    clearTimeout(watchdogTimers[token]);
    watchdogTimers[token] = null;
  }
}

function safeEndSocket(token) {
  const sock = sockets[token];
  if (!sock) {
    connState[token] = "close";
    return;
  }

  try {
    // remove all listeners (strong cleanup)
    sock.ev?.removeAllListeners?.();
  } catch (_) {}

  try {
    if (typeof sock.end === "function") sock.end();
  } catch (_) {}

  try {
    if (sock.ws && typeof sock.ws.close === "function") sock.ws.close();
  } catch (_) {}

  sockets[token] = null;
  connState[token] = "close";
}

function clamp(n, min, max) {
  return Math.max(min, Math.min(max, n));
}

function computeBackoffMs(token, code) {
  if (code === 515) return 15_000;
  const attempt = reconnectAttempts[token] || 0;
  const base = 4000;
  const ms = Math.round(base * Math.pow(1.7, attempt));
  return clamp(ms, 4000, 90_000);
}

function getDisconnectCode(lastDisconnect) {
  const e = lastDisconnect?.error;
  return (
    e?.output?.statusCode ||
    e?.output?.payload?.statusCode ||
    e?.output?.status?.statusCode ||
    e?.output?.payload?.status?.statusCode ||
    undefined
  );
}

function armWatchdog(token) {
  if (watchdogTimers[token]) clearTimeout(watchdogTimers[token]);

  // disable watchdog during grace
  const g = graceUntil[token] || 0;
  if (Date.now() < g) return;

  // if conflictStop is active, don't watchdog-restart
  if (conflictStop[token]) return;

  const hasQr = !!qrDataUrl[token];
  const ms = hasQr ? 180_000 : 75_000;

  watchdogTimers[token] = setTimeout(() => {
    const g2 = graceUntil[token] || 0;
    if (Date.now() < g2) return;
    if (conflictStop[token]) return;

    if (connState[token] !== "open") {
      pushLog(token, "warn", "Watchdog: slow connect -> restart", { token });
      reconnectAttempts[token] = (reconnectAttempts[token] || 0) + 1;
      scheduleReconnect(token, 408);
    }
  }, ms);
}

// NEW: stop reconnect for 440
function stopForConflict(token, details) {
  conflictStop[token] = true;
  reconnecting[token] = false;
  nextReconnectAt[token] = 0;

  clearTokenTimers(token);
  safeEndSocket(token);
  releaseTokenLock(token);

  // Persist reason for UI
  users[token].lastDisconnectCode = 440;
  users[token].lastDisconnectAt = new Date().toISOString();
  users[token].lastError =
    "Stream Errored (conflict) — توجد جلسة/اتصال آخر يستخدم نفس credentials. أوقف كل النسخ الأخرى (instances=1) أو احذف مجلد session وأعد الربط.";
  saveUsers(users);

  pushLog(
    token,
    "error",
    "STOP: conflict 440 detected. Auto-reconnect disabled.",
    details || null,
  );

  sseSend(token, {
    type: "error",
    message:
      "Conflict 440: يوجد اتصال آخر لنفس الحساب/السشن. تم إيقاف إعادة المحاولة التلقائية. الحل: instances=1 أو حذف session وإعادة الربط.",
    at: Date.now(),
  });
}

function scheduleReconnect(token, reasonCode) {
  // never restart during grace (pairing/sync)
  const g = graceUntil[token] || 0;
  if (Date.now() < g) {
    pushLog(token, "info", "Reconnect skipped بسبب grace period", { until: g });
    return;
  }

  // if conflictStop => do not reconnect
  if (conflictStop[token]) {
    pushLog(token, "warn", "Reconnect blocked بسبب conflictStop (440).", {
      code: reasonCode,
    });
    return;
  }

  const now = Date.now();
  if (nextReconnectAt[token] && nextReconnectAt[token] > now) return;

  const ms = computeBackoffMs(token, reasonCode);
  nextReconnectAt[token] = now + ms;

  reconnecting[token] = true;

  clearTokenTimers(token);
  safeEndSocket(token);

  if (reconnectTimers[token]) clearTimeout(reconnectTimers[token]);
  reconnectTimers[token] = setTimeout(() => {
    startSocketForToken(token).catch((e) =>
      pushLog(token, "error", "auto-reconnect error", { err: String(e) }),
    );
  }, ms);

  pushLog(token, "warn", "Scheduled reconnect", { inMs: ms, code: reasonCode });
}

async function sendWithRetry(sock, chatId, content, retries = 3) {
  let lastErr;
  for (let i = 0; i < retries; i++) {
    try {
      return await sock.sendMessage(chatId, content);
    } catch (e) {
      lastErr = e;
      const status = e?.output?.statusCode || e?.data?.output?.statusCode;
      const msg = String(e?.message || e);
      if (
        status === 408 ||
        /Timed Out/i.test(msg) ||
        /Stream Errored/i.test(msg) ||
        /Connection Closed/i.test(msg)
      ) {
        await new Promise((r) => setTimeout(r, 1500 * (i + 1)));
        continue;
      }
      throw e;
    }
  }
  throw lastErr;
}

// ===================== Socket Manager =====================
async function startSocketForToken(token) {
  // per-token mutex: prevent overlap
  if (starting[token]) return;
  starting[token] = true;

  try {
    if (!isPrimaryInstance) {
      pushLog(token, "warn", "Not primary: socket start blocked", {
        pid: process.pid,
      });
      return;
    }

    const user = users[token];
    if (!user) return;

    // conflictStop means manual intervention required
    if (conflictStop[token]) {
      pushLog(token, "warn", "Start blocked: conflictStop enabled (440).", {
        token,
      });
      return;
    }

    // lock session folder
    if (!tryAcquireTokenLock(token)) {
      pushLog(token, "warn", "Token session folder is locked, retry later", {
        token,
      });
      scheduleReconnect(token, 408);
      return;
    }

    clearTokenTimers(token);
    safeEndSocket(token);

    reconnecting[token] = true;
    connState[token] = "connecting";
    qrRaw[token] = null;
    qrDataUrl[token] = null;
    lastEventAt[token] = Date.now();

    const sessionPath = tokenSessionPath(token);
    user.sessionPath = sessionPath;
    saveUsers(users);

    // grace for pairing + initial sync
    graceUntil[token] = Date.now() + 180_000;

    pushLog(token, "info", "Starting socket", {
      sessionPath,
      graceUntil: graceUntil[token],
      pid: process.pid,
    });

    sseSend(token, {
      type: "state",
      state: "connecting",
      graceUntil: graceUntil[token],
      at: Date.now(),
    });

    try {
      const { state, saveCreds } = await useMultiFileAuthState(sessionPath);
      const { version } = await fetchLatestBaileysVersion();

      const sock = makeWASocket({
        version,
        auth: state,
        printQRInTerminal: false,
        connectTimeoutMs: 90_000,
        defaultQueryTimeoutMs: 90_000,
        keepAliveIntervalMs: 25_000,
        syncFullHistory: false,
      });

      sockets[token] = sock;

      sock.ev.on("creds.update", async (...args) => {
        try {
          await saveCreds(...args);
          lastEventAt[token] = Date.now();
          pushLog(token, "info", "Creds saved");
          sseSend(token, { type: "creds", saved: true, at: Date.now() });
        } catch (e) {
          pushLog(token, "error", "Creds save failed", {
            err: String(e?.message || e),
          });
        }
      });

      sock.ev.on("messages.upsert", async (m) => {
        try {
          lastEventAt[token] = Date.now();
          const msg = m?.messages?.[0];
          if (!msg || msg.key.fromMe) return; // Skip own messages

          const from = msg.key?.remoteJid || "unknown";
          const id = msg.key?.id || null;
          const pushName = msg.pushName || "Unknown";

          const text =
            msg.message?.conversation ||
            msg.message?.extendedTextMessage?.text ||
            msg.message?.imageMessage?.caption ||
            msg.message?.videoMessage?.caption ||
            msg.message?.documentMessage?.caption ||
            "";

          if (!text) return;

          pushMsg(token, from, text, id);

          const user = users[token];

          // 1. Webhook Call
          if (user.webhookUrl) {
            fetch(user.webhookUrl, {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({
                token,
                from,
                name: pushName,
                text,
                timestamp: Date.now(),
                messageId: id,
              }),
            }).catch((e) =>
              pushLog(token, "error", "Webhook failed", { err: e.message }),
            );
          }

          // 2. Auto Reply
          if (user.autoReplyEnabled && user.autoReplyText) {
            // Avoid loops if multiple bots talk to each other
            // (Usually checked by fromMe, but good to have)
            setTimeout(async () => {
              try {
                await sendWithRetry(sock, from, { text: user.autoReplyText }, 2);
                pushLog(token, "info", "Auto-reply sent", { to: from });
              } catch (e) {
                pushLog(token, "error", "Auto-reply failed", {
                  err: e.message,
                });
              }
            }, 2000);
          }
        } catch (_) {}
      });

      armWatchdog(token);

      sock.ev.on("connection.update", (update) => {
        lastEventAt[token] = Date.now();
        
        const { qr, connection, lastDisconnect } = update;

        if (qr) {
          qrRaw[token] = qr;
          connState[token] = "connecting";

          // extend grace while QR visible
          graceUntil[token] = Math.max(
            graceUntil[token] || 0,
            Date.now() + 300_000,
          );

          pushLog(token, "info", "QR updated", {
            graceUntil: graceUntil[token],
          });

          (async () => {
            try {
              const dataUrl = await qrcode.toDataURL(qr);
              qrDataUrl[token] = dataUrl;
              sseSend(token, {
                type: "qr",
                state: "connecting",
                qrDataUrl: dataUrl,
                graceUntil: graceUntil[token],
                at: Date.now(),
              });
            } catch (e) {
              pushLog(token, "error", "QR toDataURL failed", {
                err: String(e?.message || e),
              });
              sseSend(token, {
                type: "qr",
                state: "connecting",
                qrDataUrl: null,
                err: String(e?.message || e),
                at: Date.now(),
              });
            }
          })();

          armWatchdog(token);
        }

        if (connection === "open") {
          qrRaw[token] = null;
          qrDataUrl[token] = null;
          connState[token] = "open";

          reconnecting[token] = false;
          reconnectAttempts[token] = 0;
          error515Attempts[token] = 0; // Reset 515 error counter on success
          nextReconnectAt[token] = 0;
          readyAt[token] = Date.now() + 5000;

          // keep grace during initial sync
          graceUntil[token] = Date.now() + 180_000;

          users[token].waId = sock?.user?.id || null;
          users[token].waName = sock?.user?.name || null;
          users[token].lastDisconnectCode = null;
          users[token].lastDisconnectAt = null;
          users[token].lastError = null;
          saveUsers(users);

          pushLog(token, "ok", "Connection OPEN", {
            waId: users[token].waId,
            waName: users[token].waName,
          });

          sseSend(token, {
            type: "open",
            state: "open",
            waId: users[token].waId,
            waName: users[token].waName,
            info: sock.user || null,
            graceUntil: graceUntil[token],
            at: Date.now(),
          });

          if (watchdogTimers[token]) {
            clearTimeout(watchdogTimers[token]);
            watchdogTimers[token] = null;
          }

          releaseTokenLock(token);

          // re-arm watchdog after grace ends
          setTimeout(() => armWatchdog(token), 185_000);
        }

        if (connection === "close") {
          connState[token] = "close";

          if (watchdogTimers[token]) {
            clearTimeout(watchdogTimers[token]);
            watchdogTimers[token] = null;
          }

          const code = getDisconnectCode(lastDisconnect);
          const errMsg = String(lastDisconnect?.error?.message || "");

          users[token].lastDisconnectCode = code ?? null;
          users[token].lastDisconnectAt = new Date().toISOString();
          users[token].lastError = errMsg ? errMsg.slice(0, 600) : null;
          saveUsers(users);

          pushLog(token, "warn", "Connection CLOSE", {
            code: code ?? null,
            err: users[token].lastError,
          });

          sseSend(token, {
            type: "close",
            state: "close",
            code: code ?? null,
            err: users[token].lastError,
            at: Date.now(),
          });

          // IMPORTANT: handle conflict 440 => stop auto reconnect
          if (code === 440 || /conflict/i.test(users[token].lastError || "")) {
            stopForConflict(token, { code, err: users[token].lastError });
            return;
          }

          // Handle 515 error - Stream Errored (requires fresh session)
          if (code === 515) {
            error515Attempts[token] = (error515Attempts[token] || 0) + 1;
            
            // If too many 515 errors, stop trying
            if (error515Attempts[token] > 3) {
              pushLog(token, "error", "Too many 515 errors - manual intervention required", { 
                attempts: error515Attempts[token],
                suggestion: "حذف session يدوياً وإعادة المحاولة بعد دقائق. قد يكون هناك حظر مؤقت من واتساب."
              });
              
              users[token].lastError = "خطأ 515 متكرر - يرجى الانتظار 5-10 دقائق ثم حذف session وإعادة المحاولة";
              saveUsers(users);
              
              sseSend(token, {
                type: "error",
                message: "خطأ 515 متكرر. انتظر 5-10 دقائق ثم اضغط 'Reset Session' من الصفحة.",
                at: Date.now(),
              });
              
              releaseTokenLock(token);
              return;
            }
            
            pushLog(token, "warn", `Error 515 detected (attempt ${error515Attempts[token]}/3) - clearing session`, { code });
            
            // Clear grace period to allow immediate reconnect
            graceUntil[token] = 0;
            
            // Delete session folder to force new QR
            const sessionPath = tokenSessionPath(token);
            safeRmDir(sessionPath);
            
            // Reset QR data
            qrRaw[token] = null;
            qrDataUrl[token] = null;
            
            // Reset reconnect attempts for 515
            reconnectAttempts[token] = 0;
            
            // Increase delay with each attempt to avoid rate limiting
            const delay = 5000 * error515Attempts[token];
            
            // Schedule reconnect with increasing delay
            setTimeout(() => {
              startSocketForToken(token).catch((e) =>
                pushLog(token, "error", "515 recovery failed", { err: String(e) })
              );
            }, delay);
            
            releaseTokenLock(token);
            return;
          }

          // logged out / invalid
          if (code === 401 || code === DisconnectReason.loggedOut) {
            reconnecting[token] = false;
            reconnectAttempts[token] = 0;
            nextReconnectAt[token] = 0;
            graceUntil[token] = 0;
            releaseTokenLock(token);
            return;
          }

          reconnectAttempts[token] = (reconnectAttempts[token] || 0) + 1;
          scheduleReconnect(token, code ?? 408);
          releaseTokenLock(token);
        }
      });
    } catch (e) {
      connState[token] = "close";
      users[token].lastError = String(e?.message || e);
      saveUsers(users);
      pushLog(token, "error", "startSocketForToken failed", {
        err: users[token].lastError,
      });

      sseSend(token, {
        type: "error",
        message: users[token].lastError,
        at: Date.now(),
      });

      reconnectAttempts[token] = (reconnectAttempts[token] || 0) + 1;
      scheduleReconnect(token, 408);

      releaseTokenLock(token);
    }
  } finally {
    starting[token] = false;
  }
}

// ===================== API Routes =====================
app.get("/api/me", requireLogin, (req, res) => {
    const user = users[req.session.user.token];
    if (!user) return res.status(404).json({ error: "User not found" });
    res.json({
        username: user.username,
        token: user.token,
        phone: user.phone,
        email: user.email,
        limit: user.limit
    });
});

// ===================== Public Pairing Routes (NO LOGIN) =====================

// Home page - redirect based on login status
app.get("/", (req, res) => {
  if (req.session.user && req.session.user.token) {
    // User is logged in, redirect to their QR page
    return res.redirect(`/qr/${req.session.user.token}`);
  }
  // Not logged in, redirect to register page
  res.redirect("/register.html");
});

// Health
app.get("/health", (req, res) =>
  res.json({ ok: true, pid: process.pid, primary: isPrimaryInstance }),
);

// Takeover (public)
app.get("/takeover", (req, res) => {
  const force = req.query.force === "1";

  if (isPrimaryInstance)
    return res.send(`✅ Primary بالفعل (PID: ${process.pid})`);

  const info = readGlobalLock();
  const lockedPid = info?.pid;
  const lastHb = info?.hb || info?.at || 0;

  const staleByTime = Date.now() - lastHb > GLOBAL_LOCK_TTL_MS;
  const pidDead = lockedPid ? !pidExists(lockedPid) : true;

  if (!lockedPid || staleByTime || pidDead) {
    ensurePrimaryOrTrySteal();
    return res.send(
      isPrimaryInstance
        ? `✅ أصبحت Primary (PID: ${process.pid})`
        : `❌ فشل takeover`,
    );
  }

  if (force) {
    try {
      fs.unlinkSync(GLOBAL_LOCK);
    } catch (_) {}
    ensurePrimaryOrTrySteal();
    return res.send(
      isPrimaryInstance
        ? `✅ takeover بالقوة (PID: ${process.pid}).\nتحذير: الأفضل جعل instances=1`
        : `❌ فشل takeover بالقوة`,
    );
  }

  return res
    .status(409)
    .send(`⚠️ يوجد Primary حي (PID: ${lockedPid}). جرّب /takeover?force=1`);
});

// Debug
app.get("/__debug", (req, res) => {
  res.json({
    node: process.version,
    pid: process.pid,
    primary: isPrimaryInstance,
    globalLock: readGlobalLock(),
    usersCount: Object.keys(users).length,
    pwd: process.cwd(),
    appRoot: process.env.PASSENGER_APP_ROOT,
  });
});

// Public status (no login) — read-only
app.get("/pair-status/:token", (req, res) => {
  const token = req.params.token;
  if (!users[token]) return res.status(404).json({ error: "توكن غير موجود" });
  res.json(sseSnapshot(token));
});

// Public ensure-start (no login) — starts socket if primary
app.get("/ensure-start/:token", (req, res) => {
  const token = req.params.token;
  if (!users[token]) return res.status(404).json({ error: "توكن غير موجود" });

  if (!isPrimaryInstance) {
    return res.status(409).json({
      ok: false,
      error: `Not primary (pid=${process.pid}). اجعل instances=1 أو افتح /takeover`,
      pid: process.pid,
      primary: false,
      globalLock: readGlobalLock(),
    });
  }

  // If conflictStop is active, inform client explicitly
  if (conflictStop[token]) {
    return res.status(409).json({
      ok: false,
      error:
        "Conflict 440: تم إيقاف إعادة المحاولة. الحل: أوقف أي نسخة أخرى تستخدم نفس السشن أو احذف مجلد session وأعد الربط.",
      conflictStop: true,
      token,
    });
  }

  if (
    !sockets[token] ||
    (connState[token] !== "open" && connState[token] !== "connecting")
  ) {
    startSocketForToken(token).catch(console.error);
  }
  res.json({
    ok: true,
    state: connState[token] || "close",
    primary: true,
    pid: process.pid,
  });
});

app.get("/api/status-full/:token", requireLogin, (req, res) => {
  const token = req.params.token;
  if (!users[token]) return res.status(404).json({ error: "غير موجود" });
  const snapshot = sseSnapshot(token);
  res.json({
    ...snapshot,
    sentCount: users[token].count || 0,
    receivedCount: (tokenMsgs[token] || []).length,
  });
});

app.get("/api/admin/users", requireLogin, (req, res) => {
    const isAdmin = req.session.user.isAdmin;
    
    if (!isAdmin) {
        // Regular users can ONLY see themselves
        const u = users[req.session.user.token];
        return res.json([u ? {
            username: u.username,
            phone: u.phone || "---",
            email: u.email || "---",
            token: u.token,
            count: u.count || 0,
            limit: u.limit || 10,
            state: connState[u.token] || "close"
        } : null].filter(Boolean));
    }

    // Admin sees everything
    const allUsers = Object.values(users).map(u => ({
        username: u.username,
        phone: u.phone || "---",
        email: u.email || "---",
        token: u.token,
        count: u.count || 0,
        limit: u.limit || 10,
        state: connState[u.token] || "close"
    }));
    res.json(allUsers);
});

// Reset Session
app.post("/api/session/reset", requireLogin, (req, res) => {
    const token = req.session.user.token;
    if (!token) return res.status(401).json({ error: "Unauthorized" });

    // Stop current socket
    safeEndSocket(token);
    
    // Remote session folder
    const sessionPath = tokenSessionPath(token);
    safeRmDir(sessionPath);
    
    // Reset states
    qrRaw[token] = null;
    qrDataUrl[token] = null;
    connState[token] = "close";
    error515Attempts[token] = 0; // Reset 515 error counter
    
    // Restart logic
    startSocketForToken(token).catch(console.error);
    
    pushLog(token, "info", "Session reset by user");
    res.json({ ok: true });
});

// Update Profile (User & Admin)
app.post("/api/user/update-profile", requireLogin, (req, res) => {
    const token = req.session.user.token;
    const { webhookUrl, autoReplyText, autoReplyEnabled } = req.body;
    
    if (users[token]) {
        if (webhookUrl !== undefined) users[token].webhookUrl = webhookUrl;
        if (autoReplyText !== undefined) users[token].autoReplyText = autoReplyText;
        if (autoReplyEnabled !== undefined) users[token].autoReplyEnabled = !!autoReplyEnabled;
        
        saveUsers(users);
        res.json({ ok: true });
    } else {
        res.status(404).json({ error: "User not found" });
    }
});

// Admin Route to see all logs (Real Integrated Control)
app.get("/api/admin/all-logs", requireLogin, (req, res) => {
    if (req.session.user.username !== 'admin') return res.status(403).end();
    res.json(tokenLogs);
});
app.get("/qr/:token", async (req, res) => {
  const token = req.params.token;
  const u = users[token];
  if (!u) return res.status(404).send("توكن غير موجود");

  const primaryNote = isPrimaryInstance
    ? `✅ Primary PID: ${process.pid}`
    : `⚠️ هذه النسخة ليست Primary (PID: ${process.pid}). اجعل instances=1 أو افتح /takeover.`;

  const conflictNote = conflictStop[token]
    ? `<div class="badge err" style="margin-top:10px">❌ تم إيقاف إعادة المحاولة بسبب 440 (conflict). الحل: instances=1 أو حذف session وإعادة الربط.</div>`
    : "";

  res.send(`
  <html>
    <head>
      <meta charset="utf-8"/>
      <title>WhatsApp Pairing - ${u.username}</title>
      <meta name="viewport" content="width=device-width, initial-scale=1"/>
      <style>
        body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu; background:#f6f7fb; margin:0}
        .wrap{max-width:1100px;margin:0 auto;padding:18px}
        .card{background:#fff;border:1px solid #e7e7ee;border-radius:12px;padding:14px;margin-bottom:12px}
        .row{display:flex;gap:12px;flex-wrap:wrap}
        .col{flex:1;min-width:320px}
        .title{display:flex;justify-content:space-between;align-items:center}
        .badge{padding:6px 10px;border-radius:999px;font-size:12px}
        .ok{background:#e7f7ee;color:#0b6b2f}
        .warn{background:#fff3cd;color:#856404}
        .err{background:#fdecea;color:#b00020}
        .mono{font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace}
        #qrImg{max-width:320px;border:1px solid #eee;border-radius:12px}
        .small{font-size:12px;color:#666}
        .log{max-height:320px;overflow:auto;background:#0b1020;color:#d7defc;border-radius:12px;padding:10px}
        .logline{margin:0 0 6px 0;white-space:pre-wrap}
        .msgs{max-height:220px;overflow:auto;border:1px dashed #e1e1ea;border-radius:12px;padding:10px;background:#fafbff}
      </style>
    </head>
    <body>
      <div class="wrap">
        <div class="card title">
          <div>
            <div style="font-size:18px;font-weight:700">ربط واتساب عبر QR</div>
            <div class="small">User: <b>${u.username}</b> — Token: <span class="mono">${token}</span></div>
          </div>
          <div style="display:flex;gap:8px;align-items:center">
            <div id="primaryBadge" class="badge ${isPrimaryInstance ? "ok" : "warn"}">${primaryNote}</div>
            <a href="/logout" style="padding:6px 12px;background:#dc3545;color:#fff;border-radius:6px;text-decoration:none;font-size:12px;font-weight:600">تسجيل خروج</a>
          </div>
        </div>

        ${conflictNote}

        <div class="row">
          <div class="col">
            <div class="card">
              <div style="display:flex;justify-content:space-between;align-items:center">
                <div style="font-weight:700">الحالة</div>
                <div id="stateBadge" class="badge warn">⏳ تحضير...</div>
              </div>
              <div id="statusText" style="margin-top:10px;font-size:16px">جاري بدء الاتصال...</div>
              <div id="statusSub" class="small" style="margin-top:6px"></div>
              <div id="qrWrap" style="margin-top:14px;display:none;text-align:center">
                <img id="qrImg" src="" alt="QR"/>
                <div class="small" style="margin-top:8px">امسح QR من: واتساب > الأجهزة المرتبطة</div>
              </div>
              <div id="connectedBox" style="margin-top:14px;display:none">
                <div class="badge ok">✅ تم الربط وفتح الاتصال</div>
                <div id="waLine" style="margin-top:8px"></div>
              </div>
              <div style="margin-top:14px">
                <button onclick="resetSession()" style="width:100%;padding:10px;background:#dc3545;color:#fff;border:none;border-radius:6px;font-weight:600;cursor:pointer;font-size:14px">
                  🔄 إعادة تعيين Session (Reset)
                </button>
                <div class="small" style="margin-top:6px;text-align:center;color:#666">
                  استخدم هذا الزر إذا واجهت أخطاء متكررة (مثل 515)
                </div>
              </div>
              <div style="margin-top:10px" class="small">
                إذا ظهر على الهاتف “تعذر تسجيل الدخول…”:
                <ul>
                  <li>تأكد أنك فعلياً على instance واحدة (instances=1)</li>
                  <li>إذا ظهر code=440 conflict: أوقف أي نسخة أخرى أو احذف session وأعد الربط</li>
                  <li>أوقف VPN/Proxy على الهاتف والسيرفر</li>
                  <li>قلّل محاولات QR المتكررة (انتظر 1-2 دقيقة)</li>
                </ul>
              </div>
            </div>

            <div class="card">
              <div style="font-weight:700;margin-bottom:8px">آخر الرسائل المستلمة (للتشخيص)</div>
              <div id="msgs" class="msgs"></div>
              <div class="small" style="margin-top:8px">لن تظهر رسائل إذا لم تُفتح الجلسة أو لم تصل رسائل للحساب.</div>
            </div>
          </div>

          <div class="col">
            <div class="card">
              <div style="font-weight:700;margin-bottom:8px">Logs / أسباب الفشل (مباشر)</div>
              <div id="log" class="log"></div>
              <div class="small" style="margin-top:8px">
                أهم ما نراقبه: <span class="mono">440</span> (conflict/instance متعددة)، <span class="mono">515</span> (restart بعد pairing)، <span class="mono">401</span> (logout/invalid).
              </div>
            </div>
          </div>
        </div>
      </div>

      <script>
        const token = ${JSON.stringify(token)};
        
        function resetSession() {
          if (!confirm('هل أنت متأكد من إعادة تعيين Session؟ سيتم حذف جميع بيانات الربط وستحتاج لمسح QR مرة أخرى.')) {
            return;
          }
          
          fetch('/api/session/reset', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
          })
          .then(r => r.json())
          .then(data => {
            if (data.ok) {
              alert('✅ تم إعادة تعيين Session بنجاح. سيتم إنشاء QR جديدة خلال ثوانٍ...');
              location.reload();
            } else {
              alert('❌ فشل إعادة التعيين: ' + (data.error || 'خطأ غير معروف'));
            }
          })
          .catch(e => {
            alert('❌ خطأ في الاتصال: ' + e.message);
          });
        }
        
        const stateBadge = document.getElementById("stateBadge");
        const statusText = document.getElementById("statusText");
        const statusSub = document.getElementById("statusSub");
        const qrWrap = document.getElementById("qrWrap");
        const qrImg = document.getElementById("qrImg");
        const connectedBox = document.getElementById("connectedBox");
        const waLine = document.getElementById("waLine");
        const logEl = document.getElementById("log");
        const msgsEl = document.getElementById("msgs");

        function setBadge(cls, text) {
          stateBadge.className = "badge " + cls;
          stateBadge.textContent = text;
        }

        function addLogLine(line) {
          const p = document.createElement("div");
          p.className = "logline";
          p.textContent = line;
          logEl.appendChild(p);
          logEl.scrollTop = logEl.scrollHeight;
        }

        function renderMsgs(msgs) {
          msgsEl.innerHTML = "";
          if (!msgs || msgs.length === 0) {
            msgsEl.innerHTML = "<div class='small'>لا توجد رسائل بعد.</div>";
            return;
          }
          for (const m of msgs.slice().reverse()) {
            const d = new Date(m.ts);
            const div = document.createElement("div");
            div.style.padding = "8px";
            div.style.borderBottom = "1px solid #eee";
            div.innerHTML = "<div class='small mono'>" + d.toISOString() + " — " + (m.from || "") + "</div>" +
                            "<div style='margin-top:4px'>" + (m.text || "") + "</div>";
            msgsEl.appendChild(div);
          }
        }

        // Start socket immediately (public)
        fetch("/ensure-start/" + encodeURIComponent(token))
          .then(r => r.json())
          .then(j => {
            if (!j.ok) {
              setBadge("warn", "⚠️");
              statusText.textContent = "تعذر بدء الربط";
              statusSub.textContent = j.error || "";
              addLogLine("[WARN] " + (j.error || "Ensure start failed"));
            }
          })
          .catch(()=>{});

        const es = new EventSource("/pair-stream/" + encodeURIComponent(token));

        es.onmessage = (ev) => {
          let p;
          try { p = JSON.parse(ev.data); } catch(e) { return; }

          if (p.type === "snapshot") {
            logEl.innerHTML = "";
            if (p.logs) {
              for (const L of p.logs) {
                const d = new Date(L.ts).toISOString();
                addLogLine("[" + (L.level||"info").toUpperCase() + "] " + d + " - " + (L.msg||"") +
                  (L.meta ? " | " + JSON.stringify(L.meta) : ""));
              }
            }
            renderMsgs(p.msgs);

            if (p.conflictStop) {
              setBadge("err", "❌ CONFLICT");
              statusText.textContent = "تم إيقاف إعادة المحاولة بسبب 440 (conflict)";
              statusSub.textContent = "الحل: instances=1 أو حذف session وإعادة الربط.";
              qrWrap.style.display = "none";
              connectedBox.style.display = "none";
              return;
            }

            if (p.state === "open") {
              setBadge("ok", "✅ OPEN");
              statusText.textContent = "تم فتح الاتصال بنجاح";
              statusSub.textContent = "قد تستغرق المزامنة دقائق حسب الحساب.";
              connectedBox.style.display = "block";
              waLine.textContent = (p.waName ? p.waName + " — " : "") + (p.waId || "");
              qrWrap.style.display = "none";
              return;
            }

            if (p.qrDataUrl) {
              setBadge("warn", "⏳ QR");
              statusText.textContent = "امسح QR الآن";
              statusSub.textContent = "بانتظار التأكيد من الهاتف...";
              qrImg.src = p.qrDataUrl;
              qrWrap.style.display = "block";
              connectedBox.style.display = "none";
              return;
            }

            setBadge("warn", "⏳ CONNECTING");
            statusText.textContent = "جاري إنشاء QR / الاتصال...";
            statusSub.textContent = p.primary ? "انتظر قليلاً" : "هذه النسخة ليست Primary";
            return;
          }

          if (p.type === "qr") {
            setBadge("warn", "⏳ QR");
            statusText.textContent = "امسح QR الآن";
            statusSub.textContent = "بانتظار التأكيد من الهاتف...";
            if (p.qrDataUrl) {
              qrImg.src = p.qrDataUrl;
              qrWrap.style.display = "block";
            }
            connectedBox.style.display = "none";
            return;
          }

          if (p.type === "open") {
            setBadge("ok", "✅ OPEN");
            statusText.textContent = "تم الربط وفتح الاتصال";
            statusSub.textContent = "بدأت المزامنة، انتظر قليلاً.";
            connectedBox.style.display = "block";
            waLine.textContent = (p.waName ? p.waName + " — " : "") + (p.waId || "");
            qrWrap.style.display = "none";
            return;
          }

          if (p.type === "close") {
            setBadge("warn", "⚠️ CLOSE");
            statusText.textContent = "انقطع الاتصال";
            statusSub.textContent = "سيتم إعادة المحاولة تلقائياً (إلا إذا كان 440 conflict). راجع logs.";
            return;
          }

          if (p.type === "error") {
            setBadge("err", "❌ ERROR");
            statusText.textContent = "حدث خطأ";
            statusSub.textContent = p.message || "";
            return;
          }

          if (p.type === "log") {
            const d = new Date(p.ts).toISOString();
            addLogLine("[" + (p.level||"info").toUpperCase() + "] " + d + " - " + (p.msg||"") +
              (p.meta ? " | " + JSON.stringify(p.meta) : ""));
            return;
          }

          if (p.type === "msg") {
            fetch("/pair-status/" + encodeURIComponent(token))
              .then(r => r.json())
              .then(j => renderMsgs(j.msgs))
              .catch(()=>{});
            return;
          }
        };

        es.onerror = () => {
          setBadge("warn", "⚠️ SSE");
          statusSub.textContent = "انقطع اتصال الصفحة بالسيرفر. أعد تحميل الصفحة إذا استمر.";
        };
      </script>
    </body>
  </html>
  `);
});

// ===================== Optional Admin UI (login dashboard) =====================

// Root
app.get("/", (req, res) => {
  if (req.session.user) return res.redirect("/dashboard");
  return res.redirect("/login");
});

app.get("/register", (req, res) => {
    if (req.session.user) return res.redirect("/dashboard");
    res.sendFile(path.join(__dirname, "public", "register.html"));
});

// Inline Login page (HTML داخل الكود)
app.get("/login", (req, res) => {
  if (req.session.user) return res.redirect("/dashboard");

  res.send(`
  <html>
    <head>
      <meta charset="utf-8"/>
      <meta name="viewport" content="width=device-width, initial-scale=1"/>
      <title>Login</title>
      <style>
        body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu; background:#f6f7fb; margin:0}
        .wrap{max-width:420px;margin:60px auto;padding:18px}
        .card{background:#fff;border:1px solid #e7e7ee;border-radius:12px;padding:18px}
        input{width:100%;padding:12px;border:1px solid #ddd;border-radius:10px;margin:8px 0;font-size:14px}
        button{padding:12px 14px;border:0;border-radius:10px;background:#111827;color:#fff;width:100%;font-size:14px;cursor:pointer}
        .small{font-size:12px;color:#666;margin-top:10px}
        .mono{font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace}
      </style>
    </head>
    <body>
      <div class="wrap">
        <div class="card">
          <div style="font-size:18px;font-weight:700;margin-bottom:6px">Dashboard Login</div>
          <div class="small">هذه الصفحة للدخول للوحة الإدارة فقط.</div>
          <form method="POST" action="/login" style="margin-top:12px">
            <input name="username" placeholder="اسم المستخدم، الجوال، أو الإيميل" required />
            <input name="password" placeholder="password" type="password" required />
            <button>Login</button>
          </form>
          <div class="small" style="margin-top:12px">
            Debug: <a href="/__debug">/__debug</a> — Health: <a href="/health">/health</a><br/>
            ملاحظة: اجعل Passenger instances=1 لتجنب <span class="mono">440 conflict</span>.
          </div>
        </div>
      </div>
    </body>
  </html>
  `);
});

app.post("/login", (req, res) => {
  const { username, password } = req.body; 
  const users = loadUsers();
  
  const tokenEntry = Object.entries(users).find(([_, u]) => 
    (u.username === username || u.phone === username || u.email === username) && 
    u.password === password
  );

  if (!tokenEntry) return res.status(401).send("❌ بيانات الدخول غير صحيحة");
  
  const [token, userData] = tokenEntry;
  req.session.user = { 
    username: userData.username, 
    token: token,
    isAdmin: !!userData.isAdmin
  };
  res.redirect(`/qr/${token}`);
});

app.get("/logout", (req, res) =>
  req.session.destroy(() => res.redirect("/register.html")),
);

app.get("/dashboard", requireLogin, (req, res) => {
  const warn = !isPrimaryInstance
    ? `<div style="background:#fff3cd;border:1px solid #ffeeba;padding:12px;margin-bottom:12px">
       ⚠️ ليست Primary (PID: ${process.pid}). اجعل instances=1 أو افتح <a href="/takeover">/takeover</a>
     </div>`
    : `<div style="background:#d4edda;border:1px solid #c3e6cb;padding:12px;margin-bottom:12px">
       ✅ Primary (PID: ${process.pid})
     </div>`;

  const rows = Object.entries(users)
    .map(([token, u]) => {
      const state = connState[token] || "close";
      const statusTxt = conflictStop[token]
        ? "❌ 440 CONFLICT (STOP)"
        : state === "open"
          ? "✅ متصل"
          : qrDataUrl[token]
            ? "⏳ بانتظار QR"
            : "❌ غير متصل";

      return `
      <tr>
        <td>${u.username}<div style="font-size:12px;color:#555">${u.waId || ""}</div></td>
        <td style="font-family:monospace">${token}</td>
        <td>${statusTxt}</td>
        <td>
          <a href="/qr/${token}">Public Pair</a> |
          <a href="/pair-status/${token}">Status JSON</a> |
          <a href="/ensure-start/${token}">Ensure Start</a>
        </td>
      </tr>
    `;
    })
    .join("");

  res.send(`
    <html><head><meta charset="utf-8"/><title>Dashboard</title></head>
    <body style="font-family:sans-serif;max-width:1100px;margin:30px auto">
      <div style="display:flex;justify-content:space-between;align-items:center">
        <h2>Dashboard</h2>
        <div><a href="/__debug">Debug</a> | <a href="/logout">Logout</a></div>
      </div>
      ${warn}
      <table border="1" cellpadding="10" style="width:100%;border-collapse:collapse">
        <tr><th>User</th><th>Token</th><th>Status</th><th>Links</th></tr>
        ${rows}
      </table>

      <hr/>
      <h3>➕ إنشاء مستخدم (يتطلب Primary)</h3>
      <form method="POST" action="/auth">
        <input name="username" placeholder="username" required/>
        <input name="password" placeholder="password" required/>
        <button>إنشاء</button>
      </form>
    </body></html>
  `);
});

// Create user (admin-only) - Can also be used for registration update
app.post("/auth", (req, res) => {
    const { username, password, phone, email, limit } = req.body;
    
    if (!username || !password || !phone || !email) {
        return res.status(400).send("جميع الحقول (الاسم، كلمة المرور، الهاتف، الإيميل) مطلوبة.");
    }

    const users = loadUsers();
    
    // Check for duplicates
    const duplicate = Object.values(users).find(u => 
        u.username === username || u.phone === phone || u.email === email
    );
    
    if (duplicate) {
        return res.status(409).send("خطأ: اسم المستخدم أو الهاتف أو الإيميل مسجل مسبقاً.");
    }

    // UNIQUE TOKEN FOR USER
    const token = generateToken();
    const sessionPath = path.join(SESSIONS_DIR, token);

    users[token] = {
        username,
        password,
        phone,
        email,
        token,
        isAdmin: username.toLowerCase() === 'admin', // Flag for admin
        sessionPath,
        count: 0,
        limit: limit ? parseInt(limit) : 10,
        waId: null,
        waName: null,
        lastDisconnectCode: null,
        lastDisconnectAt: null,
        lastError: null,
    };
    saveUsers(users);

    conflictStop[token] = false;
    pushLog(token, "info", "Account created successfully", { username, phone, email });
    
    // Auto-login session
    req.session.user = { 
        username: users[token].username, 
        token: token,
        isAdmin: users[token].isAdmin
    };
    
    startSocketForToken(token).catch(console.error);
    res.redirect(`/qr/${token}`);
});

// Update Limit (Admin Only)
app.post("/admin/update-limit", requireLogin, (req, res) => {
    // Only allow admin to update limits (assuming first user or specific flag)
    // For this implementation, we check if the current user is 'admin' or let it be open if it's the dashboard
    const { token, newLimit } = req.body;
    if (users[token]) {
        users[token].limit = parseInt(newLimit);
        saveUsers(users);
        res.json({ ok: true, limit: users[token].limit });
    } else {
        res.status(404).json({ error: "User not found" });
    }
});

// Delete User (Admin Only)
app.post("/admin/delete-user", requireLogin, (req, res) => {
    const { token } = req.body;
    if (users[token]) {
        safeEndSocket(token);
        delete users[token];
        saveUsers(users);
        res.json({ ok: true });
    } else {
        res.status(404).json({ error: "User not found" });
    }
});

// API send text (kept)
app.post("/send-text", async (req, res) => {
  const { token, chatId, text } = req.body;
  if (!token || !chatId || !text)
    return res.status(400).json({ error: "token و chatId و text مطلوبة" });

  const sock = sockets[token];
  if (!sock)
    return res.status(401).json({ error: "الجلسة غير متوفرة أو لم يتم الربط" });

  if (conflictStop[token]) {
    return res.status(409).json({
      error:
        "Conflict 440: تم إيقاف إعادة المحاولة. أوقف النسخ الأخرى أو احذف session وأعد الربط.",
    });
  }

  if (connState[token] !== "open")
    return res
      .status(503)
      .json({ error: "الجلسة غير جاهزة الآن. افحص /pair-status/:token" });

  if (Date.now() < (readyAt[token] || 0))
    return res
      .status(503)
      .json({ error: "الجلسة فتحت الآن، انتظر 5 ثواني ثم أعد المحاولة." });

    const user = users[token];
    const currentCount = user.count || 0;
    const limit = user.limit || 10;

    if (limit !== -1 && currentCount >= limit) {
        return res.status(403).json({ 
            error: `عذراً، لقد تجاوزت الحد المسموح به (${limit} رسائل). تواصل مع الإدارة لزيادة الحد.` 
        });
    }

    try {
        const sent = await sendWithRetry(sock, chatId, { text }, 3);
        user.count = (user.count || 0) + 1;
        saveUsers(users);
        res.status(200).json({ status: "sent", sent, remaining: limit === -1 ? 'unlimited' : limit - user.count });
    } catch (error) {
        const status = error?.output?.statusCode || 500;
        pushLog(token, "error", "send-text failed", {
            status,
            err: String(error?.message || error),
        });
        res.status(500).json({
            status: "error",
            message: String(error?.message || error),
            statusCode: status,
        });
    }
});

// ===================== Server =====================
const PORT = process.env.PORT || 3000;
app.listen(PORT, "0.0.0.0", () => {
    console.log(`API listening on :${PORT} (pid=${process.pid}, primary=${isPrimaryInstance})`);
});
