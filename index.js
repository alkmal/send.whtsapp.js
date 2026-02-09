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
    })
);

// ===================== Paths =====================
const USERS_FILE = path.join(__dirname, "users.json");
const SESSIONS_DIR = path.join(__dirname, "sessions");
if (!fs.existsSync(SESSIONS_DIR)) fs.mkdirSync(SESSIONS_DIR, { recursive: true });

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
        return res.status(409).send(
            `⚠️ هذه النسخة ليست الـ Primary على cPanel (PID: ${process.pid}).\n` +
            `لن تعمل عمليات الربط/إعادة التشغيل من هنا.\n` +
            `الحل الأفضل: اجعل instances=1.\n` +
            `أو جرّب: /takeover أو /takeover?force=1`
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
let reconnectAttempts = {};
let nextReconnectAt = {};
let readyAt = {};
let graceUntil = {}; // token -> timestamp
let lastEventAt = {}; // token -> timestamp

let reconnectTimers = {};
let watchdogTimers = {};

// NEW: per-token start mutex
let starting = {}; // token -> boolean

// NEW: conflict flag to stop infinite loops
let conflictStop = {}; // token -> boolean

// logs & messages (ring buffers)
const LOG_KEEP = 250;
const MSG_KEEP = 50;
let tokenLogs = {}; // token -> [{ts, level, msg, meta}]
let tokenMsgs = {}; // token -> [{ts, from, text, id}]

function pushLog(token, level, msg, meta = null) {
    if (!tokenLogs[token]) tokenLogs[token] = [];
    tokenLogs[token].push({ ts: Date.now(), level, msg, meta });
    if (tokenLogs[token].length > LOG_KEEP)
        tokenLogs[token].splice(0, tokenLogs[token].length - LOG_KEEP);
    sseSend(token, { type: "log", ts: Date.now(), level, msg, meta });
}

function pushMsg(token, from, text, id) {
    if (!tokenMsgs[token]) tokenMsgs[token] = [];
    tokenMsgs[token].push({ ts: Date.now(), from, text, id });
    if (tokenMsgs[token].length > MSG_KEEP)
        tokenMsgs[token].splice(0, tokenMsgs[token].length - MSG_KEEP);
    sseSend(token, { type: "msg", ts: Date.now(), from, text, id });
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
    try {
        const fd = fs.openSync(lf, "wx");
        fs.writeFileSync(fd, JSON.stringify({ pid: process.pid, at: Date.now() }));
        fs.closeSync(fd);
        return true;
    } catch (_) {
        // steal if stale
        try {
            const info = JSON.parse(fs.readFileSync(lf, "utf8"));
            const oldPid = info?.pid;
            const oldAt = info?.at || 0;
            const stale = Date.now() - oldAt > 120_000;
            if (!pidExists(oldPid) || stale) {
                fs.unlinkSync(lf);
                const fd = fs.openSync(lf, "wx");
                fs.writeFileSync(fd, JSON.stringify({ pid: process.pid, at: Date.now() }));
                fs.closeSync(fd);
                return true;
            }
        } catch (_) {}
        return false;
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

    pushLog(token, "error", "STOP: conflict 440 detected. Auto-reconnect disabled.", details || null);

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
        pushLog(token, "warn", "Reconnect blocked بسبب conflictStop (440).", { code: reasonCode });
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
            pushLog(token, "error", "auto-reconnect error", { err: String(e) })
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
            pushLog(token, "warn", "Not primary: socket start blocked", { pid: process.pid });
            return;
        }

        const user = users[token];
        if (!user) return;

        // conflictStop means manual intervention required
        if (conflictStop[token]) {
            pushLog(token, "warn", "Start blocked: conflictStop enabled (440).", { token });
            return;
        }

        // lock session folder
        if (!tryAcquireTokenLock(token)) {
            pushLog(token, "warn", "Token session folder is locked, retry later", { token });
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

        sseSend(token, { type: "state", state: "connecting", graceUntil: graceUntil[token], at: Date.now() });

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
                    pushLog(token, "error", "Creds save failed", { err: String(e?.message || e) });
                }
            });

            sock.ev.on("messages.upsert", (m) => {
                try {
                    lastEventAt[token] = Date.now();
                    const msg = m?.messages?.[0];
                    if (!msg) return;
                    const from = msg.key?.remoteJid || "unknown";
                    const id = msg.key?.id || null;

                    const text =
                        msg.message?.conversation ||
                        msg.message?.extendedTextMessage?.text ||
                        msg.message?.imageMessage?.caption ||
                        msg.message?.videoMessage?.caption ||
                        msg.message?.documentMessage?.caption ||
                        "";

                    if (text) pushMsg(token, from, text, id);
                } catch (_) {}
            });

            armWatchdog(token);

            sock.ev.on("connection.update", (update) => {
                const { connection, lastDisconnect, qr } = update;
                lastEventAt[token] = Date.now();

                if (qr) {
                    qrRaw[token] = qr;
                    connState[token] = "connecting";

                    // extend grace while QR visible
                    graceUntil[token] = Math.max(graceUntil[token] || 0, Date.now() + 300_000);

                    pushLog(token, "info", "QR updated", { graceUntil: graceUntil[token] });

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
                            pushLog(token, "error", "QR toDataURL failed", { err: String(e?.message || e) });
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

                    pushLog(token, "ok", "Connection OPEN", { waId: users[token].waId, waName: users[token].waName });

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

                    pushLog(token, "warn", "Connection CLOSE", { code: code ?? null, err: users[token].lastError });

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
            pushLog(token, "error", "startSocketForToken failed", { err: users[token].lastError });

            sseSend(token, { type: "error", message: users[token].lastError, at: Date.now() });

            reconnectAttempts[token] = (reconnectAttempts[token] || 0) + 1;
            scheduleReconnect(token, 408);

            releaseTokenLock(token);
        }
    } finally {
        starting[token] = false;
    }
}

// ===================== Public Pairing Routes (NO LOGIN) =====================

// Health
app.get("/health", (req, res) => res.json({ ok: true, pid: process.pid, primary: isPrimaryInstance }));

// Takeover (public)
app.get("/takeover", (req, res) => {
    const force = req.query.force === "1";

    if (isPrimaryInstance) return res.send(`✅ Primary بالفعل (PID: ${process.pid})`);

    const info = readGlobalLock();
    const lockedPid = info?.pid;
    const lastHb = info?.hb || info?.at || 0;

    const staleByTime = Date.now() - lastHb > GLOBAL_LOCK_TTL_MS;
    const pidDead = lockedPid ? !pidExists(lockedPid) : true;

    if (!lockedPid || staleByTime || pidDead) {
        ensurePrimaryOrTrySteal();
        return res.send(isPrimaryInstance ? `✅ أصبحت Primary (PID: ${process.pid})` : `❌ فشل takeover`);
    }

    if (force) {
        try {
            fs.unlinkSync(GLOBAL_LOCK);
        } catch (_) {}
        ensurePrimaryOrTrySteal();
        return res.send(
            isPrimaryInstance
                ? `✅ takeover بالقوة (PID: ${process.pid}).\nتحذير: الأفضل جعل instances=1`
                : `❌ فشل takeover بالقوة`
        );
    }

    return res.status(409).send(`⚠️ يوجد Primary حي (PID: ${lockedPid}). جرّب /takeover?force=1`);
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

    if (!sockets[token] || (connState[token] !== "open" && connState[token] !== "connecting")) {
        startSocketForToken(token).catch(console.error);
    }
    res.json({ ok: true, state: connState[token] || "close", primary: true, pid: process.pid });
});

// Public pairing page (no login)
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
          <div id="primaryBadge" class="badge ${isPrimaryInstance ? "ok" : "warn"}">${primaryNote}</div>
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
            <input name="username" placeholder="username" required />
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
    const tokenEntry = Object.entries(users).find(([_, u]) => u.username === username && u.password === password);
    if (!tokenEntry) return res.status(401).send("❌ بيانات الدخول غير صحيحة");
    req.session.user = { username, token: tokenEntry[0] };
    res.redirect("/dashboard");
});

app.get("/logout", (req, res) => req.session.destroy(() => res.redirect("/login")));

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
            const statusTxt =
                conflictStop[token]
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

// Create user (admin-only)
app.post("/auth", requireLogin, requirePrimary, (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).send("الاسم وكلمة المرور مطلوبة");

    const token = generateToken();
    const sessionPath = path.join(SESSIONS_DIR, token);

    users[token] = {
        username,
        password,
        token,
        sessionPath,
        count: 0,
        waId: null,
        waName: null,
        lastDisconnectCode: null,
        lastDisconnectAt: null,
        lastError: null,
    };
    saveUsers(users);

    // reset conflict stop for new token
    conflictStop[token] = false;

    pushLog(token, "info", "User created", { username });
    startSocketForToken(token).catch(console.error);

    res.redirect(`/qr/${token}`);
});

// API send text (kept)
app.post("/send-text", async (req, res) => {
    const { token, chatId, text } = req.body;
    if (!token || !chatId || !text) return res.status(400).json({ error: "token و chatId و text مطلوبة" });

    const sock = sockets[token];
    if (!sock) return res.status(401).json({ error: "الجلسة غير متوفرة أو لم يتم الربط" });

    if (conflictStop[token]) {
        return res.status(409).json({
            error:
                "Conflict 440: تم إيقاف إعادة المحاولة. أوقف النسخ الأخرى أو احذف session وأعد الربط.",
        });
    }

    if (connState[token] !== "open")
        return res.status(503).json({ error: "الجلسة غير جاهزة الآن. افحص /pair-status/:token" });

    if (Date.now() < (readyAt[token] || 0))
        return res.status(503).json({ error: "الجلسة فتحت الآن، انتظر 5 ثواني ثم أعد المحاولة." });

    try {
        const sent = await sendWithRetry(sock, chatId, { text }, 3);
        users[token].count = (users[token].count || 0) + 1;
        saveUsers(users);
        res.status(200).json({ status: "sent", sent });
    } catch (error) {
        const status = error?.output?.statusCode || 500;
        pushLog(token, "error", "send-text failed", { status, err: String(error?.message || error) });
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
