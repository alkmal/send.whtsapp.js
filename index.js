// ✅ إصلاح مشكلة crypto في Node.js
if (!globalThis.crypto) {
    globalThis.crypto = require("crypto").webcrypto;
}

const express = require("express");
const qrcode = require("qrcode");
const { default: makeWASocket, useMultiFileAuthState, fetchLatestBaileysVersion } = require("@whiskeysockets/baileys");
const { Boom } = require("@hapi/boom");
const cors = require("cors");
const bodyParser = require("body-parser");
const session = require("express-session");
const fs = require("fs");
const crypto = require("crypto");
const path = require("path");

const app = express();
app.use(cors());
app.use(bodyParser.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use(session({
    secret: "whatsapp-api-secret",
    resave: false,
    saveUninitialized: true
}));

const USERS_FILE = "./users.json";
const SESSIONS_DIR = "./sessions";
if (!fs.existsSync(SESSIONS_DIR)) fs.mkdirSync(SESSIONS_DIR);

let sockets = {}; // الجلسات حسب التوكن
let qrCodes = {}; // QR لكل مستخدم
let onceConnectedInfo = {}; // بيانات الاتصال لمرة واحدة

function generateToken() {
    return crypto.randomBytes(16).toString("hex");
}

function saveUsers(users) {
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}

function loadUsers() {
    if (!fs.existsSync(USERS_FILE)) return {};
    return JSON.parse(fs.readFileSync(USERS_FILE));
}

const users = loadUsers();

app.get("/", (req, res) => {
    if (req.session.user) return res.redirect("/dashboard");
    res.sendFile(path.join(__dirname, "public", "login.html"));
});

app.post("/login", (req, res) => {
    const { username, password } = req.body;
    const tokenEntry = Object.entries(users).find(([_, u]) => u.username === username && u.password === password);

    if (!tokenEntry) return res.status(401).send("\u274C بيانات الدخول غير صحيحة");

    req.session.user = { username, token: tokenEntry[0] };
    res.redirect("/dashboard");
});

app.get("/dashboard", (req, res) => {
    if (!req.session.user) return res.redirect("/");

    const list = Object.entries(users).map(([token, user]) => {
        const online = !qrCodes[token];
        return `
            <tr>
                <td>${user.username}</td>
                <td>${token}</td>
                <td>${online ? "✅ متصل" : "⏳ غير متصل"}</td>
                <td>${user.count || 0}</td>
                <td>${!online ? `<a href="/qr/${token}">عرض QR</a> | <a href="/reconnect/${token}">🔁 إعادة الاتصال</a>` : "-"}</td>
                <td>
                    <form method="POST" action="/reset-count">
                        <input type="hidden" name="token" value="${token}" />
                        <button>🔁 تصفير</button>
                    </form>
                </td>
            </tr>
        `;
    });

    res.send(`
        <html><body>
        <h2>📋 قائمة الجلسات (${req.session.user.username})</h2>
        <table border="1" cellpadding="10" style="margin:auto">
            <tr><th>المستخدم</th><th>Token</th><th>الحالة</th><th>عدد الرسائل</th><th>QR / إعادة الاتصال</th><th>تصفير</th></tr>
            ${list.join("")}
        </table>
        </body></html>
    `);
});

app.post("/reset-count", (req, res) => {
    const { token } = req.body;
    if (users[token]) {
        users[token].count = 0;
        saveUsers(users);
    }
    res.redirect("/dashboard");
});

app.post("/auth", (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).send("الاسم وكلمة المرور مطلوبة");

    const token = generateToken();
    users[token] = { username, password, token, sessionPath: `${SESSIONS_DIR}/${token}`, count: 0 };
    saveUsers(users);
    startSocketForToken(token);

    res.redirect(`/qr/${token}`);
});

app.get("/qr/:token", async (req, res) => {
    const token = req.params.token;
    if (!users[token]) return res.status(401).send("توكن غير صالح");

    const qr = qrCodes[token];
    const username = users[token].username;
    const qrImage = qr ? await qrcode.toDataURL(qr) : null;
    const onceInfo = onceConnectedInfo[token];

    let infoHtml = "";
    if (onceInfo) {
        infoHtml = `
            <hr>
            <h3>📡 بيانات الاتصال:</h3>
            <pre>${JSON.stringify(onceInfo, null, 2)}</pre>
        `;
        delete onceConnectedInfo[token];
    }

    res.send(`
        <html><body style="text-align:center;font-family:sans-serif">
        <h2>📲 امسح QR لحساب المستخدم <b>${username}</b></h2>
        ${qrImage ? `<img src="${qrImage}" />` : "<p>✅ تم الاتصال بالفعل أو لم يتم توليد QR بعد.</p>"}
        ${infoHtml}
        </body></html>
    `);
});

app.get("/reconnect/:token", (req, res) => {
    const token = req.params.token;
    if (!users[token]) return res.status(404).send("توكن غير موجود");
    startSocketForToken(token);
    res.redirect("/dashboard");
});

async function startSocketForToken(token) {
    const user = users[token];
    if (!user) return;

    const { state, saveCreds } = await useMultiFileAuthState(user.sessionPath);
    const { version } = await fetchLatestBaileysVersion();

    const sock = makeWASocket({
        version,
        auth: state,
        printQRInTerminal: false,
    });

    sockets[token] = sock;

    sock.ev.on("connection.update", (update) => {
        const { connection, lastDisconnect, qr } = update;

        if (qr) {
            qrCodes[token] = qr;
            console.log(`🔔 QR جديد للمستخدم ${user.username}`);
        }

        if (connection === "open") {
            qrCodes[token] = null;
            console.log(`✅ متصل بـ WhatsApp كمستخدم ${user.username}`);
            const connInfo = sock.user;
            onceConnectedInfo[token] = connInfo;
        }

        if (connection === "close") {
            const code = lastDisconnect?.error?.output?.statusCode;
            const shouldReconnect = code !== 401;
            console.log(`⚠️ قطع الاتصال للمستخدم ${user.username} (code: ${code})`);
            if (shouldReconnect) {
                setTimeout(() => startSocketForToken(token), 5000); // إعادة المحاولة بعد 5 ثواني
            }
        }
    });

    sock.ev.on("creds.update", saveCreds);
}

Object.keys(users).forEach(startSocketForToken);

app.post("/send-text", async (req, res) => {
    const { token, chatId, text } = req.body;
    if (!token || !chatId || !text) {
        return res.status(400).json({ error: "token و chatId و text مطلوبة" });
    }

    const sock = sockets[token];
    if (!sock) return res.status(401).json({ error: "الجلسة غير متوفرة أو لم يتم الربط" });

    try {
        const sent = await sock.sendMessage(chatId, { text });
        users[token].count = (users[token].count || 0) + 1;
        saveUsers(users);
        res.status(200).json({ status: "sent", sent });
    } catch (error) {
        res.status(500).json({ status: "error", error: error.toString() });
    }
});

const PORT = process.env.PORT || 80;
app.listen(PORT, () => {
    console.log(`🚀 الخادم يعمل على http://localhost:${PORT}`);
});
