const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const path = require('path');
const mysql = require('mysql2/promise');
require('dotenv').config();

const app = express();
let db;

const JWT_SECRET = process.env.JWT_SECRET || 'kodbankapp_super_secret_key_2026';
const TOKEN_TTL_H = 2;
const COOKIE_NAME = 'kb_token';
const IFSC_CODE = 'KODBK0001';
const HF_API_KEY = process.env.HF_API_KEY;
const HF_MODEL = 'CohereLabs/tiny-aya-global';

// ── Middleware ────────────────────────────────────────────────────────────────
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// ── Vercel/Serverless: Attempt to init DB on request if it failed at boot ──
app.use(async (req, res, next) => {
    // If it's an API call and DB isn't fully ready, try one more time (lazy init)
    if (req.path.startsWith('/api') && !db) {
        console.log('🔄 Lazy-initializing DB connection...');
        await initDB().catch(e => console.error('Lazy init failed:', e.message));
    }

    if (!db && req.path.startsWith('/api')) {
        const host = process.env.DB_HOST || '';
        const missingVars = ['DB_HOST', 'DB_USER', 'DB_NAME'].filter(v => !process.env[v]);
        let errorMsg = '❌ Database not connected.';

        if (host.includes('.i.aivencloud.com')) {
            errorMsg += ' ⚠️ You are using an INTERNAL Aiven host. Please use the EXTERNAL host from Aiven console (the one without ".i.").';
        } else if (missingVars.length > 0) {
            errorMsg += ` Missing environment variables: ${missingVars.join(', ')}. Please add them in Vercel settings.`;
        } else {
            errorMsg += ' Check if your database allows connections from Vercel IPs.';
        }
        return res.status(503).json({ error: errorMsg });
    }
    next();
});

// ── Helpers ───────────────────────────────────────────────────────────────────
function clearCookie(res) {
    res.clearCookie(COOKIE_NAME, { httpOnly: true, sameSite: 'Lax' });
}

/** Generate a unique account number: KODBK + 10 random digits */
function generateAccountNumber() {
    const digits = Math.floor(Math.random() * 9_000_000_000 + 1_000_000_000);
    return `KODBK${digits}`;
}

/** Ensure the generated account number is not already taken */
async function uniqueAccountNumber() {
    let acno, exists = true;
    while (exists) {
        acno = generateAccountNumber();
        const [rows] = await db.execute('SELECT 1 FROM bank_users WHERE account_number = ?', [acno]);
        exists = rows.length > 0;
    }
    return acno;
}

// ════════════════════════════════════════════════════════════════════════════════
//  AUTH MIDDLEWARE
// ════════════════════════════════════════════════════════════════════════════════
async function authenticateToken(req, res, next) {
    // Accept token from localStorage (Bearer header) OR httpOnly cookie
    const authHeader = req.headers['authorization'];
    const token = (authHeader && authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null)
        || req.cookies[COOKIE_NAME];

    if (!token)
        return res.status(401).json({ error: 'Not authenticated. Please login.', expired: false });

    try {
        const [rows] = await db.execute(
            'SELECT id, customer_id, expires_at, is_active FROM jwt_tokens WHERE token = ? LIMIT 1',
            [token]
        );

        if (rows.length === 0) { clearCookie(res); return res.status(401).json({ error: 'Invalid session. Please login again.', expired: false }); }
        const rec = rows[0];
        if (!rec.is_active) { clearCookie(res); return res.status(401).json({ error: 'Session was logged out. Please login again.', expired: false }); }
        if (new Date() > new Date(rec.expires_at)) {
            await db.execute('UPDATE jwt_tokens SET is_active = 0 WHERE id = ?', [rec.id]);
            clearCookie(res);
            return res.status(401).json({ error: 'Session expired. Please login again.', expired: true });
        }

        req.user = jwt.verify(token, JWT_SECRET);
        req.tokenId = rec.id;
        next();
    } catch (err) {
        clearCookie(res);
        if (err.name === 'TokenExpiredError')
            return res.status(401).json({ error: 'Session expired. Please login again.', expired: true });
        return res.status(403).json({ error: 'Invalid token. Please login again.', expired: false });
    }
}

// ════════════════════════════════════════════════════════════════════════════════
//  ROUTES
// ════════════════════════════════════════════════════════════════════════════════

// ── POST /api/register ────────────────────────────────────────────────────────
app.post('/api/register', async (req, res) => {
    const { customer_name, customer_email, customer_password, bank_balance } = req.body;
    if (!customer_name || !customer_email || !customer_password)
        return res.status(400).json({ error: 'Name, email, and password are required.' });

    try {
        const [existing] = await db.execute('SELECT customer_id FROM bank_users WHERE customer_email = ?', [customer_email]);
        if (existing.length > 0) return res.status(409).json({ error: 'Email is already registered.' });

        const hashedPw = await bcrypt.hash(customer_password, 10);
        const balance = parseFloat(bank_balance) || 0.00;
        const acno = await uniqueAccountNumber();

        await db.execute(
            'INSERT INTO bank_users (customer_name, customer_email, customer_password, bank_balance, account_number, ifsc_code) VALUES (?, ?, ?, ?, ?, ?)',
            [customer_name, customer_email, hashedPw, balance, acno, IFSC_CODE]
        );

        res.status(201).json({ message: 'Account created successfully! Please log in.' });
    } catch (err) {
        console.error('Register error:', err);
        res.status(500).json({ error: err.message || 'Server error.' });
    }
});

// ── POST /api/login ───────────────────────────────────────────────────────────
app.post('/api/login', async (req, res) => {
    const { customer_email, customer_password } = req.body;
    if (!customer_email || !customer_password)
        return res.status(400).json({ error: 'Email and password are required.' });

    try {
        const [rows] = await db.execute('SELECT * FROM bank_users WHERE customer_email = ?', [customer_email]);
        if (rows.length === 0) return res.status(401).json({ error: 'Invalid email or password.' });

        const user = rows[0];
        if (!await bcrypt.compare(customer_password, user.customer_password))
            return res.status(401).json({ error: 'Invalid email or password.' });

        // Clean up old expired / inactive tokens
        await db.execute('DELETE FROM jwt_tokens WHERE customer_id = ? AND (expires_at < NOW() OR is_active = 0)', [user.customer_id]);

        // Create JWT
        const expiresAt = new Date(Date.now() + TOKEN_TTL_H * 3_600_000);
        const token = jwt.sign(
            { customer_id: user.customer_id, customer_email: user.customer_email, customer_name: user.customer_name },
            JWT_SECRET,
            { expiresIn: `${TOKEN_TTL_H}h` }
        );

        // ★ Store token in jwt_tokens table (VARCHAR 512 — fix for TEXT lookup bug)
        await db.execute(
            'INSERT INTO jwt_tokens (customer_id, token, created_at, expires_at, is_active) VALUES (?, ?, NOW(), ?, 1)',
            [user.customer_id, token, expiresAt]
        );

        // Set httpOnly cookie (backup) + return token in body (for localStorage)
        res.cookie(COOKIE_NAME, token, { httpOnly: true, sameSite: 'Lax', maxAge: TOKEN_TTL_H * 3_600_000 });

        res.json({
            message: 'Login successful!',
            token: token,
            customer_name: user.customer_name,
            customer_id: user.customer_id,
            account_number: user.account_number,
            expires_at: expiresAt.toISOString()
        });
    } catch (err) {
        console.error('Login error:', err);
        res.status(500).json({ error: err.message || 'Server error.' });
    }
});

// ── POST /api/logout ──────────────────────────────────────────────────────────
app.post('/api/logout', authenticateToken, async (req, res) => {
    try {
        await db.execute('UPDATE jwt_tokens SET is_active = 0 WHERE id = ?', [req.tokenId]);
        clearCookie(res);
        res.json({ message: 'Logged out successfully.' });
    } catch (err) {
        console.error('Logout error:', err);
        res.status(500).json({ error: 'Server error.' });
    }
});

// ── POST /api/reset-password ──────────────────────────────────────────────────
app.post('/api/reset-password', async (req, res) => {
    const { customer_email, new_password } = req.body;
    if (!customer_email || !new_password)
        return res.status(400).json({ error: 'Email and new password are required.' });
    if (new_password.length < 4)
        return res.status(400).json({ error: 'Password must be at least 4 characters.' });
    try {
        const [rows] = await db.execute('SELECT customer_id FROM bank_users WHERE customer_email = ?', [customer_email]);
        if (rows.length === 0)
            return res.status(404).json({ error: 'No account found with that email.' });
        const hashed = await bcrypt.hash(new_password, 10);
        await db.execute('UPDATE bank_users SET customer_password = ? WHERE customer_email = ?', [hashed, customer_email]);
        await db.execute('UPDATE jwt_tokens SET is_active = 0 WHERE customer_id = ?', [rows[0].customer_id]);
        res.json({ message: 'Password reset! You can now login with your new password.' });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── GET /api/me ───────────────────────────────────────────────────────────────
app.get('/api/me', authenticateToken, async (req, res) => {
    try {
        const [rows] = await db.execute(
            'SELECT customer_name, customer_email, account_number, ifsc_code FROM bank_users WHERE customer_id = ?',
            [req.user.customer_id]
        );
        if (rows.length === 0) return res.status(404).json({ error: 'User not found.' });
        res.json(rows[0]);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── GET /api/profile ──────────────────────────────────────────────────────────
app.get('/api/profile', authenticateToken, async (req, res) => {
    try {
        const [rows] = await db.execute(
            'SELECT customer_name, customer_email, account_number, ifsc_code, bank_balance FROM bank_users WHERE customer_id = ?',
            [req.user.customer_id]
        );
        if (rows.length === 0) return res.status(404).json({ error: 'User not found.' });

        // Also fetch active token info
        const [tokenRows] = await db.execute(
            'SELECT created_at, expires_at FROM jwt_tokens WHERE customer_id = ? AND is_active = 1 ORDER BY created_at DESC LIMIT 1',
            [req.user.customer_id]
        );
        res.json({
            ...rows[0],
            session: tokenRows.length > 0 ? { created_at: tokenRows[0].created_at, expires_at: tokenRows[0].expires_at } : null
        });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── GET /api/balance ──────────────────────────────────────────────────────────
app.get('/api/balance', authenticateToken, async (req, res) => {
    try {
        const [rows] = await db.execute(
            'SELECT customer_name, customer_email, bank_balance FROM bank_users WHERE customer_id = ?',
            [req.user.customer_id]
        );
        if (rows.length === 0) return res.status(404).json({ error: 'User not found.' });
        res.json(rows[0]);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── POST /api/deposit ─────────────────────────────────────────────────────────
app.post('/api/deposit', authenticateToken, async (req, res) => {
    const amount = parseFloat(req.body.amount);
    if (isNaN(amount) || amount <= 0)
        return res.status(400).json({ error: 'Deposit amount must be a positive number.' });
    if (amount > 1_000_000)
        return res.status(400).json({ error: 'Maximum single deposit is ₹10,00,000.' });

    try {
        await db.execute('UPDATE bank_users SET bank_balance = bank_balance + ? WHERE customer_id = ?', [amount, req.user.customer_id]);
        const [rows] = await db.execute('SELECT bank_balance FROM bank_users WHERE customer_id = ?', [req.user.customer_id]);
        await db.execute(
            'INSERT INTO transactions (customer_id, type, description, amount, status) VALUES (?, ?, ?, ?, ?)',
            [req.user.customer_id, 'CREDIT', 'Cash Deposit', amount, 'SUCCESS']
        );
        res.json({
            message: `₹${amount.toFixed(2)} deposited successfully!`,
            new_balance: parseFloat(rows[0].bank_balance).toFixed(2)
        });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── POST /api/withdraw ────────────────────────────────────────────────────────
app.post('/api/withdraw', authenticateToken, async (req, res) => {
    const amount = parseFloat(req.body.amount);
    if (isNaN(amount) || amount <= 0)
        return res.status(400).json({ error: 'Withdrawal amount must be a positive number.' });

    try {
        const [rows] = await db.execute('SELECT bank_balance FROM bank_users WHERE customer_id = ?', [req.user.customer_id]);
        const balance = parseFloat(rows[0].bank_balance);
        if (balance < amount)
            return res.status(400).json({ error: `Insufficient funds. Your balance is ₹${balance.toFixed(2)}.` });

        await db.execute('UPDATE bank_users SET bank_balance = bank_balance - ? WHERE customer_id = ?', [amount, req.user.customer_id]);
        const [updated] = await db.execute('SELECT bank_balance FROM bank_users WHERE customer_id = ?', [req.user.customer_id]);
        await db.execute(
            'INSERT INTO transactions (customer_id, type, description, amount, status) VALUES (?, ?, ?, ?, ?)',
            [req.user.customer_id, 'DEBIT', 'Cash Withdrawal', amount, 'SUCCESS']
        );
        res.json({
            message: `₹${amount.toFixed(2)} withdrawn successfully!`,
            new_balance: parseFloat(updated[0].bank_balance).toFixed(2)
        });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── GET /api/validate-account/:acno ──────────────────────────────────────────
app.get('/api/validate-account/:acno', authenticateToken, async (req, res) => {
    const acno = req.params.acno.trim().toUpperCase();
    try {
        const [rows] = await db.execute(
            'SELECT customer_name, account_number, ifsc_code FROM bank_users WHERE account_number = ?',
            [acno]
        );
        if (rows.length === 0)
            return res.status(404).json({ valid: false, error: 'Account number not found.' });
        res.json({ valid: true, customer_name: rows[0].customer_name, account_number: rows[0].account_number, ifsc_code: rows[0].ifsc_code });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── POST /api/transfer ────────────────────────────────────────────────────────
app.post('/api/transfer', authenticateToken, async (req, res) => {
    const { recipient_email, amount } = req.body;
    if (!recipient_email || !amount)
        return res.status(400).json({ error: 'Recipient email and amount are required.' });
    const transferAmount = parseFloat(amount);
    if (isNaN(transferAmount) || transferAmount <= 0)
        return res.status(400).json({ error: 'Amount must be a positive number.' });
    if (recipient_email === req.user.customer_email)
        return res.status(400).json({ error: 'Cannot transfer money to yourself.' });

    try {
        const [senderRows] = await db.execute('SELECT bank_balance FROM bank_users WHERE customer_id = ?', [req.user.customer_id]);
        const senderBalance = parseFloat(senderRows[0].bank_balance);
        if (senderBalance < transferAmount)
            return res.status(400).json({ error: `Insufficient balance. Your balance is ₹${senderBalance.toFixed(2)}.` });

        const [recipientRows] = await db.execute('SELECT customer_id, customer_name FROM bank_users WHERE customer_email = ?', [recipient_email]);
        if (recipientRows.length === 0)
            return res.status(404).json({ error: 'Recipient not found. Check the email address.' });

        await db.execute('UPDATE bank_users SET bank_balance = bank_balance - ? WHERE customer_id = ?', [transferAmount, req.user.customer_id]);
        await db.execute('UPDATE bank_users SET bank_balance = bank_balance + ? WHERE customer_id = ?', [transferAmount, recipientRows[0].customer_id]);
        await db.execute(
            'INSERT INTO transactions (customer_id, type, description, amount, status) VALUES (?, ?, ?, ?, ?)',
            [req.user.customer_id, 'DEBIT', `Transfer to ${recipientRows[0].customer_name}`, transferAmount, 'SUCCESS']
        );
        await db.execute(
            'INSERT INTO transactions (customer_id, type, description, amount, status) VALUES (?, ?, ?, ?, ?)',
            [recipientRows[0].customer_id, 'CREDIT', `Transfer from ${req.user.customer_name}`, transferAmount, 'SUCCESS']
        );
        res.json({
            message: `₹${transferAmount.toFixed(2)} transferred to ${recipientRows[0].customer_name} successfully!`,
            new_balance: (senderBalance - transferAmount).toFixed(2)
        });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── GET /api/transactions ─────────────────────────────────────────────────────
app.get('/api/transactions', authenticateToken, async (req, res) => {
    try {
        const [rows] = await db.execute(
            'SELECT id, type, description, amount, status, created_at FROM transactions WHERE customer_id = ? ORDER BY created_at DESC LIMIT 20',
            [req.user.customer_id]
        );
        res.json(rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── POST /api/ai-chat (HF Router · tiny-aya Space via Together) ──────────────
app.post('/api/ai-chat', authenticateToken, async (req, res) => {
    const { message, history = [] } = req.body;
    if (!message || !message.trim())
        return res.status(400).json({ error: 'Message is required.' });

    const userName = req.user.customer_name || 'User';
    const systemPrompt = `You are KodbankApp's AI banking assistant helping ${userName}. ` +
        `Answer banking, finance, savings, and investment questions concisely and helpfully. ` +
        `Keep answers short and clear. Always be professional and friendly.`;

    // Build messages array with history for context
    const messages = [
        { role: 'system', content: systemPrompt },
        ...history.slice(-6).flatMap(h => [
            { role: 'user', content: h.user },
            { role: 'assistant', content: h.bot }
        ]),
        { role: 'user', content: message.trim() }
    ];

    try {
        // HF Router (Together provider) — works with free HF API keys
        const hfRes = await fetch(
            'https://router.huggingface.co/together/v1/chat/completions',
            {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${HF_API_KEY}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    model: 'meta-llama/Llama-3.2-3B-Instruct-Turbo',
                    messages,
                    max_tokens: 400,
                    temperature: 0.6,
                    stream: false
                })
            }
        );

        const data = await hfRes.json();

        if (!hfRes.ok)
            return res.status(502).json({ error: data.error?.message || data.message || 'AI service error.' });

        const reply = data?.choices?.[0]?.message?.content?.trim();
        if (!reply)
            return res.status(502).json({ error: 'Empty AI response. Please try again.' });

        res.json({ reply });
    } catch (err) {
        console.error('AI chat error:', err.message);
        res.status(500).json({ error: 'Failed to reach AI service: ' + err.message });
    }
});

// ── Catch-all ──────────────────────────────────────────────────────────────────
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// ════════════════════════════════════════════════════════════════════════════════
//  DB INIT — auto-creates DB, both tables, and applies schema migrations
// ════════════════════════════════════════════════════════════════════════════════
async function initDB() {
    // Vercel check: if vars are missing, don't even try and throw early
    const host = process.env.DB_HOST;
    if (!host) {
        console.error('❌ DB_HOST is missing. Check your environment variables.');
        return false;
    }

    console.log('🔌 Connecting to MySQL...');

    // Assign db pool immediately so other parts of the app can use it
    if (!db) {
        try {
            db = require('./db');
        } catch (e) {
            console.error('❌ Failed to load db.js pool:', e.message);
        }
    }

    try {
        const conn = await mysql.createConnection({
            host: host,
            user: process.env.DB_USER || 'root',
            password: process.env.DB_PASSWORD || '',
            port: parseInt(process.env.DB_PORT) || 3306,
            ssl: host && !host.includes('localhost') ? { rejectUnauthorized: false } : null
        });
        const dbName = process.env.DB_NAME || 'kodbankapp';

        await conn.query(`CREATE DATABASE IF NOT EXISTS \`${dbName}\``);
        await conn.query(`USE \`${dbName}\``);

        // bank_users table
        await conn.query(`
            CREATE TABLE IF NOT EXISTS bank_users (
                customer_id       INT AUTO_INCREMENT PRIMARY KEY,
                customer_name     VARCHAR(100)   NOT NULL,
                customer_password VARCHAR(255)   NOT NULL,
                bank_balance      DECIMAL(15,2)  NOT NULL DEFAULT 0.00,
                customer_email    VARCHAR(150)   NOT NULL UNIQUE,
                account_number    VARCHAR(20)    NOT NULL UNIQUE,
                ifsc_code         VARCHAR(15)    NOT NULL DEFAULT 'KODBK0001'
            )
        `);

        // Migrate existing bank_users: add columns if they don't exist yet
        try { await conn.query(`ALTER TABLE bank_users ADD COLUMN account_number VARCHAR(20) UNIQUE`); } catch (_) { }
        try { await conn.query(`ALTER TABLE bank_users ADD COLUMN ifsc_code VARCHAR(15) NOT NULL DEFAULT 'KODBK0001'`); } catch (_) { }

        // Backfill account_number for any rows that are missing it
        await conn.query(`
            UPDATE bank_users
               SET account_number = CONCAT('KODBK', LPAD(customer_id, 10, '0')),
                   ifsc_code      = 'KODBK0001'
             WHERE account_number IS NULL OR account_number = ''
        `);

        // jwt_tokens table
        await conn.query(`
            CREATE TABLE IF NOT EXISTS jwt_tokens (
                id          INT AUTO_INCREMENT PRIMARY KEY,
                customer_id INT           NOT NULL,
                token       VARCHAR(512)  NOT NULL,
                created_at  DATETIME      NOT NULL DEFAULT NOW(),
                expires_at  DATETIME      NOT NULL,
                is_active   TINYINT(1)    NOT NULL DEFAULT 1,
                INDEX idx_token (token(255)),
                FOREIGN KEY (customer_id) REFERENCES bank_users(customer_id) ON DELETE CASCADE
            )
        `);

        // If jwt_tokens existed with TEXT column, migrate it
        try { await conn.query(`ALTER TABLE jwt_tokens MODIFY token VARCHAR(512) NOT NULL`); } catch (_) { }

        // transactions table
        await conn.query(`
            CREATE TABLE IF NOT EXISTS transactions (
                id          INT AUTO_INCREMENT PRIMARY KEY,
                customer_id INT            NOT NULL,
                type        ENUM('CREDIT','DEBIT') NOT NULL,
                description VARCHAR(200)   NOT NULL DEFAULT 'Transaction',
                amount      DECIMAL(15,2)  NOT NULL,
                status      VARCHAR(20)    NOT NULL DEFAULT 'SUCCESS',
                created_at  DATETIME       NOT NULL DEFAULT NOW(),
                FOREIGN KEY (customer_id) REFERENCES bank_users(customer_id) ON DELETE CASCADE
            )
        `);

        console.log(`✅ Database "${dbName}" ready.`);
        await conn.end();
        return true;
    } catch (err) {
        let msg = err.message;
        if (host.includes('.i.aivencloud.com')) {
            msg = 'INTERNAL HOST ERROR: Use the public hostname from Aiven (the one without ".i.")';
        } else if (err.code === 'ECONNREFUSED') {
            msg = 'MySQL not running (Check DB_HOST and if database is public)';
        } else if (err.code === 'ER_ACCESS_DENIED_ERROR') {
            msg = 'Wrong credentials (Check DB_USER / DB_PASSWORD)';
        }

        console.error('\n❌ DB Error:', msg);

        if (err.code === 'ECONNREFUSED' || err.code === 'ER_ACCESS_DENIED_ERROR' || host.includes('.i.')) {
            db = null;
        }
        return false;
    }
}

const PORT = process.env.PORT || 3000;
initDB().then(ok => {
    if (process.env.VERCEL) return; // Don't block Vercel boot
    app.listen(PORT, () =>
        console.log(ok
            ? `\n🚀 KodbankApp → http://localhost:${PORT}\n`
            : `\n⚠️  Server started but DB is NOT connected.\n`)
    );
});

module.exports = app;
