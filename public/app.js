/* ============================================================
   KodbankApp — Frontend JS (localStorage Bearer Token Auth)
   ============================================================ */

const API = '';

/* ── Token storage (localStorage) ──────────────────────── */
const TOKEN_KEY = 'kb_jwt';
const NAME_KEY = 'kb_name';

function saveToken(token, name) {
    localStorage.setItem(TOKEN_KEY, token);
    localStorage.setItem(NAME_KEY, name);
}
function getToken() { return localStorage.getItem(TOKEN_KEY); }
function clearToken() { localStorage.removeItem(TOKEN_KEY); localStorage.removeItem(NAME_KEY); }

/* ── Authenticated fetch (auto adds Bearer header) ─────── */
function authFetch(url, opts = {}) {
    const token = getToken();
    const headers = { 'Content-Type': 'application/json', ...(opts.headers || {}) };
    if (token) headers['Authorization'] = `Bearer ${token}`;
    return fetch(url, { ...opts, headers });
}

/* ── Utilities ──────────────────────────────────────────── */
function showAlert(id, msg, type) {
    const el = document.getElementById(id);
    if (!el) return;
    el.className = `alert ${type} show`;
    el.textContent = msg;
    el.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}
function hideAlert(id) { const el = document.getElementById(id); if (el) { el.className = 'alert'; el.textContent = ''; } }
function setLoading(btn, loading, def) {
    btn.disabled = loading;
    btn.innerHTML = loading ? `<span class="spinner"></span> Please wait…` : def;
}

function handleExpiry(data, alertId) {
    const msg = data?.expired ? '⏰ Session expired. Redirecting to login…'
        : (data?.error || '🔒 Session invalid. Please login again.');
    if (alertId) showAlert(alertId, msg, 'error');
    clearToken();
    setTimeout(() => { window.location.href = 'index.html'; }, 2200);
}

/* ── Login page: tab switcher ───────────────────────────── */
function switchTab(tab) {
    hideAlert('alert');
    const lf = document.getElementById('loginForm');
    const rf = document.getElementById('registerForm');
    const ff = document.getElementById('forgotForm');
    if (!lf) return;
    lf.style.display = (tab === 'login') ? '' : 'none';
    rf.style.display = (tab === 'register') ? '' : 'none';
    if (ff) ff.style.display = (tab === 'forgot') ? '' : 'none';
    document.getElementById('tab-login').classList.toggle('active', tab === 'login');
    document.getElementById('tab-register').classList.toggle('active', tab === 'register');
    const tabForgot = document.getElementById('tab-forgot');
    if (tabForgot) tabForgot.classList.toggle('active', tab === 'forgot');
}

/* ── Register ───────────────────────────────────────────── */
async function handleRegister(e) {
    e.preventDefault(); hideAlert('alert');
    const btn = document.getElementById('registerBtn');
    setLoading(btn, true, 'Create Account');
    try {
        const res = await fetch(`${API}/api/register`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                customer_name: document.getElementById('reg-name').value.trim(),
                customer_email: document.getElementById('reg-email').value.trim(),
                customer_password: document.getElementById('reg-pass').value,
                bank_balance: document.getElementById('reg-balance').value || '0'
            })
        });
        const d = await res.json();
        if (!res.ok) showAlert('alert', '❌ ' + (d.error || 'Registration failed.'), 'error');
        else {
            showAlert('alert', '✅ ' + d.message, 'success');
            document.getElementById('registerForm').reset();
            setTimeout(() => switchTab('login'), 1800);
        }
    } catch { showAlert('alert', '❌ Cannot reach server.', 'error'); }
    finally { setLoading(btn, false, 'Create Account'); }
}

/* ── Login ──────────────────────────────────────────────── */
async function handleLogin(e) {
    e.preventDefault(); hideAlert('alert');
    const btn = document.getElementById('loginBtn');
    setLoading(btn, true, 'Login to Account');
    try {
        const res = await fetch(`${API}/api/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                customer_email: document.getElementById('login-email').value.trim(),
                customer_password: document.getElementById('login-pass').value
            })
        });
        const d = await res.json();
        if (!res.ok) showAlert('alert', '❌ ' + (d.error || 'Login failed.'), 'error');
        else {
            saveToken(d.token, d.customer_name);   // ← store JWT in localStorage
            window.location.href = 'dashboard.html';
        }
    } catch { showAlert('alert', '❌ Cannot reach server.', 'error'); }
    finally { setLoading(btn, false, 'Login to Account'); }
}

/* ── Forgot Password ──────────────────────────────── */
async function handleForgotPassword(e) {
    e.preventDefault(); hideAlert('alert');
    const btn = document.getElementById('forgotBtn');
    setLoading(btn, true, '🔑 Reset Password');
    try {
        const res = await fetch(`${API}/api/reset-password`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                customer_email: document.getElementById('forgot-email').value.trim(),
                new_password: document.getElementById('forgot-newpass').value
            })
        });
        const d = await res.json();
        if (!res.ok) showAlert('alert', '❌ ' + (d.error || 'Reset failed.'), 'error');
        else {
            showAlert('alert', '✅ ' + d.message, 'success');
            document.getElementById('forgotForm').reset();
            setTimeout(() => switchTab('login'), 2000);
        }
    } catch { showAlert('alert', '❌ Cannot reach server.', 'error'); }
    finally { setLoading(btn, false, '🔑 Reset Password'); }
}

/* ────────────────────────────────────────────────────────────
   DASHBOARD
   ════════════════════════════════════════════════════════════ */
let _profileCache = null;

async function initDashboard() {
    if (!getToken()) { window.location.href = 'index.html'; return; }
    try {
        const res = await authFetch(`${API}/api/me`);
        const d = await res.json();
        if (!res.ok) { handleExpiry(d, null); return; }
        const nameEl = document.getElementById('topUserName');
        if (nameEl) nameEl.textContent = d.customer_name || localStorage.getItem(NAME_KEY) || 'User';
    } catch { window.location.href = 'index.html'; return; }
    showPanel('dashboard');
}

/* ── Sidebar navigation ─────────────────────────────────── */
const PANELS = ['dashboard', 'deposit', 'withdraw', 'transfer', 'transactions', 'profile', 'ai'];

function showPanel(name) {
    PANELS.forEach(p => {
        const el = document.getElementById(`panel-${p}`);
        const nav = document.getElementById(`nav-${p}`);
        if (el) el.style.display = (p === name) ? '' : 'none';
        if (nav) nav.classList.toggle('active', p === name);
    });
    // Toggle floating AI button state
    const floatBtn = document.getElementById('aiFloatBtn');
    if (floatBtn) floatBtn.classList.toggle('active-panel', name === 'ai');
    hideAlert('dashAlert');
    if (name === 'dashboard') loadDashboard();
    if (name === 'transactions') loadTransactions('allTxnBody');
    if (name === 'profile') loadProfile();
}

/* ── User dropdown ──────────────────────────────────────── */
function toggleUserDropdown() {
    document.getElementById('userDropdown').classList.toggle('open');
}
document.addEventListener('click', e => {
    const menu = document.getElementById('userMenu');
    const drop = document.getElementById('userDropdown');
    if (menu && drop && !menu.contains(e.target)) drop.classList.remove('open');
});

/* ── Dashboard: load stats + recent txns ───────────────── */
async function loadDashboard() {
    try {
        const [profRes, txnRes] = await Promise.all([
            authFetch(`${API}/api/profile`),
            authFetch(`${API}/api/transactions`)
        ]);
        if (profRes.status === 401) { handleExpiry(await profRes.json(), 'dashAlert'); return; }
        const prof = await profRes.json();

        const setEl = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v || '—'; };
        setEl('statBalance', '₹' + parseFloat(prof.bank_balance).toLocaleString('en-IN', { minimumFractionDigits: 2 }));
        setEl('statAccno', prof.account_number);
        setEl('statIfsc', prof.ifsc_code);

        const txns = txnRes.ok ? await txnRes.json() : [];
        renderTxnTable('recentTxnBody', txns.slice(0, 5));
    } catch { showAlert('dashAlert', '❌ Could not load dashboard.', 'error'); }
}

/* ── Transactions table renderer ────────────────────────── */
function renderTxnTable(tbodyId, txns) {
    const tbody = document.getElementById(tbodyId);
    if (!tbody) return;
    if (!txns.length) { tbody.innerHTML = '<tr><td colspan="5" class="empty-row">No transactions yet.</td></tr>'; return; }
    tbody.innerHTML = txns.map(t => {
        const d = new Date(t.created_at);
        const date = d.toLocaleDateString('en-IN', { day: '2-digit', month: 'short', year: 'numeric' })
            + ', ' + d.toLocaleTimeString('en-IN', { hour: '2-digit', minute: '2-digit' });
        const amtCls = t.type === 'CREDIT' ? 'amount-credit' : 'amount-debit';
        const sign = t.type === 'CREDIT' ? '+' : '-';
        return `<tr>
          <td>${date}</td>
          <td>${t.description}</td>
          <td><span class="badge ${t.type}">${t.type}</span></td>
          <td class="${amtCls}">${sign}₹${parseFloat(t.amount).toLocaleString('en-IN', { minimumFractionDigits: 2 })}</td>
          <td><span class="badge ${t.status}">${t.status}</span></td>
        </tr>`;
    }).join('');
}

async function loadTransactions(tbodyId) {
    const tbody = document.getElementById(tbodyId);
    if (tbody) tbody.innerHTML = '<tr><td colspan="5" class="empty-row">Loading…</td></tr>';
    try {
        const res = await authFetch(`${API}/api/transactions`);
        if (res.status === 401) { handleExpiry(await res.json(), 'dashAlert'); return; }
        renderTxnTable(tbodyId, await res.json());
    } catch { if (tbody) tbody.innerHTML = '<tr><td colspan="5" class="empty-row">Failed to load.</td></tr>'; }
}

/* ── Profile ────────────────────────────────────────────── */
async function loadProfile() {
    if (_profileCache) { applyProfile(_profileCache); return; }
    try {
        const res = await authFetch(`${API}/api/profile`);
        if (res.status === 401) { handleExpiry(await res.json(), 'dashAlert'); return; }
        const d = await res.json();
        _profileCache = d;
        applyProfile(d);
    } catch { showAlert('dashAlert', '❌ Cannot load profile.', 'error'); }
}
function applyProfile(d) {
    const set = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v || '—'; };
    const av = document.getElementById('profileAvatar');
    if (av) av.textContent = (d.customer_name || 'U')[0].toUpperCase();
    set('profileName', d.customer_name);
    set('profileEmail', d.customer_email);
    set('profileAccno', d.account_number);
    set('profileIfsc', d.ifsc_code);
    if (d.session?.expires_at) {
        set('profileExpiry', new Date(d.session.expires_at).toLocaleString('en-IN', { dateStyle: 'medium', timeStyle: 'short' }));
    }
}
function copyAccno() {
    const acno = document.getElementById('profileAccno')?.textContent;
    if (acno && acno !== '—') {
        navigator.clipboard.writeText(acno);
        const btn = document.querySelector('.copy-btn');
        if (btn) { btn.textContent = '✅ Copied!'; setTimeout(() => { btn.textContent = '⎘ Copy Account Number'; }, 1800); }
    }
}

/* ── Deposit ────────────────────────────────────────────── */
async function handleDeposit(e) {
    e.preventDefault(); hideAlert('dashAlert');
    const btn = document.getElementById('depositBtn');
    setLoading(btn, true, '⊕ Add Money');
    try {
        const res = await authFetch(`${API}/api/deposit`, {
            method: 'POST',
            body: JSON.stringify({ amount: parseFloat(document.getElementById('deposit-amount').value) })
        });
        const d = await res.json();
        if (res.status === 401) { handleExpiry(d, 'dashAlert'); return; }
        if (!res.ok) showAlert('dashAlert', '❌ ' + (d.error || 'Deposit failed.'), 'error');
        else {
            showAlert('dashAlert', `✅ ${d.message}  New Balance: ₹${parseFloat(d.new_balance).toLocaleString('en-IN', { minimumFractionDigits: 2 })}`, 'success');
            document.getElementById('deposit-amount').value = '';
            _profileCache = null;
        }
    } catch { showAlert('dashAlert', '❌ Cannot reach server.', 'error'); }
    finally { setLoading(btn, false, '⊕ Add Money'); }
}

/* ── Withdraw ───────────────────────────────────────────── */
async function handleWithdraw(e) {
    e.preventDefault(); hideAlert('dashAlert');
    const btn = document.getElementById('withdrawBtn');
    setLoading(btn, true, '⊖ Withdraw');
    try {
        const res = await authFetch(`${API}/api/withdraw`, {
            method: 'POST',
            body: JSON.stringify({ amount: parseFloat(document.getElementById('withdraw-amount').value) })
        });
        const d = await res.json();
        if (res.status === 401) { handleExpiry(d, 'dashAlert'); return; }
        if (!res.ok) showAlert('dashAlert', '❌ ' + (d.error || 'Withdrawal failed.'), 'error');
        else {
            showAlert('dashAlert', `✅ ${d.message}  New Balance: ₹${parseFloat(d.new_balance).toLocaleString('en-IN', { minimumFractionDigits: 2 })}`, 'success');
            document.getElementById('withdraw-amount').value = '';
            _profileCache = null;
        }
    } catch { showAlert('dashAlert', '❌ Cannot reach server.', 'error'); }
    finally { setLoading(btn, false, '⊖ Withdraw'); }
}

/* ── Transfer ───────────────────────────────────────────── */
async function handleTransfer(e) {
    e.preventDefault(); hideAlert('dashAlert');
    const btn = document.getElementById('transferBtn');
    setLoading(btn, true, '⇄ Send Money');
    try {
        const res = await authFetch(`${API}/api/transfer`, {
            method: 'POST',
            body: JSON.stringify({
                recipient_email: document.getElementById('recipient-email').value.trim(),
                amount: parseFloat(document.getElementById('transfer-amount').value)
            })
        });
        const d = await res.json();
        if (res.status === 401) { handleExpiry(d, 'dashAlert'); return; }
        if (!res.ok) showAlert('dashAlert', '❌ ' + (d.error || 'Transfer failed.'), 'error');
        else {
            showAlert('dashAlert', '✅ ' + d.message, 'success');
            document.getElementById('recipient-email').value = '';
            document.getElementById('transfer-amount').value = '';
            _profileCache = null;
        }
    } catch { showAlert('dashAlert', '❌ Cannot reach server.', 'error'); }
    finally { setLoading(btn, false, '⇄ Send Money'); }
}

/* ── Account Validator ──────────────────────────────────── */
async function validateAccount() {
    const input = document.getElementById('validateInput');
    const result = document.getElementById('validateResult');
    const btn = document.getElementById('validateBtn');
    const acno = (input?.value || '').trim().toUpperCase();
    if (!acno) { input?.focus(); return; }
    if (!/^KODBK\d{10}$/.test(acno)) {
        result.className = 'validate-result invalid'; result.style.display = '';
        result.textContent = '❌ Invalid format. Expected: KODBK + 10 digits.'; return;
    }
    btn.disabled = true; btn.textContent = 'Checking…';
    try {
        const res = await authFetch(`${API}/api/validate-account/${encodeURIComponent(acno)}`);
        const d = await res.json();
        result.style.display = '';
        if (res.ok && d.valid) {
            result.className = 'validate-result valid';
            result.textContent = `✅ Valid — Holder: ${d.customer_name}  |  IFSC: ${d.ifsc_code}`;
        } else {
            result.className = 'validate-result invalid';
            result.textContent = '❌ Account not found.';
        }
    } catch { result.className = 'validate-result invalid'; result.style.display = ''; result.textContent = '❌ Server error.'; }
    finally { btn.disabled = false; btn.textContent = 'Check'; }
}

/* ── Logout ─────────────────────────────────────────────── */
async function logout() {
    try { await authFetch(`${API}/api/logout`, { method: 'POST' }); } catch { }
    clearToken();
    window.location.href = 'index.html';
}

/* ════════════════════════════════════════════════════════════
   AI AGENT CHAT
   ════════════════════════════════════════════════════════════ */
let _aiHistory = [];

function appendAiMsg(role, html) {
    const messages = document.getElementById('aiMessages');
    if (!messages) return null;
    const wrap = document.createElement('div');
    wrap.className = `ai-msg ${role}`;
    wrap.innerHTML = role === 'bot'
        ? `<div class="ai-avatar">🤖</div><div class="ai-bubble">${html}</div>`
        : `<div class="ai-bubble user-bubble">${html}</div><div class="ai-avatar user-av">👤</div>`;
    messages.appendChild(wrap);
    scrollAiChat();
    return wrap;
}

function scrollAiChat() {
    const el = document.getElementById('aiMessages');
    if (el) el.scrollTop = el.scrollHeight;
}

function sendAiChip(text) {
    const input = document.getElementById('aiInput');
    if (input) { input.value = text; }
    sendAiMessage();
    const chips = document.getElementById('aiQuickPrompts');
    if (chips) chips.style.display = 'none';
}

async function sendAiMessage() {
    const input = document.getElementById('aiInput');
    const btn = document.getElementById('aiSendBtn');
    const msg = (input && input.value || '').trim();
    if (!msg) return;

    input.value = '';
    input.disabled = true;
    if (btn) btn.disabled = true;

    const safeMsg = msg.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    appendAiMsg('user', safeMsg);

    const typingEl = appendAiMsg('bot',
        '<span class="ai-typing"><span></span><span></span><span></span></span>');

    try {
        const res = await authFetch(`${API}/api/ai-chat`, {
            method: 'POST',
            body: JSON.stringify({ message: msg, history: _aiHistory.slice(-8) })
        });
        const data = await res.json();
        if (typingEl) typingEl.remove();

        if (!res.ok) {
            appendAiMsg('bot', '❌ ' + (data.error || 'AI error. Please try again.'));
        } else {
            _aiHistory.push({ user: msg, bot: data.reply });
            const safeReply = data.reply
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/\n/g, '<br>');
            appendAiMsg('bot', safeReply);
        }
    } catch {
        if (typingEl) typingEl.remove();
        appendAiMsg('bot', '❌ Cannot reach AI service. Please try again.');
    } finally {
        if (input) input.disabled = false;
        if (btn) btn.disabled = false;
        if (input) input.focus();
    }
}

function clearAiChat() {
    _aiHistory = [];
    const messages = document.getElementById('aiMessages');
    if (messages) {
        messages.innerHTML = '<div class="ai-msg bot"><div class="ai-avatar">🤖</div>' +
            '<div class="ai-bubble">Chat cleared! Ask me anything about banking or finance.</div></div>';
    }
    const chips = document.getElementById('aiQuickPrompts');
    if (chips) chips.style.display = '';
}


/* ── Router ─────────────────────────────────────────────── */
(function init() {
    if (window.location.pathname.includes('dashboard')) {
        initDashboard();
    } else {
        // If already logged in, skip login page
        if (getToken()) {
            authFetch(`${API}/api/me`)
                .then(r => { if (r.ok) window.location.href = 'dashboard.html'; })
                .catch(() => { });
        }
    }
})();
