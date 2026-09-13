/**
 * dashboard.js — Dashboard page logic
 *
 * Loads:
 *   - Unread count  → GET /api/messages/unread-count
 *   - Inbox list    → GET /api/messages/inbox    (first 5)
 *   - Sent list     → GET /api/messages/sent     (first 5)
 *   - User list     → GET /api/users             (total count)
 *
 * Populates stats cards, recent inbox, recent sent panels,
 * and the account info section.
 */

// ── Guard: redirect to login if no token ─────────────────────
if (!requireAuth()) { /* stops here */ }

// ── On DOM ready ─────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', async () => {
    initSidebar();
    populateAccountInfo();
    await Promise.all([
        loadStats(),
        loadRecentInbox(),
        loadRecentSent(),
    ]);
    refreshUnreadBadge();
});

// ─────────────────────────────────────────────────────────────
// Account info
// ─────────────────────────────────────────────────────────────
function populateAccountInfo() {
    const user = getCurrentUser();
    const name = escHtml(user.username || '—');

    const el = (id) => document.getElementById(id);
    if (el('welcomeName'))   el('welcomeName').textContent  = user.username || '—';
    if (el('acctUsername'))  el('acctUsername').textContent = user.username || '—';
    if (el('acctEmail'))     el('acctEmail').textContent    = user.email    || '—';
    if (el('acctRole'))      el('acctRole').innerHTML =
        `<span class="chip ${user.role === 'ADMIN' ? 'chip-warning' : 'chip-sent'}">${escHtml(user.role || 'USER')}</span>`;
}

// ─────────────────────────────────────────────────────────────
// Stats
// ─────────────────────────────────────────────────────────────
async function loadStats() {
    try {
        const [unreadData, inboxData, sentData, usersData] = await Promise.all([
            apiGetUnreadCount().catch(() => ({ unreadCount: '—' })),
            apiGetInbox().catch(() => []),
            apiGetSent().catch(() => []),
            apiGetUsers().catch(() => []),
        ]);

        setText('statUnread', unreadData.unreadCount ?? '—');
        setText('statInbox',  Array.isArray(inboxData) ? inboxData.length : '—');
        setText('statSent',   Array.isArray(sentData)  ? sentData.length  : '—');
        setText('statUsers',  Array.isArray(usersData) ? usersData.length : '—');
    } catch (err) {
        console.error('Failed to load stats:', err.message);
    }
}

// ─────────────────────────────────────────────────────────────
// Recent inbox (first 5 messages)
// ─────────────────────────────────────────────────────────────
async function loadRecentInbox() {
    const container = document.getElementById('recentInbox');
    if (!container) return;

    try {
        const messages = await apiGetInbox();

        if (!messages || messages.length === 0) {
            container.innerHTML = emptyState('📭', 'No messages received yet.');
            return;
        }

        const rows = messages.slice(0, 5).map(m => buildMiniCard(m, 'inbox')).join('');
        container.innerHTML = rows;

        // Attach click handlers to open inbox
        container.querySelectorAll('.mini-card').forEach(el => {
            el.addEventListener('click', () => redirectTo('inbox.html'));
        });

    } catch (err) {
        container.innerHTML = errorState(err.message);
    }
}

// ─────────────────────────────────────────────────────────────
// Recent sent (first 5 messages)
// ─────────────────────────────────────────────────────────────
async function loadRecentSent() {
    const container = document.getElementById('recentSent');
    if (!container) return;

    try {
        const messages = await apiGetSent();

        if (!messages || messages.length === 0) {
            container.innerHTML = emptyState('📮', 'No messages sent yet.');
            return;
        }

        const rows = messages.slice(0, 5).map(m => buildMiniCard(m, 'sent')).join('');
        container.innerHTML = rows;

    } catch (err) {
        container.innerHTML = errorState(err.message);
    }
}

// ─────────────────────────────────────────────────────────────
// Builders
// ─────────────────────────────────────────────────────────────

/**
 * Builds a compact message row for the dashboard panels.
 * Shows sender/recipient, encrypted indicator, and time.
 * Never shows decrypted content here — that is inbox.html's job.
 */
function buildMiniCard(msg, type) {
    const counterpart = type === 'inbox'
        ? `From: <strong>${escHtml(msg.senderUsername)}</strong>`
        : `To: <strong>${escHtml(msg.recipientUsername)}</strong>`;

    const isRead   = msg.status === 'READ';
    const statusChip = isRead
        ? `<span class="chip chip-read">Read</span>`
        : `<span class="chip chip-sent">Unread</span>`;

    return `
    <div class="mini-card" style="
        padding:.65rem 1rem;
        border-bottom:1px solid var(--gray-100);
        cursor:pointer;
        transition:background .15s;
        display:flex;
        align-items:center;
        justify-content:space-between;
        gap:.75rem;
    " onmouseover="this.style.background='var(--gray-50)'"
       onmouseout="this.style.background=''"
    >
      <div style="min-width:0;flex:1;">
        <div style="font-size:.83rem;font-weight:600;color:var(--gray-800);margin-bottom:.15rem;">
          ${counterpart}
        </div>
        <div class="msg-encrypted-label" style="font-size:.7rem;">
          🔒 RSA-2048 Encrypted
        </div>
      </div>
      <div style="text-align:right;flex-shrink:0;">
        ${statusChip}
        <div style="font-size:.72rem;color:var(--gray-400);margin-top:.2rem;">
          ${formatDateTime(msg.sentAt)}
        </div>
      </div>
    </div>`;
}

// ─────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────

function setText(id, value) {
    const el = document.getElementById(id);
    if (el) el.textContent = value;
}

function emptyState(icon, text) {
    return `<div class="empty-state" style="padding:1.5rem;">
      <div class="empty-icon">${icon}</div>
      <p>${text}</p>
    </div>`;
}

function errorState(msg) {
    return `<div class="alert alert-danger" style="margin:.75rem;">
      <span class="alert-icon">✕</span>
      <span>${escHtml(msg)}</span>
    </div>`;
}
