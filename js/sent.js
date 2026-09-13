/**
 * sent.js — Sent Messages page logic
 *
 * Loads sent messages via GET /api/messages/sent.
 * Shows RSA ciphertext for each message.
 *
 * Security note:
 *   The sender CANNOT decrypt their own sent messages.
 *   RSA encryption uses the RECIPIENT's public key, so only
 *   the recipient's private key can reverse it. This is a
 *   fundamental property of asymmetric encryption and is
 *   clearly communicated to the user on this page.
 */

if (!requireAuth()) { /* stops here */ }

document.addEventListener('DOMContentLoaded', async () => {
    initSidebar();
    await loadSent();
    refreshUnreadBadge();
});

// ─────────────────────────────────────────────────────────────
// Load sent messages
// ─────────────────────────────────────────────────────────────
async function loadSent() {
    const container = document.getElementById('messageList');
    hideAlert('alertBox');

    try {
        const messages = await apiGetSent();

        if (!messages || messages.length === 0) {
            container.innerHTML = `
              <div class="empty-state">
                <div class="empty-icon">📮</div>
                <p>You haven't sent any messages yet.</p>
                <a href="send.html" class="btn btn-primary btn-sm" style="margin-top:.75rem;">
                  Send Your First Message
                </a>
              </div>`;
            return;
        }

        container.innerHTML = `<div class="message-list">${
            messages.map(m => buildSentCard(m)).join('')
        }</div>`;

    } catch (err) {
        showAlert('alertBox', err.message || 'Failed to load sent messages.');
        container.innerHTML = '';
    }
}

// ─────────────────────────────────────────────────────────────
// Build sent message card
// ─────────────────────────────────────────────────────────────
function buildSentCard(msg) {
    return `
    <div class="message-card" id="card-${msg.id}">

      <!-- Header row -->
      <div class="msg-header">
        <div class="msg-from">
          <span style="width:28px;height:28px;background:var(--success);border-radius:50%;
            display:inline-flex;align-items:center;justify-content:center;
            color:#fff;font-size:.8rem;font-weight:700;flex-shrink:0;">
            ${escHtml((msg.recipientUsername || '?')[0].toUpperCase())}
          </span>
          To: &nbsp;<strong>${escHtml(msg.recipientUsername)}</strong>
        </div>
        <div style="display:flex;align-items:center;gap:.5rem;flex-wrap:wrap;">
          ${msg.status === 'READ'
            ? `<span class="chip chip-read">✓ Read</span>`
            : `<span class="chip chip-sent">Delivered</span>`}
          <span class="msg-time">${formatDateTime(msg.sentAt)}</span>
        </div>
      </div>

      <!-- Encrypted label -->
      <div style="margin-bottom:.5rem;">
        <span class="msg-encrypted-label">🔒 RSA-2048 Encrypted</span>
      </div>

      <!-- Ciphertext preview -->
      <div class="decrypt-row">
        <div class="decrypt-label">Encrypted Content (stored in database)</div>
        <div class="decrypt-value cipher">${escHtml(truncateCipher(msg.encryptedContent, 80))}</div>
      </div>

      <!-- Asymmetric encryption note -->
      <div style="
        background:var(--warning-bg);
        border:1px solid #fde68a;
        border-radius:var(--radius-sm);
        padding:.5rem .75rem;
        margin-top:.6rem;
        font-size:.78rem;
        color:var(--warning);
        display:flex;gap:.4rem;align-items:flex-start;
      ">
        <span>⚠️</span>
        <span>
          <strong>Cannot decrypt</strong> — this message was encrypted with
          <strong>${escHtml(msg.recipientUsername)}'s public key</strong>.
          Only they can decrypt it with their private key.
          This is RSA asymmetric encryption.
        </span>
      </div>

      <!-- Metadata footer -->
      <div style="margin-top:.75rem;display:flex;gap:1rem;flex-wrap:wrap;font-size:.75rem;color:var(--gray-400);">
        <span>Message ID: ${msg.id}</span>
        <span>•</span>
        <span>Recipient ID: ${msg.recipientId}</span>
        <span>•</span>
        <span class="algo-tag" style="font-size:.7rem;">🔒 RSA-2048 / OAEP</span>
      </div>

    </div>`;
}
