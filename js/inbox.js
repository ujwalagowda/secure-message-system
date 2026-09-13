/**
 * inbox.js — Inbox page logic
 *
 * Loads received messages via GET /api/messages/inbox.
 * Shows RSA ciphertext for each message.
 * Allows the authenticated recipient to decrypt a message via
 * GET /api/messages/{id}/decrypt — decryption is server-side only.
 *
 * Security rules enforced here:
 *   - Private RSA key is never sent to or stored on the frontend.
 *   - Decrypted content is shown only after the backend confirms
 *     the requesting user is the recipient.
 *   - Ciphertext is never treated as readable text; it is always
 *     labelled as "RSA-2048 Encrypted".
 */

if (!requireAuth()) { /* stops here */ }

// Track which messages have been decrypted this session
const decryptedCache = {};

document.addEventListener('DOMContentLoaded', async () => {
    initSidebar();
    await loadInbox();
    refreshUnreadBadge();

    document.getElementById('refreshBtn')?.addEventListener('click', async () => {
        document.getElementById('messageList').innerHTML =
            '<div class="spinner-wrap"><div class="spinner"></div></div>';
        await loadInbox();
        refreshUnreadBadge();
    });
});

// ─────────────────────────────────────────────────────────────
// Load inbox
// ─────────────────────────────────────────────────────────────
async function loadInbox() {
    const container = document.getElementById('messageList');
    hideAlert('alertBox');

    try {
        const messages = await apiGetInbox();

        if (!messages || messages.length === 0) {
            container.innerHTML = `
              <div class="empty-state">
                <div class="empty-icon">📭</div>
                <p>Your inbox is empty.</p>
                <a href="send.html" class="btn btn-primary btn-sm" style="margin-top:.75rem;">
                  Send a Message
                </a>
              </div>`;
            return;
        }

        container.innerHTML = `<div class="message-list">${
            messages.map(m => buildMessageCard(m)).join('')
        }</div>`;

        // Attach decrypt button handlers
        container.querySelectorAll('.decrypt-btn').forEach(btn => {
            btn.addEventListener('click', () => handleDecrypt(btn));
        });

    } catch (err) {
        showAlert('alertBox', err.message || 'Failed to load inbox.');
        container.innerHTML = '';
    }
}

// ─────────────────────────────────────────────────────────────
// Build message card
// ─────────────────────────────────────────────────────────────
function buildMessageCard(msg) {
    const isUnread = msg.status === 'SENT';
    const cached   = decryptedCache[msg.id];

    return `
    <div class="message-card ${isUnread ? 'unread' : ''}" id="card-${msg.id}">

      <!-- Header row -->
      <div class="msg-header">
        <div class="msg-from">
          <span style="width:28px;height:28px;background:var(--primary);border-radius:50%;
            display:inline-flex;align-items:center;justify-content:center;
            color:#fff;font-size:.8rem;font-weight:700;flex-shrink:0;">
            ${escHtml((msg.senderUsername || '?')[0].toUpperCase())}
          </span>
          ${escHtml(msg.senderUsername)}
        </div>
        <div style="display:flex;align-items:center;gap:.5rem;flex-wrap:wrap;">
          ${isUnread
            ? `<span class="chip chip-sent">Unread</span>`
            : `<span class="chip chip-read">Read</span>`}
          <span class="msg-time">${formatDateTime(msg.sentAt)}</span>
        </div>
      </div>

      <!-- Encrypted label -->
      <div style="margin-bottom:.5rem;">
        <span class="msg-encrypted-label ${cached ? 'decrypted' : ''}">
          ${cached ? '🔓 Decrypted' : '🔒 RSA-2048 Encrypted'}
        </span>
      </div>

      <!-- Ciphertext preview (always shown) -->
      <div class="decrypt-row">
        <div class="decrypt-label">Encrypted Content (stored in database)</div>
        <div class="decrypt-value cipher">${escHtml(truncateCipher(msg.encryptedContent, 80))}</div>
      </div>

      <!-- Decrypted panel (hidden until decrypted) -->
      <div class="decrypt-panel ${cached ? 'visible' : 'hidden'}" id="panel-${msg.id}">
        <div class="decrypt-row">
          <div class="decrypt-label">Decrypted Message</div>
          <div class="decrypt-value plain" id="plaintext-${msg.id}">
            ${cached ? escHtml(cached.decryptedContent) : ''}
          </div>
        </div>
        <div class="decrypt-row" style="margin-bottom:0;">
          <div class="decrypt-label">Algorithm</div>
          <div><span class="algo-tag">🔒 ${cached ? escHtml(cached.algorithm) : 'RSA-2048 / OAEP with SHA-256'}</span></div>
        </div>
      </div>

      <!-- Actions -->
      <div class="msg-actions">
        ${!cached ? `
          <button class="btn btn-primary btn-sm decrypt-btn"
            data-id="${msg.id}"
            data-btn-id="dbtn-${msg.id}">
            🔓 Decrypt Message
          </button>` : `
          <button class="btn btn-secondary btn-sm" disabled>✓ Decrypted</button>`
        }
        <span style="font-size:.75rem;color:var(--gray-400);align-self:center;">
          Message ID: ${msg.id}
        </span>
      </div>

    </div>`;
}

// ─────────────────────────────────────────────────────────────
// Decrypt handler
// ─────────────────────────────────────────────────────────────
async function handleDecrypt(btn) {
    const messageId = btn.dataset.id;
    btn.disabled = true;
    btn.textContent = '⏳ Decrypting…';

    try {
        // Server-side RSA decryption using recipient's private key.
        // The private key never leaves the server.
        const result = await apiDecryptMessage(messageId);

        // Cache result so page re-renders don't lose it
        decryptedCache[messageId] = result;

        // Update the card in-place
        const panel     = document.getElementById(`panel-${messageId}`);
        const plaintext = document.getElementById(`plaintext-${messageId}`);
        const card      = document.getElementById(`card-${messageId}`);

        if (plaintext) plaintext.textContent = result.decryptedContent;
        if (panel)     panel.classList.replace('hidden', 'visible');
        if (card)      card.classList.remove('unread');

        // Swap the decrypt button for a "Decrypted" indicator
        btn.outerHTML = `<button class="btn btn-secondary btn-sm" disabled>✓ Decrypted</button>`;

        // Update the encrypted label on the card
        const label = document.querySelector(`#card-${messageId} .msg-encrypted-label`);
        if (label) {
            label.classList.add('decrypted');
            label.textContent = '🔓 Decrypted';
        }

        // Refresh the unread badge count
        refreshUnreadBadge();

    } catch (err) {
        btn.disabled = false;
        btn.textContent = '🔓 Decrypt Message';
        showAlert('alertBox',
            `Decryption failed: ${err.message || 'Unknown error'}`);
    }
}
