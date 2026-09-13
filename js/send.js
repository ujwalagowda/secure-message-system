/**
 * send.js — Send Message page logic
 *
 * Loads registered users via GET /api/users.
 * Submits an encrypted message via POST /api/messages/send.
 *
 * Encryption flow (server-side):
 *   1. User selects a recipient and types a plaintext message.
 *   2. Frontend sends { recipientId, content } to the backend.
 *   3. Backend fetches recipient's RSA-2048 public key from DB.
 *   4. Backend encrypts content → Base64 ciphertext (RSA/OAEP).
 *   5. Only ciphertext is stored. Plaintext is discarded.
 *   6. Backend returns MessageDTO with encryptedContent.
 *
 * The frontend NEVER handles RSA keys or encryption.
 * All cryptographic operations happen on the server.
 */

if (!requireAuth()) { /* stops here */ }

const MAX_CHARS = 190; // RSA-2048 OAEP/SHA-256 limit

document.addEventListener('DOMContentLoaded', async () => {
    initSidebar();
    await loadRecipients();
    setupCharCounter();
    setupForm();
    refreshUnreadBadge();

    document.getElementById('clearBtn')?.addEventListener('click', resetForm);
    document.getElementById('sendAnotherBtn')?.addEventListener('click', resetForm);
});

// ─────────────────────────────────────────────────────────────
// Load recipient list from GET /api/users
// ─────────────────────────────────────────────────────────────
async function loadRecipients() {
    const select = document.getElementById('recipientSelect');
    const info   = document.getElementById('recipientInfo');

    try {
        const users = await apiGetUsers();
        const currentUserId = localStorage.getItem('userId');

        // Filter out the logged-in user (can't message yourself)
        const others = users.filter(u => String(u.id) !== String(currentUserId));

        if (others.length === 0) {
            select.innerHTML = '<option value="">No other users registered yet</option>';
            select.disabled  = true;
            if (info) info.textContent = 'Register another user to send messages.';
            return;
        }

        select.innerHTML = '<option value="">— Select a recipient —</option>' +
            others.map(u => `<option value="${u.id}">${escHtml(u.username)} (${escHtml(u.email)})</option>`).join('');

        select.addEventListener('change', () => {
            const chosen = others.find(u => String(u.id) === select.value);
            if (info) {
                info.textContent = chosen
                    ? `✓ Message will be encrypted with ${chosen.username}'s RSA-2048 public key.`
                    : '';
            }
        });

    } catch (err) {
        select.innerHTML = '<option value="">Failed to load users</option>';
        showAlert('sendAlert', `Could not load users: ${err.message}`, 'warning');
    }
}

// ─────────────────────────────────────────────────────────────
// Character counter
// ─────────────────────────────────────────────────────────────
function setupCharCounter() {
    const textarea = document.getElementById('messageContent');
    const counter  = document.getElementById('charCount');
    if (!textarea || !counter) return;

    textarea.addEventListener('input', () => {
        const len = textarea.value.length;
        counter.textContent = len;

        const wrap = counter.closest('.char-counter');
        if (!wrap) return;
        wrap.classList.remove('warn', 'error');
        if (len > MAX_CHARS * 0.9) wrap.classList.add('warn');
        if (len >= MAX_CHARS)      wrap.classList.add('error');
    });
}

// ─────────────────────────────────────────────────────────────
// Form submit
// ─────────────────────────────────────────────────────────────
function setupForm() {
    const form    = document.getElementById('sendForm');
    const sendBtn = document.getElementById('sendBtn');
    if (!form) return;

    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        hideAlert('sendAlert');

        const recipientId = document.getElementById('recipientSelect').value;
        const content     = document.getElementById('messageContent').value.trim();

        // Client-side validation
        if (!recipientId) {
            showAlert('sendAlert', 'Please select a recipient.', 'warning');
            return;
        }
        if (!content) {
            showAlert('sendAlert', 'Message cannot be empty.', 'warning');
            return;
        }
        if (content.length > MAX_CHARS) {
            showAlert('sendAlert',
                `Message is too long. RSA-2048 OAEP limit is ${MAX_CHARS} characters. ` +
                `You entered ${content.length}.`, 'warning');
            return;
        }

        sendBtn.disabled    = true;
        sendBtn.textContent = '⏳ Encrypting & Sending…';

        try {
            // POST /api/messages/send — backend does RSA encryption
            const result = await apiSendMessage(Number(recipientId), content);

            // Show success panel
            showResultPanel(result);

        } catch (err) {
            let msg = err.message || 'Failed to send message.';
            if (err.errors) {
                msg = Object.values(err.errors).join(' • ') || msg;
            }
            showAlert('sendAlert', msg);
        } finally {
            sendBtn.disabled    = false;
            sendBtn.textContent = '🔒 Encrypt & Send';
        }
    });
}

// ─────────────────────────────────────────────────────────────
// Show result panel after successful send
// ─────────────────────────────────────────────────────────────
function showResultPanel(result) {
    const panel = document.getElementById('resultPanel');
    if (!panel) return;

    // Populate result fields
    const set = (id, val) => {
        const el = document.getElementById(id);
        if (el) el.textContent = val;
    };

    set('resultRecipient', result.recipientUsername || `User ${result.recipientId}`);
    set('resultTime',      formatDateTime(result.sentAt));
    set('resultCipher',    result.encryptedContent || '—');

    // Show panel, scroll to it
    panel.classList.remove('hidden');
    panel.scrollIntoView({ behavior: 'smooth', block: 'start' });

    // Scroll page slightly down so form is visible too
    showAlert('sendAlert',
        '✓ Message encrypted with RSA-2048 and sent successfully!', 'success');
}

// ─────────────────────────────────────────────────────────────
// Reset form for sending another message
// ─────────────────────────────────────────────────────────────
function resetForm() {
    const form    = document.getElementById('sendForm');
    const panel   = document.getElementById('resultPanel');
    const counter = document.getElementById('charCount');

    if (form)    form.reset();
    if (panel)   panel.classList.add('hidden');
    if (counter) counter.textContent = '0';

    const wrap = counter?.closest('.char-counter');
    if (wrap) wrap.classList.remove('warn', 'error');

    hideAlert('sendAlert');

    // Reset recipient info label
    const info = document.getElementById('recipientInfo');
    if (info) info.textContent = '';

    window.scrollTo({ top: 0, behavior: 'smooth' });
}
