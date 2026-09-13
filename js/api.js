/**
 * api.js — Centralized API layer
 *
 * All communication with the Spring Boot backend goes through
 * this file. No other JS file calls fetch() directly.
 *
 * Backend base URL: http://localhost:8085
 * All authenticated requests send:  Authorization: Bearer <token>
 *
 * localStorage keys used (read-only here — written by auth.js):
 *   token    — JWT bearer token
 *   userId   — logged-in user's database ID
 *   username — logged-in user's username
 *   email    — logged-in user's email
 *   role     — USER or ADMIN
 */

const API_BASE = 'http://localhost:8085';

// ─────────────────────────────────────────────────────────────
// Token helpers
// ─────────────────────────────────────────────────────────────

/** Returns the stored JWT token, or null if not logged in. */
function getToken() {
    return localStorage.getItem('token');
}

/** Returns true if a JWT token is present in localStorage. */
function isLoggedIn() {
    return !!getToken();
}

/**
 * Returns the Authorization header object for authenticated requests.
 * Always reads fresh from localStorage so token changes are picked up.
 */
function authHeader() {
    const token = getToken();
    return token ? { 'Authorization': `Bearer ${token}` } : {};
}

/** Returns the stored user object built from localStorage. */
function getCurrentUser() {
    return {
        userId:   localStorage.getItem('userId'),
        username: localStorage.getItem('username'),
        email:    localStorage.getItem('email'),
        role:     localStorage.getItem('role'),
    };
}

// ─────────────────────────────────────────────────────────────
// Core fetch wrapper
// ─────────────────────────────────────────────────────────────

/**
 * Makes an HTTP request to the backend.
 *
 * @param {string} path       API path, e.g. '/api/auth/login'
 * @param {string} method     HTTP method: 'GET'|'POST'|'PUT'|'DELETE'
 * @param {object} [body]     Request body object (will be JSON-serialized)
 * @param {boolean} [auth]    Whether to attach Authorization header (default true)
 * @returns {Promise<object>} Parsed JSON response body
 * @throws  {ApiError}        On non-2xx response or network failure
 */
async function request(path, method = 'GET', body = null, auth = true) {
    const headers = { 'Content-Type': 'application/json' };
    if (auth) Object.assign(headers, authHeader());

    const options = { method, headers };
    if (body) options.body = JSON.stringify(body);

    let response;
    try {
        response = await fetch(`${API_BASE}${path}`, options);
    } catch (networkErr) {
        throw new ApiError(0, 'Cannot reach the server. Make sure the backend is running on port 8085.');
    }

    // 401 → token expired or invalid → redirect to login
    if (response.status === 401) {
        clearSession();
        redirectTo('login.html');
        throw new ApiError(401, 'Session expired. Please log in again.');
    }

    // 403 → forbidden — let caller handle
    let data;
    try {
        data = await response.json();
    } catch {
        data = { message: response.statusText };
    }

    if (!response.ok) {
        // Backend returns { message, errors } on validation failures
        const msg = data.message || data.error || `Request failed (${response.status})`;
        throw new ApiError(response.status, msg, data.errors);
    }

    return data;
}

/** Convenience wrappers */
const api = {
    get:    (path, auth = true)         => request(path, 'GET',    null, auth),
    post:   (path, body, auth = true)   => request(path, 'POST',   body, auth),
    put:    (path, body, auth = true)   => request(path, 'PUT',    body, auth),
    delete: (path, auth = true)         => request(path, 'DELETE', null, auth),
};

// ─────────────────────────────────────────────────────────────
// ApiError class
// ─────────────────────────────────────────────────────────────

class ApiError extends Error {
    /**
     * @param {number} status   HTTP status code (0 = network error)
     * @param {string} message  Human-readable message
     * @param {object} [errors] Field-level validation errors map
     */
    constructor(status, message, errors = null) {
        super(message);
        this.status = status;
        this.errors = errors;
        this.name   = 'ApiError';
    }
}

// ─────────────────────────────────────────────────────────────
// Auth API calls
// ─────────────────────────────────────────────────────────────

/** POST /api/auth/register */
async function apiRegister(username, email, password) {
    return api.post('/api/auth/register', { username, email, password }, false);
}

/** POST /api/auth/login  (accepts username OR email in the first field) */
async function apiLogin(usernameOrEmail, password) {
    return api.post('/api/auth/login', { usernameOrEmail, password }, false);
}

// ─────────────────────────────────────────────────────────────
// User API calls
// ─────────────────────────────────────────────────────────────

/** GET /api/users — list all users (id, username, email, publicKey) */
async function apiGetUsers() {
    return api.get('/api/users');
}

// ─────────────────────────────────────────────────────────────
// Message API calls
// ─────────────────────────────────────────────────────────────

/**
 * POST /api/messages/send
 * Sends an RSA-encrypted message to a recipient.
 * The backend encrypts the content — never do it on the frontend.
 *
 * @param {number} recipientId  Recipient's user ID
 * @param {string} content      Plaintext (max 190 chars — enforced by backend)
 */
async function apiSendMessage(recipientId, content) {
    return api.post('/api/messages/send', { recipientId, content });
}

/** GET /api/messages/inbox — received messages (ciphertext) */
async function apiGetInbox() {
    return api.get('/api/messages/inbox');
}

/** GET /api/messages/sent — sent messages */
async function apiGetSent() {
    return api.get('/api/messages/sent');
}

/**
 * GET /api/messages/{id}/decrypt
 * Decrypts a message server-side using the recipient's private key.
 * Only works if the caller is the message recipient.
 * Returns DecryptedMessageDTO containing decryptedContent.
 *
 * SECURITY: The private key is never sent to the frontend.
 * Decryption is fully server-side.
 */
async function apiDecryptMessage(messageId) {
    return api.get(`/api/messages/${messageId}/decrypt`);
}

/** GET /api/messages/unread-count */
async function apiGetUnreadCount() {
    return api.get('/api/messages/unread-count');
}

// ─────────────────────────────────────────────────────────────
// Session helpers
// ─────────────────────────────────────────────────────────────

/**
 * Persists auth response data to localStorage after login/register.
 * Only stores safe, non-sensitive fields.
 * Private RSA key is NEVER stored here.
 *
 * @param {object} data  AuthResponse from backend
 */
function saveSession(data) {
    localStorage.setItem('token',    data.token);
    localStorage.setItem('userId',   data.userId);
    localStorage.setItem('username', data.username);
    localStorage.setItem('email',    data.email);
    localStorage.setItem('role',     data.role);
}

/** Removes all session data from localStorage. */
function clearSession() {
    ['token', 'userId', 'username', 'email', 'role'].forEach(k =>
        localStorage.removeItem(k)
    );
}

// ─────────────────────────────────────────────────────────────
// Navigation helpers
// ─────────────────────────────────────────────────────────────

/**
 * Redirects to a page within the frontend folder.
 * Uses window.location.href for a hard navigation.
 */
function redirectTo(page) {
    window.location.href = page;
}

/**
 * Guards a protected page. Call at the top of every page JS except
 * login and register. Redirects to login.html if no token is present.
 */
function requireAuth() {
    if (!isLoggedIn()) {
        redirectTo('login.html');
        return false;
    }
    return true;
}

// ─────────────────────────────────────────────────────────────
// UI helpers — shared across pages
// ─────────────────────────────────────────────────────────────

/**
 * Shows an alert box.
 * @param {string} elementId  ID of the alert div
 * @param {string} message    Text to display
 * @param {'success'|'danger'|'warning'|'info'} type
 */
function showAlert(elementId, message, type = 'danger') {
    const el = document.getElementById(elementId);
    if (!el) return;
    el.className = `alert alert-${type}`;
    el.innerHTML = `<span class="alert-icon">${alertIcon(type)}</span><span>${message}</span>`;
    el.classList.remove('hidden');
    el.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function hideAlert(elementId) {
    const el = document.getElementById(elementId);
    if (el) el.classList.add('hidden');
}

function alertIcon(type) {
    return { success: '✓', danger: '✕', warning: '⚠', info: 'ℹ' }[type] || 'ℹ';
}

/** Shows / hides the full-page loading overlay. */
function setLoading(visible) {
    const el = document.getElementById('loadingOverlay');
    if (!el) return;
    visible ? el.classList.remove('hidden') : el.classList.add('hidden');
}

/** Shows a spinner inside a container; hides it when done. */
function showSpinner(containerId) {
    const el = document.getElementById(containerId);
    if (el) el.innerHTML = `<div class="spinner-wrap"><div class="spinner"></div></div>`;
}

/**
 * Formats a LocalDateTime string (ISO 8601) into a readable date/time.
 * e.g. "2026-09-11T14:30:00" → "Sep 11, 2026 • 14:30"
 */
function formatDateTime(isoString) {
    if (!isoString) return '—';
    const d = new Date(isoString);
    return d.toLocaleString('en-IN', {
        day: '2-digit', month: 'short', year: 'numeric',
        hour: '2-digit', minute: '2-digit', hour12: false
    });
}

/**
 * Truncates a long string (e.g. Base64 ciphertext) for display.
 * Shows first 40 chars + "…"
 */
function truncateCipher(text, len = 40) {
    if (!text) return '';
    return text.length > len ? text.substring(0, len) + '…' : text;
}

/** Escapes HTML to safely insert user-provided text into the DOM. */
function escHtml(str) {
    if (str == null) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}

// ─────────────────────────────────────────────────────────────
// Sidebar helpers — used by all app pages
// ─────────────────────────────────────────────────────────────

/** Populates sidebar user info from localStorage. */
function initSidebar() {
    const user = getCurrentUser();

    // Avatar letter
    document.querySelectorAll('.user-avatar').forEach(el => {
        el.textContent = (user.username || '?')[0].toUpperCase();
    });
    document.querySelectorAll('.user-name').forEach(el => {
        el.textContent = user.username || '';
    });
    document.querySelectorAll('.user-role').forEach(el => {
        el.textContent = user.role || 'USER';
    });

    // Logout buttons
    document.querySelectorAll('.btn-logout').forEach(btn => {
        btn.addEventListener('click', () => {
            clearSession();
            redirectTo('login.html');
        });
    });

    // Mobile hamburger
    const hamburger = document.getElementById('hamburger');
    const sidebar   = document.getElementById('sidebar');
    const overlay   = document.getElementById('sidebarOverlay');

    if (hamburger && sidebar) {
        hamburger.addEventListener('click', () => {
            sidebar.classList.toggle('open');
            if (overlay) overlay.classList.toggle('visible');
        });
    }
    if (overlay && sidebar) {
        overlay.addEventListener('click', () => {
            sidebar.classList.remove('open');
            overlay.classList.remove('visible');
        });
    }
}

/** Updates the unread badge in the sidebar. */
async function refreshUnreadBadge() {
    try {
        const data = await apiGetUnreadCount();
        const count = data.unreadCount || 0;
        document.querySelectorAll('#unreadBadge').forEach(el => {
            if (count > 0) {
                el.textContent = count > 99 ? '99+' : count;
                el.classList.remove('hidden');
            } else {
                el.classList.add('hidden');
            }
        });
    } catch { /* sidebar badge is non-critical — ignore errors */ }
}
