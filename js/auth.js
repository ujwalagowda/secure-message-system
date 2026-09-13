/**
 * auth.js — Registration and Login page logic
 *
 * Handles:
 *   - Login form submission  → POST /api/auth/login
 *   - Register form submission → POST /api/auth/register
 *   - Redirect to dashboard on success
 *   - Redirect to login if already on auth page while logged in
 *
 * Depends on: api.js (must be loaded before this file)
 */

// ─────────────────────────────────────────────────────────────
// Redirect already-authenticated users away from auth pages
// ─────────────────────────────────────────────────────────────
(function guardAuthPages() {
    if (isLoggedIn()) {
        redirectTo('dashboard.html');
    }
})();

// ─────────────────────────────────────────────────────────────
// LOGIN
// ─────────────────────────────────────────────────────────────

const loginForm = document.getElementById('loginForm');
if (loginForm) {
    loginForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        hideAlert('loginAlert');

        const usernameOrEmail = document.getElementById('usernameOrEmail').value.trim();
        const password        = document.getElementById('password').value;
        const submitBtn       = loginForm.querySelector('button[type="submit"]');

        if (!usernameOrEmail || !password) {
            showAlert('loginAlert', 'Please enter your username/email and password.', 'warning');
            return;
        }

        submitBtn.disabled = true;
        submitBtn.textContent = 'Signing in…';

        try {
            const data = await apiLogin(usernameOrEmail, password);
            saveSession(data);
            redirectTo('dashboard.html');
        } catch (err) {
            showAlert('loginAlert', err.message || 'Login failed. Please check your credentials.');
            submitBtn.disabled = false;
            submitBtn.textContent = 'Sign In';
        }
    });
}

// ─────────────────────────────────────────────────────────────
// REGISTER
// ─────────────────────────────────────────────────────────────

const registerForm = document.getElementById('registerForm');
if (registerForm) {
    registerForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        hideAlert('registerAlert');

        const username  = document.getElementById('username').value.trim();
        const email     = document.getElementById('email').value.trim();
        const password  = document.getElementById('password').value;
        const confirm   = document.getElementById('confirmPassword').value;
        const submitBtn = registerForm.querySelector('button[type="submit"]');

        // Client-side validation
        if (!username || !email || !password) {
            showAlert('registerAlert', 'All fields are required.', 'warning');
            return;
        }
        if (username.length < 3) {
            showAlert('registerAlert', 'Username must be at least 3 characters.', 'warning');
            return;
        }
        if (password.length < 6) {
            showAlert('registerAlert', 'Password must be at least 6 characters.', 'warning');
            return;
        }
        if (password !== confirm) {
            showAlert('registerAlert', 'Passwords do not match.', 'warning');
            return;
        }

        submitBtn.disabled = true;
        submitBtn.textContent = 'Creating account…';

        try {
            const data = await apiRegister(username, email, password);
            saveSession(data);
            // Show brief success before redirect
            showAlert('registerAlert',
                'Account created! RSA-2048 key pair generated. Redirecting…', 'success');
            setTimeout(() => redirectTo('dashboard.html'), 1200);
        } catch (err) {
            // Show field-level errors if backend returned them
            let msg = err.message || 'Registration failed.';
            if (err.errors) {
                const fieldMsgs = Object.values(err.errors).join(' • ');
                msg = fieldMsgs || msg;
            }
            showAlert('registerAlert', msg);
            submitBtn.disabled = false;
            submitBtn.textContent = 'Create Account';
        }
    });
}
