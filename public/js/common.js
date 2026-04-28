/* 
  SecureAuth — Common utilities 
  Developed by MasterT
*/

const API_BASE = '/api';
let csrfToken = null;

// Get CSRF token
async function getCsrfToken() {
  if (csrfToken) return csrfToken;
  try {
    const response = await fetch(`${API_BASE}/csrf-token`);
    const data = await response.json();
    csrfToken = data.csrfToken;
    return csrfToken;
  } catch (error) {
    return null;
  }
}

// API request wrapper with CSRF protection
async function apiRequest(endpoint, options = {}) {
  const url = `${API_BASE}${endpoint}`;
  const method = options.method || 'GET';
  
  const headers = {
    'Content-Type': 'application/json',
    ...options.headers
  };

  if (!['GET', 'HEAD', 'OPTIONS'].includes(method.toUpperCase())) {
    const token = await getCsrfToken();
    if (token) headers['x-csrf-token'] = token;
  }

  const config = { ...options, method, headers, credentials: 'same-origin' };

  try {
    const response = await fetch(url, config);
    const data = await response.json();
    
    // Retry once if CSRF fails
    if (response.status === 403 && data.code === 'CSRF_ERROR' && !options._isRetry) {
      csrfToken = null;
      if (await getCsrfToken()) return apiRequest(endpoint, { ...options, _isRetry: true });
    }
    
    return { ok: response.ok, status: response.status, data };
  } catch (error) {
    return { ok: false, status: 0, data: { message: 'Network error.' } };
  }
}

// Show/Hide alert
function showAlert(elementId, message, type = 'error') {
  const el = document.getElementById(elementId);
  if (!el) return;
  el.className = `alert alert-${type} show`;
  el.innerHTML = `<span>${escapeHtml(message)}</span>`;
}

function showLinkAlert(elementId, message, href, linkLabel, type = 'info') {
  const el = document.getElementById(elementId);
  if (!el) return;

  el.className = `alert alert-${type} show`;
  el.innerHTML = '';

  const text = document.createElement('span');
  text.textContent = `${message} `;

  const link = document.createElement('a');
  link.href = href;
  link.textContent = linkLabel;

  el.append(text, link);
}

function hideAlert(elementId) {
  const el = document.getElementById(elementId);
  if (el) el.classList.remove('show');
}

// Button loading state
function setLoading(btn, loading) {
  if (!btn) return;
  btn.classList.toggle('loading', loading);
  btn.disabled = loading;
}

// Prevent XSS
function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

// Password visibility toggle
function togglePassword(inputId, btn) {
  const input = document.getElementById(inputId);
  if (!input) return;
  const isPw = input.type === 'password';
  input.type = isPw ? 'text' : 'password';
  btn.textContent = isPw ? 'Hide' : 'Show';
}

document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('.pw-toggle').forEach(btn => {
    btn.addEventListener('click', (e) => {
      const input = e.currentTarget.parentElement.querySelector('input');
      if (input) togglePassword(input.id, e.currentTarget);
    });
  });
});

// Password strength calculation
function getPasswordStrength(pw) {
  let score = 0;
  if (pw.length >= 8) score++;
  if (pw.length >= 12) score++;
  if (/[A-Z]/.test(pw) && /[a-z]/.test(pw)) score++;
  if (/[0-9]/.test(pw) && /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(pw)) score++;
  return Math.min(score, 4);
}

// Update strength meter UI
function updateStrengthMeter(password) {
  const strength = getPasswordStrength(password);
  const labels = ['', 'Weak', 'Fair', 'Good', 'Strong'];
  const bars = document.querySelectorAll('.pw-strength .bar');
  const text = document.querySelector('.pw-strength-text');

  bars.forEach((bar, i) => {
    bar.className = 'bar';
    if (i < strength) bar.classList.add(`active-${strength}`);
  });

  if (text) {
    text.textContent = password ? labels[strength] : '';
    text.className = 'pw-strength-text';
    if (password && strength > 0) text.classList.add(`strength-${strength}`);
  }
}

// Auth checks
async function checkAuth() {
  const result = await apiRequest('/user/me');
  return result.ok ? result.data.user : null;
}

async function requireAuth() {
  const user = await checkAuth();
  if (!user) window.location.href = '/index.html';
  return user;
}

async function requireGuest() {
  if (await checkAuth()) window.location.href = '/dashboard.html';
}
