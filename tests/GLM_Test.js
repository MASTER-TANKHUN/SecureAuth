/*
  GLM_Test — Extended security & edge-case test suite
  Developed by MasterT
*/
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const Database = require('better-sqlite3');
const { authenticator } = require('otplib');

const PORT = 3000;
const BASE_URL = `http://127.0.0.1:${PORT}`;
const ROOT = path.join(__dirname, '..');
const DB_PATH = path.join(ROOT, 'auth.db');
const SECURITY_LOG = path.join(ROOT, 'security.log');
const ENCRYPTION_KEY = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

// Set env vars BEFORE requiring any server modules
process.env.JWT_SECRET = process.env.JWT_SECRET || 'glm-test-jwt-secret-glm-test-jwt-secret-glm-test';
process.env.ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || ENCRYPTION_KEY;
process.env.CSRF_SECRET = process.env.CSRF_SECRET || 'glm-test-csrf-secret-glm-test-csrf-secret';

// High rate limits for testing (defaults are too low for 17 test sections from same IP)
process.env.RATE_LIMIT_LOGIN = '500';
process.env.RATE_LIMIT_REGISTER = '500';
process.env.RATE_LIMIT_API = '1000';
process.env.RATE_LIMIT_MFA = '500';
process.env.RATE_LIMIT_REFRESH = '500';
process.env.RATE_LIMIT_VERIFY_EMAIL = '500';
process.env.RATE_LIMIT_FORGOT_PASSWORD = '500';
process.env.RATE_LIMIT_EMAIL = '500';
process.env.RATE_LIMIT_SENSITIVE = '500';

const { decrypt } = require('../server/utils/crypto');

// ============================================
// Session helper
// ============================================
class Session {
  constructor() { this.cookies = new Map(); this.csrfToken = null; }
  clone() {
    const c = new Session();
    c.cookies = new Map(this.cookies); c.csrfToken = this.csrfToken;
    return c;
  }
  cookieHeader() {
    return Array.from(this.cookies.entries()).map(([k, v]) => `${k}=${v}`).join('; ');
  }
  updateCookies(response) {
    const setCookie = response.headers.getSetCookie ? response.headers.getSetCookie() : [];
    for (const header of setCookie) {
      const [cookiePart] = header.split(';');
      const idx = cookiePart.indexOf('=');
      this.cookies.set(cookiePart.slice(0, idx), cookiePart.slice(idx + 1));
    }
  }
  async ensureCsrfToken() {
    if (this.csrfToken) return this.csrfToken;
    const r = await fetch(`${BASE_URL}/api/csrf-token`, {
      headers: this.cookieHeader() ? { cookie: this.cookieHeader() } : {},
    });
    this.updateCookies(r);
    const d = await r.json();
    assert.equal(r.status, 200, 'CSRF endpoint should succeed');
    assert.ok(d.csrfToken, 'Expected csrfToken');
    this.csrfToken = d.csrfToken;
    return this.csrfToken;
  }
  async request(endpoint, options = {}) {
    const method = (options.method || 'GET').toUpperCase();
    const headers = { ...(options.headers || {}) };
    const cookie = this.cookieHeader();
    if (cookie) headers.cookie = cookie;
    if (!['GET', 'HEAD', 'OPTIONS'].includes(method)) {
      headers['content-type'] = 'application/json';
      headers['x-csrf-token'] = await this.ensureCsrfToken();
    }
    const response = await fetch(`${BASE_URL}${endpoint}`, {
      method, headers,
      body: options.body ? JSON.stringify(options.body) : undefined,
      redirect: 'manual',
    });
    this.updateCookies(response);
    let data = null;
    const text = await response.text();
    if (text) { try { data = JSON.parse(text); } catch { data = { raw: text }; } }
    return { status: response.status, ok: response.ok, data, headers: response.headers };
  }
}

// ============================================
// Utilities
// ============================================
function cleanupArtifacts() {
  for (const f of [DB_PATH, `${DB_PATH}-wal`, `${DB_PATH}-shm`, SECURITY_LOG]) {
    try { fs.rmSync(f, { force: true }); } catch {}
  }
}
function wait(ms) { return new Promise(r => setTimeout(r, ms)); }

const http = require('http');
async function waitForServer() {
  for (let i = 0; i < 80; i++) {
    try {
      await new Promise((resolve, reject) => {
        const req = http.get(`${BASE_URL}/health`, res => {
          res.statusCode === 200 ? resolve() : reject(new Error('Status ' + res.statusCode));
        });
        req.on('error', reject); req.end();
      });
      return;
    } catch { if (i === 0) console.log('⏳ Waiting for server...'); await wait(250); }
  }
  throw new Error('Server did not become ready');
}

function getUserRecordByEmail(email) {
  const db = new Database(DB_PATH, { readonly: true });
  try { return db.prepare('SELECT * FROM users WHERE email = ?').get(email); }
  finally { db.close(); }
}

function generateCurrentTotp(email) {
  const user = getUserRecordByEmail(email);
  assert.ok(user, 'Expected user in DB');
  const secret = decrypt(user.mfa_secret);
  assert.ok(secret, 'Expected MFA secret to decrypt');
  return authenticator.generate(secret);
}

function getCount(sql, params = []) {
  const db = new Database(DB_PATH, { readonly: true });
  try { return db.prepare(sql).get(...params); }
  finally { db.close(); }
}

function clearTotpReplay(email) {
  const db = new Database(DB_PATH);
  db.prepare('UPDATE users SET last_totp_code = NULL, last_totp_timestamp = NULL WHERE email = ?').run(email);
  db.close();
}

function resetLockout(email) {
  const db = new Database(DB_PATH);
  db.prepare('UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE email = ?').run(email);
  db.close();
}

// Helper: register + verify + login a fresh user, return authenticated session
async function createVerifiedUser(email, username, password) {
  const s = new Session();
  await s.ensureCsrfToken();
  const reg = await s.request('/api/auth/register', {
    method: 'POST', body: { email, username, password },
  });
  if (reg.data.devToken) {
    await s.request('/api/auth/verify-email', {
      method: 'POST', body: { token: reg.data.devToken },
    });
  } else {
    const db = new Database(DB_PATH);
    db.prepare('UPDATE users SET is_verified = 1 WHERE email = ?').run(email);
    db.close();
  }
  // Fresh login session
  const login = new Session();
  await login.ensureCsrfToken();
  const lr = await login.request('/api/auth/login', {
    method: 'POST', body: { email, password },
  });
  assert.equal(lr.status, 200, `Login for ${email} should succeed (got ${lr.status}: ${JSON.stringify(lr.data)})`);
  return login;
}

// ============================================
// TEST SUITE
// ============================================
async function run() {
  cleanupArtifacts();
  process.env.PORT = String(PORT);
  process.env.NODE_ENV = 'development';
  process.env.APP_URL = BASE_URL;
  process.env.SMTP_HOST = '127.0.0.1';
  process.env.SMTP_PORT = '1';
  process.env.SMTP_USER = 'offline-test';
  process.env.SMTP_PASS = 'offline-test';
  process.env.EMAIL_FROM = 'noreply@example.test';
  process.env.NO_PROXY = '127.0.0.1,localhost';
  process.env.no_proxy = '127.0.0.1,localhost';

  const { startServer } = require('../server/server');
  const server = startServer();

  try {
    await waitForServer();
    let passCount = 0;
    let failCount = 0;

    function pass(name) { passCount++; console.log(`  ✅ ${name}`); }
    function fail(name, err) { failCount++; console.error(`  ❌ ${name}: ${err.message || err}`); }
    async function check(name, fn) {
      try { await fn(); pass(name); } catch (e) { fail(name, e); }
    }

    const password = 'StrongPass1!';

    // ==========================================
    // 1. REGISTRATION + EDGE CASES
    // ==========================================
    console.log('\n📋 1. Registration');
    const regSession = new Session();
    await regSession.ensureCsrfToken();

    await check('Register succeeds', async () => {
      const r = await regSession.request('/api/auth/register', {
        method: 'POST', body: { email: 'alice@example.com', username: 'alice', password },
      });
      assert.equal(r.status, 201);
      assert.ok(r.data.devToken);
    });

    await check('Duplicate email — no devToken', async () => {
      const r = await regSession.request('/api/auth/register', {
        method: 'POST', body: { email: 'alice@example.com', username: 'alice2', password },
      });
      assert.ok(!r.data.devToken, 'Duplicate should not get devToken');
    });

    await check('Duplicate username — no devToken', async () => {
      const r = await regSession.request('/api/auth/register', {
        method: 'POST', body: { email: 'other@example.com', username: 'alice', password },
      });
      assert.ok(!r.data.devToken, 'Duplicate should not get devToken');
    });

    await check('Weak password rejected', async () => {
      const r = await regSession.request('/api/auth/register', {
        method: 'POST', body: { email: 'weak@example.com', username: 'weakuser', password: '123' },
      });
      assert.equal(r.status, 400);
    });

    // ==========================================
    // 2. LOGIN BEFORE VERIFY → 403
    // ==========================================
    console.log('\n📋 2. Login before email verification');
    await check('Unverified login returns 403', async () => {
      const s = new Session();
      await s.ensureCsrfToken();
      const r = await s.request('/api/auth/login', {
        method: 'POST', body: { email: 'alice@example.com', password },
      });
      assert.equal(r.status, 403);
      assert.equal(r.data.requiresVerification, true);
    });

    // ==========================================
    // 3. VERIFY EMAIL
    // ==========================================
    console.log('\n📋 3. Email verification');
    // Verify alice via DB (devToken was on a different session)
    const dbVerify = new Database(DB_PATH);
    dbVerify.prepare('UPDATE users SET is_verified = 1 WHERE email = ?').run('alice@example.com');
    dbVerify.close();

    await check('Verified user can login', async () => {
      const s = new Session();
      await s.ensureCsrfToken();
      const r = await s.request('/api/auth/login', {
        method: 'POST', body: { email: 'alice@example.com', password },
      });
      assert.equal(r.status, 200);
    });

    // ==========================================
    // 4. WRONG CREDENTIALS (dedicated user)
    // ==========================================
    console.log('\n📋 4. Wrong credentials');
    await createVerifiedUser('credtest@example.com', 'credtest', password);

    await check('Wrong password returns 401', async () => {
      const s = new Session();
      await s.ensureCsrfToken();
      const r = await s.request('/api/auth/login', {
        method: 'POST', body: { email: 'credtest@example.com', password: 'WrongPass1!' },
      });
      assert.equal(r.status, 401);
    });

    await check('Non-existent email returns 401', async () => {
      const s = new Session();
      await s.ensureCsrfToken();
      const r = await s.request('/api/auth/login', {
        method: 'POST', body: { email: 'nobody@example.com', password: 'TestPass1!' },
      });
      assert.equal(r.status, 401);
    });

    // Reset lockout for credtest (1 wrong attempt above)
    resetLockout('credtest@example.com');

    // ==========================================
    // 5. SUCCESSFUL LOGIN + /me
    // ==========================================
    console.log('\n📋 5. Successful login');
    const loginSession = await createVerifiedUser('logintest@example.com', 'logintest', password);

    await check('Authenticated /me returns correct user', async () => {
      const r = await loginSession.request('/api/user/me');
      assert.equal(r.status, 200);
      assert.equal(r.data.user.email, 'logintest@example.com');
    });

    // ==========================================
    // 6. CSRF PROTECTION
    // ==========================================
    console.log('\n📋 6. CSRF protection');
    await check('Request without CSRF token returns 403', async () => {
      const r = await fetch(`${BASE_URL}/api/auth/logout`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', cookie: loginSession.cookieHeader() },
      });
      assert.equal(r.status, 403);
    });

    await check('Request with wrong CSRF token returns 403', async () => {
      const r = await fetch(`${BASE_URL}/api/auth/logout`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-csrf-token': 'invalid-csrf-token-12345',
          cookie: loginSession.cookieHeader(),
        },
      });
      assert.equal(r.status, 403);
    });

    // ==========================================
    // 7. ACCOUNT LOCKOUT (dedicated user)
    // The 5th wrong attempt increments counter to 5,
    // then the same request checks >= 5 and returns 423.
    // ==========================================
    console.log('\n📋 7. Account lockout');
    const lockoutEmail = 'lockout@example.com';
    await createVerifiedUser(lockoutEmail, 'lockout', password);
    resetLockout(lockoutEmail);

    await check('5th wrong attempt triggers lockout (423)', async () => {
      // Attempts 1-4: return 401
      for (let i = 0; i < 4; i++) {
        const s = new Session();
        await s.ensureCsrfToken();
        const r = await s.request('/api/auth/login', {
          method: 'POST', body: { email: lockoutEmail, password: `WrongPass${i}!` },
        });
        assert.equal(r.status, 401, `Attempt ${i + 1} should be 401`);
      }
      // Attempt 5: increments to 5, triggers lockout, returns 423
      const s5 = new Session();
      await s5.ensureCsrfToken();
      const r5 = await s5.request('/api/auth/login', {
        method: 'POST', body: { email: lockoutEmail, password: 'WrongPass5!' },
      });
      assert.equal(r5.status, 423, '5th wrong attempt should trigger lockout (423)');
      // Even correct password should be locked now
      const s6 = new Session();
      await s6.ensureCsrfToken();
      const r6 = await s6.request('/api/auth/login', {
        method: 'POST', body: { email: lockoutEmail, password },
      });
      assert.equal(r6.status, 423, 'Correct password should still be locked (423)');
    });

    // ==========================================
    // 8. CHANGE PASSWORD (dedicated user)
    // ==========================================
    console.log('\n📋 8. Change password');
    const cpEmail = 'changepass@example.com';
    const cpPass = 'InitialPass1!';
    const cpNewPass = 'NewPassword2!';
    const cpSession = await createVerifiedUser(cpEmail, 'changepass', cpPass);

    await check('Change password with wrong current password → 401', async () => {
      const r = await cpSession.request('/api/auth/change-password', {
        method: 'POST', body: { currentPassword: 'WrongPass1!', newPassword: cpNewPass },
      });
      assert.equal(r.status, 401);
    });

    // Reset lockout (1 wrong sensitive action attempt above)
    resetLockout(cpEmail);

    // Re-login (wrong password attempt may have invalidated session via registerSensitiveActionFailure)
    const cpSession2 = await (async () => {
      const s = new Session();
      await s.ensureCsrfToken();
      const r = await s.request('/api/auth/login', { method: 'POST', body: { email: cpEmail, password: cpPass } });
      assert.equal(r.status, 200);
      return s;
    })();

    await check('Change password with weak new password → 400', async () => {
      const r = await cpSession2.request('/api/auth/change-password', {
        method: 'POST', body: { currentPassword: cpPass, newPassword: 'weak' },
      });
      assert.equal(r.status, 400);
    });

    await check('Change password succeeds', async () => {
      const r = await cpSession2.request('/api/auth/change-password', {
        method: 'POST', body: { currentPassword: cpPass, newPassword: cpNewPass },
      });
      assert.equal(r.status, 200);
    });

    await check('Old session invalidated after password change', async () => {
      const r = await cpSession2.request('/api/user/me');
      assert.equal(r.status, 401, 'Old access token should be invalid');
    });

    await check('Login with new password succeeds', async () => {
      const s = new Session();
      await s.ensureCsrfToken();
      const r = await s.request('/api/auth/login', {
        method: 'POST', body: { email: cpEmail, password: cpNewPass },
      });
      assert.equal(r.status, 200);
    });

    // ==========================================
    // 9. PASSWORD REUSE (dedicated user)
    // ==========================================
    console.log('\n📋 9. Password reuse prevention');
    const reuseEmail = 'reuse@example.com';
    const reusePass1 = 'FirstPass1!';
    const reusePass2 = 'SecondPass2!';
    const reuseSession = await createVerifiedUser(reuseEmail, 'reuse', reusePass1);

    // Change password
    await reuseSession.request('/api/auth/change-password', {
      method: 'POST', body: { currentPassword: reusePass1, newPassword: reusePass2 },
    });

    // Re-login with new password (old session invalidated)
    const reuseSession2 = new Session();
    await reuseSession2.ensureCsrfToken();
    const reuseLogin = await reuseSession2.request('/api/auth/login', {
      method: 'POST', body: { email: reuseEmail, password: reusePass2 },
    });
    assert.equal(reuseLogin.status, 200, 'Reuse user login should succeed');

    await check('Reusing recent password → 400', async () => {
      const r = await reuseSession2.request('/api/auth/change-password', {
        method: 'POST', body: { currentPassword: reusePass2, newPassword: reusePass1 },
      });
      assert.equal(r.status, 400);
    });

    await check('Reusing current password → 400', async () => {
      const r = await reuseSession2.request('/api/auth/change-password', {
        method: 'POST', body: { currentPassword: reusePass2, newPassword: reusePass2 },
      });
      assert.equal(r.status, 400);
    });

    // ==========================================
    // 10. CHANGE EMAIL (dedicated user)
    // ==========================================
    console.log('\n📋 10. Change email');
    const ceEmail = 'changeemail@example.com';
    const cePass = 'EmailPass1!';
    const ceSession = await createVerifiedUser(ceEmail, 'changeemail', cePass);

    await check('Change email with wrong password → 401', async () => {
      const r = await ceSession.request('/api/auth/change-email', {
        method: 'POST', body: { newEmail: 'new@example.com', password: 'WrongPass1!' },
      });
      assert.equal(r.status, 401);
    });

    // Reset lockout + re-login (wrong password triggers registerSensitiveActionFailure)
    resetLockout(ceEmail);
    const ceSession2 = new Session();
    await ceSession2.ensureCsrfToken();
    await ceSession2.request('/api/auth/login', { method: 'POST', body: { email: ceEmail, password: cePass } });

    await check('Change email to same address → 400', async () => {
      const r = await ceSession2.request('/api/auth/change-email', {
        method: 'POST', body: { newEmail: ceEmail, password: cePass },
      });
      assert.equal(r.status, 400);
    });

    await check('Change email to invalid format → 400', async () => {
      const r = await ceSession2.request('/api/auth/change-email', {
        method: 'POST', body: { newEmail: 'not-an-email', password: cePass },
      });
      assert.equal(r.status, 400);
    });

    await check('Change email initiates (returns success message)', async () => {
      const r = await ceSession2.request('/api/auth/change-email', {
        method: 'POST', body: { newEmail: 'newemail@example.com', password: cePass },
      });
      assert.equal(r.status, 200);
      assert.ok(r.data.success);
    });

    // ==========================================
    // 11. DELETE ACCOUNT (dedicated user)
    // ==========================================
    console.log('\n📋 11. Delete account');
    const delEmail = 'deleteme@example.com';
    const delPass = 'DeleteMe1!';
    const delSession = await createVerifiedUser(delEmail, 'deleteme', delPass);

    await check('Delete account with wrong password → 401', async () => {
      const r = await delSession.request('/api/auth/delete-account', {
        method: 'POST', body: { password: 'WrongPass1!' },
      });
      assert.equal(r.status, 401);
    });

    // Reset lockout + re-login
    resetLockout(delEmail);
    const delSession2 = new Session();
    await delSession2.ensureCsrfToken();
    await delSession2.request('/api/auth/login', { method: 'POST', body: { email: delEmail, password: delPass } });

    await check('Delete account succeeds', async () => {
      const r = await delSession2.request('/api/auth/delete-account', {
        method: 'POST', body: { password: delPass },
      });
      assert.equal(r.status, 200);
    });

    await check('Deleted user cannot login', async () => {
      const s = new Session();
      await s.ensureCsrfToken();
      const r = await s.request('/api/auth/login', {
        method: 'POST', body: { email: delEmail, password: delPass },
      });
      assert.equal(r.status, 401);
    });

    await check('Deleted user DB record gone', async () => {
      const u = getUserRecordByEmail(delEmail);
      assert.equal(u, undefined);
    });

    // ==========================================
    // 12. MFA — INVALID CODES (dedicated user)
    // ==========================================
    console.log('\n📋 12. MFA — invalid codes');
    const mfaEmail = 'mfatest@example.com';
    const mfaPass = 'MfaPass1!';
    const mfaSession = await createVerifiedUser(mfaEmail, 'mfatest', mfaPass);

    let backupCodes = null;

    await check('MFA setup succeeds', async () => {
      const r = await mfaSession.request('/api/auth/mfa/setup', {
        method: 'POST', body: { password: mfaPass },
      });
      assert.equal(r.status, 200);
      assert.equal(Array.isArray(r.data.backupCodes), true);
      assert.equal(r.data.backupCodes.length, 8);
      backupCodes = r.data.backupCodes;
    });

    await check('MFA verify with wrong code → 400', async () => {
      const r = await mfaSession.request('/api/auth/mfa/verify', {
        method: 'POST', body: { code: '000000' },
      });
      assert.equal(r.status, 400);
    });

    await check('MFA verify with invalid format → 400', async () => {
      const r = await mfaSession.request('/api/auth/mfa/verify', {
        method: 'POST', body: { code: 'abc' },
      });
      assert.equal(r.status, 400);
    });

    // Enable MFA properly
    const mfaCode = generateCurrentTotp(mfaEmail);
    await mfaSession.request('/api/auth/mfa/verify', {
      method: 'POST', body: { code: mfaCode },
    });
    clearTotpReplay(mfaEmail);

    await check('Login with invalid MFA code → 401', async () => {
      const s = new Session();
      await s.ensureCsrfToken();
      const r = await s.request('/api/auth/login', {
        method: 'POST', body: { email: mfaEmail, password: mfaPass, mfaCode: '999999' },
      });
      assert.equal(r.status, 401);
    });

    await check('Login with invalid MFA format → 400', async () => {
      const s = new Session();
      await s.ensureCsrfToken();
      const r = await s.request('/api/auth/login', {
        method: 'POST', body: { email: mfaEmail, password: mfaPass, mfaCode: 'abcdef' },
      });
      assert.equal(r.status, 400);
    });

    // ==========================================
    // 13. TOTP REPLAY (same mfa user)
    // ==========================================
    console.log('\n📋 13. TOTP replay protection');
    const totpCode = generateCurrentTotp(mfaEmail);
    const replayLogin = new Session();
    await replayLogin.ensureCsrfToken();
    const mfaLogin = await replayLogin.request('/api/auth/login', {
      method: 'POST', body: { email: mfaEmail, password: mfaPass, mfaCode: totpCode },
    });

    await check('MFA login with valid TOTP succeeds', async () => {
      assert.equal(mfaLogin.status, 200);
    });

    await check('Replayed TOTP rejected', async () => {
      const s = new Session();
      await s.ensureCsrfToken();
      const r = await s.request('/api/auth/login', {
        method: 'POST', body: { email: mfaEmail, password: mfaPass, mfaCode: totpCode },
      });
      assert.equal(r.status, 401);
    });

    // ==========================================
    // 14. CONCURRENT REFRESH TOKEN
    // ==========================================
    console.log('\n📋 14. Concurrent refresh token rotation');
    const refreshSession = await createVerifiedUser('refresh@example.com', 'refresh', password);

    await check('Concurrent refresh: only one succeeds', async () => {
      const cloneA = refreshSession.clone();
      const cloneB = refreshSession.clone();
      const [rA, rB] = await Promise.all([
        cloneA.request('/api/auth/refresh', { method: 'POST' }),
        cloneB.request('/api/auth/refresh', { method: 'POST' }),
      ]);
      const statuses = [rA.status, rB.status].sort((a, b) => a - b);
      assert.deepEqual(statuses, [200, 401]);
    });

    // ==========================================
    // 15. PASSWORD RESET LIFECYCLE (dedicated user)
    // ==========================================
    console.log('\n📋 15. Password reset token lifecycle');
    const resetEmail = 'resetpass@example.com';
    const resetOldPass = 'ResetOld1!';
    const resetNewPass = 'ResetNew2!';
    await createVerifiedUser(resetEmail, 'resetpass', resetOldPass);

    const forgotSession = new Session();
    await forgotSession.ensureCsrfToken();

    const forgot1 = await forgotSession.request('/api/auth/forgot-password', {
      method: 'POST', body: { email: resetEmail },
    });
    const forgot2 = await forgotSession.request('/api/auth/forgot-password', {
      method: 'POST', body: { email: resetEmail },
    });

    await check('Second forgot-password rotates token', async () => {
      assert.ok(forgot1.data.devToken);
      assert.ok(forgot2.data.devToken);
      assert.notEqual(forgot1.data.devToken, forgot2.data.devToken);
    });

    await check('Stale reset token rejected', async () => {
      const r = await forgotSession.request('/api/auth/reset-password', {
        method: 'POST', body: { token: forgot1.data.devToken, password: resetNewPass },
      });
      assert.equal(r.status, 400);
    });

    await check('Valid reset token works', async () => {
      const r = await forgotSession.request('/api/auth/reset-password', {
        method: 'POST', body: { token: forgot2.data.devToken, password: resetNewPass },
      });
      assert.equal(r.status, 200);
    });

    await check('Used reset token cannot replay', async () => {
      const r = await forgotSession.request('/api/auth/reset-password', {
        method: 'POST', body: { token: forgot2.data.devToken, password: 'AnotherPass3!' },
      });
      assert.equal(r.status, 400);
    });

    await check('No orphan password-reset tokens remain', async () => {
      const row = getCount(
        "SELECT COUNT(*) as count FROM verification_tokens WHERE user_id = (SELECT id FROM users WHERE email = ?) AND type = 'password_reset' AND used = 0",
        [resetEmail]
      );
      assert.equal(row.count, 0);
    });

    // ==========================================
    // 16. CONCURRENT MFA DISABLE (dedicated user)
    // ==========================================
    console.log('\n📋 16. Concurrent MFA disable with backup code');
    const disableEmail = 'mfadisable@example.com';
    const disablePass = 'Disable1!';
    const disableSession = await createVerifiedUser(disableEmail, 'mfadisable', disablePass);

    const mfaSetupResult = await disableSession.request('/api/auth/mfa/setup', {
      method: 'POST', body: { password: disablePass },
    });
    const disableBackupCodes = mfaSetupResult.data.backupCodes;

    const disableVerifyCode = generateCurrentTotp(disableEmail);
    await disableSession.request('/api/auth/mfa/verify', {
      method: 'POST', body: { code: disableVerifyCode },
    });
    clearTotpReplay(disableEmail);

    // Re-login with MFA to get a valid MFA-enabled session
    const disableLogin = new Session();
    await disableLogin.ensureCsrfToken();
    const disableTotp = generateCurrentTotp(disableEmail);
    await disableLogin.request('/api/auth/login', {
      method: 'POST', body: { email: disableEmail, password: disablePass, mfaCode: disableTotp },
    });

    await check('Concurrent MFA disable: backup code consumed once', async () => {
      const cloneA = disableLogin.clone();
      const cloneB = disableLogin.clone();
      const [dA, dB] = await Promise.all([
        cloneA.request('/api/auth/mfa/disable', {
          method: 'POST', body: { password: disablePass, mfaCode: disableBackupCodes[0] },
        }),
        cloneB.request('/api/auth/mfa/disable', {
          method: 'POST', body: { password: disablePass, mfaCode: disableBackupCodes[0] },
        }),
      ]);
      const statuses = [dA.status, dB.status].sort((a, b) => a - b);
      assert.deepEqual(statuses, [200, 401]);
    });

    // ==========================================
    // 17. LOGIN HISTORY
    // ==========================================
    console.log('\n📋 17. Login history');
    const histSession = await createVerifiedUser('history@example.com', 'history', password);

    await check('Login history returns logs', async () => {
      const r = await histSession.request('/api/user/login-history');
      assert.equal(r.status, 200);
      assert.ok(Array.isArray(r.data.logs));
      assert.ok(r.data.logs.length > 0);
    });

    // ==========================================
    // SUMMARY
    // ==========================================
    console.log(`\n${'═'.repeat(50)}`);
    console.log(`  GLM_Test Results: ✅ ${passCount} passed, ❌ ${failCount} failed`);
    console.log(`${'═'.repeat(50)}`);

    if (failCount > 0) {
      console.error('\nGLM_TEST FAIL');
      process.exitCode = 1;
    } else {
      console.log('\nGLM_TEST PASS');
    }
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
}

run().catch(err => {
  console.error('GLM_TEST FAIL');
  console.error(err.stack || err.message);
  process.exitCode = 1;
});
