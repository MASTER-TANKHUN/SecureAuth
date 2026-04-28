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

process.env.JWT_SECRET = process.env.JWT_SECRET || 'smoke-test-jwt-secret-smoke-test-jwt-secret-smoke-test';
process.env.ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || ENCRYPTION_KEY;
process.env.CSRF_SECRET = process.env.CSRF_SECRET || 'smoke-test-csrf-secret-smoke-test-csrf-secret';

const { decrypt } = require('../server/utils/crypto');

class Session {
  constructor() {
    this.cookies = new Map();
    this.csrfToken = null;
  }

  clone() {
    const cloned = new Session();
    cloned.cookies = new Map(this.cookies);
    cloned.csrfToken = this.csrfToken;
    return cloned;
  }

  cookieHeader() {
    return Array.from(this.cookies.entries())
      .map(([name, value]) => `${name}=${value}`)
      .join('; ');
  }

  updateCookies(response) {
    const setCookie = response.headers.getSetCookie ? response.headers.getSetCookie() : [];
    for (const header of setCookie) {
      const [cookiePart] = header.split(';');
      const splitIndex = cookiePart.indexOf('=');
      const name = cookiePart.slice(0, splitIndex);
      const value = cookiePart.slice(splitIndex + 1);
      this.cookies.set(name, value);
    }
  }

  async ensureCsrfToken() {
    if (this.csrfToken) {
      return this.csrfToken;
    }

    const response = await fetch(`${BASE_URL}/api/csrf-token`, {
      headers: this.cookieHeader() ? { cookie: this.cookieHeader() } : {},
    });
    this.updateCookies(response);
    const data = await response.json();
    assert.equal(response.status, 200, 'Expected CSRF endpoint to succeed');
    assert.ok(data.csrfToken, 'Expected csrfToken');
    this.csrfToken = data.csrfToken;
    return this.csrfToken;
  }

  async request(endpoint, options = {}) {
    const method = (options.method || 'GET').toUpperCase();
    const headers = {
      ...(options.headers || {}),
    };

    const cookie = this.cookieHeader();
    if (cookie) {
      headers.cookie = cookie;
    }

    if (!['GET', 'HEAD', 'OPTIONS'].includes(method)) {
      headers['content-type'] = 'application/json';
      headers['x-csrf-token'] = await this.ensureCsrfToken();
    }

    const response = await fetch(`${BASE_URL}${endpoint}`, {
      method,
      headers,
      body: options.body ? JSON.stringify(options.body) : undefined,
      redirect: 'manual',
    });

    this.updateCookies(response);

    let data = null;
    const text = await response.text();
    if (text) {
      try {
        data = JSON.parse(text);
      } catch (err) {
        data = { raw: text };
      }
    }

    return { status: response.status, ok: response.ok, data, headers: response.headers };
  }
}

function cleanupArtifacts() {
  for (const file of [DB_PATH, `${DB_PATH}-wal`, `${DB_PATH}-shm`, SECURITY_LOG]) {
    try {
      fs.rmSync(file, { force: true });
    } catch (err) {
      // ignore
    }
  }
}

function wait(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

const http = require('http');

async function waitForServer() {
  for (let i = 0; i < 60; i += 1) {
    try {
      await new Promise((resolve, reject) => {
        const req = http.get(`${BASE_URL}/health`, (res) => {
          if (res.statusCode === 200) resolve();
          else reject(new Error('Status ' + res.statusCode));
        });
        req.on('error', reject);
        req.end();
      });
      return;
    } catch (err) {
      if (i === 0) console.log('⏳ Waiting for server...', err.message);
      // keep polling
    }
    await wait(250);
  }

  throw new Error('Server did not become ready in time');
}

function getUserRecordByEmail(email) {
  const db = new Database(DB_PATH, { readonly: true });
  try {
    return db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  } finally {
    db.close();
  }
}

function generateCurrentTotp(email) {
  const user = getUserRecordByEmail(email);
  assert.ok(user, 'Expected user to exist in database');
  const secret = decrypt(user.mfa_secret);
  assert.ok(secret, 'Expected stored MFA secret to decrypt');
  return authenticator.generate(secret);
}

function getCount(sql, params = []) {
  const db = new Database(DB_PATH, { readonly: true });
  try {
    return db.prepare(sql).get(...params);
  } finally {
    db.close();
  }
}

function getLatestRefreshTokenDigest(session) {
  const refreshToken = session.cookies.get('refresh_token');
  assert.ok(refreshToken, 'Expected refresh token cookie');
  return crypto.createHash('sha256').update(refreshToken).digest('hex');
}

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

    const email = 'alice@example.com';
    const password = 'StrongPass1!';
    const updatedPassword = 'EvenStronger2!';
    const registerSession = new Session();
    await registerSession.ensureCsrfToken();

    const registerResult = await registerSession.request('/api/auth/register', {
      method: 'POST',
      body: { email, username: 'alice', password },
    });
    if (registerResult.status !== 201) {
      console.error('❌ Register failed:', registerResult.status, registerResult.data);
    }
    assert.equal(registerResult.status, 201, 'Register should succeed');
    assert.ok(registerResult.data.devToken, 'Register should expose a dev verification token');

    const verifyResult = await registerSession.request('/api/auth/verify-email', {
      method: 'POST',
      body: { token: registerResult.data.devToken },
    });
    assert.equal(verifyResult.status, 200, 'Verify email should succeed');

    const loginSession = new Session();
    await loginSession.ensureCsrfToken();
    const loginResult = await loginSession.request('/api/auth/login', {
      method: 'POST',
      body: { email, password },
    });
    if (loginResult.status !== 200) {
      console.error('❌ Login failed:', loginResult.status, loginResult.data);
    }
    assert.equal(loginResult.status, 200, 'Login should succeed');
    assert.equal(loginResult.data.success, true, 'Login should return success');

    const meResult = await loginSession.request('/api/user/me');
    assert.equal(meResult.status, 200, 'Authenticated /me should succeed');
    assert.equal(meResult.data.user.email, email, 'Expected /me to return the current user');

    const refreshCloneA = loginSession.clone();
    const refreshCloneB = loginSession.clone();
    const [refreshA, refreshB] = await Promise.all([
      refreshCloneA.request('/api/auth/refresh', { method: 'POST' }),
      refreshCloneB.request('/api/auth/refresh', { method: 'POST' }),
    ]);
    const refreshStatuses = [refreshA.status, refreshB.status].sort((left, right) => left - right);
    assert.deepEqual(refreshStatuses, [200, 401], 'Concurrent refresh should only allow one success');

    const forgotSession = new Session();
    await forgotSession.ensureCsrfToken();
    const forgotFirst = await forgotSession.request('/api/auth/forgot-password', {
      method: 'POST',
      body: { email },
    });
    assert.equal(forgotFirst.status, 200, 'First forgot-password request should succeed');
    assert.ok(forgotFirst.data.devToken, 'Expected first forgot-password dev token');

    const forgotSecond = await forgotSession.request('/api/auth/forgot-password', {
      method: 'POST',
      body: { email },
    });
    assert.equal(forgotSecond.status, 200, 'Second forgot-password request should succeed');
    assert.ok(forgotSecond.data.devToken, 'Expected second forgot-password dev token');
    assert.notEqual(forgotFirst.data.devToken, forgotSecond.data.devToken, 'Expected token rotation for forgot-password');

    const staleReset = await forgotSession.request('/api/auth/reset-password', {
      method: 'POST',
      body: { token: forgotFirst.data.devToken, password: updatedPassword },
    });
    assert.equal(staleReset.status, 400, 'Older password reset token should be invalidated');

    const priorRefreshDigest = getLatestRefreshTokenDigest(loginSession);
    const resetResult = await forgotSession.request('/api/auth/reset-password', {
      method: 'POST',
      body: { token: forgotSecond.data.devToken, password: updatedPassword },
    });
    assert.equal(resetResult.status, 200, 'Latest password reset token should succeed');

    const replayReset = await forgotSession.request('/api/auth/reset-password', {
      method: 'POST',
      body: { token: forgotSecond.data.devToken, password: 'AnotherPass3!' },
    });
    assert.equal(replayReset.status, 400, 'Used password reset token must not replay');

    const revokedRefreshRow = getCount(
      'SELECT revoked FROM refresh_tokens WHERE token_digest = ?',
      [priorRefreshDigest]
    );
    assert.equal(revokedRefreshRow.revoked, 1, 'Password reset should revoke prior refresh sessions');

    const postResetLogin = new Session();
    await postResetLogin.ensureCsrfToken();
    const postResetLoginResult = await postResetLogin.request('/api/auth/login', {
      method: 'POST',
      body: { email, password: updatedPassword },
    });
    assert.equal(postResetLoginResult.status, 200, 'Login with updated password should succeed');

    const mfaSetup = await postResetLogin.request('/api/auth/mfa/setup', { method: 'POST' });
    assert.equal(mfaSetup.status, 200, 'MFA setup should succeed');
    assert.equal(Array.isArray(mfaSetup.data.backupCodes), true, 'Expected backup codes array');
    assert.equal(mfaSetup.data.backupCodes.length, 8, 'Expected eight backup codes');

    const currentCode = generateCurrentTotp(email);
    const mfaVerify = await postResetLogin.request('/api/auth/mfa/verify', {
      method: 'POST',
      body: { code: currentCode },
    });
    assert.equal(mfaVerify.status, 200, 'MFA verify should succeed');
    
    // Clear last used TOTP to avoid replay rejection during next login test
    {
      const dbForClear = new Database(DB_PATH);
      dbForClear.prepare('UPDATE users SET last_totp_code = NULL, last_totp_timestamp = NULL WHERE email = ?').run(email);
      dbForClear.close();
    }

    const mfaLoginSession = new Session();
    await mfaLoginSession.ensureCsrfToken();
    const mfaLoginPhaseOne = await mfaLoginSession.request('/api/auth/login', {
      method: 'POST',
      body: { email, password: updatedPassword },
    });
    assert.equal(mfaLoginPhaseOne.status, 200, 'Password stage of MFA login should succeed');
    assert.equal(mfaLoginPhaseOne.data.requiresMfa, true, 'Expected MFA challenge');

    const mfaCode = generateCurrentTotp(email);
    const mfaLoginPhaseTwo = await mfaLoginSession.request('/api/auth/login', {
      method: 'POST',
      body: { email, password: updatedPassword, mfaCode },
    });
    assert.equal(mfaLoginPhaseTwo.status, 200, 'MFA login should succeed with valid TOTP');

    const replaySession = new Session();
    await replaySession.ensureCsrfToken();
    const replayedTotp = await replaySession.request('/api/auth/login', {
      method: 'POST',
      body: { email, password: updatedPassword, mfaCode },
    });
    assert.equal(replayedTotp.status, 401, 'Replayed TOTP should be rejected');

    const backupCode = mfaSetup.data.backupCodes[0];
    const disableCloneA = postResetLogin.clone();
    const disableCloneB = postResetLogin.clone();
    const [disableA, disableB] = await Promise.all([
      disableCloneA.request('/api/auth/mfa/disable', {
        method: 'POST',
        body: { password: updatedPassword, mfaCode: backupCode },
      }),
      disableCloneB.request('/api/auth/mfa/disable', {
        method: 'POST',
        body: { password: updatedPassword, mfaCode: backupCode },
      }),
    ]);
    const disableStatuses = [disableA.status, disableB.status].sort((left, right) => left - right);
    assert.deepEqual(disableStatuses, [200, 401], 'Concurrent MFA disable attempts should only consume a backup code once');

    const passwordResetTokens = getCount(
      'SELECT COUNT(*) as count FROM verification_tokens WHERE user_id = (SELECT id FROM users WHERE email = ?) AND type = ? AND used = 0',
      [email, 'password_reset']
    );
    assert.equal(passwordResetTokens.count, 0, 'No active password-reset tokens should remain after reset');

    console.log('SMOKE TEST PASS');
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

run().catch((error) => {
  console.error('SMOKE TEST FAIL');
  console.error(error.stack || error.message);
  process.exitCode = 1;
});
