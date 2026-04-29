const Database = require('better-sqlite3');
const path = require('path');

const dbPath = path.join(__dirname, '..', '..', 'auth.db');
const db = new Database(dbPath);

// Enable WAL mode for better concurrent performance
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

// ============================================
// Schema Creation
// ============================================
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    is_verified INTEGER DEFAULT 0,
    mfa_enabled INTEGER DEFAULT 0,
    mfa_secret TEXT,
    backup_codes TEXT,
    failed_login_attempts INTEGER DEFAULT 0,
    session_version INTEGER DEFAULT 0,
    locked_until DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS verification_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token TEXT UNIQUE NOT NULL,
    token_digest TEXT NOT NULL,
    type TEXT NOT NULL,
    target_email TEXT,
    expires_at DATETIME NOT NULL,
    used INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS login_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    ip_address TEXT,
    user_agent TEXT,
    success INTEGER NOT NULL,
    failure_reason TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
  );

  CREATE TABLE IF NOT EXISTS refresh_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token TEXT UNIQUE NOT NULL,
    token_digest TEXT NOT NULL,
    session_version INTEGER DEFAULT 0,
    expires_at DATETIME NOT NULL,
    revoked INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS password_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    password_hash TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );
`);

// Add columns for existing databases (ignore if already exists)
try {
  db.exec('ALTER TABLE users ADD COLUMN failed_login_attempts INTEGER DEFAULT 0');
} catch (e) {
  // Column already exists
}
try {
  db.exec('ALTER TABLE users ADD COLUMN locked_until DATETIME');
} catch (e) {
  // Column already exists
}
try {
  db.exec('ALTER TABLE users ADD COLUMN session_version INTEGER DEFAULT 0');
} catch (e) {
  // Column already exists
}
// Add TOTP replay-protection columns if missing
try {
  db.exec('ALTER TABLE users ADD COLUMN last_totp_code TEXT');
} catch (e) {
  // Column already exists
}
try {
  db.exec('ALTER TABLE users ADD COLUMN last_totp_timestamp INTEGER');
} catch (e) {
  // Column already exists
}
// Add token_digest column for verification tokens if missing
try {
  db.exec('ALTER TABLE verification_tokens ADD COLUMN token_digest TEXT');
} catch (e) {
  // Column already exists or table missing
}
try {
  db.exec('ALTER TABLE verification_tokens ADD COLUMN target_email TEXT');
} catch (e) {
  // Column already exists
}
try {
  db.exec('ALTER TABLE refresh_tokens ADD COLUMN token_digest TEXT');
} catch (e) {
  // Column already exists
}
try {
  db.exec('ALTER TABLE refresh_tokens ADD COLUMN session_version INTEGER DEFAULT 0');
} catch (e) {
  // Column already exists
}

// ============================================
// Prepared Statements (Performance)
// ============================================
const statements = {
  // User operations
  createUser: db.prepare(`
    INSERT INTO users (email, username, password_hash)
    VALUES (@email, @username, @passwordHash)
  `),

  findUserByEmail: db.prepare(`
    SELECT * FROM users WHERE email = @email
  `),

  findUserByUsername: db.prepare(`
    SELECT * FROM users WHERE username = @username
  `),

  findUserById: db.prepare(`
    SELECT * FROM users WHERE id = @id
  `),

  verifyUser: db.prepare(`
    UPDATE users SET is_verified = 1, updated_at = CURRENT_TIMESTAMP WHERE id = @id
  `),

  enableMfa: db.prepare(`
    UPDATE users SET mfa_enabled = @mfaEnabled, mfa_secret = @mfaSecret, backup_codes = @backupCodes, updated_at = CURRENT_TIMESTAMP WHERE id = @id
  `),

  disableMfa: db.prepare(`
    UPDATE users SET mfa_enabled = 0, mfa_secret = NULL, backup_codes = NULL, updated_at = CURRENT_TIMESTAMP WHERE id = @id
  `),

  incrementFailedAttempts: db.prepare(`
    UPDATE users SET failed_login_attempts = failed_login_attempts + 1, updated_at = CURRENT_TIMESTAMP WHERE id = @id
  `),

  resetFailedAttempts: db.prepare(`
    UPDATE users SET failed_login_attempts = 0, locked_until = NULL, updated_at = CURRENT_TIMESTAMP WHERE id = @id
  `),

  lockAccount: db.prepare(`
    UPDATE users SET locked_until = @lockedUntil, updated_at = CURRENT_TIMESTAMP WHERE id = @id
  `),

  getLastUsedTotp: db.prepare(`
    SELECT last_totp_code, last_totp_timestamp FROM users WHERE id = @id
  `),

  updateLastUsedTotp: db.prepare(`
    UPDATE users SET last_totp_code = @code, last_totp_timestamp = @timestamp WHERE id = @id
  `),

  updatePassword: db.prepare(`
    UPDATE users SET password_hash = @passwordHash, updated_at = CURRENT_TIMESTAMP WHERE id = @id
  `),

  updateUserEmail: db.prepare(`
    UPDATE users SET email = @email, is_verified = 0, updated_at = CURRENT_TIMESTAMP WHERE id = @id
  `),

  applyVerifiedEmailChange: db.prepare(`
    UPDATE users SET email = @email, is_verified = 1, updated_at = CURRENT_TIMESTAMP WHERE id = @id
  `),

  bumpSessionVersion: db.prepare(`
    UPDATE users SET session_version = session_version + 1, updated_at = CURRENT_TIMESTAMP WHERE id = @id
  `),

  deleteUser: db.prepare(`
    DELETE FROM users WHERE id = @id
  `),

  // Token operations
  createVerificationToken: db.prepare(`
    INSERT INTO verification_tokens (user_id, token, token_digest, type, target_email, expires_at)
    VALUES (@userId, @token, @tokenDigest, @type, @targetEmail, @expiresAt)
  `),

  findVerificationToken: db.prepare(`
    SELECT * FROM verification_tokens WHERE token_digest = @tokenDigest AND type = @type
  `),

  markTokenUsed: db.prepare(`
    UPDATE verification_tokens SET used = 1 WHERE id = @id
  `),

  markActiveVerificationTokensUsedByUserAndType: db.prepare(`
    UPDATE verification_tokens
    SET used = 1
    WHERE user_id = @userId AND type = @type AND used = 0
  `),

  deleteVerificationToken: db.prepare(`
    DELETE FROM verification_tokens WHERE id = @id
  `),

  // Refresh token operations
  createRefreshToken: db.prepare(`
    INSERT INTO refresh_tokens (user_id, token, token_digest, session_version, expires_at)
    VALUES (@userId, @token, @tokenDigest, @sessionVersion, @expiresAt)
  `),

  findRefreshToken: db.prepare(`
    SELECT * FROM refresh_tokens WHERE token_digest = @tokenDigest AND revoked = 0 AND expires_at > datetime('now')
  `),

  findRefreshTokenAnyStatus: db.prepare(`
    SELECT * FROM refresh_tokens WHERE token_digest = @tokenDigest
  `),

  consumeRefreshToken: db.prepare(`
    UPDATE refresh_tokens
    SET revoked = 1
    WHERE token_digest = @tokenDigest
      AND revoked = 0
      AND expires_at > datetime('now')
  `),

  revokeRefreshToken: db.prepare(`
    UPDATE refresh_tokens SET revoked = 1 WHERE token_digest = @tokenDigest
  `),

  revokeAllUserRefreshTokens: db.prepare(`
    UPDATE refresh_tokens SET revoked = 1 WHERE user_id = @userId
  `),

  deleteExpiredVerificationTokens: db.prepare(`
    DELETE FROM verification_tokens WHERE expires_at < @expiresAt OR used = 1
  `),

  deleteExpiredRefreshTokens: db.prepare(`
    DELETE FROM refresh_tokens WHERE expires_at < @expiresAt OR (revoked = 1 AND expires_at < @expiresAt)
  `),

  // Login log operations
  createLoginLog: db.prepare(`
    INSERT INTO login_logs (user_id, ip_address, user_agent, success, failure_reason)
    VALUES (@userId, @ipAddress, @userAgent, @success, @failureReason)
  `),

  getRecentLoginLogs: db.prepare(`
    SELECT * FROM login_logs WHERE user_id = @userId ORDER BY created_at DESC LIMIT 10
  `),

  countRecentFailedAttempts: db.prepare(`
    SELECT COUNT(*) as count FROM login_logs
    WHERE ip_address = @ipAddress AND success = 0 AND created_at > datetime('now', '-15 minutes')
  `),

  // Password history operations
  addPasswordToHistory: db.prepare(`
    INSERT INTO password_history (user_id, password_hash)
    VALUES (@userId, @passwordHash)
  `),

  getPasswordHistory: db.prepare(`
    SELECT password_hash FROM password_history 
    WHERE user_id = @userId 
    ORDER BY created_at DESC 
    LIMIT 5
  `),

  deleteOldPasswordHistory: db.prepare(`
    DELETE FROM password_history 
    WHERE user_id = @userId AND id NOT IN (
      SELECT id FROM password_history 
      WHERE user_id = @userId 
      ORDER BY created_at DESC 
      LIMIT 5
    )
  `),
};

module.exports = { db, statements };
