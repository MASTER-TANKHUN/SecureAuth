const express = require('express');
const argon2 = require('argon2');
const { authenticator } = require('otplib');
const QRCode = require('qrcode');
const crypto = require('crypto');

const config = require('../config');
const { db, statements } = require('../models/db');
const { validateRegistration, validateLogin, validatePasswordStrength, isValidEmail } = require('../middleware/validator');
const { loginLimiter, registerLimiter } = require('../middleware/rateLimiter');
const { authenticate } = require('../middleware/auth');
const {
  generateAccessToken,
  generateRefreshToken,
  generateVerificationToken,
  generateBackupCodes,
} = require('../utils/token');
const {
  sendVerificationEmail,
  sendPasswordResetEmail,
  sendLockoutAlertEmail,
  sendPasswordChangeAlertEmail,
  sendMfaDisableEmail,
} = require('../utils/email');
const { encrypt, decrypt, hashToken, verifyToken, hmacBackupCode, verifyBackupCode } = require('../utils/crypto');
const {
  apiLimiter,
  mfaAttemptLimiter,
  refreshLimiter,
  verifyEmailLimiter,
  forgotPasswordLimiter,
  emailLimiter,
  sensitiveActionLimiter,
} = require('../middleware/rateLimiter');
const { logSecurityEvent } = require('../utils/logger');

const router = express.Router();
const TOTP_STEP_MS = 30 * 1000;
const TOTP_REPLAY_WINDOW_MS = 3 * TOTP_STEP_MS;

let dummyHashCache = null;

async function getDummyHash() {
  if (!dummyHashCache) {
    dummyHashCache = await argon2.hash('dummy-password-for-timing', {
      type: argon2.argon2id,
      timeCost: config.argon2.timeCost,
      memoryCost: config.argon2.memoryCost,
      parallelism: config.argon2.parallelism,
    });
  }
  return dummyHashCache;
}

function invalidateUserSessions(userId) {
  statements.bumpSessionVersion.run({ id: userId });
  statements.revokeAllUserRefreshTokens.run({ userId });
}

/**
 * Source-based login throttling - locks specific (email, IP) pairs
 * instead of locking the entire account (DoS prevention)
 */
function handleFailedAttempt(email, ipAddress, userId = null) {
  // Cleanup old records periodically (1% chance)
  if (Math.random() < 0.01) {
    statements.cleanupStaleThrottles.run();
  }

  // Check if this source is already locked
  const throttle = statements.findSourceThrottle.get({
    email: email.toLowerCase(),
    ipAddress
  });

  if (throttle?.locked_until && new Date(throttle.locked_until) > new Date()) {
    const lockMinutes = Math.ceil((new Date(throttle.locked_until) - new Date()) / 60000);
    return {
      status: 429,
      body: {
        success: false,
        message: `Too many failed attempts from this location. Try again in ${lockMinutes} minutes.`,
        code: 'SOURCE_THROTTLED',
        lockedUntil: throttle.locked_until,
      }
    };
  }

  // Increment failed count for this source
  statements.incrementSourceThrottle.run({
    email: email.toLowerCase(),
    ipAddress
  });

  const updated = statements.findSourceThrottle.get({
    email: email.toLowerCase(),
    ipAddress
  });

  // Lock this source after 5 failures
  if (updated.failed_count >= 5) {
    const lockUntil = new Date(Date.now() + 30 * 60 * 1000).toISOString();
    statements.lockSourceThrottle.run({
      email: email.toLowerCase(),
      ipAddress,
      lockedUntil: lockUntil
    });

    logSecurityEvent('source_throttled', {
      email,
      ipAddress,
      userId,
      attempts: updated.failed_count,
      totalFailures: updated.total_failures,
    });

    return {
      status: 429,
      body: {
        success: false,
        message: 'Too many failed attempts from this location. Please try again in 30 minutes.',
        code: 'SOURCE_THROTTLED',
        requireCaptcha: true,
        lockedUntil: lockUntil,
      }
    };
  }

  return null; // No throttle triggered
}

/**
 * Soft reset throttling after successful login - keeps record for audit
 */
function resetThrottling(email, ipAddress, userId) {
  statements.softResetThrottle.run({
    email: email.toLowerCase(),
    ipAddress,
    lastSuccess: new Date().toISOString()
  });

  // Log for security audit trail
  logSecurityEvent('throttle_reset_success_login', {
    email,
    ipAddress,
    userId,
    timestamp: new Date().toISOString()
  });
}

async function registerSensitiveActionFailure(user, req, failureReason, eventName) {
  const ipAddress = req.ip || req.connection.remoteAddress;
  const userAgent = req.headers['user-agent'] || 'Unknown';

  // Use source-based throttling instead of account lockout (DoS prevention)
  const throttleResult = handleFailedAttempt(user.email, ipAddress, user.id);
  if (throttleResult) {
    // Source is throttled - log and return
    logSecurityEvent('sensitive_action_throttled', {
      userId: user.id,
      email: user.email,
      ipAddress,
      failureReason,
      eventName,
      throttleStatus: throttleResult.body.code,
    });
    return true; // Indicate that action was blocked
  }

  // Log the failure but don't increment account-level counter
  statements.createLoginLog.run({
    userId: user.id,
    ipAddress,
    userAgent,
    success: 0,
    failureReason,
  });

  logSecurityEvent(eventName, { userId: user.id, ipAddress, failureReason });
  return false;
}

function parseStoredBackupCodes(serializedCodes) {
  if (!serializedCodes) {
    return [];
  }

  try {
    const parsed = JSON.parse(serializedCodes);
    return Array.isArray(parsed) ? parsed : [];
  } catch (err) {
    return [];
  }
}

function consumeTotpCode(userId, code) {
  try {
    return db.transaction(() => {
      const freshUser = statements.findUserById.get({ id: userId });
      if (!freshUser?.mfa_secret) {
        return { status: 'NO_SECRET' };
      }

      const secret = decrypt(freshUser.mfa_secret);
      if (!secret) {
        return { status: 'ERROR' };
      }

      const isValid = authenticator.verify({
        token: code,
        secret,
        window: 1,
      });

      if (!isValid) {
        return { status: 'INVALID' };
      }

      const now = Date.now();
      const hashedCode = crypto.createHash('sha256').update(code).digest('hex');
      const lastUsedAt = Number(freshUser.last_totp_timestamp || 0);

      if (
        freshUser.last_totp_code === hashedCode &&
        lastUsedAt > 0 &&
        now - lastUsedAt < TOTP_REPLAY_WINDOW_MS
      ) {
        return { status: 'REPLAY' };
      }

      statements.updateLastUsedTotp.run({
        id: userId,
        code: hashedCode,
        timestamp: now,
      });

      return { status: 'VALID' };
    })();
  } catch (err) {
    console.error('Failed to consume TOTP code:', err.message);
    return { status: 'ERROR' };
  }
}

function consumeBackupCode(userId, code) {
  const normalizedCode = typeof code === 'string' ? code.trim().toUpperCase() : '';
  if (!normalizedCode) {
    return false;
  }

  const user = statements.findUserById.get({ id: userId });
  const backupCodeHashes = parseStoredBackupCodes(user?.backup_codes);
  if (backupCodeHashes.length === 0) {
    return false;
  }

  // O(1) HMAC lookup instead of O(n) Argon2 loop — prevents DoS amplification
  const codeHmac = hmacBackupCode(normalizedCode);
  const matchedIndex = backupCodeHashes.findIndex(storedHash => {
    try {
      return crypto.timingSafeEqual(Buffer.from(codeHmac, 'hex'), Buffer.from(storedHash, 'hex'));
    } catch {
      return false;
    }
  });

  if (matchedIndex === -1) {
    return false;
  }

  try {
    db.transaction(() => {
      const freshUser = statements.findUserById.get({ id: userId });
      const freshCodes = parseStoredBackupCodes(freshUser?.backup_codes);

      // Re-verify inside transaction
      const freshIndex = freshCodes.findIndex(h => {
        try {
          return crypto.timingSafeEqual(Buffer.from(codeHmac, 'hex'), Buffer.from(h, 'hex'));
        } catch {
          return false;
        }
      });

      if (freshIndex === -1) {
        throw new Error('CODE_ALREADY_USED');
      }

      freshCodes.splice(freshIndex, 1);
      statements.enableMfa.run({
        id: userId,
        mfaEnabled: Number(freshUser.mfa_enabled ?? 0),
        mfaSecret: freshUser.mfa_secret,
        backupCodes: JSON.stringify(freshCodes),
      });
    })();

    return true;
  } catch (err) {
    if (err.message === 'CODE_ALREADY_USED') {
      return false;
    }

    throw err;
  }
}

// ============================================
// REGISTER
// ============================================
router.post('/register', registerLimiter, validateRegistration, async (req, res) => {
  try {
    const { email, username, password } = req.body;
    const ipAddress = req.ip || req.connection.remoteAddress;

    // Always hash the password to prevent timing attacks
    const passwordHash = await argon2.hash(password, {
      type: argon2.argon2id,
      timeCost: config.argon2.timeCost,
      memoryCost: config.argon2.memoryCost,
      parallelism: config.argon2.parallelism,
    });

    // Check if user already exists
    const existingEmail = statements.findUserByEmail.get({ email });
    const existingUsername = statements.findUserByUsername.get({ username });

    if (existingEmail || existingUsername) {
      logSecurityEvent('registration_attempt_duplicate', { email, username, ipAddress });
      
      // Pad timing to match successful registration
      await hashToken('dummy-token-for-timing-balance');

      // Return generic success message to prevent enumeration
      return res.status(201).json({
        success: true,
        message: 'If an account exists with this email, a verification link has been sent.',
      });
    }

    // Create user
    const result = statements.createUser.run({
      email,
      username,
      passwordHash,
    });

    const userId = result.lastInsertRowid;

    // Add to password history
    statements.addPasswordToHistory.run({ userId, passwordHash });

    // Generate verification token
    const verifyTokenStr = generateVerificationToken();
    const tokenDigest = crypto.createHash('sha256').update(verifyTokenStr).digest('hex');
    const hashedToken = await hashToken(verifyTokenStr);
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();

    statements.createVerificationToken.run({
      userId,
      token: hashedToken,
      tokenDigest,
      type: 'email_verify',
      targetEmail: null,
      expiresAt,
    });

    // Send verification email (ไม่ต้อง await เพื่อไม่ให้มี Network Delay leak)
    sendVerificationEmail(email, verifyTokenStr).catch(emailErr => {
      console.error('Failed to send verification email:', emailErr.message);
    });

    logSecurityEvent('user_registered', { userId, email, username, ipAddress });

    res.status(201).json({
      success: true,
      message: 'If an account exists with this email, a verification link has been sent.',
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({
      success: false,
      message: 'An error occurred during registration. Please try again.',
    });
  }
});

// ============================================
// VERIFY EMAIL
// ============================================
router.post('/verify-email', verifyEmailLimiter, async (req, res) => {
  try {
    const { token } = req.body;

    if (!token) {
      return res.status(400).json({
        success: false,
        message: 'Verification token is required.',
      });
    }

    const tokenDigest = crypto.createHash('sha256').update(token).digest('hex');
    let tokenRecord = statements.findVerificationToken.get({
      tokenDigest,
      type: 'email_change',
    });
    let tokenType = 'email_change';

    if (!tokenRecord) {
      tokenRecord = statements.findVerificationToken.get({
        tokenDigest,
        type: 'email_verify',
      });
      tokenType = 'email_verify';
    }

    if (!tokenRecord) {
      return res.status(400).json({ success: false, message: 'Invalid verification link.' });
    }

    // Verify Argon2 hash matches provided token
    const isValid = await verifyToken(token, tokenRecord.token);
    if (!isValid) {
      return res.status(400).json({ success: false, message: 'Invalid verification link.' });
    }

    // Explicit checks for better error messages
    if (tokenRecord.used) {
      return res.status(400).json({
        success: false,
        message: 'This verification link has already been used.',
      });
    }

    if (new Date(tokenRecord.expires_at) < new Date()) {
      return res.status(400).json({
        success: false,
        message: 'This verification link has expired.',
      });
    }

    if (tokenType === 'email_change') {
      const targetEmail = tokenRecord.target_email;
      if (!targetEmail || !isValidEmail(targetEmail)) {
        return res.status(400).json({
          success: false,
          message: 'This email change request is invalid. Please request a new one.',
        });
      }

      const existingUser = statements.findUserByEmail.get({ email: targetEmail });
      if (existingUser && existingUser.id !== tokenRecord.user_id) {
        return res.status(409).json({
          success: false,
          message: 'This email address is no longer available. Please choose another one.',
        });
      }

      try {
        db.transaction(() => {
          // Verify again inside transaction to prevent race condition
          const freshToken = statements.findVerificationToken.get({ tokenDigest, type: 'email_change' });
          if (!freshToken || freshToken.used || new Date(freshToken.expires_at) < new Date()) {
            throw new Error('TOKEN_INVALID');
          }

          statements.applyVerifiedEmailChange.run({
            id: tokenRecord.user_id,
            email: targetEmail,
          });
          statements.markActiveVerificationTokensUsedByUserAndType.run({
            userId: tokenRecord.user_id,
            type: 'email_change',
          });
          statements.bumpSessionVersion.run({ id: tokenRecord.user_id });
          statements.revokeAllUserRefreshTokens.run({ userId: tokenRecord.user_id });
        })();
      } catch (updateErr) {
        if (updateErr.message === 'TOKEN_INVALID') {
          return res.status(400).json({ success: false, message: 'Invalid or already used verification link.' });
        }
        if (/UNIQUE constraint failed: users\.email/i.test(updateErr.message)) {
          return res.status(409).json({
            success: false,
            message: 'This email address is no longer available. Please choose another one.',
          });
        }
        throw updateErr;
      }

      logSecurityEvent('email_change_verified', {
        userId: tokenRecord.user_id,
        newEmail: targetEmail,
      });

      res.clearCookie('access_token', { path: '/' });
      res.clearCookie('refresh_token', { path: '/' });

      return res.json({
        success: true,
        message: 'Email updated and verified successfully. Please log in again.',
      });
    }

    // Verify user and mark token as used ATOMICALLY
    try {
      db.transaction(() => {
        const freshToken = statements.findVerificationToken.get({ tokenDigest, type: 'email_verify' });
        if (!freshToken || freshToken.used || new Date(freshToken.expires_at) < new Date()) {
          throw new Error('TOKEN_INVALID');
        }
        
        statements.verifyUser.run({ id: tokenRecord.user_id });
        statements.markActiveVerificationTokensUsedByUserAndType.run({
          userId: tokenRecord.user_id,
          type: 'email_verify',
        });
      })();
    } catch (err) {
      if (err.message === 'TOKEN_INVALID') {
        return res.status(400).json({ success: false, message: 'Invalid or already used verification link.' });
      }
      throw err;
    }

    res.json({
      success: true,
      message: 'Email verified successfully! You can now log in.',
    });
  } catch (error) {
    console.error('Verification error:', error);
    res.status(500).json({
      success: false,
      message: 'An error occurred during verification.',
    });
  }
});

// ============================================
// LOGIN
// ============================================
router.post('/login', loginLimiter, emailLimiter, mfaAttemptLimiter, validateLogin, async (req, res) => {
  try {
    const { email, password, mfaCode } = req.body;
    const ipAddress = req.ip || req.connection.remoteAddress;
    const userAgent = req.headers['user-agent'] || 'Unknown';
    const uaHash = crypto.createHash('sha256').update(userAgent).digest('hex');

    // Find user
    const user = statements.findUserByEmail.get({ email });

    if (!user) {
      // Still perform the verify operation to match time
      await argon2.verify(await getDummyHash(), password);

      // Log failed attempt
      statements.createLoginLog.run({
        userId: null,
        ipAddress,
        userAgent,
        success: 0,
        failureReason: 'invalid_credentials',
      });

      logSecurityEvent('login_failed', { email, ipAddress, reason: 'user_not_found' });

      return res.status(401).json({
        success: false,
        message: 'Email or password is incorrect.',
      });
    }

    // Check if account is locked
    if (user.locked_until && new Date(user.locked_until) > new Date()) {
      const lockMinutes = Math.ceil((new Date(user.locked_until) - new Date()) / 60000);
      statements.createLoginLog.run({
        userId: user.id,
        ipAddress,
        userAgent,
        success: 0,
        failureReason: 'account_locked',
      });

      logSecurityEvent('login_failed_locked', { userId: user.id, email, ipAddress });

      return res.status(423).json({
        success: false,
        message: `Account is temporarily locked. Try again in ${lockMinutes} minutes.`,
      });
    } else if (user.locked_until && new Date(user.locked_until) <= new Date()) {
      statements.resetFailedAttempts.run({ id: user.id });
    }

    // Verify password
    const isPasswordValid = await argon2.verify(user.password_hash, password);

    if (!isPasswordValid) {
      // Increment DB-backed failed attempt counter
      statements.incrementFailedAttempts.run({ id: user.id });

      statements.createLoginLog.run({
        userId: user.id,
        ipAddress,
        userAgent,
        success: 0,
        failureReason: 'invalid_password',
      });

      logSecurityEvent('login_failed', { userId: user.id, email, ipAddress, reason: 'invalid_password' });

      // Use source-based throttling instead of account lockout (DoS prevention)
      const throttleResult = handleFailedAttempt(email, ipAddress, user.id);
      if (throttleResult) {
        return res.status(throttleResult.status).json(throttleResult.body);
      }

      return res.status(401).json({
        success: false,
        message: 'Email or password is incorrect.',
      });
    }

    // Check if email is verified
    if (!user.is_verified) {
      return res.status(403).json({
        success: false,
        message: 'Please verify your email before logging in.',
        requiresVerification: true,
      });
    }

    // Check MFA
    if (user.mfa_enabled) {
      if (!mfaCode) {
        return res.status(200).json({
          success: true,
          requiresMfa: true,
          message: 'Verification required.',
        });
      }

      // Validate MFA code format: must be 6 digits (TOTP) or 12 hex chars (backup code)
      const isTotpFormat = /^\d{6}$/.test(mfaCode);
      const isBackupFormat = /^[A-Fa-f0-9]{12}$/.test(mfaCode);
      if (!isTotpFormat && !isBackupFormat) {
        return res.status(400).json({
          success: false,
          message: 'Invalid MFA code format.',
        });
      }

      const totpResult = consumeTotpCode(user.id, mfaCode);
      if (totpResult.status === 'ERROR' || totpResult.status === 'NO_SECRET') {
        return res.status(500).json({ success: false, message: 'Authentication error.' });
      }

      if (totpResult.status === 'REPLAY') {
        statements.createLoginLog.run({
          userId: user.id,
          ipAddress,
          userAgent,
          success: 0,
          failureReason: 'replayed_totp',
        });

        logSecurityEvent('login_failed', {
          userId: user.id,
          email,
          ipAddress,
          reason: 'replayed_totp',
        });

        return res.status(401).json({ success: false, message: 'This code has already been used.' });
      }

      // Check backup codes if TOTP fails
      let usedBackupCode = false;
      if (totpResult.status === 'INVALID') {
        try {
          usedBackupCode = await consumeBackupCode(user.id, mfaCode);
        } catch (err) {
          console.error('Failed to consume backup code during login:', err.message);
          return res.status(500).json({ success: false, message: 'Authentication error.' });
        }
      }

      if (totpResult.status !== 'VALID' && !usedBackupCode) {
        statements.incrementFailedAttempts.run({ id: user.id });

        statements.createLoginLog.run({
          userId: user.id,
          ipAddress,
          userAgent,
          success: 0,
          failureReason: 'invalid_mfa',
        });

        logSecurityEvent('login_failed', { userId: user.id, email, ipAddress, reason: 'invalid_mfa' });

        // Use source-based throttling instead of account lockout (DoS prevention)
        const throttleResult = handleFailedAttempt(email, ipAddress, user.id);
        if (throttleResult) {
          return res.status(throttleResult.status).json(throttleResult.body);
        }

        return res.status(401).json({
          success: false,
          message: 'Invalid MFA code.',
        });
      }
    }

    // Only clear failed-attempt counters after every authentication factor succeeds.
    statements.resetFailedAttempts.run({ id: user.id });

    // Reset source-based throttling on successful login (soft reset - keeps audit trail)
    resetThrottling(email, ipAddress, user.id);

    // --------------
    // FRAUD DETECTION LOGIC: Impossible Travel
    // --------------
    const geoip = require('geoip-lite');
    const geo = geoip.lookup(ipAddress);
    let latitude = null;
    let longitude = null;
    if (geo && geo.ll) {
      latitude = geo.ll[0];
      longitude = geo.ll[1];
    }

    const lastLogin = statements.getLastLoginEvent.get({ userId: user.id });
    let isImpossibleTravel = false;
    
    if (lastLogin && lastLogin.latitude && lastLogin.longitude && latitude && longitude) {
      function getDistance(lat1, lon1, lat2, lon2) {
        const R = 6371; // Earth radius in km
        const dLat = (lat2 - lat1) * Math.PI / 180;
        const dLon = (lon2 - lon1) * Math.PI / 180;
        const a = 
            Math.sin(dLat/2) * Math.sin(dLat/2) +
            Math.cos(lat1 * Math.PI / 180) * Math.cos(lat2 * Math.PI / 180) * 
            Math.sin(dLon/2) * Math.sin(dLon/2); 
        const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a)); 
        return R * c; 
      }
      
      const distance = getDistance(lastLogin.latitude, lastLogin.longitude, latitude, longitude);
      const timeDiffHours = (new Date() - new Date(lastLogin.event_time)) / (1000 * 60 * 60);
      
      if (timeDiffHours >= 0.0833) { // 5 mins minimum to prevent infinite speed
        const speed = distance / timeDiffHours;
        if (speed > 800) { // km/h
          isImpossibleTravel = true;
        }
      }
    }

    if (isImpossibleTravel) {
      logSecurityEvent('impossible_travel_detected', { userId: user.id, email, ipAddress });
      
      // We must insert the event so the next calculation uses this location, 
      // preventing a bypass where moving back is considered "normal".
      statements.createLoginEvent.run({
        userId: user.id,
        ipAddress,
        userAgent,
        latitude,
        longitude,
        isTrusted: 0,
        status: 'pending_verification'
      });
      
      return res.status(403).json({
        success: false,
        message: 'Unusual login location detected. Step-up authentication required.',
        code: 'IMPOSSIBLE_TRAVEL'
      });
    }

    statements.createLoginEvent.run({
      userId: user.id,
      ipAddress,
      userAgent,
      latitude,
      longitude,
      isTrusted: 1,
      status: 'success'
    });

    // Generate tokens
    const accessToken = generateAccessToken(user, uaHash);
    const refreshToken = generateRefreshToken();

    // Store hashed refresh token + SHA-256 digest for lookup
    const tokenDigest = crypto.createHash('sha256').update(refreshToken).digest('hex');
    const refreshExpiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();
    statements.createRefreshToken.run({
      userId: user.id,
      token: await hashToken(refreshToken),
      tokenDigest,
      sessionVersion: Number(user.session_version ?? 0),
      uaHash,
      expiresAt: refreshExpiresAt,
    });

    // Log successful login
    statements.createLoginLog.run({
      userId: user.id,
      ipAddress,
      userAgent,
      success: 1,
      failureReason: null,
    });

    logSecurityEvent('login_success', { userId: user.id, email, ipAddress });

    // Set HttpOnly cookies
    const cookieOptions = {
      httpOnly: true,
      secure: config.nodeEnv === 'production', // true in prod only
      sameSite: 'strict',
      path: '/',
    };

    res.cookie('access_token', accessToken, {
      ...cookieOptions,
      maxAge: 15 * 60 * 1000, // 15 minutes
    });

    res.cookie('refresh_token', refreshToken, {
      ...cookieOptions,
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });

    res.json({
      success: true,
      message: 'Login successful!',
      user: {
        id: user.id,
        email: user.email,
        username: user.username,
        mfaEnabled: !!user.mfa_enabled,
      },
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({
      success: false,
      message: 'An error occurred during login.',
    });
  }
});

// ============================================
// REFRESH TOKEN
// ============================================
router.post('/refresh', refreshLimiter, async (req, res) => {
  try {
    const refreshToken = req.cookies?.refresh_token;

    if (!refreshToken) {
      return res.status(401).json({
        success: false,
        message: 'No refresh token provided.',
      });
    }

    // Atomic Refresh Operation
    let newAccessToken, newRefreshToken;
    const tokenDigest = crypto.createHash('sha256').update(refreshToken).digest('hex');

    // NEW APPROACH: Pre-calculate the hash
    const generatedRefreshToken = generateRefreshToken();
    const hashedRefreshToken = await hashToken(generatedRefreshToken);
    const newRefreshDigest = crypto.createHash('sha256').update(generatedRefreshToken).digest('hex');

    try {
      db.transaction(() => {
        const freshToken = statements.findRefreshTokenAnyStatus.get({ tokenDigest });
        if (!freshToken || new Date(freshToken.expires_at) < new Date()) {
          throw new Error('TOKEN_INVALID');
        }

        // หาก Token มีอยู่แต่ถูก revoked ไปแล้ว แสดงว่ามีการนำ Token ที่ใช้แล้วมารีเพลย์ (ขโมย)
        if (freshToken.revoked) {
          statements.revokeAllUserRefreshTokens.run({ userId: freshToken.user_id });
          statements.bumpSessionVersion.run({ id: freshToken.user_id });
          throw new Error('TOKEN_INVALID');
        }
        const freshUser = statements.findUserById.get({ id: freshToken.user_id });
        if (!freshUser) throw new Error('USER_NOT_FOUND');

        const currentSessionVersion = Number(freshUser.session_version ?? 0);
        if (Number(freshToken.session_version ?? 0) !== currentSessionVersion) {
          throw new Error('SESSION_EXPIRED');
        }

        // UA Binding Validation (Option A: Revoke legacy tokens)
        const userAgent = req.headers['user-agent'] || 'Unknown';
        const currentUaHash = crypto.createHash('sha256').update(userAgent).digest('hex');

        // Check for legacy tokens without UA binding - revoke them
        if (freshToken.ua_hash === null || freshToken.ua_hash === undefined) {
          statements.revokeRefreshToken.run({ tokenDigest });
          logSecurityEvent('legacy_token_revoked', {
            userId: freshToken.user_id,
            reason: 'missing_ua_binding',
            ipAddress: req.ip,
          });
          throw new Error('TOKEN_DEPRECATED');
        }

        // Check UA mismatch - potential token theft
        if (freshToken.ua_hash !== currentUaHash) {
          statements.revokeAllUserRefreshTokens.run({ userId: freshToken.user_id });
          statements.bumpSessionVersion.run({ id: freshToken.user_id });
          logSecurityEvent('refresh_token_ua_mismatch', {
            userId: freshToken.user_id,
            ipAddress: req.ip,
            userAgent: userAgent,
          });
          throw new Error('TOKEN_INVALID');
        }

        const consumeResult = statements.consumeRefreshToken.run({ tokenDigest });
        if (consumeResult.changes !== 1) {
          throw new Error('TOKEN_INVALID');
        }

        newAccessToken = generateAccessToken(freshUser, currentUaHash);
        newRefreshToken = generatedRefreshToken;
        const refreshExpiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();

        statements.createRefreshToken.run({
          userId: freshUser.id,
          token: hashedRefreshToken,
          tokenDigest: newRefreshDigest,
          sessionVersion: currentSessionVersion,
          uaHash: currentUaHash,
          expiresAt: refreshExpiresAt,
        });
      })();
    } catch (err) {
      const msgMap = {
        'TOKEN_INVALID': 'Invalid or expired refresh token.',
        'TOKEN_DEPRECATED': 'Your session has expired for security reasons. Please log in again.',
        'USER_NOT_FOUND': 'User not found.',
        'SESSION_EXPIRED': 'Authentication session has expired. Please log in again.'
      };
      if (msgMap[err.message]) {
        return res.status(401).json({ success: false, message: msgMap[err.message], code: 'TOKEN_REVOKED' });
      }
      throw err;
    }

    const cookieOptions = {
      httpOnly: true,
      secure: config.nodeEnv === 'production',
      sameSite: 'strict',
      path: '/',
    };

    res.cookie('access_token', newAccessToken, {
      ...cookieOptions,
      maxAge: 15 * 60 * 1000,
    });

    res.cookie('refresh_token', newRefreshToken, {
      ...cookieOptions,
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    res.json({
      success: true,
      message: 'Token refreshed successfully.',
    });
  } catch (error) {
    console.error('Token refresh error:', error);
    res.status(500).json({
      success: false,
      message: 'An error occurred.',
    });
  }
});

// ============================================
// LOGOUT
// ============================================
router.post('/logout', apiLimiter, async (req, res) => {
  try {
    const refreshToken = req.cookies?.refresh_token;

    if (refreshToken) {
      const tokenDigest = crypto.createHash('sha256').update(refreshToken).digest('hex');
      statements.revokeRefreshToken.run({ tokenDigest });
    }

    res.clearCookie('access_token', { path: '/' });
    res.clearCookie('refresh_token', { path: '/' });

    res.json({
      success: true,
      message: 'Logged out successfully.',
    });
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({
      success: false,
      message: 'An error occurred during logout.',
    });
  }
});

// ============================================
// MFA SETUP
// ============================================
router.post('/mfa/setup', authenticate, mfaAttemptLimiter, async (req, res) => {
  try {
    const { password } = req.body;

    if (!password) {
      return res.status(400).json({
        success: false,
        message: 'Password is required to setup MFA.',
      });
    }

    const user = statements.findUserById.get({ id: req.user.id });

    // Verify password before allowing MFA setup (defense-in-depth)
    const isPasswordValid = await argon2.verify(user.password_hash, password);
    if (!isPasswordValid) {
      return res.status(401).json({
        success: false,
        message: 'Incorrect password.',
      });
    }

    if (user.mfa_enabled) {
      return res.status(400).json({
        success: false,
        message: 'MFA is already enabled.',
      });
    }

    // Generate TOTP secret
    const secret = authenticator.generateSecret();
    const otpAuthUrl = authenticator.keyuri(user.email, 'SecureAuth', secret);

    // Generate QR code
    const qrCodeDataUrl = await QRCode.toDataURL(otpAuthUrl);

    // Store encrypted secret temporarily in DB (but mfa_enabled = 0)
    const backupCodes = generateBackupCodes();
    // HMAC each backup code for O(1) verification (prevents DoS amplification vs Argon2)
    const hashedBackupCodes = backupCodes.map(c => hmacBackupCode(c));

    statements.enableMfa.run({
      id: req.user.id,
      mfaEnabled: 0,
      mfaSecret: encrypt(secret),
      backupCodes: JSON.stringify(hashedBackupCodes),
    });

    // Return plaintext backup codes to user (display once)
    res.json({
      success: true,
      qrCode: qrCodeDataUrl,
      backupCodes,
    });
  } catch (error) {
    console.error('MFA setup error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to setup MFA.',
    });
  }
});

// ============================================
// MFA VERIFY & ENABLE
// ============================================
router.post('/mfa/verify', authenticate, mfaAttemptLimiter, async (req, res) => {
  try {
    const { code } = req.body;

    if (!code) {
      return res.status(400).json({
        success: false,
        message: 'Verification code is required.',
      });
    }

    // L3 & L6 Fix: Validate MFA code format (6 digits)
    if (!/^\d{6}$/.test(code)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid code format. Expected 6 digits.',
      });
    }

    const user = statements.findUserById.get({ id: req.user.id });
    
    if (!user.mfa_secret) {
      return res.status(400).json({ success: false, message: 'MFA setup not initiated.' });
    }

    const totpResult = consumeTotpCode(req.user.id, code);
    if (totpResult.status === 'ERROR' || totpResult.status === 'NO_SECRET') {
      return res.status(500).json({
        success: false,
        message: 'Failed to enable MFA.',
      });
    }

    if (totpResult.status === 'REPLAY') {
      return res.status(400).json({
        success: false,
        message: 'This verification code has already been used. Please wait for the next code.',
      });
    }

    if (totpResult.status !== 'VALID') {
      return res.status(400).json({
        success: false,
        message: 'Invalid verification code. Please try again.',
      });
    }

    // Fix: Use transaction with fresh data to prevent race condition
    try {
      db.transaction(() => {
        const freshUser = statements.findUserById.get({ id: req.user.id });
        if (!freshUser || !freshUser.mfa_secret) {
          throw new Error('MFA_NOT_SETUP');
        }
        statements.enableMfa.run({
          id: req.user.id,
          mfaEnabled: 1,
          mfaSecret: freshUser.mfa_secret,
          backupCodes: freshUser.backup_codes,
        });
      })();
    } catch (txErr) {
      if (txErr.message === 'MFA_NOT_SETUP') {
        return res.status(400).json({ success: false, message: 'MFA setup not initiated.' });
      }
      throw txErr;
    }
    res.json({
      success: true,
      message: 'MFA enabled successfully!',
    });
  } catch (error) {
    console.error('MFA verify error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to enable MFA.',
    });
  }
});

// ============================================
// MFA DISABLE (Step 1: Send Verification)
// ============================================
router.post('/mfa/disable', authenticate, sensitiveActionLimiter, mfaAttemptLimiter, async (req, res) => {
  try {
    const { password, mfaCode } = req.body;
    const ipAddress = req.ip || req.connection.remoteAddress;

    if (!password) {
      return res.status(400).json({
        success: false,
        message: 'Password is required to disable MFA.',
      });
    }

    const user = statements.findUserById.get({ id: req.user.id });

    if (!user.mfa_enabled) {
      return res.status(400).json({
        success: false,
        message: 'MFA is not enabled on this account.',
      });
    }

    const isPasswordValid = await argon2.verify(user.password_hash, password);
    if (!isPasswordValid) {
      const locked = await registerSensitiveActionFailure(
        user,
        req,
        'mfa_disable_invalid_password',
        'mfa_disable_failed_password'
      );
      if (locked) {
        return res.status(423).json({
          success: false,
          message: 'Too many failed attempts. Account locked for 30 minutes.',
        });
      }
      return res.status(401).json({
        success: false,
        message: 'Incorrect password.',
      });
    }

    // Require TOTP or Backup code if MFA is enabled
    if (user.mfa_enabled) {
      if (!mfaCode) {
        return res.status(400).json({
          success: false,
          message: 'MFA code is required to disable MFA.',
        });
      }

      const totpResult = consumeTotpCode(user.id, mfaCode);
      if (totpResult.status === 'ERROR' || totpResult.status === 'NO_SECRET') {
        return res.status(500).json({ success: false, message: 'Failed to validate MFA.' });
      }

      const isValidTotp = totpResult.status === 'VALID';
      let usedBackupCode = false;
      if (!isValidTotp && totpResult.status === 'INVALID') {
        try {
          usedBackupCode = await consumeBackupCode(user.id, mfaCode);
        } catch (err) {
          console.error('Failed to consume backup code during MFA disable:', err.message);
          return res.status(500).json({ success: false, message: 'Failed to validate MFA.' });
        }
      }

      if (!isValidTotp && !usedBackupCode) {
        const locked = await registerSensitiveActionFailure(
          user,
          req,
          totpResult.status === 'REPLAY' ? 'mfa_disable_replayed_totp' : 'mfa_disable_invalid_mfa',
          'mfa_disable_failed_mfa'
        );
        if (locked) {
          return res.status(423).json({
            success: false,
            message: 'Too many failed attempts. Account locked for 30 minutes.',
          });
        }
        return res.status(401).json({
          success: false,
          message: 'Invalid MFA code.',
        });
      }
    }

    // Generate a verification token for MFA disable
    const disableToken = generateVerificationToken();
    const tokenDigest = crypto.createHash('sha256').update(disableToken).digest('hex');
    const hashedToken = await hashToken(disableToken);
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000).toISOString(); // 15 minutes

    db.transaction(() => {
      statements.markActiveVerificationTokensUsedByUserAndType.run({
        userId: user.id,
        type: 'mfa_disable',
      });
      statements.createVerificationToken.run({
        userId: user.id,
        token: hashedToken,
        tokenDigest,
        type: 'mfa_disable',
        targetEmail: null,
        expiresAt,
      });
    })();

    // Send verification email
    try {
      await sendMfaDisableEmail(user.email, disableToken);
    } catch (emailErr) {
      console.error('Failed to send MFA disable verification email:', emailErr.message);
    }

    logSecurityEvent('mfa_disable_initiated', { userId: user.id, ipAddress });
    statements.resetFailedAttempts.run({ id: user.id });

    res.json({
      success: true,
      message: 'A verification link has been sent to your email to confirm disabling MFA.',
    });
  } catch (error) {
    console.error('MFA disable error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to initiate MFA disable.',
    });
  }
});

// ============================================
// MFA CONFIRM DISABLE (Step 2: Confirm)
// ============================================
router.post('/mfa/confirm-disable', apiLimiter, authenticate, async (req, res) => {
  try {
    const { token } = req.body;
    const ipAddress = req.ip || req.connection.remoteAddress;

    if (!token) {
      return res.status(400).json({ success: false, message: 'Token is required.' });
    }

    const tokenDigest = crypto.createHash('sha256').update(token).digest('hex');
    const tokenRecord = statements.findVerificationToken.get({ tokenDigest, type: 'mfa_disable' });

    if (!tokenRecord || tokenRecord.used || new Date(tokenRecord.expires_at) < new Date()) {
      return res.status(400).json({ success: false, message: 'Invalid or expired confirmation link.' });
    }

    if (tokenRecord.user_id !== req.user.id) {
      logSecurityEvent('mfa_disable_token_mismatch', {
        requestUserId: req.user.id,
        tokenUserId: tokenRecord.user_id,
        ipAddress,
      });
      return res.status(403).json({
        success: false,
        message: 'This confirmation link does not belong to your account.',
      });
    }

    // Verify hash
    const isValidToken = await verifyToken(token, tokenRecord.token);
    if (!isValidToken) {
      return res.status(400).json({ success: false, message: 'Invalid confirmation link.' });
    }

    try {
      db.transaction(() => {
        const freshToken = statements.findVerificationToken.get({ tokenDigest, type: 'mfa_disable' });
        if (!freshToken || freshToken.used || new Date(freshToken.expires_at) < new Date()) {
          throw new Error('TOKEN_INVALID');
        }

        statements.disableMfa.run({ id: tokenRecord.user_id });
        statements.markActiveVerificationTokensUsedByUserAndType.run({
          userId: tokenRecord.user_id,
          type: 'mfa_disable',
        });
      })();
    } catch (err) {
      if (err.message === 'TOKEN_INVALID') {
        return res.status(400).json({ success: false, message: 'Invalid or already used confirmation link.' });
      }
      throw err;
    }

    logSecurityEvent('mfa_disabled', { userId: tokenRecord.user_id, ipAddress });

    res.json({
      success: true,
      message: 'MFA has been disabled successfully.',
    });
  } catch (error) {
    console.error('MFA confirm disable error:', error);
    res.status(500).json({ success: false, message: 'Failed to disable MFA.' });
  }
});

// ============================================
// FORGOT PASSWORD
// ============================================
router.post('/forgot-password', forgotPasswordLimiter, emailLimiter, async (req, res) => {
  try {
    const { email } = req.body;
    const normalizedEmail = typeof email === 'string' ? email.toLowerCase().trim() : '';

    if (!normalizedEmail) {
      return res.status(400).json({
        success: false,
        message: 'Email is required.',
      });
    }

    // Always return success to prevent email enumeration
    const user = statements.findUserByEmail.get({ email: normalizedEmail });

    if (user && user.is_verified) {
      const resetToken = generateVerificationToken();
      const tokenDigest = crypto.createHash('sha256').update(resetToken).digest('hex');
      const hashedToken = await hashToken(resetToken);
      const expiresAt = new Date(Date.now() + 60 * 60 * 1000).toISOString();

      db.transaction(() => {
        statements.markActiveVerificationTokensUsedByUserAndType.run({
          userId: user.id,
          type: 'password_reset',
        });
        statements.createVerificationToken.run({
          userId: user.id,
          token: hashedToken,
          tokenDigest,
          type: 'password_reset',
          targetEmail: null,
          expiresAt,
        });
      })();

      logSecurityEvent('password_reset_initiated', { userId: user.id, email: user.email });

      // Send password reset email (ไม่ต้อง await เพื่อไม่ให้มี Network Delay leak)
      sendPasswordResetEmail(normalizedEmail, resetToken).catch(emailErr => {
        console.error('Failed to send password reset email:', emailErr.message);
      });
    } else {
      // Simulate token generation timing to prevent enumeration
      await hashToken('dummy-token-for-timing-balance');
    }

    res.json({
      success: true,
      message: 'If an account exists with this email, a password reset link has been sent.',
    });
  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({
      success: false,
      message: 'An error occurred. Please try again.',
    });
  }
});

// ============================================
// RESET PASSWORD
// ============================================
router.post('/reset-password', apiLimiter, async (req, res) => {
  try {
    const { token, password } = req.body;

    if (!token || !password) {
      return res.status(400).json({
        success: false,
        message: 'Token and password are required.',
      });
    }

    // Validate password strength
    const pwResult = validatePasswordStrength(password);
    if (!pwResult.isValid) {
      return res.status(400).json({
        success: false,
        message: 'Password does not meet requirements.',
        errors: pwResult.errors,
      });
    }

    const tokenDigest = crypto.createHash('sha256').update(token).digest('hex');
    const tokenRecord = statements.findVerificationToken.get({ tokenDigest, type: 'password_reset' });

    if (!tokenRecord) {
      return res.status(400).json({ success: false, message: 'Invalid password reset link.' });
    }

    // Verify Argon2 hash matches provided token
    const isValidToken = await verifyToken(token, tokenRecord.token);
    if (!isValidToken) {
      return res.status(400).json({ success: false, message: 'Invalid password reset link.' });
    }

    if (tokenRecord.used) {
      return res.status(400).json({
        success: false,
        message: 'This reset link has already been used.',
      });
    }

    if (new Date(tokenRecord.expires_at) < new Date()) {
      return res.status(400).json({
        success: false,
        message: 'This reset link has expired.',
      });
    }

    // Check password history
    const history = statements.getPasswordHistory.all({ userId: tokenRecord.user_id });
    for (const entry of history) {
      const isMatch = await argon2.verify(entry.password_hash, password);
      if (isMatch) {
        return res.status(400).json({
          success: false,
          message: 'You cannot reuse one of your last 5 passwords.',
        });
      }
    }

    // Hash new password
    const passwordHash = await argon2.hash(password, {
      type: argon2.argon2id,
      timeCost: config.argon2.timeCost,
      memoryCost: config.argon2.memoryCost,
      parallelism: config.argon2.parallelism,
    });

    // Update user password and mark token as used ATOMICALLY
    try {
      db.transaction(() => {
        // Double check token status inside transaction
        const freshToken = statements.findVerificationToken.get({ tokenDigest, type: 'password_reset' });
        if (!freshToken || freshToken.used || new Date(freshToken.expires_at) < new Date()) {
          throw new Error('TOKEN_INVALID');
        }

        statements.updatePassword.run({
          id: tokenRecord.user_id,
          passwordHash,
        });

        // Add to password history
        statements.addPasswordToHistory.run({ userId: tokenRecord.user_id, passwordHash });
        statements.deleteOldPasswordHistory.run({ userId: tokenRecord.user_id });

        // Revoke every active password-reset token so older stolen links cannot be replayed later.
        statements.markActiveVerificationTokensUsedByUserAndType.run({
          userId: tokenRecord.user_id,
          type: 'password_reset',
        });

        // Revoke all refresh tokens for security
        statements.bumpSessionVersion.run({ id: tokenRecord.user_id });
        statements.revokeAllUserRefreshTokens.run({ userId: tokenRecord.user_id });

        // Reset failed attempts
        statements.resetFailedAttempts.run({ id: tokenRecord.user_id });
      })();
    } catch (err) {
      if (err.message === 'TOKEN_INVALID') {
        return res.status(400).json({ success: false, message: 'Invalid or already used reset link.' });
      }
      throw err;
    }

    // Get user info for email
    const user = statements.findUserById.get({ id: tokenRecord.user_id });

    // Send password change alert email
    try {
      await sendPasswordChangeAlertEmail(user.email, req.ip || req.connection.remoteAddress);
    } catch (emailErr) {
      console.error('Failed to send password change alert email:', emailErr.message);
    }

    logSecurityEvent('password_reset_success', { userId: tokenRecord.user_id, ipAddress: req.ip || req.connection.remoteAddress });

    res.json({
      success: true,
      message: 'Password reset successfully. You can now log in with your new password.',
    });
  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({
      success: false,
      message: 'An error occurred. Please try again.',
    });
  }
});

// ============================================
// CHANGE PASSWORD (M9)
// ============================================
router.post('/change-password', authenticate, sensitiveActionLimiter, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    const ipAddress = req.ip || req.connection.remoteAddress;

    if (!currentPassword || !newPassword) {
      return res.status(400).json({ success: false, message: 'All fields are required.' });
    }

    const user = statements.findUserById.get({ id: req.user.id });

    // Verify current password
    const isPasswordValid = await argon2.verify(user.password_hash, currentPassword);
    if (!isPasswordValid) {
      const locked = await registerSensitiveActionFailure(
        user,
        req,
        'change_password_invalid_current_password',
        'change_password_failed_password'
      );
      if (locked) {
        return res.status(423).json({
          success: false,
          message: 'Too many failed attempts. Account locked for 30 minutes.',
        });
      }
      return res.status(401).json({ success: false, message: 'Incorrect current password.' });
    }

    // Validate new password strength
    const pwResult = validatePasswordStrength(newPassword);
    if (!pwResult.isValid) {
      return res.status(400).json({ success: false, message: 'New password does not meet requirements.', errors: pwResult.errors });
    }

    // Check password history
    const history = statements.getPasswordHistory.all({ userId: user.id });
    for (const entry of history) {
      if (await argon2.verify(entry.password_hash, newPassword)) {
        return res.status(400).json({ success: false, message: 'You cannot reuse one of your last 5 passwords.' });
      }
    }

    // Hash new password
    const passwordHash = await argon2.hash(newPassword, {
      type: argon2.argon2id,
      timeCost: config.argon2.timeCost,
      memoryCost: config.argon2.memoryCost,
      parallelism: config.argon2.parallelism,
    });

    // Update password inside a transaction for data integrity
    db.transaction(() => {
      statements.updatePassword.run({ id: user.id, passwordHash });
      statements.addPasswordToHistory.run({ userId: user.id, passwordHash });
      statements.deleteOldPasswordHistory.run({ userId: user.id });
      
      // Inline invalidateUserSessions logic to ensure it shares the transaction
      statements.bumpSessionVersion.run({ id: user.id });
      statements.revokeAllUserRefreshTokens.run({ userId: user.id });
      
      statements.resetFailedAttempts.run({ id: user.id });
    })();

    // Send password change alert email
    try {
      await sendPasswordChangeAlertEmail(user.email, ipAddress);
    } catch (emailErr) {
      console.error('Failed to send password change alert email:', emailErr.message);
    }

    logSecurityEvent('password_changed', { userId: user.id, ipAddress });

    res.json({ success: true, message: 'Password changed successfully.' });
  } catch (error) {
    console.error('Change password error:', error);
    res.status(500).json({ success: false, message: 'An error occurred.' });
  }
});

// ============================================
// CHANGE EMAIL (M10)
// ============================================
router.post('/change-email', authenticate, sensitiveActionLimiter, async (req, res) => {
  try {
    const { newEmail, password } = req.body;
    const normalizedEmail = typeof newEmail === 'string' ? newEmail.toLowerCase().trim() : '';

    if (!normalizedEmail || !password) {
      return res.status(400).json({ success: false, message: 'New email and password are required.' });
    }

    const user = statements.findUserById.get({ id: req.user.id });
    if (!isValidEmail(normalizedEmail)) {
      return res.status(400).json({ success: false, message: 'Please provide a valid email address.' });
    }

    if (normalizedEmail === user.email) {
      return res.status(400).json({ success: false, message: 'The new email must be different from the current one.' });
    }

    const emailInUse = statements.findUserByEmail.get({ email: normalizedEmail });
    const isConflict = emailInUse && emailInUse.id !== user.id;

    if (!await argon2.verify(user.password_hash, password)) {
      const locked = await registerSensitiveActionFailure(
        user,
        req,
        'change_email_invalid_password',
        'change_email_failed_password'
      );
      if (locked) {
        return res.status(423).json({
          success: false,
          message: 'Too many failed attempts. Account locked for 30 minutes.',
        });
      }
      return res.status(401).json({ success: false, message: 'Incorrect password.' });
    }

    if (isConflict) {
      await hashToken('dummy-token-for-timing-balance');
      return res.json({
        success: true,
        message: 'A verification link has been sent to your new email address. Please click it to confirm.',
      });
    }

    const verifyTokenStr = generateVerificationToken();
    const tokenDigest = crypto.createHash('sha256').update(verifyTokenStr).digest('hex');
    const hashedToken = await hashToken(verifyTokenStr);
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();

    try {
      db.transaction(() => {
        statements.markActiveVerificationTokensUsedByUserAndType.run({
          userId: user.id,
          type: 'email_change',
        });
        statements.createVerificationToken.run({
          userId: user.id,
          token: hashedToken,
          tokenDigest,
          type: 'email_change',
          targetEmail: normalizedEmail,
          expiresAt,
        });
      })();
    } catch (updateErr) {
      console.error('Failed to update email during change-email flow:', updateErr.message);
      return res.status(500).json({ success: false, message: 'Failed to update email. Please try again.' });
    }

    // ส่งอีเมลแบบ Asynchronous เพื่อไม่ให้เกิด Network Delay Leak
    sendVerificationEmail(normalizedEmail, verifyTokenStr).catch(emailErr => {
      console.error('Failed to send email change verification email:', emailErr.message);
    });

    logSecurityEvent('email_change_initiated', {
      userId: user.id,
      oldEmail: user.email,
      newEmail: normalizedEmail,
    });
    statements.resetFailedAttempts.run({ id: user.id });

    res.json({
      success: true,
      message: 'Verification link sent to your new email address. Your current email stays active until you verify it.',
    });
  } catch (error) {
    console.error('Change email error:', error);
    res.status(500).json({ success: false, message: 'An error occurred.' });
  }
});

// ============================================
// DELETE ACCOUNT (M11)
// ============================================
router.post('/delete-account', authenticate, sensitiveActionLimiter, async (req, res) => {
  try {
    const { password } = req.body;
    if (!password) {
      return res.status(400).json({ success: false, message: 'Password is required to delete account.' });
    }

    const user = statements.findUserById.get({ id: req.user.id });
    if (!await argon2.verify(user.password_hash, password)) {
      const locked = await registerSensitiveActionFailure(
        user,
        req,
        'delete_account_invalid_password',
        'delete_account_failed_password'
      );
      if (locked) {
        return res.status(423).json({
          success: false,
          message: 'Too many failed attempts. Account locked for 30 minutes.',
        });
      }
      return res.status(401).json({ success: false, message: 'Incorrect password.' });
    }

    db.transaction(() => {
      statements.bumpSessionVersion.run({ id: user.id });
      statements.revokeAllUserRefreshTokens.run({ userId: user.id });
      statements.deleteUser.run({ id: user.id });
    })();
    
    res.clearCookie('access_token', { path: '/' });
    res.clearCookie('refresh_token', { path: '/' });

    logSecurityEvent('account_deleted', { userId: user.id, email: user.email });

    res.json({ success: true, message: 'Account deleted successfully.' });
  } catch (error) {
    console.error('Delete account error:', error);
    res.status(500).json({ success: false, message: 'An error occurred.' });
  }
});

module.exports = router;
