const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const config = require('../config');

/**
 * Generate an access token (short-lived JWT)
 */
function generateAccessToken(user) {
  const payload = {
    sub: user.id,
    email: user.email,
    username: user.username,
    type: 'access',
    sessionVersion: Number(user.session_version ?? 0),
  };
  return jwt.sign(payload, config.jwt.secret, {
    expiresIn: config.jwt.expiresIn,
  });
}

/**
 * Generate a refresh token (long-lived, stored in DB)
 */
function generateRefreshToken() {
  return uuidv4();
}

/**
 * Verify and decode an access token
 */
function verifyAccessToken(token) {
  try {
    return jwt.verify(token, config.jwt.secret);
  } catch (err) {
    return null;
  }
}

/**
 * Generate a random verification token for email or password reset
 */
function generateVerificationToken() {
  return uuidv4();
}

const crypto = require('crypto');
/**
 * Generate MFA backup codes using CSPRNG
 */
function generateBackupCodes() {
  const codes = [];
  for (let i = 0; i < 8; i++) {
    // L4 Fix: Increase entropy to 6 bytes (48 bits)
    codes.push(crypto.randomBytes(6).toString('hex').toUpperCase());
  }
  return codes;
}

module.exports = {
  generateAccessToken,
  generateRefreshToken,
  verifyAccessToken,
  generateVerificationToken,
  generateBackupCodes,
};
