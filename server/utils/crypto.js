const crypto = require('crypto');
const argon2 = require('argon2');
const config = require('../config');

// Use AES-256-GCM for encryption
const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12;

/**
 * Encrypt sensitive string data
 */
function encrypt(text) {
  const iv = crypto.randomBytes(IV_LENGTH);
  const encryptionKey = deriveEncryptionKey(config.encryptionKey);
  const cipher = crypto.createCipheriv(ALGORITHM, encryptionKey, iv);
  
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  
  const authTag = cipher.getAuthTag().toString('hex');
  
  // Return IV + AuthTag + EncryptedData
  return `${iv.toString('hex')}:${authTag}:${encrypted}`;
}

/**
 * Decrypt sensitive string data
 */
function decrypt(data) {
  try {
    const [ivHex, authTagHex, encryptedHex] = data.split(':');
    const iv = Buffer.from(ivHex, 'hex');
    const authTag = Buffer.from(authTagHex, 'hex');
    const encryptionKey = deriveEncryptionKey(config.encryptionKey);
    const decipher = crypto.createDecipheriv(ALGORITHM, encryptionKey, iv);
    
    decipher.setAuthTag(authTag);
    
    let decrypted = decipher.update(encryptedHex, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
  } catch (err) {
    console.error('Decryption failed:', err.message);
    return null;
  }
}

/**
 * Derive encryption key using HKDF-SHA256
 * Returns a 32-byte key for AES-256-GCM
 */
function deriveEncryptionKey(secret) {
  // M2 Fix: Use a static non-zero salt for HKDF
  const salt = crypto.createHash('sha256').update('secureauth-encryption-salt').digest();
  return crypto.hkdfSync('sha256', Buffer.from(secret), salt, 'encryption', 32);
}

/**
 * Hash data for storage (e.g. refresh tokens) using Argon2id
 * IMPORTANT: This is async.
 */
async function hashToken(token) {
  return await argon2.hash(token, {
    type: argon2.argon2id,
    timeCost: 2,           // Slightly lower than passwords for efficiency
    memoryCost: 19456,     // ~19MB
    parallelism: 1,
  });
}

/**
 * Verify a token against its Argon2 hash
 */
async function verifyToken(token, hash) {
  try {
    return await argon2.verify(hash, token);
  } catch (err) {
    return false;
  }
}

module.exports = { encrypt, decrypt, hashToken, verifyToken, deriveEncryptionKey };
