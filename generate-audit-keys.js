#!/usr/bin/env node
/**
 * Generate ECDSA P-256 key pair for audit log signing
 * Usage: node generate-audit-keys.js
 */
const crypto = require('crypto');

const keyPair = crypto.generateKeyPairSync('ec', {
  namedCurve: 'prime256v1'
});

const privateKey = keyPair.privateKey.export({ type: 'sec1', format: 'pem' });
const publicKey = keyPair.publicKey.export({ type: 'spki', format: 'pem' });

const fingerprint = crypto
  .createHash('sha256')
  .update(publicKey)
  .digest('hex')
  .slice(0, 16);

console.log('========================================');
console.log('Audit Log Signing Keys Generated');
console.log('========================================');
console.log(`Key Version: ec-p256-${fingerprint}`);
console.log('');
console.log('Add these to your .env file:');
console.log('');
console.log('AUDIT_SIGNING_PRIVATE_KEY_PEM="' + privateKey.trim() + '"');
console.log('');
console.log('AUDIT_SIGNING_PUBLIC_KEY_PEM="' + publicKey.trim() + '"');
console.log('');
console.log('⚠️  WARNING: Keep the private key secret!');
console.log('⚠️  WARNING: In production, use a KMS or HSM instead.');
