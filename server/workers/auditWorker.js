const { Worker } = require('bullmq');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { db, statements } = require('../models/db');
const config = require('../config');

const connection = {
  host: process.env.REDIS_HOST || '127.0.0.1',
  port: process.env.REDIS_PORT || 6379,
};

const BATCH_SIZE = 50;
const BATCH_TIMEOUT_MS = 100;

let batch = [];
let resolvers = [];
let flushTimer = null;

// ============================================
// ECDSA Key for signing Critical Events
// ============================================

// Load keys from environment variables
let privateKey = process.env.AUDIT_SIGNING_PRIVATE_KEY_PEM;
let publicKeyPem = process.env.AUDIT_SIGNING_PUBLIC_KEY_PEM;

// Production: Must have keys configured
if (config.nodeEnv === 'production') {
  if (!privateKey || !publicKeyPem) {
    throw new Error(
      'AUDIT_SIGNING_PRIVATE_KEY_PEM and AUDIT_SIGNING_PUBLIC_KEY_PEM must be set in production. ' +
      'Run: node generate-audit-keys.js to generate keys.'
    );
  }
}
// Development: Generate ephemeral keys if not provided (with .gitignore safety check)
else {
  if (!privateKey) {
    // SECURITY: Check .gitignore before generating ephemeral keys
    const gitignorePath = path.join(__dirname, '../../.gitignore');
    let gitignoreOk = false;

    try {
      if (fs.existsSync(gitignorePath)) {
        const gitignore = fs.readFileSync(gitignorePath, 'utf8');
        // Check for exact match or wildcard pattern
        gitignoreOk = gitignore.includes('.audit-keys-temp.pem') ||
                      gitignore.includes('*.pem.key') ||
                      gitignore.includes('audit-keys-*.pem');
      }
    } catch (e) {
      // If we can't read .gitignore, be conservative
    }

    if (!gitignoreOk) {
      console.error('[AUDIT] ❌ SECURITY ERROR: .audit-keys-temp.pem is not in .gitignore');
      console.error('[AUDIT] Add the following to your .gitignore file:');
      console.error('[AUDIT]   .audit-keys-temp.pem');
      console.error('[AUDIT]   *.pem.key');
      console.error('[AUDIT] Or run: echo ".audit-keys-temp.pem" >> .gitignore');
      throw new Error(
        'Refusing to create ephemeral audit key file because it is not in .gitignore. ' +
        'This prevents accidental commit of private keys to version control. ' +
        'Add ".audit-keys-temp.pem" to .gitignore and restart.'
      );
    }

    console.warn('[AUDIT] AUDIT_SIGNING_PRIVATE_KEY_PEM not set. Generating ephemeral keys for development.');
    console.warn('[AUDIT] Signatures will NOT persist across restarts and will NOT be verifiable after restart.');

    const keyObj = crypto.generateKeyPairSync('ec', {
      namedCurve: 'prime256v1'
    });

    privateKey = keyObj.privateKey.export({ type: 'sec1', format: 'pem' });
    publicKeyPem = keyObj.publicKey.export({ type: 'spki', format: 'pem' });

    // Save to temp file for this session (with strict permissions)
    const tempKeyPath = path.join(__dirname, '../../.audit-keys-temp.pem');
    fs.writeFileSync(tempKeyPath, privateKey, { mode: 0o600 });
    console.warn(`[AUDIT] Ephemeral private key saved to: ${tempKeyPath} (protected by .gitignore)`);
    console.warn('[AUDIT] This file will be regenerated on each restart. DO NOT COMMIT IT.');
  }
}

// Derive key version from public key fingerprint
const keyFingerprint = crypto
  .createHash('sha256')
  .update(publicKeyPem)
  .digest('hex')
  .slice(0, 16);
const CURRENT_KEY_VERSION = `ec-p256-${keyFingerprint}`;

// Save the Public Key for future verification (INSERT OR REPLACE for key rotation)
try {
  statements.insertSignatureKey.run({
    keyVersion: CURRENT_KEY_VERSION,
    publicKeyPem: publicKeyPem
  });
  console.log(`[AUDIT] Using signing key version: ${CURRENT_KEY_VERSION}`);
} catch (err) {
  console.error('[AUDIT] Failed to initialize signature_keys:', err.message);
}

// Rule-set for critical events that require Digital Signature
const CRITICAL_EVENTS = new Set([
  'login_success',
  'login_failed_locked',
  'account_locked_login',
  'mfa_enabled',
  'mfa_disabled',
  'password_changed',
  'impossible_travel_detected'
]);

async function flushBatch() {
  if (batch.length === 0) return;
  
  const currentBatch = batch;
  const currentResolvers = resolvers;
  batch = [];
  resolvers = [];
  clearTimeout(flushTimer);
  flushTimer = null;

  try {
    // 1. Execute all logs in a single SQLite Transaction
    const tx = db.transaction((items) => {
      // 2. Lock state and fetch last hash (Sequential guarantee)
      const state = statements.getLogChainState.get();
      let currentHash = state ? state.last_hash : 'GENESIS_HASH_0000000000000000000000000';

      for (const item of items) {
        const data = item.data;
        const payloadStr = JSON.stringify(data.payload || {});
        
        let signature = null;
        let keyVersion = null;

        // 3. Apply Digital Signature to Critical Events (Preventing Key Confusion)
        if (CRITICAL_EVENTS.has(data.eventType)) {
          const sign = crypto.createSign('SHA256');
          // Add keyVersion to the signed payload to prevent key confusion attacks
          sign.update(data.eventType + payloadStr + currentHash + CURRENT_KEY_VERSION);
          sign.end();
          signature = sign.sign(privateKey, 'hex');
          keyVersion = CURRENT_KEY_VERSION;
        }

        // 4. Calculate new Hash in the chain
        const dataToHash = currentHash + payloadStr + (signature || '') + data.eventType;
        const newHash = crypto.createHash('sha256').update(dataToHash).digest('hex');

        // 5. Insert Log
        statements.insertAuditLog.run({
          eventType: data.eventType,
          userId: data.userId,
          ipAddress: data.ipAddress,
          userAgent: data.userAgent,
          payload: payloadStr,
          previousHash: currentHash,
          currentHash: newHash,
          signature,
          keyVersion
        });

        currentHash = newHash; // Carry forward the chain
      }

      // 6. Update Final Chain State
      statements.updateLogChainState.run({ lastHash: currentHash });
    });

    tx(currentBatch);

    // Resolve all BullMQ jobs successfully ONLY AFTER transaction is committed
    currentResolvers.forEach(res => res.resolve());

  } catch (error) {
    console.error('Audit Batch processing failed:', error);
    // Reject all jobs in this batch so they retry or go to Dead Letter Queue
    currentResolvers.forEach(res => res.reject(error));
  }
}

// 7. Initialize BullMQ Worker with Concurrency = BATCH_SIZE
const auditWorker = new Worker('auditLogs', async job => {
  return new Promise((resolve, reject) => {
    batch.push(job);
    resolvers.push({ resolve, reject });

    if (batch.length >= BATCH_SIZE) {
      if (flushTimer) clearTimeout(flushTimer);
      flushBatch();
    } else if (!flushTimer) {
      flushTimer = setTimeout(flushBatch, BATCH_TIMEOUT_MS);
    }
  });
}, { 
  connection,
  concurrency: BATCH_SIZE 
});

auditWorker.on('failed', (job, err) => {
  console.error(`Audit Job ${job.id} failed:`, err.message);
});

module.exports = auditWorker;
