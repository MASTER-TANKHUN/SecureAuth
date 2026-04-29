const { Worker } = require('bullmq');
const crypto = require('crypto');
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

// ECDSA Key for signing Critical Events
// In production, load from KMS or Vault. Using a hardcoded demo key for portfolio purposes.
const privateKeyObj = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const privateKey = privateKeyObj.privateKey.export({ type: 'sec1', format: 'pem' });
const publicKeyPem = privateKeyObj.publicKey.export({ type: 'spki', format: 'pem' });
const CURRENT_KEY_VERSION = 'v1';

// Save the Public Key for future verification (Phase 4 readiness)
try {
  statements.insertSignatureKey.run({
    keyVersion: CURRENT_KEY_VERSION,
    publicKeyPem: publicKeyPem
  });
} catch (err) {
  console.error('Failed to initialize signature_keys:', err.message);
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
