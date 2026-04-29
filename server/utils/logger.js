const fs = require('fs');
const path = require('path');
const { enqueueAuditLog } = require('./auditQueue');

const LOG_FILE = path.join(__dirname, '..', '..', 'security.log');

/**
 * Log a security event to the security log file and BullMQ
 * @param {string} event - Type of event (e.g., 'login_failed', 'mfa_disabled')
 * @param {object} data - Metadata associated with the event
 */
function logSecurityEvent(event, data = {}) {
  // 1. Send to Redis / BullMQ for Hash Chaining & Signing
  enqueueAuditLog(event, data, {
    userId: data.userId || null,
    ipAddress: data.ipAddress || null,
    userAgent: data.userAgent || null
  });

  // 2. Local Fallback (Append-only Log)
  const logEntry = {
    timestamp: new Date().toISOString(),
    event,
    ...data,
  };

  const logString = JSON.stringify(logEntry) + '\n';

  try {
    fs.appendFileSync(LOG_FILE, logString);
  } catch (err) {
    console.error('Failed to write to security log:', err.message);
  }

  // Also log to console in development
  if (process.env.NODE_ENV !== 'production') {
    console.log(`[SECURITY EVENT] ${event}:`, data);
  }
}

module.exports = { logSecurityEvent };
