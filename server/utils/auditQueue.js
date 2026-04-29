const { Queue } = require('bullmq');

const connection = {
  host: process.env.REDIS_HOST || '127.0.0.1',
  port: process.env.REDIS_PORT || 6379,
};

// Create the Audit Logs queue
const auditQueue = new Queue('auditLogs', { 
  connection,
  defaultJobOptions: {
    attempts: 3,
    backoff: {
      type: 'exponential',
      delay: 1000,
    },
    removeOnComplete: true,
    removeOnFail: false, // Keep failed jobs for Dead Letter Queue investigation
  }
});

/**
 * Enqueue an audit log asynchronously
 * @param {string} eventType - The type of security event
 * @param {object} payload - Additional details (will be JSON stringified)
 * @param {object} context - { userId, ipAddress, userAgent }
 */
async function enqueueAuditLog(eventType, payload, context = {}) {
  try {
    await auditQueue.add('logEvent', {
      eventType,
      payload,
      userId: context.userId || null,
      ipAddress: context.ipAddress || null,
      userAgent: context.userAgent || null,
      timestamp: Date.now()
    });
  } catch (error) {
    console.error('CRITICAL: Failed to enqueue audit log to Redis', error);
    // In an enterprise system, write to a local fallback buffer file here
  }
}

module.exports = { auditQueue, enqueueAuditLog };
