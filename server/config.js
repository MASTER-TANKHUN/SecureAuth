require('dotenv').config();
const crypto = require('crypto');

// Helper function for required keys to prevent accidental production leaks
function requireInProduction(envVar, name) {
  const value = process.env[envVar];
  if (!value) {
    if (process.env.NODE_ENV === 'production') {
      throw new Error(`FATAL: ${name} must be set in production via ${envVar} environment variable!`);
    }
    console.warn(`⚠️  WARNING: ${name} not set. Generating a random one-time secret for development. SESSIONS WILL NOT PERSIST ACROSS RESTARTS!`);
    // Generate a random 32-byte secret for dev if missing
    return crypto.randomBytes(32).toString('hex');
  }
  return value;
}

module.exports = {
  port: process.env.PORT || 3000,
  nodeEnv: process.env.NODE_ENV || 'development',

  jwt: {
    secret: requireInProduction('JWT_SECRET', 'JWT_SECRET'),
    expiresIn: process.env.JWT_EXPIRES_IN || '15m',
    refreshExpiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '7d',
  },

  argon2: {
    timeCost: parseInt(process.env.ARGON2_TIME_COST, 10) || 3,
    memoryCost: parseInt(process.env.ARGON2_MEMORY_COST, 10) || 65536,
    parallelism: parseInt(process.env.ARGON2_PARALLELISM, 10) || 4,
  },

  email: {
    host: process.env.SMTP_HOST,
    port: parseInt(process.env.SMTP_PORT, 10) || 587,
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
    from: process.env.EMAIL_FROM || 'noreply@secureauth.app',
  },

  rateLimit: {
    windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS, 10) || 900000,
    maxAttempts: parseInt(process.env.RATE_LIMIT_MAX_ATTEMPTS, 10) || 5,
  },

  encryptionKey: requireInProduction('ENCRYPTION_KEY', 'ENCRYPTION_KEY'),
  hkdfSalt: requireInProduction('HKDF_SALT', 'HKDF_SALT'),
  csrfSecret: requireInProduction('CSRF_SECRET', 'CSRF_SECRET'),
  appUrl: process.env.APP_URL || 'http://localhost:3000',
};
