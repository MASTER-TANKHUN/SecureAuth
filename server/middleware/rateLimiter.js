/* 
  Rate limiting protection 
  Developed by MasterT
*/
const rateLimit = require('express-rate-limit');

const loginLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 15,
  message: { success: false, message: 'Too many login attempts. Try again in 10 mins.', retryAfter: 600 },
  standardHeaders: true,
  legacyHeaders: false,
});

const registerLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 10,
  message: { success: false, message: 'Registration limit reached. Try again in 10 mins.' },
  standardHeaders: true,
  legacyHeaders: false,
});

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
});

const mfaAttemptLimiter = rateLimit({
  windowMs: 1 * 60 * 1000,
  max: 5,
  skipSuccessfulRequests: true,
  message: { success: false, message: 'Too many MFA attempts.', retryAfter: 60 },
  standardHeaders: true,
  legacyHeaders: false,
});

const refreshLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
});

const verifyEmailLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
});

const forgotPasswordLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 3,
  message: { success: false, message: 'Limit reached. Try again in an hour.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// M3 Fix: Email-based rate limiter to mitigate account lockout DoS
const emailLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5,
  message: { success: false, message: 'Too many attempts for this account. Please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    const email = (req.body.email || '').toLowerCase().trim();
    return `email-${email}`;
  },
  skipSuccessfulRequests: true,
});

const sensitiveActionLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => `sensitive-${req.user?.id || 'guest'}-${req.ip}`,
});

module.exports = {
  loginLimiter,
  registerLimiter,
  apiLimiter,
  mfaAttemptLimiter,
  refreshLimiter,
  verifyEmailLimiter,
  forgotPasswordLimiter,
  emailLimiter,
  sensitiveActionLimiter,
};
