/* 
  Rate limiting protection 
  Developed by MasterT
*/
const rateLimit = require('express-rate-limit');

const loginLimiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_LOGIN_WINDOW_MS) || 10 * 60 * 1000,
  max: parseInt(process.env.RATE_LIMIT_LOGIN) || 15,
  message: { success: false, message: 'Too many login attempts. Try again in 10 mins.', retryAfter: 600 },
  standardHeaders: true,
  legacyHeaders: false,
});

const registerLimiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_REGISTER_WINDOW_MS) || 10 * 60 * 1000,
  max: parseInt(process.env.RATE_LIMIT_REGISTER) || 10,
  message: { success: false, message: 'Registration limit reached. Try again in 10 mins.' },
  standardHeaders: true,
  legacyHeaders: false,
});

const apiLimiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_API_WINDOW_MS) || 15 * 60 * 1000,
  max: parseInt(process.env.RATE_LIMIT_API) || 100,
  standardHeaders: true,
  legacyHeaders: false,
});

const mfaAttemptLimiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_MFA_WINDOW_MS) || 1 * 60 * 1000,
  max: parseInt(process.env.RATE_LIMIT_MFA) || 5,
  skipSuccessfulRequests: true,
  message: { success: false, message: 'Too many MFA attempts.', retryAfter: 60 },
  standardHeaders: true,
  legacyHeaders: false,
});

const refreshLimiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_REFRESH_WINDOW_MS) || 15 * 60 * 1000,
  max: parseInt(process.env.RATE_LIMIT_REFRESH) || 20,
  standardHeaders: true,
  legacyHeaders: false,
});

const verifyEmailLimiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_VERIFY_EMAIL_WINDOW_MS) || 15 * 60 * 1000,
  max: parseInt(process.env.RATE_LIMIT_VERIFY_EMAIL) || 10,
  standardHeaders: true,
  legacyHeaders: false,
});

const forgotPasswordLimiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_FORGOT_PASSWORD_WINDOW_MS) || 60 * 60 * 1000,
  max: parseInt(process.env.RATE_LIMIT_FORGOT_PASSWORD) || 3,
  message: { success: false, message: 'Limit reached. Try again in an hour.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// M3 Fix: Email-based rate limiter to mitigate account lockout DoS
const emailLimiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_EMAIL_WINDOW_MS) || 15 * 60 * 1000, // 15 minutes
  max: parseInt(process.env.RATE_LIMIT_EMAIL) || 5,
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
  windowMs: parseInt(process.env.RATE_LIMIT_SENSITIVE_WINDOW_MS) || 15 * 60 * 1000,
  max: parseInt(process.env.RATE_LIMIT_SENSITIVE) || 10,
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
