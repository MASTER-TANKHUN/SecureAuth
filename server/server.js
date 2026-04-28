const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const path = require('path');
const crypto = require('crypto');

let morgan = null;
try {
  morgan = require('morgan');
} catch (err) {
  console.warn('Morgan not installed; request logging disabled.');
}

const config = require('./config');
const { db, statements } = require('./models/db');
const { apiLimiter } = require('./middleware/rateLimiter');
const authRoutes = require('./routes/auth');
const userRoutes = require('./routes/user');

const app = express();
const csrfCookieName = '__CSRF-Token';
const csrfTokenPattern = /^[A-Za-z0-9_-]{43}$/;
const signedCsrfCookiePattern = /^[A-Za-z0-9_-]{43}\.[A-Za-z0-9_-]{43}$/;
const csrfCookieOptions = {
  httpOnly: true,
  secure: config.nodeEnv === 'production',
  sameSite: 'strict',
  path: '/',
};

function signCsrfToken(token) {
  return crypto.createHmac('sha256', config.csrfSecret).update(token).digest('base64url');
}

function safeEqualString(left, right) {
  if (typeof left !== 'string' || typeof right !== 'string') {
    return false;
  }

  try {
    return crypto.timingSafeEqual(Buffer.from(left), Buffer.from(right));
  } catch (err) {
    return false;
  }
}

function parseSignedCsrfCookie(cookieValue) {
  if (typeof cookieValue !== 'string' || !signedCsrfCookiePattern.test(cookieValue)) {
    return null;
  }

  const [token, signature] = cookieValue.split('.');
  if (!csrfTokenPattern.test(token) || !csrfTokenPattern.test(signature)) {
    return null;
  }

  return { token, signature };
}

function issueCsrfToken(req, res) {
  const existingToken = parseSignedCsrfCookie(req.cookies?.[csrfCookieName]);
  if (existingToken && safeEqualString(signCsrfToken(existingToken.token), existingToken.signature)) {
    return existingToken.token;
  }

  const token = crypto.randomBytes(32).toString('base64url');
  const signature = signCsrfToken(token);
  res.cookie(csrfCookieName, `${token}.${signature}`, csrfCookieOptions);
  return token;
}

function validateCsrfToken(req) {
  const cookieToken = parseSignedCsrfCookie(req.cookies?.[csrfCookieName]);
  const headerToken = req.get('x-csrf-token') || req.get('csrf-token');

  if (
    !cookieToken ||
    !headerToken ||
    !csrfTokenPattern.test(headerToken)
  ) {
    return false;
  }

  const expectedSignature = signCsrfToken(cookieToken.token);
  if (!safeEqualString(expectedSignature, cookieToken.signature)) {
    return false;
  }

  return safeEqualString(cookieToken.token, headerToken);
}

// ============================================
// Security Headers (Helmet)
// ============================================
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"], // Removed 'unsafe-inline'
        styleSrc: ["'self'", 'https://fonts.googleapis.com'],
        fontSrc: ["'self'", 'https://fonts.gstatic.com'],
        imgSrc: ["'self'", 'data:', 'https:'],
        connectSrc: ["'self'"],
        frameAncestors: ["'none'"],
        objectSrc: ["'none'"],
      },
    },
    crossOriginEmbedderPolicy: false,
    strictTransportSecurity: {
      maxAge: 31536000,
      includeSubDomains: true,
      preload: true
    },
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
    permissionsPolicy: {
      features: {
        camera: ["'none'"],
        microphone: ["'none'"],
        geolocation: ["'none'"],
      }
    }
  })
);

// ============================================
// Middleware
// ============================================
if (morgan) {
  app.use(morgan('combined'));
}

app.use(cors({
  origin: config.appUrl,
  credentials: true,
}));

// Parse cookies early because CSRF validation uses cookies
app.use(cookieParser());

const csrfProtectionMiddleware = (req, res, next) => {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
  if (!validateCsrfToken(req)) {
    return res.status(403).json({ success: false, message: 'Invalid CSRF token', code: 'CSRF_ERROR' });
  }
  next();
};

const jsonOnly = (req, res, next) => {
  if (req.method !== 'GET' && req.method !== 'DELETE' && !req.is('application/json')) {
    return res.status(415).json({ success: false, message: 'Content-Type must be application/json' });
  }
  next();
};

app.use('/api', jsonOnly);

// Body parsers before CSRF so req.body is available for token validation
app.use(express.json({ limit: '1kb' })); // Limit body size

// Apply CSRF to state-changing API routes after body parsing
app.post('/api/*', csrfProtectionMiddleware);
app.put('/api/*', csrfProtectionMiddleware);
app.delete('/api/*', csrfProtectionMiddleware);

// Trust proxy for rate limiting behind reverse proxy — only trusted IPs
app.set('trust proxy', ['127.0.0.1', process.env.PROXY_IP].filter(Boolean));

// Static files
app.use(express.static(path.join(__dirname, '..', 'public')));

// General API rate limiter
app.use('/api', apiLimiter);

// ============================================
// Routes
// ============================================
app.use('/api/auth', authRoutes);
app.use('/api/user', userRoutes);

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'OK' });
});

// CSRF Token endpoint
app.get('/api/csrf-token', (req, res) => {
  try {
    const token = issueCsrfToken(req, res);
    res.set('Cache-Control', 'no-store');
    res.json({ csrfToken: token });
  } catch (err) {
    console.error('Failed to generate CSRF token:', err.message);
    res.status(500).json({ success: false, message: 'Failed to generate CSRF token.' });
  }
});

// ============================================
// Serve SPA for all other routes
// ============================================
app.get('*', (req, res) => {
  if (req.accepts('html')) {
    res.sendFile(path.join(__dirname, '..', 'public', 'index.html'));
  } else {
    res.status(404).json({ success: false, message: 'Not Found' });
  }
});

// ============================================
// Error Handler
// ============================================
app.use((err, req, res, next) => {
  if (err.code === 'EBADCSRFTOKEN') {
    return res.status(403).json({
      success: false,
      message: 'Invalid or missing CSRF token.',
      code: 'CSRF_ERROR'
    });
  }
  
  console.error('Unhandled error:', err);
  res.status(500).json({
    success: false,
    message: 'An internal server error occurred.',
  });
});

// ============================================
// Start Server
// ============================================
function startServer() {
  return app.listen(config.port, () => {
  console.log(`
  ╔══════════════════════════════════════════╗
  ║     🔐 SecureAuth Server Running        ║
  ║                                          ║
  ║  → Local:  http://localhost:${config.port}        ║
  ║  → Mode:   ${config.nodeEnv.padEnd(25)}║
  ║                                          ║
  ║  Security Features:                      ║
  ║  ✓ Argon2id password hashing             ║
  ║  ✓ JWT in HttpOnly cookies               ║
  ║  ✓ Rate limiting enabled                 ║
  ║  ✓ Helmet security headers               ║
  ║  ✓ TOTP MFA support                      ║
  ║  ✓ Input validation & sanitization       ║
  ╚══════════════════════════════════════════╝
  `);
  });
}

// ============================================
// Token Cleanup Job
// ============================================
function startTokenCleanup() {
  const cleanupInterval = 60 * 60 * 1000; // 1 hour
  return setInterval(() => {
    try {
      const now = new Date().toISOString();
      const delVerify = statements.deleteExpiredVerificationTokens.run({ expiresAt: now });
      const delRefresh = statements.deleteExpiredRefreshTokens.run({ expiresAt: now });
      console.log(`✅ Token cleanup: ${delVerify.changes} verification, ${delRefresh.changes} refresh deleted`);
    } catch (err) {
      console.error('❌ Token cleanup error:', err.message);
    }
  }, cleanupInterval);
}

let cleanupHandle = null;

if (require.main === module) {
  cleanupHandle = startTokenCleanup();
  startServer();
}

module.exports = {
  app,
  startServer,
  startTokenCleanup,
  getCleanupHandle: () => cleanupHandle,
};
