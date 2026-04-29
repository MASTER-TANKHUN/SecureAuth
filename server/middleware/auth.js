const { verifyAccessToken } = require('../utils/token');
const { statements } = require('../models/db');

/**
 * Authentication middleware
 * Verifies JWT from HttpOnly cookie
 */
function authenticate(req, res, next) {
  const token = req.cookies?.access_token;

  if (!token) {
    return res.status(401).json({
      success: false,
      message: 'Authentication required. Please log in.',
    });
  }

  const decoded = verifyAccessToken(token);
  if (!decoded) {
    return res.status(401).json({
      success: false,
      message: 'Invalid or expired authentication token. Please log in again.',
      code: 'INVALID_TOKEN',
    });
  }

  if (decoded.type !== 'access') {
    return res.status(401).json({
      success: false,
      message: 'Invalid authentication token. Please log in again.',
      code: 'INVALID_TOKEN',
    });
  }

  // Attach user info to request
  const user = statements.findUserById.get({ id: decoded.sub });
  if (!user) {
    return res.status(401).json({
      success: false,
      message: 'User not found. Please log in again.',
      code: 'USER_NOT_FOUND',
    });
  }

  // หมายเหตุ: ไม่ตรวจสอบ user.locked_until ใน middleware เพื่อป้องกันไม่ให้แฮกเกอร์โจมตีแบบ DoS เตะผู้ใช้ปัจจุบันออกจากระบบ

  const tokenSessionVersion = Number(decoded.sessionVersion ?? 0);
  const currentSessionVersion = Number(user.session_version ?? 0);
  if (tokenSessionVersion !== currentSessionVersion) {
    return res.status(401).json({
      success: false,
      message: 'Authentication session has expired. Please log in again.',
      code: 'TOKEN_REVOKED',
    });
  }

  const userAgent = req.headers['user-agent'] || 'Unknown';
  const crypto = require('crypto');
  const currentUaHash = crypto.createHash('sha256').update(userAgent).digest('hex');

  // If the token contains a User-Agent hash, compare it
  if (decoded.uaHash && decoded.uaHash !== currentUaHash) {
    const ipAddress = req.ip || req.connection.remoteAddress;
    statements.createLoginLog.run({
      userId: user.id,
      ipAddress,
      userAgent,
      success: 0,
      failureReason: 'session_hijack_attempt_ua_mismatch',
    });
    
    // SOFT CHECK: We flag it for downstream controllers instead of hard blocking
    // to prevent False Positives from minor browser updates.
    req.uaMismatch = true;
  }

  req.user = {
    id: user.id,
    email: user.email,
    username: user.username,
    isVerified: user.is_verified,
    mfaEnabled: user.mfa_enabled,
  };

  next();
}

module.exports = { authenticate };
