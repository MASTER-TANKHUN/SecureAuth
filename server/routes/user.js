const express = require('express');
const { authenticate } = require('../middleware/auth');
const { statements } = require('../models/db');

const router = express.Router();

// ============================================
// GET CURRENT USER PROFILE
// ============================================
router.get('/me', authenticate, (req, res) => {
  res.json({
    success: true,
    user: req.user,
  });
});

// ============================================
// GET LOGIN HISTORY
// ============================================
router.get('/login-history', authenticate, (req, res) => {
  try {
    const logs = statements.getRecentLoginLogs.all({ userId: req.user.id });

    const formattedLogs = logs.map((log) => ({
      id: log.id,
      ipAddress: log.ip_address,
      userAgent: log.user_agent,
      success: !!log.success,
      failureReason: log.failure_reason,
      timestamp: log.created_at,
    }));

    res.json({
      success: true,
      logs: formattedLogs,
    });
  } catch (error) {
    console.error('Login history error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to retrieve login history.',
    });
  }
});

module.exports = router;
