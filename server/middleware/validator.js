/* 
  Input validation & sanitization 
  Developed by MasterT
*/

function sanitize(str) {
  if (typeof str !== 'string') return str;
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;')
    .replace(/\//g, '&#x2F;');
}

function isValidEmail(email) {
  const emailRegex = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
  return emailRegex.test(email) && email.length <= 254;
}

function isValidUsername(username) {
  return /^[a-zA-Z0-9_-]{3,30}$/.test(username);
}

// Password rules: 8+ chars, upper, lower, digit, special
function validatePasswordStrength(password) {
  const errors = [];
  if (password.length < 8) errors.push('Password must be at least 8 characters');
  if (password.length > 128) errors.push('Password too long');
  if (!/[A-Z]/.test(password)) errors.push('Needs one uppercase letter');
  if (!/[a-z]/.test(password)) errors.push('Needs one lowercase letter');
  if (!/[0-9]/.test(password)) errors.push('Needs one number');
  if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) errors.push('Needs one special character');

  return { isValid: errors.length === 0, errors };
}

// Registration validation middleware
function validateRegistration(req, res, next) {
  const { email, username, password } = req.body;
  const errors = [];

  if (!email || !isValidEmail(email)) errors.push('Invalid email address');
  if (!username || !isValidUsername(username)) errors.push('Username: 3-30 chars, alphanumeric, _ or - only');

  if (!password) {
    errors.push('Password is required');
  } else {
    const pw = validatePasswordStrength(password);
    if (!pw.isValid) errors.push(...pw.errors);
  }

  if (errors.length > 0) return res.status(400).json({ success: false, message: 'Validation failed', errors });

  req.body.email = email.toLowerCase().trim();
  req.body.username = sanitize(username.trim());
  next();
}

// Login validation middleware
function validateLogin(req, res, next) {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ success: false, message: 'Email and password required' });

  // Limit password length for Argon2 DoS protection
  if (password.length > 128) return res.status(400).json({ success: false, message: 'Invalid credentials' });

  req.body.email = email.toLowerCase().trim();
  next();
}

module.exports = {
  sanitize,
  isValidEmail,
  isValidUsername,
  validatePasswordStrength,
  validateRegistration,
  validateLogin,
};
