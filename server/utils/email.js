/* 
  Email delivery utility
  Developed by MasterT
*/
const nodemailer = require('nodemailer');
const config = require('../config');

let transporter = null;

// Initialize SMTP transporter
async function getTransporter() {
  if (transporter) return transporter;

  // Use Ethereal for dev if no SMTP user provided
  if (config.nodeEnv === 'development' && !config.email.user) {
    const testAccount = await nodemailer.createTestAccount();
    transporter = nodemailer.createTransport({
      host: 'smtp.ethereal.email',
      port: 587,
      secure: false,
      auth: { user: testAccount.user, pass: testAccount.pass },
    });
    console.log('📧 Ethereal account:', testAccount.user);
  } else {
    transporter = nodemailer.createTransport({
      host: config.email.host,
      port: config.email.port,
      secure: config.email.port === 465,
      auth: { user: config.email.user, pass: config.email.pass },
    });
  }
  return transporter;
}

function escapeHtml(text) {
  if (!text) return '';
  return String(text).replace(/[&<>"']/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":"&#39;"}[m]));
}

// Log links to console in dev mode
function devLog(title, url) {
  if (config.nodeEnv === 'development') {
    console.log(`\n--- ${title} ---\n${url}\n----------------\n`);
  }
}

async function sendVerificationEmail(to, token) {
  const transport = await getTransporter();
  const url = `${config.appUrl}/verify.html#token=${token}`;
  devLog('Verification Link', url);
  const safeUrl = escapeHtml(url);

  return transport.sendMail({
    from: `"SecureAuth" <${config.email.from}>`,
    to,
    subject: 'Verify your email',
    html: `<p>Click to verify: <a href="${safeUrl}">${safeUrl}</a></p>`,
  });
}

async function sendPasswordResetEmail(to, token) {
  const transport = await getTransporter();
  const url = `${config.appUrl}/reset-password.html#token=${token}`;
  devLog('Password Reset Link', url);
  const safeUrl = escapeHtml(url);

  return transport.sendMail({
    from: `"SecureAuth" <${config.email.from}>`,
    to,
    subject: 'Reset your password',
    html: `<p>Click to reset: <a href="${safeUrl}">${safeUrl}</a></p>`,
  });
}

async function sendMfaDisableEmail(to, token) {
  const transport = await getTransporter();
  const url = `${config.appUrl}/mfa-disable.html#token=${token}`;
  devLog('MFA Disable Link', url);
  const safeUrl = escapeHtml(url);

  return transport.sendMail({
    from: `"SecureAuth" <${config.email.from}>`,
    to,
    subject: 'Confirm MFA disable',
    html: `<p>Click to confirm: <a href="${safeUrl}">${safeUrl}</a></p>`,
  });
}

async function sendLockoutAlertEmail(to, ip) {
  const transport = await getTransporter();
  return transport.sendMail({
    from: `"SecureAuth" <${config.email.from}>`,
    to,
    subject: 'Security Alert: Account Locked',
    html: `<p>Account locked due to failed attempts from IP: ${escapeHtml(ip)}</p>`,
  });
}

async function sendPasswordChangeAlertEmail(to, ip) {
  const transport = await getTransporter();
  return transport.sendMail({
    from: `"SecureAuth" <${config.email.from}>`,
    to,
    subject: 'Password Changed',
    html: `<p>Your password was changed from IP: ${escapeHtml(ip)}</p>`,
  });
}

module.exports = {
  sendVerificationEmail,
  sendPasswordResetEmail,
  sendLockoutAlertEmail,
  sendPasswordChangeAlertEmail,
  sendMfaDisableEmail,
};
