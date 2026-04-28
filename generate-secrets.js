#!/usr/bin/env node
const crypto = require('crypto');

console.log('=== SecureAuth Secret Generator ===');
console.log('Generating production-ready secrets...');
console.log('');

const jwtSecret = crypto.randomBytes(32).toString('hex');
const encryptionKey = crypto.randomBytes(32).toString('hex');
const csrfSecret = crypto.randomBytes(32).toString('hex');

console.log('Copy these values to your .env.production file:');
console.log('----------------------------------------------');
console.log(`JWT_SECRET=${jwtSecret}`);
console.log(`ENCRYPTION_KEY=${encryptionKey}`);
console.log(`CSRF_SECRET=${csrfSecret}`);
console.log('----------------------------------------------');
console.log('');
console.log('⚠️  IMPORTANT:');
console.log('1. Never commit .env.production to version control.');
console.log('2. Rotate these secrets every 90 days.');
console.log('3. Use these only in Production environment.');
console.log('');
