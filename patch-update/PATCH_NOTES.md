# 🔒 SecureAuth Patch Update — Security Hardening
## Post-Audit Remediation (April 2026)

---

## 📋 Overview

This patch addresses **8 security findings** identified during an independent code review by **Claude Opus 4.7**. The original codebase was of high quality with strong security fundamentals (Argon2id hashing, JWT + session versioning, TOTP with replay protection, atomic token rotation). However, several gaps were found that required remediation.

---

## 🔴 HIGH Priority Fixes

### 1. Permissions-Policy Header Not Working
- **File:** `server/server.js`
- **Finding:** Helmet v8 does **not** support the `permissionsPolicy` option. The configuration was silently ignored, meaning the browser never received the `Permissions-Policy` header despite the code suggesting otherwise.
- **Fix:** Removed the invalid Helmet option and added a custom Express middleware that manually sets the header:
  ```
  Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=()
  ```
- **Impact:** Camera, microphone, geolocation, payment, and USB APIs are now properly restricted by the browser.

---

## 🟠 MEDIUM Priority Fixes

### 2. Login Failed Attempts Not Incrementing DB Counter
- **File:** `server/routes/auth.js` (login handler)
- **Finding:** When a login password was incorrect, the code logged the failure to `login_logs` but did **not** call `incrementFailedAttempts`. The `failed_login_attempts` column in the database was never updated from login, meaning the DB-backed account lockout mechanism never triggered.
- **Fix:** Added `incrementFailedAttempts` call on failed login, plus account lock logic (5 failures → 30-minute lock + email alert). This is now consistent with the sensitive-action lockout behavior.
- **Impact:** Brute-force login attempts are now properly tracked in the database and trigger account lockout even if the server restarts (previously only in-memory rate limiting was effective).

### 3. Backup Code Verification DoS Amplification → HMAC-SHA256
- **Files:** `server/utils/crypto.js`, `server/routes/auth.js`
- **Finding:** Backup codes were hashed with Argon2id. Verification required looping through all 8 stored hashes (~313ms total per request for a wrong code). An attacker rotating IPs could cause significant CPU load.
- **Fix:** Replaced Argon2id with **HMAC-SHA256** for backup codes:
  - Storage: `HMAC-SHA256(ENCRYPTION_KEY, code)` — deterministic, O(1)
  - Verification: `timingSafeEqual` comparison — constant-time
  - `consumeBackupCode` is now synchronous (no async Argon2 calls)
- **Impact:** Backup code verification dropped from ~313ms to <1ms. DoS amplification vector eliminated.

---

## 🟡 LOW Priority Fixes

### 4. JSON Body Size Limit Too Restrictive
- **File:** `server/server.js`
- **Finding:** `express.json({ limit: '1kb' })` was too small and could block legitimate requests with longer payloads.
- **Fix:** Increased to `10kb` — sufficient for all normal payloads while still preventing abuse.

### 5. Inconsistent MFA Code Format Validation in Login
- **File:** `server/routes/auth.js` (login handler)
- **Finding:** `/mfa/verify` enforced a 6-digit regex check, but `/login` did not validate `mfaCode` format before processing.
- **Fix:** Added format validation: must be 6 digits (TOTP) or 12 hex chars (backup code).

### 6. Race Condition in /mfa/verify
- **File:** `server/routes/auth.js` (MFA verify handler)
- **Finding:** After `consumeTotpCode` validated the code in a transaction, `enableMfa` was called with stale `user.mfa_secret` and `user.backup_codes` from a snapshot taken before the transaction. If `/mfa/setup` was called concurrently, the old secret could overwrite the new one.
- **Fix:** Wrapped `enableMfa` in its own transaction that reads fresh data from the database.

### 7. No Password Re-confirmation in /mfa/setup
- **Files:** `server/routes/auth.js`, `public/mfa-setup.html`, `public/js/mfa.js`
- **Finding:** `/mfa/setup` only required `authenticate` middleware — no password confirmation. A stolen access token could be used to overwrite the MFA secret.
- **Fix:** Added password verification as the first step. Frontend updated with a 2-step flow: enter password → see QR code.

### 8. HKDF Salt Was Static Across All Deployments
- **Files:** `server/utils/crypto.js`, `server/config.js`, `.env`, `.env.example`, `generate-secrets.js`
- **Finding:** The HKDF salt was hardcoded as `'secureauth-encryption-salt'`, meaning all SecureAuth instances derived the same encryption key from the same `ENCRYPTION_KEY`.
- **Fix:** Added `HKDF_SALT` as a per-installation environment variable using the existing `requireInProduction` pattern. Each deployment now derives a unique key.
- **⚠️ Migration Note:** Changing the salt invalidates all existing encrypted data (e.g., `mfa_secret`). Existing installations must either keep the old salt or re-encrypt all secrets.

---

## 📁 Files Modified

| File | Changes |
|------|---------|
| `server/server.js` | Permissions-Policy middleware, JSON limit increased |
| `server/routes/auth.js` | Login lockout, MFA format check, MFA verify race fix, MFA setup password, HMAC backup codes |
| `server/utils/crypto.js` | HMAC backup code functions, per-install HKDF salt |
| `server/config.js` | Added `hkdfSalt` config |
| `public/mfa-setup.html` | Password confirmation UI |
| `public/js/mfa.js` | 2-step MFA setup flow |
| `.env` / `.env.example` | Added `HKDF_SALT` |
| `generate-secrets.js` | Generates `HKDF_SALT` |

---

## ✅ Items Reviewed But NOT Changed (Acceptable as-is)

| Finding | Reason Not Changed |
|---------|-------------------|
| TOTP `window: 1` (90s) | RFC 6238 recommended value; used by Google, GitHub, etc. |
| `__CSRF-Token` not using `__Host-` prefix | `SameSite: strict` provides equivalent protection; `__Host-` breaks dev mode (HTTP) |
| Account lockout cross-contamination | Requires chaining XSS + CSRF + token theft within 15min — extremely unlikely |
| `trust proxy` config | Operational concern — documented in README |
| CSP `imgSrc: https:` | Requires XSS to exploit, which CSP blocks |
| Dummy hash hardcoded | Added comment about keeping it in sync with Argon2 config |
| `verification_tokens` redundant hash | SHA-256 digest used as fast DB lookup index; Argon2 hash used for verification — functional design |
