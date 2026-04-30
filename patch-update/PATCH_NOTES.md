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

---

## Post-Audit Remediation II (April 29, 2026 - Claude 4.5 Audit)

### 🔴 HIGH Priority Fixes

#### 1. Smoke Test Broken by MFA Password Requirement [BUG-1]
- **File:** `tests/smoke.js`
- **Finding:** Patch #7 added a password requirement to `/mfa/setup`, but the automated smoke test wasn't updated to send it, causing the test suite to fail out-of-the-box.
- **Fix:** Added the `password` payload to the `/api/auth/mfa/setup` request in the test script. The test now passes successfully.

### 🟠 MEDIUM Priority Fixes

#### 2. MFA Failure Not Incrementing Lockout Counter [VULN-1]
- **File:** `server/routes/auth.js` (Login handler)
- **Finding:** While a wrong password triggered the database account lockout after 5 attempts, a correct password followed by a wrong MFA code did not increment the `failed_login_attempts` counter. This allowed attackers to brute-force TOTP indefinitely without persistent account lockout.
- **Fix:** Added `incrementFailedAttempts` and the 5-strike lockout logic to the MFA failure path.

#### 3. Email Enumeration via `/change-email` [VULN-2]
- **File:** `server/routes/auth.js` (Change email handler)
- **Finding:** The endpoint returned `409 Conflict` immediately if the requested new email was already in use. This allowed authenticated users to probe and enumerate registered emails.
- **Fix:** Refactored the endpoint to always check the password first. If the email is in use, the system pads the timing with a dummy hash and returns a generic success message ("A verification link has been sent..."), preventing enumeration without sending confusing emails to other users.

#### 4. Timing-Based Email Enumeration in `/forgot-password` and `/register` [VULN-3 & VULN-4]
- **File:** `server/routes/auth.js`
- **Finding:** Both endpoints exited early when an email didn't exist or was a duplicate. The non-early path executed `hashToken()` (Argon2), creating a 100-300ms timing gap that attackers could measure to enumerate registered emails.
- **Fix:** Added `await hashToken('dummy-token-for-timing-balance')` to the early exit paths. This balances the execution time, closing the timing side-channel.

### 🟡 LOW Priority Fixes

#### 5. Key Reuse for HMAC Backup Codes [VULN-5]
- **File:** `server/utils/crypto.js`
- **Finding:** The primary `ENCRYPTION_KEY` was used directly as the HMAC key for backup codes, violating the Key Separation Principle (NIST SP 800-108).
- **Fix:** Implemented `crypto.hkdfSync` to derive a distinct, purpose-specific key (`backup-code-hmac`) from the `ENCRYPTION_KEY` for backup code hashing.

#### 6. CSP `imgSrc: https:` Too Broad [LOW-7]
- **File:** `server/server.js`
- **Finding:** Allowing images from any HTTPS source could theoretically facilitate image-based data exfiltration if XSS was achieved.
- **Fix:** Tightened Content Security Policy to `imgSrc: ["'self'", 'data:']`.

---

### ✅ Items Reviewed But NOT Changed (Claude 4.5)

| Finding | Reason Not Changed |
|---------|-------------------|
| `__CSRF-Token` not using `__Host-` prefix [LOW-6] | Requires HTTPS. Imposing this breaks local development (HTTP). `SameSite: strict` is sufficient. |
| `trust proxy` config accepts only 1 IP [LOW-8] | Advanced load balancer/CDN configurations (multiple CIDRs) are deployment-specific infrastructure details, not application bugs. |

---

## 🚀 Post-Audit Remediation III (April 29, 2026 - Gemini 3.1 Pro Audit)

### 🔴 HIGH Priority Fixes

#### 1. Persistent Account Lockout DoS
- **File:** `server/routes/auth.js` (Login handler)
- **Finding:** When the account lock period expired, the system bypassed the lock check without resetting the `failed_login_attempts` counter. A subsequent failed login incremented the counter and locked the account again immediately.
- **Fix:** Added logic to call `statements.resetFailedAttempts.run()` when the lockout period has expired before proceeding with login verification.

### 🟠 MEDIUM Priority Fixes

#### 2. Missing Alert Email in `/change-password`
- **File:** `server/routes/auth.js`
- **Finding:** The endpoint successfully changed the password but failed to call `sendPasswordChangeAlertEmail`, meaning users were not notified of changes.
- **Fix:** Added the email notification step immediately following a successful password update.

### 🟡 LOW Priority Fixes

#### 3. Incorrect Middleware Order in `/mfa/setup`
- **File:** `server/routes/auth.js`
- **Finding:** `mfaAttemptLimiter` was placed before `authenticate`, allowing unauthenticated requests to exhaust the rate limit quota.
- **Fix:** Swapped the middleware order so `authenticate` verifies the user's session before hitting the rate limiter.

#### 4. Dummy Hash Length Mismatch and Synchronization
- **File:** `server/routes/auth.js`
- **Finding:** The hardcoded dummy hash did not match the expected 32-byte output length and would drift out of sync if the Argon2 configuration was changed.
- **Fix:** Implemented a dynamic `getDummyHash()` function that generates and caches a dummy hash using the current application configuration, ensuring perfect timing and format parity.

---

## 🚀 Post-Audit Remediation IV (April 29, 2026 - Antigravity Audit)

### 🔴 HIGH Priority Fixes

#### 1. Refresh Token Theft Detection (Token Family Revocation)
- **Files:** `server/routes/auth.js`, `server/models/db.js`
- **Finding:** The system failed to identify "token replay" attacks. When a revoked token was submitted, it merely threw an error, allowing the attacker's newly issued token to remain valid.
- **Fix:** Implemented a "find any status" lookup. If a revoked token is presented, the system now triggers a full family revocation (invalidating all refresh tokens for that user) and increments the `session_version` to kill all active access tokens.

#### 2. Active Session Disruption DoS
- **File:** `server/middleware/auth.js`
- **Finding:** The `authenticate` middleware checked the `locked_until` column. An unauthenticated attacker could lock a victim's account via the login route (brute force), which would then terminate the victim's existing, legitimate sessions.
- **Fix:** Removed the `locked_until` check from the middleware. Account lockout now only prevents *new* logins, preserving the availability of existing sessions.

### 🟠 MEDIUM Priority Fixes

#### 3. Email Enumeration via SMTP Timing
- **File:** `server/routes/auth.js`
- **Finding:** The server `await`-ed the SMTP transport response in registration, password reset, and email change routes. This created measurable network latency differences based on whether an email was actually sent.
- **Fix:** Changed email delivery to an asynchronous approach using `.catch()` for error handling. Responses are now sent immediately after the hashing step, ensuring timing uniformity across all account existence states.

#### 4. Missing Database Transactions in Sensitive Routes
- **File:** `server/routes/auth.js`
- **Finding:** The `/change-password` and `/delete-account` endpoints updated multiple database tables and revoked sessions sequentially without a transaction, risking data inconsistency if a failure occurred mid-process.
- **Fix:** Wrapped the entire state-changing logic in `db.transaction()` to ensure atomicity.

### 🟡 LOW Priority Fixes

#### 5. XSS in Email Templates
- **File:** `server/utils/email.js`
- **Finding:** The `config.appUrl` was injected into HTML email templates without escaping. While the URL is admin-controlled, it lacked consistent protection against accidental HTML injection or malicious environment configuration.
- **Fix:** Applied `escapeHtml()` to all URLs injected into HTML email bodies.

---

## 🛡️ Post-Audit Remediation VII (April 30, 2026 - Security Hardening)

### 🔴 HIGH Priority Fixes

#### 1. UA Binding Lost After Token Refresh [VULN-2026-1]
- **Files:** `server/models/db.js`, `server/routes/auth.js`
- **Finding:** Refresh tokens were not bound to User-Agent hash, allowing stolen tokens to be used from any device without detection.
- **Fix:**
  - Added `ua_hash` column to `refresh_tokens` table
  - Validate UA hash on token refresh — mismatch triggers revocation
  - Auto-revoke legacy tokens without UA hash
  - Generate new access tokens with UA hash binding

#### 2. Account Lockout DoS Vulnerability [VULN-2026-2]
- **Files:** `server/routes/auth.js`, `server/models/db.js`
- **Finding:** Account-wide lockout after 5 failed attempts allowed attackers to lock any account knowing only the email address (Denial of Service).
- **Fix:**
  - Created new `login_throttle` table for per-source tracking (email + IP)
  - Replaced account lockout with source-based throttling — locks only the attacker source, not the entire account
  - Soft reset: clears counter but preserves audit history for threat analysis
  - Added 3-phase cleanup strategy for stale throttle records

#### 3. Ephemeral Audit Log Signing Keys [VULN-2026-3]
- **Files:** `server/workers/auditWorker.js`, `.gitignore`, `.env.example`, `generate-audit-keys.js`
- **Finding:** ECDSA keys were regenerated on every restart, making audit log signatures unverifiable after restart (keys lost).
- **Fix:**
  - Load keys from environment variables (`AUDIT_SIGNING_PRIVATE_KEY_PEM`, `AUDIT_SIGNING_PUBLIC_KEY_PEM`)
  - Production: Application refuses to start if keys missing (fail-safe)
  - Development: Generates ephemeral keys with `.gitignore` check — throws error if patterns missing
  - Created `generate-audit-keys.js` script for key pair generation
  - Key version derived from public key fingerprint (not static 'v1')

---

## 🛡️ Enterprise Security Enhancement V

### 🚀 Enterprise-Grade New Features
#### 1. Tamper-evident Audit Trail & Digital Signature (Phase 2)
Files: server/models/db.js, server/workers/auditWorker.js, server/utils/auditQueue.js
Description: Upgraded the Audit Log system to a Hash Chaining model (similar to blockchain linking) to prevent retrospective log tampering.
Micro-batching: Utilizes Redis and BullMQ for micro-batching, allowing high-volume logs to be grouped into a single transaction, reducing database lock contention.
Digital Signature: Critical events (e.g., password changes, MFA verification) are signed using an ECDSA private key to ensure integrity and provide non-repudiation.
2. Fraud Detection: Impossible Travel (Phase 1)
File: server/routes/auth.js
Description: Implements geolocation velocity checks using the Haversine formula. If two login events occur within an შეუძლausible timeframe (e.g., Thailand to the U.S. in one minute), the system flags the event as IMPOSSIBLE_TRAVEL and immediately triggers step-up authentication.
3. Fraud Detection: User-Agent Binding (Phase 1)
File: server/middleware/auth.js
Description: Hashes the User-Agent and embeds it into the JWT to mitigate token hijacking. If a mismatch is detected during a session, the system raises an alert and sets the flag req.uaMismatch for monitoring.

### Security Fixes Applied VI

The following vulnerabilities have been fixed:

| Fix | File | Description |
|-----|------|-------------|
| **devToken Removal** | `server/routes/auth.js` | Removed `devToken` from `/register` and `/forgot-password` responses to prevent verification token leaks |
| **APP_URL Enforcement** | `server/config.js` | `APP_URL` is now required in production; app will crash with clear error message if not set |
| **Impossible Travel Fix** | `server/models/db.js` | `getLastLoginEvent` now filters `is_trusted=1 AND status='success'` to prevent baseline poisoning attacks |

#### Verification Notes

✅ **`requireInProduction` Error Handling**: The function correctly throws `Error` in production when required variables are missing, causing the application to stop immediately. This is the intended behavior for misconfigured production environments.

✅ **`getLastLoginEvent` Usage**: Verified that `getLastLoginEvent` is only used in the Impossible Travel detection logic in `auth.js`. The SQL filter change does not affect other features.

✅ **Regression Test Coverage**: 
- Test Case 1: Legitimate impossible travel detection still works
- Test Case 2: Baseline is not poisoned by blocked/failed login attempts
- Test Case 3: Real users can still log in after attacker spray attempts
