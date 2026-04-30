# SecureAuth

Simple authentication system built with Node.js, Express, SQLite, JWT cookies, and TOTP MFA.

The goal of this repository is to show a compact auth example with better-than-basic security hygiene for development and learning. It is not government-grade infrastructure.

Developed by MasterT.

---

## Stack

- Backend: Node.js, Express, SQLite (`better-sqlite3`)
- Queue: Redis + BullMQ (for high-throughput audit logging)
- Auth: JWT access token + rotating refresh token in HttpOnly cookies
- Password hashing: Argon2id
- MFA: TOTP with backup codes
- Frontend: Vanilla HTML, CSS, and JavaScript

## Security Features

- **Argon2id** password hashing with configurable cost parameters
- **JWT access tokens** with session versioning
- **Refresh-token rotation** with database-backed revocation
- **Email verification** and password-reset flows
- **TOTP MFA** with encrypted secret storage
- **One-time backup codes** for account recovery
- **CSRF protection** for all state-changing requests (POST/PUT/DELETE)
- **Helmet** security headers (CSP, HSTS, etc.)
- **Route-specific rate limiting** to prevent brute-force attacks
- **Account lockout** after 5 failed login attempts (DB-backed)
- **Password history** checks (prevents reusing last 5 passwords)
- **Login history audit** for authenticated users
- **HMAC-SHA256** for backup codes (O(1) constant-time verification preventing DoS)
- **Per-install HKDF salt** for derived encryption keys
- **Anti-enumeration (Timing attack prevention)** for registration, login, and password reset

## API Endpoints

| Method | Endpoint | Description | Auth Required |
| :--- | :--- | :--- | :--- |
| GET | `/health` | Health check | No |
| GET | `/api/csrf-token` | Issue or refresh a CSRF token for browser requests | No |
| POST | `/api/auth/register` | Create a new user account | No |
| POST | `/api/auth/verify-email` | Verify signup email or confirm email-change link | No |
| POST | `/api/auth/login` | Authenticate and receive cookies | No |
| POST | `/api/auth/refresh` | Rotate access and refresh tokens | No |
| POST | `/api/auth/logout` | Revoke the current refresh token and clear cookies | No |
| POST | `/api/auth/forgot-password` | Start password reset flow | No |
| POST | `/api/auth/reset-password` | Complete password reset | No |
| POST | `/api/auth/mfa/setup` | Generate MFA QR code and backup codes | Yes |
| POST | `/api/auth/mfa/verify` | Enable MFA after verifying a TOTP code | Yes |
| POST | `/api/auth/mfa/disable` | Start MFA disable flow | Yes |
| POST | `/api/auth/mfa/confirm-disable` | Confirm MFA disable using emailed token | Yes |
| POST | `/api/auth/change-password` | Change password and revoke active sessions | Yes |
| POST | `/api/auth/change-email` | Start email-change verification flow | Yes |
| POST | `/api/auth/delete-account` | Permanently delete the current account | Yes |
| GET | `/api/user/me` | Return current authenticated user | Yes |
| GET | `/api/user/login-history` | Return latest login audit entries | Yes |

## Setup & Installation

### Requirements
- Node.js 16 or later
- npm
- Redis Server (running on localhost:6379)

### Installation Steps
1. **Install dependencies**:
   ```bash
   npm install
   ```
2. **Configure environment**:
   Copy `.env.example` to `.env`, then replace the placeholder secrets.
   ```bash
   cp .env.example .env
   ```
3. **Generate Secrets**:
   Use the helper script to generate cryptographically secure keys:
   ```bash
   node generate-secrets.js
   ```
4. **Start the Application**:
   ```bash
   npm run dev
   ```

### 📧 Email Testing in Development

The system uses **Ethereal Email** (a fake SMTP service) for development. When the app sends emails (verification, password reset, etc.), the email content including **clickable links** will appear directly in the **terminal console** instead of being sent to a real inbox.

> 💡 **Tip**: Look for the preview URL in the terminal when testing features like:
> - Email verification after registration
> - Password reset flow
> - MFA disable confirmation
> - Email change verification

## Testing (Quality Assurance)

Automated tests are included to ensure all security features work as expected.

### 1. Basic Smoke Test (Created by GPT5.4)
1. **Ensure no other server is running** on port 3000.
2. **Run the command**:
   ```bash
   npm run test:smoke
   ```

### 2. Extended Security & Edge-Case Test (Created by GLM5.1)
This suite performs 40+ deep security checks including rate limit behavior, concurrent token rotation, and timing side-channels.
1. **Run the command**:
   ```bash
   npm run test:glm
   ```

### What it tests:
- User registration and email verification flow.
- Login and session token management.
- Concurrent refresh token rotation (replay protection).
- Password reset and session revocation logic.
- MFA setup, TOTP verification, and replay protection.
- MFA disable using backup codes.

### ⚠️ Known Test Issues

> **Note**: These tests may fail due to environment-specific issues unrelated to the actual security fixes.

#### 1. Redis Version Compatibility
Both `test:smoke` and `test:glm` require **Redis 5.0.0+** for BullMQ queue functionality. If you see:
```
Error: Redis version needs to be greater or equal than 5.0.0
```
The tests will fail even though the security fixes are correctly implemented. **Solution**: Upgrade Redis to version 5.0.0 or later.

#### 2. devToken Removal (Security Fix Applied)
**Change**: `devToken` has been removed from API responses to prevent token leaks on production.

**Impact on Tests**: Tests that previously relied on `devToken` from response bodies have been updated to fetch tokens directly from the database for testing purposes.

#### 3. GLM Test - Account Lockout Interference
In some test runs, the account lockout test may cause subsequent login attempts to fail with 401 errors because:
- The account lockout persists across test runs (stored in database)
- Previous test users may still be locked when running new tests

**Solution**: Clear the database (`rm auth.db`) before running tests, or wait for the lockout period (30 minutes) to expire.

## Project Structure
```text
public/                  Frontend assets (HTML, CSS, JS)
server/                  Backend source code
server/routes/           API Endpoints
server/middleware/       Security & Validation logic
server/models/           Database & SQL statements
server/utils/            Helper utilities (Crypto, Email, Tokens)
tests/                   Automated smoke tests
```

## ⚠️ Security Notes

- Set `NODE_ENV=production` before deploying
- **devToken removed**: Development tokens are no longer exposed in API responses for security
- Make sure to set all required secrets in production
---


# SecureAuth (ภาษาไทย)

ระบบยืนยันตัวตนแบบเรียบง่ายที่สร้างด้วย Node.js, Express, SQLite, JWT cookies และ TOTP MFA

เป้าหมายของโปรเจกต์นี้คือการแสดงตัวอย่างระบบ Auth ที่มีมาตรฐานความปลอดภัยสูงกว่าพื้นฐานทั่วไป เพื่อใช้ในการเรียนรู้และพัฒนา ไม่ได้ถูกออกแบบมาเพื่อเป็นโครงสร้างพื้นฐานระดับรัฐบาลหรือกองทัพ

พัฒนาโดย MasterT.

---

## เทคโนโลยีที่ใช้ (Stack)

- **Backend**: Node.js, Express, SQLite (`better-sqlite3`)
- **Queue**: Redis + BullMQ (สำหรับระบบ Audit Log คิวเพื่อทำ Micro-batching)
- **Auth**: ใช้ JWT access token คู่กับ rotating refresh token ในรูปแบบ HttpOnly cookies
- **Password hashing**: ใช้ Argon2id (มาตรฐานสูงสุด)
- **MFA**: รองรับ TOTP (แอปยืนยันตัวตน) และมีระบบรหัสกู้คืน (Backup codes)
- **Frontend**: Vanilla HTML, CSS และ JavaScript (ไม่ใช้ Library ภายนอก)

## ฟีเจอร์ด้านความปลอดภัย

- **Argon2id**: การแฮชรหัสผ่านที่ป้องกันการถอดรหัสด้วย GPU/ASIC
- **JWT Session Versioning**: ระบบควบคุมเวอร์ชันของ Session เพื่อให้สามารถยกเลิก Session ได้ทันที
- **Refresh-token rotation**: เปลี่ยน Token ใหม่ทุกครั้งที่ใช้งานเพื่อป้องกันการโจมตีซ้ำ
- **Email verification**: ระบบยืนยันอีเมลและการรีเซ็ตรหัสผ่านที่ปลอดภัย
- **TOTP MFA**: การยืนยันตัวตนหลายชั้นพร้อมการเก็บความลับแบบเข้ารหัส
- **Backup codes**: รหัสกู้คืนแบบใช้ครั้งเดียวสำหรับกรณีทำมือถือหาย
- **CSRF protection**: ป้องกันการโจมตีแบบ CSRF ในทุกคำขอที่มีการเปลี่ยนแปลงข้อมูล
- **Helmet**: เสริมความปลอดภัยผ่าน HTTP Headers (CSP, HSTS ฯลฯ)
- **Rate limiting**: จำกัดความถี่ในการเข้าถึงเพื่อป้องกัน Brute-force
- **Account lockout**: ล็อคบัญชีอัตโนมัติหากเข้าสู่ระบบผิดพลาด 5 ครั้ง (เก็บสถานะในฐานข้อมูล)
- **Password history**: ป้องกันการใช้รหัสผ่านซ้ำ 5 ครั้งล่าสุด
- **Login history**: ระบบตรวจสอบประวัติการเข้าใช้งานสำหรับผู้ใช้
- **HMAC-SHA256 Backup Codes**: จัดเก็บและตรวจสอบรหัสกู้คืนด้วย HMAC เพื่อป้องกันการโจมตีแบบ DoS
- **Per-install HKDF Salt**: ใช้ Salt ที่ไม่ซ้ำกันในแต่ละการติดตั้งสำหรับการเข้ารหัสข้อมูลลับ
- **Anti-enumeration (Timing attack prevention)**: ป้องกันแฮกเกอร์ใช้การจับเวลา (Response Time) เพื่อเดาว่าอีเมลมีอยู่ในระบบหรือไม่

## ตาราง API Endpoints

| Method | Endpoint | คำอธิบาย | ต้องล็อกอิน |
| :--- | :--- | :--- | :--- |
| GET | `/health` | ตรวจสอบสถานะเซิร์ฟเวอร์ | ไม่ต้อง |
| GET | `/api/csrf-token` | ขอ CSRF token สำหรับ browser request | ไม่ต้อง |
| POST | `/api/auth/register` | สมัครสมาชิก | ไม่ต้อง |
| POST | `/api/auth/verify-email` | ยืนยันอีเมลสมัครสมาชิกหรือเปลี่ยนอีเมล | ไม่ต้อง |
| POST | `/api/auth/login` | ล็อกอิน | ไม่ต้อง |
| POST | `/api/auth/refresh` | ต่ออายุ token | ไม่ต้อง |
| POST | `/api/auth/logout` | ออกจากระบบ | ไม่ต้อง |
| POST | `/api/auth/forgot-password` | เริ่มรีเซ็ตรหัสผ่าน | ไม่ต้อง |
| POST | `/api/auth/reset-password` | ตั้งรหัสผ่านใหม่ | ไม่ต้อง |
| POST | `/api/auth/mfa/setup` | สร้าง QR code และ backup codes สำหรับ MFA | ต้อง |
| POST | `/api/auth/mfa/verify` | เปิดใช้งาน MFA | ต้อง |
| POST | `/api/auth/mfa/disable` | เริ่มขั้นตอนปิด MFA | ต้อง |
| POST | `/api/auth/mfa/confirm-disable` | ยืนยันการปิด MFA ด้วย token จากอีเมล | ต้อง |
| POST | `/api/auth/change-password` | เปลี่ยนรหัสผ่านและตัด session เดิม | ต้อง |
| POST | `/api/auth/change-email` | เริ่มขั้นตอนเปลี่ยนอีเมล | ต้อง |
| POST | `/api/auth/delete-account` | ลบบัญชี | ต้อง |
| GET | `/api/user/me` | ดูข้อมูลผู้ใช้ปัจจุบัน | ต้อง |
| GET | `/api/user/login-history` | ดูประวัติล็อกอินล่าสุด | ต้อง |

## วิธีการติดตั้งและใช้งาน

### สิ่งที่จำเป็น
- Node.js 16 ขึ้นไป
- npm
- Redis Server (จำเป็นสำหรับรัน Background Worker ที่ localhost:6379)

### ขั้นตอนการติดตั้ง
1. **ติดตั้ง Library**:
   ```bash
   npm install
   ```
2. **ตั้งค่าสภาพแวดล้อม**:
   คัดลอกไฟล์ `.env.example` เป็น `.env` และกำหนดค่ารหัสผ่านต่างๆ
   ```bash
   cp .env.example .env
   ```
3. **สร้างรหัสความปลอดภัย (Secrets)**:
   ใช้สคริปต์ช่วยเพื่อสร้างคีย์ที่ปลอดภัยสำหรับการเข้ารหัส:
   ```bash
   node generate-secrets.js
   ```
4. **เริ่มรันระบบ**:
   ```bash
   npm run dev
   ```

### 📧 การทดสอบอีเมลในขณะพัฒนา

ระบบใช้ **Ethereal Email** (บริการ SMTP จำลอง) สำหรับการพัฒนา เมื่อแอปส่งอีเมล (ยืนยันอีเมล, รีเซ็ตรหัสผ่าน ฯลฯ) เนื้อหาอีเมลรวมถึง **ลิงก์ที่คลิกได้** จะแสดงโดยตรงใน **หน้าจอเทอร์มินอล (Terminal)** แทนที่จะส่งไปยังกล่องจดหมายจริง

> 💡 **เคล็ดลับ**: ดูหา URL สำหรับพรีวิวในเทอร์มินอลเมื่อทดสอบฟีเจอร์ต่างๆ เช่น:
> - การยืนยันอีเมลหลังสมัครสมาชิก
> - ขั้นตอนรีเซ็ตรหัสผ่าน
> - การยืนยันปิด MFA
> - การยืนยันเปลี่ยนอีเมล

## การทดสอบระบบ (Automated Testing)

โปรเจกต์นี้มีระบบทดสอบอัตโนมัติเพื่อยืนยันว่าฟีเจอร์ความปลอดภัยทั้งหมดทำงานได้ถูกต้อง

### 1. การทดสอบพื้นฐาน (Smoke Test)
1. **ตรวจสอบว่าไม่มี Server อื่นรันอยู่** บน Port 3000
2. **รันคำสั่ง**:
   ```bash
   npm run test:smoke
   ```

### 2. การทดสอบความปลอดภัยขั้นสูง (GLM_Test)
ระบบทดสอบเจาะลึก 40+ รายการ รวมถึงการตรวจสอบ Rate Limit, การหมุน Token พร้อมกัน และการป้องกันการโจมตีทางเวลา (Timing Attacks)
1. **รันคำสั่ง**:
   ```bash
   npm run test:glm
   ```

### สิ่งที่ระบบจะทดสอบ:
- ขั้นตอนการสมัครสมาชิกและการยืนยันอีเมล
- การจัดการ Login และ Session Token
- ระบบป้องกันการใช้ Refresh Token ซ้ำ (Replay Protection)
- ระบบรีเซ็ตรหัสผ่านและการยกเลิก Session เมื่อเปลี่ยนรหัส
- ระบบ MFA, การตรวจสอบรหัส TOTP และการป้องกันการใช้รหัสซ้ำ
- การปิดใช้งาน MFA ด้วยรหัสกู้คืน (Backup Codes)

## โครงสร้างโปรเจกต์
```text
public/                  ไฟล์ฝั่งหน้าบ้าน (HTML, CSS, JS)
server/                  โค้ดฝั่งหลังบ้าน
server/routes/           เส้นทาง API ต่างๆ
server/middleware/       ระบบความปลอดภัยและการตรวจสอบข้อมูล
server/models/           โครงสร้างฐานข้อมูลและคำสั่ง SQL
server/utils/            เครื่องมือช่วย (การเข้ารหัส, อีเมล, Token)
tests/                   ระบบทดสอบอัตโนมัติ
```
