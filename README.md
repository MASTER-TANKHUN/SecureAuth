# SecureAuth

Simple authentication system built with Node.js, Express, SQLite, JWT cookies, and TOTP MFA.

The goal of this repository is to show a compact auth example with better-than-basic security hygiene for development and learning. It is not government-grade infrastructure.

Developed by MasterT.

---

## Stack

- Backend: Node.js, Express, SQLite (`better-sqlite3`)
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
- **Password history** checks (prevents reusing last 5 passwords)
- **Login history audit** for authenticated users

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

## Smoke Testing (Quality Assurance)

A comprehensive automated smoke test is included to ensure all security features work as expected.

### How to Run:
1. **Ensure no other server is running** on port 3000.
2. **Run the command**:
   ```bash
   npm run test:smoke
   ```

### What it tests:
- User registration and email verification flow.
- Login and session token management.
- Concurrent refresh token rotation (replay protection).
- Password reset and session revocation logic.
- MFA setup, TOTP verification, and replay protection.
- MFA disable using backup codes.

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

---

# SecureAuth (ภาษาไทย)

ระบบยืนยันตัวตนแบบเรียบง่ายที่สร้างด้วย Node.js, Express, SQLite, JWT cookies และ TOTP MFA

เป้าหมายของโปรเจกต์นี้คือการแสดงตัวอย่างระบบ Auth ที่มีมาตรฐานความปลอดภัยสูงกว่าพื้นฐานทั่วไป เพื่อใช้ในการเรียนรู้และพัฒนา ไม่ได้ถูกออกแบบมาเพื่อเป็นโครงสร้างพื้นฐานระดับรัฐบาลหรือกองทัพ

พัฒนาโดย MasterT.

---

## เทคโนโลยีที่ใช้ (Stack)

- **Backend**: Node.js, Express, SQLite (`better-sqlite3`)
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
- **Password history**: ป้องกันการใช้รหัสผ่านซ้ำ 5 ครั้งล่าสุด
- **Login history**: ระบบตรวจสอบประวัติการเข้าใช้งานสำหรับผู้ใช้

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

## การทดสอบระบบ (Smoke Testing)

โปรเจกต์นี้มีระบบทดสอบอัตโนมัติ (Smoke Test) เพื่อยืนยันว่าฟีเจอร์ความปลอดภัยทั้งหมดทำงานได้ถูกต้อง

### วิธีการรันเทส:
1. **ตรวจสอบว่าไม่มี Server อื่นรันอยู่** บน Port 3000
2. **รันคำสั่ง**:
   ```bash
   npm run test:smoke
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
