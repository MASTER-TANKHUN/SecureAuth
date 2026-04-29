# 🔒 SecureAuth Patch Update — การแก้ไขด้านความปลอดภัย
## การแก้ไขหลังการตรวจสอบ (เมษายน 2026)

---

## 📋 ภาพรวม

แพทช์นี้แก้ไข **8 ปัญหาด้านความปลอดภัย** ที่ค้นพบจากการตรวจสอบโค้ดอิสระโดย **Claude Opus 4.7** โค้ดต้นฉบับมีคุณภาพสูงและมีพื้นฐานด้านความปลอดภัยที่แข็งแกร่ง (Argon2id hashing, JWT + session versioning, TOTP พร้อม replay protection, atomic token rotation) แต่พบช่องว่างหลายจุดที่ต้องแก้ไข

---

## 🔴 แก้ไขระดับ HIGH

### 1. Permissions-Policy Header ไม่ทำงาน
- **ไฟล์:** `server/server.js`
- **ปัญหา:** Helmet v8 **ไม่รองรับ** option `permissionsPolicy` — config ถูก ignore อย่างเงียบๆ ทำให้ browser ไม่เคยได้รับ header นี้เลย
- **แก้ไข:** ลบ option ที่ไม่ถูกต้องออก แล้วเพิ่ม middleware ที่ set header เอง:
  ```
  Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=()
  ```
- **ผลกระทบ:** Camera, microphone, geolocation, payment, USB APIs ถูกจำกัดโดย browser อย่างถูกต้องแล้ว

---

## 🟠 แก้ไขระดับ MEDIUM

### 2. Login ไม่นับ Failed Attempts ลงฐานข้อมูล
- **ไฟล์:** `server/routes/auth.js` (login handler)
- **ปัญหา:** เมื่อ password ผิด โค้ด log ลง `login_logs` แต่ **ไม่ได้เรียก** `incrementFailedAttempts` → counter ใน DB ไม่เคยถูกอัพเดตจาก login → account lock ไม่ทำงาน
- **แก้ไข:** เพิ่มการ increment counter เมื่อ login ผิด + lock account เมื่อผิด 5 ครั้ง (ล็อก 30 นาที + ส่ง email แจ้งเตือน)
- **ผลกระทบ:** Brute-force login ถูกติดตามใน DB อย่างถาวร (ไม่หายเมื่อ server restart)

### 3. Backup Code Verification → เปลี่ยนจาก Argon2 เป็น HMAC-SHA256
- **ไฟล์:** `server/utils/crypto.js`, `server/routes/auth.js`
- **ปัญหา:** Backup codes ใช้ Argon2id hash → verify ต้องวน loop 8 รอบ (~313ms/request) → ผู้โจมตีหมุน IP สร้าง CPU load ได้มาก
- **แก้ไข:** เปลี่ยนเป็น HMAC-SHA256 — O(1) lookup, ใช้ `timingSafeEqual` เปรียบเทียบ
- **ผลกระทบ:** เวลา verify ลดจาก ~313ms เหลือ <1ms ปิดช่องทาง DoS

---

## 🟡 แก้ไขระดับ LOW

### 4. JSON Body Limit แคบเกินไป (1kb → 10kb)
- **ไฟล์:** `server/server.js`
- **ปัญหา:** `1kb` อาจ block request ที่ถูกต้อง
- **แก้ไข:** เพิ่มเป็น `10kb`

### 5. Login MFA ไม่ตรวจ Format ของ Code
- **ไฟล์:** `server/routes/auth.js`
- **ปัญหา:** `/mfa/verify` บังคับ 6 หลัก แต่ `/login` ไม่ตรวจ format
- **แก้ไข:** เพิ่ม regex check: ต้องเป็น 6 digits (TOTP) หรือ 12 hex chars (backup code)

### 6. Race Condition ใน /mfa/verify
- **ไฟล์:** `server/routes/auth.js`
- **ปัญหา:** ใช้ snapshot เก่าของ `mfa_secret` หลังจาก `consumeTotpCode` → อาจเขียนทับ secret ใหม่
- **แก้ไข:** ครอบ `enableMfa` ด้วย transaction ที่อ่าน fresh data จาก DB

### 7. /mfa/setup ไม่ยืนยัน Password
- **ไฟล์:** `server/routes/auth.js`, `public/mfa-setup.html`, `public/js/mfa.js`
- **ปัญหา:** ต้องการแค่ `authenticate` middleware — ถ้ามีคนได้ access_token ก็ overwrite MFA secret ได้
- **แก้ไข:** เพิ่มการยืนยัน password ก่อน setup — Frontend เปลี่ยนเป็น 2 ขั้นตอน: ใส่ password → เห็น QR code

### 8. HKDF Salt เป็นค่าคงที่เหมือนกันทุก Deployment
- **ไฟล์:** `server/utils/crypto.js`, `server/config.js`, `.env`, `.env.example`, `generate-secrets.js`
- **ปัญหา:** HKDF salt hardcode เป็น `'secureauth-encryption-salt'` → ทุก instance ใช้ derived key เดียวกัน
- **แก้ไข:** เพิ่ม `HKDF_SALT` เป็น environment variable แต่ละ deployment
- **⚠️ หมายเหตุ:** การเปลี่ยน salt ทำให้ข้อมูลที่เข้ารหัสไว้ (เช่น `mfa_secret`) ใช้ไม่ได้ — ต้อง re-encrypt หรือใช้ salt เดิม

---

## ✅ สิ่งที่ตรวจแล้วไม่ต้องแก้ (ยอมรับได้)

| ประเด็น | เหตุผล |
|---------|--------|
| TOTP `window: 1` (90 วินาที) | เป็นค่าที่ RFC 6238 แนะนำ — Google, GitHub ใช้เหมือนกัน |
| `__CSRF-Token` ไม่ใช้ `__Host-` prefix | `SameSite: strict` ป้องกันได้เพียงพอ — `__Host-` ทำให้ dev mode (HTTP) พัง |
| Account lockout cross-contamination | ต้อง chain XSS + CSRF + ขโมย token ภายใน 15 นาที — ยากมาก |
| `trust proxy` config | เป็นเรื่อง operational — บันทึกไว้ใน README |
| CSP `imgSrc: https:` | ต้องมี XSS ก่อน ซึ่ง CSP บล็อกอยู่แล้ว |

---

## 🛠️ Post-Audit Remediation II (29-04-2026 - Claude 4.7 Audit)

### 🔴 HIGH Priority Fixes

#### 1. Smoke Test พังเพราะเพิ่มระบบยืนยันรหัสผ่าน [BUG-1]
- **ไฟล์:** `tests/smoke.js`
- **ปัญหา:** แพตช์ที่ 7 มีการเพิ่มให้ `/mfa/setup` ต้องส่งรหัสผ่าน แต่ลืมอัปเดตไฟล์ Automated Test ทำให้รันเทสต์แล้วไม่ผ่าน
- **แก้ไข:** เพิ่มฟิลด์ `password` ใน payload ที่ยิงไป `/api/auth/mfa/setup` ตอนนี้เทสต์ผ่าน 100% แล้ว

### 🟠 MEDIUM Priority Fixes

#### 2. ใส่ MFA ผิดไม่ทำให้ Account โดน Lockout [VULN-1]
- **ไฟล์:** `server/routes/auth.js`
- **ปัญหา:** การล็อกอินที่รหัสผ่านถูกต้องแต่ MFA ผิด ไม่มีการเรียกใช้ `incrementFailedAttempts` ทำให้แฮกเกอร์สามารถสุ่มเดา MFA ได้เรื่อยๆ โดยบัญชีไม่ถูกล็อค
- **แก้ไข:** เพิ่มคำสั่งบวกจำนวนครั้งที่ผิด และระบบล็อคบัญชีเมื่อครบ 5 ครั้ง เข้าไปใน Flow ที่เช็ก MFA ผิดด้วย

#### 3. Email Enumeration ในระบบเปลี่ยนอีเมล (`/change-email`) [VULN-2]
- **ไฟล์:** `server/routes/auth.js`
- **ปัญหา:** ระบบตอบกลับ `409 Conflict` ทันทีถ้าอีเมลที่ต้องการเปลี่ยนมีคนใช้แล้ว ทำให้ผู้ใช้งานสามารถเดาได้ว่าอีเมลไหนมีอยู่ในระบบบ้าง
- **แก้ไข:** ปรับลอจิกให้เช็กรหัสผ่านก่อนเสมอ และหากอีเมลซ้ำ จะหน่วงเวลาด้วย Dummy Hash และส่งข้อความ Generic Success ("ระบบได้ส่งลิงก์ไปแล้ว") แทนเพื่อซ่อนข้อมูล

#### 4. Timing-based Email Enumeration ใน `/forgot-password` และ `/register` [VULN-3 & VULN-4]
- **ไฟล์:** `server/routes/auth.js`
- **ปัญหา:** เมื่อใส่อีเมลที่ไม่มีในระบบ (หรือมีแล้วในกรณีสมัคร) ระบบจะ Return ทันที ทำให้เร็วกว่าเคสปกติที่ต้องรันการแฮชด้วย Argon2 ประมาณ 100-300ms แฮกเกอร์สามารถใช้จับเวลาเพื่อตรวจสอบว่ามีอีเมลนั้นในระบบหรือไม่
- **แก้ไข:** เพิ่มคำสั่ง `await hashToken('dummy-token-for-timing-balance')` ลงใน Path ที่มีการ Return เร็ว เพื่อถ่วงเวลาให้เท่ากันในทุกกรณี

### 🟡 LOW Priority Fixes

#### 5. การใช้ Key ซ้ำซ้อน (Key Reuse) [VULN-5]
- **ไฟล์:** `server/utils/crypto.js`
- **ปัญหา:** `ENCRYPTION_KEY` ถูกนำมาใช้เป็น Key โดยตรงสำหรับการทำ HMAC-SHA256 ของ Backup Codes ซึ่งผิดหลักการ Key Separation Principle
- **แก้ไข:** ใช้ `crypto.hkdfSync` ในการ Derive Key ใหม่ชื่อ `backup-code-hmac` ขึ้นมาจาก `ENCRYPTION_KEY` ก่อนนำไปใช้

#### 6. CSP `imgSrc: https:` เปิดกว้างเกินไป [LOW-7]
- **ไฟล์:** `server/server.js`
- **ปัญหา:** การอนุญาตดึงรูปภาพจากทุก URL อาจถูกนำไปใช้แอบส่งข้อมูลออกนอกระบบ (Data Exfiltration) ได้ถ้าหากเกิดช่องโหว่ XSS
- **แก้ไข:** ปรับลดเหลือเฉพาะ `["'self'", 'data:']` เท่านั้น

---

### ✅ สิ่งที่ตรวจแล้วไม่ต้องแก้ (Claude 4.7)

| ประเด็น | เหตุผล |
|---------|--------|
| `__CSRF-Token` ไม่ใช้ `__Host-` prefix [LOW-6] | การใช้ `__Host-` บังคับให้ต้องรันบน HTTPS ทำให้โหมด Local Dev พัง (แค่ใช้ `SameSite: strict` ก็เพียงพอแล้ว) |
| `trust proxy` config ใส่ได้แค่ 1 IP [LOW-8] | เป็นเรื่องการตั้งค่าระดับ Infrastructure ไม่ใช่บั๊กของโค้ด สามารถระบุหลายไอพีที่ `.env` หรือ Load Balancer ได้ |
