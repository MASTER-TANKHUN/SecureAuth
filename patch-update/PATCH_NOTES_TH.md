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
