# Offline MFA CLI (Python)

A **fully offline, security-focused Multi-Factor Authentication (MFA) CLI application** implemented in Python. The project demonstrates real-world MFA concepts including **Argon2 password hashing**, **TOTP (HMAC-SHA256)**, **one-time backup codes**, **rate limiting**, and **temporary account lockout with countdown** — all without any network dependency.

---

## ✨ Features

- 🔐 **Password Authentication** using Argon2id
- ⏱️ **TOTP-based MFA** (HMAC-SHA256, 6 digits, 30-second window)
- 📱 **Authenticator App Support** (Google Authenticator, Authy, etc.)
- 🧾 **QR Code Provisioning** (terminal-rendered)
- 🆘 **One-Time Backup Codes** (hashed & single-use)
- 🚦 **Rate Limiting** for password and MFA attempts
- ⛔ **Temporary Account Lockout** with live countdown
- 🔒 **Encrypted MFA Secrets at Rest** (AES-256-GCM)
- 🗄️ **SQLite Storage** (offline, serverless)

---

## 🧠 Architecture Overview

The system follows a layered, offline-first architecture:

- **CLI Interface** – user interaction, prompts, QR rendering
- **Authentication Logic** – password verification, MFA flow enforcement
- **Cryptography Layer** – Argon2, AES-GCM, HMAC-SHA256
- **Key Management** – local AES master key (`master.key`)
- **Persistence Layer** – SQLite database (`mfa.db`)
- **Out-of-Band Factor** – external authenticator app

TOTP secrets are encrypted at rest, and MFA is strictly enforced _after_ password verification.

---

## 🔄 Authentication Flow

1. User enters **username + password**
2. Password verified using **Argon2id**
3. User prompted for **TOTP code**
4. If TOTP fails → **backup code** option
5. On success → counters reset and login allowed
6. On repeated failures → **temporary lockout** with countdown

Backup codes act as a fallback **only for the second factor**, never as a password replacement.

---

## 🗄️ Data Storage

Stored locally in SQLite:

- Username
- Password hash (Argon2)
- Encrypted TOTP secret
- Hashed backup codes
- Failed attempt counters
- Lockout timestamp

Sensitive data is never stored in plaintext.

---

## 🔑 Key Management (`master.key`)

- A local **AES-256-GCM master key** is generated on first run
- Used to encrypt/decrypt TOTP secrets
- **Never committed to version control**

If both the database and master key are compromised, MFA security is lost — hence the strict separation.

---

## 📦 Setup & Usage

### 1. Create virtual environment

```bash
python3 -m venv venv
source venv/bin/activate
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Run the application

```bash
python MFA.py
```

---

## 🧪 Testing Tips

- Save backup codes during account creation
- Test wrong password → no MFA prompt (expected)
- Test correct password + wrong TOTP → backup code prompt
- Reuse backup code → rejected (one-time)
- Trigger lockout to observe countdown

---

## 🎓 Learning Outcomes

This project demonstrates:

- Correct MFA lifecycle design
- Secure secret handling at rest
- Offline authentication systems
- Defensive security controls
- Real-world cryptographic primitives

---
