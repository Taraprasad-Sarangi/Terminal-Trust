#!/usr/bin/env python3
"""
Offline MFA CLI (Python)
-----------------------
Features implemented in this initial version:
- Create account (username + password)
- Argon2id password hashing
- TOTP provisioning (HMAC-SHA256, 6 digits, 30s)
- otpauth:// URI generation
- ASCII QR code rendering in terminal
- Offline login with TOTP verification (±1 window)
- SQLite local database

Next milestones (we'll add later):
- Backup codes
- Rate limiting / lockout
- Session handling
- Configurable master key storage
"""

import base64
import hashlib
import os
import secrets
import sqlite3
import sys
import time
from getpass import getpass

import pyotp
import qrcode
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# =============================
# Configuration
# =============================
DB_PATH = "mfa.db"
ISSUER = "OfflineMFA"
TOTP_DIGITS = 6
TOTP_PERIOD = 30

# NOTE: For demo purposes only.
# In a real system, store this securely (env var / OS keyring).
MASTER_KEY_PATH = "master.key"

# =============================
# Crypto setup
# =============================
ph = PasswordHasher()


def load_or_create_master_key():
    if os.path.exists(MASTER_KEY_PATH):
        with open(MASTER_KEY_PATH, "rb") as f:
            return f.read()
    key = AESGCM.generate_key(bit_length=256)
    with open(MASTER_KEY_PATH, "wb") as f:
        f.write(key)
    return key


MASTER_KEY = load_or_create_master_key()


# =============================
# Database
# =============================


def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        cur = conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                totp_secret_enc BLOB NOT NULL,
                totp_nonce BLOB NOT NULL,
                created_at INTEGER NOT NULL
            )
            """
        )
        conn.commit()


# =============================
# Utility functions
# =============================


def encrypt_secret(secret: bytes) -> tuple[bytes, bytes]:
    aesgcm = AESGCM(MASTER_KEY)
    nonce = secrets.token_bytes(12)
    ciphertext = aesgcm.encrypt(nonce, secret, None)
    return ciphertext, nonce


def decrypt_secret(ciphertext: bytes, nonce: bytes) -> bytes:
    aesgcm = AESGCM(MASTER_KEY)
    return aesgcm.decrypt(nonce, ciphertext, None)


def generate_totp_secret() -> bytes:
    # 32 bytes for SHA256
    return secrets.token_bytes(32)


def base32_encode(secret: bytes) -> str:
    return base64.b32encode(secret).decode("utf-8").replace("=", "")


def show_qr(otpauth_uri: str):
    qr = qrcode.QRCode(border=1)
    qr.add_data(otpauth_uri)
    qr.make(fit=True)
    qr.print_ascii(invert=True)


# =============================
# Flows
# =============================


def create_account():
    username = input("Username: ").strip()
    password = getpass("Password: ")
    confirm = getpass("Confirm password: ")

    if password != confirm:
        print("[!] Passwords do not match")
        return

    password_hash = ph.hash(password)

    secret = generate_totp_secret()
    secret_b32 = base32_encode(secret)

    totp = pyotp.TOTP(
        secret_b32,
        digits=TOTP_DIGITS,
        interval=TOTP_PERIOD,
        digest=hashlib.sha256,
    )

    otpauth_uri = totp.provisioning_uri(name=username, issuer_name=ISSUER)

    ciphertext, nonce = encrypt_secret(secret)

    try:
        with sqlite3.connect(DB_PATH) as conn:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO users (username, password_hash, totp_secret_enc, totp_nonce, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (username, password_hash, ciphertext, nonce, int(time.time())),
            )
            conn.commit()
    except sqlite3.IntegrityError:
        print("[!] Username already exists")
        return

    print("\nAccount created successfully!\n")
    print("Add this account to your authenticator app:")
    print("-----------------------------------------")
    print(f"Setup key (Base32): {secret_b32}")
    print(f"Algorithm: SHA256 | Digits: {TOTP_DIGITS} | Period: {TOTP_PERIOD}s")
    print("\nOR scan this QR code:\n")
    show_qr(otpauth_uri)
    print("\nIMPORTANT: Save your setup key securely. It will not be shown again.\n")


def login():
    username = input("Username: ").strip()
    password = getpass("Password: ")

    with sqlite3.connect(DB_PATH) as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT password_hash, totp_secret_enc, totp_nonce FROM users WHERE username = ?",
            (username,),
        )
        row = cur.fetchone()

    if not row:
        print("[!] Invalid username or password")
        return

    password_hash, secret_enc, nonce = row

    try:
        ph.verify(password_hash, password)
    except VerifyMismatchError:
        print("[!] Invalid username or password")
        return

    secret = decrypt_secret(secret_enc, nonce)
    secret_b32 = base32_encode(secret)

    user_code = input("Enter 6-digit code from authenticator: ").strip()

    totp = pyotp.TOTP(
        secret_b32,
        digits=TOTP_DIGITS,
        interval=TOTP_PERIOD,
        digest=hashlib.sha256,
    )

    if totp.verify(user_code, valid_window=1):
        print("\n[✓] Login successful. MFA verified.\n")
    else:
        print("[!] Invalid authentication code")


# =============================
# Main menu
# =============================


def main():
    init_db()

    while True:
        print("\n=== Offline MFA CLI ===")
        print("1) Create account")
        print("2) Login")
        print("3) Exit")

        choice = input("> ").strip()

        if choice == "1":
            create_account()
        elif choice == "2":
            login()
        elif choice == "3":
            print("Goodbye!")
            sys.exit(0)
        else:
            print("Invalid choice")


if __name__ == "__main__":
    main()
