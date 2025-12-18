#!/usr/bin/env python3
"""
Offline MFA CLI (Python) — Hardened
----------------------------------
Features:
- Username + password login (Argon2)
- TOTP MFA (SHA256, offline)
- QR provisioning
- 5 one-time backup codes
- Rate limiting
- Temporary lockout with countdown
- SQLite storage
"""

import base64
import hashlib
import json
import os
import secrets
import sqlite3
import sys
import time
from getpass import getpass

import pyotp
import qrcode
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# =============================
# Configuration
# =============================
DB_PATH = "mfa.db"
ISSUER = "OfflineMFA"

TOTP_DIGITS = 6
TOTP_PERIOD = 30
BACKUP_CODE_COUNT = 5

MAX_PASSWORD_ATTEMPTS = 5
MAX_MFA_ATTEMPTS = 5
LOCKOUT_SECONDS = 60  # demo-friendly

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
                backup_codes_hash TEXT,
                failed_password_attempts INTEGER DEFAULT 0,
                failed_mfa_attempts INTEGER DEFAULT 0,
                locked_until INTEGER DEFAULT 0,
                created_at INTEGER NOT NULL
            )
            """
        )
        conn.commit()


# =============================
# Utility helpers
# =============================


def encrypt_secret(secret: bytes):
    aesgcm = AESGCM(MASTER_KEY)
    nonce = secrets.token_bytes(12)
    return aesgcm.encrypt(nonce, secret, None), nonce


def decrypt_secret(ciphertext: bytes, nonce: bytes):
    aesgcm = AESGCM(MASTER_KEY)
    return aesgcm.decrypt(nonce, ciphertext, None)


def generate_totp_secret():
    return secrets.token_bytes(32)


def base32_encode(secret: bytes):
    return base64.b32encode(secret).decode().replace("=", "")


def show_qr(uri: str):
    qr = qrcode.QRCode(border=1)
    qr.add_data(uri)
    qr.make(fit=True)
    qr.print_ascii(invert=True)


def is_locked(locked_until):
    return locked_until and time.time() < locked_until


def lock_account(username):
    with sqlite3.connect(DB_PATH) as conn:
        cur = conn.cursor()
        cur.execute(
            "UPDATE users SET locked_until = ? WHERE username = ?",
            (int(time.time()) + LOCKOUT_SECONDS, username),
        )
        conn.commit()


def reset_counters(username):
    with sqlite3.connect(DB_PATH) as conn:
        cur = conn.cursor()
        cur.execute(
            """
            UPDATE users
            SET failed_password_attempts = 0,
                failed_mfa_attempts = 0,
                locked_until = 0
            WHERE username = ?
            """,
            (username,),
        )
        conn.commit()


# =============================
# Backup codes
# =============================


def generate_backup_codes():
    return [secrets.token_hex(4).upper() for _ in range(BACKUP_CODE_COUNT)]


def hash_backup_codes(codes):
    return json.dumps([ph.hash(code) for code in codes])


def verify_backup_code(stored_hashes, user_code):
    hashes = json.loads(stored_hashes)
    remaining = []

    for h in hashes:
        try:
            ph.verify(h, user_code)
            return True, json.dumps(remaining + hashes[hashes.index(h) + 1 :])
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            remaining.append(h)

    return False, json.dumps(remaining)


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

    uri = totp.provisioning_uri(name=username, issuer_name=ISSUER)
    cipher, nonce = encrypt_secret(secret)

    backup_codes = generate_backup_codes()
    backup_hashes = hash_backup_codes(backup_codes)

    try:
        with sqlite3.connect(DB_PATH) as conn:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO users
                (username, password_hash, totp_secret_enc, totp_nonce,
                 backup_codes_hash, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    username,
                    password_hash,
                    cipher,
                    nonce,
                    backup_hashes,
                    int(time.time()),
                ),
            )
            conn.commit()
    except sqlite3.IntegrityError:
        print("[!] Username already exists")
        return

    print("\nAccount created successfully!")
    print("\nScan this QR in Google Authenticator:\n")
    show_qr(uri)

    print("\nBackup codes (SAVE THESE NOW):")
    for c in backup_codes:
        print(" ", c)
    print("\nEach code can be used ONCE.\n")


def login():
    username = input("Username: ").strip()
    password = getpass("Password: ")

    with sqlite3.connect(DB_PATH) as conn:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT password_hash, totp_secret_enc, totp_nonce,
                   backup_codes_hash, failed_password_attempts,
                   failed_mfa_attempts, locked_until
            FROM users WHERE username = ?
            """,
            (username,),
        )
        row = cur.fetchone()

    if not row:
        print("[!] Invalid username or password")
        return

    (
        password_hash,
        secret_enc,
        nonce,
        backup_hashes,
        pwd_fails,
        mfa_fails,
        locked_until,
    ) = row

    # Lockout check
    if is_locked(locked_until):
        remaining = int(locked_until - time.time())
        print(f"[!] Account locked. Try again in {remaining} seconds.")
        return

    # Password check
    try:
        ph.verify(password_hash, password)
    except VerifyMismatchError:
        pwd_fails += 1
        with sqlite3.connect(DB_PATH) as conn:
            cur = conn.cursor()
            cur.execute(
                "UPDATE users SET failed_password_attempts = ? WHERE username = ?",
                (pwd_fails, username),
            )
            conn.commit()

        if pwd_fails >= MAX_PASSWORD_ATTEMPTS:
            lock_account(username)
            print("[!] Too many failed attempts. Account locked.")
        else:
            print("[!] Invalid username or password")
        return

    # Reset password failures
    with sqlite3.connect(DB_PATH) as conn:
        cur = conn.cursor()
        cur.execute(
            "UPDATE users SET failed_password_attempts = 0 WHERE username = ?",
            (username,),
        )
        conn.commit()

    # MFA
    secret = decrypt_secret(secret_enc, nonce)
    secret_b32 = base32_encode(secret)

    code = input("Enter 6-digit authenticator code: ").strip()
    totp = pyotp.TOTP(
        secret_b32,
        digits=TOTP_DIGITS,
        interval=TOTP_PERIOD,
        digest=hashlib.sha256,
    )

    if totp.verify(code, valid_window=1):
        reset_counters(username)
        print("\n[✓] Login successful (TOTP)\n")
        return

    print("[!] TOTP failed. Try a backup code.")
    backup = input("Enter backup code (or press Enter to cancel): ").strip()

    ok = False
    if backup:
        ok, updated_hashes = verify_backup_code(backup_hashes, backup)
        if ok:
            with sqlite3.connect(DB_PATH) as conn:
                cur = conn.cursor()
                cur.execute(
                    "UPDATE users SET backup_codes_hash = ? WHERE username = ?",
                    (updated_hashes, username),
                )
                conn.commit()

    if ok:
        reset_counters(username)
        print("\n[✓] Login successful (backup code used)\n")
        return

    # MFA failed
    mfa_fails += 1
    with sqlite3.connect(DB_PATH) as conn:
        cur = conn.cursor()
        cur.execute(
            "UPDATE users SET failed_mfa_attempts = ? WHERE username = ?",
            (mfa_fails, username),
        )
        conn.commit()

    if mfa_fails >= MAX_MFA_ATTEMPTS:
        lock_account(username)
        print("[!] Too many MFA failures. Account locked.")
    else:
        print("[!] Invalid authentication attempt")


# =============================
# Main
# =============================


def main():
    init_db()
    while True:
        print("\n=== Offline MFA CLI ===")
        print("1) Create account")
        print("2) Login")
        print("3) Exit")

        c = input("> ").strip()
        if c == "1":
            create_account()
        elif c == "2":
            login()
        elif c == "3":
            sys.exit(0)
        else:
            print("Invalid choice")


if __name__ == "__main__":
    main()
