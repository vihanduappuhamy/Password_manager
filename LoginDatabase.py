import sqlite3
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import base64
import os
import time

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION = 300  # seconds (5 minutes)

class AuthentionDatabase:
    def __init__(self, db_path="auth.db"):
        self.db_path = db_path
        self.enc_key = None  # will hold encryption key after login
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                         CREATE TABLE IF NOT EXISTS users
                         (
                             id INTEGER PRIMARY KEY AUTOINCREMENT,
                             username TEXT NOT NULL UNIQUE,
                             password_hash TEXT NOT NULL,
                             salt BLOB NOT NULL,
                             failed_attempts INTEGER DEFAULT 0,
                             last_failed_login REAL DEFAULT 0
                         )
                         """)
            conn.execute("""
                         CREATE TABLE IF NOT EXISTS passwords
                         (
                             id INTEGER PRIMARY KEY AUTOINCREMENT,
                             username TEXT NOT NULL,
                             website TEXT NOT NULL,
                             site_username TEXT,
                             nonce BLOB NOT NULL,
                             password BLOB NOT NULL
                         )
                         """)

    def _derive_keys(self, master_password: str, salt: bytes) -> tuple[str, bytes]:
        """Derive two keys: auth_key (base64 str), enc_key (bytes)"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=64,  # derive 64 bytes
            salt=salt,
            iterations=480000,
        )
        full_key = kdf.derive(master_password.encode())
        auth_key = base64.b64encode(full_key[:32]).decode()
        enc_key = full_key[32:]  # bytes
        return auth_key, enc_key

    def create_user(self, username: str, password: str):
        salt = os.urandom(16)
        auth_key, _ = self._derive_keys(password, salt)

        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO users (username, password_hash, salt)
                VALUES (?, ?, ?)
            """, (username, auth_key, salt))

    def verify_user(self, username: str, password: str) -> bool:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT password_hash, salt, failed_attempts, last_failed_login FROM users WHERE username = ?",
                (username,))
            row = cursor.fetchone()

            if row:
                stored_hash, salt, failed_attempts, last_failed_login = row
                try:
                    provided_auth, enc_key = self._derive_keys(password, salt)
                    if stored_hash == provided_auth:
                        # ✅ Save encryption key in memory for vault use
                        self.enc_key = enc_key
                        # Reset failed attempts on successful login
                        cursor.execute("UPDATE users SET failed_attempts = 0, last_failed_login = 0 WHERE username = ?",
                                       (username,))
                        conn.commit()
                        return True
                    else:
                        failed_attempts = failed_attempts or 0
                        failed_attempts += 1
                        cursor.execute("UPDATE users SET failed_attempts = ?, last_failed_login = ? WHERE username = ?",
                                       (failed_attempts, time.time(), username))
                        conn.commit()
                        return False
                except Exception:
                    return False
            return False

    def is_locked_out(self, username: str) -> tuple[bool, float]:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                           SELECT failed_attempts, last_failed_login
                           FROM users
                           WHERE username = ?
                           """, (username,))
            row = cursor.fetchone()

            if row:
                failed_attempts, last_failed_login = row
                if failed_attempts >= MAX_FAILED_ATTEMPTS:
                    time_since_last_fail = time.time() - last_failed_login
                    if time_since_last_fail < LOCKOUT_DURATION:
                        return True, LOCKOUT_DURATION - time_since_last_fail
        return False, 0

    def update_username(self, current_username: str, new_username: str):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("UPDATE users SET username = ? WHERE username = ?", (new_username, current_username))

    def update_password(self, username: str, new_password: str):
        salt = os.urandom(16)
        auth_key, enc_key = self._derive_keys(new_password, salt)
        self.enc_key = enc_key  # update in memory
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("UPDATE users SET password_hash = ?, salt = ? WHERE username = ?",
                         (auth_key, salt, username))

    def save_website_password(self, username, website, site_username, password):
        if not self.enc_key:
            raise ValueError("Encryption key not available. User must be logged in.")

        aesgcm = AESGCM(self.enc_key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, password.encode(), None)

        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                         INSERT INTO passwords (username, website, site_username, nonce, password)
                         VALUES (?, ?, ?, ?, ?)
                         """, (username, website, site_username, nonce, ciphertext))

    def get_passwords_for_user(self, username):
        if not self.enc_key:
            raise ValueError("Encryption key not available. User must be logged in.")

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT website, site_username, nonce, password FROM passwords WHERE username = ?", (username,))
            rows = cursor.fetchall()

        aesgcm = AESGCM(self.enc_key)
        decrypted_entries = []
        for website, site_username, nonce, ciphertext in rows:
            try:
                plaintext = aesgcm.decrypt(nonce, ciphertext, None).decode()
            except Exception:
                plaintext = "[Decryption Failed]"
            decrypted_entries.append((website, site_username, plaintext))

        return decrypted_entries
