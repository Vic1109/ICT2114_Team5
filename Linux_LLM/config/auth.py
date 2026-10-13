"""Small app-managed authentication primitives (passwords, TOTP and signed cookies)."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import struct
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any
from cryptography.fernet import Fernet


class AuthStore:
    """SQLite-backed accounts; the initial WEB_* account is the bootstrap admin."""

    def __init__(self, database: str, bootstrap_username: str, bootstrap_password: str, encryption_key: str):
        if len(bootstrap_password) < 12:
            raise ValueError("WEB_PASSWORD must be at least 12 characters for the bootstrap admin")
        self.path = Path(database).expanduser()
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        key = hashlib.sha256(b"soc-rag-totp:" + encryption_key.encode()).digest()
        self._fernet = Fernet(base64.urlsafe_b64encode(key))
        with self._connect() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('admin','analyst')),
                totp_secret TEXT,
                enabled INTEGER NOT NULL DEFAULT 1,
                auth_version INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL
            )""")
            columns = {row[1] for row in db.execute("PRAGMA table_info(users)")}
            if "auth_version" not in columns:
                db.execute("ALTER TABLE users ADD COLUMN auth_version INTEGER NOT NULL DEFAULT 0")
            count = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
            if not count and bootstrap_username and bootstrap_password:
                db.execute(
                    "INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)",
                    (bootstrap_username, self.hash_password(bootstrap_password), "admin", int(time.time())),
                )
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    @contextmanager
    def _connect(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA journal_mode=WAL")
        try:
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    @staticmethod
    def hash_password(password: str) -> str:
        salt = secrets.token_bytes(16)
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 310_000)
        return "pbkdf2_sha256$310000$%s$%s" % (
            base64.urlsafe_b64encode(salt).decode(), base64.urlsafe_b64encode(digest).decode()
        )

    @staticmethod
    def verify_password(password: str, encoded: str) -> bool:
        try:
            scheme, iterations, salt, expected = encoded.split("$", 3)
            if scheme != "pbkdf2_sha256":
                return False
            digest = hashlib.pbkdf2_hmac(
                "sha256", password.encode(), base64.urlsafe_b64decode(salt), int(iterations)
            )
            return hmac.compare_digest(base64.urlsafe_b64encode(digest).decode(), expected)
        except (ValueError, TypeError):
            return False

    def get_user(self, username: str):
        with self._connect() as db:
            row = db.execute(
                "SELECT username,password_hash,role,totp_secret,enabled,auth_version FROM users WHERE username=? COLLATE NOCASE",
                (username,),
            ).fetchone()
        if not row:
            return None
        result = dict(row)
        if result["totp_secret"]:
            result["totp_secret"] = self._fernet.decrypt(result["totp_secret"].encode()).decode()
        return result

    def create_user(self, username: str, password: str, role: str):
        with self._connect() as db:
            db.execute(
                "INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)",
                (username, self.hash_password(password), role, int(time.time())),
            )

    def set_password(self, username: str, password: str):
        with self._connect() as db:
            db.execute(
                "UPDATE users SET password_hash=?,auth_version=auth_version+1 WHERE username=? COLLATE NOCASE",
                (self.hash_password(password), username),
            )

    def set_role(self, username: str, role: str):
        with self._connect() as db:
            db.execute(
                "UPDATE users SET role=?,auth_version=auth_version+1 WHERE username=? COLLATE NOCASE",
                (role, username),
            )

    def active_admin_count(self) -> int:
        with self._connect() as db:
            return int(db.execute("SELECT COUNT(*) FROM users WHERE role='admin' AND enabled=1").fetchone()[0])

    def set_totp_secret(self, username: str, secret: str):
        encrypted = self._fernet.encrypt(secret.encode()).decode()
        with self._connect() as db:
            db.execute("UPDATE users SET totp_secret=?,auth_version=auth_version+1 WHERE username=? COLLATE NOCASE", (encrypted, username))

    def reset_totp(self, username: str):
        with self._connect() as db:
            db.execute("UPDATE users SET totp_secret=NULL,auth_version=auth_version+1 WHERE username=? COLLATE NOCASE", (username,))

    def disable_user(self, username: str):
        with self._connect() as db:
            db.execute("UPDATE users SET enabled=0,auth_version=auth_version+1 WHERE username=? COLLATE NOCASE", (username,))

    def enable_user(self, username: str):
        with self._connect() as db:
            db.execute("UPDATE users SET enabled=1,auth_version=auth_version+1 WHERE username=? COLLATE NOCASE", (username,))

    def delete_user(self, username: str):
        with self._connect() as db:
            db.execute("DELETE FROM users WHERE username=? COLLATE NOCASE", (username,))

    def list_users(self):
        with self._connect() as db:
            return [dict(row) for row in db.execute(
                "SELECT username,role,enabled,created_at,(totp_secret IS NOT NULL) AS mfa_enabled FROM users ORDER BY username"
            )]


def new_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def verify_totp(secret: str, code: str, now: int | None = None) -> bool:
    if not code or not code.isdigit() or len(code) != 6:
        return False
    try:
        key = base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
    except (ValueError, TypeError):
        return False
    counter = int((now if now is not None else time.time()) // 30)
    for offset in (-1, 0, 1):
        digest = hmac.new(key, struct.pack(">Q", counter + offset), hashlib.sha1).digest()
        index = digest[-1] & 0x0F
        value = (struct.unpack(">I", digest[index:index + 4])[0] & 0x7FFFFFFF) % 1_000_000
        if hmac.compare_digest(f"{value:06d}", code):
            return True
    return False


def sign_session(payload: dict[str, Any], secret: str, max_age: int = 8 * 60 * 60) -> str:
    body = dict(payload, exp=int(time.time()) + max_age)
    encoded = base64.urlsafe_b64encode(json.dumps(body, separators=(",", ":")).encode()).decode().rstrip("=")
    signature = hmac.new(secret.encode(), encoded.encode(), hashlib.sha256).digest()
    return encoded + "." + base64.urlsafe_b64encode(signature).decode().rstrip("=")


def read_session(cookie: str | None, secret: str) -> dict[str, Any] | None:
    if not cookie or "." not in cookie:
        return None
    try:
        encoded, supplied = cookie.rsplit(".", 1)
        expected = base64.urlsafe_b64encode(
            hmac.new(secret.encode(), encoded.encode(), hashlib.sha256).digest()
        ).decode().rstrip("=")
        if not hmac.compare_digest(supplied, expected):
            return None
        payload = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
        if int(payload.get("exp", 0)) < int(time.time()):
            return None
        return payload
    except (ValueError, TypeError, json.JSONDecodeError):
        return None
