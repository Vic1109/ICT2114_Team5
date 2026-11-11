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


class AccountDeletionError(Exception):
    def __init__(self, status_code: int, detail: str):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


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
                totp_last_counter INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL
            )""")
            columns = {row[1] for row in db.execute("PRAGMA table_info(users)")}
            if "auth_version" not in columns:
                db.execute("ALTER TABLE users ADD COLUMN auth_version INTEGER NOT NULL DEFAULT 0")
            if "totp_last_counter" not in columns:
                db.execute("ALTER TABLE users ADD COLUMN totp_last_counter INTEGER NOT NULL DEFAULT 0")
            # Signed cookies are stateless, so logout records the session id here
            # until the cookie would have expired anyway.
            db.execute("""CREATE TABLE IF NOT EXISTS revoked_sessions (
                sid TEXT PRIMARY KEY,
                expires_at INTEGER NOT NULL
            )""")
            
            db.execute("""CREATE TABLE IF NOT EXISTS audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at INTEGER NOT NULL,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                target TEXT,
                client_ip TEXT,
                outcome TEXT NOT NULL,
                detail TEXT
            )""")
            db.execute("""CREATE TABLE IF NOT EXISTS account_deletion_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_username TEXT NOT NULL,
                requested_by TEXT NOT NULL,
                requested_at INTEGER NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending'
                    CHECK(status IN ('pending','approved','cancelled')),
                approved_by TEXT,
                resolved_at INTEGER
            )""")
            db.execute("""CREATE UNIQUE INDEX IF NOT EXISTS one_pending_deletion_per_user
                ON account_deletion_requests(target_username COLLATE NOCASE)
                WHERE status='pending'""")
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

    def get_user_metadata(self, username: str):
        """Read account state without decrypting the stored MFA secret."""
        with self._connect() as db:
            row = db.execute(
                "SELECT username,role,enabled,auth_version,(totp_secret IS NOT NULL) AS mfa_enabled "
                "FROM users WHERE username=? COLLATE NOCASE",
                (username,),
            ).fetchone()
        return dict(row) if row else None

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

    def create_account_deletion_request(self, target_username: str, requested_by: str):
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            requester = db.execute(
                "SELECT role,enabled FROM users WHERE username=? COLLATE NOCASE", (requested_by,),
            ).fetchone()
            if not requester or requester["role"] != "admin" or not requester["enabled"]:
                raise AccountDeletionError(403, "An active administrator is required")
            target = db.execute(
                "SELECT username FROM users WHERE username=? COLLATE NOCASE", (target_username,),
            ).fetchone()
            if not target:
                raise AccountDeletionError(404, "User not found")
            if target["username"].casefold() == requested_by.casefold():
                raise AccountDeletionError(400, "Administrators cannot request deletion of their own account")
            existing = db.execute(
                "SELECT id,target_username,requested_by,requested_at FROM account_deletion_requests "
                "WHERE target_username=? COLLATE NOCASE AND status='pending'",
                (target["username"],),
            ).fetchone()
            if existing:
                return {**dict(existing), "created": False}
            cursor = db.execute(
                "INSERT INTO account_deletion_requests(target_username,requested_by,requested_at) VALUES(?,?,?)",
                (target["username"], requested_by, int(time.time())),
            )
            return {
                "id": cursor.lastrowid,
                "target_username": target["username"],
                "requested_by": requested_by,
                "requested_at": int(time.time()),
                "created": True,
            }

    def list_pending_account_deletions(self):
        with self._connect() as db:
            rows = db.execute(
                "SELECT r.id,r.target_username,r.requested_by,r.requested_at,"
                "u.role AS target_role,u.enabled AS target_enabled "
                "FROM account_deletion_requests AS r "
                "LEFT JOIN users AS u ON u.username=r.target_username COLLATE NOCASE "
                "WHERE r.status='pending' ORDER BY r.requested_at,r.id"
            )
            return [dict(row) for row in rows]

    def approve_account_deletion(self, request_id: int, approved_by: str):
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            request = db.execute(
                "SELECT id,target_username,requested_by FROM account_deletion_requests "
                "WHERE id=? AND status='pending'", (request_id,),
            ).fetchone()
            if not request:
                raise AccountDeletionError(404, "Pending deletion request not found")
            if request["requested_by"].casefold() == approved_by.casefold():
                raise AccountDeletionError(403, "A different administrator must approve this request")
            if request["target_username"].casefold() == approved_by.casefold():
                raise AccountDeletionError(403, "The account being deleted cannot approve its deletion")
            requester = db.execute(
                "SELECT role,enabled FROM users WHERE username=? COLLATE NOCASE", (request["requested_by"],),
            ).fetchone()
            approver = db.execute(
                "SELECT role,enabled FROM users WHERE username=? COLLATE NOCASE", (approved_by,),
            ).fetchone()
            if not requester or requester["role"] != "admin" or not requester["enabled"]:
                raise AccountDeletionError(409, "The requesting administrator is no longer active")
            if not approver or approver["role"] != "admin" or not approver["enabled"]:
                raise AccountDeletionError(403, "An active administrator is required to approve")
            target = db.execute(
                "SELECT username,role,enabled FROM users WHERE username=? COLLATE NOCASE",
                (request["target_username"],),
            ).fetchone()
            if not target:
                raise AccountDeletionError(404, "The account no longer exists")
            active_admins = int(db.execute(
                "SELECT COUNT(*) FROM users WHERE role='admin' AND enabled=1"
            ).fetchone()[0])
            admins_removed = 1 if target["role"] == "admin" and target["enabled"] else 0
            if active_admins <= admins_removed:
                raise AccountDeletionError(409, "Cannot delete the last active administrator")
            db.execute("DELETE FROM users WHERE username=? COLLATE NOCASE", (target["username"],))
            db.execute(
                "UPDATE account_deletion_requests SET status='approved',approved_by=?,resolved_at=? WHERE id=?",
                (approved_by, int(time.time()), request_id),
            )
            return {"username": target["username"], "requested_by": request["requested_by"]}

    def cancel_account_deletion(self, request_id: int, cancelled_by: str):
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            admin = db.execute(
                "SELECT role,enabled FROM users WHERE username=? COLLATE NOCASE", (cancelled_by,),
            ).fetchone()
            if not admin or admin["role"] != "admin" or not admin["enabled"]:
                raise AccountDeletionError(403, "An active administrator is required")
            row = db.execute(
                "SELECT target_username FROM account_deletion_requests WHERE id=? AND status='pending'",
                (request_id,),
            ).fetchone()
            if not row:
                raise AccountDeletionError(404, "Pending deletion request not found")
            db.execute(
                "UPDATE account_deletion_requests SET status='cancelled',approved_by=?,resolved_at=? WHERE id=?",
                (cancelled_by, int(time.time()), request_id),
            )
            return row["target_username"]

    def list_users(self):
        with self._connect() as db:
            return [dict(row) for row in db.execute(
                "SELECT username,role,enabled,created_at,(totp_secret IS NOT NULL) AS mfa_enabled FROM users ORDER BY username"
            )]

    def revoke_session(self, sid: str, expires_at: int):
        now = int(time.time())
        with self._connect() as db:
            db.execute("DELETE FROM revoked_sessions WHERE expires_at < ?", (now,))
            db.execute(
                "INSERT OR REPLACE INTO revoked_sessions(sid,expires_at) VALUES(?,?)",
                (sid, int(expires_at)),
            )

    def is_session_revoked(self, sid: str) -> bool:
        with self._connect() as db:
            return db.execute("SELECT 1 FROM revoked_sessions WHERE sid=?", (sid,)).fetchone() is not None

    def record_event(self, actor: str, action: str, target: str | None = None,
                     client_ip: str | None = None, outcome: str = "success", detail: str | None = None):
        with self._connect() as db:
            db.execute(
                "INSERT INTO audit_events(created_at,actor,action,target,client_ip,outcome,detail) VALUES(?,?,?,?,?,?,?)",
                (int(time.time()), actor[:128], action[:64], (target or "")[:256] or None,
                 client_ip, outcome[:32], (detail or "")[:512] or None),
            )

    def list_events(self, limit: int = 200, before_id: int | None = None, action: str | None = None,
                    outcome: str | None = None, actor: str | None = None):
        limit = max(1, min(int(limit), 1000))
        clauses, params = [], []
        if before_id:
            clauses.append("id < ?")
            params.append(int(before_id))
        if action:
            clauses.append("action = ?")
            params.append(action)
        if outcome:
            clauses.append("outcome = ?")
            params.append(outcome)
        if actor:
            clauses.append("actor = ? COLLATE NOCASE")
            params.append(actor)
        where = f"WHERE {' AND '.join(clauses)} " if clauses else ""
        with self._connect() as db:
            rows = db.execute(f"SELECT * FROM audit_events {where}ORDER BY id DESC LIMIT ?", (*params, limit))
            return [dict(row) for row in rows]

    def list_event_actions(self):
        with self._connect() as db:
            return [row[0] for row in db.execute("SELECT DISTINCT action FROM audit_events ORDER BY action")]

    def claim_totp(self, username: str, secret: str, code: str) -> bool:
        matched = verify_totp(secret, code)
        if matched is None:
            return False
        with self._connect() as db:
            cur = db.execute(
                "UPDATE users SET totp_last_counter=? "
                "WHERE username=? COLLATE NOCASE AND totp_last_counter < ?",
                (matched, username, matched),
            )
            return cur.rowcount == 1  

def new_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def verify_totp(secret: str, code: str, now: int | None = None) -> int | None:
    if not code or not code.isdigit() or len(code) != 6:
        return None
    try:
        key = base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
    except (ValueError, TypeError):
        return None
    counter = int((now if now is not None else time.time()) // 30)
    for offset in (-1, 0, 1):
        digest = hmac.new(key, struct.pack(">Q", counter + offset), hashlib.sha1).digest()
        index = digest[-1] & 0x0F
        value = (struct.unpack(">I", digest[index:index + 4])[0] & 0x7FFFFFFF) % 1_000_000
        if hmac.compare_digest(f"{value:06d}", code):
            return counter + offset
    return None


def sign_session(payload: dict[str, Any], secret: str, max_age: int = 8 * 60 * 60) -> str:
    body = dict(payload, exp=int(time.time()) + max_age)
    body.setdefault("sid", secrets.token_urlsafe(16))
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
