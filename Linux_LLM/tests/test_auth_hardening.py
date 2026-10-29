"""Server-side logout, registration gating and the account audit log."""

from __future__ import annotations

import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace

from fastapi import FastAPI
from fastapi.testclient import TestClient
from fastapi.templating import Jinja2Templates


CONFIG_DIR = Path(__file__).resolve().parents[1] / "config"
if str(CONFIG_DIR) not in sys.path:
    sys.path.insert(0, str(CONFIG_DIR))

from auth import AuthStore, read_session, sign_session  # noqa: E402
from main import SOCApplication  # noqa: E402

SECRET = "test-secret-test-secret-test-secret"


class AuthStoreTests(unittest.TestCase):
    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.store = AuthStore(str(Path(self._dir.name) / "users.sqlite3"), "boss", "bootstrap-password", SECRET)

    def tearDown(self):
        self._dir.cleanup()

    def test_signed_sessions_carry_unique_ids(self):
        first = read_session(sign_session({"username": "a"}, SECRET), SECRET)
        second = read_session(sign_session({"username": "a"}, SECRET), SECRET)
        self.assertTrue(first["sid"])
        self.assertNotEqual(first["sid"], second["sid"])

    def test_revocation_persists_and_expired_rows_are_purged(self):
        self.store.revoke_session("old", int(time.time()) - 10)
        self.store.revoke_session("current", int(time.time()) + 600)
        self.assertTrue(self.store.is_session_revoked("current"))
        self.assertFalse(self.store.is_session_revoked("never-issued"))
        # Purge runs before each insert, so "old" is gone once another revocation lands.
        self.store.revoke_session("later", int(time.time()) + 600)
        self.assertFalse(self.store.is_session_revoked("old"))

    def test_audit_events_are_listed_newest_first_and_paginate(self):
        for index in range(3):
            self.store.record_event(actor="boss", action=f"step{index}", client_ip="127.0.0.1")
        events = self.store.list_events(limit=2)
        self.assertEqual([event["action"] for event in events], ["step2", "step1"])
        older = self.store.list_events(limit=5, before_id=events[-1]["id"])
        self.assertEqual([event["action"] for event in older], ["step0"])


class AuthRouteTests(unittest.TestCase):
    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self._dir.cleanup()

    def _application(self, allow_registration: bool = False) -> SOCApplication:
        application = SOCApplication.__new__(SOCApplication)
        application.config = SimpleNamespace(
            web=SimpleNamespace(username="boss", password="bootstrap-password", allow_registration=allow_registration),
            paths=SimpleNamespace(reports_dir=self._dir.name),
        )
        application.app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
        application.templates = Jinja2Templates(directory=str(CONFIG_DIR / "templates"))
        application.templates.env.globals["allow_registration"] = allow_registration
        application._static_version = "test"
        application._pending_totp = {}
        application.session_results = {}
        application.draft_reports = {}
        application.session_cookie_name = "soc_session"
        application.session_secret = SECRET
        application.auth_store = AuthStore(
            str(Path(self._dir.name) / "users.sqlite3"), "boss", "bootstrap-password", SECRET
        )
        application._setup_routes()
        return application

    def _cookie(self, application, username="boss"):
        user = application.auth_store.get_user(username)
        return sign_session(
            {"username": username, "role": user["role"], "auth_version": user["auth_version"], "authenticated": True},
            SECRET,
        )

    def test_logout_revokes_the_cookie_server_side(self):
        application = self._application()
        cookie = self._cookie(application)
        with TestClient(application.app) as client:
            client.cookies.set("soc_session", cookie)
            self.assertEqual(client.get("/admin/audit").status_code, 200)
            client.post("/logout", follow_redirects=False)
            # Replay the copied cookie after the browser has dropped it.
            client.cookies.set("soc_session", cookie)
            self.assertEqual(client.get("/admin/audit").status_code, 401)

        actions = [event["action"] for event in application.auth_store.list_events()]
        self.assertIn("logout", actions)

    def test_other_sessions_survive_one_logout(self):
        application = self._application()
        laptop, phone = self._cookie(application), self._cookie(application)
        with TestClient(application.app) as client:
            client.cookies.set("soc_session", laptop)
            client.post("/logout", follow_redirects=False)
            client.cookies.set("soc_session", phone)
            self.assertEqual(client.get("/admin/audit").status_code, 200)

    def test_registration_is_disabled_by_default(self):
        application = self._application()
        with TestClient(application.app) as client:
            self.assertEqual(client.get("/register").status_code, 404)
            response = client.post("/register", data={
                "username": "intruder", "password": "long-enough-pass", "confirm_password": "long-enough-pass",
            })
            self.assertEqual(response.status_code, 404)
            self.assertNotIn('href="/register"', client.get("/login").text)
        self.assertIsNone(application.auth_store.get_user("intruder"))

    def test_registration_can_be_enabled_and_is_audited(self):
        application = self._application(allow_registration=True)
        with TestClient(application.app) as client:
            self.assertIn('href="/register"', client.get("/login").text)
            response = client.post("/register", data={
                "username": "newanalyst", "password": "long-enough-pass", "confirm_password": "long-enough-pass",
            }, follow_redirects=False)
        self.assertEqual(response.status_code, 303)
        self.assertEqual(application.auth_store.get_user("newanalyst")["role"], "analyst")
        self.assertEqual(application.auth_store.list_events()[0]["action"], "register")

    def test_failed_login_and_admin_changes_are_audited(self):
        application = self._application()
        with TestClient(application.app) as client:
            client.post("/login", data={"username": "boss", "password": "wrong-password"})
            client.cookies.set("soc_session", self._cookie(application))
            client.post("/admin/users", json={"username": "analyst1", "password": "long-enough-pass", "role": "analyst"})
            client.delete("/admin/users/analyst1")
            audit = client.get("/admin/audit").json()

        summary = [(event["actor"], event["action"], event["outcome"], event["target"]) for event in audit]
        self.assertIn(("boss", "login", "failure", None), summary)
        self.assertIn(("boss", "user_create", "success", "analyst1"), summary)
        self.assertIn(("boss", "user_disable", "success", "analyst1"), summary)

    def test_analysts_cannot_read_the_audit_log(self):
        application = self._application()
        application.auth_store.create_user("analyst1", "long-enough-pass", "analyst")
        with TestClient(application.app) as client:
            client.cookies.set("soc_session", self._cookie(application, "analyst1"))
            self.assertEqual(client.get("/admin/audit").status_code, 403)

    def test_api_docs_require_sign_in_for_any_role(self):
        application = self._application()
        application.auth_store.create_user("analyst1", "long-enough-pass", "analyst")
        with TestClient(application.app) as client:
            self.assertEqual(client.get("/openapi.json").status_code, 401)
            anonymous = client.get("/docs", headers={"Accept": "text/html"}, follow_redirects=False)
            self.assertEqual(anonymous.status_code, 303)
            self.assertEqual(client.get("/redoc").status_code, 404)
            for user in ("boss", "analyst1"):
                client.cookies.set("soc_session", self._cookie(application, user))
                self.assertEqual(client.get("/docs").status_code, 200, user)
                schema = client.get("/openapi.json")
                self.assertEqual(schema.status_code, 200, user)
                self.assertIn("/admin/audit", schema.json()["paths"])
                self.assertNotIn("/docs", schema.json()["paths"])


class ReportPathTests(unittest.TestCase):
    def test_only_top_level_markdown_and_pdf_reports_resolve(self):
        from fastapi import HTTPException
        from main import resolve_report_path

        with tempfile.TemporaryDirectory() as reports:
            root = Path(reports)
            self.assertEqual(resolve_report_path(root, "report.md").parent, root.resolve())
            self.assertEqual(resolve_report_path(root, "report.PDF").name, "report.PDF")
            for hostile in (
                "../secrets.md", "..\\secrets.md", "sub/report.md", "/etc/passwd", "C:report.md",
                "report.md:hidden", ".env.md", "report.md\x00.pdf", "notes.html", "users.sqlite3",
                "trace.json", "", "a" * 253 + ".md",
            ):
                with self.assertRaises(HTTPException, msg=repr(hostile)):
                    resolve_report_path(root, hostile)


if __name__ == "__main__":
    unittest.main()
