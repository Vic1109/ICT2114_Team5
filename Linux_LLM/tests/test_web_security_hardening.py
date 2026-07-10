"""Browser-boundary and data-minimization regressions for authenticated SOC pages."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient


CONFIG_DIR = Path(__file__).resolve().parents[1] / "config"
if str(CONFIG_DIR) not in sys.path:
    sys.path.insert(0, str(CONFIG_DIR))

from main import SOCApplication, generate_alert_uuid  # noqa: E402


class BrowserBoundaryTests(unittest.TestCase):
    def _client(self):
        application = SOCApplication.__new__(SOCApplication)
        application.app = FastAPI()
        application._install_security_middleware()

        @application.app.get("/read")
        async def read():
            return {"ok": True}

        @application.app.post("/mutate")
        async def mutate():
            return {"ok": True}

        return TestClient(application.app)

    def test_state_changes_reject_cross_origin_browser_requests(self):
        with self._client() as client:
            rejected = client.post(
                "/mutate",
                headers={"Origin": "https://attacker.invalid"},
            )
            same_origin = client.post(
                "/mutate",
                headers={"Origin": "http://testserver"},
            )
            api_client = client.post("/mutate")

        self.assertEqual(rejected.status_code, 403)
        self.assertEqual(same_origin.status_code, 200)
        self.assertEqual(api_client.status_code, 200)

    def test_security_headers_prevent_framing_sniffing_and_remote_preview_images(self):
        with self._client() as client:
            response = client.get("/read")

        self.assertEqual(response.headers["x-frame-options"], "DENY")
        self.assertEqual(response.headers["x-content-type-options"], "nosniff")
        self.assertEqual(response.headers["cache-control"], "no-store")
        policy = response.headers["content-security-policy"]
        self.assertIn("frame-ancestors 'none'", policy)
        self.assertIn("img-src 'self' data:", policy)


class AlertIdentityAndTemplateTests(unittest.TestCase):
    def test_full_alert_identity_distinguishes_fields_omitted_by_the_old_hash(self):
        first = {
            "timestamp": "2026-07-10T00:00:00Z",
            "rule": {"id": "7", "description": "same"},
            "data": {"src_ip": "192.0.2.1", "dest_ip": "198.51.100.2", "dest_port": 443},
        }
        second = {
            "data": {"dest_port": 8443, "dest_ip": "198.51.100.2", "src_ip": "192.0.2.1"},
            "rule": {"description": "same", "id": "7"},
            "timestamp": "2026-07-10T00:00:00Z",
        }
        reordered_first = {
            "data": {"dest_port": 443, "dest_ip": "198.51.100.2", "src_ip": "192.0.2.1"},
            "rule": {"description": "same", "id": "7"},
            "timestamp": "2026-07-10T00:00:00Z",
            "_alert_uuid": "transport-only",
        }

        self.assertNotEqual(generate_alert_uuid(first), generate_alert_uuid(second))
        self.assertEqual(generate_alert_uuid(first), generate_alert_uuid(reordered_first))

    def test_authenticated_templates_pin_external_assets_and_sanitize_preview(self):
        editor = (CONFIG_DIR / "templates/report_editor.html").read_text(encoding="utf-8")
        viewer = (CONFIG_DIR / "templates/alert_viewer.html").read_text(encoding="utf-8")
        dashboard = (CONFIG_DIR / "templates/dashboard.html").read_text(encoding="utf-8")

        self.assertIn("marked@9.1.6", editor)
        self.assertIn("integrity=", editor)
        self.assertIn("renderSafeMarkdown", editor)
        self.assertNotIn("previewDiv.innerHTML = marked.parse", editor)
        self.assertEqual(viewer.count("integrity="), 1)
        self.assertNotIn("bootstrap.bundle", viewer)
        self.assertIn("config_summary.ssh.configured", dashboard)
        self.assertNotIn("config_summary.ssh.host", dashboard)

    def test_live_alert_response_does_not_embed_complete_raw_records(self):
        source = (CONFIG_DIR / "main.py").read_text(encoding="utf-8")
        self.assertNotIn("'raw_alert': alert", source)


if __name__ == "__main__":
    unittest.main()
