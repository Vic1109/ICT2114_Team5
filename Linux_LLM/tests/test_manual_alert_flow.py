"""Integration/regression coverage for the production manual alert upload path."""

from __future__ import annotations

import json
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from fastapi import FastAPI
from fastapi.security import HTTPBasic
from fastapi.testclient import TestClient
from fastapi.templating import Jinja2Templates


CONFIG_DIR = Path(__file__).resolve().parents[1] / "config"
if str(CONFIG_DIR) not in sys.path:
    sys.path.insert(0, str(CONFIG_DIR))

from auth import sign_session  # noqa: E402
from main import SOCApplication  # noqa: E402
from llm_provider import ProviderBusyError  # noqa: E402


class _ProgressStub:
    async def send_progress(self, *_args, **_kwargs):
        return True


class _ReportGeneratorStub:
    rag_ready = True

    def __init__(self):
        self.calls = []

    def generate_report_with_rag(self, current_alerts, source, is_automatic=False, trigger_info=None):
        self.calls.append({
            "current_alerts": current_alerts,
            "source": source,
            "is_automatic": is_automatic,
            "trigger_info": trigger_info,
        })
        return """**Executive Summary:** Manual path exercised.

**Key Findings:**
- Uploaded evidence reached the report generator.
- Manual mode was retained.
- Trigger metadata was retained.
- Charts flag was retained.

**Immediate Actions:**
- Review the uploaded host.

**Analysis Complete**
"""

    @staticmethod
    def get_generation_metrics():
        return {"avg_generation_time": 0.01, "reports_generated": 1}


def _alert(description="Manual multipart test"):
    return {
        "timestamp": "2026-06-06T08:10:00Z",
        "rule": {"id": "900001", "level": 12, "description": description},
        "agent": {"name": "fixture-host", "ip": "192.168.56.10"},
        "data": {
            "src_ip": "192.168.56.10",
            "dest_ip": "198.51.100.20",
            "alert": {"signature": description, "signature_id": 900001},
        },
    }


class ManualAlertParserTests(unittest.TestCase):
    def setUp(self):
        self.parser = SOCApplication.__new__(SOCApplication)

    def parse(self, payload):
        data = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        return self.parser._parse_uploaded_alert_template(data, "fixture.json")

    def test_supported_upload_shapes(self):
        single = self.parse(_alert("single"))
        array = self.parse([_alert("one"), _alert("two")])
        wrapper = self.parse({"alerts": [_alert("wrapped")]})
        ndjson = self.parser._parse_uploaded_alert_template(
            b"\n".join(json.dumps(item).encode() for item in (_alert("line one"), _alert("line two"))),
            "fixture.json",
        )
        self.assertEqual([len(single), len(array), len(wrapper), len(ndjson)], [1, 2, 1, 2])
        self.assertEqual(array[1]["rule"]["description"], "two")
        self.assertEqual(ndjson[0]["rule"]["description"], "line one")


class ManualMultipartEndpointTests(unittest.TestCase):
    def build_application(self, reports_dir: str):
        application = SOCApplication.__new__(SOCApplication)
        application.config = SimpleNamespace(
            web=SimpleNamespace(username="analyst", password="secret"),
            paths=SimpleNamespace(reports_dir=reports_dir),
            llm=SimpleNamespace(timeout=5),
            ssh=SimpleNamespace(host="unused.example"),
        )
        application.app = FastAPI()
        application.security = HTTPBasic()
        application.templates = Jinja2Templates(directory=str(CONFIG_DIR / "templates"))
        application.session_results = {}
        application.draft_reports = {}
        application.progress_tracker = _ProgressStub()
        application.report_generator = _ReportGeneratorStub()
        application.pdf_converter = SimpleNamespace(conversion_available=False)
        application.live_monitoring = SimpleNamespace()
        application.session_cookie_name = "soc_session"
        application.session_secret = "test-secret-test-secret-test-secret"
        application.auth_store = SimpleNamespace(
            get_user=lambda name: {
                "username": "analyst",
                "role": "analyst",
                "enabled": True,
                "auth_version": 1,
            } if name == "analyst" else None,
            is_session_revoked=lambda sid: False,
            record_event=lambda **event: None,
        )
        application._setup_routes()
        return application

    def test_exact_manual_multipart_path_reaches_report_generator(self):
        with tempfile.TemporaryDirectory() as reports_dir:
            application = self.build_application(reports_dir)
            cookie = sign_session(
                {"username": "analyst", "authenticated": True, "auth_version": 1},
                application.session_secret,
            )
            auth_headers = {"Cookie": f"{application.session_cookie_name}={cookie}"}
            with TestClient(application.app) as client:
                response = client.post(
                    "/analyze-alerts",
                    headers=auth_headers,
                    data={"include_charts": "true"},
                    files={
                        "alertTemplate": (
                            "uploaded-alert.json",
                            json.dumps({"alerts": [_alert()]}).encode(),
                            "application/json",
                        )
                    },
                )
                self.assertEqual(response.status_code, 200, response.text)
                session_id = response.json()["session_id"]

                result = None
                for _ in range(100):
                    polled = client.get(
                        f"/api/check-analysis-result/{session_id}",
                        headers=auth_headers,
                    )
                    self.assertEqual(polled.status_code, 200, polled.text)
                    result = polled.json()
                    if result.get("redirect"):
                        break
                    time.sleep(0.01)

            self.assertTrue(result and result.get("redirect"), result)
            self.assertEqual(len(application.report_generator.calls), 1)
            call = application.report_generator.calls[0]
            self.assertEqual(call["source"], "Manual uploaded alert")
            self.assertIs(call["is_automatic"], False)
            self.assertEqual(call["trigger_info"]["trigger_type"], "manual")
            self.assertIs(call["trigger_info"]["include_charts"], True)
            self.assertIn("timestamp", call["trigger_info"])
            self.assertEqual(call["current_alerts"][0]["rule"]["description"], "Manual multipart test")

    def test_second_upload_is_queued_and_can_be_cancelled(self):
        import threading
        started = threading.Event()
        release = threading.Event()
        with tempfile.TemporaryDirectory() as reports_dir:
            application = self.build_application(reports_dir)
            calls = []

            def slow(current_alerts, source, is_automatic=False, trigger_info=None, generation_reservation=None):
                calls.append(source)
                started.set()
                release.wait(3)
                return _ReportGeneratorStub.generate_report_with_rag(
                    application.report_generator,
                    current_alerts,
                    source,
                    is_automatic,
                    trigger_info,
                )

            application.report_generator.generate_report_with_rag = slow
            cookie = sign_session(
                {"username": "analyst", "authenticated": True, "auth_version": 1},
                application.session_secret,
            )
            headers = {"Cookie": f"{application.session_cookie_name}={cookie}"}
            upload = {
                "alertTemplate": (
                    "uploaded-alert.json",
                    json.dumps({"alerts": [_alert()]}).encode(),
                    "application/json",
                )
            }
            try:
                with TestClient(application.app) as client:
                    first = client.post("/analyze-alerts", headers=headers, files=upload)
                    self.assertEqual(first.status_code, 200, first.text)
                    self.assertTrue(started.wait(2))
                    second = client.post(
                        "/analyze-alerts",
                        headers=headers,
                        files={
                            "alertTemplate": (
                                "second.json",
                                json.dumps({"alerts": [_alert("second")]}).encode(),
                                "application/json",
                            )
                        },
                    )
                    self.assertEqual(second.status_code, 200, second.text)
                    self.assertNotEqual(second.json()["session_id"], first.json()["session_id"])
                    listed = client.get("/api/analysis-queue", headers=headers)
                    self.assertEqual(listed.status_code, 200, listed.text)
                    labels = [job["label"] for job in listed.json()["jobs"]]
                    self.assertIn("second.json", labels)
                    cancelled = client.post(
                        f"/api/analysis-queue/{second.json()['job_id']}/cancel",
                        headers=headers,
                    )
                    self.assertEqual(cancelled.status_code, 200, cancelled.text)
                    self.assertEqual(cancelled.json()["status"], "cancelled")
                    dismissed = client.post(
                        f"/api/analysis-queue/{second.json()['job_id']}/dismiss",
                        headers=headers,
                    )
                    self.assertEqual(dismissed.status_code, 200, dismissed.text)
                    after_dismiss = client.get("/api/analysis-queue", headers=headers)
                    self.assertNotIn(
                        "second.json",
                        [job["label"] for job in after_dismiss.json()["jobs"]],
                    )
                    stopped = client.post(
                        f"/api/analysis-queue/{first.json()['job_id']}/cancel",
                        headers=headers,
                    )
                    self.assertEqual(stopped.status_code, 200, stopped.text)
                    self.assertEqual(stopped.json()["status"], "cancelled")
                    still_up = client.get("/api/analysis-queue", headers=headers)
                    self.assertEqual(still_up.status_code, 200, still_up.text)
            finally:
                release.set()
            self.assertEqual(calls, ["Manual uploaded alert"])

    def test_queue_and_delete_controls_render(self):
        with tempfile.TemporaryDirectory() as reports_dir:
            report = Path(reports_dir) / "stored-report.md"
            report.write_text("**Executive Summary:** stored\n", encoding="utf-8")
            application = self.build_application(reports_dir)
            application.config.get_summary = lambda: {}
            application.report_generator.provider_status = lambda: {"provider": "local", "label": "Local"}
            cookie = sign_session(
                {"username": "analyst", "authenticated": True, "auth_version": 1},
                application.session_secret,
            )
            headers = {"Cookie": f"{application.session_cookie_name}={cookie}"}
            with TestClient(application.app) as client:
                analysis = client.get("/analysis", headers=headers)
                library = client.get("/library", headers=headers)
                removed = client.post("/reports/stored-report.md/delete", headers=headers)
            self.assertEqual(analysis.status_code, 200, analysis.text)
            self.assertIn("Alert queue", analysis.text)
            self.assertIn("analysisQueue", analysis.text)
            self.assertIn("data-dismiss-job", (CONFIG_DIR / "static" / "js" / "script.js").read_text(encoding="utf-8"))
            self.assertEqual(library.status_code, 200, library.text)
            self.assertIn("Delete", library.text)
            self.assertIn("stored-report.md", library.text)
            self.assertEqual(removed.status_code, 200, removed.text)
            self.assertFalse(report.exists())

    def test_approving_a_report_clears_only_that_queue_entry(self):
        with tempfile.TemporaryDirectory() as reports_dir:
            application = self.build_application(reports_dir)
            application.config.get_summary = lambda: {}
            application.report_generator.mark_report_approved = mock.Mock()
            application.report_generator.index_approved_report = mock.Mock(return_value=True)
            report_id = "c" * 32
            other_id = "d" * 32
            application.draft_reports[report_id] = {
                "executive_summary": "Review current endpoint evidence.",
                "key_findings": ["Current execution remains unconfirmed."],
                "threats": [],
                "recommendations": ["Preserve endpoint telemetry."],
                "metadata": {"threat_level": "HIGH", "source_filename": "AUTO_HIGH_example.md"},
                "mitre_techniques": [],
            }
            queue = application._analysis_queue()
            manual = queue.add_manual(
                owner="analyst", source="manual_upload", label="uploaded-alert.json",
                session_id="55555555-5555-5555-5555-555555555555", alert_count=1,
                llm_provider=None, payload={"selected_alerts": []},
            )
            queue.finish(manual["id"], "processed", "Report is ready for review.", report_id=report_id)
            other = queue.add_manual(
                owner="analyst", source="manual_upload", label="still-open.json",
                session_id="66666666-6666-6666-6666-666666666666", alert_count=1,
                llm_provider=None, payload={"selected_alerts": []},
            )
            queue.finish(other["id"], "processed", "Report is ready for review.", report_id=other_id)
            queue.observe_live("live-hash", "live alert", "processed", 10)
            queue.attach_report(["live-hash"], "AUTO_HIGH_example.md")
            cookie = sign_session(
                {"username": "analyst", "authenticated": True, "auth_version": 1},
                application.session_secret,
            )
            headers = {"Cookie": f"{application.session_cookie_name}={cookie}"}
            payload = {
                "report_id": report_id,
                "executive_summary": "Review current endpoint evidence.",
                "key_findings": ["Current execution remains unconfirmed."],
                "threats": [],
                "recommendations": ["Preserve endpoint telemetry."],
                "metadata": {"threat_level": "HIGH", "source_filename": "AUTO_HIGH_example.md"},
                "mitre_techniques": [],
            }
            with TestClient(application.app) as client:
                approved = client.post(f"/api/approve-report/{report_id}", json=payload, headers=headers)
                self.assertEqual(approved.status_code, 200, approved.text)
                listed = client.get("/api/analysis-queue", headers=headers)
            remaining = {job["id"] for job in listed.json()["jobs"]}
            self.assertNotIn(manual["id"], remaining)
            self.assertNotIn("live-hash", remaining)
            self.assertIn(other["id"], remaining)

    def test_viewer_and_editor_receive_authenticated_account_role(self):
        for role in ("admin", "analyst"):
            with self.subTest(role=role), tempfile.TemporaryDirectory() as reports_dir:
                application = self.build_application(reports_dir)
                application.auth_store.get_user = lambda name: {
                    "username": "analyst", "role": role,
                    "enabled": True, "auth_version": 1,
                } if name == "analyst" else None
                report_id = "a" * 32
                application.draft_reports[report_id] = {
                    "executive_summary": "Review evidence", "key_findings": [],
                    "threats": [], "mitre_techniques": [], "recommendations": [],
                    "metadata": {},
                }
                cookie = sign_session(
                    {"username": "analyst", "authenticated": True, "auth_version": 1},
                    application.session_secret,
                )
                headers = {"Cookie": f"{application.session_cookie_name}={cookie}"}
                with TestClient(application.app) as client:
                    viewer = client.get("/alerts/viewer", headers=headers)
                    editor = client.get(f"/review-report/{report_id}", headers=headers)
                self.assertEqual(viewer.status_code, 200, viewer.text)
                self.assertIn("Alert queue", viewer.text)
                self.assertEqual(editor.status_code, 200, editor.text)
                self.assertIn('data-can-change="true"', viewer.text)
                for page in (viewer.text, editor.text):
                    self.assertIn(f"analyst · {role}", page)
                    self.assertEqual('href="/admin/accounts"' in page, role == "admin")

    def test_provider_change_is_rejected_for_pending_or_running_work(self):
        for pending in (True, False):
            with self.subTest(pending=pending), tempfile.TemporaryDirectory() as reports_dir:
                application = self.build_application(reports_dir)
                application.auth_store.get_user = lambda name: {
                    "username": "analyst", "role": "admin", "enabled": True, "auth_version": 1,
                }
                application._analysis_task = SimpleNamespace(done=lambda: False) if pending else None
                application.report_generator.provider_status = lambda: {"provider": "local"}
                setter = mock.Mock(side_effect=ProviderBusyError("generation busy"))
                application.report_generator.set_llm_provider = setter
                cookie = sign_session(
                    {"username": "analyst", "authenticated": True, "auth_version": 1},
                    application.session_secret,
                )
                headers = {"Cookie": f"{application.session_cookie_name}={cookie}"}
                with TestClient(application.app) as client:
                    response = client.post("/api/llm-provider", json={"provider": "anthropic"}, headers=headers)
                self.assertEqual(response.status_code, 409, response.text)
                self.assertEqual(setter.call_count, 0 if pending else 1)

    def test_analyst_can_select_the_provider_from_the_analysis_form(self):
        with tempfile.TemporaryDirectory() as reports_dir:
            application = self.build_application(reports_dir)
            application.report_generator.provider_status = lambda: {"provider": "local"}
            application.report_generator.set_llm_provider = mock.Mock()
            cookie = sign_session(
                {"username": "analyst", "authenticated": True, "auth_version": 1},
                application.session_secret,
            )
            with TestClient(application.app) as client:
                response = client.post(
                    "/analyze-alerts", data={"llm_provider": "anthropic"},
                    headers={"Cookie": f"{application.session_cookie_name}={cookie}"},
                )
            self.assertNotEqual(response.status_code, 403, response.text)
            application.report_generator.set_llm_provider.assert_called_once_with("anthropic")

    def test_review_routes_restore_evidence_baseline_and_apply_current_selection(self):
        with tempfile.TemporaryDirectory() as reports_dir:
            application = self.build_application(reports_dir)
            report_id = "b" * 32
            rich = "## MITRE ATT&CK — Historical CTI Context Only (Not Observed)\n\n- **T1105** - Prior transfer [RAG-1].\n"
            details = {"T1105": {"evidence_classes": ["historical_only"]}}
            original = {
                "executive_summary": "Review current endpoint evidence.",
                "key_findings": ["Current execution remains unconfirmed."],
                "threats": [], "recommendations": ["Preserve endpoint telemetry."],
                "metadata": {"threat_level": "HIGH", "total_alerts": 1},
                "mitre_techniques": ["T1105"], "mitre_original_techniques": ["T1105"],
                "mitre_technique_details": details,
                "preserved_rich_sections_markdown": rich,
                "preserved_appendix_markdown": "## Report QA Findings\nOriginal QA appendix.",
            }
            application.draft_reports[report_id] = original
            application.report_generator.mark_report_approved = mock.Mock()
            application.report_generator.index_approved_report = mock.Mock(return_value=True)
            cookie = sign_session(
                {"username": "analyst", "authenticated": True, "auth_version": 1},
                application.session_secret,
            )
            headers = {"Cookie": f"{application.session_cookie_name}={cookie}"}
            payload = {
                **original, "report_id": report_id,
                "mitre_techniques": [{"id": "T1486", "name": "Data Encrypted for Impact"}],
                "mitre_original_techniques": [], "mitre_technique_details": {},
                "preserved_rich_sections_markdown": "## MITRE ATT&CK\nForged explicit classification.",
                "preserved_appendix_markdown": "Replaced QA appendix.",
            }
            with TestClient(application.app) as client:
                preview = client.post("/api/preview-report", json=payload, headers=headers)
                self.assertEqual(preview.status_code, 200, preview.text)
                reviewed = preview.json()["markdown"]
                self.assertNotIn("Forged explicit classification", reviewed)
                self.assertNotIn("**T1105**", reviewed)
                self.assertIn("**T1486**", reviewed)
                self.assertIn("evidence classification not established", reviewed)
                self.assertIn("Original QA appendix", reviewed)
                saved = client.post(f"/api/save-draft/{report_id}", json=payload, headers=headers)
                self.assertEqual(saved.status_code, 200, saved.text)
                draft = application.draft_reports[report_id]
                self.assertEqual(draft["mitre_original_techniques"], ["T1105"])
                self.assertEqual(draft["mitre_technique_details"], details)
                self.assertEqual(draft["preserved_rich_sections_markdown"], rich)
                valid = client.post("/api/validate-report", json=payload, headers=headers)
                self.assertEqual(valid.status_code, 200, valid.text)
                self.assertTrue(valid.json()["valid"])
                approved = client.post(f"/api/approve-report/{report_id}", json=payload, headers=headers)
                self.assertEqual(approved.status_code, 200, approved.text)
            approved_markdown = (Path(reports_dir) / approved.json()["filename"]).read_text(encoding="utf-8")
            self.assertNotIn("Forged explicit classification", approved_markdown)
            self.assertIn("**T1486**", approved_markdown)
            self.assertNotIn("**T1105**", approved_markdown)
            self.assertEqual(application.report_generator.index_approved_report.call_args.args[0], approved_markdown)


if __name__ == "__main__":
    unittest.main()
