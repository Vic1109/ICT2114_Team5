"""Integration/regression coverage for the production manual alert upload path."""

from __future__ import annotations

import base64
import json
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace

from fastapi import FastAPI
from fastapi.security import HTTPBasic
from fastapi.testclient import TestClient
from fastapi.templating import Jinja2Templates


CONFIG_DIR = Path(__file__).resolve().parents[1] / "config"
if str(CONFIG_DIR) not in sys.path:
    sys.path.insert(0, str(CONFIG_DIR))

from main import SOCApplication  # noqa: E402


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
        application._setup_routes()
        return application

    def test_exact_manual_multipart_path_reaches_report_generator(self):
        with tempfile.TemporaryDirectory() as reports_dir:
            application = self.build_application(reports_dir)
            auth = "Basic " + base64.b64encode(b"analyst:secret").decode()
            with TestClient(application.app) as client:
                response = client.post(
                    "/analyze-alerts",
                    headers={"Authorization": auth},
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
                        headers={"Authorization": auth},
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


if __name__ == "__main__":
    unittest.main()
