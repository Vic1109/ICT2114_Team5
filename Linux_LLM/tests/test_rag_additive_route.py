"""Route and dashboard regressions for additive RAG context updates."""

from __future__ import annotations

import base64
import sys
import tempfile
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

from main import SOCApplication  # noqa: E402


class RagBuildRouteTests(unittest.TestCase):
    @staticmethod
    def _authorization() -> dict[str, str]:
        value = base64.b64encode(b"analyst:secret").decode("ascii")
        return {"Authorization": f"Basic {value}"}

    def _application(self, status_payload):
        reports_dir = tempfile.TemporaryDirectory()
        self.addCleanup(reports_dir.cleanup)

        application = SOCApplication.__new__(SOCApplication)
        application.config = SimpleNamespace(
            web=SimpleNamespace(username="analyst", password="secret"),
            paths=SimpleNamespace(reports_dir=reports_dir.name),
            llm=SimpleNamespace(timeout=5),
            ssh=SimpleNamespace(host=""),
        )
        application.app = FastAPI()
        application.security = HTTPBasic()
        application.templates = Jinja2Templates(directory=str(CONFIG_DIR / "templates"))
        application.session_results = {}
        application.draft_reports = {}
        application._rag_build_task = None
        application._analysis_task = None
        application._background_tasks = set()
        application.report_generator = SimpleNamespace(
            get_rag_status=mock.Mock(return_value=status_payload),
        )
        application.progress_tracker = SimpleNamespace()
        application.pdf_converter = SimpleNamespace(conversion_available=False)
        application.live_monitoring = SimpleNamespace()
        application._build_rag_with_progress = mock.Mock(
            return_value=mock.sentinel.rag_operation
        )
        application._start_background_task = mock.Mock()

        async def run_blocking(function, *args, **kwargs):
            return function(*args, **kwargs)

        application._run_blocking = run_blocking
        application._setup_routes()
        return application

    def test_default_mode_extends_an_active_ready_corpus(self):
        application = self._application({
            "ready": True,
            "alerts_with_embeddings": 2,
            "docs_with_embeddings": 4,
        })

        with TestClient(application.app) as client:
            response = client.post(
                "/build-rag",
                headers=self._authorization(),
                data={"use_archives": "true", "ragDays": "1"},
            )

        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["build_mode"], "extend")
        application._build_rag_with_progress.assert_called_once_with(
            session_id=mock.ANY,
            use_archives=True,
            use_uploads=False,
            archive_days=1,
            custom_docs=[],
            uploaded_files=[],
            build_mode="extend",
        )
        application._start_background_task.assert_called_once_with(
            mock.sentinel.rag_operation,
            kind="rag-build",
        )

    def test_cti_upload_defaults_to_extension_and_is_queued_for_union(self):
        application = self._application({
            "ready": True,
            "alerts_with_embeddings": 2,
            "docs_with_embeddings": 4,
        })
        content = b"Threat intelligence describing a known malicious campaign."

        with TestClient(application.app) as client:
            response = client.post(
                "/build-rag",
                headers=self._authorization(),
                data={"use_uploads": "true"},
                files={"customFiles": ("campaign.txt", content, "text/plain")},
            )

        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["build_mode"], "extend")
        call = application._build_rag_with_progress.call_args
        self.assertEqual(call.kwargs["build_mode"], "extend")
        self.assertEqual(call.kwargs["uploaded_files"], [{
            "filename": "campaign.txt",
            "content": content,
        }])

    def test_active_replacement_requires_explicit_confirmation(self):
        application = self._application({
            "ready": True,
            "alerts_with_embeddings": 2,
            "docs_with_embeddings": 4,
        })

        with TestClient(application.app) as client:
            response = client.post(
                "/build-rag",
                headers=self._authorization(),
                data={
                    "use_archives": "true",
                    "ragDays": "1",
                    "build_mode": "replace",
                },
            )

        self.assertEqual(response.status_code, 400, response.text)
        self.assertIn("explicit confirmation", response.json()["detail"])
        application._build_rag_with_progress.assert_not_called()
        application._start_background_task.assert_not_called()

    def test_confirmed_replacement_is_dispatched_as_replacement(self):
        application = self._application({
            "ready": True,
            "alerts_with_embeddings": 2,
            "docs_with_embeddings": 4,
        })

        with TestClient(application.app) as client:
            response = client.post(
                "/build-rag",
                headers=self._authorization(),
                data={
                    "use_archives": "true",
                    "ragDays": "1",
                    "build_mode": "replace",
                    "confirm_replace": "true",
                },
            )

        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["build_mode"], "replace")
        application._build_rag_with_progress.assert_called_once_with(
            session_id=mock.ANY,
            use_archives=True,
            use_uploads=False,
            archive_days=1,
            custom_docs=[],
            uploaded_files=[],
            build_mode="replace",
        )

    def test_first_build_uses_initial_replacement_snapshot(self):
        application = self._application({
            "ready": False,
            "alerts_with_embeddings": 0,
            "docs_with_embeddings": 0,
        })

        with TestClient(application.app) as client:
            response = client.post(
                "/build-rag",
                headers=self._authorization(),
                data={"use_archives": "true", "ragDays": "1"},
            )

        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["build_mode"], "replace")
        self.assertEqual(response.json()["message"], "Initial RAG context build started")
        self.assertEqual(
            application._build_rag_with_progress.call_args.kwargs["build_mode"],
            "replace",
        )

    def test_unready_active_corpus_cannot_be_silently_replaced_by_extend(self):
        application = self._application({
            "ready": False,
            "active_corpus_id": "a" * 64,
            "alerts_with_embeddings": 0,
            "docs_with_embeddings": 4,
        })

        with TestClient(application.app) as client:
            response = client.post(
                "/build-rag",
                headers=self._authorization(),
                data={"use_archives": "true", "ragDays": "1"},
            )

        self.assertEqual(response.status_code, 409, response.text)
        self.assertIn("cannot be extended losslessly", response.json()["detail"])
        application._build_rag_with_progress.assert_not_called()
        application._start_background_task.assert_not_called()

    def test_unready_active_corpus_requires_confirmed_replacement(self):
        application = self._application({
            "ready": False,
            "active_corpus_id": "a" * 64,
            "alerts_with_embeddings": 0,
            "docs_with_embeddings": 4,
        })

        with TestClient(application.app) as client:
            unconfirmed = client.post(
                "/build-rag",
                headers=self._authorization(),
                data={
                    "use_archives": "true",
                    "ragDays": "1",
                    "build_mode": "replace",
                },
            )
            confirmed = client.post(
                "/build-rag",
                headers=self._authorization(),
                data={
                    "use_archives": "true",
                    "ragDays": "1",
                    "build_mode": "replace",
                    "confirm_replace": "true",
                },
            )

        self.assertEqual(unconfirmed.status_code, 400, unconfirmed.text)
        self.assertEqual(confirmed.status_code, 200, confirmed.text)
        self.assertEqual(confirmed.json()["build_mode"], "replace")
        self.assertEqual(
            application._build_rag_with_progress.call_args.kwargs["build_mode"],
            "replace",
        )

    def test_no_source_request_refreshes_without_selecting_a_mutation_mode(self):
        application = self._application({
            "ready": True,
            "alerts_with_embeddings": 2,
            "docs_with_embeddings": 4,
        })

        with TestClient(application.app) as client:
            response = client.post(
                "/build-rag",
                headers=self._authorization(),
            )

        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["build_mode"], "refresh")
        call = application._build_rag_with_progress.call_args
        self.assertFalse(call.kwargs["use_archives"])
        self.assertFalse(call.kwargs["use_uploads"])
        self.assertEqual(call.kwargs["build_mode"], "refresh")

    def test_invalid_build_mode_is_rejected(self):
        application = self._application({
            "ready": True,
            "alerts_with_embeddings": 2,
            "docs_with_embeddings": 4,
        })

        with TestClient(application.app) as client:
            response = client.post(
                "/build-rag",
                headers=self._authorization(),
                data={
                    "use_archives": "true",
                    "ragDays": "1",
                    "build_mode": "merge-ish",
                },
            )

        self.assertEqual(response.status_code, 400, response.text)
        application._build_rag_with_progress.assert_not_called()

    def test_status_failure_blocks_all_corpus_mutation(self):
        application = self._application({
            "ready": False,
            "error": "RAG status is temporarily unavailable",
        })

        with TestClient(application.app) as client:
            response = client.post(
                "/build-rag",
                headers=self._authorization(),
                data={"use_archives": "true", "ragDays": "1"},
            )

        self.assertEqual(response.status_code, 503, response.text)
        self.assertIn("no corpus mutation", response.json()["detail"])
        application._build_rag_with_progress.assert_not_called()
        application._start_background_task.assert_not_called()


class RagDashboardContractTests(unittest.TestCase):
    def test_dashboard_defaults_to_lossless_extension_and_labels_active_counts(self):
        dashboard = (CONFIG_DIR / "templates" / "dashboard.html").read_text(
            encoding="utf-8"
        )
        script = (CONFIG_DIR / "static" / "js" / "script.js").read_text(
            encoding="utf-8"
        )

        self.assertIn('value="extend" checked', dashboard)
        self.assertIn('id="confirmReplaceCheck"', dashboard)
        self.assertIn("lossless union", dashboard)
        self.assertIn("formData.append('build_mode', buildMode)", script)
        self.assertIn("formData.append('confirm_replace', confirmReplace)", script)
        self.assertIn("Active RAG union:", script)
        self.assertIn("CTI source document(s)", script)
        self.assertIn("CTI chunk(s)", script)
        self.assertIn("archive record(s)", script)
        self.assertIn("total retrievable chunk(s)", script)
        self.assertIn("cannot be extended losslessly", script)
        self.assertIn("status.active_corpus_id", script)
        self.assertIn("ragStatusAvailable", script)


if __name__ == "__main__":
    unittest.main()
