"""Focused regressions for production lifecycle and safety boundaries."""

from __future__ import annotations

import asyncio
import io
import json
import logging
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


CONFIG_DIR = Path(__file__).resolve().parents[1] / "config"
if str(CONFIG_DIR) not in sys.path:
    sys.path.insert(0, str(CONFIG_DIR))

from config import (  # noqa: E402
    ConfigManager,
    DatabaseConfig,
    PathConfig,
    SSHConfig,
    WebConfig,
    _parse_bool,
)
from live_monitoring import EnhancedLiveMonitoringService  # noqa: E402
from main import SOCApplication  # noqa: E402
from report import RAGContextManager, ReportFormatter, ReportGenerator  # noqa: E402
from report_parser import ReportParser  # noqa: E402
import runtime_preflight  # noqa: E402
from runtime_utils import log_sanitized_exception  # noqa: E402


class ConfigurationBoundaryTests(unittest.TestCase):
    def test_preflight_json_config_load_failure_is_structured_and_sanitized(self):
        stdout = io.StringIO()
        stderr = io.StringIO()
        private_error = ValueError("invalid=/home/operator/private secret-value")
        with mock.patch.object(sys, "argv", ["runtime_preflight.py", "--json"]), mock.patch.object(
            runtime_preflight, "ConfigManager", side_effect=private_error
        ), mock.patch("sys.stdout", stdout), mock.patch("sys.stderr", stderr):
            result = runtime_preflight.main()

        payload = json.loads(stdout.getvalue())
        self.assertEqual(result, 2)
        self.assertFalse(payload["ready"])
        self.assertEqual(payload["checks"][0]["name"], "configuration")
        combined = stdout.getvalue() + stderr.getvalue()
        self.assertNotIn("/home/operator", combined)
        self.assertNotIn("secret-value", combined)
        self.assertNotIn("Traceback", combined)

    def test_preflight_text_config_load_failure_is_sanitized_without_traceback(self):
        stdout = io.StringIO()
        stderr = io.StringIO()
        private_error = ValueError("invalid=/home/operator/private secret-value")
        with mock.patch.object(sys, "argv", ["runtime_preflight.py"]), mock.patch.object(
            runtime_preflight, "ConfigManager", side_effect=private_error
        ), mock.patch("sys.stdout", stdout), mock.patch("sys.stderr", stderr):
            result = runtime_preflight.main()

        self.assertEqual(result, 2)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("Preflight configuration load failed (ValueError)", stderr.getvalue())
        self.assertNotIn("/home/operator", stderr.getvalue())
        self.assertNotIn("secret-value", stderr.getvalue())
        self.assertNotIn("Traceback", stderr.getvalue())

    def test_preflight_includes_fail_closed_section_validation(self):
        config = SimpleNamespace(
            validate_all=lambda: (False, ["SSH: private detail", "Runtime: invalid"]),
            llm=SimpleNamespace(
                model_path="",
                llama_cpp_path="",
                use_custom_template=False,
                system_prompt_file="cti.txt",
                chat_template_file="qwen_chat.j2",
            ),
            paths=SimpleNamespace(templates_dir="", geoip_db_path=""),
            get_production_warnings=lambda: [],
        )
        passing = {"name": "stub", "status": "pass", "message": "ok"}
        with mock.patch.object(runtime_preflight, "_dependency_check", return_value=passing), mock.patch.object(
            runtime_preflight, "_path_check", return_value=passing
        ):
            report = runtime_preflight.build_preflight_report(
                config,
                include_database=False,
            )

        self.assertFalse(report["ready"])
        config_check = next(check for check in report["checks"] if check["name"] == "configuration")
        self.assertEqual(config_check["details"]["invalid_sections"], ["Runtime", "SSH"])
        self.assertNotIn("private detail", json.dumps(report))

    def test_explicit_missing_and_malformed_config_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(FileNotFoundError):
                ConfigManager(str(root / "missing.json"))

            malformed = root / "malformed.json"
            malformed.write_text("{not-json", encoding="utf-8")
            with self.assertRaises(ValueError):
                ConfigManager(str(malformed))

    def test_ssh_is_optional_but_partial_configuration_is_rejected(self):
        self.assertTrue(SSHConfig().validate()[0])
        self.assertFalse(SSHConfig(host="wazuh.invalid").validate()[0])

    def test_blank_web_host_is_rejected_instead_of_binding_all_interfaces(self):
        valid_auth = {"username": "operator", "password": "strong-password"}
        self.assertFalse(WebConfig(host="", **valid_auth).validate()[0])
        self.assertFalse(WebConfig(host="   ", **valid_auth).validate()[0])
        self.assertTrue(WebConfig(host="127.0.0.1", **valid_auth).validate()[0])

    def test_boolean_environment_values_are_strict(self):
        self.assertTrue(_parse_bool("YES"))
        self.assertFalse(_parse_bool("off"))
        with self.assertRaises(ValueError):
            _parse_bool("tru")

    def test_canonical_database_name_wins_over_compatibility_alias(self):
        manager = ConfigManager.__new__(ConfigManager)
        manager.database = DatabaseConfig()
        with mock.patch.dict(
            os.environ,
            {"DB_NAME": "canonical", "DB_DATABASE": "legacy"},
            clear=True,
        ):
            manager.load_from_env()
        self.assertEqual(manager.database.database, "canonical")

    def test_xdg_state_root_loaded_late_updates_only_default_state_paths(self):
        manager = ConfigManager.__new__(ConfigManager)
        manager.paths = PathConfig()
        manager._explicit_path_fields = set()
        with mock.patch.dict(os.environ, {"XDG_STATE_HOME": "/srv/state"}, clear=True):
            manager._apply_environment_state_root_defaults()
        self.assertEqual(manager.paths.reports_dir, "/srv/state/soc-rag/reports")
        self.assertEqual(manager.paths.uploads_dir, "/srv/state/soc-rag/uploads")

    def test_config_summary_contains_no_credentials(self):
        manager = ConfigManager.__new__(ConfigManager)
        manager.ssh = SSHConfig(host="host", username="operator", password="secret")
        manager.wazuh = SimpleNamespace(alerts_file_path="/private/a", archives_base_path="/private/b")
        manager.llm = SimpleNamespace(
            model_path="/private/model.gguf", llama_cpp_path="/private/llama-cli",
            context_size=1024, max_tokens=64, temperature=0.2, disable_thinking=True,
        )
        manager.web = SimpleNamespace(host="127.0.0.1", port=8000, username="admin", password="secret")
        manager.paths = SimpleNamespace(reports_dir="r", templates_dir="t", uploads_dir="u", geoip_db_path="")
        manager.rag = SimpleNamespace(
            document_chunk_size=2, document_chunk_overlap=0,
            embedding_model="m", embedding_device="cpu", embedding_devices=[], embedding_dimensions=1,
            embedding_batch_size=1, embedding_multi_gpu_min_chunks=1, max_retrieval_docs=1,
            normalize_embeddings=True, similarity_threshold=0.2, retrieval_candidate_multiplier=1,
            embedding_query_instruction="query",
        )
        manager.database = SimpleNamespace(
            host="db", port=5432, database="name", user="user", password="secret",
            connect_timeout=1, auto_create_database=False,
        )
        manager.asset_inventory = SimpleNamespace(owned_cidrs=[], infrastructure_ips=[], internal_cidrs=[])
        manager.runtime = SimpleNamespace(
            max_alert_upload_bytes=1, max_alert_records=1, max_document_files=1,
            max_document_batch_bytes=1, max_drafts=1, max_session_results=1,
            max_background_tasks=1,
            max_current_alert_lines=1, max_current_alert_bytes=1, max_alert_line_bytes=1,
            max_archive_days=1, max_archive_records=1,
            max_archive_bytes=1, max_archive_line_bytes=1, max_worker_threads=1,
        )
        manager.dotenv_files_loaded = []
        manager.get_production_warnings = lambda: []

        serialized = json.dumps(manager.get_summary())
        for secret_value in ("operator", "secret", "/private/", '"user"'):
            self.assertNotIn(secret_value, serialized)

    def test_sanitized_traceback_keeps_location_without_exception_content(self):
        logger = logging.getLogger("sanitized-traceback-test")
        try:
            raise RuntimeError("credential=secret /home/alice/private")
        except RuntimeError as error:
            with self.assertLogs(logger, level="ERROR") as captured:
                log_sanitized_exception("Model generation failed", error, logger=logger)

        output = "\n".join(captured.output)
        self.assertIn("Model generation failed (RuntimeError)", output)
        self.assertIn("test_runtime_hardening.py", output)
        self.assertNotIn("credential=secret", output)
        self.assertNotIn("/home/alice", output)


class CorpusLifecycleTests(unittest.TestCase):
    def test_archive_identity_ignores_transport_provenance(self):
        record = {"_source": {"rule": {"id": "1"}, "_archive_source": "/private/day.json"}}
        payload = RAGContextManager._archive_record_payload(record)
        self.assertEqual(payload, {"rule": {"id": "1"}})

    def test_active_corpus_memory_changes_only_after_commit_boundary(self):
        manager = RAGContextManager.__new__(RAGContextManager)
        manager.active_corpus_id = "old"
        cursor = SimpleNamespace(execute=mock.Mock())
        manager._set_active_corpus(cursor, "new")
        self.assertEqual(manager.active_corpus_id, "old")

    def test_missing_database_is_not_created_without_opt_in(self):
        report_module = sys.modules[RAGContextManager.__module__]
        error = report_module.psycopg2.OperationalError('database "missing" does not exist')
        with mock.patch.object(RAGContextManager, "_is_missing_database_error", return_value=True), mock.patch(
            "report.psycopg2.connect", side_effect=error
        ) as connect:
            with self.assertRaises(RuntimeError) as raised:
                RAGContextManager._connect_with_database_bootstrap(
                    {"host": "db", "database": "missing"},
                    auto_create_database=False,
                )
        self.assertIn("DB_AUTO_CREATE", str(raised.exception))
        self.assertEqual(connect.call_count, 1)

    def test_automatic_multi_source_retrieval_uses_one_corpus_snapshot(self):
        class TrackingLock:
            def __init__(self):
                self.lock = __import__("threading").RLock()
                self.depth = 0

            def __enter__(self):
                self.lock.acquire()
                self.depth += 1
                return self

            def __exit__(self, *_args):
                self.depth -= 1
                self.lock.release()

        corpus_a = "a" * 64
        corpus_b = "b" * 64
        lock = TrackingLock()
        formatter = ReportFormatter.__new__(ReportFormatter)
        formatter.rag_manager = SimpleNamespace(
            corpus_state_lock=lock,
            active_corpus_id=corpus_a,
            get_recent_custom_documents=lambda k: [],
        )

        def retrieve(_alerts, **kwargs):
            self.assertGreater(lock.depth, 0)
            corpus_id = corpus_a if kwargs.get("source_mode") == "custom" else corpus_b
            return [{"content": corpus_id, "metadata": {"corpus_id": corpus_id}}]

        formatter._retrieve_context_for_alerts = retrieve
        formatter._select_relevant_context_docs = lambda docs, *_args, **_kwargs: docs
        formatter._annotate_context_docs = lambda docs, _alerts: docs

        selected = formatter._retrieve_automatic_context_snapshot([], {}, max_docs=4)
        self.assertEqual([item["metadata"]["corpus_id"] for item in selected], [corpus_a])


class ReportRoundTripTests(unittest.TestCase):
    def test_report_finalization_is_preserved_but_not_reindexed(self):
        markdown = (
            "# Report\n\n## Executive Summary\n\nObserved activity.\n\n---\n\n"
            "## Report Finalization\n\nDeterministic repair substituted.\n\n"
            "## RAG Sources Used\n\n- [RAG-1] source\n"
        )
        parsed = ReportParser.parse_report(markdown)
        self.assertIn("## Report Finalization", parsed["preserved_appendix_markdown"])
        serialized = ReportParser.serialize_to_markdown(parsed)
        self.assertIn("## Report Finalization", serialized)
        indexed = ReportGenerator._strip_generated_appendices_for_indexing(serialized)
        self.assertNotIn("Report Finalization", indexed)
        self.assertNotIn("RAG Sources Used", indexed)


class RequestLimitTests(unittest.IsolatedAsyncioTestCase):
    async def test_upload_read_enforces_actual_bytes_without_declared_size(self):
        class Upload:
            def __init__(self, content: bytes):
                self.stream = io.BytesIO(content)

            async def read(self, size: int = -1) -> bytes:
                return self.stream.read(size)

        app = SOCApplication.__new__(SOCApplication)
        with self.assertRaises(Exception) as raised:
            await app._read_upload_limited(Upload(b"12345"), 4)
        self.assertEqual(getattr(raised.exception, "status_code", None), 413)

    async def test_bounded_store_evicts_oldest_item(self):
        values = {"old": 1, "middle": 2}
        SOCApplication._store_bounded(values, "new", 3, 2)
        self.assertEqual(values, {"middle": 2, "new": 3})

    async def test_empty_requested_replacement_does_not_reuse_old_corpus_as_success(self):
        app = SOCApplication.__new__(SOCApplication)
        app.report_generator = SimpleNamespace(
            rag_ready=True,
            get_rag_status=lambda: {
                "alerts_with_embeddings": 1,
                "docs_with_embeddings": 0,
            },
            build_rag_context=mock.Mock(),
        )
        app.progress_tracker = SimpleNamespace(send_progress=mock.AsyncMock())

        result = await app._build_rag_with_progress(
            session_id="session",
            use_archives=False,
            use_uploads=True,
            archive_days=None,
            custom_docs=[],
            uploaded_files=[],
            build_mode="replace",
        )

        self.assertFalse(result)
        app.report_generator.build_rag_context.assert_not_called()
        messages = [call.args[1] for call in app.progress_tracker.send_progress.await_args_list]
        self.assertTrue(any("prior corpus remains active" in message for message in messages))

    async def test_failed_replacement_result_is_not_masked_by_prior_ready_state(self):
        app = SOCApplication.__new__(SOCApplication)
        app.report_generator = SimpleNamespace(
            rag_ready=True,
            get_rag_status=lambda: {
                "alerts_with_embeddings": 1,
                "docs_with_embeddings": 0,
            },
            build_rag_context=mock.Mock(return_value=False),
        )
        app.progress_tracker = SimpleNamespace(send_progress=mock.AsyncMock())
        app._ssh_enabled = lambda: False

        async def run(function, *args, **kwargs):
            return function(*args, **kwargs)

        app._run_blocking = run
        result = await app._build_rag_with_progress(
            session_id="session",
            use_archives=False,
            use_uploads=True,
            archive_days=None,
            custom_docs=[{"content": "text", "metadata": {}}],
            uploaded_files=[],
            build_mode="replace",
        )

        self.assertFalse(result)
        app.report_generator.build_rag_context.assert_called_once()

    async def test_successful_build_does_not_restart_monitoring_during_shutdown(self):
        app = SOCApplication.__new__(SOCApplication)
        app._shutting_down = True
        app.report_generator = SimpleNamespace(
            rag_ready=True,
            get_rag_status=lambda: {
                "ready": True,
                "alerts_with_embeddings": 0,
                "docs_with_embeddings": 0,
            },
            build_rag_context=mock.Mock(return_value=True),
        )
        app.progress_tracker = SimpleNamespace(send_progress=mock.AsyncMock())
        app.live_monitoring = SimpleNamespace(start_monitoring=mock.Mock(return_value=True))
        app._ssh_enabled = lambda: True

        async def run(function, *args, **kwargs):
            return function(*args, **kwargs)

        app._run_blocking = run
        result = await app._build_rag_with_progress(
            session_id="session",
            use_archives=False,
            use_uploads=True,
            archive_days=None,
            custom_docs=[{"content": "text", "metadata": {}}],
            uploaded_files=[],
            build_mode="replace",
        )

        self.assertTrue(result)
        app.live_monitoring.start_monitoring.assert_not_called()

    async def test_build_result_requires_exact_ready_post_build_status(self):
        statuses = [
            {"ready": True, "docs_with_embeddings": 1, "alerts_with_embeddings": 0},
            {"ready": False, "docs_with_embeddings": 1, "alerts_with_embeddings": 0},
        ]
        app = SOCApplication.__new__(SOCApplication)
        app.report_generator = SimpleNamespace(
            rag_ready=True,
            get_rag_status=mock.Mock(side_effect=statuses),
            build_rag_context=mock.Mock(return_value=True),
        )
        app.progress_tracker = SimpleNamespace(send_progress=mock.AsyncMock())

        async def run(function, *args, **kwargs):
            return function(*args, **kwargs)

        app._run_blocking = run
        result = await app._build_rag_with_progress(
            session_id="session",
            use_archives=False,
            use_uploads=True,
            archive_days=None,
            custom_docs=[{"content": "text", "metadata": {}}],
            uploaded_files=[],
            build_mode="replace",
        )

        self.assertFalse(result)
        app.report_generator.build_rag_context.assert_called_once()
        completion = app.progress_tracker.send_progress.await_args_list[-1]
        self.assertEqual(completion.args[3], "error")

    async def test_additive_build_passes_archives_and_documents_to_union_extension(self):
        archive_logs = [{"rule": {"id": "1001", "description": "archive"}}]
        custom_docs = [{"content": "new CTI", "metadata": {"filename": "new.md"}}]
        status = {
            "ready": True,
            "alerts_with_embeddings": 4,
            "uploaded_documents_with_embeddings": 3,
            "custom_doc_chunks_with_embeddings": 9,
            "docs_with_embeddings": 9,
        }
        app = SOCApplication.__new__(SOCApplication)
        app.report_generator = SimpleNamespace(
            rag_ready=True,
            get_rag_status=mock.Mock(return_value=status),
            extend_rag_context=mock.Mock(return_value=True),
            build_rag_context=mock.Mock(),
        )
        app.progress_tracker = SimpleNamespace(send_progress=mock.AsyncMock())
        app._read_archives_sync = mock.Mock(return_value=(True, archive_logs))
        app._ssh_enabled = lambda: False

        async def run(function, *args, **kwargs):
            return function(*args, **kwargs)

        app._run_blocking = run
        result = await app._build_rag_with_progress(
            session_id="session",
            use_archives=True,
            use_uploads=True,
            archive_days=1,
            custom_docs=custom_docs,
            uploaded_files=[],
            build_mode="extend",
        )

        self.assertTrue(result)
        app.report_generator.extend_rag_context.assert_called_once_with(
            archive_logs=archive_logs,
            custom_docs=custom_docs,
        )
        app.report_generator.build_rag_context.assert_not_called()
        completion = app.progress_tracker.send_progress.await_args_list[-1]
        self.assertIn("Active RAG union ready", completion.args[1])
        self.assertIn("3 CTI source document(s)", completion.args[1])
        self.assertIn("9 CTI chunk(s)", completion.args[1])
        self.assertIn("4 archive record(s)", completion.args[1])
        self.assertIn("13 total retrievable chunk(s)", completion.args[1])

    async def test_status_refresh_reports_active_union_without_mutating_corpus(self):
        status = {
            "ready": True,
            "active_archive_records": 5,
            "active_source_documents": 7,
            "active_document_chunks": 21,
            "alerts_with_embeddings": 5,
            "docs_with_embeddings": 21,
        }
        app = SOCApplication.__new__(SOCApplication)
        app.report_generator = SimpleNamespace(
            rag_ready=True,
            get_rag_status=mock.Mock(return_value=status),
            extend_rag_context=mock.Mock(),
            build_rag_context=mock.Mock(),
        )
        app.progress_tracker = SimpleNamespace(send_progress=mock.AsyncMock())

        async def run(function, *args, **kwargs):
            return function(*args, **kwargs)

        app._run_blocking = run
        result = await app._build_rag_with_progress(
            session_id="session",
            use_archives=False,
            use_uploads=False,
            archive_days=None,
            custom_docs=[],
            uploaded_files=[],
            build_mode="refresh",
        )

        self.assertTrue(result)
        app.report_generator.extend_rag_context.assert_not_called()
        app.report_generator.build_rag_context.assert_not_called()
        completion = app.progress_tracker.send_progress.await_args_list[-1]
        self.assertIn("7 CTI source document(s)", completion.args[1])
        self.assertIn("21 CTI chunk(s)", completion.args[1])
        self.assertIn("5 archive record(s)", completion.args[1])
        self.assertIn("26 total retrievable chunk(s)", completion.args[1])

    async def test_status_failure_prevents_background_corpus_mutation(self):
        app = SOCApplication.__new__(SOCApplication)
        app.report_generator = SimpleNamespace(
            rag_ready=False,
            get_rag_status=mock.Mock(return_value={
                "ready": False,
                "error": "RAG status is temporarily unavailable",
            }),
            extend_rag_context=mock.Mock(),
            build_rag_context=mock.Mock(),
        )
        app.progress_tracker = SimpleNamespace(send_progress=mock.AsyncMock())

        async def run(function, *args, **kwargs):
            return function(*args, **kwargs)

        app._run_blocking = run
        result = await app._build_rag_with_progress(
            session_id="session",
            use_archives=False,
            use_uploads=True,
            archive_days=None,
            custom_docs=[{"content": "text", "metadata": {}}],
            uploaded_files=[],
            build_mode="extend",
        )

        self.assertFalse(result)
        app.report_generator.extend_rag_context.assert_not_called()
        app.report_generator.build_rag_context.assert_not_called()
        completion = app.progress_tracker.send_progress.await_args_list[-1]
        self.assertIn("active corpus was not changed", completion.args[1])

    async def test_second_analysis_task_is_rejected(self):
        app = SOCApplication.__new__(SOCApplication)
        app.config = SimpleNamespace(runtime=SimpleNamespace(max_session_results=2))
        app._background_tasks = set()
        app._rag_build_task = None
        app._analysis_task = None
        blocker = asyncio.Event()

        async def wait_for_release():
            await blocker.wait()

        first = app._start_background_task(wait_for_release(), kind="analysis")
        with self.assertRaises(Exception) as raised:
            app._start_background_task(wait_for_release(), kind="analysis")
        self.assertEqual(getattr(raised.exception, "status_code", None), 409)
        blocker.set()
        await first

    async def test_any_failed_document_prevents_partial_replacement(self):
        app = SOCApplication.__new__(SOCApplication)
        app.document_processor = SimpleNamespace(process_upload=lambda *_args, **_kwargs: None)
        app.progress_tracker = SimpleNamespace(send_progress=mock.AsyncMock())

        async def extract(_function, _content, filename, **_kwargs):
            if filename == "bad.pdf":
                raise ValueError("corrupt document")
            return "usable text", {"filename": filename}

        app._run_blocking = extract
        with self.assertRaises(ValueError):
            await app._process_uploaded_documents_with_progress(
                "session",
                [
                    {"filename": "good.pdf", "content": b"good"},
                    {"filename": "bad.pdf", "content": b"bad"},
                ],
            )

    async def test_document_type_is_rejected_before_content_read(self):
        with self.assertRaises(Exception) as raised:
            SOCApplication._require_supported_document_type("payload.exe")
        self.assertEqual(getattr(raised.exception, "status_code", None), 415)

    async def test_upload_filename_is_bounded_and_path_free(self):
        value = SOCApplication._safe_upload_filename("../private/evil\nname.pdf")
        self.assertEqual(value, "evil_name.pdf")
        self.assertNotIn("/", value)


class MonitoringRetryTests(unittest.IsolatedAsyncioTestCase):
    async def test_failed_generation_releases_reserved_alert_for_retry(self):
        service = EnhancedLiveMonitoringService(
            SimpleNamespace(),
            SimpleNamespace(rag_ready=True),
            lambda: None,
        )
        service.logger = logging.getLogger("monitoring-test")
        service.batch_wait_seconds = 0
        alert = {"rule_level": 12, "rule_id": "1", "timestamp": "2026-01-01T00:00:00Z"}
        snapshot = service._create_enhanced_snapshot([alert])
        selected = service._detect_high_severity_alerts_enhanced([alert], snapshot)
        self.assertEqual(selected, [alert])
        self.assertFalse(service.processed_alert_hashes)
        self.assertTrue(service.inflight_alert_hashes)

        service._execute_report_generation = mock.AsyncMock(return_value=False)
        self.assertFalse(await service._generate_automatic_report_enhanced([alert], [alert]))
        self.assertFalse(service.processed_alert_hashes)
        self.assertFalse(service.inflight_alert_hashes)
        self.assertEqual(service._detect_high_severity_alerts_enhanced([alert], snapshot), [alert])


if __name__ == "__main__":
    unittest.main()
