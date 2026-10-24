"""Release-blocking corpus lifecycle and failure-semantics regressions."""

from __future__ import annotations

import inspect
import os
import sys
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


CONFIG_DIR = Path(__file__).resolve().parents[1] / "config"
if str(CONFIG_DIR) not in sys.path:
    sys.path.insert(0, str(CONFIG_DIR))

from report import (  # noqa: E402
    EnhancedReportFormatter,
    RAGContextManager,
    ReportFormatter,
    ReportGenerator,
)


def _configured_manager() -> RAGContextManager:
    manager = RAGContextManager.__new__(RAGContextManager)
    manager.embedding_model = "configured/model-v2"
    manager.embedding_device = "cpu"
    manager.embedding_devices = []
    manager.vector_dimensions = 1024
    manager.document_chunk_size = 1200
    manager.document_chunk_overlap = 120
    manager.max_retrieval_docs = 8
    manager.normalize_embeddings = True
    manager.similarity_threshold = 0.2
    manager.embedding_batch_size = 16
    manager.embedding_multi_gpu_min_chunks = 64
    manager.retrieval_candidate_multiplier = 4
    manager.embedding_query_instruction = "query instruction"
    manager.embedding_document_instruction = "document instruction"
    manager.db_lock = threading.RLock()
    manager.corpus_state_lock = threading.RLock()
    manager.active_corpus_id = "a" * 64
    manager.active_corpus_version_mismatches = {}
    manager.rag_ready = True
    return manager


def _mock_connection(cursor: mock.MagicMock) -> SimpleNamespace:
    cursor.__enter__.return_value = cursor
    cursor.__exit__.return_value = False
    return SimpleNamespace(
        cursor=mock.Mock(return_value=cursor),
        commit=mock.Mock(),
        rollback=mock.Mock(),
    )


class RetrievalFailureSemanticsTests(unittest.TestCase):
    def test_focused_retrieval_failure_propagates(self):
        formatter = ReportFormatter.__new__(ReportFormatter)
        rollback = mock.Mock()
        formatter.rag_manager = SimpleNamespace(
            corpus_state_lock=threading.RLock(),
            active_corpus_id="a" * 64,
            search_custom_documents=mock.Mock(side_effect=RuntimeError("database unavailable")),
            _rollback_safely=rollback,
        )
        formatter._build_exact_terms_from_alerts = lambda _alerts: {}
        formatter._build_focused_retrieval_queries = lambda _alerts: ["high-signal query"]

        with mock.patch("report.log_sanitized_exception"), self.assertRaisesRegex(
            RuntimeError, "Focused RAG retrieval failed"
        ):
            formatter._retrieve_context_for_alerts([], k=2, source_mode="custom")

        rollback.assert_called_once()

    def test_recent_document_fallback_failure_propagates(self):
        manager = _configured_manager()
        manager.conn = SimpleNamespace(cursor=mock.Mock(side_effect=RuntimeError("database unavailable")))
        manager._rollback_safely = mock.Mock()

        with mock.patch("report.log_sanitized_exception"), self.assertRaisesRegex(
            RuntimeError, "Recent custom document fallback failed"
        ):
            manager.get_recent_custom_documents(k=2)

        manager._rollback_safely.assert_called_once()

    def test_enhanced_formatter_raises_instead_of_returning_error_draft(self):
        formatter = EnhancedReportFormatter.__new__(EnhancedReportFormatter)
        formatter.rag_manager = SimpleNamespace(rag_ready=True, _rollback_safely=mock.Mock())
        formatter._generate_with_full_rag = mock.Mock(side_effect=RuntimeError("retrieval failed"))
        alerts = [{"threat_classification": {"category": "test"}}]

        with mock.patch("report.log_sanitized_exception"), self.assertRaisesRegex(
            RuntimeError, "Enhanced report generation failed"
        ):
            formatter.generate_report_with_rag(alerts)

        formatter.rag_manager._rollback_safely.assert_called_once()

    def test_report_generator_propagates_formatter_failure(self):
        generator = ReportGenerator.__new__(ReportGenerator)
        generator._generation_lock = threading.Lock()
        generator._generation_state_lock = threading.RLock()
        generator._generation_reservation = None
        generator._generation_started = False
        generator._generation_client = None
        generator.llm_client = SimpleNamespace(prepare_generation=lambda: True)
        generator.report_formatter = SimpleNamespace(
            generate_report_with_rag=mock.Mock(side_effect=RuntimeError("retrieval failed"))
        )
        generator._update_report_metrics = mock.Mock()

        with self.assertRaisesRegex(RuntimeError, "retrieval failed"):
            generator.generate_report_with_rag([])

        self.assertFalse(generator.generation_active)
        generator._update_report_metrics.assert_called_once_with(
            mock.ANY, "manual", success=False
        )


class CorpusVersionCompatibilityTests(unittest.TestCase):
    def setUp(self):
        self.manager = _configured_manager()
        self.current_versions = self.manager.corpus_version_manifest()
        self.old_model_versions = dict(self.current_versions)
        # Deliberately keep vector dimensions identical.  Model identity is an
        # independent compatibility boundary.
        self.old_model_versions["embedding_model"] = "stored/model-v1"

    def test_startup_readiness_rejects_same_dimension_model_change(self):
        cursor = mock.MagicMock()
        cursor.fetchone.return_value = (
            "ready",
            {"versions": self.old_model_versions},
            0,
            4,
        )
        self.manager.conn = _mock_connection(cursor)

        self.assertFalse(self.manager._check_ready())
        self.assertIn("embedding_model", self.manager.active_corpus_version_mismatches)

    def test_loading_incompatible_active_pointer_records_mismatch(self):
        cursor = mock.MagicMock()
        cursor.fetchone.return_value = (
            self.manager.active_corpus_id,
            {"versions": self.old_model_versions},
        )
        self.manager.conn = _mock_connection(cursor)

        with mock.patch("builtins.print"):
            selected = self.manager._ensure_active_corpus()

        self.assertEqual(selected, self.manager.active_corpus_id)
        self.assertIn("embedding_model", self.manager.active_corpus_version_mismatches)

    def test_unversioned_legacy_rows_are_not_relabelled_as_current_vectors(self):
        cursor = mock.MagicMock()
        cursor.fetchone.side_effect = [None, (True,), None]
        self.manager.conn = _mock_connection(cursor)

        with mock.patch("builtins.print"):
            selected = self.manager._ensure_active_corpus()

        self.assertIsNone(selected)
        sql = "\n".join(call.args[0] for call in cursor.execute.call_args_list)
        self.assertNotIn("UPDATE custom_documents", sql)
        self.assertNotIn("INSERT INTO rag_runtime_state", sql)

    def test_startup_does_not_auto_activate_partial_ready_corpus(self):
        candidate_id = "b" * 64
        manifest = self.manager._build_corpus_manifest(["c" * 64], [])
        manifest["corpus_id"] = candidate_id
        cursor = mock.MagicMock()
        cursor.fetchone.side_effect = [
            None,
            (False,),
            (candidate_id, manifest, 1, 1),
        ]
        self.manager.conn = _mock_connection(cursor)
        self.manager._validate_corpus_completeness = mock.Mock(
            side_effect=ValueError("partial corpus")
        )
        self.manager._set_active_corpus = mock.Mock()

        with mock.patch("builtins.print"):
            selected = self.manager._ensure_active_corpus()

        self.assertIsNone(selected)
        self.manager._set_active_corpus.assert_not_called()

    def test_explicit_activation_rejects_incompatible_ready_corpus(self):
        cursor = mock.MagicMock()
        cursor.fetchone.return_value = (
            "ready",
            {"versions": self.old_model_versions},
            True,
        )
        self.manager.conn = _mock_connection(cursor)
        self.manager._set_active_corpus = mock.Mock()

        with self.assertRaisesRegex(ValueError, "incompatible"):
            self.manager.activate_corpus("b" * 64)

        self.manager._set_active_corpus.assert_not_called()
        self.manager.conn.commit.assert_not_called()

    def test_status_reports_stored_mismatch_and_disables_readiness(self):
        cursor = mock.MagicMock()
        cursor.fetchone.return_value = (
            0,
            0,
            4,
            4,
            1,
            1,
            0,
            0,
            self.old_model_versions,
            "ready",
            {"versions": self.old_model_versions},
            4,
            1,
        )
        self.manager.conn = _mock_connection(cursor)
        self.manager.list_corpora = mock.Mock(return_value={
            "corpora": [], "total": 0, "returned": 0, "truncated": False, "limit": 20,
        })

        status = self.manager.get_rag_status()

        self.assertFalse(status["ready"])
        self.assertFalse(status["active_corpus_version_compatible"])
        self.assertEqual(status["corpus_versions"]["embedding_model"], "stored/model-v1")
        self.assertEqual(
            status["configured_corpus_versions"]["embedding_model"],
            "configured/model-v2",
        )
        self.assertIn("embedding_model", status["active_corpus_version_mismatches"])
        self.assertTrue(status["rag_rebuild_recommended"])


class CorpusLifecycleBoundaryTests(unittest.TestCase):
    def test_lifecycle_listing_is_bounded_manifest_free_and_includes_active(self):
        manager = _configured_manager()
        versions = manager.corpus_version_manifest()
        recent_rows = [
            ("c" * 64, "ready", 3, 9, "created-3", "validated-3", None, versions),
            ("b" * 64, "failed", 2, 0, "created-2", None, None, versions),
        ]
        active_row = (
            manager.active_corpus_id,
            "ready",
            1,
            4,
            "created-1",
            "validated-1",
            "activated-1",
            versions,
        )
        cursor = mock.MagicMock()
        cursor.fetchone.side_effect = [(3,), active_row]
        cursor.fetchall.return_value = recent_rows
        manager.conn = _mock_connection(cursor)

        lifecycle = manager.list_corpora(limit=2)

        self.assertEqual(lifecycle["total"], 3)
        self.assertEqual(lifecycle["returned"], 2)
        self.assertTrue(lifecycle["truncated"])
        self.assertLessEqual(len(lifecycle["corpora"]), 2)
        self.assertTrue(lifecycle["corpora"][0]["active"])
        for summary in lifecycle["corpora"]:
            self.assertNotIn("manifest", summary)
            self.assertNotIn("stored_versions", summary)

        sql = "\n".join(call.args[0] for call in cursor.execute.call_args_list)
        self.assertIn("LIMIT %s", sql)
        self.assertNotIn("SELECT corpus_id, status, manifest,", sql)

    def test_status_database_failure_clears_stale_ready_flag(self):
        manager = _configured_manager()
        manager.rag_ready = True
        manager.conn = SimpleNamespace(
            cursor=mock.Mock(side_effect=RuntimeError("database unavailable")),
            rollback=mock.Mock(),
        )

        with mock.patch("report.log_sanitized_exception"):
            status = manager.get_rag_status()

        self.assertFalse(status["ready"])
        self.assertFalse(manager.rag_ready)
        manager.conn.rollback.assert_called_once()

    def test_schema_startup_contains_no_drop_index(self):
        schema_source = inspect.getsource(RAGContextManager._init_schema).upper()
        self.assertNotIn("DROP INDEX", schema_source)

    def test_empty_core_build_returns_false_without_masking_with_old_readiness(self):
        manager = _configured_manager()
        manager._check_ready = mock.Mock(return_value=True)

        result = manager.build_rag_context(archive_logs=[], custom_docs=[])

        self.assertFalse(result)
        self.assertTrue(manager.rag_ready)
        manager._check_ready.assert_called_once()

    def test_archive_plus_low_quality_document_is_rejected_before_any_source_write(self):
        manager = _configured_manager()
        manager._add_archive_logs = mock.Mock()
        manager._add_custom_docs = mock.Mock()
        manager._rollback_safely = mock.Mock()
        manager._check_ready = mock.Mock(return_value=True)
        low_quality = {
            "content": "x",
            "metadata": {
                "document_quality": {"quality": "low"},
                "cti_artifacts": {},
            },
        }

        with mock.patch("report.log_sanitized_exception"):
            result = manager.build_rag_context(
                archive_logs=[{"rule": {"id": "1001"}}],
                custom_docs=[low_quality],
            )

        self.assertFalse(result)
        self.assertEqual(manager.active_corpus_id, "a" * 64)
        manager._add_archive_logs.assert_not_called()
        manager._add_custom_docs.assert_not_called()

    def test_unindexable_archive_record_cannot_hide_behind_a_valid_document(self):
        manager = _configured_manager()
        manager._add_archive_logs = mock.Mock()
        manager._add_custom_docs = mock.Mock()
        manager._rollback_safely = mock.Mock()
        manager._check_ready = mock.Mock(return_value=True)
        valid = {
            "content": "Observed security incident details and response guidance. " * 8,
            "metadata": {"document_quality": {"quality": "high"}},
        }

        with mock.patch("report.log_sanitized_exception"):
            result = manager.build_rag_context(
                archive_logs=[{}],
                custom_docs=[valid],
            )

        self.assertFalse(result)
        manager._add_archive_logs.assert_not_called()
        manager._add_custom_docs.assert_not_called()

    def test_valid_plus_low_quality_documents_cannot_partially_activate(self):
        manager = _configured_manager()
        manager._add_archive_logs = mock.Mock()
        manager._add_custom_docs = mock.Mock()
        manager._rollback_safely = mock.Mock()
        manager._check_ready = mock.Mock(return_value=True)
        valid = {
            "content": "Observed security incident details and response guidance. " * 8,
            "metadata": {"document_quality": {"quality": "high"}},
        }
        low_quality = {
            "content": "x",
            "metadata": {"document_quality": {"quality": "low"}},
        }

        with mock.patch("report.log_sanitized_exception"):
            result = manager.build_rag_context(custom_docs=[valid, low_quality])

        self.assertFalse(result)
        self.assertEqual(manager.active_corpus_id, "a" * 64)
        manager._add_custom_docs.assert_not_called()

    def test_ingestion_defense_rejects_a_late_low_quality_source(self):
        manager = _configured_manager()
        low_quality = {
            "content": "x",
            "metadata": {"document_quality": {"quality": "low"}},
        }

        with self.assertRaisesRegex(ValueError, "low quality"):
            manager._add_custom_docs([low_quality], corpus_id="b" * 64)

    def test_custom_document_summary_counts_artifact_values(self):
        manager = _configured_manager()
        cursor = mock.MagicMock()
        manager.conn = _mock_connection(cursor)
        manager._encode_texts = mock.Mock(
            side_effect=lambda texts, is_query=False, batch_size=None: [[0.5, 0.5] for _text in texts]
        )
        manager._to_vector_literal = mock.Mock(return_value="[0.5,0.5]")
        content = (
            "Observed 192.0.2.15 communicating with threat.example during an "
            "investigation; isolate the affected endpoint and preserve telemetry."
        )

        with (
            mock.patch(
                "report.execute_values",
                side_effect=[[(7, content)], None],
            ),
            mock.patch("builtins.print") as printer,
        ):
            manager._add_custom_docs(
                [{"content": content, "metadata": {"filename": "source.txt"}}],
                corpus_id="b" * 64,
            )

        output = "\n".join(str(call.args[0]) for call in printer.call_args_list)
        self.assertRegex(output, r"artifacts=\d+")
        self.assertGreaterEqual(manager.conn.commit.call_count, 2)


class SharedConnectionOwnershipTests(unittest.TestCase):
    def test_rollback_waits_for_database_lock_owner(self):
        manager = _configured_manager()
        rollback_called = threading.Event()
        worker_started = threading.Event()
        manager.conn = SimpleNamespace(rollback=rollback_called.set)

        def rollback_from_worker():
            worker_started.set()
            manager._rollback_safely()

        manager.db_lock.acquire()
        try:
            worker = threading.Thread(target=rollback_from_worker)
            worker.start()
            self.assertTrue(worker_started.wait(1.0))
            self.assertFalse(rollback_called.wait(0.05))
        finally:
            manager.db_lock.release()

        worker.join(1.0)
        self.assertFalse(worker.is_alive())
        self.assertTrue(rollback_called.is_set())


class EmbeddingEfficiencyTests(unittest.TestCase):
    def test_chunk_geometry_and_qwen_query_template(self):
        from config import RAGConfig
        from runtime_utils import physical_cpu_count

        config = RAGConfig()
        self.assertEqual(config.document_chunk_size, 1200)
        self.assertEqual(config.document_chunk_overlap, 120)
        self.assertEqual(config.embedding_batch_size, 32)
        self.assertGreaterEqual(physical_cpu_count(), 1)
        self.assertLessEqual(physical_cpu_count(), os.cpu_count() or physical_cpu_count())

        manager = _configured_manager()
        self.assertEqual(
            manager._prepare_embedding_inputs(["alpha"], is_query=True),
            ["Instruct: query instruction\nQuery:alpha"],
        )
        self.assertEqual(
            manager._prepare_embedding_inputs(["passage"], is_query=False),
            ["Instruction: document instruction\nInput: passage"],
        )
        manager.embedding_document_instruction = ""
        self.assertEqual(
            manager._prepare_embedding_inputs(["  passage \n text  "], is_query=False),
            ["passage text"],
        )
        manifest = manager.corpus_version_manifest()
        self.assertEqual(manifest["embedding_input"], "chunk_body")
        self.assertEqual(manifest["document_chunk_size"], 1200)
        self.assertEqual(manifest["document_chunk_overlap"], 120)

    def test_pascal_kernels_are_accepted_and_ampere_only_builds_are_not(self):
        self.assertTrue(RAGContextManager._cuda_arch_supported(6, 1, ["sm_50", "sm_60", "sm_70"]))
        self.assertFalse(RAGContextManager._cuda_arch_supported(6, 1, ["sm_75", "sm_80", "sm_90"]))
        self.assertTrue(RAGContextManager._cuda_arch_supported(10, 0, ["sm_100", "sm_120"]))

    def test_resume_keeps_committed_vectors_and_resets_vectorless_attempts(self):
        manager = _configured_manager()
        cursor = mock.MagicMock()
        cursor.fetchone.return_value = (4, 0)
        manager._reset_unembedded_corpus_rows(cursor, "b" * 64)
        sql = "\n".join(call.args[0] for call in cursor.execute.call_args_list)
        self.assertNotIn("DELETE FROM custom_documents", sql)

        cursor = mock.MagicMock()
        cursor.fetchone.return_value = (0, 0)
        manager._reset_unembedded_corpus_rows(cursor, "c" * 64)
        sql = "\n".join(call.args[0] for call in cursor.execute.call_args_list)
        self.assertIn("DELETE FROM custom_documents", sql)
        self.assertIn("DELETE FROM document_iocs", sql)

    def test_chunk_vectors_use_the_body_and_storage_keeps_the_header(self):
        manager = _configured_manager()
        cursor = mock.MagicMock()
        manager.conn = _mock_connection(cursor)
        encoded = []

        def _encode(texts, is_query=False, batch_size=None):
            encoded.append(list(texts))
            return [[0.2, 0.3] for _text in texts]

        manager._encode_texts = _encode
        manager._to_vector_literal = lambda vector: "[0.2,0.3]"
        content = (
            "Indicators of Compromise\n\n"
            "The implant called 203.0.113.50 and is tracked as CVE-2024-3094 "
            "in the incident writeup."
        )
        inserted_rows = []

        def _execute_values(_cursor, statement, values, fetch=False):
            if "INSERT INTO custom_documents" in statement:
                inserted_rows.extend(values)
                return [(index, row[1], {}) for index, row in enumerate(values)]
            return None

        with mock.patch("report.execute_values", side_effect=_execute_values), mock.patch("builtins.print"):
            manager._add_custom_docs(
                [{"content": content, "metadata": {"filename": "note.txt", "type": "text"}}],
                corpus_id="b" * 64,
            )

        stored = [row[3] for row in inserted_rows]
        self.assertTrue(any(
            "Extracted CTI Artefacts" in text and "CVE-2024-3094" in text
            for text in stored
        ))
        flat = [text for batch in encoded for text in batch]
        body_vectors = [
            text for text in flat
            if "CVE-2024-3094" in text and "Extracted CTI Artefacts" not in text
        ]
        self.assertTrue(body_vectors)


if __name__ == "__main__":
    unittest.main()
