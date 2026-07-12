"""Focused regressions for lossless additive RAG corpus unions."""

from __future__ import annotations

import json
import sys
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


CONFIG_DIR = Path(__file__).resolve().parents[1] / "config"
if str(CONFIG_DIR) not in sys.path:
    sys.path.insert(0, str(CONFIG_DIR))

from report import RAGContextManager, ReportGenerator  # noqa: E402


def _manager() -> RAGContextManager:
    manager = RAGContextManager.__new__(RAGContextManager)
    manager.embedding_model = "configured/embed-v1"
    manager.embedding_device = "cpu"
    manager.embedding_devices = []
    manager.vector_dimensions = 8
    manager.document_chunk_size = 1200
    manager.document_chunk_overlap = 120
    manager.max_retrieval_docs = 8
    manager.normalize_embeddings = True
    manager.similarity_threshold = 0.2
    manager.embedding_batch_size = 8
    manager.embedding_multi_gpu_min_chunks = 64
    manager.retrieval_candidate_multiplier = 4
    manager.embedding_query_instruction = "query"
    manager.embedding_document_instruction = "document"
    manager.db_lock = threading.RLock()
    manager.corpus_state_lock = threading.RLock()
    manager.active_corpus_id = "a" * 64
    manager.active_corpus_version_mismatches = {}
    manager.rag_ready = True
    return manager


def _connection(cursor: mock.MagicMock) -> SimpleNamespace:
    cursor.__enter__.return_value = cursor
    cursor.__exit__.return_value = False
    return SimpleNamespace(
        cursor=mock.Mock(return_value=cursor),
        commit=mock.Mock(),
        rollback=mock.Mock(),
    )


def _inventory(
    custom_hashes=(),
    archive_hashes=(),
    *,
    custom_chunks=0,
    archive_chunks=0,
    embedded_custom_chunks=None,
    embedded_archive_chunks=None,
):
    custom_hashes = set(custom_hashes)
    archive_hashes = set(archive_hashes)
    if embedded_custom_chunks is None:
        embedded_custom_chunks = custom_chunks
    if embedded_archive_chunks is None:
        embedded_archive_chunks = archive_chunks
    return {
        "custom_document_hashes": custom_hashes,
        "archive_record_hashes": archive_hashes,
        "embedded_custom_document_hashes": (
            set(custom_hashes)
            if embedded_custom_chunks == custom_chunks
            else set()
        ),
        "embedded_archive_record_hashes": (
            set(archive_hashes)
            if embedded_archive_chunks == archive_chunks
            else set()
        ),
        "custom_chunks": custom_chunks,
        "archive_chunks": archive_chunks,
        "embedded_custom_chunks": embedded_custom_chunks,
        "embedded_archive_chunks": embedded_archive_chunks,
        "total_chunks": custom_chunks + archive_chunks,
        "embedded_chunks": embedded_custom_chunks + embedded_archive_chunks,
    }


class AdditiveManifestTests(unittest.TestCase):
    def test_manifest_is_typed_deduplicated_and_content_derived(self):
        manager = _manager()
        shared_hash = "b" * 64
        manifest = manager._build_corpus_manifest(
            [shared_hash, shared_hash.upper()],
            [shared_hash, "c" * 64],
            extended_from=manager.active_corpus_id,
        )

        self.assertEqual(manifest["custom_document_hashes"], [shared_hash])
        self.assertEqual(
            manifest["archive_record_hashes"],
            [shared_hash, "c" * 64],
        )
        self.assertEqual(manifest["custom_document_count"], 1)
        self.assertEqual(manifest["archive_record_count"], 2)
        self.assertEqual(manifest["source_item_count"], 3)
        self.assertEqual(manifest["document_count"], 3)
        self.assertEqual(
            manifest["corpus_id"],
            manager.derive_corpus_id(
                [
                    f"custom:{shared_hash}",
                    f"archive:{shared_hash}",
                    f"archive:{'c' * 64}",
                ]
            ),
        )

    def test_inventory_identity_prefers_manifest_content_hash(self):
        manager = _manager()
        cursor = mock.MagicMock()
        cursor.fetchall.side_effect = [
            [("content-hash", 3, 3)],
            [("archive-hash", 1, 1)],
        ]

        inventory = manager._corpus_source_inventory(cursor, "d" * 64)

        self.assertEqual(inventory["custom_document_hashes"], {"content-hash"})
        self.assertEqual(inventory["archive_record_hashes"], {"archive-hash"})
        self.assertEqual(inventory["total_chunks"], 4)
        self.assertEqual(inventory["embedded_chunks"], 4)
        custom_sql = cursor.execute.call_args_list[0].args[0]
        self.assertLess(
            custom_sql.index("metadata->>'content_hash'"),
            custom_sql.index("metadata->>'raw_document_hash'"),
        )

    def test_legacy_manifest_must_exactly_match_row_derived_sources(self):
        manager = _manager()
        source_a = "b" * 64
        source_b = "c" * 64
        corpus_id = manager.derive_corpus_id([source_a, source_b])
        manifest = {
            "corpus_id": corpus_id,
            "document_content_hashes": [source_a, source_b],
            "document_count": 2,
            "versions": manager.corpus_version_manifest(),
        }
        manager._corpus_source_inventory = mock.Mock(return_value=_inventory(
            [source_a],
            [],
            custom_chunks=1,
        ))

        with self.assertRaisesRegex(ValueError, "legacy source membership"):
            manager._validate_legacy_corpus_completeness(
                mock.Mock(),
                corpus_id,
                manifest,
                lifecycle_chunk_count=1,
                lifecycle_source_count=2,
            )

        complete = _inventory(
            [source_a],
            [source_b],
            custom_chunks=1,
            archive_chunks=1,
        )
        manager._corpus_source_inventory.return_value = complete
        result = manager._validate_legacy_corpus_completeness(
            mock.Mock(),
            corpus_id,
            manifest,
            lifecycle_chunk_count=2,
            lifecycle_source_count=2,
        )
        self.assertEqual(result["total_chunks"], 2)

    def test_completeness_requires_exact_membership_and_every_embedding(self):
        manager = _manager()
        manifest = manager._build_corpus_manifest(["b" * 64], ["c" * 64])
        complete = _inventory(
            ["b" * 64],
            ["c" * 64],
            custom_chunks=3,
            archive_chunks=1,
        )
        manager._corpus_source_inventory = mock.Mock(return_value=complete)

        result = manager._validate_corpus_completeness(
            mock.Mock(), manifest["corpus_id"], manifest
        )
        self.assertEqual(result["total_chunks"], 4)

        incomplete = _inventory(
            ["b" * 64],
            ["c" * 64],
            custom_chunks=3,
            archive_chunks=1,
            embedded_custom_chunks=2,
        )
        manager._corpus_source_inventory.return_value = incomplete
        with self.assertRaisesRegex(ValueError, "lack embeddings"):
            manager._validate_corpus_completeness(
                mock.Mock(), manifest["corpus_id"], manifest
            )

        missing_source = _inventory(
            ["b" * 64],
            [],
            custom_chunks=3,
            archive_chunks=0,
        )
        manager._corpus_source_inventory.return_value = missing_source
        with self.assertRaisesRegex(ValueError, "archive record membership"):
            manager._validate_corpus_completeness(
                mock.Mock(), manifest["corpus_id"], manifest
            )

        duplicated_archive_row = _inventory(
            ["b" * 64],
            ["c" * 64],
            custom_chunks=3,
            archive_chunks=2,
        )
        manager._corpus_source_inventory.return_value = duplicated_archive_row
        with self.assertRaisesRegex(ValueError, "rows are duplicated"):
            manager._validate_corpus_completeness(
                mock.Mock(), manifest["corpus_id"], manifest
            )

        manager._corpus_source_inventory.return_value = complete
        with self.assertRaisesRegex(ValueError, "lifecycle chunk count"):
            manager._validate_corpus_completeness(
                mock.Mock(),
                manifest["corpus_id"],
                manifest,
                lifecycle_chunk_count=3,
                lifecycle_source_count=2,
            )


class AdditiveLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.manager = _manager()
        self.cursor = mock.MagicMock()
        self.manager.conn = _connection(self.cursor)
        self.old_doc_hash = "b" * 64
        self.old_archive_hash = "c" * 64
        self.active_inventory = _inventory(
            [self.old_doc_hash],
            [self.old_archive_hash],
            custom_chunks=2,
            archive_chunks=1,
        )
        self.old_manifest = self.manager._build_corpus_manifest(
            [self.old_doc_hash], [self.old_archive_hash]
        )
        self.previous_corpus_id = self.old_manifest["corpus_id"]
        self.manager.active_corpus_id = self.previous_corpus_id
        self.manager._corpus_source_inventory = mock.Mock(
            return_value=self.active_inventory
        )
        self.manager._add_custom_docs = mock.Mock()
        self.manager._add_archive_logs = mock.Mock()
        self.manager._set_active_corpus = mock.Mock()
        self.manager._check_ready = mock.Mock(return_value=True)
        self.manager._rollback_safely = mock.Mock()

    @staticmethod
    def _new_sources():
        document_hash = "d" * 64
        document = {
            "content": "Observed threat activity and response guidance. " * 8,
            "metadata": {
                "content_hash": document_hash,
                "document_quality": {"quality": "high"},
            },
        }
        archive = {
            "rule": {"id": "1001", "description": "Observed threat activity"},
            "data": {"src_ip": "192.0.2.5"},
        }
        return document_hash, document, archive

    def test_extension_copies_prior_rows_and_activates_exact_union(self):
        document_hash, document, archive = self._new_sources()
        existing_document = {
            "content": document["content"],
            "metadata": {
                **document["metadata"],
                "content_hash": self.old_doc_hash,
            },
        }
        archive_hash = self.manager._stable_json_hash(archive)
        self.cursor.fetchone.side_effect = [
            ("ready", self.old_manifest, 3, 2),
            None,
        ]
        final_inventory = _inventory(
            [self.old_doc_hash, document_hash],
            [self.old_archive_hash, archive_hash],
            custom_chunks=5,
            archive_chunks=2,
        )
        self.manager._validate_corpus_completeness = mock.Mock(
            side_effect=[self.active_inventory, final_inventory]
        )

        with mock.patch("builtins.print"):
            result = self.manager.extend_rag_context(
                archive_logs=[archive],
                custom_docs=[existing_document, document, document],
            )

        self.assertTrue(result)
        insert_call = next(
            call
            for call in self.cursor.execute.call_args_list
            if "INSERT INTO rag_corpora" in call.args[0]
        )
        manifest = json.loads(insert_call.args[1][1])
        self.assertEqual(
            set(manifest["custom_document_hashes"]),
            {self.old_doc_hash, document_hash},
        )
        self.assertEqual(
            set(manifest["archive_record_hashes"]),
            {self.old_archive_hash, archive_hash},
        )
        self.assertEqual(manifest["source_item_count"], 4)
        self.assertEqual(manifest["document_count"], 4)
        self.assertEqual(self.manager.active_corpus_id, manifest["corpus_id"])
        self.manager._set_active_corpus.assert_called_once_with(
            self.cursor, manifest["corpus_id"]
        )
        self.manager._add_archive_logs.assert_called_once_with(
            [archive], corpus_id=manifest["corpus_id"]
        )
        self.manager._add_custom_docs.assert_called_once_with(
            [document],
            corpus_id=manifest["corpus_id"],
            manifest=manifest,
        )
        sql = "\n".join(
            call.args[0] for call in self.cursor.execute.call_args_list
        )
        self.assertIn("FROM custom_documents WHERE corpus_id = %s", sql)
        self.assertIn("FROM alert_embeddings WHERE corpus_id = %s", sql)
        self.assertIn("metadata->>'raw_alert_hash'", sql)

    def test_explicit_replacement_uses_the_same_typed_manifest_contract(self):
        document_hash, document, archive = self._new_sources()
        archive_hash = self.manager._stable_json_hash(archive)
        self.cursor.fetchone.return_value = None
        final_inventory = _inventory(
            [document_hash],
            [archive_hash],
            custom_chunks=3,
            archive_chunks=1,
        )
        self.manager._validate_corpus_completeness = mock.Mock(
            return_value=final_inventory
        )

        with mock.patch("builtins.print"):
            result = self.manager.build_rag_context(
                archive_logs=[archive], custom_docs=[document]
            )

        self.assertTrue(result)
        insert_call = next(
            call
            for call in self.cursor.execute.call_args_list
            if "INSERT INTO rag_corpora" in call.args[0]
        )
        manifest = json.loads(insert_call.args[1][1])
        self.assertEqual(manifest["custom_document_hashes"], [document_hash])
        self.assertEqual(manifest["archive_record_hashes"], [archive_hash])
        self.assertEqual(manifest["source_item_count"], 2)
        self.assertNotIn("extended_from", manifest)
        self.manager._add_archive_logs.assert_called_once_with(
            [archive], corpus_id=manifest["corpus_id"]
        )
        self.manager._add_custom_docs.assert_called_once_with(
            [document],
            corpus_id=manifest["corpus_id"],
            manifest=manifest,
        )

    def test_extension_failure_preserves_prior_active_pointer(self):
        _document_hash, document, _archive = self._new_sources()
        self.cursor.fetchone.side_effect = [
            ("ready", self.old_manifest, 3, 2),
            None,
        ]
        self.manager._add_custom_docs.side_effect = RuntimeError("embedding failed")

        with mock.patch("builtins.print"), self.assertRaisesRegex(
            RuntimeError, "embedding failed"
        ):
            self.manager.extend_rag_context(custom_docs=[document])

        self.assertEqual(self.manager.active_corpus_id, self.previous_corpus_id)
        self.assertTrue(self.manager.rag_ready)
        self.manager._set_active_corpus.assert_not_called()
        self.manager._rollback_safely.assert_called()
        failed_updates = [
            call
            for call in self.cursor.execute.call_args_list
            if "status='failed'" in call.args[0]
        ]
        self.assertEqual(len(failed_updates), 1)
        self.assertIn("status <> 'ready'", failed_updates[0].args[0])

    def test_ready_target_shortcut_rejects_partial_membership(self):
        _document_hash, document, _archive = self._new_sources()
        target_manifest = self.manager._build_corpus_manifest(
            [self.old_doc_hash, "d" * 64], [self.old_archive_hash]
        )
        self.cursor.fetchone.side_effect = [
            ("ready", self.old_manifest, 3, 2),
            ("ready", target_manifest, 4, 3),
        ]
        self.manager._validate_corpus_completeness = mock.Mock(
            side_effect=ValueError("target membership is incomplete")
        )

        with self.assertRaisesRegex(ValueError, "membership is incomplete"):
            self.manager.extend_rag_context(custom_docs=[document])

        self.assertEqual(self.manager.active_corpus_id, self.previous_corpus_id)
        self.manager._set_active_corpus.assert_not_called()
        sql = "\n".join(
            call.args[0] for call in self.cursor.execute.call_args_list
        )
        self.assertNotIn("DELETE FROM custom_documents", sql)
        self.assertNotIn("INSERT INTO custom_documents", sql)


class ArchiveAndStatusTests(unittest.TestCase):
    def test_distinct_raw_archive_records_do_not_collapse_on_equal_text(self):
        manager = _manager()
        cursor = mock.MagicMock()
        cursor.fetchall.return_value = [(1, "same"), (2, "same")]
        manager.conn = _connection(cursor)
        manager._create_semantic_chunk = mock.Mock(return_value="same semantic text")
        manager._encode_texts = mock.Mock(return_value=[[0.1] * 8, [0.2] * 8])
        manager._to_vector_literal = mock.Mock(return_value="[0.1]")
        records = [
            {"rule": {"id": "1"}, "private_variant": "one"},
            {"rule": {"id": "1"}, "private_variant": "two"},
        ]

        with mock.patch(
            "report.execute_values",
            side_effect=[[(1,), (2,)], None],
        ) as execute:
            manager._add_archive_logs(records, corpus_id="e" * 64)

        inserted_values = execute.call_args_list[0].args[2]
        source_hashes = [row[1] for row in inserted_values]
        metadata_hashes = [json.loads(row[3])["raw_alert_hash"] for row in inserted_values]
        self.assertEqual(len(set(source_hashes)), 2)
        self.assertEqual(source_hashes, metadata_hashes)

    def test_status_exposes_explicit_active_union_counts(self):
        manager = _manager()
        cursor = mock.MagicMock()
        versions = manager.corpus_version_manifest()
        manifest = manager._build_corpus_manifest(
            ["b" * 64, "c" * 64],
            ["d" * 64, "e" * 64, "f" * 64],
        )
        cursor.fetchone.return_value = (
            3,
            3,
            7,
            7,
            2,
            2,
            0,
            0,
            versions,
            "ready",
            manifest,
            10,
            5,
        )
        manager.conn = _connection(cursor)
        manager._validate_corpus_completeness = mock.Mock(return_value=_inventory(
            ["b" * 64, "c" * 64],
            ["d" * 64, "e" * 64, "f" * 64],
            custom_chunks=7,
            archive_chunks=3,
        ))
        manager.list_corpora = mock.Mock(return_value={
            "corpora": [],
            "total": 1,
            "returned": 1,
            "truncated": False,
            "limit": 20,
        })

        status = manager.get_rag_status()

        self.assertEqual(status["active_archive_records"], 3)
        self.assertEqual(status["active_source_documents"], 2)
        self.assertEqual(status["active_document_chunks"], 7)
        self.assertEqual(status["active_total_chunks"], 10)
        self.assertEqual(status["active_embedded_chunks"], 10)
        self.assertEqual(status["active_source_items"], 5)
        self.assertEqual(status["active_union_counts"]["source_items"], 5)
        self.assertEqual(status["active_union_counts"]["total_chunks"], 10)

    def test_readiness_and_activation_reject_typed_partial_corpus(self):
        manager = _manager()
        manifest = manager._build_corpus_manifest(["b" * 64], [])
        corpus_id = manifest["corpus_id"]
        manager.active_corpus_id = corpus_id
        cursor = mock.MagicMock()
        cursor.fetchone.return_value = ("ready", manifest, 2, 1)
        manager.conn = _connection(cursor)
        manager._corpus_source_inventory = mock.Mock(return_value=_inventory(
            ["b" * 64],
            [],
            custom_chunks=2,
            embedded_custom_chunks=1,
        ))
        manager._set_active_corpus = mock.Mock()

        with mock.patch("report.log_sanitized_exception"):
            self.assertFalse(manager._check_ready())
        with self.assertRaisesRegex(ValueError, "lack embeddings"):
            manager.activate_corpus(corpus_id)

        manager._set_active_corpus.assert_not_called()

    def test_status_is_not_ready_when_any_active_chunk_lacks_embedding(self):
        manager = _manager()
        cursor = mock.MagicMock()
        versions = manager.corpus_version_manifest()
        manifest = manager._build_corpus_manifest(
            ["b" * 64, "c" * 64],
            ["d" * 64, "e" * 64, "f" * 64],
        )
        cursor.fetchone.return_value = (
            3,
            2,
            7,
            7,
            2,
            2,
            0,
            0,
            versions,
            "ready",
            manifest,
            10,
            5,
        )
        manager.conn = _connection(cursor)
        manager._validate_corpus_completeness = mock.Mock(return_value=_inventory(
            ["b" * 64, "c" * 64],
            ["d" * 64, "e" * 64, "f" * 64],
            custom_chunks=7,
            archive_chunks=3,
        ))
        manager.list_corpora = mock.Mock(return_value={
            "corpora": [],
            "total": 1,
            "returned": 1,
            "truncated": False,
            "limit": 20,
        })

        status = manager.get_rag_status()

        self.assertFalse(status["ready"])
        self.assertEqual(status["active_total_chunks"], 10)
        self.assertEqual(status["active_embedded_chunks"], 9)

    def test_status_rejects_ready_row_with_inexact_manifest_membership(self):
        manager = _manager()
        cursor = mock.MagicMock()
        versions = manager.corpus_version_manifest()
        manifest = manager._build_corpus_manifest(["b" * 64, "c" * 64], [])
        cursor.fetchone.return_value = (
            0,
            0,
            4,
            4,
            1,
            1,
            0,
            0,
            versions,
            "ready",
            manifest,
            4,
            2,
        )
        manager.conn = _connection(cursor)
        manager._validate_corpus_completeness = mock.Mock(
            side_effect=ValueError(
                "Corpus validation failed: custom document membership is incomplete"
            )
        )
        manager.list_corpora = mock.Mock(return_value={
            "corpora": [],
            "total": 1,
            "returned": 1,
            "truncated": False,
            "limit": 20,
        })

        status = manager.get_rag_status()

        self.assertFalse(status["ready"])
        self.assertFalse(status["active_corpus_integrity_valid"])
        self.assertIn("membership is incomplete", status["active_corpus_integrity_error"])


class ApprovedReportUnionTests(unittest.TestCase):
    def test_approved_report_uses_additive_path_and_propagates_failure(self):
        generator = ReportGenerator.__new__(ReportGenerator)
        generator.add_custom_documents = mock.Mock(return_value=True)

        self.assertTrue(generator.index_approved_report(
            "# Analyst CTI\n\nObserved malware behavior and remediation evidence.",
            "approved.md",
        ))
        indexed_doc = generator.add_custom_documents.call_args.args[0][0]
        self.assertEqual(indexed_doc["metadata"]["type"], "approved_report")
        self.assertTrue(indexed_doc["metadata"]["human_validated"])

        generator.add_custom_documents.return_value = False
        self.assertFalse(generator.index_approved_report(
            "# Analyst CTI\n\nA second validated report.",
            "failed.md",
        ))


if __name__ == "__main__":
    unittest.main()
