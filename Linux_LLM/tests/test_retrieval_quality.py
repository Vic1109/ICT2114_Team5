#!/usr/bin/env python3
"""Deterministic checks for lexical retrieval, index lifecycle, thresholds and chunking.

PostgreSQL is replaced by a recording cursor, so these checks validate the SQL
that would be executed (placeholder/parameter agreement, OR composition,
LIMIT presence) plus every pure-Python decision around it. They do not prove
PostgreSQL planner behaviour; see the runtime validation checklist for that.
"""

from __future__ import annotations

import sys
import threading
import types
import unittest
from pathlib import Path

CONFIG_DIR = Path(__file__).resolve().parents[1] / "config"
if str(CONFIG_DIR) not in sys.path:
    sys.path.insert(0, str(CONFIG_DIR))

from test_rag_regressions import _install_runtime_stubs  # noqa: E402

_install_runtime_stubs()

from report import RAGContextManager  # noqa: E402


class RecordingCursor:
    """Minimal cursor that records statements and serves canned rows."""

    def __init__(self, rows_by_marker=None):
        self.statements = []
        self.rows_by_marker = rows_by_marker or {}
        self._pending = []

    def execute(self, statement, params=None):
        params = tuple(params or ())
        placeholders = statement.count("%s")
        if placeholders != len(params):
            raise AssertionError(
                f"SQL placeholder/parameter mismatch: {placeholders} placeholders, "
                f"{len(params)} parameters in:\n{statement}"
            )
        self.statements.append((statement, params))
        self._pending = []
        for marker, rows in self.rows_by_marker.items():
            if marker in statement:
                self._pending = list(rows)
                break

    def fetchall(self):
        return list(self._pending)

    def fetchone(self):
        return self._pending[0] if self._pending else None

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False


class FakeConnection:
    def __init__(self, cursor):
        self._cursor = cursor
        self.commits = 0

    def cursor(self):
        return self._cursor

    def commit(self):
        self.commits += 1


def _manager(**overrides) -> RAGContextManager:
    manager = RAGContextManager.__new__(RAGContextManager)
    manager.max_lexical_terms = 24
    manager.max_exact_match_rows = 200
    manager.similarity_threshold = 0.2
    manager.evidence_similarity_threshold = 0.35
    manager.similarity_instrumentation = False
    manager.last_similarity_observation = {}
    manager.max_retrieval_docs = 10
    manager.retrieval_candidate_multiplier = 4
    manager.document_chunk_size = 1200
    manager.document_chunk_overlap = 120
    manager.vector_index_type = "ivfflat"
    manager.vector_index_min_rows = 1000
    manager.ivfflat_lists = 0
    manager.ivfflat_probes = 0
    manager.hnsw_m = 16
    manager.hnsw_ef_construction = 64
    manager.hnsw_ef_search = 0
    manager.vector_index_rebuild_ratio = 3.0
    manager._vector_index_state = {}
    manager._vector_tuning_warning_emitted = False
    manager.db_lock = threading.RLock()
    manager.corpus_state_lock = threading.RLock()
    manager.active_corpus_id = "a" * 64
    manager.rag_ready = True
    for key, value in overrides.items():
        setattr(manager, key, value)
    return manager


# --------------------------------------------------------------------------
# Phase 2 - lexical retrieval
# --------------------------------------------------------------------------

class LexicalRetrievalTests(unittest.TestCase):
    def test_terms_are_or_composed_not_anded(self):
        """Regression: one plainto_tsquery ANDed every term, matching nothing."""
        manager = _manager()
        sql = manager._lexical_tsquery_sql(3)
        self.assertEqual(sql.count("plainto_tsquery('simple', %s)"), 3)
        self.assertEqual(sql.count("||"), 2)
        self.assertNotIn("&&", sql)

    def test_identifiers_and_phrases_are_separate_terms(self):
        manager = _manager()
        terms = manager._build_lexical_terms(
            "poisonfrog.ps1 c2.example.net credential dumping",
            {
                "hashes": ["a" * 64],
                "domains": ["c2.example.net"],
                "rule_ids": ["900001"],
                "threat_actors": ["APT29"],
                "malware_families": ["Cobalt Strike"],
            },
        )
        self.assertIn("a" * 64, terms)
        self.assertIn("c2.example.net", terms)
        self.assertIn("900001", terms)
        # Short curated entity names must survive; the generic-term heuristic
        # would have rejected "APT29" on length alone.
        self.assertIn("APT29", terms)
        # Multi-word phrases stay whole so plainto_tsquery ANDs their words.
        self.assertIn("Cobalt Strike", terms)

    def test_many_unrelated_terms_do_not_all_have_to_match(self):
        manager = _manager()
        terms = manager._build_lexical_terms(
            " ".join(f"unrelated-token-{index}" for index in range(50)),
            {"domains": ["evil.example.com"]},
        )
        self.assertIn("evil.example.com", terms)
        self.assertGreater(len(terms), 1)
        sql = manager._lexical_tsquery_sql(len(terms))
        # Disjunction means a document matching only evil.example.com is found.
        self.assertEqual(sql.count("||"), len(terms) - 1)

    def test_term_count_is_bounded(self):
        manager = _manager(max_lexical_terms=8)
        terms = manager._build_lexical_terms(
            " ".join(f"indicator-{index}.example.net" for index in range(200)),
            {"domains": [f"host-{index}.example.org" for index in range(200)]},
        )
        self.assertLessEqual(len(terms), 8)

    def test_ioc_heavy_query_keeps_identifiers_over_prose(self):
        manager = _manager(max_lexical_terms=4)
        terms = manager._build_lexical_terms(
            "reconnaissance activity observed against the perimeter appliance",
            {"hashes": ["b" * 64], "cves": ["CVE-2024-3400"], "urls": ["http://evil.example.net/a"]},
        )
        self.assertIn("b" * 64, terms)
        self.assertIn("CVE-2024-3400", terms)

    def test_malformed_and_empty_input_does_not_crash(self):
        manager = _manager()
        for query, exact in (
            ("", None),
            (None, {}),
            ("   ", {"domains": []}),
            ("' OR 1=1 --", {"keywords": ["!!!", "   ", "&&&"]}),
            ("a & b | c ! ( ) : * <->", {"domains": ["<script>"]}),
        ):
            with self.subTest(query=query):
                terms = manager._build_lexical_terms(query, exact)
                self.assertIsInstance(terms, list)
                for term in terms:
                    # Every operand must yield at least one lexeme.
                    self.assertTrue(manager._lexical_term_is_usable(term))

    def test_plain_prose_query_still_reaches_the_lexical_arm(self):
        manager = _manager()
        terms = manager._build_lexical_terms("lsass dump mimikatz", None)
        self.assertTrue(terms, "Plain prose query produced no lexical operands")

    def test_hybrid_search_binds_every_lexical_term(self):
        manager = _manager()
        cursor = RecordingCursor()
        manager.conn = FakeConnection(cursor)
        manager._encode_texts = lambda texts, is_query=False: [[0.1, 0.2]]
        manager._to_vector_literal = lambda vector: "[0.1,0.2]"
        manager._normalize_for_embedding = lambda text, max_chars=4000: str(text)

        manager._hybrid_search(
            "c2.example.net poisonfrog.ps1",
            k=5,
            exact_terms={"domains": ["c2.example.net"], "rule_ids": ["900001"]},
        )

        lexical = [
            (statement, params)
            for statement, params in cursor.statements
            if "ts_rank_cd" in statement
        ]
        self.assertEqual(len(lexical), 2, "Both lexical arms should run")
        for statement, _params in lexical:
            self.assertIn("plainto_tsquery('simple', %s) || plainto_tsquery('simple', %s)", statement)
            self.assertIn("LIMIT %s", statement)

    def test_lexical_arm_is_skipped_when_no_terms_survive(self):
        manager = _manager()
        cursor = RecordingCursor()
        manager.conn = FakeConnection(cursor)
        manager._encode_texts = lambda texts, is_query=False: [[0.1, 0.2]]
        manager._to_vector_literal = lambda vector: "[0.1,0.2]"
        manager._normalize_for_embedding = lambda text, max_chars=4000: ""

        manager._hybrid_search("", k=5, exact_terms=None)
        self.assertFalse([s for s, _ in cursor.statements if "ts_rank_cd" in s])

    def test_lexical_evidence_accepts_vetted_short_entity_names(self):
        manager = _manager()
        evidence = manager._lexical_match_evidence(
            "apt29 campaign",
            "Reporting attributes the intrusion to APT29 infrastructure.",
            {},
            terms=["APT29"],
        )
        self.assertTrue(any("apt29" in item for item in evidence))


# --------------------------------------------------------------------------
# Phase 3 - vector index lifecycle
# --------------------------------------------------------------------------

class VectorIndexLifecycleTests(unittest.TestCase):
    def test_lists_follow_pgvector_sizing_guidance(self):
        manager = _manager()
        self.assertEqual(manager._ivfflat_lists_for_rows(0), 1)
        self.assertEqual(manager._ivfflat_lists_for_rows(50_000), 50)
        self.assertEqual(manager._ivfflat_lists_for_rows(1_000_000), 1000)
        self.assertEqual(manager._ivfflat_lists_for_rows(4_000_000), 2000)

    def test_probes_default_to_sqrt_of_lists(self):
        manager = _manager()
        self.assertEqual(manager._ivfflat_probes_for_lists(100), 10)
        self.assertEqual(manager._ivfflat_probes_for_lists(1), 1)

    def test_probes_prefer_explicit_configuration(self):
        self.assertEqual(_manager(ivfflat_probes=42)._resolved_ivfflat_probes(), 42)

    def test_probes_derive_from_recorded_build_state(self):
        manager = _manager(_vector_index_state={"alert_embeddings": {"lists": 400}})
        self.assertEqual(manager._resolved_ivfflat_probes(), 20)

    def test_probes_fall_back_to_a_safe_default(self):
        self.assertEqual(_manager()._resolved_ivfflat_probes(), 10)

    def test_search_tuning_uses_set_config_not_set(self):
        """SET rejects bind parameters; set_config(..., true) is transaction-local."""
        manager = _manager()
        cursor = RecordingCursor()
        manager._apply_vector_search_tuning(cursor)
        statements = [statement for statement, _ in cursor.statements]
        self.assertIn("SAVEPOINT vector_search_tuning", statements[0])
        self.assertIn("set_config", statements[1])
        self.assertEqual(cursor.statements[1][1], ("ivfflat.probes", "10"))

    def test_small_corpus_drops_the_index_instead_of_keeping_a_stale_one(self):
        manager = _manager()
        cursor = RecordingCursor(rows_by_marker={
            "count(*)": [(12,)],
            "pg_class": [(True,)],
            "SELECT value FROM rag_runtime_state": [],
        })
        manager.conn = FakeConnection(cursor)
        manager._rollback_safely = lambda: None
        summary = manager._ensure_vector_indexes()
        statements = " ".join(statement for statement, _ in cursor.statements)
        self.assertIn("DROP INDEX IF EXISTS alert_embedding_idx", statements)
        self.assertNotIn("USING ivfflat", statements)
        self.assertEqual(summary["alert_embeddings"]["action"], "dropped")

    def test_populated_corpus_builds_index_sized_to_the_data(self):
        manager = _manager()
        cursor = RecordingCursor(rows_by_marker={
            "count(*)": [(60_000,)],
            "pg_class": [(False,)],
            "SELECT value FROM rag_runtime_state": [],
        })
        manager.conn = FakeConnection(cursor)
        manager._rollback_safely = lambda: None
        summary = manager._ensure_vector_indexes()
        statements = " ".join(statement for statement, _ in cursor.statements)
        self.assertIn("USING ivfflat (embedding vector_cosine_ops) WITH (lists = 60)", statements)
        self.assertEqual(summary["alert_embeddings"]["lists"], 60)

    def test_untracked_existing_index_is_rebuilt(self):
        """An index with no recorded state came from the old empty-table path."""
        manager = _manager()
        cursor = RecordingCursor(rows_by_marker={
            "count(*)": [(60_000,)],
            "pg_class": [(True,)],
            "SELECT value FROM rag_runtime_state": [],
        })
        manager.conn = FakeConnection(cursor)
        manager._rollback_safely = lambda: None
        summary = manager._ensure_vector_indexes()
        self.assertEqual(summary["alert_embeddings"]["action"], "rebuilt")

    def test_hnsw_is_available_but_not_automatic(self):
        default = _manager()
        self.assertEqual(default.vector_index_type, "ivfflat")
        opted_in = _manager(vector_index_type="hnsw")
        statement, state = opted_in._vector_index_sql("custom_documents", "doc_embedding_idx", 60_000)
        self.assertIn("USING hnsw", statement)
        self.assertEqual(state["index_type"], "hnsw")


# --------------------------------------------------------------------------
# Phase 4 - similarity thresholds
# --------------------------------------------------------------------------

class SimilarityThresholdTests(unittest.TestCase):
    def test_weak_semantic_only_candidates_are_dropped(self):
        manager = _manager(evidence_similarity_threshold=0.4)
        kept, dropped = manager._apply_evidence_similarity_threshold([
            {"id": 1, "match_types": ["semantic"], "semantic_score": 0.55},
            {"id": 2, "match_types": ["semantic"], "semantic_score": 0.22},
        ])
        self.assertEqual([item["id"] for item in kept], [1])
        self.assertEqual([item["id"] for item in dropped], [2])

    def test_exact_ioc_matches_survive_low_similarity(self):
        manager = _manager(evidence_similarity_threshold=0.9)
        kept, dropped = manager._apply_evidence_similarity_threshold([
            {"id": 1, "match_types": ["exact"], "semantic_score": 0.05},
            {"id": 2, "match_types": ["lexical"], "semantic_score": 0.0},
            {"id": 3, "match_types": ["semantic", "exact"], "semantic_score": 0.1},
        ])
        self.assertEqual([item["id"] for item in kept], [1, 2, 3])
        self.assertEqual(dropped, [])

    def test_candidate_and_evidence_thresholds_are_distinct(self):
        manager = _manager()
        self.assertLess(manager.similarity_threshold, manager.evidence_similarity_threshold)

    def test_threshold_can_be_disabled(self):
        manager = _manager(evidence_similarity_threshold=0.0)
        kept, dropped = manager._apply_evidence_similarity_threshold([
            {"id": 1, "match_types": ["semantic"], "semantic_score": 0.01},
        ])
        self.assertEqual(len(kept), 1)
        self.assertEqual(dropped, [])

    def test_instrumentation_records_a_measurable_distribution(self):
        manager = _manager()
        observation = manager._record_similarity_observation(
            "query text",
            [{"match_types": ["semantic"], "semantic_score": 0.8},
             {"match_types": ["exact"], "semantic_score": 0.1}],
            [{"match_types": ["semantic"], "semantic_score": 0.05}],
        )
        self.assertEqual(observation["candidates"], 3)
        self.assertEqual(observation["kept"], 2)
        self.assertEqual(observation["dropped_weak_semantic"], 1)
        self.assertEqual(observation["similarity_max"], 0.8)
        self.assertEqual(observation["exact_or_lexical_supported"], 1)
        # No query text or document content may be captured.
        self.assertNotIn("query", observation)
        self.assertEqual(observation["query_chars"], len("query text"))


# --------------------------------------------------------------------------
# Phase 5 - chunk overlap
# --------------------------------------------------------------------------

def _long_paragraph(marker: str, sentences: int = 12) -> str:
    return " ".join(
        f"{marker} sentence {index} describing intrusion activity in detail."
        for index in range(sentences)
    )


class ChunkOverlapTests(unittest.TestCase):
    def test_consecutive_chunks_share_real_overlap(self):
        manager = _manager()
        text = "\n\n".join(_long_paragraph(f"P{index}") for index in range(8))
        chunks = manager._chunk_text(text, chunk_size=600, chunk_overlap=120)
        self.assertGreater(len(chunks), 2)
        for previous, following in zip(chunks, chunks[1:]):
            shared = following[:120].strip()
            self.assertTrue(shared, "Chunk boundary produced no overlap text")
            self.assertIn(shared.split()[0], previous)

    def test_long_paragraphs_still_produce_overlap(self):
        """Regression: paragraphs longer than the overlap gave exactly zero overlap."""
        manager = _manager()
        text = "\n\n".join(_long_paragraph(f"LONG{index}", sentences=40) for index in range(4))
        chunks = manager._chunk_text(text, chunk_size=800, chunk_overlap=150)
        self.assertGreater(len(chunks), 2)
        overlaps = 0
        for previous, following in zip(chunks, chunks[1:]):
            head = following[:100].strip()
            if head and head in previous:
                overlaps += 1
        self.assertEqual(overlaps, len(chunks) - 1)

    def test_short_text_is_a_single_chunk(self):
        manager = _manager()
        self.assertEqual(manager._chunk_text("short note", chunk_size=600), ["short note"])

    def test_overlap_does_not_split_structured_iocs(self):
        manager = _manager()
        digest = "d" * 64
        text = "\n\n".join([
            _long_paragraph("A", sentences=20),
            f"Observed file hash {digest} on the affected host.",
            _long_paragraph("B", sentences=20),
        ])
        chunks = manager._chunk_text(text, chunk_size=500, chunk_overlap=120)
        for chunk in chunks:
            for token in chunk.split():
                if token.startswith("d") and set(token) == {"d"}:
                    self.assertEqual(len(token), 64, "Hash IoC was cut mid-token by overlap")

    def test_overlap_never_breaks_unicode(self):
        manager = _manager()
        text = "\n\n".join(f" Observación {index} — actividad maliciosa 攻撃 " * 30 for index in range(4))
        chunks = manager._chunk_text(text, chunk_size=500, chunk_overlap=120)
        for chunk in chunks:
            chunk.encode("utf-8").decode("utf-8")
        self.assertGreater(len(chunks), 1)

    def test_section_metadata_survives_overlap(self):
        manager = _manager()
        text = "\n\n".join([
            "## Attribution",
            _long_paragraph("ATTR", sentences=30),
            "## Indicators of Compromise",
            _long_paragraph("IOC", sentences=30),
        ])
        chunks = manager._chunk_text_with_sections(text, chunk_size=600, chunk_overlap=120)
        self.assertGreater(len(chunks), 2)
        paths = {chunk["section_path"] for chunk in chunks}
        self.assertIn("Attribution", paths)
        self.assertIn("Indicators of Compromise", paths)
        for chunk in chunks:
            self.assertTrue(chunk["text"].strip())
            if chunk["section_path"]:
                self.assertEqual(chunk["section_heading"], chunk["section_path"].split(" > ")[-1])

    def test_section_chunks_share_overlap_too(self):
        manager = _manager()
        text = "## Analysis\n\n" + "\n\n".join(
            _long_paragraph(f"S{index}", sentences=25) for index in range(4)
        )
        chunks = manager._chunk_text_with_sections(text, chunk_size=700, chunk_overlap=140)
        self.assertGreater(len(chunks), 2)
        for previous, following in zip(chunks, chunks[1:]):
            head = following["text"][:100].strip()
            self.assertTrue(head and head in previous["text"])

    def test_overlap_is_capped_relative_to_chunk_size(self):
        manager = _manager()
        self.assertEqual(manager._effective_chunk_overlap(1200, 120), 120)
        self.assertEqual(manager._effective_chunk_overlap(400, 350), 100)


if __name__ == "__main__":
    unittest.main()
