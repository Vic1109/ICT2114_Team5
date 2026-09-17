import hashlib
import json
import sys
import unittest
from pathlib import Path


CONFIG_DIR = Path(__file__).resolve().parents[1] / "config"
if str(CONFIG_DIR) not in sys.path:
    sys.path.insert(0, str(CONFIG_DIR))

from main import SOCApplication  # noqa: E402
from rag import CSVProcessor, DocumentProcessor, JSONProcessor, XMLProcessor  # noqa: E402
from report import AlertAnalyzer, EnhancedReportFormatter, RAGContextManager  # noqa: E402


class CorpusIdentityTests(unittest.TestCase):
    def manager(self):
        manager = object.__new__(RAGContextManager)
        manager.embedding_model = "fictional/embed-v1"
        manager.vector_dimensions = 16
        manager.normalize_embeddings = True
        manager.document_chunk_size = 900
        manager.document_chunk_overlap = 90
        manager.embedding_document_instruction = ""
        return manager

    def test_corpus_identity_is_filename_and_order_invariant(self):
        manager = self.manager()
        hashes = [hashlib.sha256(value).hexdigest() for value in (b"alpha", b"beta")]
        expected = manager.derive_corpus_id(hashes)
        self.assertEqual(expected, manager.derive_corpus_id(reversed(hashes)))
        self.assertEqual(expected, manager.derive_corpus_id(hashes + [hashes[0]]))

    def test_corpus_identity_changes_with_index_configuration(self):
        first = self.manager()
        second = self.manager()
        second.document_chunk_size += 1
        self.assertNotEqual(first.derive_corpus_id(["a" * 64]), second.derive_corpus_id(["a" * 64]))

    def test_cache_key_includes_corpus_and_versions(self):
        manager = self.manager()
        manager.active_corpus_id = "a" * 64
        one = manager.build_cache_key({"domain": "new-value.test"}, "ctx", "model", "prompt-v1")
        manager.active_corpus_id = "b" * 64
        two = manager.build_cache_key({"domain": "new-value.test"}, "ctx", "model", "prompt-v1")
        self.assertNotEqual(one, two)
        manager.active_corpus_id = "a" * 64
        self.assertNotEqual(one, manager.build_cache_key({"domain": "new-value.test"}, "ctx", "model", "prompt-v2"))

    def test_display_metadata_is_excluded_from_scoring(self):
        first = RAGContextManager._ranking_metadata({
            "filename": "wrong-actor-report.pdf", "source_path": "/tmp/wrong",
            "cti_artifacts": {"domains": ["content-driven.test"]},
        })
        second = RAGContextManager._ranking_metadata({
            "filename": "random.pdf", "source_path": "/elsewhere",
            "cti_artifacts": {"domains": ["content-driven.test"]},
        })
        self.assertEqual(first, second)

    def test_mitre_only_overlap_and_version_numbers_are_not_decisive(self):
        self.assertTrue(EnhancedReportFormatter._is_low_signal_cti_exact_value("keywords", "3.6"))
        formatter = object.__new__(EnhancedReportFormatter)
        docs = formatter._annotate_context_docs([{
            "source": "custom_document", "match_types": ["exact"],
            "match_evidence": ["mitre technique matched extracted CTI artifact T1059.001"],
            "metadata": {"cti_artifacts": {"mitre_techniques": ["T1059.001"]}},
        }], [{"observed_iocs": {"mitre_techniques": ["T1059.001"]}, "behavior_tags": []}])
        self.assertEqual(docs[0]["evidence_strength"], "low")


class FilenameIsolationTests(unittest.TestCase):
    def test_filename_and_pdf_metadata_do_not_enter_artifact_text(self):
        body = "Observed domain body-only.test"
        first = DocumentProcessor._artifact_extraction_text(
            body, "wrong-actor.test.pdf", {"pdf_title": "Wrong Campaign"}
        )
        second = DocumentProcessor._artifact_extraction_text(
            body, "uuid.pdf", {"pdf_title": "Different Wrong Campaign"}
        )
        self.assertEqual(first, second)
        self.assertNotIn("wrong-actor", first)

    def test_structured_formatters_do_not_embed_filename(self):
        json_text = JSONProcessor._format_for_rag({"domain": "body-only.test"}, "actor-name.json")
        self.assertNotIn("actor-name.json", json_text)
        csv_text, _ = CSVProcessor.extract_text_and_metadata(b"domain\nbody-only.test\n", "actor-name.csv")
        self.assertNotIn("actor-name.csv", csv_text)
        xml_text, _ = XMLProcessor.extract_text_and_metadata(
            b"<report><domain>body-only.test</domain></report>", "actor-name.xml"
        )
        self.assertNotIn("actor-name.xml", xml_text)


class SchemaToleranceTests(unittest.TestCase):
    def setUp(self):
        self.app = object.__new__(SOCApplication)

    def normalize(self, value):
        return self.app._normalize_uploaded_alert_shape(value, 1)

    def critical(self, value):
        root = value.get("_source", value)
        data = root.get("data") or {}
        fileinfo = data.get("fileinfo") or {}
        return {
            "src_ip": data.get("src_ip"), "dest_ip": data.get("dest_ip"),
            "domain": (data.get("http") or {}).get("hostname"),
            "sha256": fileinfo.get("sha256"),
            "mitre": (root.get("rule") or {}).get("mitre"),
        }

    def test_ecs_dotted_and_nested_shapes_are_equivalent(self):
        digest = "c" * 64
        dotted = self.normalize({
            "source.ip": "8.8.4.4", "destination.ip": "10.2.3.4",
            "url.domain": "unseen-schema.test", "file.hash.sha256": digest,
            "rule": {"description": "schema test", "mitre": {"id": "T1059.001"}},
        })
        nested = self.normalize({
            "source": {"ip": "8.8.4.4"}, "destination": {"ip": "10.2.3.4"},
            "url": {"domain": "unseen-schema.test"}, "file": {"hash": {"sha256": digest}},
            "rule": {"description": "schema test", "mitre": {"id": "T1059.001"}},
        })
        self.assertEqual(self.critical(dotted), self.critical(nested))

    def test_direct_and_embedded_suricata_are_equivalent(self):
        eve = {
            "event_type": "alert", "src_ip": "9.9.9.9", "dest_ip": "10.0.0.8",
            "alert": {"signature": "Fictional callback"},
            "http": {"hostname": "callback-unseen.test"},
        }
        direct = self.normalize(eve)
        embedded = self.normalize({"event": {"original": json.dumps(eve)}})
        self.assertEqual(self.critical(direct), self.critical(embedded))

    def test_affected_items_ndjson_and_idempotence(self):
        alert = {"rule": {"description": "wrapper test"}, "data": {"src_ip": "1.1.1.1"}}
        wrapped = self.app._parse_uploaded_alert_template(
            json.dumps({"data": {"affected_items": [alert]}}).encode(), "misleading-name.json"
        )
        ndjson = self.app._parse_uploaded_alert_template(
            (json.dumps(alert) + "\n").encode(), "different-name.ndjson"
        )
        self.assertEqual(self.critical(wrapped[0]), self.critical(ndjson[0]))
        self.assertEqual(wrapped[0], self.normalize(wrapped[0]))

    def test_unknown_fields_are_bounded_and_raw_is_preserved(self):
        source = {"rule": {"description": "unknown test"}}
        source.update({f"vendor_security_{index}": "x" * 2000 for index in range(80)})
        normalized = self.normalize(source)
        self.assertEqual(normalized["_raw_alert"]["vendor_security_0"], "x" * 2000)
        unknown = normalized["_unknown_security_fields"]
        self.assertLessEqual(len(unknown), 32)
        self.assertTrue(all(len(str(value)) <= 1024 for value in unknown.values()))

    def test_malformed_input_fails_with_analyst_readable_error(self):
        with self.assertRaisesRegex(ValueError, "Invalid JSON at line"):
            self.app._parse_uploaded_alert_template(b'{"rule":}\n', "alerts.ndjson")

    def test_provenance_field_names_are_not_promoted_to_iocs(self):
        normalized = self.normalize({
            "source.ip": "198.51.100.2", "destination.ip": "10.0.0.9",
            "url.domain": "canonical-only.test", "rule": {"description": "provenance test"},
        })
        cleaned = AlertAnalyzer().clean_log_data([normalized])[0]
        domains = (cleaned.get("observed_iocs") or {}).get("domains") or []
        self.assertIn("canonical-only.test", domains)
        self.assertNotIn("source.ip", domains)
        self.assertNotIn("rule.description", domains)


class PromptPolicyTests(unittest.TestCase):
    def test_prompt_has_no_fixed_actor_examples_and_marks_context_untrusted(self):
        prompt = (Path(__file__).parents[1] / "config" / "templates" / "cti.txt").read_text(
            encoding="utf-8"
        )
        for actor in ("APT29", "FIN7", "TA505", "G0016"):
            self.assertNotIn(actor, prompt)
        self.assertIn("untrusted quoted evidence", prompt)

    def test_deterministic_fallback_preserves_supported_unseen_actor_and_actions(self):
        formatter = object.__new__(EnhancedReportFormatter)
        formatter.alert_analyzer = AlertAnalyzer()
        alert = {
            "rule_level": 10, "rule_description": "fictional relay",
            "agent_name": "host-unseen", "proto": "tcp",
            "threat_context": {"actor": "Orchid-Unseen"},
            "ioc_context": {"domain": "supported-unseen.test"},
            "file_context": {"sha256": "d" * 64},
            "observed_iocs": {
                "domains": ["supported-unseen.test"], "hashes": ["d" * 64],
                "threat_actors": ["Orchid-Unseen"],
            },
            "threat_classification": {"threat_direction": "unknown"},
        }
        doc = {
            "source": "custom_document", "evidence_strength": "high",
            "cti_context_labels": ["attribution"],
            "current_ioc_overlap": {"domains": ["supported-unseen.test"]},
            "metadata": {
                "cti_artifacts": {
                    "domains": ["supported-unseen.test"],
                    "threat_actors": ["Orchid-Unseen"],
                },
                "cti_artifact_dispositions": {"domains": {"supported-unseen.test": "malicious"}},
            },
        }
        analysis = formatter.alert_analyzer.analyze_current_alerts([alert])
        report = formatter._build_deterministic_report([alert], analysis, [doc], "manual analysis", ["test"])
        self.assertIn("jointly support Orchid-Unseen", report)
        self.assertIn("host-unseen", report)
        self.assertIn("supported-unseen.test", report)
        self.assertIn("d" * 64, report)


if __name__ == "__main__":
    unittest.main()
