"""Deterministic evidence-discipline regression tests for manual alert analysis."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path


CONFIG_DIR = Path(__file__).resolve().parents[1] / "config"
if str(CONFIG_DIR) not in sys.path:
    sys.path.insert(0, str(CONFIG_DIR))

from report import AlertAnalyzer, CTIArtifactExtractor, RAGContextManager, ReportFormatter  # noqa: E402


class StructuredFieldPreservationTests(unittest.TestCase):
    def test_ics_windows_network_and_vulnerability_fields_survive_cleaning(self):
        analyzer = AlertAnalyzer()
        cleaned = analyzer.clean_log_data([{
            "timestamp": "2026-06-06T00:00:00Z",
            "rule": {"id": "900010", "level": 12, "description": "Structured evidence"},
            "agent": {"name": "ics-host-01", "ip": "192.168.56.20"},
            "data": {
                "src_ip": "192.168.56.20",
                "dest_ip": "192.168.56.30",
                "alert": {"signature": "Structured evidence", "signature_id": 900010},
                "ics": {"protocol": "s7comm", "operation": "write", "function_code": 5, "unit_id": 2},
                "windows": {"event_id": 4688, "computer": "ics-host-01", "user": "operator", "registry_key": r"HKLM\\Software\\Run"},
                "network": {"direction": "lateral", "service": "s7comm", "community_id": "1:test"},
                "vulnerability": {"cve": "CVE-2024-12345", "product": "Example PLC Suite", "version": "4.2"},
                "process": {"name": "plcctl.exe", "command_line": "plcctl.exe --write-db 1"},
                "fileinfo": {"filename": "plcctl.exe", "sha256": "a" * 64},
                "ioc": {"domain": "control.example.test", "hash": "a" * 64},
            },
        }])
        self.assertEqual(len(cleaned), 1)
        alert = cleaned[0]
        self.assertEqual(alert["ics_context"]["operation"], "write")
        self.assertEqual(alert["windows_context"]["event_id"], 4688)
        self.assertEqual(alert["network_context"]["service"], "s7comm")
        self.assertEqual(alert["vulnerability_context"]["cve"], "CVE-2024-12345")
        self.assertEqual(alert["process_context"]["name"], "plcctl.exe")
        self.assertEqual(alert["file_context"]["sha256"], "a" * 64)
        self.assertEqual(alert["ioc_context"]["domain"], "control.example.test")


class MitreExtractionTests(unittest.TestCase):
    def test_string_array_nested_parallel_and_subtechnique_shapes(self):
        merged = AlertAnalyzer._merge_mitre_values(
            "T1190",
            ["T1059.001", {"id": "T1105", "name": "Ingress Tool Transfer"}],
            {"ids": ["T1021.001"], "techniques": ["Remote Desktop Protocol"]},
        )
        self.assertEqual(merged["id"], ["T1190", "T1059.001", "T1105", "T1021.001"])
        self.assertIn("Ingress Tool Transfer", merged["technique"])
        self.assertIn("Remote Desktop Protocol", merged["technique"])

    def test_invalid_ids_are_not_preserved_as_explicit_techniques(self):
        merged = AlertAnalyzer._merge_mitre_values(
            {"id": ["T1190", "T9999", "not-a-technique"], "technique": ["Exploit Public-Facing Application"]}
        )
        self.assertEqual(merged["id"], ["T1190"])
        self.assertIn("T9999", merged["invalid_ids"])
        self.assertIn("not-a-technique", merged["invalid_ids"])
        self.assertTrue(merged["catalog_version"])

    def test_explicit_id_name_mismatch_is_recorded_without_replacing_id(self):
        merged = AlertAnalyzer._merge_mitre_values({
            "id": ["T1190"],
            "technique": ["PowerShell"],
        })
        self.assertEqual(merged["id"], ["T1190"])
        self.assertEqual(merged["name_mismatches"][0]["catalog_name"], "Exploit Public-Facing Application")

    def test_explicit_ids_remain_separate_from_inferred_and_historical(self):
        formatter = ReportFormatter.__new__(ReportFormatter)
        categories = formatter._mitre_evidence_categories(
            [{"mitre_context": {"id": ["T1059.001"]}, "behavior_tags": ["ingress_tool_transfer"]}],
            [{"metadata": {"cti_artifacts": {"mitre_techniques": ["T1105", "T1027"]}}}],
        )
        self.assertEqual(categories["explicit_current"], ["T1059.001"])
        self.assertIn("T1105", categories["inferred_current"])
        self.assertEqual(categories["historical_only"], ["T1027"])


class IndicatorAndBehaviorTests(unittest.TestCase):
    def test_generic_tls_without_corroboration_is_not_c2_or_domain_behavior(self):
        analyzer = AlertAnalyzer()
        tags = analyzer._infer_behavior_tags({
            "rule_description": "Generic connection allowed",
            "alert_signature": "Generic connection allowed",
            "app_proto": "tls",
            "proto": "TCP",
            "direction": "outbound",
            "threat_classification": {"threat_direction": "outbound"},
        })
        self.assertNotIn("possible_c2", tags)
        self.assertNotIn("domain_or_tls_indicator", tags)
        self.assertNotIn("compromised_asset_egress", tags)

    def test_defanged_iocs_and_boundaries(self):
        manager = RAGContextManager.__new__(RAGContextManager)
        self.assertEqual(manager._refang_text("hxxps://evil[.]example/path"), "https://evil.example/path")
        self.assertTrue(manager._contains_exact_term("Connect to evil.example now", "evil[.]example", "domain"))
        self.assertTrue(manager._contains_exact_term("Observed 45.77.1.2.", "45.77.1.2", "ip"))
        self.assertFalse(manager._contains_exact_term("Connect to notevil.example now", "evil[.]example", "domain"))
        self.assertFalse(manager._contains_exact_term("198.51.100.100", "198.51.100.10", "ip"))
        self.assertFalse(manager._contains_exact_term("45.77.1.2.3", "45.77.1.2", "ip"))

    def test_non_global_ip_classes_are_not_cti_indicators(self):
        for value in (
            "10.0.0.1", "127.0.0.1", "169.254.10.1", "224.0.0.1",
            "192.0.2.10", "198.51.100.10", "203.0.113.10",
        ):
            self.assertFalse(CTIArtifactExtractor.is_public_ip(value), value)

    def test_victim_ip_is_not_promoted_as_attacker_cti(self):
        selected = ReportFormatter._attacker_relevant_cti_ips({
            "src_ip": "45.33.32.156",
            "dest_ip": "1.1.1.1",
            "src_ip_context": "external",
            "dest_ip_context": "owned",
            "threat_classification": {"threat_direction": "inbound"},
            "ioc_context": {"ip": "1.1.1.1", "ip_role": "victim"},
        })
        self.assertIn("45.33.32.156", selected)
        self.assertNotIn("1.1.1.1", selected)

    def test_retrieval_diversity_caps_chunks_per_canonical_document(self):
        manager = RAGContextManager.__new__(RAGContextManager)
        results = [
            {"id": 1, "source": "custom_document", "metadata": {"raw_document_hash": "doc-a"}},
            {"id": 2, "source": "custom_document", "metadata": {"raw_document_hash": "doc-a"}},
            {"id": 3, "source": "custom_document", "metadata": {"raw_document_hash": "doc-a"}},
            {"id": 4, "source": "custom_document", "metadata": {"raw_document_hash": "doc-b"}},
        ]
        selected = manager._apply_source_diversity(results, limit=3)
        self.assertEqual([item["id"] for item in selected], [1, 2, 4])

    def test_canonical_exact_selection_keeps_the_strongest_validated_chunk(self):
        candidates = [
            {
                "id": 100,
                "source": "custom_document",
                "score": 1.0,
                "match_evidence": ["indicator matched metadata"],
                "metadata": {"raw_document_hash": "doc-a"},
            },
            {
                "id": 1,
                "source": "custom_document",
                "score": 1.4,
                "match_evidence": ["domain matched content"],
                "metadata": {"raw_document_hash": "doc-a"},
            },
            {
                "id": 2,
                "source": "custom_document",
                "score": 1.2,
                "match_evidence": ["hash matched content"],
                "metadata": {"raw_document_hash": "doc-b"},
            },
        ]
        selected = RAGContextManager._best_exact_candidate_per_canonical_document(candidates, limit=2)
        self.assertEqual([item["id"] for item in selected], [1, 2])

    def test_generic_filename_alone_is_not_distinctive_exact_evidence(self):
        formatter = ReportFormatter.__new__(ReportFormatter)
        self.assertTrue(formatter._is_low_signal_cti_exact_value("keywords", "Backdoor.PDF"))
        self.assertTrue(formatter._is_low_signal_cti_exact_value(
            "keywords", r"C:\Users\victim\AppData\Local\malware_payload_2.exe"
        ))
        self.assertFalse(formatter._is_low_signal_cti_exact_value("keywords", "mses.exe"))


class ContextAndFinalizationTests(unittest.TestCase):
    def setUp(self):
        self.formatter = ReportFormatter.__new__(ReportFormatter)
        self.formatter.alert_analyzer = AlertAnalyzer()

    def current_alert(self):
        return {
            "rule_level": 12,
            "rule_description": "Observed PowerShell command",
            "alert_signature": "Observed PowerShell command",
            "agent_name": "host-01",
            "src_ip": "192.168.56.20",
            "src_ip_context": "internal",
            "process_context": {"name": "powershell.exe", "command_line": "powershell.exe -File observed.ps1"},
            "file_context": {"filename": "observed.ps1"},
            "mitre_context": {"id": ["T1059.001"], "catalog_version": "fixture"},
            "behavior_tags": ["script_execution_candidate"],
            "response_focus": ["Investigate source asset 192.168.56.20 as potentially compromised."],
            "threat_classification": {"threat_direction": "unknown"},
            "observed_iocs": {"processes": ["powershell.exe", "observed.ps1"], "mitre_techniques": ["T1059.001"]},
        }

    def test_context_selection_never_repeats_a_canonical_article(self):
        docs = [
            {"id": 1, "source": "custom_document", "metadata": {"source_document": "one.pdf", "chunk_index": 1}},
            {"id": 2, "source": "custom_document", "metadata": {"source_document": "one.pdf", "chunk_index": 2}},
        ]
        selected = self.formatter._apply_context_source_document_diversity(docs, limit=5)
        self.assertEqual(len(selected), 1)

    def test_strong_exact_current_evidence_outranks_weak_semantic_similarity(self):
        self.formatter.rag_manager = RAGContextManager.__new__(RAGContextManager)
        alert = self.current_alert()
        exact_doc = {
            "id": 1,
            "content": "The observed.ps1 PowerShell payload was executed.",
            "source": "custom_document",
            "score": 0.10,
            "match_types": ["exact"],
            "match_evidence": ["exact filename: observed.ps1"],
            "metadata": {"raw_document_hash": "exact-doc", "source_document": "exact.pdf"},
        }
        semantic_doc = {
            "id": 2,
            "content": "Generic malware activity with no matching current artifact.",
            "source": "custom_document",
            "score": 0.99,
            "match_types": ["semantic"],
            "metadata": {"raw_document_hash": "semantic-doc", "source_document": "semantic.pdf"},
        }
        selected = self.formatter._select_relevant_context_docs(
            [semantic_doc, exact_doc], [alert], max_docs=2
        )
        self.assertEqual(selected[0]["id"], 1)

    def test_actor_name_in_document_title_alone_does_not_support_attribution(self):
        alert = self.current_alert()
        doc = {
            "content": "Background report",
            "source": "custom_document",
            "evidence_strength": "high",
            "cti_context_labels": ["attribution"],
            "metadata": {
                "source_document": "APT29-campaign.pdf",
                "cti_artifacts": {"threat_actors": ["APT29"]},
            },
        }
        findings = self.formatter._audit_report_claims(
            "APT29 is responsible for the current incident.", [doc], [alert]
        )
        self.assertTrue(any("Attribution language" in finding for finding in findings), findings)

    def test_low_strength_historical_ioc_cannot_be_stated_as_current(self):
        alert = self.current_alert()
        doc = {
            "content": "Historical infrastructure 45.77.1.2",
            "source": "custom_document",
            "evidence_strength": "low",
            "historical_only_artifacts": {"ips": ["45.77.1.2"]},
            "metadata": {"source_document": "history.pdf"},
        }
        findings = self.formatter._audit_report_claims(
            "The current alert observed 45.77.1.2.", [doc], [alert]
        )
        self.assertTrue(any("low-strength historical context" in finding for finding in findings), findings)

    def test_supported_current_host_and_process_actions_pass_target_audit(self):
        alert = self.current_alert()
        report = """**Executive Summary:** Current evidence reviewed; actor attribution is not confirmed.

**Key Findings:**
- Current host host-01 executed powershell.exe.
- Explicit current technique T1059.001 was preserved.

**Immediate Actions:**
1. Isolate host-01 while investigating powershell.exe.
2. Hunt for observed.ps1 on host-01 and preserve the command line.

**Analysis Complete**
"""
        findings = self.formatter._audit_report_claims(report, [], [alert])
        self.assertFalse(any("Remediation" in finding or "unobserved host" in finding.lower() for finding in findings), findings)

    def test_unsupported_actor_mitre_and_remediation_are_quarantined(self):
        alert = self.current_alert()
        analysis = self.formatter.alert_analyzer.analyze_current_alerts([alert])
        raw = """**Executive Summary:** FIN6 compromised unobserved-host.

**Key Findings:**
- FIN6 is responsible.
- T9999 was observed.
- Historical evidence is current.
- Block 8.8.8.8 immediately.

**Immediate Actions:**
1. Isolate unobserved-host.
2. Block 8.8.8.8.

**Analysis Complete**
"""
        final, appendix = self.formatter._finalize_report_with_audit(
            raw, [], [alert], analysis, "test report"
        )
        self.assertNotIn("FIN6", final)
        self.assertNotIn("T9999", final)
        self.assertNotIn("8.8.8.8", final)
        self.assertIn("T1059.001", final)
        self.assertTrue("deterministic repair" in appendix.lower() or "analyst review required" in appendix.lower())

    def test_historical_mitre_can_remain_only_when_explicitly_labelled(self):
        alert = self.current_alert()
        doc = {
            "content": "Historical technique T1027",
            "source": "custom_document",
            "evidence_strength": "high",
            "metadata": {"cti_artifacts": {"mitre_techniques": ["T1027"]}},
        }
        report = """**Executive Summary:** Current evidence reviewed.

**Key Findings:**
- Current alert technique T1059.001 is explicit.
- Historical CTI context only: T1027 was not observed in this incident.
- No actor attribution was made.
- Remediation uses current facts only.

**Immediate Actions:**
1. Investigate host-01.
2. Review powershell.exe on host-01.

**Analysis Complete**
"""
        findings = self.formatter._audit_report_claims(report, [doc], [alert])
        self.assertFalse(any("T1027" in finding for finding in findings), findings)

    def test_observed_documentation_ip_is_never_a_block_target(self):
        alert = self.current_alert()
        alert["dest_ip"] = "203.0.113.25"
        alert["observed_iocs"]["ips"] = ["203.0.113.25"]
        report = """**Executive Summary:** Current alert reviewed.

**Key Findings:**
- Current host is host-01.
- No actor attribution was made.
- Current process is powershell.exe.
- Documentation address was observed.

**Immediate Actions:**
1. Block 203.0.113.25 at the firewall.
2. Investigate host-01.

**Analysis Complete**
"""
        findings = self.formatter._audit_report_claims(report, [], [alert])
        self.assertTrue(any("non_global_or_low_signal" in finding for finding in findings), findings)

    def test_unobserved_host_and_unsupported_patch_target_are_rejected(self):
        alert = self.current_alert()
        report = """**Executive Summary:** Review complete.

**Key Findings:**
- No actor attribution.
- Current process observed.
- No vulnerability field was present.
- Current host is host-01.

**Immediate Actions:**
1. Isolate host-99.
2. Patch CVE-2025-99999 on Example Product.

**Analysis Complete**
"""
        findings = self.formatter._audit_report_claims(report, [], [alert])
        self.assertTrue(any("unobserved host" in finding.lower() for finding in findings), findings)
        self.assertTrue(any("unsupported CVE" in finding for finding in findings), findings)


class EvaluationIsolationTests(unittest.TestCase):
    def test_production_modules_do_not_reference_gold_manifest(self):
        for filename in ("main.py", "report.py", "cti_artifacts.py", "llm_client.py", "config.py"):
            text = (CONFIG_DIR / filename).read_text(encoding="utf-8-sig")
            self.assertNotIn("gold_manifest", text, filename)
            self.assertNotRegex(text, r"(?m)^\s*(?:from|import)\s+evaluation\b", filename)


if __name__ == "__main__":
    unittest.main()
