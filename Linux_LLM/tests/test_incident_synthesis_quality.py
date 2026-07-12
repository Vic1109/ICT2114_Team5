import sys
import unittest
from pathlib import Path

CONFIG_DIR = Path(__file__).resolve().parents[1] / "config"
if str(CONFIG_DIR) not in sys.path:
    sys.path.insert(0, str(CONFIG_DIR))

from report import AlertAnalyzer, ReportFormatter  # noqa: E402
from report_parser import ReportParser  # noqa: E402
from llm_client import LlamaModelClient  # noqa: E402


class IncidentSynthesisTests(unittest.TestCase):
    def setUp(self):
        self.formatter = ReportFormatter.__new__(ReportFormatter)
        self.formatter.alert_analyzer = AlertAnalyzer()
        self.formatter._active_trace = None

    def tearDown(self):
        self.formatter.alert_analyzer.close()

    @staticmethod
    def alert():
        return {
            "timestamp": "2026-06-06T08:07:00Z",
            "rule_level": 12,
            "rule_id": "100080",
            "rule_description": "Suspicious payload download over HTTP",
            "alert_signature": "Suspicious payload download over HTTP",
            "agent_name": "asset-01",
            "agent_ip": "10.10.10.10",
            "src_ip": "198.51.100.57",
            "dest_ip": "10.10.10.10",
            "direction": "inbound",
            "alert_action": "allowed",
            "http_context": {"hostname": "example.invalid", "url": "/sample.bin", "method": "GET", "status": 200},
            "file_context": {"filename": "sample.bin"},
            "observed_iocs": {"domains": ["example.invalid"], "files": ["sample.bin"]},
            "behavior_tags": ["ingress_tool_transfer"],
            "threat_classification": {"threat_direction": "unknown"},
        }

    def test_synthesis_preserves_direction_and_separates_ip_actionability(self):
        synthesis = self.formatter._build_incident_synthesis([self.alert()], [], [])
        self.assertEqual(synthesis["network_direction"], ["inbound"])
        self.assertIn("separate judgments", synthesis["ip_actionability"]["note"])
        outcome = synthesis["action_and_response_outcome"][0]
        self.assertIn("allowed", outcome)
        self.assertIn("not payload execution", outcome)
        self.assertIn("Insufficient evidence", synthesis["actor_attribution"]["abstention"])

    def test_expansion_reads_only_the_already_selected_top_document(self):
        calls = []

        class Rag:
            def get_selected_document_passages(self, selected_doc, preferred_terms, limit):
                calls.append((selected_doc, preferred_terms, limit))
                return [{"content": "complementary", "source": "custom_document", "metadata": {}}]

        self.formatter.rag_manager = Rag()
        ranked = [
            {"id": 7, "source": "custom_document", "metadata": {"raw_document_hash": "top"}},
            {"id": 8, "source": "custom_document", "metadata": {"raw_document_hash": "second"}},
        ]
        before = [item["id"] for item in ranked]
        passages = self.formatter._expand_selected_document_evidence(ranked, [self.alert()])
        self.assertEqual([item["id"] for item in ranked], before)
        self.assertEqual(calls[0][0]["id"], 7)
        self.assertEqual(len(passages), 1)

    def test_single_repairable_claim_preserves_model_analysis(self):
        report = """**Executive Summary:**

Unique incident narrative that must survive targeted repair. APT-Z was attributed to this incident.

**Key Findings:**
- Current payload transfer was allowed.
- Execution remains unconfirmed.
- The affected asset requires endpoint review.
- Historical CTI is contextual.

**Immediate Actions:**
1. Review asset-01 telemetry.
2. Hash sample.bin.

**Analysis Complete**
"""
        classified = [{"severity": "REPAIRABLE", "claim_type": "actor_attribution", "message": "unsupported"}]
        repaired, applied = self.formatter._apply_targeted_audit_repairs(report, classified)
        self.assertIn("Unique incident narrative", repaired)
        self.assertIn("remains unconfirmed", repaired)
        self.assertEqual(applied[0]["claim_type"], "actor_attribution")

    def test_direction_outcome_and_non_global_ip_contradictions_are_repaired(self):
        report = """**Executive Summary:**

An outbound request from the internal host was blocked. HTTP 200 confirmed a successful download.

**Key Findings:**
- 198.51.100.57 is an external IP in United States malicious infrastructure.
- RAG context references a "RATED CRITICAL" threat actor.
- T1105 indicates transfer to a compromised system.
- Execution remains unconfirmed.
- Endpoint validation is required.
- Attribution is insufficient.

**Immediate Actions:**
1. Review asset-01 telemetry.
2. Add 198.51.100.57 to the blocklist.

**Analysis Complete**
Threat actor infrastructure: 198.51.100.57 (external)
Threats requiring immediate blocking: 1
"""
        findings = self.formatter._audit_report_claims(report, [], [self.alert()])
        classified = self.formatter._classify_audit_findings(findings)
        types = {item["claim_type"] for item in classified}
        self.assertTrue({"incident_direction", "network_outcome", "ip_actionability", "actor_attribution", "response_action", "incident_impact"}.issubset(types), classified)
        repaired, _ = self.formatter._apply_targeted_audit_repairs(report, classified, [self.alert()])
        self.assertIn("explicitly records inbound direction", repaired)
        self.assertIn("transaction was allowed", repaired)
        self.assertNotIn("successful download", repaired.lower())
        self.assertNotIn("United States", repaired)
        self.assertNotIn("RATED CRITICAL", repaired)
        self.assertNotIn("blocklist", repaired.lower())
        self.assertIn("**Key Findings:**", repaired)
        self.assertIn("potentially affected system", repaired)
        self.assertIn("Threats requiring actionability validation", repaired)
        self.assertNotIn("Threat actor infrastructure", repaired)


class RichReportRoundTripTests(unittest.TestCase):
    def test_rich_sections_citations_tables_and_action_count_survive(self):
        markdown = """# SOC Report

## Executive Summary

An inbound transfer reached asset-01; execution remains unconfirmed.

## Key Findings

- Current evidence supports delivery [ALERT-1].

## Incident Assessment

| Time | Event | Confidence |
|------|-------|------------|
| 08:07 | HTTP response [ALERT-1] | High |

## Attribution Assessment

Family association is contextual [RAG-1]; actor attribution is insufficient.

## MITRE ATT&CK — Historical CTI Context Only (Not Observed)

| ID | Evidence class |
|----|----------------|
| T1105 | Historical only [RAG-1] |

## Prioritized Response Plan

- P1: Review asset-01.
- P2: Hunt the observed domain.

## Immediate Actions Required

1. Preserve asset-01 telemetry.
2. Hash the observed file.

---

**Analysis Complete**
Priority actions: 99 identified
"""
        parsed = ReportParser.parse_report(markdown)
        self.assertEqual(parsed["recommendations"], [
            "Preserve asset-01 telemetry.", "Hash the observed file."
        ])
        self.assertEqual(parsed["metadata"]["priority_actions"], 2)
        rich = parsed["preserved_rich_sections_markdown"]
        self.assertIn("Incident Assessment", rich)
        self.assertIn("[RAG-1]", rich)
        serialized = ReportParser.serialize_to_markdown(parsed)
        self.assertIn("| 08:07 | HTTP response [ALERT-1] | High |", serialized)
        self.assertIn("Family association is contextual [RAG-1]", serialized)
        self.assertIn("Priority actions: 2 identified", serialized)

    def test_prompt_compaction_retains_incident_synthesis_and_current_evidence(self):
        prompt = """ANALYSIS TYPE: MANUAL
CURRENT ALERTS DATA:
summary
CURRENT ALERT — AUTHORITATIVE OBSERVATIONS:
authoritative-inbound-allowed
CURRENT ALERT — EXPLICIT / INFERRED MITRE EVIDENCE:
explicit-none
CANONICAL INCIDENT SYNTHESIS — ORGANIZE THE REPORT AROUND THIS OBJECT:
synthesis-direction-inbound outcome-allowed execution-unconfirmed
RETRIEVED HISTORICAL CTI — SOURCE-BOUND EXCERPTS:
""" + ("historical filler " * 4000) + """
COMPLEMENTARY PASSAGES FROM THE ALREADY-SELECTED TOP DOCUMENT:
selected-document-only
OUTPUT CONTRACT:
write incident assessment
"""
        compacted = LlamaModelClient._section_aware_compact(prompt, 12000)
        self.assertIn("authoritative-inbound-allowed", compacted)
        self.assertIn("synthesis-direction-inbound", compacted)
        self.assertIn("write incident assessment", compacted)


if __name__ == "__main__":
    unittest.main()
