#!/usr/bin/env python3
"""Generic evidence-fidelity regressions.

These fixtures are synthetic. They check that direction, ports, repeated
events, distinct indicators, process parentage, and reference portals survive
normalisation and are not contradicted in the report audit.
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

CONFIG_DIR = Path(__file__).resolve().parents[1] / "config"
if str(CONFIG_DIR) not in sys.path:
    sys.path.insert(0, str(CONFIG_DIR))

from cti_artifacts import CTIArtifactExtractor  # noqa: E402
from report import AlertAnalyzer, ReportFormatter  # noqa: E402
from report_parser import ReportParser  # noqa: E402


def _wazuh(description, data, level=10, rule_id="900001", timestamp="2026-09-27T13:00:00Z"):
    return {
        "timestamp": timestamp,
        "rule": {"level": level, "id": rule_id, "description": description},
        "agent": {"name": "workstation-a", "ip": "10.8.8.8"},
        "data": data,
    }


class EvidenceFidelityTests(unittest.TestCase):
    def setUp(self):
        self.analyzer = AlertAnalyzer()
        self.formatter = ReportFormatter.__new__(ReportFormatter)
        self.formatter.alert_analyzer = self.analyzer
        self.formatter._active_trace = None

    def tearDown(self):
        self.analyzer.close()

    def _cleaned(self):
        raw = [
            _wazuh(
                "ET MALWARE HTTP C2",
                {
                    "src_ip": "10.8.8.8",
                    "src_port": 51498,
                    "dest_ip": "93.184.216.34",
                    "dest_port": 443,
                    "proto": "TCP",
                    "app_proto": "http",
                    "alert": {"signature": "ET MALWARE C2", "signature_id": 2026001, "action": "allowed"},
                    "http": {
                        "hostname": "updates.example",
                        "http_method": "POST",
                        "url": "/search/abc",
                        "status": 200,
                        "length": 128,
                    },
                    "flow": {"bytes_toserver": 128, "bytes_toclient": 40},
                },
                timestamp="2026-09-27T13:01:00Z",
                rule_id="1",
            ),
            _wazuh(
                "ET MALWARE HTTP C2",
                {
                    "src_ip": "10.8.8.8",
                    "src_port": 51510,
                    "dest_ip": "93.184.216.34",
                    "dest_port": 443,
                    "proto": "TCP",
                    "app_proto": "http",
                    "alert": {"signature": "ET MALWARE C2", "signature_id": 2026001, "action": "allowed"},
                    "http": {"hostname": "updates.example", "http_method": "GET", "url": "/search/abc", "status": 200},
                },
                timestamp="2026-09-27T13:06:00Z",
                rule_id="1",
            ),
            _wazuh(
                "DNS query",
                {
                    "src_ip": "10.8.8.8",
                    "dest_ip": "10.8.8.1",
                    "dest_port": 53,
                    "proto": "UDP",
                    "app_proto": "dns",
                    "dns": {"query": [{"rrname": "alpha.callback.example", "rrtype": "A"}]},
                },
                timestamp="2026-09-27T13:02:00Z",
                rule_id="2",
            ),
            _wazuh(
                "DNS query",
                {
                    "src_ip": "10.8.8.8",
                    "dest_ip": "10.8.8.1",
                    "dest_port": 53,
                    "dns": {"query": [{"rrname": "beta.callback.example", "rrtype": "A"}]},
                },
                timestamp="2026-09-27T13:03:00Z",
                rule_id="2",
            ),
            _wazuh(
                "Process created",
                {
                    "event_type": "process",
                    "process": {
                        "name": "helper.exe",
                        "parent_process": "scheduler.exe",
                        "path": "C:\\Windows\\helper.exe",
                        "command_line": "helper.exe --run",
                    },
                },
                timestamp="2026-09-27T13:04:00Z",
                rule_id="3",
            ),
            _wazuh(
                "File added",
                {
                    "fileinfo": {
                        "filename": "helper.exe",
                        "path": "C:\\Windows\\helper.exe",
                        "size": 4096,
                        "md5": "0123456789abcdef0123456789abcdef",
                        "sha256": "a" * 64,
                    },
                    "http": {"url": "https://www.virustotal.com/gui/file/" + ("a" * 64)},
                },
                timestamp="2026-09-27T13:05:00Z",
                rule_id="4",
            ),
            _wazuh(
                "ET SCAN inbound probe",
                {
                    "src_ip": "93.184.216.10",
                    "src_port": 4444,
                    "dest_ip": "10.8.8.8",
                    "dest_port": 80,
                    "proto": "TCP",
                    "direction": "inbound",
                    "alert": {"signature": "ET SCAN", "signature_id": 2026002, "action": "allowed"},
                },
                timestamp="2026-09-27T12:00:00Z",
                rule_id="5",
            ),
        ]
        return self.analyzer.clean_log_data(raw)

    def test_normalisation_keeps_direction_ports_and_file_evidence(self):
        cleaned = self._cleaned()
        outbound = next(alert for alert in cleaned if alert.get("signature_id") in (2026001, "2026001"))
        self.assertEqual(outbound["src_ip_context"], "internal")
        self.assertEqual(outbound["dest_ip_context"], "external")
        self.assertEqual(outbound["threat_classification"]["threat_direction"], "outbound")
        self.assertEqual(str(outbound["dest_port"]), "443")
        self.assertEqual(str(outbound["src_port"]), "51498")
        self.assertEqual(outbound["http_context"]["status"], 200)
        self.assertEqual(outbound["flow_context"]["bytes_toserver"], 128)
        created = next(alert for alert in cleaned if (alert.get("process_context") or {}).get("name") == "helper.exe")
        self.assertEqual(created["process_context"]["parent_process"], "scheduler.exe")
        filed = next(alert for alert in cleaned if (alert.get("file_context") or {}).get("md5"))
        self.assertEqual(filed["file_context"]["size"], 4096)
        self.assertEqual(len(filed["file_context"]["sha256"]), 64)

    def test_ledger_preserves_repeats_and_distinct_names(self):
        cleaned = self._cleaned()
        ledger = self.formatter._flow_ledger(cleaned)
        self.assertIn("13:01:00Z", ledger)
        self.assertIn("13:06:00Z", ledger)
        self.assertIn("alpha.callback.example", ledger)
        self.assertIn("beta.callback.example", ledger)
        self.assertIn("service_port=443", ledger)
        self.assertIn("client_port=51498", ledger)
        self.assertIn("dir=outbound", ledger)
        self.assertIn("dir=inbound", ledger)
        self.assertIn("parent_process:scheduler.exe", ledger)
        self.assertIn("0123456789abcdef0123456789abcdef", ledger)
        self.assertNotIn("www.virustotal.com", self.formatter._contacted_domains(cleaned))

    def test_repeated_same_flow_is_not_collapsed_before_the_cap(self):
        cleaned = self._cleaned()
        shown = self.formatter._create_current_alert_context(cleaned, max_alerts=20)
        self.assertIn("13:01:00Z", shown)
        self.assertIn("13:06:00Z", shown)

    def test_bad_report_is_audited_and_repaired(self):
        cleaned = [alert for alert in self._cleaned() if alert.get("rule_id") != "5"]
        report = """**Executive Summary:**

Confirmed: malicious file execution. The execution status of the payload remains unconfirmed.
Exfiltration indicators: Present - HTTP POST.

**Key Findings:**
- 10.8.8.8 is External and the C2 flow is Inbound.
- Hunt DNS for www.virustotal.com.
- Endpoint validation is required.
- Attribution is insufficient.

**Immediate Actions:**
1. Review workstation-a.
2. Hunt www.virustotal.com.

**Analysis Complete**
"""
        findings = self.formatter._audit_report_claims(report, [], cleaned)
        text = " ".join(findings)
        self.assertIn("non-public address", text)
        self.assertIn("outbound", text.lower())
        self.assertIn("Execution claim contradicts", text)
        self.assertIn("exfiltration", text.lower())
        self.assertIn("www.virustotal.com", text)
        classified = self.formatter._classify_audit_findings(findings)
        repaired, _applied = self.formatter._apply_targeted_audit_repairs(report, classified, cleaned)
        self.assertNotIn("www.virustotal.com", repaired)
        self.assertNotIn("Exfiltration indicators: Present", repaired)
        self.assertIn("process creation was observed", repaired.lower())

    def test_schema_paths_are_not_domains(self):
        for token in ("http.url", "win.eventdata.image", "win.eventdata.parentimage"):
            self.assertTrue(CTIArtifactExtractor._is_false_domain(token), token)
        extracted = CTIArtifactExtractor.extract(
            "data.http.url data.win.eventdata.image data.win.eventdata.parentImage mail.example.com"
        )
        domains = [item.lower() for item in extracted.get("domains") or []]
        self.assertIn("mail.example.com", domains)
        self.assertNotIn("http.url", domains)
        self.assertFalse(any("eventdata" in item for item in domains))

    def test_missing_key_findings_are_restored_when_other_sections_exist(self):
        markdown = """# Security Operations Center - Threat Analysis Report
**Threat Level:** HIGH | **Total Alerts:** 15

## Executive Summary

Outbound connections from workstation-a were observed.

## Top Priority Threats

| IP Address | Type | Country | Direction | Activity | Severity | Confidence | Count |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 93.184.216.34 | External | Unknown | Outbound | HTTP C2 | HIGH | High | 1 |

## Incident Assessment

The asset initiated the connection. Execution of a child process was observed.

## Immediate Actions Required

1. Preserve telemetry for workstation-a.

**Analysis Complete**
"""
        parsed = ReportParser.parse_report(markdown)
        self.assertTrue(parsed["key_findings"])
        serialized = ReportParser.serialize_to_markdown(parsed)
        self.assertIn("## Key Findings", serialized)
        self.assertGreaterEqual(serialized.lower().count("key findings"), 1)

    def test_to_server_from_a_workstation_is_outbound_and_counted_once_per_alert(self):
        raw = []
        for index, host in enumerate(("asset-a", "asset-a", "asset-b")):
            raw.append(_wazuh(
                "ET MALWARE download",
                {
                    "src_ip": "10.20.30.41",
                    "dest_ip": "93.184.216.34",
                    "src_port": 50000 + index,
                    "dest_port": 80,
                    "direction": "to_server",
                    "http": {"hostname": "files.example", "url": "/payload.doc", "status": 200, "length": 84213},
                    "alert": {"action": "allowed", "signature": "ET MALWARE download", "signature_id": 42},
                },
                timestamp=f"2018-10-16T08:0{index}:00Z",
                rule_id=str(index),
            ))
            raw[-1]["agent"] = {"name": host, "ip": "10.20.30.41"}
        cleaned = self.analyzer.clean_log_data(raw)
        self.assertTrue(all(self.formatter._classified_direction(alert) == "outbound" for alert in cleaned))
        counts = {row["indicator"]: row["count"] for row in self.formatter._indicator_counts(cleaned)}
        self.assertEqual(counts["93.184.216.34"], 3)
        stamped = self.formatter._stamp_authoritative_evidence(
            "| 93.184.216.34 | External | Unknown | Inbound | download | HIGH | High | 5 |\n\n**Analysis Complete**",
            cleaned,
        )
        self.assertIn("| Outbound |", stamped)
        self.assertIn("| 3 |", stamped)
        self.assertIn("Application-Established Evidence", stamped)

    def test_separate_dates_and_hosts_stay_separate_clusters(self):
        alerts = self.analyzer.clean_log_data([
            _wazuh("first", {"src_ip": "10.1.1.1", "dest_ip": "93.184.216.34", "direction": "to_server"}, timestamp="2018-10-16T08:00:00Z"),
            _wazuh("later", {"src_ip": "10.2.2.2", "dest_ip": "93.184.216.34", "direction": "to_server", "http": {"hostname": "files.example"}}, timestamp="2019-02-21T08:00:00Z"),
        ])
        alerts[0]["agent_name"] = "host-a"
        alerts[1]["agent_name"] = "host-b"
        clusters = self.formatter._activity_clusters(alerts)
        self.assertEqual(len(clusters), 2)
        notes = self.formatter._infrastructure_recurrence(alerts)
        self.assertTrue(any("93.184.216.34" in note and "not by itself proof" in note for note in notes))

    def test_explicit_subtechnique_is_not_only_inferred(self):
        alert = {
            "behavior_tags": ["possible_c2"],
            "mitre_context": {"id": ["T1071.004", "T1573.001"]},
            "process_context": {"name": "cscript.exe", "parent_process": "cmstp.exe", "command_line": "cscript.exe //E:jscript C:\\Temp\\3521.txt"},
        }
        categories = self.formatter._mitre_evidence_categories([alert], [])
        self.assertIn("T1071.004", categories["explicit_current"])
        self.assertIn("T1573.001", categories["explicit_current"])
        self.assertNotIn("T1071", categories["inferred_current"])
        self.assertIn("cmstp.exe -> cscript.exe", " ".join(self.formatter._process_chain_lines([alert])))
        self.assertIn("execution", self.formatter._observed_stage([alert]))

    def test_generated_report_ranks_below_original_cti(self):
        class Rag:
            max_retrieval_docs = 5
            def _contains_exact_term(self, haystack, term):
                return term in haystack
            def _score_exact_candidate(self, evidence, source):
                return 1.0
            def _is_high_signal_search_value(self, token):
                return True
        self.formatter.rag_manager = Rag()
        original = {"source": "custom_document", "content": "93.184.216.34 malware", "score": 1.0, "match_types": ["exact"], "match_evidence": ["ip"], "metadata": {"original_filename": "vendor-report.pdf"}}
        generated = {"source": "custom_document", "content": "93.184.216.34 malware", "score": 1.0, "match_types": ["exact"], "match_evidence": ["ip"], "metadata": {"original_filename": "APPROVED_Threat_analysis_old.md", "human_validated": True}}
        selected = self.formatter._select_relevant_context_docs([generated, original], [{"src_ip": "10.1.1.1", "dest_ip": "93.184.216.34"}])
        self.assertEqual(selected[0]["metadata"]["original_filename"], "vendor-report.pdf")

    def test_hash_miss_does_not_imply_benign(self):
        alert = {"file_context": {"sha256": "d" * 64}, "observed_iocs": {"hashes": ["d" * 64]}}
        findings = self.formatter._audit_report_claims("**Executive Summary:**\n\nA long enough narrative for the validator to ignore this advisory path.\n", [], [alert])
        self.assertTrue(any("does not mean the file is benign" in item for item in findings), findings)

    def test_inbound_alert_is_not_relabelled_outbound(self):
        inbound = self.analyzer.clean_log_data([
            _wazuh(
                "ET SCAN inbound probe",
                {
                    "src_ip": "93.184.216.10",
                    "dest_ip": "10.8.8.8",
                    "dest_port": 80,
                    "src_port": 4444,
                    "direction": "inbound",
                    "alert": {"action": "allowed", "signature": "ET SCAN", "signature_id": 9},
                },
            )
        ])[0]
        self.assertEqual(inbound["threat_classification"]["threat_direction"], "inbound")
        synthesis = self.formatter._build_incident_synthesis([inbound], [], [])
        self.assertEqual(synthesis["network_direction"], ["inbound"])


class AllAlertsPipelineTests(unittest.TestCase):
    """Run every saved alert through normalisation and the evidence stamp. No model calls."""

    def test_every_saved_alert_keeps_a_defensible_direction(self):
        folder = Path.home() / "Desktop" / "AllAlerts"
        files = sorted(folder.glob("*.json"))
        self.assertGreaterEqual(len(files), 10, "AllAlerts fixtures are not available")
        analyzer = AlertAnalyzer()
        formatter = ReportFormatter.__new__(ReportFormatter)
        formatter.alert_analyzer = analyzer
        formatter._active_trace = None
        try:
            for path in files:
                payload = json.loads(path.read_text(encoding="utf-8"))
                records = payload.get("alerts") if isinstance(payload, dict) else payload
                cleaned = analyzer.clean_log_data(records if isinstance(records, list) else [payload])
                for alert in cleaned:
                    direction = formatter._classified_direction(alert)
                    self.assertIn(direction, {"inbound", "outbound", "lateral", "external", "infrastructure", "unknown"})
                    raw = str(alert.get("direction") or "").lower()
                    if raw == "to_server" and alert.get("src_ip_context") in {"internal", "owned", "non_global"} and alert.get("dest_ip_context") == "external":
                        self.assertEqual(direction, "outbound", path.name)
                if cleaned:
                    stamped = formatter._stamp_authoritative_evidence("**Analysis Complete**", cleaned)
                    self.assertIn("Analysis Complete", stamped)
        finally:
            analyzer.close()


class EndpointTelemetryGuardTests(unittest.TestCase):
    """Endpoint-only alerts must not become an inbound attacker story."""

    def _alert(self, host, ip, rule_id, mitre, data, timestamp):
        alert = _wazuh("endpoint event", data, 12, rule_id, timestamp)
        alert["agent"] = {"name": host, "ip": ip}
        alert["rule"]["mitre"] = mitre
        return alert

    def test_counts_agent_ip_mitre_and_cross_host_facts_are_deterministic(self):
        digest = "ab" * 32
        shared = {"fileinfo": {"filename": "stage.bin", "sha256": digest}}
        alerts = []
        for index in range(13):
            if index == 0:
                data = shared
            elif index == 1:
                data = {"process": {"name": "stage.bin", "command_line": "stage.bin", "target": r"C:\Windows\System32\lsass.exe"}}
            else:
                data = {"process": {"name": "stage.bin", "command_line": "stage.bin"}}
            alerts.append(self._alert(
                "host-a", "10.1.1.5", "100201",
                {"id": ["T1204.002"], "tactic": ["Execution"], "technique": ["User Execution: Malicious File"]},
                data,
                f"2026-03-01T01:00:{index:02d}Z",
            ))
        alerts.append(self._alert(
            "host-a", "10.1.1.5", "100206",
            {"id": ["T1570"], "tactic": ["Lateral Movement"], "technique": ["Lateral Tool Transfer"]},
            {"process": {"name": "remote.exe", "parent_process": "stage.bin", "command_line": r"remote.exe \\host-b -s cmd"}},
            "2026-03-01T01:02:00Z",
        ))
        alerts.append(self._alert(
            "host-b", "10.1.1.6", "100207",
            {"id": ["T1047"], "tactic": ["Execution"], "technique": ["Windows Management Instrumentation"]},
            {"process": {"name": "wmic.exe", "command_line": "wmic process call create"}, "fileinfo": {"filename": "stage.bin", "sha256": digest}},
            "2026-03-01T01:02:05Z",
        ))
        alerts.append(self._alert(
            "host-c", "10.1.1.7", "100212",
            {"id": ["T1485"], "tactic": ["Impact"], "technique": ["Data Destruction"]},
            {"fileinfo": {"path": r"\\host-c\share\manifest.docx", "size": 0}},
            "2026-03-01T01:03:00Z",
        ))
        alerts.append(self._alert(
            "host-a", "10.1.1.5", "100210",
            {"id": ["T1490"], "tactic": ["Impact"], "technique": ["Inhibit System Recovery"]},
            {"process": {"name": "wbadmin.exe", "command_line": "wbadmin delete catalog -quiet"}},
            "2026-03-01T01:04:00Z",
        ))
        # 13 process/file alerts were built, then three more on host-a/host-b/host-c
        # plus the recovery command. Recount from the objects, which is the rule.
        analyzer = AlertAnalyzer()
        formatter = ReportFormatter.__new__(ReportFormatter)
        formatter.alert_analyzer = analyzer
        formatter._active_trace = None
        try:
            cleaned = analyzer.clean_log_data(alerts)
            by_host = {}
            for alert in cleaned:
                by_host[alert["agent_name"]] = by_host.get(alert["agent_name"], 0) + 1
            draft = "\n".join([
                "Threat Level: CRITICAL | Total Alerts: 99",
                "| 10.1.1.5 | External | Unknown | Inbound | activity | CRITICAL | High | 99 |",
                "| 203.0.113.5 | External | Unknown | Inbound | invented | CRITICAL | High | 1 |",
                "No external network traffic or C2 indicators were observed.",
                "This is the confirmed initial execution vector.",
                "This confirms a high-confidence credential dumping.",
                "| T1570 | Boot or Logon Autostart Execution: Registry Run Keys |",
                "T1570 is Boot or Logon Autostart Execution: Registry Run Keys.",
                "| T1490 | Deobfuscate/Decode Files or Information |",
                "host-a: 14 alerts",
                "host-b: 9 alerts",
                "host-c: 4 alerts",
                "Perform deep forensic analysis to identify the initial entry vector and",
                "**Analysis Complete**",
            ])
            stamped = formatter._stamp_authoritative_evidence(draft, cleaned, [{
                "filename": "historical-note.pdf",
                "source": "custom_document",
                "match_types": ["semantic"],
                "evidence_strength": "low",
                "metadata": {},
            }])
            self.assertIn(f"Total alerts: {len(cleaned)}", stamped)
            self.assertIn(f"host-a: {by_host['host-a']} alert(s)", stamped)
            self.assertIn(f"host-b: {by_host['host-b']} alert(s)", stamped)
            self.assertIn(f"host-c: {by_host['host-c']} alert(s)", stamped)
            self.assertNotIn("| 10.1.1.5 | External", stamped)
            self.assertNotIn("203.0.113.5", stamped)
            self.assertIn("Monitored endpoint addresses: 10.1.1.5, 10.1.1.6, 10.1.1.7.", stamped)
            self.assertIn("No network-connection telemetry is included", stamped)
            self.assertNotIn("No external network traffic", stamped)
            self.assertNotIn("Registry Run Keys", stamped)
            self.assertIn("Lateral Tool Transfer", stamped)
            self.assertIn("Inhibit System Recovery", stamped)
            self.assertIn("T1485", stamped)
            self.assertIn("size after the event is 0 bytes", stamped)
            self.assertIn("remote target host-b", stamped)
            self.assertIn("WMI-style execution observed", stamped)
            self.assertIn("wbadmin delete catalog -quiet", stamped)
            self.assertIn(digest, stamped)
            self.assertIn("cross-host correlation", stamped)
            self.assertIn("initial access vector is not established", stamped)
            self.assertIn("successful extraction is not established", stamped)
            self.assertIn("involving lsass", stamped)
            self.assertIn("Evidence-based response actions:", stamped)
            self.assertIn("### OBSERVED", stamped)
            self.assertIn("### INFERRED", stamped)
            self.assertIn("### HISTORICAL CTI", stamped)
            self.assertIn("### NOT ESTABLISHED", stamped)
            self.assertIn("General background: historical-note.pdf.", stamped)
            self.assertIn("not current telemetry", stamped)
            self.assertIn("Earliest timestamp: 2026-03-01T01:00:00Z.", stamped)
            self.assertIn("Latest timestamp: 2026-03-01T01:04:00Z.", stamped)
            self.assertIn("A specific threat actor is not established.", stamped)
            self.assertIn("[incomplete clause removed].", stamped)
            self.assertNotIn("FAIL", stamped)
            self.assertIn("Total alerts:", stamped.split("## Telemetry Validation", 1)[1])
        finally:
            analyzer.close()


if __name__ == "__main__":
    unittest.main()
