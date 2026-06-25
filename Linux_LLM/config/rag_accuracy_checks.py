#!/usr/bin/env python3
"""Deterministic checks for RAG retrieval quality guardrails.

This script intentionally avoids connecting to PostgreSQL, loading embedding
models, or invoking llama.cpp. It validates the small but important matching and
evidence-audit rules that protect CTI reports from common RAG failure modes.
"""

from __future__ import annotations

import json
import sys
import types
from typing import Callable


def _install_runtime_stubs() -> None:
    """Stub heavyweight runtime modules that are not needed for these checks."""
    geoip2 = types.ModuleType("geoip2")
    geoip2.database = types.ModuleType("geoip2.database")
    geoip2.errors = types.ModuleType("geoip2.errors")
    geoip2.errors.AddressNotFoundError = type("AddressNotFoundError", (Exception,), {})
    sys.modules.setdefault("geoip2", geoip2)
    sys.modules.setdefault("geoip2.database", geoip2.database)
    sys.modules.setdefault("geoip2.errors", geoip2.errors)

    psycopg2 = types.ModuleType("psycopg2")
    psycopg2.OperationalError = type("OperationalError", (Exception,), {})
    psycopg2.Error = type("Error", (Exception,), {})
    psycopg2.errors = types.SimpleNamespace(
        DuplicateDatabase=type("DuplicateDatabase", (Exception,), {})
    )
    psycopg2.connect = lambda *_args, **_kwargs: None
    sys.modules.setdefault("psycopg2", psycopg2)

    psycopg2_sql = types.ModuleType("psycopg2.sql")
    psycopg2_sql.SQL = lambda value: value
    psycopg2_sql.Identifier = lambda value: value
    sys.modules.setdefault("psycopg2.sql", psycopg2_sql)

    psycopg2_extras = types.ModuleType("psycopg2.extras")
    psycopg2_extras.execute_values = lambda *_args, **_kwargs: []
    sys.modules.setdefault("psycopg2.extras", psycopg2_extras)

    psycopg2_extensions = types.ModuleType("psycopg2.extensions")
    psycopg2_extensions.ISOLATION_LEVEL_AUTOCOMMIT = 0
    sys.modules.setdefault("psycopg2.extensions", psycopg2_extensions)

    sentence_transformers = types.ModuleType("sentence_transformers")
    sentence_transformers.SentenceTransformer = object
    sys.modules.setdefault("sentence_transformers", sentence_transformers)

    charts = types.ModuleType("charts")
    charts.SOCChartGenerator = object
    sys.modules.setdefault("charts", charts)

    llm_client = types.ModuleType("llm_client")
    llm_client.ChatTemplateManager = object
    llm_client.LlamaModelClient = object
    sys.modules.setdefault("llm_client", llm_client)


_install_runtime_stubs()

import report as report_module  # noqa: E402
from cti_artifacts import CTIArtifactExtractor  # noqa: E402
from report import AlertAnalyzer, RAGContextManager, ReportFormatter, ReportGenerator  # noqa: E402


def _assert(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def check_ip_substring_not_exact() -> None:
    manager = RAGContextManager.__new__(RAGContextManager)
    content = (
        "Extracted CTI Artefacts | IPs: 192.168.56.101, "
        "128.199.138.233; document text follows."
    )

    false_evidence = manager._exact_match_evidence(
        content,
        {},
        {"ips": ["192.168.56.10"]},
    )
    true_evidence = manager._exact_match_evidence(
        content,
        {},
        {"ips": ["192.168.56.101"]},
    )

    _assert(false_evidence == [], "IP substring was incorrectly treated as exact evidence")
    _assert(true_evidence, "True exact IP match did not produce evidence")


def check_hash_case_insensitive_exact_matching() -> None:
    manager = RAGContextManager.__new__(RAGContextManager)
    uppercase_hash = "F70CEF297EFE9EC0ABEA369B3C1235F14220A6165B48F6E8AA054296078122C8"
    lowercase_hash = uppercase_hash.lower()

    evidence = manager._exact_match_evidence(
        "Indicators list SHA256 " + uppercase_hash,
        {"cti_artifacts": {"hashes": [uppercase_hash]}},
        {"hashes": [lowercase_hash]},
    )
    _assert(evidence, "Hash exact matching remained case-sensitive")

    formatter = ReportFormatter.__new__(ReportFormatter)
    annotated = formatter._annotate_context_docs(
        [
            {
                "source": "custom_document",
                "content": "Malicious payload hash " + uppercase_hash,
                "metadata": {
                    "cti_artifacts": {"hashes": [uppercase_hash]},
                    "cti_artifact_dispositions": {"hashes": {uppercase_hash: "malicious"}},
                },
                "match_types": ["exact"],
            }
        ],
        [{"file_context": {"sha256": lowercase_hash}}],
    )
    _assert(
        annotated[0]["evidence_strength"] == "high",
        "Case-different malicious hash overlap was not high-strength evidence",
    )
    _assert(
        lowercase_hash in [value.lower() for value in annotated[0]["current_ioc_overlap"].get("hashes", [])],
        "Case-different hash overlap was not recorded",
    )


def check_defanged_indicator_matching() -> None:
    manager = RAGContextManager.__new__(RAGContextManager)
    content = "CTI listed hxxps[:]//evil[.]example/payload and callback evil[.]example."

    _assert(
        manager._contains_exact_term(content, "https://evil.example/payload", term_type="url"),
        "Defanged URL was not matched to refanged alert URL",
    )
    _assert(
        manager._contains_exact_term(content, "evil.example", term_type="domain"),
        "Defanged domain was not matched to refanged alert domain",
    )
    evidence = manager._exact_match_evidence(
        content,
        {},
        {"urls": ["https://evil.example/payload"], "domains": ["evil.example"]},
    )
    _assert(evidence, "Defanged content did not produce exact-match evidence")

    patterns = manager._like_patterns(["https://evil.example/payload"])
    joined_patterns = " ".join(patterns).lower()
    _assert("hxxps" in joined_patterns and "[.]" in joined_patterns, "SQL patterns lack defanged variants")


def check_flat_alert_artifact_extraction_for_retrieval() -> None:
    analyzer = AlertAnalyzer.__new__(AlertAnalyzer)
    observed = analyzer._extract_observed_iocs(
        {
            "rule_id": "100001",
            "raw_alert_artifacts": {
                "hashes": ["ABCDEF1234567890ABCDEF1234567890"],
                "domains": ["evil.example"],
                "urls": ["https://evil.example/payload"],
            },
        }
    )

    _assert(
        "ABCDEF1234567890ABCDEF1234567890" in observed.get("hashes", []),
        "Raw alert hash artifact was not promoted for retrieval",
    )
    _assert("evil.example" in observed.get("domains", []), "Raw alert domain artifact missing")

    formatter = ReportFormatter.__new__(ReportFormatter)
    exact_terms = formatter._build_exact_terms_from_alerts([{"observed_iocs": observed}])
    _assert(
        "ABCDEF1234567890ABCDEF1234567890" in exact_terms.get("hashes", []),
        "Raw alert hash did not become an exact hash retrieval term",
    )


def check_private_ips_not_promoted_as_cti_context() -> None:
    content = (
        "Lab host 192.168.56.101 connected to public command node "
        "128.199.138.233 and internal server 10.0.0.5."
    )
    artifacts = CTIArtifactExtractor.extract(content)
    context_artifacts = CTIArtifactExtractor.for_cti_context(artifacts)

    _assert("128.199.138.233" in context_artifacts.get("ips", []), "Public IP was not retained")
    _assert("192.168.56.101" not in context_artifacts.get("ips", []), "Private IP was promoted")
    _assert("10.0.0.5" not in context_artifacts.get("ips", []), "Internal IP was promoted")
    _assert("192.168.56.101" in artifacts.get("non_public_ips", []), "Private IP was not preserved")


def check_evidence_audit_labels() -> None:
    formatter = ReportFormatter.__new__(ReportFormatter)
    alerts = [
        {
            "src_ip": "203.0.113.10",
            "dest_ip": "10.0.0.5",
            "rule_id": "1001",
            "signature_id": "900001",
            "alert_signature": "ET TEST Malware Callback",
            "observed_iocs": {
                "ips": ["203.0.113.10"],
                "signature_ids": ["900001"],
            },
        }
    ]
    docs = [
        {
            "source": "archive",
            "content": "ET TEST Malware Callback from 203.0.113.10 to 10.0.0.5",
            "metadata": {"src_ip": "203.0.113.10", "signature_id": "900001"},
            "match_types": ["exact"],
            "match_evidence": ["source ip matched metadata src_ip=203.0.113.10"],
        },
        {
            "source": "custom_document",
            "content": "APT report describing unrelated 198.51.100.50 infrastructure",
            "metadata": {"cti_artifacts": {"ips": ["198.51.100.50"]}},
            "match_types": ["semantic"],
            "match_evidence": ["semantic nearest-neighbor similarity=0.31"],
        },
    ]

    annotated = formatter._annotate_context_docs(docs, alerts)
    high_support = annotated[0]
    weak_support = annotated[1]

    _assert(high_support["evidence_strength"] == "high", "Exact local telemetry was not high strength")
    _assert(
        high_support["source_reliability"] == "local_security_telemetry",
        "Archive source reliability label is wrong",
    )
    _assert(
        weak_support["evidence_strength"] == "low",
        "Semantic-only CTI source without overlap should be low strength",
    )
    _assert(
        "semantic-only support; do not use alone for attribution"
        in weak_support["retrieval_cautions"],
        "Semantic-only caution missing",
    )


def check_cti_context_classification() -> None:
    text = (
        "Indicators of Compromise: 128.199.138.233 and bad.example.com. "
        "The threat actor APT29 used T1021.002 for lateral movement. "
        "Mitigation: isolate affected hosts and block the command and control domain."
    )
    labels = CTIArtifactExtractor.classify_context(text)

    _assert("ioc_listing" in labels, "IoC listing context was not detected")
    _assert("ttp_behavior" in labels, "TTP behavior context was not detected")
    _assert("remediation" in labels, "Remediation context was not detected")

    formatter = ReportFormatter.__new__(ReportFormatter)
    annotated = formatter._annotate_context_docs(
        [
            {
                "source": "custom_document",
                "content": "Sandbox analysis environment contacted 192.168.56.101.",
                "metadata": {"cti_context_labels": ["analysis_environment"]},
                "match_types": ["semantic"],
            }
        ],
        [{"src_ip": "203.0.113.10", "dest_ip": "10.0.0.5"}],
    )
    _assert(
        "analysis-environment details may not be malicious infrastructure"
        in annotated[0]["retrieval_cautions"],
        "Analysis-environment caution missing",
    )


def check_artifact_disposition_labels() -> None:
    text = (
        "Malicious C2 server 128.199.138.233 was used by the threat actor. "
        "Victim host 10.0.0.5 was compromised. "
        "Sandbox analysis environment used 192.168.56.101 during detonation. "
        "The legitimate update domain updates.example.com is known good and should be allowlisted."
    )
    artifacts = CTIArtifactExtractor.extract(text)
    dispositions = CTIArtifactExtractor.classify_artifact_dispositions(text, artifacts)

    _assert(
        dispositions.get("ips", {}).get("128.199.138.233") == "malicious",
        "Malicious public IP disposition missing",
    )
    _assert(
        dispositions.get("ips", {}).get("10.0.0.5") == "victim",
        "Victim IP disposition missing",
    )
    _assert(
        dispositions.get("ips", {}).get("192.168.56.101") == "analysis_environment",
        "Analysis-environment IP disposition missing",
    )
    _assert(
        dispositions.get("domains", {}).get("updates.example.com") == "benign",
        "Benign domain disposition missing",
    )

    formatter = ReportFormatter.__new__(ReportFormatter)
    annotated = formatter._annotate_context_docs(
        [
            {
                "source": "custom_document",
                "content": text,
                "metadata": {
                    "cti_artifacts": artifacts,
                    "cti_artifact_dispositions": dispositions,
                },
                "match_types": ["exact"],
            }
        ],
        [{"src_ip": "10.0.0.5"}],
    )
    _assert(
        annotated[0]["evidence_strength"] == "medium",
        "Victim-side exact overlap should not be promoted to high strength",
    )
    _assert(
        "current overlap is marked benign, victim, or analysis-environment, not attacker infrastructure"
        in annotated[0]["retrieval_cautions"],
        "Victim/analysis overlap caution missing",
    )

    benign_annotated = formatter._annotate_context_docs(
        [
            {
                "source": "custom_document",
                "content": text,
                "metadata": {
                    "cti_artifacts": artifacts,
                    "cti_artifact_dispositions": dispositions,
                },
                "match_types": ["exact"],
            }
        ],
        [{"dns_context": {"query_name": "updates.example.com"}}],
    )
    _assert(
        benign_annotated[0]["evidence_strength"] == "medium",
        "Benign exact overlap should not be promoted to high strength",
    )


def check_report_claim_audit() -> None:
    formatter = ReportFormatter.__new__(ReportFormatter)
    report = (
        "APT29 is attributed to this incident. "
        "Mapped MITRE ATT&CK technique T9999. "
        "Block 198.51.100.50 immediately."
    )
    docs = [
        {
            "source": "custom_document",
            "content": "Historical report lists 198.51.100.50.",
            "metadata": {"cti_artifacts": {"ips": ["198.51.100.50"]}},
            "match_types": ["semantic"],
            "evidence_strength": "low",
            "source_reliability": "uploaded_cti_document",
            "historical_only_artifacts": {"ips": ["198.51.100.50"]},
            "cti_context_labels": ["ioc_listing"],
        }
    ]
    findings = formatter._audit_report_claims(report, docs, [{"src_ip": "203.0.113.10"}])
    joined = " ".join(findings).lower()

    _assert("attribution language appears" in joined, "Attribution warning missing")
    _assert("t9999" in joined, "Unsupported MITRE warning missing")
    _assert("198.51.100.50" in joined, "Low-strength historical artifact warning missing")


def check_actor_specific_attribution_audit() -> None:
    formatter = ReportFormatter.__new__(ReportFormatter)
    unsupported_findings = formatter._audit_report_claims(
        "APT29 is attributed to this incident.",
        [
            {
                "source": "custom_document",
                "content": "APT28 used this infrastructure in a prior campaign.",
                "metadata": {"cti_artifacts": {"ips": ["203.0.113.10"], "threat_actors": ["APT28"]}},
                "evidence_strength": "high",
                "cti_context_labels": ["attribution"],
                "current_ioc_overlap": {"ips": ["203.0.113.10"]},
            }
        ],
        [{"src_ip": "203.0.113.10"}],
    )
    joined_unsupported = " ".join(unsupported_findings).lower()
    _assert("specific threat actor term" in joined_unsupported, "Actor-specific attribution warning missing")
    _assert("apt29" in joined_unsupported, "Unsupported actor term missing from warning")

    supported_findings = formatter._audit_report_claims(
        "APT29 is attributed to this incident.",
        [
            {
                "source": "custom_document",
                "content": "APT29 used this infrastructure in a prior campaign.",
                "metadata": {"cti_artifacts": {"ips": ["203.0.113.10"], "threat_actors": ["APT29"]}},
                "evidence_strength": "high",
                "cti_context_labels": ["attribution"],
                "current_ioc_overlap": {"ips": ["203.0.113.10"]},
            }
        ],
        [{"src_ip": "203.0.113.10"}],
    )
    joined_supported = " ".join(supported_findings).lower()
    _assert("specific threat actor term" not in joined_supported, "Supported actor was incorrectly warned")


def check_remediation_target_grounding() -> None:
    formatter = ReportFormatter.__new__(ReportFormatter)
    docs = [
        {
            "source": "custom_document",
            "content": "Known-good update domain updates.example.com should remain allowlisted.",
            "metadata": {
                "cti_artifacts": {"domains": ["updates.example.com"]},
                "cti_artifact_dispositions": {"domains": {"updates.example.com": "benign"}},
            },
            "evidence_strength": "medium",
            "cti_context_labels": ["remediation"],
        },
        {
            "source": "custom_document",
            "content": "Historical C2 IP 198.51.100.50 was used in a prior campaign.",
            "metadata": {
                "cti_artifacts": {"ips": ["198.51.100.50"]},
                "cti_artifact_dispositions": {"ips": {"198.51.100.50": "malicious"}},
            },
            "evidence_strength": "medium",
            "cti_context_labels": ["ioc_listing"],
            "historical_only_artifacts": {"ips": ["198.51.100.50"]},
        },
    ]
    findings = formatter._audit_report_claims(
        "Block updates.example.com immediately. Block 198.51.100.50 at the firewall.",
        docs,
        [{"src_ip": "203.0.113.10"}],
    )
    joined = " ".join(findings).lower()
    _assert("not observed in current alert artifacts" in joined, "Unobserved remediation target warning missing")
    _assert("updates.example.com=benign" in joined, "Benign remediation target warning missing")

    safe_findings = formatter._audit_report_claims(
        "Block 203.0.113.10 at the perimeter.",
        docs,
        [{"src_ip": "203.0.113.10"}],
    )
    safe_joined = " ".join(safe_findings).lower()
    _assert("not observed in current alert artifacts" not in safe_joined, "Observed remediation target was warned")


def check_mitre_catalog_validation() -> None:
    formatter = ReportFormatter.__new__(ReportFormatter)
    previous_cache = ReportFormatter._mitre_catalog_cache
    try:
        ReportFormatter._mitre_catalog_cache = {
            "t1001": {"id": "T1001", "deprecated": False},
            "t9998": {"id": "T9998", "deprecated": True},
        }
        report = "Mapped MITRE ATT&CK techniques T1001, T9998, and T9999."
        findings = formatter._audit_report_claims(
            report,
            [
                {
                    "evidence_strength": "high",
                    "cti_context_labels": ["ttp_behavior"],
                    "metadata": {"cti_artifacts": {"mitre_techniques": ["T1001"]}},
                }
            ],
            [{"mitre_context": {"id": ["T1001"]}}],
        )
        joined = " ".join(findings).lower()

        _assert("not present in the local att&ck catalog" in joined, "Unknown MITRE catalog warning missing")
        _assert("t9999" in joined, "Unknown MITRE technique ID missing from warning")
        _assert("marked deprecated" in joined, "Deprecated MITRE catalog warning missing")
        _assert("t9998" in joined, "Deprecated MITRE technique ID missing from warning")
    finally:
        ReportFormatter._mitre_catalog_cache = previous_cache


def check_approved_report_index_sanitization() -> None:
    markdown = """# Approved Report

## Executive Summary

Human-approved incident analysis.

---

## Report QA Findings

- Reviewer warning that should not become future RAG evidence.

---

## RAG Sources Used

- [RAG-1] source=custom_document; weak historical source
"""
    sanitized = ReportGenerator._strip_generated_appendices_for_indexing(markdown)

    _assert("Human-approved incident analysis" in sanitized, "Approved report body was removed")
    _assert("Report QA Findings" not in sanitized, "QA appendix was not stripped")
    _assert("RAG Sources Used" not in sanitized, "RAG appendix was not stripped")
    _assert("weak historical source" not in sanitized, "Generated source details leaked into indexed content")


def check_low_strength_context_filtering() -> None:
    formatter = ReportFormatter.__new__(ReportFormatter)
    docs = [
        {"id": "high", "evidence_strength": "high"},
        {"id": "medium", "evidence_strength": "medium"},
        {"id": "low-1", "evidence_strength": "low"},
        {"id": "low-2", "evidence_strength": "low"},
    ]

    selected = formatter._filter_context_docs_by_evidence_quality(docs, limit=4)
    selected_ids = [doc["id"] for doc in selected]

    _assert("high" in selected_ids and "medium" in selected_ids, "Strong evidence was not retained")
    _assert(
        sum(1 for doc_id in selected_ids if doc_id.startswith("low")) == 1,
        "Low-strength background was not capped when stronger evidence existed",
    )

    weak_only = formatter._filter_context_docs_by_evidence_quality(
        [{"id": "low-only-1", "evidence_strength": "low"}, {"id": "low-only-2", "evidence_strength": "low"}],
        limit=2,
    )
    _assert(len(weak_only) == 2, "Weak-only fallback context was incorrectly removed")


def check_document_extraction_quality() -> None:
    low_text = "\n".join(
        [
            "--- Page 1 ---",
            "[IMAGES DETECTED: 2 image(s) on this page; OCR not performed]",
            "--- Page 2 ---",
            "[IMAGES DETECTED: 1 image(s) on this page; OCR not performed]",
        ]
    )
    quality = CTIArtifactExtractor.assess_extraction_quality(low_text, pages=2, artefacts={})
    _assert(quality["quality"] == "low", "Image-heavy low-text document was not marked low quality")
    _assert("image_heavy_pdf_no_ocr" in quality["warnings"], "Image-heavy warning missing")

    formatter = ReportFormatter.__new__(ReportFormatter)
    annotated = formatter._annotate_context_docs(
        [
            {
                "source": "custom_document",
                "content": low_text,
                "metadata": {"document_quality": quality},
                "match_types": ["semantic"],
            }
        ],
        [{"src_ip": "203.0.113.10"}],
    )
    cautions = " ".join(annotated[0]["retrieval_cautions"])
    _assert("source document extraction quality is low" in cautions, "Document quality caution missing")


def check_alert_behavior_and_response_focus() -> None:
    analyzer = AlertAnalyzer.__new__(AlertAnalyzer)
    outbound_alert = {
        "rule_level": 12,
        "rule_description": "ET MALWARE Possible command and control beacon",
        "alert_signature": "ET MALWARE C2 callback",
        "src_ip": "10.0.0.5",
        "dest_ip": "8.8.8.8",
        "dest_port": 443,
        "app_proto": "tls",
        "threat_classification": {"threat_direction": "outbound"},
        "tls_context": {"sni": "c2.example.com"},
    }
    tags = analyzer._infer_behavior_tags(outbound_alert)
    focus = analyzer._build_response_focus(outbound_alert, tags)

    _assert("possible_c2" in tags, "C2 behavior tag missing")
    _assert("compromised_asset_egress" in tags, "Outbound compromised-asset tag missing")
    _assert(
        any("potentially compromised" in item.lower() or "contain" in item.lower() for item in focus),
        "Outbound C2 response focus missing",
    )

    lateral_alert = {
        "rule_level": 12,
        "rule_description": "ET MALWARE Possible ransomware or destructive SMB file write",
        "src_ip": "10.0.0.5",
        "dest_ip": "10.0.0.6",
        "dest_port": 445,
        "app_proto": "smb",
        "threat_classification": {"threat_direction": "lateral"},
    }
    lateral_tags = analyzer._infer_behavior_tags(lateral_alert)
    lateral_focus = analyzer._build_response_focus(lateral_alert, lateral_tags)
    _assert("lateral_movement_candidate" in lateral_tags, "Lateral movement tag missing")
    _assert("malware_or_destructive_activity" in lateral_tags, "Destructive malware tag missing")
    _assert(any("smb" in item.lower() for item in lateral_focus), "SMB response focus missing")


def check_cti_corpus_alert_shape_parsing() -> None:
    class QuietGeoIPManager:
        def __init__(self, *_args, **_kwargs):
            pass

        def get_location(self, *_args, **_kwargs):
            return None

        def close(self):
            pass

    previous_geoip_manager = report_module.GeoIPManager
    try:
        report_module.GeoIPManager = QuietGeoIPManager
        analyzer = AlertAnalyzer()
        wrapped_alert = {
            "alerts": [
                {
                    "timestamp": "2026-06-05T08:00:00.000+0000",
                    "rule": {
                        "level": 10,
                        "id": "100001",
                        "description": "ET PHISHING Suspicious executable or archive attachment delivered via SMTP",
                    },
                    "agent": {"ip": "66.96.12.44", "name": "mail-edge-01"},
                    "data": {
                        "src_ip": "95.216.59.92",
                        "dest_ip": "66.96.12.44",
                        "src_port": 42568,
                        "dest_port": 25,
                        "proto": "TCP",
                        "app_proto": "smtp",
                        "event_type": "alert",
                        "direction": "inbound",
                        "alert": {
                            "signature": "ET PHISHING Suspicious executable or archive attachment delivered via SMTP",
                            "category": "Attempted User Privilege Gain",
                            "severity": 2,
                            "action": "allowed",
                            "signature_id": 2026001,
                        },
                        "email": {
                            "from": "notification@www.jmj.com",
                            "to": "target-user@victim.local",
                            "subject": "Action required: document review",
                            "attachment": "ds7002.zip",
                            "mail_from_domain": "www.jmj.com",
                            "url": "https://www.jmj.com/personal/nauerthn_state_gov",
                        },
                        "dns": {"type": "query", "rrname": "www.jmj.com", "rrtype": "A", "rcode": "NOERROR"},
                        "fileinfo": {
                            "filename": "ds7002.zip",
                            "md5": "f713d5df826c6051e65f995e57d6817d",
                            "sha256": "f70cef297efe9ec0abea369b3c1235f14220a6165b48f6e8aa054296078122c8",
                        },
                        "smb": {
                            "command": "SMB2_CREATE",
                            "share": "\\\\file-server-01\\admin$",
                            "filename": "ransom-note.txt",
                            "disposition": "FILE_OVERWRITE_IF",
                        },
                        "modbus": {"function": "write_multiple_registers", "unit_id": 1, "address": 40001, "quantity": 8},
                    },
                }
            ]
        }

        cleaned = analyzer.clean_log_data([wrapped_alert])
    finally:
        report_module.GeoIPManager = previous_geoip_manager

    _assert(len(cleaned) == 1, "Wrapped alerts array was not parsed")
    alert = cleaned[0]
    _assert(alert.get("email_context", {}).get("attachment") == "ds7002.zip", "Email attachment missing")
    _assert(alert.get("dns_context", {}).get("query_name") == "www.jmj.com", "Direct DNS rrname missing")
    _assert(
        alert.get("file_context", {}).get("sha256") == "f70cef297efe9ec0abea369b3c1235f14220a6165b48f6e8aa054296078122c8",
        "fileinfo sha256 missing",
    )
    _assert(alert.get("smb_context", {}).get("filename") == "ransom-note.txt", "SMB context missing")
    _assert(alert.get("modbus_context", {}).get("function") == "write_multiple_registers", "Modbus context missing")
    _assert("phishing_or_email_delivery" in alert.get("behavior_tags", []), "Email phishing behavior tag missing")

    observed = alert.get("observed_iocs") or {}
    _assert("www.jmj.com" in observed.get("domains", []), "Email/DNS domain missing from observed IoCs")
    _assert("https://www.jmj.com/personal/nauerthn_state_gov" in observed.get("urls", []), "Email URL missing")
    _assert("notification@www.jmj.com" in observed.get("emails", []), "Email sender missing")
    _assert("f713d5df826c6051e65f995e57d6817d" in observed.get("hashes", []), "File hash missing")
    _assert("ransom-note.txt" in observed.get("files", []), "SMB filename missing from observed files")
    _assert("Action required: document review" in observed.get("keywords", []), "Email subject missing from keywords")

    formatter = ReportFormatter.__new__(ReportFormatter)
    exact_terms = formatter._build_exact_terms_from_alerts(cleaned)
    _assert("www.jmj.com" in exact_terms.get("domains", []), "Email domain missing from exact terms")
    _assert("ds7002.zip" in exact_terms.get("keywords", []), "Attachment missing from exact terms")

    manager = RAGContextManager.__new__(RAGContextManager)
    chunk = manager._create_semantic_chunk(wrapped_alert["alerts"][0])
    _assert("Email:" in chunk and "SMB:" in chunk and "Modbus:" in chunk, "Semantic chunk missed enriched contexts")


def check_cti_behavior_alignment() -> None:
    tags = CTIArtifactExtractor.infer_behavior_tags(
        "The ransomware payload moved laterally over SMB admin shares and wrote encrypted files."
    )
    _assert("lateral_movement_candidate" in tags, "CTI lateral movement behavior tag missing")
    _assert("malware_or_destructive_activity" in tags, "CTI destructive malware behavior tag missing")

    formatter = ReportFormatter.__new__(ReportFormatter)
    formatter.rag_manager = RAGContextManager.__new__(RAGContextManager)
    formatter.rag_manager.max_retrieval_docs = 4

    alert = {
        "rule_level": 12,
        "rule_description": "ET MALWARE Possible ransomware or destructive SMB file write",
        "behavior_tags": ["lateral_movement_candidate", "malware_or_destructive_activity"],
    }
    aligned_doc = {
        "id": "aligned",
        "source": "custom_document",
        "content": "Ransomware operators used SMB for lateral movement. Technique T1021.002.",
        "metadata": {
            "cti_behavior_tags": ["lateral_movement_candidate", "malware_or_destructive_activity"],
            "cti_context_labels": ["ttp_behavior"],
            "cti_artifacts": {"mitre_techniques": ["T1021.002"]},
        },
        "match_types": ["semantic"],
        "score": 0.4,
    }
    mismatch_doc = {
        "id": "mismatch",
        "source": "custom_document",
        "content": "Credential phishing and password spraying were observed. Technique T1110.",
        "metadata": {
            "cti_behavior_tags": ["credential_attack"],
            "cti_context_labels": ["ttp_behavior"],
            "cti_artifacts": {"mitre_techniques": ["T1110"]},
        },
        "match_types": ["semantic"],
        "score": 0.9,
    }

    selected = formatter._select_relevant_context_docs([mismatch_doc, aligned_doc], [alert], max_docs=2)
    _assert(selected[0]["id"] == "aligned", "Behavior-aligned CTI did not outrank mismatch")
    _assert(selected[0]["behavior_overlap"], "Behavior overlap was not recorded")
    _assert(selected[1]["behavior_mismatch"], "Behavior mismatch was not recorded")
    _assert(
        "CTI behavior tags do not align with current alert behavior" in selected[1]["retrieval_cautions"],
        "Behavior mismatch caution missing",
    )

    findings = formatter._audit_report_claims(
        "Mapped MITRE ATT&CK technique T1110.",
        [
            {
                "evidence_strength": "high",
                "cti_context_labels": ["ttp_behavior"],
                "cti_behavior_tags": ["credential_attack"],
                "metadata": {"cti_artifacts": {"mitre_techniques": ["T1110"]}},
            }
        ],
        [alert],
    )
    _assert("t1110" in " ".join(findings).lower(), "Behavior-mismatched TTP support was accepted")


def check_structure_aware_cti_chunking() -> None:
    manager = RAGContextManager.__new__(RAGContextManager)
    manager.document_chunk_size = 180
    manager.document_chunk_overlap = 0

    text = """# Indicators of Compromise

The following infrastructure was observed during the campaign.

203.0.113.50

This host received repeated callbacks from infected machines.

# Victim Infrastructure

10.0.0.7 was the internal file server affected during the incident.
"""
    chunks = manager._chunk_text_with_sections(text, chunk_size=180, chunk_overlap=0)
    ioc_chunks = [chunk for chunk in chunks if "203.0.113.50" in chunk["text"]]
    victim_chunks = [chunk for chunk in chunks if "10.0.0.7" in chunk["text"]]

    _assert(ioc_chunks, "IoC chunk missing")
    _assert(victim_chunks, "Victim chunk missing")
    _assert(
        "Indicators of Compromise" in ioc_chunks[0]["section_path"],
        "IoC section path was not preserved",
    )
    _assert(
        "Victim Infrastructure" in victim_chunks[0]["section_path"],
        "Victim section path was not preserved",
    )

    ioc_dispositions = CTIArtifactExtractor.classify_artifact_dispositions(
        ioc_chunks[0]["text"],
        {"ips": ["203.0.113.50"]},
    )
    adjusted_ioc = CTIArtifactExtractor.apply_section_context_to_dispositions(
        ioc_dispositions,
        CTIArtifactExtractor.classify_context(ioc_chunks[0]["section_path"]),
    )
    _assert(
        adjusted_ioc["ips"]["203.0.113.50"] == "malicious",
        "IoC section did not promote unknown artifact to malicious indicator",
    )

    victim_dispositions = CTIArtifactExtractor.classify_artifact_dispositions(
        victim_chunks[0]["text"],
        {"ips": ["10.0.0.7"]},
    )
    adjusted_victim = CTIArtifactExtractor.apply_section_context_to_dispositions(
        victim_dispositions,
        CTIArtifactExtractor.classify_context(victim_chunks[0]["section_path"]),
    )
    _assert(
        adjusted_victim["ips"]["10.0.0.7"] == "victim",
        "Victim section did not classify unknown artifact as victim infrastructure",
    )


def main() -> int:
    checks: list[tuple[str, Callable[[], None]]] = [
        ("ip_substring_not_exact", check_ip_substring_not_exact),
        ("hash_case_insensitive_exact_matching", check_hash_case_insensitive_exact_matching),
        ("defanged_indicator_matching", check_defanged_indicator_matching),
        ("flat_alert_artifact_extraction_for_retrieval", check_flat_alert_artifact_extraction_for_retrieval),
        ("private_ips_not_promoted_as_cti_context", check_private_ips_not_promoted_as_cti_context),
        ("evidence_audit_labels", check_evidence_audit_labels),
        ("cti_context_classification", check_cti_context_classification),
        ("artifact_disposition_labels", check_artifact_disposition_labels),
        ("report_claim_audit", check_report_claim_audit),
        ("actor_specific_attribution_audit", check_actor_specific_attribution_audit),
        ("remediation_target_grounding", check_remediation_target_grounding),
        ("mitre_catalog_validation", check_mitre_catalog_validation),
        ("approved_report_index_sanitization", check_approved_report_index_sanitization),
        ("low_strength_context_filtering", check_low_strength_context_filtering),
        ("document_extraction_quality", check_document_extraction_quality),
        ("alert_behavior_and_response_focus", check_alert_behavior_and_response_focus),
        ("cti_corpus_alert_shape_parsing", check_cti_corpus_alert_shape_parsing),
        ("cti_behavior_alignment", check_cti_behavior_alignment),
        ("structure_aware_cti_chunking", check_structure_aware_cti_chunking),
    ]

    results = []
    for name, check in checks:
        try:
            check()
            results.append({"check": name, "status": "pass"})
        except Exception as error:
            results.append({"check": name, "status": "fail", "error": str(error)})

    print(json.dumps(results, indent=2))
    return 0 if all(result["status"] == "pass" for result in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
