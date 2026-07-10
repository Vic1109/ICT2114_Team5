#!/usr/bin/env python3
"""Deterministic checks for CTI ingestion and RAG guardrails.

These checks avoid PostgreSQL, embeddings, and llama.cpp. They focus on the
small deterministic pieces that decide whether uploaded CTI can be retrieved
and whether retrieved context is allowed to support strong incident claims.
"""

from __future__ import annotations

import io
import json
import sys
import types
import zipfile
from pathlib import Path
from typing import Callable

CONFIG_DIR = Path(__file__).resolve().parents[1] / "config"
if str(CONFIG_DIR) not in sys.path:
    sys.path.insert(0, str(CONFIG_DIR))


def _install_runtime_stubs() -> None:
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
    psycopg2.errors = types.SimpleNamespace(DuplicateDatabase=type("DuplicateDatabase", (Exception,), {}))
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

from cti_artifacts import CTIArtifactExtractor  # noqa: E402
from rag import DOCXProcessor, DocumentProcessor, DocumentValidator  # noqa: E402
from report import AlertAnalyzer, RAGContextManager, ReportFormatter  # noqa: E402


def _assert(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def _minimal_docx(text: str) -> bytes:
    document_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        "<w:body><w:p><w:r><w:t>"
        + text
        + "</w:t></w:r></w:p></w:body></w:document>"
    )
    content_types = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="xml" ContentType="application/xml"/>'
        "</Types>"
    )
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("[Content_Types].xml", content_types)
        archive.writestr("word/document.xml", document_xml)
    return buffer.getvalue()


def check_article_formats_are_accepted_and_extracted() -> None:
    processor = DocumentProcessor("/tmp/cti-rag-check-uploads")
    samples = {
        "report.html": b"<html><title>Crimson Lynx</title><body><h1>Indicators</h1><p>C2 hxxp[:]//c2[.]example[.]net/a.exe SHA256 F70CEF297EFE9EC0ABEA369B3C1235F14220A6165B48F6E8AA054296078122C8</p></body></html>",
        "iocs.csv": b"type,value\nactor,Crimson Lynx\ndomain,c2.example.net\nmitre,T1105\n",
        "bundle.stix": json.dumps({
            "type": "bundle",
            "objects": [
                {"type": "threat-actor", "id": "threat-actor--1", "name": "Crimson Lynx", "aliases": ["CLX"]},
                {"type": "malware", "id": "malware--1", "name": "WispRAT"},
                {"type": "attack-pattern", "id": "attack-pattern--1", "external_references": [{"source_name": "mitre-attack", "external_id": "T1105"}]},
            ],
        }).encode("utf-8"),
        "summary.yaml": b"threat_actor: Azure Kite\nobservables:\n  - c2.example.net\nmitre_attack:\n  - T1071\n",
        "stix.xml": b"<STIX_Package><Threat_Actor>Azure Kite</Threat_Actor><Indicator>c2.example.net</Indicator><TTP>T1071</TTP></STIX_Package>",
        "report.docx": _minimal_docx("Threat actor Azure Kite used c2.example.net and T1105."),
    }

    for filename, payload in samples.items():
        valid, message = DocumentValidator.validate_file(filename, payload)
        _assert(valid, f"{filename} was rejected: {message}")
        text, metadata = processor.process_upload(payload, filename, save_to_disk=False)
        artifacts = metadata.get("cti_artifacts") or {}
        _assert(text.strip(), f"{filename} produced no text")
        _assert(metadata.get("document_quality", {}).get("quality") != "empty", f"{filename} was marked empty")
        _assert(any(artifacts.values()), f"{filename} produced no CTI artifacts")


def check_docx_container_safety() -> None:
    valid_docx = _minimal_docx("Indicators include c2.example.net.")
    _assert(DOCXProcessor.is_safe_docx_container(valid_docx), "Minimal DOCX was not accepted")

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("[Content_Types].xml", "<Types/>")
        archive.writestr("word/document.xml", "<w:document/>")
        archive.writestr("word/vbaProject.bin", b"macro")
    _assert(not DOCXProcessor.is_safe_docx_container(buffer.getvalue()), "Macro DOCX container was accepted")


def check_pdf_size_limit_accepts_large_cti_reports() -> None:
    max_pdf_size = DocumentValidator.max_size_bytes("large-threat-report.pdf")
    _assert(max_pdf_size is not None and max_pdf_size >= 20 * 1024 * 1024, "PDF CTI size limit is too low for corpus reports")


def check_no_actor_hardcoding_required_for_structured_inputs() -> None:
    payload = json.dumps({
        "threat_actor": "Novel Sparrow",
        "aliases": ["Night Heron"],
        "malware_family": "QuartzRAT",
        "campaign": "Operation Lantern Glass",
        "tools": ["CloudSweep"],
        "observables": ["c2.example.net", "F70CEF297EFE9EC0ABEA369B3C1235F14220A6165B48F6E8AA054296078122C8"],
        "mitre_attack": ["T1105", "T1071"],
    }).encode("utf-8")

    processor = DocumentProcessor("/tmp/cti-rag-check-uploads")
    _text, metadata = processor.process_upload(payload, "novel.json", save_to_disk=False)
    artifacts = metadata.get("cti_artifacts") or {}

    _assert("NOVEL SPARROW" in artifacts.get("threat_actors", []), "Arbitrary actor name was not extracted")
    _assert("QUARTZRAT" in [value.upper() for value in artifacts.get("malware_families", [])], "Arbitrary malware family was not extracted")
    _assert("Operation Lantern Glass" in artifacts.get("campaigns", []), "Arbitrary campaign was not extracted")
    _assert("CloudSweep" in artifacts.get("tools", []), "Arbitrary tool was not extracted")


def check_exact_ioc_boundaries_and_source_artifacts() -> None:
    manager = RAGContextManager.__new__(RAGContextManager)
    false_evidence = manager._exact_match_evidence(
        "Extracted CTI Artefacts | IPs: 192.168.56.101",
        {},
        {"ips": ["192.168.56.10"]},
    )
    true_evidence = manager._exact_match_evidence(
        "Narrative chunk without repeated hash.",
        {"source_cti_artifacts": {"hashes": ["f70cef297efe9ec0abea369b3c1235f14220a6165b48f6e8aa054296078122c8"]}},
        {"hashes": ["F70CEF297EFE9EC0ABEA369B3C1235F14220A6165B48F6E8AA054296078122C8"]},
    )

    _assert(false_evidence == [], "IP substring was treated as exact evidence")
    _assert(true_evidence, "Source-level CTI artifact was not exact-match evidence")


def check_evidence_strength_respects_disposition_and_behavior() -> None:
    formatter = ReportFormatter.__new__(ReportFormatter)
    doc = {
        "source": "custom_document",
        "content": "Victim infrastructure: 203.0.113.50. C2 behavior discussed elsewhere.",
        "metadata": {
            "cti_artifacts": {"ips": ["203.0.113.50"], "mitre_techniques": ["T1105"]},
            "cti_context_labels": ["victim_infrastructure"],
            "cti_behavior_tags": ["possible_c2"],
            "cti_artifact_dispositions": {"ips": {"203.0.113.50": "victim"}},
        },
        "match_types": ["exact"],
    }
    annotated = formatter._annotate_context_docs(
        [doc],
        [{
            "src_ip": "203.0.113.50",
            "behavior_tags": ["web_or_exploit_attempt"],
            "observed_iocs": {"ips": ["203.0.113.50"]},
        }],
    )[0]

    _assert(annotated["evidence_strength"] == "medium", "Victim-side overlap was promoted to high evidence")
    _assert(annotated["behavior_mismatch"] is True, "Behavior mismatch was not recorded")
    _assert(any("victim" in note for note in annotated["retrieval_cautions"]), "Victim caution was missing")


def check_low_signal_private_ips_not_promoted_to_cti_context() -> None:
    artifacts = CTIArtifactExtractor.extract("Lab host 192.168.56.10 contacted malicious c2.example.net and 8.8.8.8.")
    context = CTIArtifactExtractor.for_cti_context(artifacts)
    _assert("192.168.56.10" not in context.get("ips", []), "Private lab IP was promoted as CTI IoC")
    _assert("8.8.8.8" not in context.get("ips", []), "Low-signal resolver IP was promoted as CTI IoC")
    _assert("c2.example.net" in context.get("domains", []), "Real domain IoC was not promoted")


def check_alert_mitre_fields_are_extracted() -> None:
    analyzer = AlertAnalyzer()
    cleaned = analyzer.clean_log_data([{
        "_source": {
            "timestamp": "2026-06-06T00:00:00Z",
            "rule": {
                "level": 12,
                "id": "900001",
                "description": "Exploit attempt with explicit MITRE mapping",
                "mitre": {
                    "id": ["T1190"],
                    "tactic": ["Initial Access"],
                    "technique": ["Exploit Public-Facing Application"],
                },
            },
            "agent": {"ip": "192.168.56.10", "name": "web-01"},
            "data": {
                "src_ip": "198.51.100.20",
                "dest_ip": "192.168.56.10",
                "alert": {
                    "signature": "ET EXPLOIT test",
                    "signature_id": 900001,
                    "metadata": {"confidence": ["High"]},
                },
                "mitre": {"id": ["T1059.001"], "technique": ["PowerShell"]},
            },
        }
    }])

    mitre_context = cleaned[0].get("mitre_context") or {}
    _assert("T1190" in mitre_context.get("id", []), "rule.mitre ID was not preserved")
    _assert("T1059.001" in mitre_context.get("id", []), "data.mitre ID was not preserved")
    _assert("Exploit Public-Facing Application" in mitre_context.get("technique", []), "MITRE technique name was not preserved")


def check_low_signal_alert_terms_are_filtered() -> None:
    formatter = ReportFormatter.__new__(ReportFormatter)
    formatter.rag_manager = RAGContextManager.__new__(RAGContextManager)
    terms = formatter._build_exact_terms_from_alerts([{
        "rule_id": "900002",
        "signature_id": "900002",
        "rule_description": "Suspicious callback",
        "alert_signature": "Suspicious callback",
        "http_context": {"hostname": "c2.example.net", "url": "/"},
        "process_context": {
            "name": "powershell.exe",
            "parent_process": "explorer.exe",
            "path": r"C:\Users\victim\AppData\Local\poisonfrog.ps1",
            "command_line": "powershell.exe -ExecutionPolicy Bypass -File poisonfrog.ps1",
        },
        "observed_iocs": {
            "domains": ["c2.example.net"],
            "urls": ["/"],
            "processes": ["powershell.exe", "explorer.exe", "poisonfrog.ps1"],
        },
    }])

    _assert("/" not in terms.get("urls", []), "Path-only slash URL was kept as an exact retrieval URL")
    _assert("powershell.exe" not in terms.get("keywords", []), "Common process name was kept as a retrieval keyword")
    _assert("explorer.exe" not in terms.get("keywords", []), "Common parent process was kept as a retrieval keyword")
    _assert("poisonfrog.ps1" in terms.get("keywords", []), "Specific payload filename was incorrectly filtered")


def check_context_selection_prefers_distinct_articles() -> None:
    formatter = ReportFormatter.__new__(ReportFormatter)
    docs = [
        {
            "id": 1,
            "content": "first chunk",
            "source": "custom_document",
            "metadata": {"source_document": "alpha.pdf", "chunk_index": 0},
        },
        {
            "id": 2,
            "content": "second chunk",
            "source": "custom_document",
            "metadata": {"source_document": "alpha.pdf", "chunk_index": 1},
        },
        {
            "id": 3,
            "content": "other article",
            "source": "custom_document",
            "metadata": {"source_document": "bravo.pdf", "chunk_index": 0},
        },
    ]

    selected = formatter._apply_context_source_document_diversity(docs, limit=2)
    sources = [(doc.get("metadata") or {}).get("source_document") for doc in selected]
    _assert(sources == ["alpha.pdf", "bravo.pdf"], "Repeated chunks crowded out a distinct CTI article")


def main() -> int:
    checks: list[tuple[str, Callable[[], None]]] = [
        ("article_formats_are_accepted_and_extracted", check_article_formats_are_accepted_and_extracted),
        ("docx_container_safety", check_docx_container_safety),
        ("pdf_size_limit_accepts_large_cti_reports", check_pdf_size_limit_accepts_large_cti_reports),
        ("no_actor_hardcoding_required_for_structured_inputs", check_no_actor_hardcoding_required_for_structured_inputs),
        ("exact_ioc_boundaries_and_source_artifacts", check_exact_ioc_boundaries_and_source_artifacts),
        ("evidence_strength_respects_disposition_and_behavior", check_evidence_strength_respects_disposition_and_behavior),
        ("low_signal_private_ips_not_promoted_to_cti_context", check_low_signal_private_ips_not_promoted_to_cti_context),
        ("alert_mitre_fields_are_extracted", check_alert_mitre_fields_are_extracted),
        ("low_signal_alert_terms_are_filtered", check_low_signal_alert_terms_are_filtered),
        ("context_selection_prefers_distinct_articles", check_context_selection_prefers_distinct_articles),
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
