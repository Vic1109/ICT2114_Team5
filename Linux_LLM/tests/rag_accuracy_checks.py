#!/usr/bin/env python3
"""Deterministic checks for RAG retrieval quality guardrails.

This script intentionally avoids connecting to PostgreSQL, loading embedding
models, or invoking llama.cpp. It validates the small but important matching and
evidence-audit rules that protect CTI reports from common RAG failure modes.
"""

from __future__ import annotations

import json
import importlib.util
import contextlib
import io
import sys
import tempfile
import types
from pathlib import Path
from typing import Callable

CONFIG_DIR = Path(__file__).resolve().parents[1] / "config"
if str(CONFIG_DIR) not in sys.path:
    sys.path.insert(0, str(CONFIG_DIR))


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
import validate_rag_flow  # noqa: E402
from cti_artifacts import CTIArtifactExtractor  # noqa: E402
from rag import DocumentProcessor, DocumentValidator, JSONProcessor, PDFProcessor  # noqa: E402
from report import AlertAnalyzer, RAGContextManager, ReportFormatter, ReportGenerator  # noqa: E402
from report_parser import ReportParser  # noqa: E402
from config import LLMConfig  # noqa: E402
import runtime_preflight  # noqa: E402


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


def check_source_level_pdf_artifacts_count_as_exact_evidence() -> None:
    manager = RAGContextManager.__new__(RAGContextManager)
    seaduke_hash = "a25ec7749b2de12c2a86167afa88a4dd"

    evidence = manager._exact_match_evidence(
        "Chunk text describes SeaDuke behavior but does not repeat the hash.",
        {"source_cti_artifacts": {"hashes": [seaduke_hash], "domains": ["sitebar.org"]}},
        {"hashes": [seaduke_hash]},
    )
    _assert(evidence, "Source-level PDF artifact did not count as exact evidence")

    formatter = ReportFormatter.__new__(ReportFormatter)
    annotated = formatter._annotate_context_docs(
        [
            {
                "source": "custom_document",
                "content": "Chunk text describes SeaDuke behavior but does not repeat the hash.",
                "metadata": {
                    "source_cti_artifacts": {"hashes": [seaduke_hash], "domains": ["sitebar.org"]},
                    "cti_artifact_dispositions": {"hashes": {seaduke_hash: "malicious"}},
                },
                "match_types": ["exact"],
            }
        ],
        [{"file_context": {"md5": seaduke_hash}}],
    )
    _assert(
        annotated[0]["current_ioc_overlap"].get("hashes") == [seaduke_hash],
        "Source-level PDF artifact overlap was not recorded",
    )
    _assert(
        annotated[0]["evidence_strength"] == "high",
        "Source-level PDF artifact exact overlap was not high-strength evidence",
    )


def check_malformed_url_does_not_abort_artifact_extraction() -> None:
    text = (
        "MD5 A25EC7749B2DE12C2A86167AFA88A4DD "
        "user_agent SiteBar/3.3.8 (Bookmark Server; http://sitebar.org/) "
        "malformed reference http://[not-an-ipv6]/ and payload LogonUI.exe"
    )

    artifacts = CTIArtifactExtractor.extract(text)

    _assert(
        "a25ec7749b2de12c2a86167afa88a4dd" in artifacts.get("hashes", []),
        "Malformed URL aborted Seaduke hash extraction",
    )
    _assert(
        "sitebar.org" in artifacts.get("domains", []),
        "Valid Seaduke domain was lost when another URL was malformed",
    )


def check_named_threat_actor_alias_extraction() -> None:
    artifacts = CTIArtifactExtractor.extract(
        "SeaDuke is associated with APT29 and Cozy Bear. "
        "Carbanak, OilRig, Sandworm, and Wizard Spider are also tracked actors. "
        "Threat actor aliases: CozyDuke and Office Monkeys."
    )
    actors = set(artifacts.get("threat_actors", []))
    related_aliases = set(artifacts.get("threat_actor_aliases", []))

    for actor in ("SEADUKE", "APT29", "COZY BEAR", "CARBANAK", "OILRIG", "SANDWORM", "WIZARD SPIDER"):
        _assert(actor in actors, f"Named threat actor alias missing: {actor}")
    for alias in ("COZYDUKE", "OFFICE MONKEYS"):
        _assert(alias in related_aliases, f"Related threat actor alias missing: {alias}")
        _assert(alias not in actors, f"Related alias was incorrectly promoted as directly observed actor: {alias}")


def check_document_identity_used_for_pdf_actor_extraction() -> None:
    artifact_text = DocumentProcessor._artifact_extraction_text(
        "Threat actor: SeaDuke. The body describes malware execution and persistence.",
        "Seaduke.pdf",
        {"title": "Latest Weapon in the Duke Armory", "aliases": ["APT29", "Cozy Bear"]},
    )
    artifacts = CTIArtifactExtractor.extract(artifact_text)
    actors = artifacts.get("threat_actors", [])
    related_aliases = artifacts.get("threat_actor_aliases", [])
    _assert("SEADUKE" in actors, "Explicit PDF actor context was not extracted")
    _assert("APT29" in related_aliases, "Explicit PDF actor alias metadata did not preserve APT29")
    _assert("COZY BEAR" in related_aliases, "Explicit PDF actor alias metadata did not preserve Cozy Bear")


def check_file_names_do_not_become_domains() -> None:
    artifacts = CTIArtifactExtractor.extract(
        "Payloads included micro.docx, adobeupdatetool.vbs, Target.lnk, "
        "Invoice_29557473.exe, and callback updates.example.com."
    )

    domains = set(artifacts.get("domains", []))
    _assert("updates.example.com" in domains, "Real callback domain was filtered")
    _assert("micro.docx" not in domains, "Office document filename became a domain")
    _assert("adobeupdatetool.vbs" not in domains, "Script filename became a domain")
    _assert("target.lnk" not in domains, "Shortcut filename became a domain")


def check_pdf_sentence_fragments_do_not_become_domains() -> None:
    artifacts = CTIArtifactExtractor.extract(
        "The actor moved across the environment.The activity continued. "
        "Payment.This sentence boundary is not a domain. "
        "Code showed sys.path.append, f.read, item.name, and Target.lnkhttps noise. "
        "The report was research.By an analyst. "
        "Other PDF fragments include zlib.decompress and ransomware.despite. "
        "Real indicators included mazenews.topdomainshttps and canada-post.icuh."
    )
    domains = set(artifacts.get("domains", []))

    _assert("mazenews.top" in domains, "Real .top IoC was filtered")
    _assert("canada-post.icu" in domains, "Real .icu IoC was filtered")
    _assert("environment.the" not in domains, "PDF sentence fragment became a domain")
    _assert("payment.this" not in domains, "PDF sentence fragment became a domain")
    _assert("sys.path.append" not in domains, "Python dotted identifier became a domain")
    _assert("f.read" not in domains, "Code method call became a domain")
    _assert("item.name" not in domains, "Object property name became a domain")
    _assert("research.by" not in domains, "PDF prose fragment became a domain")
    _assert("zlib.decompress" not in domains, "Code/library fragment became a domain")
    _assert("ransomware.despite" not in domains, "PDF prose fragment became a domain")
    _assert("target.lnkhttps" not in domains, "PDF path/protocol glue became a domain")


def check_uncommon_tlds_remain_extractable() -> None:
    artifacts = CTIArtifactExtractor.extract(
        "Threat infrastructure included fastflux.cfd, update.monster, panel.lol, "
        "and xn--malware-9d0b.example."
    )
    domains = set(artifacts.get("domains", []))
    context_domains = set(CTIArtifactExtractor.for_cti_context(artifacts).get("domains", []))

    _assert("fastflux.cfd" in domains, "Uncommon .cfd IoC was filtered")
    _assert("update.monster" in domains, "Uncommon .monster IoC was filtered")
    _assert("panel.lol" in domains, "Uncommon .lol IoC was filtered")
    _assert("xn--malware-9d0b.example" in domains, "Punycode-style IoC was filtered")
    _assert("fastflux.cfd" in context_domains, "Uncommon .cfd IoC was not promoted to CTI context")
    _assert("update.monster" in context_domains, "Uncommon .monster IoC was not promoted to CTI context")
    _assert("panel.lol" in context_domains, "Uncommon .lol IoC was not promoted to CTI context")


def check_pdf_onion_domain_glue_is_repaired() -> None:
    artifacts = CTIArtifactExtractor.extract(
        "Related domains aoacugmutagkwctu.onionmazedecrypt.top and "
        "maze-relateddomainsaoacugmutagkwctu.onion were listed."
    )
    domains = set(artifacts.get("domains", []))
    context_domains = set(CTIArtifactExtractor.for_cti_context(artifacts).get("domains", []))

    _assert("aoacugmutagkwctu.onion" in domains, "Onion IoC was not recovered from PDF glue")
    _assert("mazedecrypt.top" in domains, "Adjacent .top domain was not recovered from onion glue")
    _assert("aoacugmutagkwctu.onionmazedecrypt.top" not in domains, "Glued onion/domain artifact was retained")
    _assert("maze-relateddomainsaoacugmutagkwctu.onion" not in domains, "Heading-prefixed onion artifact was retained")
    _assert("aoacugmutagkwctu.onion" in context_domains, "Recovered onion IoC was not promoted to CTI context")


def check_reference_domains_not_promoted_to_cti_context() -> None:
    artifacts = CTIArtifactExtractor.extract(
        "Report references https://unit42.paloaltonetworks.com/report and "
        "https://www.trustwave.com/blog, but IoCs are sitebar.org and mazenews.top."
    )
    context = CTIArtifactExtractor.for_cti_context(artifacts)
    domains = set(context.get("domains", []))

    _assert("sitebar.org" in domains, "Real domain IoC was filtered from CTI context")
    _assert("mazenews.top" in domains, "Real domain IoC was filtered from CTI context")
    _assert(
        "unit42.paloaltonetworks.com" not in domains,
        "Reference vendor domain was promoted into CTI context",
    )
    _assert("www.trustwave.com" not in domains, "Reference vendor domain was promoted into CTI context")


def check_concatenated_pdf_urls_are_split() -> None:
    artifacts = CTIArtifactExtractor.extract(
        "References https://cloud.google.com/contact/https://download.example.com/stage1.exe"
        "https://c2.example.net/a--- footer text"
    )
    urls = set(artifacts.get("urls", []))

    _assert("https://cloud.google.com/contact/" in urls, "First concatenated URL was not retained")
    _assert("https://download.example.com/stage1.exe" in urls, "Second concatenated URL was not split out")
    _assert("https://c2.example.net/a" in urls, "Third concatenated URL was not split out")
    _assert(
        all(value.count("https://") <= 1 for value in urls),
        "Concatenated PDF URL remained as a single artifact",
    )


def check_defanged_and_wrapped_ioc_extraction() -> None:
    text = (
        "Indicators include hxxp[:]//payload[.]example[.]com/a.exe and "
        "wrapped domain update\n.example.net plus wrapped MD5 "
        "A25EC7749B2DE12C2\nA86167AFA88A4DD."
    )
    artifacts = CTIArtifactExtractor.extract(text)

    _assert(
        "http://payload.example.com/a.exe" in artifacts.get("urls", []),
        "Defanged URL was not refanged for extraction",
    )
    _assert(
        "payload.example.com" in artifacts.get("domains", []),
        "Defanged URL host was not extracted",
    )
    _assert(
        "update.example.net" in artifacts.get("domains", []),
        "Line-wrapped domain was not recovered",
    )
    _assert(
        "a25ec7749b2de12c2a86167afa88a4dd" in artifacts.get("hashes", []),
        "Line-wrapped hash was not recovered",
    )


def check_pdf_table_ips_not_concatenated() -> None:
    text = """
        a4cbb7167176990d5a8d24e9

        91.218.114.11

        91.218.114.25

        91.218.114.26
    """
    artifacts = CTIArtifactExtractor.extract(text)
    ips = artifacts.get("ips", [])

    _assert("91.218.114.11" in ips, "First table-listed IP was lost during line-wrap normalization")
    _assert("91.218.114.25" in ips, "Second table-listed IP was lost during line-wrap normalization")
    _assert("91.218.114.26" in ips, "Third table-listed IP was lost during line-wrap normalization")
    _assert(
        all("91.218.114.1191" not in ip for ip in ips),
        "PDF table-listed IPs were concatenated into an invalid run",
    )


def check_pdf_annotation_link_filtering() -> None:
    _assert(
        not PDFProcessor._should_include_link("https://www.w3.org/1999/xhtml", "Navigation footer"),
        "Generic PDF annotation reference link was retained as CTI context",
    )
    _assert(
        PDFProcessor._should_include_link(
            "https://download.example.com/stage1.exe",
            "Payload delivery instructions",
        ),
        "Payload-like PDF annotation link was filtered out",
    )


def check_pdf_fallback_merge_only_when_useful() -> None:
    primary = "Campaign narrative mentions SeaDuke but no appendix indicators. " * 30
    fallback = (
        "Appendix MD5 A25EC7749B2DE12C2A86167AFA88A4DD and domain sitebar.org. "
        "This prose should not be copied when primary extraction is already dense."
    )
    merged, metadata = PDFProcessor._merge_fallback_text_if_useful(primary, fallback, pages=4)

    _assert(metadata.get("fallback_used") is True, "Useful pypdf fallback was not merged")
    _assert("SECONDARY PDF EXTRACTION" in merged, "Merged fallback section marker missing")
    _assert("a25ec7749b2de12c2a86167afa88a4dd" in merged.lower(), "Recovered hash missing from concise fallback section")
    _assert("sitebar.org" in merged, "Recovered domain missing from concise fallback section")
    _assert("This prose should not be copied" not in merged, "Dense-primary fallback copied duplicate prose")
    _assert(
        metadata.get("fallback_added_artifacts", {}).get("hashes") == 1,
        "Fallback-added hash count missing",
    )

    duplicate, duplicate_metadata = PDFProcessor._merge_fallback_text_if_useful(
        "Same narrative with sitebar.org.",
        "Same narrative with sitebar.org.",
        pages=1,
    )
    _assert(duplicate_metadata.get("fallback_used") is False, "Duplicate fallback text was merged")
    _assert("SECONDARY PDF EXTRACTION" not in duplicate, "Duplicate fallback marker was inserted")

    low_signal, low_signal_metadata = PDFProcessor._merge_fallback_text_if_useful(
        "Adequate primary extraction " * 80,
        "Fallback only adds 192.168.56.10 and 8.8.8.8.",
        pages=1,
    )
    _assert(low_signal_metadata.get("fallback_used") is False, "Low-signal fallback artifacts triggered merge")
    _assert("SECONDARY PDF EXTRACTION" not in low_signal, "Low-signal fallback marker was inserted")


def check_json_cti_summary_ingestion() -> None:
    summary = {
        "report_id": "apt29-seaduke",
        "title": "SeaDuke: Latest Weapon in the Duke Armory",
        "severity": "high",
        "aliases": ["SeaDuke", "APT29", "Cozy Bear", "CozyDuke"],
        "observables": [
            "A25EC7749B2DE12C2A86167AFA88A4DD",
            "http://sitebar.org/",
            "sitebar.org",
            "LogonUI.exe",
        ],
        "mitre_attack": ["T1547 - Boot or Logon Autostart Execution", "T1105 - Ingress Tool Transfer"],
        "recommended_actions": ["Hunt endpoint, proxy, DNS, and EDR telemetry for the listed observables"],
    }
    payload = json.dumps(summary).encode("utf-8")

    valid, message = DocumentValidator.validate_file("Seaduke.json", payload)
    _assert(valid, f"JSON CTI summary upload was rejected: {message}")

    text, metadata = JSONProcessor.extract_text_and_metadata(payload, "Seaduke.json")
    artifacts = CTIArtifactExtractor.extract(text)

    _assert(metadata["type"] == "json", "JSON metadata type was not preserved")
    _assert("SeaDuke" in text and "LogonUI.exe" in text, "JSON CTI fields were lost in RAG text")
    _assert(
        "a25ec7749b2de12c2a86167afa88a4dd" in artifacts.get("hashes", []),
        "Seaduke hash was not extractable from JSON summary text",
    )
    _assert("sitebar.org" in artifacts.get("domains", []), "Seaduke domain missing from JSON summary text")
    _assert("APT29" in artifacts.get("threat_actor_aliases", []), "APT29 alias missing from JSON summary text")
    _assert(
        "APT29" not in artifacts.get("threat_actors", []),
        "Ambiguous JSON alias was incorrectly promoted to direct actor evidence",
    )


def check_stix_json_structured_artifact_ingestion() -> None:
    stix_bundle = {
        "type": "bundle",
        "id": "bundle--11111111-1111-4111-8111-111111111111",
        "objects": [
            {
                "type": "threat-actor",
                "id": "threat-actor--22222222-2222-4222-8222-222222222222",
                "name": "Crimson Lynx",
                "aliases": ["CL-2026"],
            },
            {
                "type": "intrusion-set",
                "id": "intrusion-set--33333333-3333-4333-8333-333333333333",
                "name": "Amber Tempest",
            },
            {
                "type": "malware",
                "id": "malware--44444444-4444-4444-8444-444444444444",
                "name": "WispRAT",
            },
            {
                "type": "campaign",
                "id": "campaign--77777777-7777-4777-8777-777777777777",
                "name": "Operation Northstar Test",
            },
            {
                "type": "tool",
                "id": "tool--88888888-8888-4888-8888-888888888888",
                "name": "CloudSweep",
                "description": "Only the name should be treated as the tool artifact.",
            },
            {
                "type": "course-of-action",
                "id": "course-of-action--bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                "name": "Disable Script Interpreter Abuse",
                "description": "Restrict script interpreter access for untrusted users.",
            },
            {
                "type": "indicator",
                "id": "indicator--55555555-5555-4555-8555-555555555555",
                "name": "Crimson Lynx C2",
                "pattern": "[domain-name:value = 'c2.nebula-example.net']",
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--66666666-6666-4666-8666-666666666666",
                "name": "Command and Scripting Interpreter",
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": "T1059",
                        "url": "https://attack.mitre.org/techniques/T1059/",
                    }
                ],
            },
            {
                "type": "relationship",
                "id": "relationship--99999999-9999-4999-8999-999999999999",
                "relationship_type": "uses",
                "source_ref": "threat-actor--22222222-2222-4222-8222-222222222222",
                "target_ref": "malware--44444444-4444-4444-8444-444444444444",
            },
            {
                "type": "relationship",
                "id": "relationship--aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                "relationship_type": "uses",
                "source_ref": "threat-actor--22222222-2222-4222-8222-222222222222",
                "target_ref": "tool--88888888-8888-4888-8888-888888888888",
            },
            {
                "type": "relationship",
                "id": "relationship--cccccccc-cccc-4ccc-8ccc-cccccccccccc",
                "relationship_type": "mitigates",
                "source_ref": "course-of-action--bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                "target_ref": "attack-pattern--66666666-6666-4666-8666-666666666666",
            },
        ],
    }
    payload = json.dumps(stix_bundle).encode("utf-8")

    text, metadata = JSONProcessor.extract_text_and_metadata(payload, "generic-stix.json")
    artifacts = metadata.get("structured_cti_artifacts") or {}

    _assert(metadata.get("stix_type") == "bundle", "STIX bundle type was not captured in JSON metadata")
    _assert(metadata.get("stix_object_count") == 11, "STIX object count was not captured")
    _assert("Crimson Lynx" in artifacts.get("threat_actors", []), "Generic STIX threat actor was not extracted")
    _assert("Amber Tempest" in artifacts.get("threat_actors", []), "Generic STIX intrusion set was not extracted as actor context")
    _assert("WispRAT" in artifacts.get("malware_families", []), "Generic STIX malware family was not extracted")
    _assert("Operation Northstar Test" in artifacts.get("campaigns", []), "Generic STIX campaign was not extracted")
    _assert("CloudSweep" in artifacts.get("tools", []), "Generic STIX tool was not extracted")
    _assert(
        "Disable Script Interpreter Abuse" in artifacts.get("courses_of_action", []),
        "Generic STIX course-of-action was not extracted",
    )
    _assert(
        "Only the name should be treated as the tool artifact." not in artifacts.get("tools", []),
        "STIX tool description leaked into tool artifact names",
    )
    _assert("c2.nebula-example.net" in artifacts.get("domains", []), "STIX indicator domain was not extracted")
    _assert("T1059" in artifacts.get("mitre_techniques", []), "STIX ATT&CK external_id was not extracted")
    _assert("Crimson Lynx" in text and "WispRAT" in text, "STIX JSON content was not preserved for RAG text")
    _assert(
        "Crimson Lynx (threat-actor) uses WispRAT (malware)" in text,
        "STIX relationship summary did not resolve actor-to-malware relationship",
    )
    _assert(
        "Crimson Lynx (threat-actor) uses CloudSweep (tool)" in text,
        "STIX relationship summary did not resolve actor-to-tool relationship",
    )
    _assert(
        "Disable Script Interpreter Abuse (course-of-action) mitigates Command and Scripting Interpreter (attack-pattern)" in text,
        "STIX relationship summary did not resolve mitigation relationship",
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        processor = DocumentProcessor(uploads_dir=tmpdir)
        with contextlib.redirect_stdout(io.StringIO()):
            _processed_text, processed_metadata = processor.process_upload(
                payload,
                "generic-stix.json",
                save_to_disk=False,
            )

    processed_artifacts = processed_metadata.get("cti_artifacts") or {}
    _assert(
        "Crimson Lynx" in processed_artifacts.get("threat_actors", []),
        "Structured STIX actor was not merged into processed CTI artifacts",
    )
    _assert(
        "WispRAT" in processed_artifacts.get("malware_families", []),
        "Structured STIX malware family was not merged into processed CTI artifacts",
    )
    _assert(
        "Disable Script Interpreter Abuse" in processed_artifacts.get("courses_of_action", []),
        "Structured STIX course-of-action was not merged into processed CTI artifacts",
    )


def check_document_processor_version_metadata() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        processor = DocumentProcessor(uploads_dir=tmpdir)
        with contextlib.redirect_stdout(io.StringIO()):
            _text, metadata = processor.process_upload(
                b"Threat actor SeaDuke used sitebar.org.",
                "seaduke-notes.txt",
                save_to_disk=False,
            )

    _assert(
        metadata.get("processor_version") == CTIArtifactExtractor.EXTRACTION_PIPELINE_VERSION,
        "Processed document metadata lacks current extraction pipeline version",
    )


def check_document_processor_duplicate_tracking_reset() -> None:
    payload = b"Threat actor SeaDuke used sitebar.org and LogonUI.exe."

    with tempfile.TemporaryDirectory() as tmpdir:
        processor = DocumentProcessor(uploads_dir=tmpdir)
        with contextlib.redirect_stdout(io.StringIO()):
            processor.process_upload(
                payload,
                "seaduke-notes.txt",
                save_to_disk=False,
            )

        is_duplicate, duplicate_message = processor.check_duplicate(payload, "seaduke-notes.txt")
        _assert(is_duplicate, "Processed upload was not tracked as a duplicate")
        _assert("already been processed" in duplicate_message, "Duplicate message did not explain processed hash state")

        processor.processing_hashes.add("inflight-test-hash")
        reset_counts = processor.reset_duplicate_tracking()
        _assert(reset_counts["processed_hashes_cleared"] == 1, "Processed hash reset count was incorrect")
        _assert(reset_counts["processing_hashes_cleared"] == 1, "Processing hash reset count was incorrect")

        is_duplicate_after_reset, _hash_or_message = processor.check_duplicate(payload, "seaduke-notes.txt")
        _assert(not is_duplicate_after_reset, "RAG clear would still block re-uploading the same CTI document")


def check_rag_status_warns_on_stale_processor_version() -> None:
    _assert(
        CTIArtifactExtractor.EXTRACTION_PIPELINE_VERSION == "2026-07-cti-rag-v4",
        "Extraction pipeline version was not bumped after CTI/STIX RAG extraction semantics changed",
    )

    class FakeCursor:
        def __init__(self):
            self.params = None

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def execute(self, _query, params=None):
            self.params = params

        def fetchone(self):
            return (10, 10, 5, 5, 2, 2, 3, 1)

    class FakeConnection:
        def __init__(self):
            self.cursor_obj = FakeCursor()

        def cursor(self):
            return self.cursor_obj

    manager = RAGContextManager.__new__(RAGContextManager)
    manager.db_lock = report_module.threading.RLock()
    manager.conn = FakeConnection()
    manager.rag_ready = False
    manager.embedding_model = "test-model"
    manager.embedding_device = "cpu"
    manager.embedding_devices = []
    manager.vector_dimensions = 384
    manager.embedding_batch_size = 1
    manager.embedding_multi_gpu_min_chunks = 64
    manager.normalize_embeddings = False
    manager.similarity_threshold = 0.2
    manager.retrieval_candidate_multiplier = 4
    manager.embedding_query_instruction = "query"
    manager.embedding_document_instruction = ""
    manager.max_retrieval_docs = 10

    status = manager.get_rag_status()

    _assert(status["ready"] is True, "RAG status did not remain ready with stale documents")
    _assert(status["current_processor_version"] == CTIArtifactExtractor.EXTRACTION_PIPELINE_VERSION, "Current processor version missing")
    _assert(status["stale_custom_doc_chunks"] == 3, "Stale chunk count missing from RAG status")
    _assert(status["stale_uploaded_documents"] == 1, "Stale source document count missing from RAG status")
    _assert(status["rag_rebuild_recommended"] is True, "RAG rebuild recommendation missing")
    _assert(status["warnings"], "Stale RAG warning missing")
    _assert(
        manager.conn.cursor_obj.params == (
            CTIArtifactExtractor.EXTRACTION_PIPELINE_VERSION,
            CTIArtifactExtractor.EXTRACTION_PIPELINE_VERSION,
        ),
        "RAG status did not query stale documents against current processor version",
    )


def check_exact_document_condition_uses_structured_artifacts() -> None:
    manager = RAGContextManager.__new__(RAGContextManager)
    condition, params = manager._exact_document_condition(
        {
            "hashes": ["A25EC7749B2DE12C2A86167AFA88A4DD"],
            "domains": ["sitebar.org"],
            "cves": ["CVE-2018-8174"],
            "mitre_techniques": ["T1203"],
            "threat_actor_aliases": ["APT29"],
            "malware_families": ["WispRAT"],
            "campaigns": ["Operation Northstar Test"],
            "tools": ["CloudSweep"],
            "courses_of_action": ["Disable Script Interpreter Abuse"],
            "keywords": ["LogonUI.exe"],
        }
    )

    _assert("metadata->'cti_artifacts'->'hashes'" in condition, "Hash exact search did not use structured CTI artifacts")
    _assert("metadata->'source_cti_artifacts'->'hashes'" in condition, "Hash exact search did not use source-level CTI artifacts")
    _assert("metadata->'cti_artifacts'->'domains'" in condition, "Domain exact search did not use structured CTI artifacts")
    _assert("metadata->'source_cti_artifacts'->'domains'" in condition, "Domain exact search did not use source-level CTI artifacts")
    _assert("metadata->'cti_artifacts'->'cves'" in condition, "CVE exact search did not use structured CTI artifacts")
    _assert("metadata->'source_cti_artifacts'->'cves'" in condition, "CVE exact search did not use source-level CTI artifacts")
    _assert("metadata->'cti_artifacts'->'mitre_techniques'" in condition, "MITRE exact search did not use structured CTI artifacts")
    _assert("metadata->'source_cti_artifacts'->'mitre_techniques'" in condition, "MITRE exact search did not use source-level CTI artifacts")
    _assert("metadata->'cti_artifacts'->'threat_actor_aliases'" in condition, "Related actor alias exact search did not use structured CTI artifacts")
    _assert("metadata->'cti_artifacts'->'malware_families'" in condition, "Malware exact search did not use structured CTI artifacts")
    _assert("metadata->'cti_artifacts'->'campaigns'" in condition, "Campaign exact search did not use structured CTI artifacts")
    _assert("metadata->'cti_artifacts'->'tools'" in condition, "Tool exact search did not use structured CTI artifacts")
    _assert("metadata->'cti_artifacts'->'courses_of_action'" in condition, "Course-of-action exact search did not use structured CTI artifacts")
    _assert(any(
        isinstance(param, list) and "a25ec7749b2de12c2a86167afa88a4dd" in param
        for param in params
    ), "Hash exact search parameters were not case-folded")
    _assert("content ILIKE ANY" in condition, "Raw content fallback was removed from exact document search")
    evidence = manager._exact_match_evidence(
        "Technique and vulnerability are captured in structured metadata.",
        {"cti_artifacts": {"cves": ["CVE-2018-8174"], "mitre_techniques": ["T1203"], "threat_actor_aliases": ["APT29"]}},
        {"cves": ["CVE-2018-8174"], "mitre_techniques": ["T1203"], "threat_actor_aliases": ["APT29"]},
    )
    _assert(
        any("cve matched extracted CTI artifact CVE-2018-8174" in item for item in evidence),
        "CVE structured artifact match did not produce exact evidence",
    )
    _assert(
        any("mitre technique matched extracted CTI artifact T1203" in item for item in evidence),
        "MITRE structured artifact match did not produce exact evidence",
    )
    _assert(
        any("related actor alias matched extracted CTI artifact APT29" in item for item in evidence),
        "Related actor alias structured artifact match did not produce exact evidence",
    )


def check_exact_document_condition_filters_private_endpoint_ips() -> None:
    manager = RAGContextManager.__new__(RAGContextManager)
    _condition, params = manager._exact_document_condition(
        {
            "source_ips": ["91.218.114.11"],
            "destination_ips": ["192.168.56.10"],
            "ips": ["91.218.114.11", "192.168.56.10", "10.0.0.5"],
            "domains": ["sitebar.org"],
        }
    )

    flattened = []
    for param in params:
        if isinstance(param, list):
            flattened.extend(param)
        else:
            flattened.append(param)
    joined = " ".join(str(value).lower() for value in flattened)

    _assert("91.218.114.11" in joined, "Public source IP was removed from uploaded CTI exact matching")
    _assert("192.168.56.10" not in joined, "Private destination IP leaked into uploaded CTI exact matching")
    _assert("10.0.0.5" not in joined, "Private IP artifact leaked into uploaded CTI exact matching")
    _assert("sitebar.org" in joined, "Domain IoC was removed from uploaded CTI exact matching")


def check_exact_document_condition_prefers_attacker_cti_ips() -> None:
    manager = RAGContextManager.__new__(RAGContextManager)
    _condition, params = manager._exact_document_condition(
        {
            "cti_ips": ["91.218.114.11", "8.8.8.8"],
            "ips": ["91.218.114.11", "66.96.12.44", "8.8.8.8"],
            "domains": ["mail-edge-01.victim.local"],
        }
    )

    joined = " ".join(
        str(item).lower()
        for param in params
        for item in (param if isinstance(param, list) else [param])
    )
    _assert("91.218.114.11" in joined, "Attacker CTI IP missing from uploaded CTI exact matching")
    _assert("66.96.12.44" not in joined, "Protected public destination IP leaked into uploaded CTI exact matching")
    _assert("8.8.8.8" not in joined, "Low-signal resolver IP leaked into uploaded CTI exact matching")

    formatter = ReportFormatter.__new__(ReportFormatter)
    formatter.rag_manager = RAGContextManager.__new__(RAGContextManager)
    analyzer = AlertAnalyzer(asset_config=None)
    cleaned = analyzer.clean_log_data([
        {
            "timestamp": "2026-06-05T08:00:00.000+0000",
            "rule": {"level": 11, "id": "100141", "description": "ET EXPLOIT Possible CVE-2018-8174 exploit attempt"},
            "agent": {"ip": "66.96.12.44", "name": "mail-edge-01"},
            "data": {
                "src_ip": "91.218.114.11",
                "dest_ip": "66.96.12.44",
                "src_port": 37881,
                "dest_port": 80,
                "proto": "TCP",
                "app_proto": "http",
                "event_type": "alert",
                "direction": "inbound",
                "alert": {
                    "signature": "ET EXPLOIT Possible CVE-2018-8174 exploit attempt",
                    "signature_id": 2026141,
                },
                "http": {"hostname": "mail-edge-01.victim.local", "http_method": "POST", "url": "/exploit/cve-2018-8174"},
            },
        }
    ])
    exact_terms = formatter._build_exact_terms_from_alerts(cleaned)
    _assert(exact_terms.get("cti_ips") == ["91.218.114.11"], "Inbound protected-asset alert did not isolate source as CTI IP")
    _assert("66.96.12.44" in exact_terms.get("ips", []), "Archive exact IP terms lost observed destination IP")
    _assert("CVE-2018-8174" in exact_terms.get("cves", []), "Alert CVE did not become an exact document retrieval term")


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
                "cves": ["CVE-2024-9999"],
                "mitre_techniques": ["T1105"],
                "threat_actors": ["Crimson Lynx"],
                "threat_actor_aliases": ["Amber Tempest"],
                "malware_families": ["WispRAT"],
                "campaigns": ["Operation Northstar Test"],
                "tools": ["CloudSweep"],
                "courses_of_action": ["Disable Script Interpreter Abuse"],
            },
            "threat_context": {
                "actor": "Amber Tempest",
                "campaign": "Operation Shadow Trail",
                "malware_family": "NightRAT",
                "tool": "CloudSweep",
            },
        }
    )

    _assert(
        "ABCDEF1234567890ABCDEF1234567890" in observed.get("hashes", []),
        "Raw alert hash artifact was not promoted for retrieval",
    )
    _assert("evil.example" in observed.get("domains", []), "Raw alert domain artifact missing")
    _assert("CVE-2024-9999" in observed.get("cves", []), "Raw alert CVE artifact missing")
    _assert("T1105" in observed.get("mitre_techniques", []), "Raw alert MITRE artifact missing")
    _assert("Crimson Lynx" in observed.get("threat_actors", []), "Raw alert actor artifact missing")
    _assert("Amber Tempest" in observed.get("threat_actor_aliases", []), "Raw alert related actor alias artifact missing")
    _assert("Amber Tempest" in observed.get("threat_actors", []), "Threat context actor missing from observed IoCs")
    _assert("WispRAT" in observed.get("malware_families", []), "Raw alert malware artifact missing")
    _assert("NightRAT" in observed.get("malware_families", []), "Threat context malware family missing from observed IoCs")
    _assert("Operation Northstar Test" in observed.get("campaigns", []), "Raw alert campaign artifact missing")
    _assert("Operation Shadow Trail" in observed.get("campaigns", []), "Threat context campaign missing from observed IoCs")
    _assert("CloudSweep" in observed.get("tools", []), "Tool artifact missing from observed IoCs")
    _assert("Disable Script Interpreter Abuse" in observed.get("courses_of_action", []), "Course-of-action artifact missing from observed IoCs")

    formatter = ReportFormatter.__new__(ReportFormatter)
    exact_terms = formatter._build_exact_terms_from_alerts([{"observed_iocs": observed}])
    _assert(
        "ABCDEF1234567890ABCDEF1234567890" in exact_terms.get("hashes", []),
        "Raw alert hash did not become an exact hash retrieval term",
    )
    _assert("CVE-2024-9999" in exact_terms.get("cves", []), "Raw alert CVE did not become an exact retrieval term")
    _assert("T1105" in exact_terms.get("mitre_techniques", []), "Raw alert MITRE ID did not become an exact retrieval term")
    _assert("Crimson Lynx" in exact_terms.get("threat_actors", []), "Raw alert actor did not become an exact retrieval term")
    _assert("Amber Tempest" in exact_terms.get("threat_actor_aliases", []), "Raw alert related actor alias did not become an exact retrieval term")
    _assert("Operation Northstar Test" in exact_terms.get("campaigns", []), "Raw alert campaign did not become an exact retrieval term")
    _assert("Operation Northstar Test" not in exact_terms.get("threat_actors", []), "Campaign leaked into threat actor exact terms")
    _assert("WispRAT" in exact_terms.get("malware_families", []), "Raw alert malware did not become an exact retrieval term")
    _assert("CloudSweep" in exact_terms.get("tools", []), "Raw alert tool did not become an exact retrieval term")
    _assert(
        "Disable Script Interpreter Abuse" in exact_terms.get("courses_of_action", []),
        "Course-of-action did not become an exact retrieval term",
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


def check_low_signal_values_not_promoted_as_cti_context() -> None:
    artifacts = CTIArtifactExtractor.extract(
        "Report template linked www.w3.org and community.riskiq.com; "
        "DNS test used 8.8.8.8; real callback was payload.example.com."
    )
    context_artifacts = CTIArtifactExtractor.for_cti_context(artifacts)

    _assert("www.w3.org" in artifacts.get("domains", []), "Raw low-signal domain was not preserved")
    _assert("8.8.8.8" in artifacts.get("ips", []), "Raw public DNS IP was not preserved")
    _assert("www.w3.org" not in context_artifacts.get("domains", []), "W3C domain was promoted as CTI")
    _assert("community.riskiq.com" not in context_artifacts.get("domains", []), "Threat-intel portal domain was promoted as CTI")
    _assert("8.8.8.8" not in context_artifacts.get("ips", []), "Public DNS IP was promoted as CTI")
    _assert("payload.example.com" in context_artifacts.get("domains", []), "Real callback domain was filtered")


def check_low_signal_alert_terms_not_used_for_cti_exact_search() -> None:
    formatter = ReportFormatter.__new__(ReportFormatter)
    exact_terms = formatter._build_exact_terms_from_alerts(
        [
            {
                "src_ip": "8.8.8.8",
                "dest_ip": "10.0.0.5",
                "http_context": {"hostname": "www.w3.org", "url": "https://www.w3.org/1999/xhtml"},
                "observed_iocs": {
                    "ips": ["8.8.8.8", "203.0.113.77"],
                    "domains": ["www.w3.org", "payload.example.com"],
                },
            }
        ]
    )

    _assert("8.8.8.8" in exact_terms.get("source_ips", []), "Source IP archive hint was removed")
    _assert("8.8.8.8" not in exact_terms.get("ips", []), "Public DNS IP became CTI exact term")
    _assert("www.w3.org" not in exact_terms.get("domains", []), "W3C domain became CTI exact term")
    _assert("payload.example.com" in exact_terms.get("domains", []), "Real domain exact term was filtered")


def check_generic_alert_words_not_high_signal() -> None:
    for value in ("MALWARE", "PHISHING", "Suspicious", "archive", "delivered", "executable", "notification"):
        _assert(
            not RAGContextManager._is_high_signal_search_value(value),
            f"Generic alert word remained high-signal: {value}",
        )

    _assert(
        RAGContextManager._is_high_signal_search_value("LogonUI.exe"),
        "Specific suspicious filename was filtered as generic",
    )
    _assert(
        RAGContextManager._is_high_signal_search_value("a25ec7749b2de12c2a86167afa88a4dd"),
        "Hash was filtered as generic",
    )


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


def check_weak_exact_overlap_not_high_confidence() -> None:
    formatter = ReportFormatter.__new__(ReportFormatter)
    annotated = formatter._annotate_context_docs(
        [
            {
                "source": "custom_document",
                "content": "Historical CTI maps credential attacks to T1110.",
                "metadata": {"cti_artifacts": {"mitre_techniques": ["T1110"]}},
                "match_types": ["exact"],
                "match_evidence": ["indicator matched content T1110"],
            }
        ],
        [{"mitre_context": {"id": ["T1110"]}}],
    )

    _assert(
        annotated[0]["evidence_strength"] == "medium",
        "Technique-only exact overlap should not be high strength",
    )
    _assert(
        "current overlap is technique/signature/context only; do not use alone for attribution"
        in annotated[0]["retrieval_cautions"],
        "Weak-overlap attribution caution missing",
    )

    hash_annotated = formatter._annotate_context_docs(
        [
            {
                "source": "custom_document",
                "content": "Historical CTI lists MD5 a25ec7749b2de12c2a86167afa88a4dd.",
                "metadata": {"cti_artifacts": {"hashes": ["a25ec7749b2de12c2a86167afa88a4dd"]}},
                "match_types": ["exact"],
                "match_evidence": ["hash matched extracted CTI artifact"],
            }
        ],
        [{"file_context": {"md5": "a25ec7749b2de12c2a86167afa88a4dd"}}],
    )
    _assert(hash_annotated[0]["evidence_strength"] == "high", "Hash exact overlap should remain high strength")

    entity_annotated = formatter._annotate_context_docs(
        [
            {
                "source": "custom_document",
                "content": "Operation Shadow Trail uses WispRAT with CloudSweep. It also references OldRAT.",
                "metadata": {
                    "cti_artifacts": {
                        "malware_families": ["WispRAT", "OldRAT"],
                        "campaigns": ["Operation Shadow Trail"],
                        "tools": ["CloudSweep"],
                    }
                },
                "match_types": ["exact"],
                "match_evidence": ["malware family matched extracted CTI artifact WispRAT"],
            }
        ],
        [{
            "observed_iocs": {
                "malware_families": ["WispRAT"],
                "campaigns": ["Operation Shadow Trail"],
                "tools": ["CloudSweep"],
            }
        }],
    )
    _assert(
        entity_annotated[0]["current_ioc_overlap"].get("malware_families") == ["WispRAT"],
        "Malware family overlap was not recorded in current overlap",
    )
    _assert(
        entity_annotated[0]["current_ioc_overlap"].get("campaigns") == ["Operation Shadow Trail"],
        "Campaign overlap was not recorded in current overlap",
    )
    _assert(
        entity_annotated[0]["evidence_strength"] == "medium",
        "Entity-only exact overlap should remain medium-strength context",
    )
    _assert(
        "current overlap is technique/signature/context only; do not use alone for attribution"
        in entity_annotated[0]["retrieval_cautions"],
        "Entity-only overlap caution missing",
    )
    _assert(
        entity_annotated[0]["historical_only_artifacts"].get("malware_families") == ["OldRAT"],
        "Historical-only malware family was not preserved",
    )


def check_exact_candidate_scoring_prefers_current_iocs() -> None:
    hash_score = RAGContextManager._score_exact_candidate(
        ["hash matched extracted CTI artifact a25ec7749b2de12c2a86167afa88a4dd"],
        "custom_document",
    )
    domain_score = RAGContextManager._score_exact_candidate(
        ["domain matched extracted CTI artifact sitebar.org"],
        "custom_document",
    )
    weak_score = RAGContextManager._score_exact_candidate(
        ["signature matched content ET MALWARE"],
        "custom_document",
    )

    _assert(hash_score > domain_score > weak_score, "Exact candidate scoring did not prefer strong IoCs")
    _assert(hash_score >= 1.45, "Hash exact score is too low to outrank semantic neighbors")

    formatter = ReportFormatter.__new__(ReportFormatter)
    formatter.rag_manager = RAGContextManager.__new__(RAGContextManager)
    formatter.rag_manager.max_retrieval_docs = 2
    alert = {
        "file_context": {"md5": "a25ec7749b2de12c2a86167afa88a4dd"},
        "observed_iocs": {"hashes": ["a25ec7749b2de12c2a86167afa88a4dd"]},
    }
    weak_exact = {
        "id": "weak",
        "source": "custom_document",
        "content": "A generic malware report mentions ET MALWARE.",
        "metadata": {},
        "score": weak_score,
        "match_types": ["exact"],
        "match_evidence": ["signature matched content ET MALWARE"],
    }
    strong_exact = {
        "id": "strong",
        "source": "custom_document",
        "content": "SeaDuke appendix lists MD5 a25ec7749b2de12c2a86167afa88a4dd.",
        "metadata": {
            "cti_artifacts": {"hashes": ["a25ec7749b2de12c2a86167afa88a4dd"]},
            "cti_artifact_dispositions": {
                "hashes": {"a25ec7749b2de12c2a86167afa88a4dd": "malicious"}
            },
        },
        "score": hash_score,
        "match_types": ["exact"],
        "match_evidence": ["hash matched extracted CTI artifact a25ec7749b2de12c2a86167afa88a4dd"],
    }
    selected = formatter._select_relevant_context_docs([weak_exact, strong_exact], [alert], max_docs=2)
    _assert(selected[0]["id"] == "strong", "Strong exact IoC evidence did not outrank weak exact signature evidence")


def check_source_context_outranks_semantic_neighbor() -> None:
    formatter = ReportFormatter.__new__(ReportFormatter)
    formatter.rag_manager = RAGContextManager.__new__(RAGContextManager)
    formatter.rag_manager.max_retrieval_docs = 2
    alert = {
        "file_context": {"md5": "a25ec7749b2de12c2a86167afa88a4dd"},
        "behavior_tags": ["ingress_tool_transfer", "malware_execution_candidate"],
        "observed_iocs": {"hashes": ["a25ec7749b2de12c2a86167afa88a4dd"]},
    }
    semantic_neighbor = {
        "id": "carbanak_semantic",
        "source": "custom_document",
        "content": "Carbanak malware delivery through DNS TXT records.",
        "metadata": {
            "cti_behavior_tags": ["ingress_tool_transfer", "malware_execution_candidate"],
            "cti_context_labels": ["ttp_behavior"],
        },
        "score": 0.95,
        "match_types": ["semantic"],
        "match_evidence": ["semantic nearest-neighbor similarity=0.950"],
    }
    source_context = {
        "id": "seaduke_context",
        "source": "custom_document",
        "content": "SeaDuke/APT29 background, delivery infrastructure, and remediation guidance.",
        "metadata": {
            "source_cti_artifacts": {
                "hashes": ["a25ec7749b2de12c2a86167afa88a4dd"],
                "threat_actors": ["SEADUKE", "APT29"],
            },
            "cti_behavior_tags": ["ingress_tool_transfer", "malware_execution_candidate"],
            "cti_context_labels": ["attribution", "ttp_behavior", "remediation"],
        },
        "score": 1.2,
        "match_types": ["source_context"],
        "match_evidence": [
            "same uploaded CTI document as exact IoC match",
            "hash matched extracted CTI artifact a25ec7749b2de12c2a86167afa88a4dd",
        ],
        "linked_exact_match_evidence": [
            "hash matched extracted CTI artifact a25ec7749b2de12c2a86167afa88a4dd"
        ],
    }

    selected = formatter._select_relevant_context_docs([semantic_neighbor, source_context], [alert], max_docs=2)
    _assert(selected[0]["id"] == "seaduke_context", "Exact-hit source context did not outrank semantic neighbor")
    _assert(selected[0]["evidence_strength"] == "medium", "Source context should be medium-strength background")


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

    hash_gap_findings = formatter._audit_report_claims(
        "Downloaded LogonUI.exe with MD5 a25ec7749b2de12c2a86167afa88a4dd.",
        [
            {
                "source": "custom_document",
                "content": "A semantically similar malware delivery report with no matching hashes.",
                "metadata": {"cti_artifacts": {"hashes": ["eb3d0b5d91fbde4d7a58ef5b9c954051"]}},
                "match_types": ["semantic"],
                "evidence_strength": "low",
            }
        ],
        [{"file_context": {"md5": "a25ec7749b2de12c2a86167afa88a4dd"}}],
    )
    joined_hash_gap = " ".join(hash_gap_findings).lower()
    _assert("no selected high/medium-strength rag source matched current file hash" in joined_hash_gap, "Missing hash coverage warning")
    _assert("a25ec7749b2de12c2a86167afa88a4dd" in joined_hash_gap, "Missing hash value absent from coverage warning")


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

    unsupported_alias_findings = formatter._audit_report_claims(
        "SeaDuke activity is linked to this incident.",
        [
            {
                "source": "custom_document",
                "content": "Carbanak used this infrastructure in a prior campaign.",
                "metadata": {"cti_artifacts": {"ips": ["203.0.113.10"], "threat_actors": ["CARBANAK"]}},
                "evidence_strength": "high",
                "cti_context_labels": ["attribution"],
                "current_ioc_overlap": {"ips": ["203.0.113.10"]},
            }
        ],
        [{"src_ip": "203.0.113.10"}],
    )
    joined_alias_unsupported = " ".join(unsupported_alias_findings).lower()
    _assert("specific threat actor term" in joined_alias_unsupported, "Actor alias attribution warning missing")
    _assert("seaduke" in joined_alias_unsupported, "Unsupported actor alias missing from warning")

    supported_alias_findings = formatter._audit_report_claims(
        "SeaDuke activity is linked to this incident.",
        [
            {
                "source": "custom_document",
                "content": "SeaDuke used sitebar.org in a prior campaign.",
                "metadata": {"cti_artifacts": {"domains": ["sitebar.org"], "threat_actors": ["SEADUKE", "APT29"]}},
                "evidence_strength": "high",
                "cti_context_labels": ["attribution"],
                "current_ioc_overlap": {"domains": ["sitebar.org"]},
            }
        ],
        [{"http_context": {"hostname": "sitebar.org"}}],
    )
    joined_alias_supported = " ".join(supported_alias_findings).lower()
    _assert("specific threat actor term" not in joined_alias_supported, "Supported actor alias was incorrectly warned")

    related_alias_only_findings = formatter._audit_report_claims(
        "APT29 is attributed to this incident.",
        [
            {
                "source": "custom_document",
                "content": "SeaDuke infrastructure overlaps with this alert; APT29 is only retained as related alias context.",
                "metadata": {
                    "cti_artifacts": {
                        "domains": ["sitebar.org"],
                        "threat_actors": ["SEADUKE"],
                        "threat_actor_aliases": ["APT29"],
                    }
                },
                "evidence_strength": "high",
                "cti_context_labels": ["attribution"],
                "current_ioc_overlap": {"domains": ["sitebar.org"], "threat_actor_aliases": ["APT29"]},
            }
        ],
        [{"http_context": {"hostname": "sitebar.org"}, "observed_iocs": {"threat_actor_aliases": ["APT29"]}}],
    )
    joined_related_alias_only = " ".join(related_alias_only_findings).lower()
    _assert(
        "specific threat actor term" in joined_related_alias_only,
        "Related actor alias incorrectly supported direct actor attribution",
    )
    _assert("apt29" in joined_related_alias_only, "Related alias attribution warning omitted the alias value")

    victim_only_findings = formatter._audit_report_claims(
        "SeaDuke activity is linked to this incident.",
        [
            {
                "source": "custom_document",
                "content": "SeaDuke report lists victim host 10.10.10.5.",
                "metadata": {
                    "cti_artifacts": {"ips": ["10.10.10.5"], "threat_actors": ["SEADUKE"]},
                    "cti_artifact_dispositions": {"ips": {"10.10.10.5": "victim"}},
                },
                "cti_artifact_dispositions": {"ips": {"10.10.10.5": "victim"}},
                "evidence_strength": "medium",
                "cti_context_labels": ["attribution", "victim_infrastructure"],
                "current_ioc_overlap": {"ips": ["10.10.10.5"]},
            }
        ],
        [{"dest_ip": "10.10.10.5"}],
    )
    joined_victim_only = " ".join(victim_only_findings).lower()
    _assert(
        "specific threat actor term" in joined_victim_only,
        "Victim-only overlap incorrectly supported actor attribution",
    )
    _assert("seaduke" in joined_victim_only, "Victim-only unsupported actor alias missing from warning")


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

    weak_overflow = formatter._filter_context_docs_by_evidence_quality(
        [
            {"id": "low-only-1", "evidence_strength": "low"},
            {"id": "low-only-2", "evidence_strength": "low"},
            {"id": "low-only-3", "evidence_strength": "low"},
            {"id": "low-only-4", "evidence_strength": "low"},
        ],
        limit=4,
    )
    _assert(len(weak_overflow) == 2, "Weak-only semantic background was not capped")


def check_custom_docs_context_uses_persistent_fallback() -> None:
    class FakeRagManager:
        def get_recent_custom_documents(self, k: int = 4):
            return [
                {
                    "id": 42,
                    "content": (
                        "CTI Document Summary\n"
                        "Source document: Seaduke.pdf\n"
                        "CTI Context | attribution, ttp_behavior\n"
                        "CTI Behavior | malware_execution_candidate\n"
                        "SeaDuke is associated with APT29 and uses sitebar.org for payload delivery."
                    ),
                    "metadata": {
                        "filename": "Seaduke_document_summary",
                        "source_document": "Seaduke.pdf",
                        "chunk_role": "document_summary",
                        "cti_context_labels": ["attribution", "ttp_behavior"],
                        "cti_behavior_tags": ["malware_execution_candidate"],
                        "cti_artifacts": {
                            "threat_actors": ["SEADUKE", "APT29"],
                            "domains": ["sitebar.org"],
                        },
                    },
                    "source": "custom_document",
                    "match_types": ["persistent_fallback"],
                    "match_evidence": ["recent uploaded CTI document fallback"],
                }
            ][:k]

    formatter = ReportFormatter.__new__(ReportFormatter)
    formatter.rag_manager = FakeRagManager()
    formatter._search_custom_doc_results = lambda _alerts, k=4: []

    context = formatter._get_custom_docs_context([
        {
            "behavior_tags": ["malware_execution_candidate"],
            "observed_iocs": {"domains": ["sitebar.org"]},
        }
    ])

    _assert("Seaduke.pdf" in context, "Persistent uploaded CTI fallback was not included")
    _assert("persistent_fallback" in context, "Fallback source type was not exposed for analyst caution")
    _assert("APT29" in context or "SEADUKE" in context, "Actor context was lost in persistent fallback")


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

    download_alert = {
        "rule_level": 12,
        "rule_description": "Suspicious Windows payload download",
        "alert_signature": "ET MALWARE LogonUI.exe payload delivered over HTTP",
        "src_ip": "198.51.100.177",
        "dest_ip": "192.168.56.10",
        "dest_port": 80,
        "app_proto": "http",
        "threat_classification": {"threat_direction": "inbound"},
        "http_context": {
            "hostname": "sitebar.org",
            "url": "/LogonUI.exe",
            "status": 200,
        },
        "file_context": {
            "filename": "LogonUI.exe",
            "md5": "a25ec7749b2de12c2a86167afa88a4dd",
        },
    }
    download_tags = analyzer._infer_behavior_tags(download_alert)
    download_focus = analyzer._build_response_focus(download_alert, download_tags)

    _assert("ingress_tool_transfer" in download_tags, "Payload download was not tagged as ingress tool transfer")
    _assert("web_or_exploit_attempt" not in download_tags, "Plain HTTP payload download was over-classified as exploit attempt")
    _assert(any("payload" in item.lower() or "hash" in item.lower() for item in download_focus), "Payload analysis response focus missing")

    exploit_alert = {
        "rule_level": 12,
        "rule_description": "ET EXPLOIT Possible CVE-2018-8174 exploit attempt",
        "alert_signature": "Possible CVE-2018-8174 exploit attempt",
        "src_ip": "91.218.114.11",
        "dest_ip": "66.96.12.44",
        "dest_port": 80,
        "app_proto": "http",
        "threat_classification": {"threat_direction": "inbound"},
        "http_context": {"url": "/exploit/cve-2018-8174", "method": "POST", "status": 403},
    }
    exploit_tags = analyzer._infer_behavior_tags(exploit_alert)
    _assert("web_or_exploit_attempt" in exploit_tags, "CVE exploit attempt was not tagged as web/exploit")

    formatter = ReportFormatter.__new__(ReportFormatter)
    download_alert["behavior_tags"] = download_tags
    exploit_alert["behavior_tags"] = exploit_tags
    download_mitre = formatter._fallback_mitre_rows([download_alert])
    exploit_mitre = formatter._fallback_mitre_rows([exploit_alert])

    _assert(any(row["id"] == "T1105" for row in download_mitre), "Payload download fallback MITRE did not include T1105")
    _assert(not any(row["id"] == "T1190" for row in download_mitre), "Payload download fallback MITRE incorrectly included T1190")
    _assert(not any(row["id"] == "T1059" for row in download_mitre), "Payload download fallback MITRE incorrectly included T1059")
    _assert(any(row["id"] == "T1190" for row in exploit_mitre), "CVE exploit fallback MITRE did not include T1190")


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


def check_report_generation_guardrail_fallback() -> None:
    class BlankLLM:
        def __init__(self):
            self.calls = 0

        def generate_response(self, *_args, **_kwargs):
            self.calls += 1
            return "<think>reasoning only"

    formatter = ReportFormatter.__new__(ReportFormatter)
    formatter.llm_client = BlankLLM()
    alert = {
        "rule_level": 10,
        "rule_description": "ET WEB_SERVER Possible exploit attempt",
        "alert_signature": "ET WEB_SERVER Possible exploit attempt",
        "src_ip": "203.0.113.10",
        "dest_ip": "66.96.12.44",
        "dest_port": 443,
        "proto": "TCP",
        "app_proto": "http",
        "src_ip_context": "external",
        "dest_ip_context": "owned",
        "threat_classification": {"threat_direction": "inbound", "is_external_threat": True},
        "behavior_tags": ["web_or_exploit_attempt", "external_to_protected_asset"],
        "observed_iocs": {"ips": ["203.0.113.10"], "rule_ids": ["1001"]},
    }
    analysis = {
        "severity_breakdown": {"High": 1},
        "threat_classification": {
            "infrastructure_alerts": 0,
            "inbound_threats": 1,
            "outbound_threats": 0,
            "lateral_threats": 0,
        },
        "top_external_sources": {"203.0.113.10": 1},
        "protocol_breakdown": {"TCP": 1},
    }

    report = formatter._generate_llm_report_with_guardrails(
        "context",
        [alert],
        [],
        analysis,
        "manual analysis",
    )
    lower = report.lower()
    _assert("executive summary" in lower, "Fallback report missing executive summary")
    _assert("key findings" in lower, "Fallback report missing key findings")
    _assert("immediate actions" in lower, "Fallback report missing immediate actions")
    _assert("analysis complete" in lower, "Fallback report missing closure")
    _assert(formatter.llm_client.calls == 2, "LLM was not retried once before fallback")


def check_report_parser_derives_key_findings() -> None:
    markdown = """# SOC Threat Analysis Report

Generated: 2026-07-06 10:00:00
Alerts Analyzed: 2

**Executive Summary:**

Suspicious inbound activity targeted a protected asset.

**Top 5 Priority Threats:**

| Indicator | Type | Direction | Activity | Severity | Count |
|-----------|------|-----------|----------|----------|-------|
| 203.0.113.10 | Source | inbound | Web exploit attempt | HIGH | 2 |

**Immediate Actions:**

1. Review web server logs.

---

**Analysis Complete**
"""
    parsed = ReportParser.parse_report(markdown)
    _assert(parsed["executive_summary"], "Executive summary was not parsed")
    _assert(parsed["key_findings"], "Key findings were not derived")
    _assert(
        any("203.0.113.10" in finding for finding in parsed["key_findings"]),
        "Derived findings did not include top threat context",
    )


def check_generation_defaults_and_qwen_args() -> None:
    config = LLMConfig()
    _assert(config.temperature <= 0.2, "Default LLM temperature is too high for grounded CTI reports")
    _assert(config.max_tokens > 0, "Default LLM max_tokens should be bounded, not infinite/context-fill")

    args = config.get_llama_args(include_optional_qwen_args=True)
    joined = " ".join(args)
    _assert("--chat-template-kwargs" in args, "Qwen thinking-control args missing")
    _assert("enable_thinking" in joined and "false" in joined, "Qwen thinking was not disabled")

    fallback_args = config.get_llama_args(include_optional_qwen_args=False)
    _assert("--chat-template-kwargs" not in fallback_args, "Optional Qwen args were not removable")

    module_path = CONFIG_DIR / "llm_client.py"
    spec = importlib.util.spec_from_file_location("llm_client_real_for_qwen_checks", module_path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)

    client = module.LlamaModelClient.__new__(module.LlamaModelClient)
    client.config = config
    controlled_prompt = client._apply_model_control_tokens("Generate report")
    _assert("/no_think" in controlled_prompt, "Qwen soft no-thinking control missing from prompt")
    _assert(
        client._apply_model_control_tokens(controlled_prompt).count("/no_think") == 1,
        "Qwen soft no-thinking control was duplicated",
    )

    class MinimalTemplateManager:
        def format_user_message(self, user_message: str) -> str:
            return f"<|im_start|>user\n{user_message}<|im_end|>\n<|im_start|>assistant\n"

    client.template_manager = MinimalTemplateManager()
    rendered = client.template_manager.format_user_message(client._apply_model_control_tokens("Generate report"))
    _assert(
        rendered.index("/no_think") < rendered.index("<|im_start|>assistant"),
        "Qwen no-thinking control must stay inside the user turn before assistant generation",
    )


def check_runtime_preflight_report_is_safe_and_actionable() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        model_path = root / "model.gguf"
        llama_path = root / "llama-cli"
        templates_dir = root / "templates"
        templates_dir.mkdir()
        model_path.write_text("model", encoding="utf-8")
        llama_path.write_text("#!/bin/sh\n", encoding="utf-8")
        (templates_dir / "cti.txt").write_text("system", encoding="utf-8")
        (templates_dir / "qwen_chat.j2").write_text("template", encoding="utf-8")

        fake_config = types.SimpleNamespace(
            llm=types.SimpleNamespace(
                model_path=str(model_path),
                llama_cpp_path=str(llama_path),
                system_prompt_file="cti.txt",
                chat_template_file="qwen_chat.j2",
                use_custom_template=True,
            ),
            paths=types.SimpleNamespace(
                templates_dir=str(templates_dir),
                geoip_db_path="",
            ),
            database=types.SimpleNamespace(
                get_dict=lambda: {
                    "host": "db.internal",
                    "port": 5432,
                    "database": "soc_rag",
                    "user": "soc_user",
                    "password": "super-secret-password",
                }
            ),
            get_production_warnings=lambda: [],
        )

        original_dependency_check = runtime_preflight._dependency_check
        original_database_check = runtime_preflight._database_check
        try:
            runtime_preflight._dependency_check = lambda: {
                "name": "python_dependencies",
                "status": "pass",
                "message": "stubbed",
            }
            runtime_preflight._database_check = lambda _config: {
                "name": "postgresql",
                "status": "pass",
                "message": "stubbed",
                "details": {"host": "db.internal", "database": "soc_rag", "user": "soc_user"},
            }
            report = runtime_preflight.build_preflight_report(
                fake_config,
                include_database=True,
                rag_status={
                    "stale_custom_doc_chunks": 2,
                    "stale_uploaded_documents": 1,
                },
            )
        finally:
            runtime_preflight._dependency_check = original_dependency_check
            runtime_preflight._database_check = original_database_check

    serialized = json.dumps(report, sort_keys=True)
    _assert(report["ready"] is False, "Stale RAG processor version should fail preflight")
    _assert("rag_processor_version" in serialized, "Preflight did not include stale RAG processor check")
    _assert("super-secret-password" not in serialized, "Preflight report leaked database password")
    _assert("db.internal" in serialized, "Safe database host detail was lost from preflight")


def check_runtime_preflight_accepts_fitz_import_name() -> None:
    original_find_spec = runtime_preflight.importlib.util.find_spec

    def fake_find_spec(module_name: str):
        if module_name == "pymupdf":
            return None
        return object()

    try:
        runtime_preflight.importlib.util.find_spec = fake_find_spec
        report = runtime_preflight._dependency_check()
    finally:
        runtime_preflight.importlib.util.find_spec = original_find_spec

    _assert(report["status"] == "pass", "Preflight should accept fitz when pymupdf import name is unavailable")
    _assert("pymupdf_or_fitz" not in json.dumps(report), "PyMuPDF alternative group was incorrectly marked missing")


def check_cti_rag_validation_helpers() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        alert_path = Path(tmpdir) / "alert.json"
        alert_path.write_text(json.dumps({"alerts": [{"rule": {"id": "1001"}}]}), encoding="utf-8")
        alerts = validate_rag_flow._load_json_alerts(alert_path)

    _assert(len(alerts) == 1, "Validation alert loader did not unpack alerts wrapper")
    sections = validate_rag_flow._report_sections(
        "**Executive Summary:**\nOK\n\n**Key Findings:**\n- one\n\n"
        "**MITRE ATT&CK Mapping:**\nT1105\n\n**Immediate Actions:**\n- isolate\n\n"
        "**Analysis Complete**"
    )
    _assert(all(sections.values()), "Validation report section detection missed required headings")
    selected = [{"source_document": "Seaduke_123_chunk_1"}, {"source_document": "Carbanak_456_chunk_1"}]
    _assert(
        validate_rag_flow._validate_expected_sources(selected, ["Seaduke"]) == [],
        "Expected source validation missed selected Seaduke source",
    )
    _assert(
        validate_rag_flow._validate_expected_sources(selected, ["FIN6"]),
        "Expected source validation should fail for absent source",
    )
    processed_summary = [{
        "actors": ["SEADUKE", "APT29"],
        "related_actor_aliases": ["COZY BEAR"],
        "malware_families": ["WispRAT"],
        "campaigns": ["Operation Example"],
        "tools": ["PsExec"],
        "courses_of_action": ["Disable Script Interpreter Abuse"],
        "hashes": ["a25ec7749b2de12c2a86167afa88a4dd"],
        "domains": ["sitebar.org"],
        "ips": ["91.218.114.11"],
    }]
    expectations = types.SimpleNamespace(
        expect_actor=["APT29"],
        expect_related_actor=["COZY BEAR"],
        expect_malware=["WispRAT"],
        expect_campaign=["Operation Example"],
        expect_tool=["PsExec"],
        expect_course_of_action=["Disable Script Interpreter Abuse"],
        expect_hash=["a25ec7749b2de12c2a86167afa88a4dd"],
        expect_domain=["sitebar.org"],
        expect_ip=["91.218.114.11"],
    )
    _assert(
        validate_rag_flow._validate_expected_document_artifacts(processed_summary, expectations) == [],
        "Expected document artifact validation failed for present actor/hash/domain/IP",
    )
    missing_expectations = types.SimpleNamespace(
        expect_actor=["FIN6"],
        expect_related_actor=[],
        expect_malware=[],
        expect_campaign=[],
        expect_tool=[],
        expect_course_of_action=[],
        expect_hash=[],
        expect_domain=[],
        expect_ip=[],
    )
    _assert(
        validate_rag_flow._validate_expected_document_artifacts(processed_summary, missing_expectations),
        "Expected document artifact validation should fail for absent actor",
    )
    selected_with_overlap = [{
        "source_document": "Seaduke_123_chunk_1",
        "match_types": ["exact"],
        "evidence_strength": "high",
        "source_reliability": "uploaded_cti_document",
        "behavior_mismatch": False,
        "current_ioc_overlap": {
            "hashes": ["a25ec7749b2de12c2a86167afa88a4dd"],
            "domains": ["sitebar.org"],
        },
    }]
    _assert(
        validate_rag_flow._validate_expected_current_overlaps(
            selected_with_overlap,
            ["hashes:a25ec7749b2de12c2a86167afa88a4dd", "domains:sitebar.org"],
        ) == [],
        "Expected current-overlap validation failed for present overlap",
    )
    _assert(
        validate_rag_flow._validate_expected_current_overlaps(
            selected_with_overlap,
            ["ips:91.218.114.11"],
        ),
        "Expected current-overlap validation should fail for absent typed overlap",
    )
    report_expectations = types.SimpleNamespace(
        expect_report_contains=["APT29", "sitebar.org"],
        reject_report_contains=["T1190", "T1203"],
        expect_mitre=["T1105"],
    )
    report = (
        "**Executive Summary:** APT29 SeaDuke activity used sitebar.org.\n\n"
        "**MITRE ATT&CK Mapping:** T1105 - Ingress Tool Transfer"
    )
    _assert(
        validate_rag_flow._validate_report_text(report, report_expectations) == [],
        "Expected report text validation failed for present required text and absent rejected text",
    )
    bad_report = report + "\nT1190 - Exploit Public-Facing Application"
    _assert(
        validate_rag_flow._validate_report_text(bad_report, report_expectations),
        "Report text validation should fail when rejected MITRE text is present",
    )
    _assert(
        validate_rag_flow._validate_report_text("", report_expectations),
        "Report text validation should fail when expectations are supplied but report is empty",
    )
    source_quality = types.SimpleNamespace(
        require_evidence_strength="high",
        require_match_type=["exact"],
        require_source_reliability=["uploaded_cti_document"],
        reject_behavior_mismatch=True,
    )
    _assert(
        validate_rag_flow._validate_selected_source_quality(selected_with_overlap, source_quality) == [],
        "Selected-source quality validation failed for high-strength exact uploaded CTI source",
    )
    weak_source = [{
        "source_document": "Carbanak_chunk_1",
        "match_types": ["semantic"],
        "evidence_strength": "low",
        "source_reliability": "uploaded_cti_document",
        "behavior_mismatch": True,
    }]
    _assert(
        validate_rag_flow._validate_selected_source_quality(weak_source, source_quality),
        "Selected-source quality validation should fail for weak semantic behavior-mismatched source",
    )


def check_cti_rag_validation_clear_rag_bypasses_stale_preflight() -> None:
    class FakeConfig:
        llm = types.SimpleNamespace()
        paths = types.SimpleNamespace(
            templates_dir="templates",
            reports_dir="reports",
            uploads_dir="uploads",
            geoip_db_path="",
        )
        database = types.SimpleNamespace(get_dict=lambda: {})
        rag = types.SimpleNamespace()
        asset_inventory = types.SimpleNamespace()

    class FakeAnalyzer:
        def clean_log_data(self, alerts):
            return alerts

    class FakeFormatter:
        def _retrieve_context_for_alerts(self, *_args, **_kwargs):
            return [{"metadata": {"source_document": "Seaduke_validation.pdf"}, "source": "custom_document"}]

        def _build_exact_terms_from_alerts(self, _alerts):
            return {"hashes": ["a25ec7749b2de12c2a86167afa88a4dd"]}

        def _build_focused_retrieval_queries(self, _alerts):
            return ["a25ec7749b2de12c2a86167afa88a4dd sitebar.org"]

        def _validate_generated_report(self, _report):
            return []

        def _create_retrieval_summary(self, _docs):
            return "{}"

    class FakeGenerator:
        def __init__(self, *_args, **_kwargs):
            self.alert_analyzer = FakeAnalyzer()
            self.report_formatter = FakeFormatter()
            self.cleared = False

        def get_rag_status(self):
            return {
                "ready": True,
                "stale_custom_doc_chunks": 9,
                "stale_uploaded_documents": 3,
            }

        def clear_rag_database(self):
            self.cleared = True
            return {"success": True}

        def add_custom_documents(self, _docs):
            return None

    captured_rag_statuses = []

    def fake_preflight(_config, include_database=True, rag_status=None):
        captured_rag_statuses.append(rag_status)
        return {"ready": True, "summary": {}, "checks": []}

    original_config = validate_rag_flow._safe_config
    original_preflight = validate_rag_flow.build_preflight_report
    original_process_documents = validate_rag_flow._process_documents
    original_load_alerts = validate_rag_flow._load_json_alerts
    original_report_generator = report_module.ReportGenerator
    try:
        validate_rag_flow._safe_config = lambda _path: FakeConfig()
        validate_rag_flow.build_preflight_report = fake_preflight
        validate_rag_flow._process_documents = lambda _processor, _paths: [{"content": "cti", "metadata": {"filename": "Seaduke.pdf"}}]
        validate_rag_flow._load_json_alerts = lambda _path: [{"rule": {"id": "1001"}}]
        report_module.ReportGenerator = FakeGenerator
        args = types.SimpleNamespace(
            config=None,
            clear_rag=True,
            force=False,
            document=[],
            pdf=["Seaduke.pdf"],
            alert="alert.json",
            max_docs=4,
            custom_only=True,
            skip_generation=True,
            output=None,
            server_host="validation",
            min_selected=1,
            expect_source=["Seaduke"],
            expect_actor=[],
            expect_related_actor=[],
            expect_malware=[],
            expect_campaign=[],
            expect_tool=[],
            expect_course_of_action=[],
            expect_hash=[],
            expect_domain=[],
            expect_ip=[],
            expect_overlap=[],
            expect_mitre=[],
            expect_report_contains=[],
            reject_report_contains=[],
            require_evidence_strength=None,
            require_match_type=[],
            require_source_reliability=[],
            reject_behavior_mismatch=False,
        )
        result = validate_rag_flow.run_validation(args)
    finally:
        validate_rag_flow._safe_config = original_config
        validate_rag_flow.build_preflight_report = original_preflight
        validate_rag_flow._process_documents = original_process_documents
        validate_rag_flow._load_json_alerts = original_load_alerts
        report_module.ReportGenerator = original_report_generator

    _assert(result["success"] is True, "Clear-RAG validation path should complete with stubbed matching source")
    _assert(captured_rag_statuses == [None], "Clear-RAG validation should not fail preflight on stale rows it will remove")


def check_high_signal_retrieval_queries() -> None:
    formatter = ReportFormatter.__new__(ReportFormatter)
    formatter.rag_manager = RAGContextManager.__new__(RAGContextManager)
    alert = {
        "rule_level": 8,
        "rule_description": "External protected asset security analysis medium true alert",
        "alert_signature": "ET WEB_SERVER Possible CVE-2026-12345 exploit attempt",
        "rule_id": "100001",
        "signature_id": "2026123",
        "src_ip": "203.0.113.10",
        "dest_ip": "66.96.12.44",
        "threat_classification": {"threat_direction": "inbound", "is_external_threat": True},
        "behavior_tags": ["web_or_exploit_attempt", "external_to_protected_asset"],
        "observed_iocs": {
            "ips": ["203.0.113.10", "66.96.12.44"],
            "domains": ["exploit.example.com"],
            "cves": ["CVE-2026-12345"],
            "threat_actor_aliases": ["APT29"],
            "malware_families": ["NightRAT"],
            "campaigns": ["Operation Shadow Trail"],
            "tools": ["CloudSweep"],
            "keywords": ["external", "protected", "powershell.exe"],
        },
    }

    queries = formatter._build_focused_retrieval_queries([alert])
    joined = " ".join(queries).lower()
    _assert("203.0.113.10" in joined, "High-signal source IP missing from retrieval query")
    _assert("exploit.example.com" in joined, "High-signal domain missing from retrieval query")
    _assert("cve-2026-12345" in joined, "CVE missing from retrieval query")
    _assert("apt29" in joined, "Related actor alias missing from retrieval query")
    _assert("nightrat" in joined, "Malware family missing from retrieval query")
    _assert("operation shadow trail" in joined, "Campaign missing from retrieval query")
    _assert("cloudsweep" in joined, "Tool missing from retrieval query")
    _assert("powershell.exe" in joined, "High-signal process/file keyword missing from retrieval query")
    _assert(" protected " not in f" {joined} ", "Generic token leaked into retrieval query")
    _assert(" medium " not in f" {joined} ", "Severity adjective leaked into retrieval query")


def check_document_summary_exact_hit_expands_from_start() -> None:
    manager = RAGContextManager.__new__(RAGContextManager)

    class FakeCursor:
        def __init__(self):
            self.calls = []
            self._rows = []

        def execute(self, query, params):
            self.calls.append((query, params))
            self._rows = [
                (
                    101,
                    "Initial narrative chunk for SeaDuke background.",
                    {
                        "source_document": "Seaduke.pdf",
                        "chunk_index": 0,
                        "filename": "Seaduke_chunk_0",
                    },
                )
            ] if len(self.calls) == 1 else []

        def fetchall(self):
            return self._rows

    cursor = FakeCursor()
    seed = {
        "id": 1,
        "source": "custom_document",
        "content": "CTI Document Summary",
        "metadata": {
            "source_document": "Seaduke.pdf",
            "chunk_index": -1,
            "chunk_role": "document_summary",
            "filename": "Seaduke_document_summary",
            "source_cti_artifacts": {"threat_actors": ["SEADUKE", "APT29"]},
        },
        "match_types": ["exact"],
        "match_evidence": ["hash matched extracted CTI artifact a25ec7749b2de12c2a86167afa88a4dd"],
    }

    expanded = manager._expand_custom_document_context_from_exact_hits(
        cursor,
        [seed],
        per_seed_limit=4,
        total_limit=4,
    )

    first_query, first_params = cursor.calls[0]
    second_query, second_params = cursor.calls[1]
    _assert("document_summary" in first_query, "Summary chunks were not excluded from context expansion")
    _assert(first_params[1] == 0, "Summary exact hit did not start context expansion at chunk 0")
    _assert(first_params[2] >= 3, "Summary exact hit did not include early narrative chunks")
    _assert("%SEADUKE%" in second_params, "Actor-aware expansion did not search for SeaDuke context")
    _assert("%APT29%" in second_params, "Actor-aware expansion did not search for APT29 context")
    _assert("%FIN6%" not in second_params, "Hard-coded FIN6 pattern leaked into SeaDuke expansion")
    _assert("%MAZE%" not in second_params, "Hard-coded Maze pattern leaked into SeaDuke expansion")
    _assert(expanded and expanded[0]["match_types"] == ["source_context"], "Summary exact hit did not yield source context")
    _assert(
        expanded[0]["linked_exact_chunk_index"] == -1,
        "Source context did not preserve the linked summary exact-hit index",
    )


def check_source_context_expansion_is_actor_aware() -> None:
    seed = {
        "source": "custom_document",
        "metadata": {
            "source_document": "Seaduke.pdf",
            "filename": "Seaduke_document_summary",
            "source_cti_artifacts": {
                "threat_actors": ["SEADUKE"],
                "threat_actor_aliases": ["APT29"],
                "malware_families": ["WispRAT"],
                "campaigns": ["Operation Northstar Test"],
                "tools": ["CloudSweep"],
                "courses_of_action": ["Disable Script Interpreter Abuse"],
                "hashes": ["a25ec7749b2de12c2a86167afa88a4dd"],
            },
        },
    }

    patterns = RAGContextManager._source_context_patterns_for_seed(seed)
    lowered = {pattern.lower() for pattern in patterns}

    _assert("%seaduke%" in lowered, "SeaDuke document identity was not used for source context expansion")
    _assert("%apt29%" in lowered, "APT29 actor artifact was not used for source context expansion")
    _assert("%wisprat%" in lowered, "Malware family artifact was not used for source context expansion")
    _assert("%operation northstar test%" in lowered, "Campaign artifact was not used for source context expansion")
    _assert("%cloudsweep%" in lowered, "Tool artifact was not used for source context expansion")
    _assert(
        "%disable script interpreter abuse%" in lowered,
        "Course-of-action artifact was not used for source context expansion",
    )
    _assert("%indicators of compromise%" in lowered, "Generic CTI context sections were not retained")
    _assert("%fin6%" not in lowered, "FIN6 leaked into non-FIN6 source context expansion")
    _assert("%maze%" not in lowered, "Maze leaked into non-Maze source context expansion")


def check_section_aware_prompt_compaction() -> None:
    module_path = CONFIG_DIR / "llm_client.py"
    spec = importlib.util.spec_from_file_location("llm_client_real_for_checks", module_path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)

    prompt = """
ANALYSIS TYPE: MANUAL ANALYSIS

CURRENT ALERTS DATA:
- Total Alerts: 1

CONFIGURED ASSET INVENTORY:
Protected asset: 66.96.12.44

""" + ("LOW VALUE FILLER " * 1000) + """

REPRESENTATIVE CURRENT ALERTS:
[{"src_ip":"203.0.113.10","dest_ip":"66.96.12.44","alert_signature":"ET WEB exploit"}]

HISTORICAL AND CUSTOM REFERENCE CONTEXT:
[RAG-1] source=archive; evidence_strength=high
Matched: source ip matched metadata src_ip=203.0.113.10

OUTPUT CONTRACT:
- Begin with **Executive Summary:**
- Do not output reasoning.
"""
    compacted = module.LlamaModelClient._section_aware_compact(prompt, 2600)
    _assert("203.0.113.10" in compacted, "Compacted prompt lost current alert evidence")
    _assert("RAG-1" in compacted, "Compacted prompt lost selected RAG evidence")
    _assert("OUTPUT CONTRACT" in compacted, "Compacted prompt lost output contract")
    _assert(len(compacted) <= 2600, "Compacted prompt exceeded budget")


def main() -> int:
    checks: list[tuple[str, Callable[[], None]]] = [
        ("ip_substring_not_exact", check_ip_substring_not_exact),
        ("hash_case_insensitive_exact_matching", check_hash_case_insensitive_exact_matching),
        ("source_level_pdf_artifacts_count_as_exact_evidence", check_source_level_pdf_artifacts_count_as_exact_evidence),
        ("malformed_url_does_not_abort_artifact_extraction", check_malformed_url_does_not_abort_artifact_extraction),
        ("named_threat_actor_alias_extraction", check_named_threat_actor_alias_extraction),
        ("document_identity_used_for_pdf_actor_extraction", check_document_identity_used_for_pdf_actor_extraction),
        ("file_names_do_not_become_domains", check_file_names_do_not_become_domains),
        ("pdf_sentence_fragments_do_not_become_domains", check_pdf_sentence_fragments_do_not_become_domains),
        ("uncommon_tlds_remain_extractable", check_uncommon_tlds_remain_extractable),
        ("pdf_onion_domain_glue_is_repaired", check_pdf_onion_domain_glue_is_repaired),
        ("reference_domains_not_promoted_to_cti_context", check_reference_domains_not_promoted_to_cti_context),
        ("concatenated_pdf_urls_are_split", check_concatenated_pdf_urls_are_split),
        ("defanged_and_wrapped_ioc_extraction", check_defanged_and_wrapped_ioc_extraction),
        ("pdf_table_ips_not_concatenated", check_pdf_table_ips_not_concatenated),
        ("pdf_annotation_link_filtering", check_pdf_annotation_link_filtering),
        ("pdf_fallback_merge_only_when_useful", check_pdf_fallback_merge_only_when_useful),
        ("json_cti_summary_ingestion", check_json_cti_summary_ingestion),
        ("stix_json_structured_artifact_ingestion", check_stix_json_structured_artifact_ingestion),
        ("document_processor_version_metadata", check_document_processor_version_metadata),
        ("document_processor_duplicate_tracking_reset", check_document_processor_duplicate_tracking_reset),
        ("rag_status_warns_on_stale_processor_version", check_rag_status_warns_on_stale_processor_version),
        ("exact_document_condition_uses_structured_artifacts", check_exact_document_condition_uses_structured_artifacts),
        ("exact_document_condition_filters_private_endpoint_ips", check_exact_document_condition_filters_private_endpoint_ips),
        ("exact_document_condition_prefers_attacker_cti_ips", check_exact_document_condition_prefers_attacker_cti_ips),
        ("defanged_indicator_matching", check_defanged_indicator_matching),
        ("flat_alert_artifact_extraction_for_retrieval", check_flat_alert_artifact_extraction_for_retrieval),
        ("private_ips_not_promoted_as_cti_context", check_private_ips_not_promoted_as_cti_context),
        ("low_signal_values_not_promoted_as_cti_context", check_low_signal_values_not_promoted_as_cti_context),
        ("low_signal_alert_terms_not_used_for_cti_exact_search", check_low_signal_alert_terms_not_used_for_cti_exact_search),
        ("generic_alert_words_not_high_signal", check_generic_alert_words_not_high_signal),
        ("evidence_audit_labels", check_evidence_audit_labels),
        ("weak_exact_overlap_not_high_confidence", check_weak_exact_overlap_not_high_confidence),
        ("exact_candidate_scoring_prefers_current_iocs", check_exact_candidate_scoring_prefers_current_iocs),
        ("source_context_outranks_semantic_neighbor", check_source_context_outranks_semantic_neighbor),
        ("cti_context_classification", check_cti_context_classification),
        ("artifact_disposition_labels", check_artifact_disposition_labels),
        ("report_claim_audit", check_report_claim_audit),
        ("actor_specific_attribution_audit", check_actor_specific_attribution_audit),
        ("remediation_target_grounding", check_remediation_target_grounding),
        ("mitre_catalog_validation", check_mitre_catalog_validation),
        ("approved_report_index_sanitization", check_approved_report_index_sanitization),
        ("low_strength_context_filtering", check_low_strength_context_filtering),
        ("custom_docs_context_uses_persistent_fallback", check_custom_docs_context_uses_persistent_fallback),
        ("document_extraction_quality", check_document_extraction_quality),
        ("alert_behavior_and_response_focus", check_alert_behavior_and_response_focus),
        ("cti_corpus_alert_shape_parsing", check_cti_corpus_alert_shape_parsing),
        ("cti_behavior_alignment", check_cti_behavior_alignment),
        ("structure_aware_cti_chunking", check_structure_aware_cti_chunking),
        ("report_generation_guardrail_fallback", check_report_generation_guardrail_fallback),
        ("report_parser_derives_key_findings", check_report_parser_derives_key_findings),
        ("generation_defaults_and_qwen_args", check_generation_defaults_and_qwen_args),
        ("runtime_preflight_report_is_safe_and_actionable", check_runtime_preflight_report_is_safe_and_actionable),
        ("runtime_preflight_accepts_fitz_import_name", check_runtime_preflight_accepts_fitz_import_name),
        ("cti_rag_validation_helpers", check_cti_rag_validation_helpers),
        ("cti_rag_validation_clear_rag_bypasses_stale_preflight", check_cti_rag_validation_clear_rag_bypasses_stale_preflight),
        ("high_signal_retrieval_queries", check_high_signal_retrieval_queries),
        ("document_summary_exact_hit_expands_from_start", check_document_summary_exact_hit_expands_from_start),
        ("source_context_expansion_is_actor_aware", check_source_context_expansion_is_actor_aware),
        ("section_aware_prompt_compaction", check_section_aware_prompt_compaction),
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
