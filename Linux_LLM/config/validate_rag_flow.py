#!/usr/bin/env python3
"""Validate the production CTI document -> RAG -> retrieval -> report flow.

This script is intended to run on the Ubuntu deployment host where PostgreSQL,
pgvector, the embedding model, and llama.cpp are available. It is non-destructive
by default: uploaded CTI documents are added to the configured RAG database and
existing rows are preserved unless --clear-rag is explicitly passed.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import sys
import traceback
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from config import ConfigManager
from runtime_preflight import build_preflight_report
from runtime_utils import configure_console_encoding


configure_console_encoding()


def _load_json_alerts(path: Path) -> List[Dict[str, Any]]:
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)

    if isinstance(payload, list):
        alerts = payload
    elif isinstance(payload, dict) and isinstance(payload.get("alerts"), list):
        alerts = payload["alerts"]
    elif isinstance(payload, dict):
        alerts = [payload]
    else:
        raise ValueError(f"Unsupported alert JSON root type: {type(payload).__name__}")

    cleaned = [alert for alert in alerts if isinstance(alert, dict)]
    if not cleaned:
        raise ValueError("Alert JSON did not contain any alert objects")
    return cleaned


def _safe_config(config_path: str | None) -> ConfigManager:
    # ConfigManager reports loaded env vars to stdout. Suppress that only for
    # JSON mode callers so diagnostics stay machine-readable.
    return ConfigManager(config_path)


def _process_documents(processor: Any, document_paths: List[Path]) -> List[Dict[str, Any]]:
    docs: List[Dict[str, Any]] = []
    for document_path in document_paths:
        if not document_path.exists() or not document_path.is_file():
            raise FileNotFoundError(f"Document not found: {document_path}")
        content = document_path.read_bytes()
        text, metadata = processor.process_upload(content, document_path.name, save_to_disk=False)
        docs.append({"content": text, "metadata": metadata})
    return docs


def _input_document_paths(args: argparse.Namespace) -> List[Path]:
    paths = list(args.document or []) + list(args.pdf or [])
    if not paths:
        raise ValueError("At least one --document or --pdf path is required")
    return [Path(path).expanduser() for path in paths]


def _metadata_source_name(doc: Dict[str, Any]) -> str:
    metadata = doc.get("metadata") or {}
    return str(
        metadata.get("source_document")
        or metadata.get("original_filename")
        or metadata.get("filename")
        or ""
    )


def _selected_source_summary(docs: List[Any]) -> List[Dict[str, Any]]:
    summary: List[Dict[str, Any]] = []
    for index, doc in enumerate(docs or [], 1):
        if not isinstance(doc, dict):
            summary.append({"rank": index, "source": "inline", "text_preview": str(doc)[:160]})
            continue
        metadata = doc.get("metadata") or {}
        summary.append({
            "rank": index,
            "source": doc.get("source"),
            "source_document": _metadata_source_name(doc),
            "filename": metadata.get("filename"),
            "chunk_index": metadata.get("chunk_index"),
            "chunk_role": metadata.get("chunk_role"),
            "match_types": doc.get("match_types"),
            "evidence_strength": doc.get("evidence_strength"),
            "source_reliability": doc.get("source_reliability"),
            "score": doc.get("score"),
            "rank_score": doc.get("context_rank_score"),
            "current_ioc_overlap": doc.get("current_ioc_overlap") or {},
            "behavior_overlap": doc.get("behavior_overlap") or [],
            "behavior_mismatch": bool(doc.get("behavior_mismatch")),
            "cautions": doc.get("retrieval_cautions") or [],
            "query": doc.get("retrieval_query"),
        })
    return summary


def _report_sections(report: str) -> Dict[str, bool]:
    lowered = str(report or "").lower()
    return {
        "executive_summary": "executive summary" in lowered,
        "key_findings": "key finding" in lowered,
        "mitre": "mitre" in lowered,
        "immediate_actions": "immediate action" in lowered or "recommendation" in lowered,
        "analysis_complete": "analysis complete" in lowered,
    }


def _validate_expected_sources(selected: List[Dict[str, Any]], expected: List[str]) -> List[str]:
    failures: List[str] = []
    source_text = "\n".join(
        str(item.get("source_document") or item.get("filename") or "").lower()
        for item in selected
    )
    for expected_value in expected or []:
        if expected_value.lower() not in source_text:
            failures.append(f"Expected selected RAG source containing '{expected_value}' was not found")
    return failures


def _normalize_match_value(value: Any) -> str:
    return " ".join(str(value or "").strip().lower().split())


def _value_present(values: List[Any], expected: str) -> bool:
    expected_norm = _normalize_match_value(expected)
    if not expected_norm:
        return True
    for value in values or []:
        value_norm = _normalize_match_value(value)
        if value_norm == expected_norm or expected_norm in value_norm:
            return True
    return False


def _validate_expected_document_artifacts(processed_summary: List[Dict[str, Any]], args: argparse.Namespace) -> List[str]:
    failures: List[str] = []
    expectations = {
        "actors": list(args.expect_actor or []),
        "related_actor_aliases": list(args.expect_related_actor or []),
        "malware_families": list(args.expect_malware or []),
        "campaigns": list(args.expect_campaign or []),
        "tools": list(args.expect_tool or []),
        "courses_of_action": list(args.expect_course_of_action or []),
        "hashes": list(args.expect_hash or []),
        "domains": list(args.expect_domain or []),
        "ips": list(args.expect_ip or []),
    }
    labels = {
        "actors": "actor",
        "related_actor_aliases": "related actor alias",
        "malware_families": "malware family",
        "campaigns": "campaign",
        "tools": "tool",
        "courses_of_action": "course of action",
        "hashes": "hash",
        "domains": "domain",
        "ips": "ip",
    }
    for artifact_type, expected_values in expectations.items():
        extracted_values: List[Any] = []
        for doc in processed_summary or []:
            extracted_values.extend(doc.get(artifact_type) or [])
        for expected in expected_values:
            if not _value_present(extracted_values, expected):
                failures.append(
                    f"Expected extracted {labels.get(artifact_type, artifact_type)} '{expected}' was not found"
                )
    return failures


def _validate_expected_current_overlaps(selected: List[Dict[str, Any]], expected: List[str]) -> List[str]:
    failures: List[str] = []
    overlaps: Dict[str, List[Any]] = {}
    for item in selected or []:
        current_overlap = item.get("current_ioc_overlap") or {}
        if not isinstance(current_overlap, dict):
            continue
        for key, values in current_overlap.items():
            overlaps.setdefault(str(key), [])
            if isinstance(values, list):
                overlaps[str(key)].extend(values)
            elif values not in (None, "", [], {}):
                overlaps[str(key)].append(values)

    for expected_value in expected or []:
        if ":" in expected_value:
            artifact_type, artifact_value = expected_value.split(":", 1)
            search_values = overlaps.get(artifact_type.strip(), [])
        else:
            artifact_value = expected_value
            search_values = [value for values in overlaps.values() for value in values]
        if not _value_present(search_values, artifact_value):
            failures.append(
                f"Expected selected-source current IoC overlap '{expected_value}' was not found"
            )
    return failures


def _validate_report_text(report: str, args: argparse.Namespace) -> List[str]:
    failures: List[str] = []
    if not report:
        if args.expect_report_contains or args.reject_report_contains or args.expect_mitre:
            return ["Report text expectations were supplied, but report generation was skipped or empty"]
        return failures

    report_norm = _normalize_match_value(report)
    for expected in args.expect_report_contains or []:
        if _normalize_match_value(expected) not in report_norm:
            failures.append(f"Expected generated report text containing '{expected}' was not found")
    for rejected in args.reject_report_contains or []:
        if _normalize_match_value(rejected) in report_norm:
            failures.append(f"Rejected generated report text '{rejected}' was present")
    for technique_id in args.expect_mitre or []:
        if _normalize_match_value(technique_id) not in report_norm:
            failures.append(f"Expected MITRE technique '{technique_id}' was not found in generated report")
    return failures


def _evidence_rank(value: Any) -> int:
    return {"low": 1, "medium": 2, "high": 3}.get(str(value or "").strip().lower(), 0)


def _validate_selected_source_quality(selected: List[Dict[str, Any]], args: argparse.Namespace) -> List[str]:
    failures: List[str] = []

    min_strength = str(args.require_evidence_strength or "").strip().lower()
    if min_strength:
        min_rank = _evidence_rank(min_strength)
        if min_rank <= 0:
            failures.append(f"Unknown evidence strength requirement '{args.require_evidence_strength}'")
        elif not any(_evidence_rank(item.get("evidence_strength")) >= min_rank for item in selected or []):
            failures.append(
                f"No selected RAG source met required evidence strength '{args.require_evidence_strength}'"
            )

    for required_type in args.require_match_type or []:
        required_norm = _normalize_match_value(required_type)
        if not any(
            required_norm in {_normalize_match_value(match_type) for match_type in item.get("match_types") or []}
            for item in selected or []
        ):
            failures.append(f"No selected RAG source included required match type '{required_type}'")

    for required_reliability in args.require_source_reliability or []:
        if not any(
            _normalize_match_value(item.get("source_reliability")) == _normalize_match_value(required_reliability)
            for item in selected or []
        ):
            failures.append(f"No selected RAG source had required reliability '{required_reliability}'")

    if args.reject_behavior_mismatch and any(item.get("behavior_mismatch") for item in selected or []):
        failures.append("At least one selected RAG source had behavior_mismatch=true")

    return failures


def run_validation(args: argparse.Namespace) -> Dict[str, Any]:
    # These imports intentionally live inside the runtime path so --help and
    # basic CLI parsing do not require Ubuntu-only dependencies on workstations.
    from rag import DocumentProcessor
    from report import ReportGenerator

    config = _safe_config(args.config)
    generator = ReportGenerator(
        config.llm,
        config.paths.templates_dir,
        config.paths.reports_dir,
        config.database.get_dict(),
        config.rag,
        config.paths.geoip_db_path,
        config.asset_inventory,
    )

    initial_rag_status = generator.get_rag_status()
    preflight_rag_status = None if args.clear_rag else initial_rag_status
    preflight = build_preflight_report(
        config,
        include_database=True,
        rag_status=preflight_rag_status,
    )
    if not preflight["ready"] and not args.force:
        return {
            "success": False,
            "stage": "preflight",
            "message": "Preflight failed. Re-run with --force only if you intentionally want to continue.",
            "preflight": preflight,
        }

    if args.clear_rag:
        generator.clear_rag_database()

    processor = DocumentProcessor(uploads_dir=config.paths.uploads_dir)
    processed_docs = _process_documents(processor, _input_document_paths(args))
    generator.add_custom_documents(processed_docs)

    alerts = _load_json_alerts(Path(args.alert).expanduser())
    cleaned_alerts = generator.alert_analyzer.clean_log_data(alerts)
    formatter = generator.report_formatter
    selected_docs = formatter._retrieve_context_for_alerts(
        cleaned_alerts,
        k=args.max_docs,
        source_mode="custom" if args.custom_only else "all",
    )

    exact_terms = formatter._build_exact_terms_from_alerts(cleaned_alerts)
    retrieval_queries = formatter._build_focused_retrieval_queries(cleaned_alerts)
    selected_summary = _selected_source_summary(selected_docs)

    report = ""
    report_path = None
    report_issues: List[str] = []
    if not args.skip_generation:
        report = generator.generate_report_with_rag(
            alerts,
            server_host=args.server_host,
            is_automatic=False,
        )
        report_issues = formatter._validate_generated_report(report)
        if args.output:
            report_path = Path(args.output).expanduser()
        else:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            report_path = Path(config.paths.reports_dir) / f"CTI_RAG_Validation_{timestamp}.md"
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(report, encoding="utf-8")

    rag_status = generator.get_rag_status()
    processed_summary = []
    for item in processed_docs:
        metadata = item.get("metadata") or {}
        processed_summary.append({
            "filename": metadata.get("filename"),
            "pages": metadata.get("pages"),
            "characters": metadata.get("characters"),
            "processor_version": metadata.get("processor_version"),
            "document_quality": metadata.get("document_quality"),
            "artifact_counts": metadata.get("artifact_counts"),
            "actors": (metadata.get("cti_artifacts") or {}).get("threat_actors", [])[:12],
            "related_actor_aliases": (metadata.get("cti_artifacts") or {}).get("threat_actor_aliases", [])[:12],
            "malware_families": (metadata.get("cti_artifacts") or {}).get("malware_families", [])[:12],
            "campaigns": (metadata.get("cti_artifacts") or {}).get("campaigns", [])[:12],
            "tools": (metadata.get("cti_artifacts") or {}).get("tools", [])[:12],
            "courses_of_action": (metadata.get("cti_artifacts") or {}).get("courses_of_action", [])[:12],
            "hashes": (metadata.get("cti_artifacts") or {}).get("hashes", [])[:12],
            "domains": (metadata.get("cti_artifacts") or {}).get("domains", [])[:12],
            "ips": (metadata.get("cti_artifacts") or {}).get("ips", [])[:12],
        })

    assertion_failures = []
    if len(selected_docs) < args.min_selected:
        assertion_failures.append(
            f"Selected {len(selected_docs)} RAG source(s), below required minimum {args.min_selected}"
        )
    assertion_failures.extend(_validate_expected_sources(selected_summary, args.expect_source))
    assertion_failures.extend(_validate_expected_document_artifacts(processed_summary, args))
    assertion_failures.extend(_validate_expected_current_overlaps(selected_summary, args.expect_overlap))
    assertion_failures.extend(_validate_report_text(report, args))
    assertion_failures.extend(_validate_selected_source_quality(selected_summary, args))
    if report_issues:
        assertion_failures.append("Generated report failed section validation: " + "; ".join(report_issues))

    return {
        "success": not assertion_failures,
        "stage": "complete",
        "message": "CTI RAG validation completed" if not assertion_failures else "CTI RAG validation found issues",
        "assertion_failures": assertion_failures,
        "preflight": preflight,
        "rag_status": rag_status,
        "processed_documents": processed_summary,
        "alert_count": len(alerts),
        "cleaned_alert_count": len(cleaned_alerts),
        "exact_terms": exact_terms,
        "retrieval_queries": retrieval_queries,
        "selected_sources": selected_summary,
        "retrieval_summary": formatter._create_retrieval_summary(selected_docs),
        "report_path": str(report_path) if report_path else None,
        "report_sections": _report_sections(report) if report else {},
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate uploaded CTI document extraction, RAG retrieval, and report generation on the Ubuntu runtime"
    )
    parser.add_argument("--config", help="Optional JSON config file path")
    parser.add_argument("--document", action="append", default=[], help="CTI document to ingest (.pdf, .json, .txt, .md). Repeatable.")
    parser.add_argument("--pdf", action="append", default=[], help="Backward-compatible alias for --document for PDF CTI files. Repeatable.")
    parser.add_argument("--alert", required=True, help="Alert JSON file to analyze")
    parser.add_argument("--output", help="Optional markdown report output path")
    parser.add_argument("--server-host", default="validation-host", help="Server host label for generated reports")
    parser.add_argument("--max-docs", type=int, default=8, help="Maximum RAG sources to retrieve")
    parser.add_argument("--min-selected", type=int, default=1, help="Minimum selected RAG sources required")
    parser.add_argument("--expect-source", action="append", default=[], help="Substring expected in selected RAG source names")
    parser.add_argument("--expect-actor", action="append", default=[], help="Threat actor/APT name expected from CTI extraction")
    parser.add_argument("--expect-related-actor", action="append", default=[], help="Related actor alias expected as context but not direct attribution evidence")
    parser.add_argument("--expect-malware", action="append", default=[], help="Malware family name expected from CTI extraction")
    parser.add_argument("--expect-campaign", action="append", default=[], help="Campaign name expected from CTI extraction")
    parser.add_argument("--expect-tool", action="append", default=[], help="Tool name expected from CTI extraction")
    parser.add_argument("--expect-course-of-action", action="append", default=[], help="Mitigation/course-of-action name expected from CTI extraction")
    parser.add_argument("--expect-hash", action="append", default=[], help="Hash expected from CTI extraction")
    parser.add_argument("--expect-domain", action="append", default=[], help="Domain expected from CTI extraction")
    parser.add_argument("--expect-ip", action="append", default=[], help="Public IP expected from CTI extraction")
    parser.add_argument(
        "--expect-overlap",
        action="append",
        default=[],
        help="Current-alert IoC overlap expected in selected RAG sources, optionally typed like hashes:<value>",
    )
    parser.add_argument("--expect-mitre", action="append", default=[], help="MITRE technique ID expected in the generated report")
    parser.add_argument("--expect-report-contains", action="append", default=[], help="Text expected in the generated report")
    parser.add_argument("--reject-report-contains", action="append", default=[], help="Text that must not appear in the generated report")
    parser.add_argument("--require-evidence-strength", choices=["low", "medium", "high"], help="Require at least one selected RAG source at or above this evidence strength")
    parser.add_argument("--require-match-type", action="append", default=[], help="Require at least one selected RAG source with this match type, e.g. exact")
    parser.add_argument("--require-source-reliability", action="append", default=[], help="Require at least one selected RAG source with this reliability label")
    parser.add_argument("--reject-behavior-mismatch", action="store_true", help="Fail if any selected RAG source has behavior_mismatch=true")
    parser.add_argument("--custom-only", action="store_true", help="Retrieve only uploaded CTI documents")
    parser.add_argument("--skip-generation", action="store_true", help="Validate extraction and retrieval without invoking llama.cpp")
    parser.add_argument("--clear-rag", action="store_true", help="Explicitly clear and recreate the configured RAG database first")
    parser.add_argument("--force", action="store_true", help="Continue even if preflight reports failures")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON only")
    args = parser.parse_args()

    try:
        if args.json:
            with contextlib.redirect_stdout(io.StringIO()):
                result = run_validation(args)
            print(json.dumps(result, indent=2, sort_keys=True, default=str))
        else:
            result = run_validation(args)
            print(json.dumps(result, indent=2, sort_keys=True, default=str))
        return 0 if result.get("success") else 1
    except Exception as error:
        failure = {
            "success": False,
            "stage": "exception",
            "message": str(error),
            "traceback": traceback.format_exc(),
        }
        print(json.dumps(failure, indent=2, sort_keys=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
