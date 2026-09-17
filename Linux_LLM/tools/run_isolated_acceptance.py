#!/usr/bin/env python3
"""User-facing isolated-database acceptance workflow.

Loads operator configuration from ENV_FILE, forces a disposable PostgreSQL
database name, then exercises:

    CTI upload -> extraction/chunking/embedding -> alert upload ->
    parse/normalise -> hybrid RAG -> token-budgeted Qwen -> validation ->
    report -> PDF

It never targets the default production database name.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List


def _prepare_isolated_env(args: argparse.Namespace) -> Path:
    if args.env_file:
        os.environ["ENV_FILE"] = str(Path(args.env_file).expanduser())
    elif "ENV_FILE" not in os.environ:
        desktop_env = Path.home() / "Desktop" / ".env"
        if desktop_env.is_file():
            os.environ["ENV_FILE"] = str(desktop_env)

    os.environ["DB_NAME"] = args.database
    os.environ["DB_AUTO_CREATE"] = "true"
    os.environ["LIVE_MONITORING_ENABLED"] = "false"
    os.environ["SSH_HOST"] = ""
    os.environ["SSH_USERNAME"] = ""
    os.environ["SSH_PASSWORD"] = ""
    # Isolated acceptance must not open the configured Wazuh SSH session.
    geoip = Path.home() / "Desktop" / "GeoLite2-City.mmdb"
    if geoip.is_file() and not os.getenv("GEOIP_DB_PATH"):
        os.environ["GEOIP_DB_PATH"] = str(geoip)
    workdir = Path(args.workdir).expanduser() if args.workdir else Path(tempfile.mkdtemp(prefix="soc-isolated-e2e-"))
    workdir.mkdir(parents=True, exist_ok=True)
    os.environ["REPORTS_DIR"] = str(workdir / "reports")
    os.environ["UPLOADS_DIR"] = str(workdir / "uploads")
    os.environ["REPORT_DIAGNOSTIC_TRACE"] = "true"
    os.environ["REPORT_DIAGNOSTIC_TRACE_DIR"] = str(workdir / "traces")
    Path(os.environ["REPORTS_DIR"]).mkdir(parents=True, exist_ok=True)
    Path(os.environ["UPLOADS_DIR"]).mkdir(parents=True, exist_ok=True)
    Path(os.environ["REPORT_DIAGNOSTIC_TRACE_DIR"]).mkdir(parents=True, exist_ok=True)
    if args.database in {"soc_rag", "postgres", "template1"}:
        raise SystemExit("Refusing to run isolated acceptance against a production/maintenance database name")
    return workdir


def _auth_header(username: str, password: str) -> Dict[str, str]:
    import base64
    token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    return {"Authorization": f"Basic {token}"}


def _poll(client, path: str, headers: Dict[str, str], timeout_s: float, ok) -> Dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    last: Dict[str, Any] = {}
    while time.monotonic() < deadline:
        response = client.get(path, headers=headers)
        if response.status_code != 200:
            last = {"status_code": response.status_code, "body": response.text[:500]}
            time.sleep(2)
            continue
        last = response.json()
        if ok(last):
            return last
        time.sleep(2)
    raise TimeoutError(f"Timed out waiting on {path}: {last}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env-file", default="")
    parser.add_argument("--database", default="soc_rag_eval")
    parser.add_argument("--workdir", default="")
    parser.add_argument(
        "--reports-root",
        default=os.getenv("CTI_REPORTS_DIR", str(Path.home() / "Desktop/CTI-Folder/CTI-HAL-main/reports")),
    )
    parser.add_argument("--skip-llm", action="store_true")
    parser.add_argument("--build-timeout", type=int, default=1800)
    parser.add_argument("--analyze-timeout", type=int, default=1800)
    args = parser.parse_args()
    workdir = _prepare_isolated_env(args)

    config_dir = Path(__file__).resolve().parents[1] / "config"
    if str(config_dir) not in sys.path:
        sys.path.insert(0, str(config_dir))

    from fastapi.testclient import TestClient
    from main import SOCApplication

    reports_root = Path(args.reports_root).expanduser()
    cti_files = [
        next(iter(reports_root.glob("fin7/fact_sheet*")), None),
        next(iter(reports_root.glob("fin7/*SentinelLabs.pdf")), None),
    ]
    cti_files = [path for path in cti_files if path and path.is_file()]
    if len(cti_files) < 1:
        raise SystemExit(f"No CTI PDFs found under {reports_root}")

    alert_path = Path(__file__).resolve().parent / "eval_fixtures" / "artificial_fin7_sysmon_alert.json"
    negative_path = Path(__file__).resolve().parent / "eval_fixtures" / "artificial_negative_admin_alert.json"

    started = time.monotonic()
    application = SOCApplication()
    application.config.ssh.host = ""
    application.config.ssh.username = ""
    application.config.ssh.password = ""
    headers = _auth_header(application.config.web.username, application.config.web.password)
    result: Dict[str, Any] = {
        "database": args.database,
        "workdir": str(workdir),
        "cti_files": [path.name for path in cti_files],
        "skip_llm": args.skip_llm,
    }

    try:
        with TestClient(application.app) as client:
            upload_files = [
                ("customFiles", (path.name, path.read_bytes(), "application/pdf"))
                for path in cti_files
            ]
            build = client.post(
                "/build-rag",
                headers=headers,
                data={"use_uploads": "true", "use_archives": "false", "build_mode": "extend"},
                files=upload_files,
            )
            if build.status_code != 200:
                result["build_error"] = {"status": build.status_code, "body": build.text[:800]}
                print(json.dumps(result, indent=2))
                return 1
            build_session = build.json()["session_id"]
            result["build_session_id"] = build_session
            rag_status = _poll(
                client,
                "/rag-status",
                headers,
                args.build_timeout,
                lambda payload: bool(payload.get("ready")) and int(payload.get("docs_with_embeddings") or 0) > 0,
            )
            result["rag_status"] = {
                "ready": rag_status.get("ready"),
                "docs_with_embeddings": rag_status.get("docs_with_embeddings"),
                "active_source_documents": rag_status.get("active_source_documents"),
                "active_corpus_id": (rag_status.get("active_corpus_id") or "")[:16],
            }
            progress = client.get(f"/api/progress/{build_session}", headers=headers).json()
            result["build_progress"] = {
                "available": progress.get("available"),
                "progress": progress.get("progress"),
                "status": progress.get("status"),
                "message": progress.get("message"),
            }

            if args.skip_llm:
                result["stage"] = "rag_ready"
                result["elapsed_s"] = round(time.monotonic() - started, 1)
                print(json.dumps(result, indent=2))
                return 0

            analyze = client.post(
                "/analyze-alerts",
                headers=headers,
                data={"include_charts": "false"},
                files={"alertTemplate": ("artificial_fin7_sysmon_alert.json", alert_path.read_bytes(), "application/json")},
            )
            if analyze.status_code != 200:
                result["analyze_error"] = {"status": analyze.status_code, "body": analyze.text[:800]}
                print(json.dumps(result, indent=2))
                return 1
            analyze_session = analyze.json()["session_id"]
            result["analyze_session_id"] = analyze_session
            analysis = _poll(
                client,
                f"/api/check-analysis-result/{analyze_session}",
                headers,
                args.analyze_timeout,
                lambda payload: bool(payload.get("redirect") and payload.get("report_id")),
            )
            report_id = analysis["report_id"]
            result["report_id"] = report_id
            draft = application.draft_reports.get(report_id) or {}
            executive = str(draft.get("executive_summary") or draft.get("Executive Summary") or "")
            serialized = json.dumps(draft, default=str).lower()
            result["report_observations"] = {
                "has_executive_summary": bool(executive.strip()),
                "mentions_injected_actor_as_data": "ignore all previous instructions" in serialized,
                "forced_apt29_attribution": (
                    "apt29" in serialized and "insufficient evidence" not in serialized
                ),
                "section_keys": sorted(str(key) for key in draft.keys())[:20],
            }
            metrics = application.report_generator.get_generation_metrics()
            result["last_stage_timings_ms"] = metrics.get("last_stage_timings_ms") or {}
            result["generation_seconds"] = metrics.get("avg_generation_time")

            approve = client.post(
                f"/api/approve-report/{report_id}",
                headers=headers,
                json=draft,
            )
            result["approve_status"] = approve.status_code
            if approve.status_code != 200:
                try:
                    result["approve_error"] = approve.json()
                except Exception:
                    result["approve_error"] = approve.text[:500]
            approved_name = None
            if approve.status_code == 200:
                approved_name = (approve.json() or {}).get("filename")
            if not approved_name:
                reports = client.get("/reports", headers=headers).json().get("items") or []
                markdown_reports = [item["filename"] for item in reports if str(item.get("filename")).endswith(".md")]
                approved_name = markdown_reports[0] if markdown_reports else None
            result["approved_markdown"] = approved_name
            if approved_name:
                pdf = client.post(
                    "/convert-to-pdf",
                    headers=headers,
                    data={"filename": approved_name},
                )
                result["pdf"] = {
                    "status": pdf.status_code,
                    "body": pdf.json() if pdf.headers.get("content-type", "").startswith("application/json") else pdf.text[:400],
                    "pdf_ms": getattr(application.pdf_converter, "last_pdf_ms", None),
                }

            negative = client.post(
                "/analyze-alerts",
                headers=headers,
                data={"include_charts": "false"},
                files={"alertTemplate": ("negative.json", negative_path.read_bytes(), "application/json")},
            )
            result["negative_analyze_status"] = negative.status_code
            if negative.status_code == 409:
                result["negative_analyze"] = "skipped_busy"
            elif negative.status_code == 200:
                neg_session = negative.json()["session_id"]
                try:
                    neg_done = _poll(
                        client,
                        f"/api/check-analysis-result/{neg_session}",
                        headers,
                        args.analyze_timeout,
                        lambda payload: bool(payload.get("redirect") and payload.get("report_id")),
                    )
                    neg_draft = application.draft_reports.get(neg_done["report_id"]) or {}
                    neg_text = json.dumps(neg_draft, default=str).lower()
                    result["negative_report"] = {
                        "insufficient_or_benign": any(
                            token in neg_text
                            for token in (
                                "insufficient evidence",
                                "no sufficiently relevant",
                                "benign",
                                "administrative",
                                "does not support",
                            )
                        )
                    }
                except TimeoutError as error:
                    result["negative_report"] = {"error": str(error)}

        result["elapsed_s"] = round(time.monotonic() - started, 1)
        traces = list((workdir / "traces").glob("*.json"))
        result["diagnostic_traces"] = len(traces)
        print(json.dumps(result, indent=2, default=str))
        if not result.get("rag_status", {}).get("ready"):
            return 1
        if args.skip_llm:
            return 0
        if not result.get("report_id"):
            return 1
        if result.get("approve_status") != 200:
            return 1
        if not (result.get("pdf") or {}).get("status") == 200:
            return 1
        return 0
    finally:
        close = getattr(application, "report_generator", None)
        if close is not None:
            try:
                application.report_generator.close()
            except Exception:
                pass


if __name__ == "__main__":
    raise SystemExit(main())
