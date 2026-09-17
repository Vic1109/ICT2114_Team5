#!/usr/bin/env python3
"""Skip-LLM user-facing acceptance for unseen CTI + exact IOC retrieval.

Uses an isolated database name and synthetic fixtures that do not appear in
the CTI-HAL sample set.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import time
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env-file", default="")
    parser.add_argument("--database", default="soc_rag_unseen")
    parser.add_argument("--workdir", default="")
    parser.add_argument("--analyze", action="store_true", help="Also POST /analyze-alerts after retrieval")
    args = parser.parse_args()

    if args.env_file:
        os.environ["ENV_FILE"] = str(Path(args.env_file).expanduser())
    elif "ENV_FILE" not in os.environ:
        desktop_env = Path.home() / "Desktop" / ".env"
        if desktop_env.is_file():
            os.environ["ENV_FILE"] = str(desktop_env)
    if args.database in {"soc_rag", "postgres", "template1"}:
        raise SystemExit("Refusing to run against a production/maintenance database name")
    os.environ["DB_NAME"] = args.database
    os.environ["DB_AUTO_CREATE"] = "true"
    os.environ["LIVE_MONITORING_ENABLED"] = "false"
    os.environ["SSH_HOST"] = ""
    os.environ["SSH_USERNAME"] = ""
    os.environ["SSH_PASSWORD"] = ""

    workdir = Path(args.workdir).expanduser() if args.workdir else Path(tempfile.mkdtemp(prefix="soc-unseen-"))
    workdir.mkdir(parents=True, exist_ok=True)
    os.environ["REPORTS_DIR"] = str(workdir / "reports")
    os.environ["UPLOADS_DIR"] = str(workdir / "uploads")
    Path(os.environ["REPORTS_DIR"]).mkdir(parents=True, exist_ok=True)
    Path(os.environ["UPLOADS_DIR"]).mkdir(parents=True, exist_ok=True)

    config_dir = Path(__file__).resolve().parents[1] / "config"
    sys.path.insert(0, str(config_dir))
    from fastapi.testclient import TestClient
    from main import SOCApplication

    fixtures = Path(__file__).resolve().parent / "eval_fixtures" / "generalisation"
    cti_path = fixtures / "nightorchid_advisory.txt"
    alert_path = fixtures / "artificial_unseen_alert.json"
    started = time.monotonic()
    application = SOCApplication()
    application.config.ssh.host = ""
    application.config.ssh.username = ""
    application.config.ssh.password = ""
    import base64
    token = base64.b64encode(
        f"{application.config.web.username}:{application.config.web.password}".encode()
    ).decode("ascii")
    headers = {"Authorization": f"Basic {token}"}
    result = {"database": args.database, "workdir": str(workdir)}

    with TestClient(application.app) as client:
        build = client.post(
            "/build-rag",
            headers=headers,
            data={
                "use_uploads": "true",
                "use_archives": "false",
                "build_mode": "replace",
                "confirm_replace": "true",
            },
            files=[("customFiles", (cti_path.name, cti_path.read_bytes(), "text/plain"))],
        )
        if build.status_code != 200:
            result["build_error"] = {"status": build.status_code, "body": build.text[:800]}
            print(json.dumps(result, indent=2))
            return 1
        deadline = time.monotonic() + 600
        rag = {}
        while time.monotonic() < deadline:
            rag = client.get("/rag-status", headers=headers).json()
            if rag.get("ready") and int(rag.get("docs_with_embeddings") or 0) > 0:
                break
            time.sleep(2)
        result["rag_status"] = {
            "ready": rag.get("ready"),
            "docs_with_embeddings": rag.get("docs_with_embeddings"),
            "active_corpus_id": (rag.get("active_corpus_id") or "")[:16],
        }
        alerts = json.loads(alert_path.read_text(encoding="utf-8"))
        if not isinstance(alerts, list):
            alerts = [alerts]
        from alert_normalizer import AlertNormalizer
        normalized = [AlertNormalizer().normalize(alert) for alert in alerts]
        cleaned = application.report_generator.alert_analyzer.clean_log_data(normalized)
        formatter = application.report_generator.report_formatter
        exact_terms = formatter._build_exact_terms_from_alerts(cleaned)
        query = " ".join(
            exact_terms.get("hashes", [])
            + exact_terms.get("ips", [])
            + exact_terms.get("domains", [])
            + exact_terms.get("urls", [])
        )
        search_started = time.monotonic()
        retrieved = application.report_generator.rag_manager.search_custom_documents(
            query or "203.0.113.42",
            k=5,
            exact_terms=exact_terms,
        )
        result["retrieval_ms"] = round((time.monotonic() - search_started) * 1000, 1)
        result["preserved_alert_fields"] = {
            "dest_ip": cleaned[0].get("dest_ip"),
            "rule_id": cleaned[0].get("rule_id"),
            "command_line": bool((cleaned[0].get("process_context") or {}).get("command_line") or cleaned[0].get("command_line")),
            "raw_alert": "_raw_alert" in cleaned[0],
        }
        result["exact_terms"] = {
            key: exact_terms.get(key)
            for key in ("ips", "domains", "urls", "hashes", "cves")
            if exact_terms.get(key)
        }
        result["retrieved"] = [
            {
                "id": doc.get("id"),
                "match_types": doc.get("match_types"),
                "evidence_strength": doc.get("evidence_strength"),
                "match_evidence": doc.get("match_evidence"),
                "score": doc.get("score"),
            }
            for doc in retrieved[:5]
        ]
        result["exact_hit"] = any("exact" in (doc.get("match_types") or []) for doc in retrieved)
        result["hash_or_ip_evidence"] = any(
            "hash matched" in " ".join(doc.get("match_evidence") or []).lower()
            or "ip matched" in " ".join(doc.get("match_evidence") or []).lower()
            or "domain matched" in " ".join(doc.get("match_evidence") or []).lower()
            or "url matched" in " ".join(doc.get("match_evidence") or []).lower()
            for doc in retrieved
        )
        result["elapsed_s"] = round(time.monotonic() - started, 1)

        if args.analyze:
            analyze = client.post(
                "/analyze-alerts",
                headers=headers,
                data={"include_charts": "false"},
                files={"alertTemplate": (alert_path.name, alert_path.read_bytes(), "application/json")},
            )
            result["analyze_status"] = analyze.status_code
            session_id = (analyze.json() or {}).get("session_id") if analyze.status_code == 200 else None
            draft = {}
            deadline = time.monotonic() + 90
            while session_id and time.monotonic() < deadline:
                polled = client.get(f"/api/check-analysis-result/{session_id}", headers=headers)
                if polled.status_code == 200:
                    draft = polled.json()
                    if draft.get("redirect") or draft.get("error"):
                        break
                time.sleep(2)
            result["analyze"] = {
                "session_id": session_id,
                "redirect": draft.get("redirect"),
                "error": (str(draft.get("error") or ""))[:400],
                "has_draft": bool(draft.get("redirect")),
            }
            result["elapsed_s"] = round(time.monotonic() - started, 1)

    print(json.dumps(result, indent=2, default=str))
    return 0 if result.get("exact_hit") and result.get("hash_or_ip_evidence") else 2


if __name__ == "__main__":
    raise SystemExit(main())
