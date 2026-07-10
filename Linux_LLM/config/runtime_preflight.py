"""Production readiness checks for the Ubuntu SOC runtime.

The web app and validation CLI use this module to catch missing dependencies,
bad model paths, PostgreSQL/pgvector issues, prompt drift, and stale CTI
extraction versions before a report run depends on them.
"""

import argparse
import contextlib
import importlib.util
import io
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from config import ConfigManager
from cti_artifacts import CTIArtifactExtractor


def _check_result(name: str, status: str, message: str, **details: Any) -> Dict[str, Any]:
    result = {"name": name, "status": status, "message": message}
    clean_details = {key: value for key, value in details.items() if value not in (None, "", [], {})}
    if clean_details:
        result["details"] = clean_details
    return result


def _path_check(
    name: str,
    path: str,
    require_executable: bool = False,
    require_directory: bool = False,
) -> Dict[str, Any]:
    path_obj = Path(path or "")
    if not path:
        return _check_result(name, "fail", "Path is not configured")
    if not path_obj.exists():
        return _check_result(name, "fail", "Configured path does not exist")
    if require_directory and not path_obj.is_dir():
        return _check_result(name, "fail", "Configured path is not a directory")
    if not require_directory and not path_obj.is_file():
        return _check_result(name, "fail", "Configured path is not a file")
    if require_executable and not os.access(path_obj, os.X_OK):
        return _check_result(name, "fail", "Configured binary is not executable")
    return _check_result(name, "pass", "Configured path is usable")


def _database_check(config: ConfigManager, timeout_seconds: int = 3) -> Dict[str, Any]:
    db_config = config.database.get_dict()
    db_config.pop("_auto_create_database", None)
    safe_details = {"port": db_config.get("port")}

    try:
        import psycopg2
    except Exception:
        return _check_result(
            "postgresql",
            "fail",
            "psycopg2 is unavailable",
            **safe_details,
        )

    connect_config = dict(db_config)
    connect_config["connect_timeout"] = timeout_seconds
    connect_config["options"] = f"-c statement_timeout={max(1, timeout_seconds) * 1000}"
    try:
        conn = psycopg2.connect(**connect_config)
    except Exception as error:
        return _check_result(
            "postgresql",
            "fail",
            "Could not connect to PostgreSQL",
            error_type=type(error).__name__,
            **safe_details,
        )

    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute("SELECT version()")
                version = cur.fetchone()[0]
                cur.execute("SELECT EXISTS (SELECT 1 FROM pg_available_extensions WHERE name = 'vector')")
                vector_available = bool(cur.fetchone()[0])
                cur.execute("SELECT EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'vector')")
                vector_installed = bool(cur.fetchone()[0])
    except Exception as error:
        return _check_result(
            "postgresql",
            "fail",
            "Connected to PostgreSQL but validation query failed",
            error_type=type(error).__name__,
            **safe_details,
        )
    finally:
        conn.close()

    if not vector_available:
        return _check_result(
            "pgvector",
            "fail",
            "PostgreSQL is reachable but pgvector is not available. Install the vector extension package.",
            postgres_version=version,
            **safe_details,
        )
    if not vector_installed:
        return _check_result(
            "pgvector",
            "warn",
            "pgvector is available but not installed in the configured database yet; app startup should create it if the DB user has permission.",
            postgres_version=version,
            **safe_details,
        )
    return _check_result(
        "postgresql",
        "pass",
        "PostgreSQL is reachable and pgvector is installed.",
        postgres_version=version,
        **safe_details,
    )


def _module_group_available(module_names: List[str]) -> bool:
    return any(importlib.util.find_spec(module_name) is not None for module_name in module_names)


def _dependency_check() -> Dict[str, Any]:
    required_modules = [
        ("fastapi", ["fastapi"]),
        ("uvicorn", ["uvicorn"]),
        ("websockets", ["websockets"]),
        ("paramiko", ["paramiko"]),
        ("pymupdf_or_fitz", ["pymupdf", "fitz"]),
        ("jinja2", ["jinja2"]),
        ("geoip2", ["geoip2"]),
        ("psycopg2", ["psycopg2"]),
        ("sentence_transformers", ["sentence_transformers"]),
        ("matplotlib", ["matplotlib"]),
        ("pandas", ["pandas"]),
    ]
    optional_modules = ["weasyprint", "markdown", "pypdf", "yaml"]

    missing = [label for label, module_names in required_modules if not _module_group_available(module_names)]
    optional_missing = [module for module in optional_modules if importlib.util.find_spec(module) is None]
    if missing:
        return _check_result(
            "python_dependencies",
            "fail",
            "Required Python packages are missing.",
            missing=missing,
            optional_missing=optional_missing,
        )
    return _check_result(
        "python_dependencies",
        "pass",
        "Required Python packages are discoverable.",
        optional_missing=optional_missing,
    )


def build_preflight_report(
    config: Optional[ConfigManager] = None,
    include_database: bool = True,
    rag_status: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Build a safe production-readiness report without leaking secrets."""
    config = config or ConfigManager()
    checks: List[Dict[str, Any]] = []

    try:
        config_valid, config_errors = config.validate_all()
    except Exception as error:
        config_valid = False
        config_errors = [f"Configuration: {type(error).__name__}"]
    if config_valid:
        checks.append(
            _check_result(
                "configuration",
                "pass",
                "Configuration sections and cross-section requirements are valid.",
            )
        )
    else:
        known_sections = {
            "SSH", "Wazuh", "LLM", "Web", "Paths", "RAG", "Database",
            "AssetInventory", "Runtime",
        }
        invalid_sections = sorted({
            str(error).partition(":")[0]
            for error in config_errors
            if str(error).partition(":")[0] in known_sections
        })
        checks.append(
            _check_result(
                "configuration",
                "fail",
                "Configuration validation failed.",
                invalid_sections=invalid_sections,
                error_count=len(config_errors),
            )
        )

    checks.append(_dependency_check())
    checks.append(_path_check("llm_model", config.llm.model_path))
    checks.append(_path_check("llama_cpp_binary", config.llm.llama_cpp_path, require_executable=True))
    checks.append(_path_check("templates_dir", config.paths.templates_dir, require_directory=True))

    system_prompt = Path(config.paths.templates_dir) / config.llm.system_prompt_file
    chat_template = Path(config.paths.templates_dir) / config.llm.chat_template_file
    checks.append(_path_check("system_prompt", str(system_prompt)))
    if config.llm.use_custom_template:
        checks.append(_path_check("chat_template", str(chat_template)))
    if config.paths.geoip_db_path:
        geoip_status = "pass" if Path(config.paths.geoip_db_path).exists() else "warn"
        checks.append(
            _check_result(
                "geoip_database",
                geoip_status,
                (
                    "Optional GeoIP database is configured and exists"
                    if geoip_status == "pass"
                    else "Optional GeoIP database is configured but missing"
                ),
            )
        )

    if include_database:
        checks.append(_database_check(config))

    if rag_status is not None:
        stale_chunks = int(rag_status.get("stale_custom_doc_chunks") or 0)
        stale_docs = int(rag_status.get("stale_uploaded_documents") or 0)
        if stale_chunks or stale_docs:
            checks.append(
                _check_result(
                    "rag_processor_version",
                    "fail",
                    "Uploaded CTI documents use an older extraction pipeline; build a replacement corpus.",
                    current_processor_version=CTIArtifactExtractor.EXTRACTION_PIPELINE_VERSION,
                    stale_custom_doc_chunks=stale_chunks,
                    stale_uploaded_documents=stale_docs,
                )
            )
        else:
            checks.append(
                _check_result(
                    "rag_processor_version",
                    "pass",
                    "Uploaded CTI chunks match the current extraction pipeline.",
                    current_processor_version=CTIArtifactExtractor.EXTRACTION_PIPELINE_VERSION,
                )
            )

    production_warnings = config.get_production_warnings()
    for warning in production_warnings:
        checks.append(_check_result("production_warning", "warn", warning))

    failed = [check for check in checks if check["status"] == "fail"]
    warnings = [check for check in checks if check["status"] == "warn"]
    return {
        "ready": not failed,
        "summary": {
            "failed": len(failed),
            "warnings": len(warnings),
            "passed": sum(1 for check in checks if check["status"] == "pass"),
        },
        "checks": checks,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="SOC framework production preflight checks")
    parser.add_argument("--config", help="Optional JSON config file path")
    parser.add_argument("--skip-db", action="store_true", help="Skip PostgreSQL/pgvector connectivity checks")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    args = parser.parse_args()

    try:
        if args.json:
            with contextlib.redirect_stdout(io.StringIO()):
                config = ConfigManager(args.config)
        else:
            config = ConfigManager(args.config)
    except Exception as error:
        failure = {
            "ready": False,
            "summary": {"failed": 1, "warnings": 0, "passed": 0},
            "checks": [
                _check_result(
                    "configuration",
                    "fail",
                    "Configuration could not be loaded.",
                    error_type=type(error).__name__,
                )
            ],
        }
        if args.json:
            print(json.dumps(failure, indent=2, sort_keys=True))
        else:
            print(
                f"Preflight configuration load failed ({type(error).__name__})",
                file=sys.stderr,
            )
        return 2

    report = build_preflight_report(
        config,
        include_database=not args.skip_db,
    )
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print("SOC framework production preflight")
        for check in report["checks"]:
            print(f"[{check['status'].upper()}] {check['name']}: {check['message']}")
        print(
            "Summary: "
            f"{report['summary']['passed']} passed, "
            f"{report['summary']['warnings']} warning(s), "
            f"{report['summary']['failed']} failed"
        )
    return 0 if report["ready"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
