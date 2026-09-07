#!/usr/bin/env python3
import json
import asyncio
import uuid
import hashlib
import base64
import re
import threading
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional
from contextlib import asynccontextmanager 
from urllib.parse import urlsplit

import uvicorn
from fastapi import FastAPI, HTTPException, Depends, status, Form, WebSocket, UploadFile, File, Request, WebSocketDisconnect, Query
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.staticfiles import StaticFiles
import secrets
import sys
import math
from runtime_utils import atomic_write_text, configure_console_encoding, log_sanitized_exception


configure_console_encoding()


BASE_DIR = Path(__file__).resolve().parent

from alert_normalizer import AlertNormalizer
from config import ConfigManager, validate_environment
from ssh import SmartSSHLogReader
from report import ReportGenerator
from rag import DocumentProcessor, DocumentValidator
from progress import ProgressTracker, generate_session_id
from report_parser import ReportParser
from runtime_preflight import build_preflight_report

from live_monitoring import (
    create_enhanced_live_monitoring_service
)
from pdf_converter import (
    create_enhanced_pdf_converter,
    create_enhanced_pdf_api_handlers
)


def generate_alert_uuid(alert: Dict[str, Any]) -> str:
    """Create a stable full-record identity without transport-only helper fields."""
    transport_fields = {"_alert_uuid", "_archive_source"}

    def canonicalize(value: Any) -> Any:
        if isinstance(value, dict):
            return {
                str(key): canonicalize(item)
                for key, item in value.items()
                if str(key) not in transport_fields
            }
        if isinstance(value, list):
            return [canonicalize(item) for item in value]
        return value

    serialized = json.dumps(
        canonicalize(alert),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    )
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

def resolve_report_path(reports_root: Path, filename: str) -> Path:
    """Resolve a report filename while preventing directory traversal."""
    if not filename or "/" in filename or "\\" in filename:
        raise HTTPException(status_code=400, detail="Invalid report filename")

    root = reports_root.resolve()
    report_path = (root / filename).resolve()
    if report_path.parent != root:
        raise HTTPException(status_code=400, detail="Invalid report filename")
    return report_path


def resolve_chart_path(reports_root: Path, filename: str) -> Path:
    """Resolve a generated chart filename without allowing path traversal."""
    if not filename or Path(filename).name != filename:
        raise HTTPException(status_code=400, detail="Invalid chart filename")

    charts_root = (reports_root / "charts").resolve()
    chart_path = (charts_root / filename).resolve()
    if chart_path.parent != charts_root or chart_path.suffix.lower() != ".png":
        raise HTTPException(status_code=400, detail="Invalid chart filename")
    return chart_path


class SOCApplication:   
    @asynccontextmanager
    async def lifespan(self, app: FastAPI):
        await self.progress_tracker.start_cleanup_task()
        await self._restore_monitoring_state()
        try:
            yield
        finally:
            print("Ending application lifespan...")
            await self._shutdown_runtime()

    def __init__(self, config_file: str = None):
        self.config = ConfigManager(config_file)
        is_valid, errors = self.config.validate_all()
        if not is_valid:
            print("❌ Configuration validation failed:")
            for error in errors:
                print(f"  - {error}")
            raise ValueError("Invalid configuration")
        
        self.draft_reports = {}
        self.session_results = {}
        self._background_tasks = set()
        self._rag_build_task = None
        self._analysis_task = None
        self._shutting_down = False
        worker_threads = self._runtime_limit("max_worker_threads", 4)
        worker_admission = worker_threads + self._runtime_limit("max_background_tasks", 8)
        self._worker_admission = threading.BoundedSemaphore(worker_admission)
        self._executor = ThreadPoolExecutor(
            max_workers=worker_threads,
            thread_name_prefix="soc-worker",
        )
        try:
            self._init_components()
        except Exception:
            self._executor.shutdown(wait=False, cancel_futures=True)
            raise

        self.app = FastAPI(
            title="SOC Threat Analysis with Enhanced Monitoring",
            description="Cybersecurity threat analysis with proper alert filtering and PDF reports",
            version="3.1.0",
            lifespan=self.lifespan
        )
        static_dir = BASE_DIR / "static"
        static_dir.mkdir(exist_ok=True)
        self.app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

        self.security = HTTPBasic()
        self.templates = Jinja2Templates(directory=BASE_DIR / "templates")
        self._install_security_middleware()
        self._setup_routes()
            
    def _init_components(self):
        try:
            self.progress_tracker = ProgressTracker(
                max_sessions=self._runtime_limit("max_session_results", 200),
                session_timeout=3600,
            )
            self.document_processor = DocumentProcessor(self.config.paths.uploads_dir)
            db_config = self.config.database.get_dict()
            self.report_generator = ReportGenerator(
                llm_config=self.config.llm,  
                templates_dir=self.config.paths.templates_dir,
                reports_dir=self.config.paths.reports_dir,
                db_config=db_config,
                rag_config=self.config.rag,
                geoip_db_path=self.config.paths.geoip_db_path,
                asset_config=self.config.asset_inventory
            )

            rag_status = self.report_generator.get_rag_status()
            print(
                "RAG status loaded: "
                f"ready={bool(rag_status.get('ready'))}, "
                f"alert_embeddings={int(rag_status.get('alerts_with_embeddings') or 0)}, "
                f"document_chunks={int(rag_status.get('docs_with_embeddings') or 0)}"
            )
            
            self.live_monitoring = create_enhanced_live_monitoring_service(
                config_manager=self.config,
                report_generator=self.report_generator,
                ssh_reader_factory=self._create_ssh_reader,
                executor=self._executor,
                worker_admission=self._worker_admission,
            )
        
            self.pdf_converter = create_enhanced_pdf_converter()
            self.pdf_api_handlers = create_enhanced_pdf_api_handlers(
                Path(self.config.paths.reports_dir),
                converter=self.pdf_converter,
            )
            
            print(" All components with charts initialized")
            
        except Exception as e:
            log_sanitized_exception("Component initialization failed", e)
            generator = getattr(self, "report_generator", None)
            if generator is not None:
                generator.close()
            raise
    
    def _create_ssh_reader(self):
        return SmartSSHLogReader(
            host=self.config.ssh.host,
            username=self.config.ssh.username,
            password=self.config.ssh.password,
            port=self.config.ssh.port,
            alerts_path=self.config.wazuh.alerts_file_path,
            archives_base_path=self.config.wazuh.archives_base_path,
            timeout=self.config.ssh.timeout,
            allow_unknown_host=self.config.ssh.allow_unknown_host,
            known_hosts_path=self.config.ssh.known_hosts_path,
            max_alert_lines=self._runtime_limit("max_current_alert_lines", 1000),
            max_current_alert_bytes=self._runtime_limit(
                "max_current_alert_bytes", 20 * 1024 * 1024
            ),
            max_alert_line_bytes=self._runtime_limit("max_alert_line_bytes", 1024 * 1024),
            max_archive_days=self._runtime_limit("max_archive_days", 31),
            max_archive_records=self._runtime_limit("max_archive_records", 100000),
            max_archive_bytes=self._runtime_limit("max_archive_bytes", 100 * 1024 * 1024),
            max_archive_line_bytes=self._runtime_limit("max_archive_line_bytes", 1024 * 1024),
        )

    def _read_current_alerts_sync(self, max_lines: int) -> tuple[bool, List[Dict[str, Any]]]:
        """Connect, read, and close in one worker-thread ownership boundary."""
        ssh_reader = self._create_ssh_reader()
        if not ssh_reader.connect():
            ssh_reader.disconnect()
            return False, []
        try:
            return True, ssh_reader.read_alerts(max_lines)
        finally:
            ssh_reader.disconnect()

    def _read_archives_sync(self, archive_days: int) -> tuple[bool, List[Dict[str, Any]]]:
        """Connect, read a bounded archive request, and always close the client."""
        ssh_reader = self._create_ssh_reader()
        if not ssh_reader.connect():
            ssh_reader.disconnect()
            return False, []
        try:
            return True, ssh_reader.read_archives_smart(archive_days)
        finally:
            ssh_reader.disconnect()

    def _ssh_enabled(self) -> bool:
        return bool(
            self.config.ssh.host
            and self.config.ssh.username
            and self.config.ssh.password
        )

    def _start_background_task(self, coroutine, *, kind: str) -> asyncio.Task:
        """Track application-owned tasks so shutdown and exclusivity are deterministic."""
        if getattr(self, "_shutting_down", False):
            coroutine.close()
            raise HTTPException(status_code=503, detail="Application shutdown is in progress")
        if not hasattr(self, "_background_tasks"):
            self._background_tasks = set()
        if not hasattr(self, "_rag_build_task"):
            self._rag_build_task = None
        if not hasattr(self, "_analysis_task"):
            self._analysis_task = None
        if kind == "analysis":
            active_analysis = self._analysis_task
            if active_analysis is not None and not active_analysis.done():
                coroutine.close()
                raise HTTPException(status_code=409, detail="An alert analysis is already running")
        if len(self._background_tasks) >= self._runtime_limit("max_background_tasks", 8):
            coroutine.close()
            raise HTTPException(status_code=429, detail="Too many background operations")
        task = asyncio.create_task(coroutine, name=f"soc-{kind}")
        self._background_tasks.add(task)
        if kind == "rag-build":
            reservation = self._rag_build_task
            if reservation is not None and not reservation.done():
                reservation.cancel()
            self._rag_build_task = task
        elif kind == "analysis":
            self._analysis_task = task

        def finalize(done: asyncio.Task) -> None:
            self._background_tasks.discard(done)
            if self._rag_build_task is done:
                self._rag_build_task = None
            if self._analysis_task is done:
                self._analysis_task = None
            if done.cancelled():
                return
            try:
                error = done.exception()
            except asyncio.CancelledError:
                return
            if error:
                log_sanitized_exception(f"Background {kind} operation failed", error)

        task.add_done_callback(finalize)
        return task

    def _runtime_limit(self, name: str, default: int) -> int:
        config = getattr(self, "config", None)
        runtime = getattr(config, "runtime", None)
        return max(1, int(getattr(runtime, name, default)))

    @staticmethod
    def _active_rag_counts(
        status_payload: Dict[str, Any]
    ) -> tuple[int, int, int, int]:
        """Return active archive, source-document, document-chunk, and total counts."""
        def count(*keys: str) -> int:
            for key in keys:
                if key in status_payload and status_payload[key] is not None:
                    try:
                        return max(0, int(status_payload[key]))
                    except (TypeError, ValueError):
                        return 0
            return 0

        archive_records = count("active_archive_records", "alerts_with_embeddings")
        source_documents = count(
            "active_source_documents", "uploaded_documents_with_embeddings"
        )
        document_chunks = count(
            "active_document_chunks",
            "custom_doc_chunks_with_embeddings",
            "docs_with_embeddings",
        )
        total_chunks = count("active_total_chunks")
        if status_payload.get("active_total_chunks") is None:
            total_chunks = archive_records + document_chunks
        return archive_records, source_documents, document_chunks, total_chunks

    async def _run_blocking(self, function, *args, **kwargs):
        """Run bounded blocking work on the shutdown-aware executor."""
        admission = getattr(self, "_worker_admission", None)
        if admission is not None and not admission.acquire(blocking=False):
            raise HTTPException(
                status_code=503,
                detail="The bounded worker pool is busy; retry later",
            )
        loop = asyncio.get_running_loop()
        try:
            future = loop.run_in_executor(
                getattr(self, "_executor", None),
                partial(function, *args, **kwargs),
            )
        except BaseException:
            if admission is not None:
                admission.release()
            raise
        if admission is not None:
            future.add_done_callback(lambda _done: admission.release())
        # Shield the executor future so request/task cancellation does not free
        # admission while the non-preemptible callable is still running.
        return await asyncio.shield(future)

    async def _drain_background_tasks(self) -> None:
        """Await admitted workflows because their worker callables are not preemptible."""
        tasks = list(getattr(self, "_background_tasks", ()))
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _shutdown_runtime(self) -> None:
        """Run every teardown boundary even when an earlier cleanup step fails."""
        self._shutting_down = True
        failures = []

        async def attempt_async(label, operation) -> None:
            try:
                await operation()
            except BaseException as error:
                failures.append(error)
                if not isinstance(error, asyncio.CancelledError):
                    log_sanitized_exception(f"Shutdown step failed ({label})", error)

        def attempt_sync(label, operation) -> None:
            try:
                operation()
            except BaseException as error:
                failures.append(error)
                if not isinstance(error, asyncio.CancelledError):
                    log_sanitized_exception(f"Shutdown step failed ({label})", error)

        await attempt_async("progress cleanup", self.progress_tracker.stop_cleanup_task)
        attempt_sync(
            "generation cancellation",
            lambda: self.report_generator.cancel_active_generations(permanent=True),
        )
        await attempt_async("monitoring stop", self.live_monitoring.shutdown)

        # Executor callables cannot be cancelled safely once running. Let
        # admitted background workflows reach their defined commit/cleanup
        # boundary before database resources are closed.
        await attempt_async("background workflow drain", self._drain_background_tasks)

        # A workflow that crossed its commit boundary during the drain must not
        # be able to leave a newly created monitoring task behind.
        await attempt_async("final monitoring stop", self.live_monitoring.shutdown)
        attempt_sync(
            "final generation cancellation",
            lambda: self.report_generator.cancel_active_generations(permanent=True),
        )
        await attempt_async(
            "worker executor drain",
            lambda: asyncio.to_thread(
                self._executor.shutdown,
                wait=True,
                cancel_futures=True,
            ),
        )
        attempt_sync("report pipeline close", self.report_generator.close)

        if failures:
            raise failures[0]

    @staticmethod
    def _origin_is_same_host(headers) -> bool:
        """Reject browser cross-origin state changes while retaining non-browser API use."""
        fetch_site = str(headers.get("sec-fetch-site", "") or "").strip().lower()
        if fetch_site and fetch_site not in {"same-origin", "none"}:
            return False
        candidate = str(headers.get("origin") or headers.get("referer") or "").strip()
        if not candidate:
            return True
        if candidate.lower() == "null":
            return False
        expected = urlsplit("//" + str(headers.get("host") or ""), scheme="http").hostname
        supplied = urlsplit(candidate).hostname
        if not expected or not supplied:
            return False
        return secrets.compare_digest(expected.lower(), supplied.lower())

    def _install_security_middleware(self) -> None:
        @self.app.middleware("http")
        async def browser_security_boundary(request: Request, call_next):
            if request.method.upper() in {"POST", "PUT", "PATCH", "DELETE"}:
                if not self._origin_is_same_host(request.headers):
                    return JSONResponse(
                        status_code=403,
                        content={"detail": "Cross-origin state-changing requests are not allowed"},
                    )
            response = await call_next(request)
            response.headers["Cache-Control"] = "no-store"
            response.headers["X-Content-Type-Options"] = "nosniff"
            response.headers["X-Frame-Options"] = "DENY"
            response.headers["Referrer-Policy"] = "no-referrer"
            response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
            response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
            response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; base-uri 'self'; form-action 'self'; "
                "frame-ancestors 'none'; object-src 'none'; img-src 'self' data:; "
                "connect-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
                "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net"
            )
            if request.url.scheme == "https":
                response.headers["Strict-Transport-Security"] = "max-age=31536000"
            return response

    def _collect_system_checks(self, rag_status: Dict[str, Any]):
        """Collect filesystem/dependency/database health away from the event loop."""
        is_env_valid, env_issues = validate_environment()
        preflight = build_preflight_report(self.config, rag_status=rag_status)
        return is_env_valid, env_issues, preflight

    @staticmethod
    def _store_bounded(mapping: Dict[str, Any], key: str, value: Any, limit: int) -> None:
        if key not in mapping and len(mapping) >= limit:
            mapping.pop(next(iter(mapping)))
        mapping[key] = value

    async def _read_upload_limited(self, file: UploadFile, max_bytes: int) -> bytes:
        """Read an upload with an enforced limit even when Content-Length is absent."""
        chunks = []
        total = 0
        chunk_size = 1024 * 1024
        while True:
            chunk = await file.read(min(chunk_size, max_bytes - total + 1))
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise HTTPException(status_code=413, detail="Uploaded file exceeds the configured size limit")
            chunks.append(chunk)
        return b"".join(chunks)

    async def _read_json_limited(self, request: Request, max_bytes: int = 5 * 1024 * 1024) -> Any:
        chunks = []
        total = 0
        async for chunk in request.stream():
            total += len(chunk)
            if total > max_bytes:
                raise HTTPException(status_code=413, detail="JSON request exceeds the configured size limit")
            chunks.append(chunk)
        try:
            return json.loads(b"".join(chunks))
        except (json.JSONDecodeError, UnicodeDecodeError) as error:
            raise HTTPException(status_code=400, detail="Request body must be valid UTF-8 JSON") from error

    def _websocket_is_authenticated(self, websocket: WebSocket) -> bool:
        if not self._origin_is_same_host(websocket.headers):
            return False
        authorization = websocket.headers.get("authorization", "")
        if not authorization.lower().startswith("basic "):
            return False
        try:
            decoded = base64.b64decode(authorization.split(None, 1)[1], validate=True).decode("utf-8")
            username, password = decoded.split(":", 1)
        except (ValueError, UnicodeDecodeError):
            return False
        return secrets.compare_digest(username, self.config.web.username) and secrets.compare_digest(
            password, self.config.web.password
        )

    @staticmethod
    def _get_alert_root_for_validation(alert: Dict[str, Any], index: int) -> Dict[str, Any]:
        """Return the Wazuh alert body, accepting both raw and Elasticsearch-style _source wrappers."""
        if "_source" not in alert:
            return alert

        source = alert.get("_source")
        if not isinstance(source, dict):
            raise ValueError(f"Alert {index}: _source must be a JSON object")
        return source

    @staticmethod
    def _path_value(value: Dict[str, Any], path: str) -> Any:
        """Read either a literal dotted key or its nested-object equivalent."""
        if path in value:
            return value.get(path)
        current: Any = value
        for part in path.split("."):
            if not isinstance(current, dict) or part not in current:
                return None
            current = current.get(part)
        return current

    @staticmethod
    def _set_nested_missing(root: Dict[str, Any], path: str, value: Any) -> bool:
        if value in (None, "", [], {}):
            return False
        current = root
        parts = path.split(".")
        for part in parts[:-1]:
            child = current.get(part)
            if not isinstance(child, dict):
                child = {}
                current[part] = child
            current = child
        if current.get(parts[-1]) in (None, "", [], {}):
            current[parts[-1]] = value
            return True
        return False

    @classmethod
    def _bounded_unknown_fields(
        cls, value: Any, depth: int = 0, budget: Optional[List[int]] = None
    ) -> Dict[str, Any]:
        """Keep a small analyst-visible sample of otherwise unknown fields."""
        if budget is None:
            budget = [32]
        if not isinstance(value, dict) or depth > 5 or budget[0] <= 0:
            return {}
        known = {
            "rule", "agent", "manager", "decoder", "data", "timestamp", "full_log",
            "location", "_source", "event_type", "src_ip", "dest_ip", "src_port",
            "dest_port", "proto", "app_proto", "alert", "http", "dns", "tls",
            "flow", "fileinfo", "files", "process", "network", "source",
            "destination", "url", "file", "host", "user", "vulnerability", "threat",
            "event", "affected_items", "alerts",
        }
        output: Dict[str, Any] = {}
        for key in sorted(value, key=lambda item: str(item)):
            if budget[0] <= 0:
                break
            text_key = str(key)
            child = value.get(key)
            if text_key.lower() in known:
                nested = cls._bounded_unknown_fields(child, depth + 1, budget)
                if nested:
                    output[text_key] = nested
                continue
            if isinstance(child, dict):
                nested = cls._bounded_unknown_fields(child, depth + 1, budget)
                if nested:
                    output[text_key] = nested
            elif isinstance(child, list):
                safe = [item for item in child[:8] if isinstance(item, (str, int, float, bool))]
                if safe:
                    output[text_key] = safe
                    budget[0] -= 1
            elif isinstance(child, (str, int, float, bool)) and str(child)[:1024]:
                output[text_key] = str(child)[:1024] if isinstance(child, str) else child
                budget[0] -= 1
        return output

    @staticmethod
    def _parse_embedded_event(value: Any, depth: int = 0) -> Optional[Dict[str, Any]]:
        if depth > 2 or not isinstance(value, str) or not value.strip() or len(value) > 65536:
            return None
        candidate = value.strip()
        if not (candidate.startswith("{") and candidate.endswith("}")):
            return None
        try:
            parsed = json.loads(candidate)
        except (json.JSONDecodeError, RecursionError):
            return None
        return parsed if isinstance(parsed, dict) else None

    def _normalize_uploaded_alert_shape(self, alert: Dict[str, Any], index: int) -> Dict[str, Any]:
        """Canonicalize an uploaded alert through the shared ingestion boundary.

        Manual upload, SSH live ingestion and SSH archive ingestion all use
        AlertNormalizer, so a native Wazuh decoder record is understood
        identically no matter how it arrived.
        """
        return AlertNormalizer.normalize(alert, index=index, ingestion_source="manual_upload")

    def _pre_read_upload_error(self, file: UploadFile) -> Optional[str]:
        filename = self._safe_upload_filename(file.filename)
        declared_size = getattr(file, "size", None)
        if not filename or declared_size in (None, ""):
            return None
        try:
            declared_size_bytes = int(declared_size)
        except (TypeError, ValueError):
            return None

        max_size = DocumentValidator.max_size_bytes(filename)
        if max_size is not None and declared_size_bytes > max_size:
            file_size_mb = declared_size_bytes / (1024 * 1024)
            max_size_mb = max_size / (1024 * 1024)
            return f"File too large: {file_size_mb:.1f}MB. Max allowed: {max_size_mb:.0f}MB"
        return None

    @staticmethod
    def _safe_upload_filename(value: Any) -> str:
        """Return a bounded display/extension name without path or control data."""
        candidate = str(value or "").replace("\\", "/").rsplit("/", 1)[-1].strip()
        candidate = re.sub(r"[\x00-\x1f\x7f]", "_", candidate)
        candidate = re.sub(r"[^A-Za-z0-9._ ()\[\]-]", "_", candidate)
        if candidate in {"", ".", ".."}:
            return ""
        suffix = Path(candidate).suffix[:20]
        stem_limit = max(1, 160 - len(suffix))
        stem = Path(candidate).stem[:stem_limit]
        return f"{stem}{suffix}" if suffix else candidate[:160]

    @staticmethod
    def _require_supported_document_type(filename: str) -> None:
        suffix = Path(filename).suffix.lower()
        if suffix not in DocumentValidator.SUPPORTED_TYPES:
            raise HTTPException(status_code=415, detail="Unsupported CTI document type")

    def _parse_uploaded_alert_template(self, file_content: bytes, filename: str) -> List[Dict[str, Any]]:
        """Parse uploaded JSON alert templates for offline/manual testing."""
        if Path(filename).suffix.lower() not in {".json", ".jsonl", ".ndjson"}:
            raise ValueError("Alert template must be a .json, .jsonl, or .ndjson file")

        try:
            text = file_content.decode("utf-8-sig")
        except UnicodeDecodeError as error:
            raise ValueError("Alert template must be valid UTF-8 text") from error

        text = text.strip()
        if not text:
            raise ValueError("Alert template file is empty")

        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            # Allow newline-delimited JSON as a convenience for copied alerts.json lines.
            alerts = []
            for line_number, line in enumerate(text.splitlines(), 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    item = json.loads(line)
                except json.JSONDecodeError as e:
                    raise ValueError(f"Invalid JSON at line {line_number}: {e}") from e
                if not isinstance(item, dict):
                    raise ValueError(f"Line {line_number} must be a JSON object")
                alerts.append(item)
            payload = alerts

        if isinstance(payload, dict):
            if isinstance(payload.get("alerts"), list):
                alerts = payload["alerts"]
            elif isinstance(payload.get("affected_items"), list):
                alerts = payload["affected_items"]
            elif isinstance(payload.get("data"), dict) and isinstance(payload["data"].get("affected_items"), list):
                alerts = payload["data"]["affected_items"]
            else:
                alerts = [payload]
        elif isinstance(payload, list):
            alerts = payload
        else:
            raise ValueError(
                "Alert template must be a JSON object, array, alerts wrapper, or affected_items wrapper"
            )

        if not alerts:
            raise ValueError("Alert template contains no alerts")
        max_alert_records = self._runtime_limit("max_alert_records", 1000)
        if len(alerts) > max_alert_records:
            raise ValueError(
                f"Alert template may contain at most {max_alert_records} alerts"
            )
        if not all(isinstance(alert, dict) for alert in alerts):
            raise ValueError("Every alert entry must be a JSON object")

        return [
            self._normalize_uploaded_alert_shape(alert, index)
            for index, alert in enumerate(alerts, 1)
        ]
    
    def _setup_routes(self):
        def authenticate(credentials: HTTPBasicCredentials = Depends(self.security)):
            username_match = secrets.compare_digest(credentials.username, self.config.web.username)
            password_match = secrets.compare_digest(credentials.password, self.config.web.password)
            if not (username_match and password_match):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Incorrect username or password",
                    headers={"WWW-Authenticate": "Basic"},
                )
            return credentials.username

        reports_root = Path(self.config.paths.reports_dir).resolve()

        @self.app.get("/api/report-chart/{filename}")
        async def get_report_chart(filename: str, username: str = Depends(authenticate)):
            """Serve generated report charts to the authenticated report preview."""
            chart_path = resolve_chart_path(reports_root, filename)
            if not chart_path.is_file():
                raise HTTPException(status_code=404, detail="Report chart not found")
            return FileResponse(chart_path, media_type="image/png")
        
        @self.app.get("/", response_class=HTMLResponse)
        async def dashboard(request: Request, username: str = Depends(authenticate)):
            """Enhanced dashboard with live monitoring and PDF conversion"""
            config_summary = self.config.get_summary()
            
            report_entries = []
            reports_dir = Path(self.config.paths.reports_dir)
            default_page_size = 5
            try:
                requested_page_size = int(request.query_params.get("existing_page_size", default_page_size))
                existing_page_size = max(1, min(50, requested_page_size))
            except ValueError:
                existing_page_size = default_page_size
            try:
                requested_page = int(request.query_params.get("existing_page", 1))
                existing_page = max(1, requested_page)
            except ValueError:
                existing_page = 1
            
            if reports_dir.exists():
                for report_file in sorted(reports_dir.glob("*.md"), reverse=True):
                    try:
                        stat = report_file.stat()
                        report_entries.append({
                            "filename": report_file.name,
                            "timestamp": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                            "created_at": stat.st_mtime,
                            "size": f"{stat.st_size / 1024:.1f} KB",
                            "path": report_file,
                        })
                    except Exception as e:
                        log_sanitized_exception("Report inventory entry failed", e)
            
            report_entries.sort(key=lambda r: r.get("created_at", 0), reverse=True)
            
            print(f"📊 Total reports found: {len(report_entries)}")
            total_existing = len(report_entries)
            total_existing_pages = math.ceil(total_existing / existing_page_size) if total_existing else 0
            if total_existing_pages and existing_page > total_existing_pages:
                existing_page = total_existing_pages
            start = (existing_page - 1) * existing_page_size if total_existing else 0
            end = start + existing_page_size
            paginated_existing = []
            for entry in report_entries[start:end]:
                try:
                    with entry["path"].open("r", encoding="utf-8") as handle:
                        content = handle.read(1_000_001)
                    if len(content) > 1_000_000:
                        content = content[:1_000_000] + "\n\n[Preview truncated.]"
                    rendered = {key: value for key, value in entry.items() if key != "path"}
                    rendered["content"] = content
                    rendered["preview"] = content[:500] + ("..." if len(content) > 500 else "")
                    paginated_existing.append(rendered)
                except Exception as e:
                    log_sanitized_exception("Report preview failed", e)
            
            context = {
                "request": request,
                "config_summary": config_summary,
                "existing_reports": paginated_existing,
                "existing_reports_page": existing_page,
                "existing_reports_page_size": existing_page_size,
                "existing_reports_total_pages": total_existing_pages,
                "existing_reports_total": total_existing,
                "static_version": int(datetime.now().timestamp())
            }
            return self.templates.TemplateResponse("dashboard.html", context)
        
        @self.app.websocket("/ws/progress/{session_id}")
        async def websocket_progress(websocket: WebSocket, session_id: str):
            try:
                if (
                    not self._websocket_is_authenticated(websocket)
                    or not self.progress_tracker._is_valid_session_id(session_id)
                ):
                    await websocket.close(code=1008)
                    return

                await websocket.accept()
                print(f"🔌 Progress WebSocket connected: {session_id}")
                
                connected = await self.progress_tracker.connect(session_id, websocket, "progress_tracking")
                
                if not connected:
                    await websocket.send_json({
                        "error": "Failed to establish progress tracking",
                        "session_id": session_id
                    })
                    return
                
                await websocket.send_json({
                    "message": f"🔗 Connected to progress tracker for session: {session_id}",
                    "progress": 0,
                    "status": "success",
                    "timestamp": datetime.now().strftime("%H:%M:%S")
                })
                
                try:
                    while True:
                        data = await asyncio.wait_for(websocket.receive_text(), timeout=600.0)
                        if data == "ping":
                            await websocket.send_text("pong")
                                
                except asyncio.TimeoutError:
                    print(f"⏱️ Progress WebSocket timeout: {session_id}")
                except WebSocketDisconnect:
                    print(f"🔌 Progress WebSocket disconnected: {session_id}")
                except Exception as e:
                    log_sanitized_exception("Progress WebSocket failed", e)
                    
            except Exception as e:
                log_sanitized_exception("Progress WebSocket setup failed", e)
            finally:
                try:
                    self.progress_tracker.disconnect(session_id)
                    print(f"🧹 Progress WebSocket cleanup: {session_id}")
                except Exception:
                    pass
    
        @self.app.post("/build-rag")
        async def build_rag(
            use_archives: bool = Form(False),
            use_uploads: bool = Form(False),
            ragDays: Optional[int] = Form(None),
            customFiles: List[UploadFile] = File([]),
            build_mode: str = Form("extend"),
            confirm_replace: bool = Form(False),
            username: str = Depends(authenticate)
        ):
            active_build = getattr(self, "_rag_build_task", None)
            if active_build is not None and not active_build.done():
                raise HTTPException(status_code=409, detail="A RAG corpus build is already running")
            # Reserve the single build slot before the first upload await. The
            # request-task callback releases it on validation/read failure.
            reservation = asyncio.get_running_loop().create_future()
            self._rag_build_task = reservation
            request_task = asyncio.current_task()
            if request_task is not None:
                def release_reservation(_done: asyncio.Task) -> None:
                    if self._rag_build_task is reservation:
                        reservation.cancel()
                        self._rag_build_task = None
                request_task.add_done_callback(release_reservation)
            max_document_files = self._runtime_limit("max_document_files", 50)
            max_document_batch_bytes = self._runtime_limit(
                "max_document_batch_bytes", 100 * 1024 * 1024
            )
            if len(customFiles) > max_document_files:
                raise HTTPException(
                    status_code=413,
                    detail=f"At most {max_document_files} documents may be uploaded per build",
                )
            if use_uploads and not any(file.filename for file in customFiles):
                raise HTTPException(
                    status_code=400,
                    detail="Upload source was selected but no CTI document was provided",
                )
            max_archive_days = self._runtime_limit("max_archive_days", 31)
            if ragDays is not None and not 1 <= ragDays <= max_archive_days:
                raise HTTPException(
                    status_code=400,
                    detail=f"Archive days must be between 1 and {max_archive_days}",
                )
            existing_status = await self._run_blocking(
                self.report_generator.get_rag_status
            )
            if existing_status.get("error"):
                raise HTTPException(
                    status_code=503,
                    detail=(
                        "RAG status is unavailable; no corpus mutation was started"
                    ),
                )
            has_existing_data = (
                existing_status.get('alerts_with_embeddings', 0) > 0 or 
                existing_status.get('docs_with_embeddings', 0) > 0
            )
            has_active_corpus = bool(
                existing_status.get("active_corpus_id") or has_existing_data
            )
            has_active_ready_corpus = bool(existing_status.get("ready"))

            requested_mode = str(build_mode or "extend").strip().lower()
            if requested_mode not in {"extend", "replace"}:
                raise HTTPException(
                    status_code=400,
                    detail="RAG build mode must be either 'extend' or 'replace'",
                )

            has_requested_sources = bool(use_archives or use_uploads)
            if requested_mode == "replace" and has_active_corpus:
                if not has_requested_sources:
                    raise HTTPException(
                        status_code=400,
                        detail="Select at least one source for a replacement RAG build",
                    )
                if not confirm_replace:
                    raise HTTPException(
                        status_code=400,
                        detail=(
                            "Replacing the active RAG context requires explicit confirmation"
                        ),
                    )

            if not has_requested_sources and not has_active_corpus:
                raise HTTPException(
                    status_code=400,
                    detail=(
                        "No active RAG corpus found. Select at least one source "
                        "for the initial build."
                    ),
                )
            if not has_requested_sources:
                effective_mode = "refresh"
            elif has_active_ready_corpus:
                effective_mode = requested_mode
            elif has_active_corpus:
                if requested_mode == "extend":
                    raise HTTPException(
                        status_code=409,
                        detail=(
                            "The active RAG corpus is not validated and cannot be "
                            "extended losslessly. Choose replacement mode and confirm it."
                        ),
                    )
                effective_mode = "replace"
            else:
                # There is no compatible active corpus to extend. The first
                # successful build creates the initial immutable snapshot.
                effective_mode = "replace"
            
            session_id = generate_session_id()
            
            uploaded_files = []
            if use_uploads and customFiles:
                print(f"\n📤 Queuing {len(customFiles)} uploaded files for pgvector storage...")
                batch_hashes = set()
                batch_bytes = 0
                for file in customFiles:
                    if file.filename:
                        try:
                            safe_filename = self._safe_upload_filename(file.filename)
                            if not safe_filename:
                                raise HTTPException(status_code=400, detail="Uploaded document needs a valid filename")
                            self._require_supported_document_type(safe_filename)
                            pre_read_error = self._pre_read_upload_error(file)
                            if pre_read_error:
                                raise HTTPException(status_code=413, detail=pre_read_error)
                            per_file_limit = DocumentValidator.max_size_bytes(safe_filename)
                            effective_limit = min(
                                per_file_limit or max_document_batch_bytes,
                                max_document_batch_bytes,
                            )
                            content = await self._read_upload_limited(file, effective_limit)
                            batch_bytes += len(content)
                            if batch_bytes > max_document_batch_bytes:
                                raise HTTPException(
                                    status_code=413,
                                    detail="Document upload batch exceeds the configured size limit",
                                )
                            content_hash = hashlib.sha256(content).hexdigest()
                            if content_hash in batch_hashes:
                                print("Duplicate in current upload batch skipped")
                                continue
                            batch_hashes.add(content_hash)
                            uploaded_files.append({
                                "filename": safe_filename,
                                "content": content
                            })
                            print("Queued uploaded document for background extraction")
                        except HTTPException:
                            raise
                        except Exception as e:
                            log_sanitized_exception("Document upload read failed", e)
                            raise HTTPException(status_code=400, detail="Unable to read an uploaded document") from e
                
                if uploaded_files:
                    print(f"💾 Total uploaded files queued for extraction: {len(uploaded_files)}")
                else:
                    print(f"⚠️ No new documents to add (all may be duplicates)")
            
            self._start_background_task(self._build_rag_with_progress(
                session_id=session_id,
                use_archives=use_archives,
                use_uploads=use_uploads,
                archive_days=ragDays,
                custom_docs=[],
                uploaded_files=uploaded_files,
                build_mode=effective_mode,
            ), kind="rag-build")

            operation_messages = {
                "extend": "Active RAG context extension started",
                "replace": (
                    "Initial RAG context build started"
                    if not has_active_corpus
                    else "Confirmed RAG context replacement started"
                ),
                "refresh": "Active RAG context status refresh started",
            }
            return {
                "session_id": session_id,
                "build_mode": effective_mode,
                "message": operation_messages[effective_mode],
            }
        @self.app.post("/generate-visual-report")
        async def generate_visual_report(username: str = Depends(authenticate)):
            """Generate a visual report with charts only"""
            session_id = generate_session_id()
            self._start_background_task(
                self._generate_visual_report_with_progress(session_id),
                kind="visual-report",
            )
            return {"session_id": session_id, "message": "Visual report generation started"}
        
        @self.app.get("/chart-capabilities")
        async def get_chart_capabilities(username: str = Depends(authenticate)):
            """Get chart generation capabilities"""
            return self.report_generator.get_chart_capabilities()
        
        @self.app.post("/analyze-alerts")
        async def analyze_alerts(
            include_charts: bool = Form(True),
            alertTemplate: Optional[UploadFile] = File(None),
            username: str = Depends(authenticate)
        ):
            """Analyze current alerts with RAG"""
            try:
                active_analysis = getattr(self, "_analysis_task", None)
                if (
                    (active_analysis is not None and not active_analysis.done())
                    or bool(getattr(self.report_generator, "generation_active", False))
                ):
                    raise HTTPException(status_code=409, detail="An alert analysis is already running")
                print(f"📊 /analyze-alerts endpoint called with include_charts={include_charts}")
                
                if not self.report_generator.rag_ready:
                    print("❌ RAG not ready")
                    raise HTTPException(
                        status_code=400, 
                        detail="RAG context not ready. Please build RAG first."
                    )
                
                session_id = generate_session_id()
                print(f"✅ Generated session_id: {session_id}")
                
                selected_alerts = None
                alert_source = None
                if alertTemplate and alertTemplate.filename:
                    try:
                        alert_filename = self._safe_upload_filename(alertTemplate.filename)
                        if not alert_filename:
                            raise HTTPException(status_code=400, detail="Alert upload needs a valid filename")
                        content = await self._read_upload_limited(
                            alertTemplate,
                            self._runtime_limit("max_alert_upload_bytes", 5 * 1024 * 1024),
                        )
                        selected_alerts = self._parse_uploaded_alert_template(content, alert_filename)
                        # The upload name is display/transport metadata, never alert evidence.
                        alert_source = "Manual uploaded alert"
                        print(f"Loaded {len(selected_alerts)} alerts from uploaded template")
                    except ValueError as e:
                        raise HTTPException(status_code=400, detail=str(e))

                self._start_background_task(self._analyze_alerts_with_progress(
                    session_id, 
                    selected_alerts=selected_alerts,
                    include_charts=include_charts,
                    alert_source=alert_source
                ), kind="analysis")
                
                response = {
                    "session_id": session_id,
                    "message": "Alert analysis started",
                    "poll_timeout_ms": (max(1, int(self.config.llm.timeout)) + 60) * 1000,
                }
                print(f"✅ Returning response: {response}")
                return response
                
            except HTTPException:
                raise
            except Exception as e:
                log_sanitized_exception("Analyze-alerts request failed", e)
                raise HTTPException(
                    status_code=500,
                    detail="Failed to start analysis"
                )
        
        @self.app.post("/convert-to-pdf")
        async def convert_to_pdf(
            filename: str = Form(...),
            username: str = Depends(authenticate)
        ):
            try:
                result = await self.pdf_api_handlers.handle_single_conversion(filename)
                
                if result["success"]:
                    return {
                        "pdf_filename": result["pdf_filename"],
                        "message": result["message"],
                        "method": result["method"]
                    }
                else:
                    status_code = 400 if result["error"].startswith("Invalid filename") else 500
                    raise HTTPException(
                        status_code=status_code, 
                        detail=result["error"]
                    )
            except HTTPException:
                raise
            except Exception as e:
                log_sanitized_exception("PDF conversion route failed", e)
                raise HTTPException(
                    status_code=500, 
                    detail="PDF conversion failed"
                ) from e
        
        @self.app.post("/batch-convert-pdf")
        async def batch_convert_pdf(username: str = Depends(authenticate)):
            """Convert all markdown reports to PDF"""
            try:
                result = await self.pdf_api_handlers.handle_batch_conversion()
                
                if result["success"]:
                    return result["results"]
                else:
                    raise HTTPException(
                        status_code=500,
                        detail=result["error"]
                    )
            except HTTPException:
                raise
            except Exception as e:
                log_sanitized_exception("PDF batch conversion route failed", e)
                raise HTTPException(
                    status_code=500, 
                    detail="Batch conversion failed"
                ) from e
        
        @self.app.get("/pdf-status")
        async def get_pdf_status(username: str = Depends(authenticate)):
            """Get enhanced PDF conversion capabilities"""
            return self.pdf_api_handlers.get_status()
        
        @self.app.post("/set-auto-convert")
        async def set_auto_convert(
            request: Request,
            username: str = Depends(authenticate)
        ):
            """Set auto-convert to PDF setting"""
            try:
                data = await self._read_json_limited(request)
                enabled = data.get('enabled', False)
                
                self.auto_convert_enabled = enabled
                
                return {
                    "success": True,
                    "enabled": enabled,
                    "message": f"Auto-convert {'enabled' if enabled else 'disabled'}"
                }
            except Exception as e:
                log_sanitized_exception("Auto-convert setting failed", e)
                raise HTTPException(
                    status_code=500,
                    detail="Failed to set auto-convert"
                ) from e
        
        @self.app.get("/auto-convert-status")
        async def get_auto_convert_status(username: str = Depends(authenticate)):
            """Get current auto-convert setting"""
            return {
                "enabled": getattr(self, 'auto_convert_enabled', False),
                "pdf_available": self.pdf_converter.conversion_available
            }
        
        @self.app.get("/rag-status")
        async def get_rag_status(username: str = Depends(authenticate)):
            """Get current RAG status"""
            return await self._run_blocking(self.report_generator.get_rag_status)

        @self.app.get("/reports")
        async def list_reports(
            page: int = Query(1, ge=1),
            page_size: int = Query(10, ge=1, le=100),
            include_all_markdown: bool = Query(False),
            username: str = Depends(authenticate)
        ):
            """List generated reports (both MD and PDF) with pagination"""
            reports = []
            reports_path = Path(self.config.paths.reports_dir)
            
            if reports_path.exists():
                for report_file in reports_path.glob("*"):
                    if report_file.suffix in ['.md', '.pdf', '.html']:
                        stat = report_file.stat()
                        file_type = "markdown" if report_file.suffix == '.md' else \
                                   "pdf" if report_file.suffix == '.pdf' else "html"
                        
                        reports.append({
                            "filename": report_file.name,
                            "created": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                            "size": f"{stat.st_size / 1024:.1f} KB",
                            "type": file_type
                        })
            
            reports.sort(key=lambda x: x["created"], reverse=True)
            total_items = len(reports)
            total_pages = math.ceil(total_items / page_size) if total_items else 0
            if total_pages and page > total_pages:
                page = total_pages
            start = (page - 1) * page_size if total_items else 0
            end = start + page_size
            paginated = reports[start:end]
            response = {
                "items": paginated,
                "page": page,
                "page_size": page_size,
                "total_items": total_items,
                "total_pages": total_pages
            }
            if include_all_markdown:
                response["markdown_reports"] = [
                    report["filename"] for report in reports if report["filename"].endswith('.md')
                ]
            return response
        
        @self.app.get("/reports/{filename}")
        async def download_report(filename: str, username: str = Depends(authenticate)):
            """Download or view report"""
            report_path = resolve_report_path(reports_root, filename)
            
            if not report_path.is_file():
                raise HTTPException(status_code=404, detail="Report not found")
            
            # Determine media type
            if filename.endswith('.pdf'):
                media_type = 'application/pdf'
            elif filename.endswith('.html'):
                media_type = 'text/html'
            else:
                media_type = 'text/markdown'
            
            return FileResponse(
                path=report_path,
                filename=filename,
                media_type=media_type
            )
        
        @self.app.get("/reports/{filename}/edit")
        async def edit_existing_report(request: Request, filename: str, username: str = Depends(authenticate)):
            """Open an existing markdown report inside the editor"""
            report_path = resolve_report_path(reports_root, filename)

            if not report_path.is_file():
                raise HTTPException(status_code=404, detail="Report not found")

            if report_path.suffix.lower() != ".md":
                raise HTTPException(status_code=400, detail="Only markdown reports can be edited")
            if report_path.stat().st_size > 5 * 1024 * 1024:
                raise HTTPException(status_code=413, detail="Report is too large for the web editor")

            try:
                markdown_text = report_path.read_text(encoding="utf-8")
                parsed_report = ReportParser.parse_report(markdown_text)
            except Exception as e:
                log_sanitized_exception("Report load failed", e)
                raise HTTPException(status_code=500, detail="Failed to load report") from e

            report_id = uuid.uuid4().hex
            metadata = parsed_report.setdefault("metadata", {})
            metadata["source_filename"] = filename
            self._store_bounded(
                self.draft_reports,
                report_id,
                parsed_report,
                self._runtime_limit("max_drafts", 100),
            )

            return RedirectResponse(url=f"/review-report/{report_id}", status_code=303)
        
        @self.app.get("/test-connection")
        async def test_connection(username: str = Depends(authenticate)):
            """Test SSH connection to Wazuh server"""
            try:
                connected, alerts = await self._run_blocking(
                    self._read_current_alerts_sync,
                    self._runtime_limit("max_current_alert_lines", 1000),
                )
            except Exception as error:
                log_sanitized_exception("SSH connection test failed", error)
                return {"status": "error", "message": "Remote alert file could not be read"}
            if not connected:
                return {"status": "error", "message": "Failed to establish SSH connection"}
            return {
                "status": "success",
                "message": "Connected successfully",
                "alerts_count": len(alerts),
            }
        
        @self.app.get("/system-status")
        async def system_status(username: str = Depends(authenticate)):
            """Get system status including chart capabilities"""
            rag_status = await self._run_blocking(
                self.report_generator.get_rag_status
            )
            is_env_valid, env_issues, runtime_preflight = await self._run_blocking(
                self._collect_system_checks,
                rag_status,
            )
            
            chart_capabilities = self.report_generator.get_chart_capabilities()
            
            return {
                "config": self.config.get_summary(),
                "runtime_preflight": runtime_preflight,
                "rag_status": rag_status,
                "environment": {
                    "valid": is_env_valid,
                    "issues": env_issues
                },
                "components": {
                    "rag_ready": bool(rag_status.get("ready")),
                    "auto_monitoring_enabled": self.live_monitoring.monitoring_enabled,
                    "pdf_available": self.pdf_converter.conversion_available,
                    "charts_available": chart_capabilities["charts_available"],
                    "progress_sessions": len(self.progress_tracker.websockets),
                    "document_processor": "ready"
                },
                "chart_info": chart_capabilities,
                "stats": self.progress_tracker.get_all_stats(),
                "monitoring_stats": self.live_monitoring.get_statistics() if self.live_monitoring.monitoring_enabled else None,
                "pdf_capabilities": self.pdf_converter.get_conversion_status(),
                "automatic_features": {
                    "persistent_ssh": self._ssh_enabled(),
                    "auto_start_monitoring": self._ssh_enabled(),
                    "continuous_alert_detection": self._ssh_enabled(),
                    "auto_report_generation": self._ssh_enabled(),
                    "visual_analysis": True
                }
            }
        
        @self.app.get("/api/report-metrics")
        async def get_report_metrics(username: str = Depends(authenticate)):
            """Get report generation timing metrics and statistics"""
            return self.report_generator.get_generation_metrics()
        
        @self.app.post("/check-duplicates")
        async def check_duplicates(
            files: List[UploadFile] = File([]),
            username: str = Depends(authenticate)
        ):
            """Check if uploaded files are duplicates before processing"""
            max_files = self._runtime_limit("max_document_files", 50)
            max_batch_bytes = self._runtime_limit("max_document_batch_bytes", 100 * 1024 * 1024)
            if len(files) > max_files:
                raise HTTPException(status_code=413, detail=f"At most {max_files} files may be checked")
            duplicates = []
            batch_bytes = 0

            for file in files:
                if file.filename:
                    try:
                        safe_filename = self._safe_upload_filename(file.filename)
                        if not safe_filename:
                            raise HTTPException(status_code=400, detail="Uploaded document needs a valid filename")
                        self._require_supported_document_type(safe_filename)
                        pre_read_error = self._pre_read_upload_error(file)
                        if pre_read_error:
                            raise HTTPException(status_code=413, detail=pre_read_error)
                        format_limit = DocumentValidator.max_size_bytes(safe_filename)
                        content = await self._read_upload_limited(
                            file,
                            min(format_limit or max_batch_bytes, max_batch_bytes),
                        )
                        batch_bytes += len(content)
                        if batch_bytes > max_batch_bytes:
                            raise HTTPException(
                                status_code=413,
                                detail="Duplicate-check batch exceeds the configured size limit",
                            )
                        await file.seek(0)  
                        
                        is_dup, hash_or_msg = self.document_processor.check_duplicate(
                            content, safe_filename
                        )
                        
                        if is_dup:
                            import re
                            hash_match = re.search(r'hash: ([a-f0-9]+)', hash_or_msg)
                            file_hash = hash_match.group(1) if hash_match else "unknown"
                            
                            duplicates.append({
                                "filename": safe_filename,
                                "hash": file_hash,
                                "message": hash_or_msg
                            })
                    except HTTPException:
                        raise
                    except Exception as e:
                        log_sanitized_exception("Duplicate check failed", e)
            
            return {
                "duplicates": duplicates,
                "total_checked": len(files),
                "duplicate_count": len(duplicates)
            }
                
        @self.app.get("/review-report/{report_id}", response_class=HTMLResponse)
        async def review_report(request: Request, report_id: str, username: str = Depends(authenticate)):
            """Load report editor with draft data"""
            if report_id not in self.draft_reports:
                raise HTTPException(status_code=404, detail="Draft report not found")
            
            draft_data = self.draft_reports[report_id]
            
            context = {
                "request": request,
                "report_id": report_id,
                "report_data": draft_data
            }
            return self.templates.TemplateResponse("report_editor.html", context)
        
        @self.app.post("/api/save-draft/{report_id}")
        async def save_draft(report_id: str, request: Request, username: str = Depends(authenticate)):
            """Save draft changes"""
            try:
                data = await self._read_json_limited(request)
                existing = self.draft_reports.get(report_id, {})
                if isinstance(existing, dict):
                    for preserved_field in (
                        "preserved_rich_sections_markdown",
                        "preserved_appendix_markdown",
                    ):
                        if existing.get(preserved_field) and not data.get(preserved_field):
                            data[preserved_field] = existing[preserved_field]
                self._store_bounded(
                    self.draft_reports,
                    report_id,
                    data,
                    self._runtime_limit("max_drafts", 100),
                )
                print("Draft saved")
                return {"success": True, "message": "Draft saved successfully"}
            except HTTPException:
                raise
            except Exception as e:
                log_sanitized_exception("Draft save failed", e)
                raise HTTPException(status_code=500, detail="Failed to save draft") from e
        
        @self.app.post("/api/approve-report/{report_id}")
        async def approve_report(report_id: str, request: Request, username: str = Depends(authenticate)):
            """Finalize and save approved report"""
            try:
                data = await self._read_json_limited(request)
                existing = self.draft_reports.get(report_id, {})
                if isinstance(existing, dict):
                    for preserved_field in (
                        "preserved_rich_sections_markdown",
                        "preserved_appendix_markdown",
                    ):
                        if existing.get(preserved_field) and not data.get(preserved_field):
                            data[preserved_field] = existing[preserved_field]
                
                # Validate first
                is_valid, errors = ReportParser.validate_report(data)
                if not is_valid:
                    return JSONResponse(
                        status_code=400,
                        content={"valid": False, "errors": errors}
                    )
                
                markdown = ReportParser.serialize_to_markdown(data)
                if hasattr(self.report_generator, "record_report_trace_stage"):
                    self.report_generator.record_report_trace_stage("final_serialized_markdown", markdown)
                
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
                filename = f"APPROVED_Threat_analysis_{timestamp}_{uuid.uuid4().hex[:8]}.md"
                report_path = Path(self.config.paths.reports_dir) / filename
                atomic_write_text(report_path, markdown)
                
                print(f"✅ Approved report saved: {filename}")
                
                self.report_generator.mark_report_approved()
                try:
                    await self._run_blocking(
                        self.report_generator.index_approved_report,
                        markdown,
                        filename
                    )
                except Exception as e:
                    log_sanitized_exception("Approved report indexing failed", e)
                
                if getattr(self, 'auto_convert_enabled', False):
                    await self._auto_convert_report(report_path)
                
                # Remove from drafts
                if report_id in self.draft_reports:
                    del self.draft_reports[report_id]
                
                return {
                    "success": True,
                    "filename": filename,
                    "message": "Report approved and saved successfully"
                }
                
            except HTTPException:
                raise
            except Exception as e:
                log_sanitized_exception("Report approval failed", e)
                raise HTTPException(status_code=500, detail="Failed to approve report") from e
        
        @self.app.post("/api/preview-report")
        async def preview_report(request: Request, username: str = Depends(authenticate)):
            """Generate markdown preview from edited data"""
            try:
                data = await self._read_json_limited(request)
                markdown = ReportParser.serialize_to_markdown(data)
                return {"markdown": markdown}
            except HTTPException:
                raise
            except Exception as e:
                log_sanitized_exception("Report preview failed", e)
                raise HTTPException(status_code=500, detail="Preview generation failed") from e
        
        @self.app.post("/api/validate-report")
        async def validate_report(request: Request, username: str = Depends(authenticate)):
            """Validate report data before approval"""
            try:
                data = await self._read_json_limited(request)
                is_valid, errors = ReportParser.validate_report(data)
                return {"valid": is_valid, "errors": errors}
            except HTTPException:
                raise
            except Exception as e:
                log_sanitized_exception("Report validation failed", e)
                raise HTTPException(status_code=500, detail="Validation failed") from e
            
        @self.app.get("/api/check-analysis-result/{session_id}")
        async def check_analysis_result(
            session_id: str,
            username: str = Depends(authenticate)
        ) -> Dict[str, Any]:
            """Check if analysis needs human review"""
            result = self.session_results.get(session_id)
            if result and isinstance(result, dict) and result.get("redirect"):
                return result
            return {"redirect": False, "report_id": None}    
        
        @self.app.get("/api/mitre-techniques")
        async def get_mitre_techniques(username: str = Depends(authenticate)):
            """Get all MITRE ATT&CK techniques"""
            try:
                mitre_file = Path(BASE_DIR) / "mitre_techniques.json"
                with open(mitre_file, 'r') as f:
                    techniques = json.load(f)
                return techniques
            except Exception as e:
                log_sanitized_exception("MITRE technique API catalog load failed", e)
                raise HTTPException(
                    status_code=503,
                    detail="MITRE technique catalog is unavailable",
                ) from e
        @self.app.get("/api/live-alerts")
        async def get_live_alerts(
            page: int = 1, 
            page_size: int = 50,
            min_severity: int = 0,
            username: str = Depends(authenticate)
        ):
            try:
                def get_rule_level(alert: Dict[str, Any]) -> int:
                    raw_level = alert.get('rule', {}).get('level', 0)
                    try:
                        return int(raw_level) if raw_level is not None else 0
                    except (TypeError, ValueError):
                        return 0

                page = max(1, page)
                page_size = max(1, min(page_size, 500))
               
                raw_alerts = await self.live_monitoring.persistent_ssh.read_alerts(
                    self._runtime_limit("max_current_alert_lines", 1000)
                )
                if (
                    not raw_alerts
                    and not (
                        self.live_monitoring.persistent_ssh.ssh_reader
                        and self.live_monitoring.persistent_ssh.ssh_reader.is_connected
                    )
                ):
                    return {
                        "success": False,
                        "total_alerts": 0,
                        "page": page,
                        "page_size": page_size,
                        "total_pages": 1,
                        "alerts": [],
                        "timestamp": datetime.now().isoformat(),
                        "is_live": False,
                        "message": "Wazuh server is unavailable. Upload a JSON alert template from the dashboard for offline testing."
                    }
                
                raw_alerts.reverse()
                
                if min_severity > 0:
                    filtered = [a for a in raw_alerts if get_rule_level(a) >= min_severity]
                else:
                    filtered = raw_alerts
                
                total = len(filtered)
                total_pages = (total + page_size - 1) // page_size if total > 0 else 1
                start = (page - 1) * page_size
                end = start + page_size
                page_alerts = filtered[start:end]

                processed_by_uuid = {}
                try:
                    page_alerts_for_processing = []
                    for raw_alert in page_alerts:
                        tagged_alert = dict(raw_alert)
                        tagged_alert["_alert_uuid"] = generate_alert_uuid(raw_alert)
                        page_alerts_for_processing.append(tagged_alert)

                    processed_page_alerts = await self._run_blocking(
                        self.report_generator.alert_analyzer.clean_log_data,
                        page_alerts_for_processing
                    )
                    for processed_alert in processed_page_alerts:
                        alert_uuid = processed_alert.get("alert_uuid")
                        if alert_uuid:
                            processed_by_uuid[alert_uuid] = processed_alert
                except Exception as processing_error:
                    log_sanitized_exception(
                        "Live alert enrichment was skipped",
                        processing_error,
                    )
                
                minimal_alerts = []
                for idx, alert in enumerate(page_alerts):
                    rule = alert.get('rule', {})
                    data = alert.get('data', {})
                    alert_uuid = generate_alert_uuid(alert)
                    processed_alert = processed_by_uuid.get(alert_uuid, {})
                    
                    minimal_alerts.append({
                        'alert_id': start + idx,
                        'alert_uuid': alert_uuid,
                        'timestamp': alert.get('timestamp', ''),
                        'rule_level': get_rule_level(alert),
                        'rule_description': rule.get('description', 'N/A'),
                        'src_ip': data.get('src_ip', '-'),
                        'dest_ip': data.get('dest_ip', '-'),
                        'agent_name': alert.get('agent', {}).get('name', 'N/A'),
                        'threat_classification': processed_alert.get('threat_classification', {}),
                    })                
                return {
                    "success": True,
                    "total_alerts": total,
                    "page": page,
                    "page_size": page_size,
                    "total_pages": total_pages,
                    "alerts": minimal_alerts,
                    "timestamp": datetime.now().isoformat(),
                    "is_live": True
                }
                
            except Exception as e:
                log_sanitized_exception("Live alert route failed", e)
                raise HTTPException(status_code=500, detail="Failed to read live alerts") from e

        @self.app.post("/analyze-selected-alerts")
        async def analyze_selected_alerts(
            request: Request,
            username: str = Depends(authenticate)
        ):
            """Analyze selected alerts by re-fetching recent Wazuh alerts."""
            try:
                active_analysis = getattr(self, "_analysis_task", None)
                if (
                    (active_analysis is not None and not active_analysis.done())
                    or bool(getattr(self.report_generator, "generation_active", False))
                ):
                    raise HTTPException(status_code=409, detail="An alert analysis is already running")
                data = await self._read_json_limited(request)
                selected_uuids = data.get('selected_uuids')
                selected_ids = data.get('selected_ids')
                
                identifiers: List[str] = []
                if selected_uuids:
                    identifiers = [str(uid) for uid in selected_uuids if uid]
                elif selected_ids:
                    identifiers = [str(uid) for uid in selected_ids if uid is not None]
                
                if not identifiers:
                    raise HTTPException(status_code=400, detail="No alerts selected")
                
                print(f"📊 Analyzing {len(identifiers)} selected alerts...")
                
                # Re-fetch alerts (fast with tail)
                raw_alerts = await self.live_monitoring.persistent_ssh.read_alerts(
                    self._runtime_limit("max_current_alert_lines", 1000)
                )
                if (
                    not raw_alerts
                    and not (
                        self.live_monitoring.persistent_ssh.ssh_reader
                        and self.live_monitoring.persistent_ssh.ssh_reader.is_connected
                    )
                ):
                    raise HTTPException(
                        status_code=503,
                        detail="Wazuh server is unavailable. Upload a JSON alert template from the dashboard for offline testing."
                    )
                
                print(f"✅ Re-fetched {len(raw_alerts)} alerts")
                
                # Get selected raw alerts by ID
                uuid_map = {}
                for alert in raw_alerts:
                    uuid_value = generate_alert_uuid(alert)
                    uuid_map[uuid_value] = alert
                
                selected_raw = []
                for identifier in identifiers:
                    if identifier in uuid_map:
                        selected_raw.append(uuid_map[identifier])
                        continue
                    # Legacy support for numeric indices
                    try:
                        alert_idx = int(identifier)
                        if 0 <= alert_idx < len(raw_alerts):
                            selected_raw.append(raw_alerts[alert_idx])
                    except (ValueError, TypeError):
                        continue
                
                if not selected_raw:
                    raise HTTPException(status_code=400, detail="Invalid alert IDs")
                
                print(f"🔍 Processing {len(selected_raw)} selected alerts with FULL analysis...")
                
                # Do FULL processing (geolocation, threat classification, etc.)
                processed_alerts = await self._run_blocking(
                    self.report_generator.alert_analyzer.clean_log_data,
                    selected_raw
                )
                if not processed_alerts:
                    raise HTTPException(status_code=400, detail="No valid alerts after processing")
                
                print(f" Processed {len(processed_alerts)} alerts")
                
                # Generate report
                session_id = generate_session_id()
                self._start_background_task(self._analyze_alerts_with_progress(
                    session_id, 
                    selected_alerts=processed_alerts
                ), kind="analysis")
                
                return {
                    "session_id": session_id,
                    "message": f"Analyzing {len(processed_alerts)} alerts",
                    "selected_count": len(processed_alerts),
                    "poll_timeout_ms": (max(1, int(self.config.llm.timeout)) + 60) * 1000,
                }
                
            except HTTPException:
                raise
            except Exception as e:
                log_sanitized_exception("Selected-alert request failed", e)
                raise HTTPException(status_code=500, detail="Failed to start selected-alert analysis") from e
            
        @self.app.get("/alerts/viewer", response_class=HTMLResponse)
        async def alert_viewer_page(request: Request, username: str = Depends(authenticate)):
            """Live alert viewer page"""
            return self.templates.TemplateResponse("alert_viewer.html", {"request": request})

    async def _process_uploaded_documents_with_progress(
        self,
        session_id: str,
        uploaded_files: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Extract uploaded CTI documents in background worker threads."""
        if not uploaded_files:
            return []

        total_files = len(uploaded_files)
        concurrency = min(4, total_files)
        semaphore = asyncio.Semaphore(concurrency)

        async def process_one(uploaded_file: Dict[str, Any]):
            filename = uploaded_file.get("filename") or "uploaded_document"
            content = uploaded_file.get("content") or b""
            async with semaphore:
                try:
                    text, metadata = await self._run_blocking(
                        self.document_processor.process_upload,
                        content,
                        filename,
                        save_to_disk=False,
                        remember_processed=False,
                    )
                    if not text.strip():
                        return {
                            "filename": filename,
                            "status": "skipped",
                            "message": "no extractable text"
                        }
                    return {
                        "filename": filename,
                        "status": "ok",
                        "document": {
                            "content": text,
                            "metadata": metadata
                        }
                    }
                except ValueError as ve:
                    log_sanitized_exception("Uploaded document extraction was rejected", ve)
                    return {
                        "filename": filename,
                        "status": "skipped",
                        "message": "validation or extraction rejected the document"
                    }
                except Exception as e:
                    log_sanitized_exception("Uploaded document extraction failed", e)
                    return {
                        "filename": filename,
                        "status": "error",
                        "message": "document extraction failed"
                    }

        custom_docs = []
        failed_documents = 0
        tasks = [asyncio.create_task(process_one(uploaded_file)) for uploaded_file in uploaded_files]
        completed = 0

        try:
            for task in asyncio.as_completed(tasks):
                result = await task
                completed += 1
                filename = result.get("filename", "uploaded_document")
                if result.get("status") == "ok":
                    custom_docs.append(result["document"])
                    message = f"✅ Extracted {filename} ({completed}/{total_files})"
                elif result.get("status") == "skipped":
                    failed_documents += 1
                    message = f"⚠️ Skipped {filename}: {result.get('message', 'not processed')}"
                else:
                    failed_documents += 1
                    message = f"❌ Error extracting {filename}: {result.get('message', 'unknown error')}"

                progress = 55 + int((completed / total_files) * 5)
                await self.progress_tracker.send_progress(session_id, message, progress)
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

        if failed_documents:
            raise ValueError(
                f"{failed_documents} of {total_files} requested documents were not indexable"
            )

        return custom_docs
    
    async def _build_rag_with_progress(self, session_id: str, use_archives: bool, 
                                 use_uploads: bool, archive_days: Optional[int], 
                                 custom_docs: List[Any],
                                 uploaded_files: Optional[List[Dict[str, Any]]] = None,
                                 build_mode: str = "extend"):
        """Extend, replace, or refresh the active RAG context with progress tracking."""
        try:
            if build_mode not in {"extend", "replace", "refresh"}:
                await self.progress_tracker.send_progress(
                    session_id, "ERROR: Invalid RAG build mode.", 0, "error"
                )
                return False
            archive_logs = []
            existing_status = await self._run_blocking(
                self.report_generator.get_rag_status
            )
            if existing_status.get("error"):
                await self.progress_tracker.send_progress(
                    session_id,
                    "ERROR: RAG status is unavailable; the active corpus was not changed.",
                    0,
                    "error",
                )
                return False
            has_existing_data = (
                existing_status.get('alerts_with_embeddings', 0) > 0 or 
                existing_status.get('docs_with_embeddings', 0) > 0
            )
            has_active_corpus = bool(
                existing_status.get("active_corpus_id") or has_existing_data
            )
            
            # Check if we're just refreshing existing data
            if not use_archives and not use_uploads:
                await self.progress_tracker.send_progress(
                    session_id, "🔄 Loading active RAG union status from PostgreSQL...", 50
                )
                
                # Just verify the existing data is ready
                if existing_status.get("ready"):
                    archive_records, source_documents, document_chunks, total_chunks = (
                        self._active_rag_counts(existing_status)
                    )
                    await self.progress_tracker.send_progress(
                        session_id,
                        (
                            "✅ Active RAG union ready: "
                            f"{source_documents} CTI source document(s), "
                            f"{document_chunks} CTI chunk(s), and "
                            f"{archive_records} archive record(s) "
                            f"({total_chunks} total retrievable chunk(s))."
                        ),
                        100,
                        "success",
                    )
                    return True
                else:
                    await self.progress_tracker.send_progress(
                        session_id, "❌ No data found in persistent database", 0, "error"
                    )
                    archive_logs = []
                    return False
	            
            if use_archives:
                if not archive_days:
                    await self.progress_tracker.send_progress(
                        session_id, "❌ Error: Archive days not specified.", 0, "error"
                    )
                    return False
                
                await self.progress_tracker.send_progress(
                    session_id, "🔌 Connecting to Wazuh server...", 10
                )
                
                archive_ssh_connected, archive_logs = await self._run_blocking(
                    self._read_archives_sync,
                    archive_days,
                )
                if not archive_ssh_connected:
                    await self.progress_tracker.send_progress(
                        session_id,
                        "ERROR: Unable to read the requested Wazuh archives. The prior corpus remains active.",
                        0,
                        "error"
                    )
                    return False
                
                await self.progress_tracker.send_progress(
                    session_id, f"📊 Loaded {len(archive_logs)} archive logs", 50
                )
            else:
                await self.progress_tracker.send_progress(
                    session_id, "⏭️ Skipping OSSEC archive retrieval as requested.", 50
                )
            
            if use_uploads and uploaded_files:
                await self.progress_tracker.send_progress(
                    session_id,
                    f"📄 Extracting {len(uploaded_files)} uploaded CTI document(s)...",
                    55
                )
                custom_docs = await self._process_uploaded_documents_with_progress(
                    session_id,
                    uploaded_files
                )

            if use_uploads:
                if custom_docs:
                    await self.progress_tracker.send_progress(
                        session_id, f"💾 Chunking and storing {len(custom_docs)} uploaded files in pgvector...", 60
                    )
                else:
                    await self.progress_tracker.send_progress(
                        session_id, "⚠️ No uploaded document produced indexable text.", 60, "warning"
                    )

            if not archive_logs and not custom_docs:
                retained = (
                    " The prior corpus remains active."
                    if has_active_corpus
                    else ""
                )
                await self.progress_tracker.send_progress(
                    session_id,
                    "ERROR: None of the requested sources produced indexable RAG data."
                    + retained,
                    0,
                    "error"
                )
                return False

            await self.progress_tracker.send_progress(
                session_id,
                (
                    "➕ Extending the active RAG context with the union of existing and new sources..."
                    if build_mode == "extend"
                    else (
                        "♻️ Building a confirmed replacement RAG context from the selected sources..."
                        if has_active_corpus
                        else "🧠 Building the initial RAG context from the selected sources..."
                    )
                ),
                70,
            )

            def build_rag():
                try:
                    if build_mode == "extend":
                        success = bool(
                            self.report_generator.extend_rag_context(
                                archive_logs=archive_logs,
                                custom_docs=custom_docs,
                            )
                        )
                    else:
                        success = bool(
                            self.report_generator.build_rag_context(
                                archive_logs,
                                custom_docs,
                            )
                        )
                    if not success:
                        return False, {}
                    try:
                        active_status = self.report_generator.get_rag_status()
                    except Exception as status_error:
                        log_sanitized_exception(
                            "RAG post-build status query failed", status_error
                        )
                        active_status = {}
                    if not active_status.get("ready"):
                        return False, active_status
                    return True, active_status
                except Exception as e:
                    log_sanitized_exception("RAG build worker failed", e)
                    return False, {}
            
            success, active_status = await self._run_blocking(build_rag)
            
            if success:
                archive_records, source_documents, document_chunks, total_chunks = (
                    self._active_rag_counts(active_status)
                )
                await self.progress_tracker.send_progress(
                    session_id,
                    (
                        "✅ Active RAG union ready: "
                        f"{source_documents} CTI source document(s), "
                        f"{document_chunks} CTI chunk(s), and "
                        f"{archive_records} archive record(s) "
                        f"({total_chunks} total retrievable chunk(s))."
                    ),
                    100,
                    "success",
                )
                
                # Auto-start monitoring if enabled
                if self._ssh_enabled() and not getattr(self, "_shutting_down", False):
                    print("RAG ready - starting configured alert monitoring")
                    monitoring_success = self.live_monitoring.start_monitoring(continuous=False)
                    if monitoring_success:
                        await asyncio.sleep(1)
                        print("Alert monitoring started")
                    else:
                        print("WARNING: Alert monitoring did not start")
                elif not self._ssh_enabled():
                    print("RAG ready in upload-only mode; SSH monitoring remains disabled")
                else:
                    print("RAG ready during application shutdown; monitoring remains stopped")
                
                return True
            else:
                await self.progress_tracker.send_progress(
                    session_id, "❌ RAG build failed or no data available", 0, "error"
                )
                return False
                
        except Exception as e:
            log_sanitized_exception("RAG build background operation failed", e)
            await self.progress_tracker.send_progress(
                session_id, "❌ RAG build failed. Check server logs.", 0, "error"
            )
            return False
    
    async def _generate_visual_report_with_progress(self, session_id: str):
        """Generate visual report with progress tracking"""
        try:
            await self.progress_tracker.send_progress(
                session_id, "🔌 Connecting to get current alerts...", 10
            )
            
            connected, current_alerts = await self._run_blocking(
                self._read_current_alerts_sync,
                self._runtime_limit("max_current_alert_lines", 1000),
            )
            if not connected:
                await self.progress_tracker.send_progress(
                    session_id, "❌ Failed to connect to SSH", 0, "error"
                )
                return None
            
            await self.progress_tracker.send_progress(
                session_id, "📁 Reading current alerts...", 30
            )
            
            await self.progress_tracker.send_progress(
                session_id, f"📊 Found {len(current_alerts)} alerts, generating charts...", 50
            )
            
            # Generate visual report
            def generate_visual():
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
                filename = f"VISUAL_Analysis_{timestamp}_{uuid.uuid4().hex[:8]}.md"
                filepath = Path(self.config.paths.reports_dir) / filename
                
                return self.report_generator.generate_visual_report(
                    current_alerts, str(filepath)
                )
            
            report = await self._run_blocking(generate_visual)
            
            if report:
                await self.progress_tracker.send_progress(
                    session_id, "📊 Charts generated successfully!", 90
                )
                
                report_path = Path(report)
                filename = report_path.name
                
                if self.pdf_converter.conversion_available:
                    await self._auto_convert_report(report_path)
                
                await self.progress_tracker.send_progress(
                    session_id, f"✅ Visual report saved: {filename}", 100, "success"
                )
                return filename
            else:
                await self.progress_tracker.send_progress(
                    session_id, "❌ No charts could be generated (insufficient data)", 0, "error"
                )
                return None
                
        except Exception as e:
            log_sanitized_exception("Visual report background operation failed", e)
            await self.progress_tracker.send_progress(
                session_id, "❌ Visual report generation failed. Check server logs.", 0, "error"
            )
            return None
    
    async def _analyze_alerts_with_progress(
        self,
        session_id: str,
        selected_alerts: List[Dict] = None,
        include_charts: bool = False,
        alert_source: str = None
    ):
        try:
            if not self.report_generator.rag_ready:
                await self.progress_tracker.send_progress(
                    session_id, "❌ RAG context not ready", 0, "error"
                )
                return None
            
            # Use provided alerts
            if selected_alerts is not None:
                current_alerts = selected_alerts
                await self.progress_tracker.send_progress(
                    session_id, f"📊 Analyzing {len(current_alerts)} selected alerts", 50
                )
            else:
                # Fetch from SSH if no alerts provided
                await self.progress_tracker.send_progress(
                    session_id, "🔌 Connecting to get current alerts...", 10
                )
                
                # Retry SSH connection with exponential backoff
                max_retries = 3
                retry_delay = 2
                connected = False
                
                for attempt in range(max_retries):
                    try:
                        print(f"📡 SSH connection attempt {attempt + 1}/{max_retries}...")
                        connected, current_alerts = await self._run_blocking(
                            self._read_current_alerts_sync,
                            self._runtime_limit("max_current_alert_lines", 1000),
                        )
                        if connected:
                            connected = True
                            print("✅ SSH connected successfully")
                            break
                        else:
                            print(f"❌ SSH connection failed (attempt {attempt + 1})")
                    except Exception as e:
                        log_sanitized_exception("SSH connection attempt failed", e)
                    
                    if attempt < max_retries - 1:
                        await self.progress_tracker.send_progress(
                            session_id, f"⏳ Retrying SSH connection... ({attempt + 2}/{max_retries})", 10 + (attempt * 5)
                        )
                        await asyncio.sleep(retry_delay)
                        retry_delay *= 2  # Exponential backoff
                
                if not connected:
                    await self.progress_tracker.send_progress(
                        session_id, "ERROR: Unable to reach Wazuh for current alerts. Upload a JSON alert template on the dashboard to run an offline test analysis.", 0, "error"
                    )
                    return None
                
                current_alerts = await self._run_blocking(
                    self.report_generator.alert_analyzer.clean_log_data,
                    current_alerts
                )
            
            if not current_alerts or len(current_alerts) == 0:
                await self.progress_tracker.send_progress(
                    session_id, "❌ No alerts to analyze", 0, "error"
                )
                return None
            
            print(f"📊 About to call generate_report_with_rag with {len(current_alerts)} alerts, include_charts={include_charts}")
            
            # Add chart generation progress if enabled
            if include_charts:
                await self.progress_tracker.send_progress(
                    session_id, "📊 Generating visual charts...", 50
                )
            
            await self.progress_tracker.send_progress(
                session_id, "🧠 Generating report...", 60
            )
            

            report_start_time = asyncio.get_event_loop().time()
            
            def generate_report():
                return self.report_generator.generate_report_with_rag(
                    current_alerts, 
                    alert_source or self.config.ssh.host,
                    is_automatic=False, 
                    trigger_info={
                        "trigger_type": "manual",
                        "include_charts": include_charts,
                        "timestamp": datetime.now().isoformat()
                    }
                )
            
            loop = asyncio.get_running_loop()
            
            try:
                report = await asyncio.wait_for(
                    self._run_blocking(generate_report),
                    timeout=max(1, int(self.config.llm.timeout)) + 30
                )
                
                report_end_time = loop.time()
                generation_time = report_end_time - report_start_time
                
            except asyncio.TimeoutError:
                self.report_generator.cancel_active_generations(permanent=False)
                await self.progress_tracker.send_progress(
                    session_id, "❌ Report generation timed out", 0, "error"
                )
                return None
            
            await self.progress_tracker.send_progress(
                session_id, 
                f"💾 Saving enhanced report... (Generated in {generation_time:.2f}s)", 
                90,
                "info",
                {"generation_time_seconds": round(generation_time, 2)}
            )
            
            # Parse report into editable structure
            await self.progress_tracker.send_progress(
                session_id, "📝 Preparing report for review...", 95
            )

            try:
                parsed_report = ReportParser.parse_report(report)
                if hasattr(self.report_generator, "record_report_trace_stage"):
                    self.report_generator.record_report_trace_stage("parsed_structure", parsed_report)
                report_id = generate_session_id()
                self._store_bounded(
                    self.draft_reports,
                    report_id,
                    parsed_report,
                    self._runtime_limit("max_drafts", 100),
                )
                
                print(f"📝 Draft report created: {report_id}")
                print(f"   → Redirect to: /review-report/{report_id}")
                
                metrics = self.report_generator.get_generation_metrics()
                await self.progress_tracker.send_progress(
                    session_id, 
                    f"✅ Report ready! Generated in {generation_time:.2f}s (Avg: {metrics['avg_generation_time']:.2f}s)", 
                    100, 
                    "success",
                    {
                        "generation_time_seconds": round(generation_time, 2),
                        "total_reports": metrics["reports_generated"]
                    }
                )
                
                result = {"report_id": report_id, "redirect": True}
                self._store_bounded(
                    self.session_results,
                    session_id,
                    result,
                    self._runtime_limit("max_session_results", 200),
                )
                return result
                
            except Exception as e:
                log_sanitized_exception("Report parsing failed", e)
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
                filename = f"MANUAL_Threat_analysis_{timestamp}_{uuid.uuid4().hex[:8]}.md"
                report_path = Path(self.config.paths.reports_dir) / filename
                atomic_write_text(report_path, report)
                
                await self.progress_tracker.send_progress(
                    session_id, f"⚠️ Report saved (parsing failed): {filename}", 100, "success"
                )
                return filename
            
        except Exception as e:
            log_sanitized_exception("Alert analysis background operation failed", e)
            await self.progress_tracker.send_progress(
                session_id, "❌ Alert analysis failed. Check server logs.", 0, "error"
            )
            return None
    
    async def _auto_convert_report(self, report_path: Path):
        try:
            if not getattr(self, 'auto_convert_enabled', False):
                return
                
            if self.pdf_converter.conversion_available:
                pdf_path = await self.pdf_converter.convert_markdown_to_pdf(
                    report_path, report_path.parent
                )
                if pdf_path:
                    print(f"📄 Auto-converted to PDF: {pdf_path.name}")
        except Exception as e:
            log_sanitized_exception("Auto-convert to PDF failed", e)
    
    async def _restore_monitoring_state(self):
        try:
            print("🔄 Checking if monitoring should auto-start...")
        
            if self.report_generator.rag_ready and self._ssh_enabled():
                print("✅ RAG ready at startup - Starting monitoring...")
                success = self.live_monitoring.start_monitoring(continuous=False)
                
                if success:
                    print("✅ Monitoring started successfully")
                    await asyncio.sleep(2)
                    
                    # Verify it's actually running
                    stats = self.live_monitoring.get_statistics()
                    if stats.get("monitoring_started"):
                        print(f"✅ Monitoring verified active: {stats['monitoring_started']}")
                    else:
                        print("❌ WARNING: Monitoring flag set but loop not running!")
                else:
                    print("❌ Failed to start monitoring")
            elif not self.report_generator.rag_ready:
                print("⚠️ RAG not ready - monitoring will start after RAG build")
            else:
                print("RAG ready in upload-only mode; SSH monitoring is disabled")
        except Exception as e:
            log_sanitized_exception("Monitoring state restore failed", e)
    
    def run(self, host: str = None, port: int = None):
        host = host or self.config.web.host
        port = port or self.config.web.port
        
        print("Dashboard server starting on the configured bind address")
        print(f"🔧 Config summary: {self.config.get_summary()}")
        print(f"🚨 Alert Detection: AUTOMATIC after RAG build (Level >= {self.live_monitoring.high_severity_threshold})")

        try:
            uvicorn.run(
                self.app, 
                host=host, 
                port=port,
                log_level="info",
                access_log=False  # Disable access logs for cleaner output
            )
        except KeyboardInterrupt:
            print("\n🛑 Shutting down gracefully...")


def main():    
    is_valid, issues = validate_environment()
    if not is_valid:
        print("❌ Environment validation failed:")
        for issue in issues:
            print(f"  - {issue}")
        sys.exit(1)
    
    try:
        config_file = sys.argv[1] if len(sys.argv) > 1 else None
        app = SOCApplication(config_file)
        app.run()
    except Exception as e:
        log_sanitized_exception("Application startup failed", e)
        sys.exit(1)


if __name__ == "__main__":
    main()
