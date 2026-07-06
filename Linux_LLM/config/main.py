#!/usr/bin/env python3
import json
import asyncio
import uuid
import hashlib
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional
from contextlib import asynccontextmanager 

import uvicorn
from fastapi import FastAPI, HTTPException, Depends, status, Form, WebSocket, UploadFile, File, Request, WebSocketDisconnect, Query
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.staticfiles import StaticFiles
import secrets
import sys
import signal
import math


BASE_DIR = Path(__file__).resolve().parent

from config import ConfigManager, validate_environment
from ssh import SmartSSHLogReader
from report import ReportGenerator
from rag import DocumentProcessor, DocumentValidator
from progress import ProgressTracker, generate_session_id
from report_parser import ReportParser

from live_monitoring import (
    create_enhanced_live_monitoring_service
)
from pdf_converter import (
    create_enhanced_pdf_converter,
    create_enhanced_pdf_api_handlers
)


def generate_alert_uuid(alert: Dict[str, Any]) -> str:
    """Create a stable hash for an alert based on key identifying fields."""
    rule = alert.get('rule', {}) or {}
    data = alert.get('data', {}) or {}
    agent = alert.get('agent', {}) or {}
    key_fields = [
        rule.get('id') or rule.get('rule_id') or alert.get('rule_id') or '',
        rule.get('description') or alert.get('rule_description') or data.get('description') or '',
        data.get('src_ip') or alert.get('src_ip') or alert.get('srcip') or '',
        data.get('dest_ip') or alert.get('dest_ip') or alert.get('dstip') or '',
        agent.get('name') or '',
        alert.get('timestamp') or alert.get('time') or ''
    ]
    normalized = "|".join(str(field).strip().lower() for field in key_fields)
    return hashlib.md5(normalized.encode('utf-8')).hexdigest()

def resolve_report_path(reports_root: Path, filename: str) -> Path:
    """Resolve a report filename while preventing directory traversal."""
    if not filename or "/" in filename or "\\" in filename:
        raise HTTPException(status_code=400, detail="Invalid report filename")

    root = reports_root.resolve()
    report_path = (root / filename).resolve()
    if report_path.parent != root:
        raise HTTPException(status_code=400, detail="Invalid report filename")
    return report_path


class SOCApplication:   
    @asynccontextmanager
    async def lifespan(self, app: FastAPI):
        await self.progress_tracker.start_cleanup_task()        
        await self._restore_monitoring_state()
        yield
        
        print(" Ending application lifespan...")
        self.progress_tracker.stop_cleanup_task()
        
        if self.live_monitoring.monitoring_enabled:
            self.live_monitoring.stop_monitoring()

    def __init__(self, config_file: str = None):
        self.config = ConfigManager(config_file)
        is_valid, errors = self.config.validate_all()
        if not is_valid:
            print("❌ Configuration validation failed:")
            for error in errors:
                print(f"  - {error}")
            raise ValueError("Invalid configuration")
        
        self.draft_reports = {}
        self._init_components()

        self.app = FastAPI(
            title="SOC Threat Analysis with Enhanced Monitoring",
            description="Cybersecurity threat analysis with proper alert filtering and PDF reports",
            version="3.1.0",
            lifespan=self.lifespan
        )
        static_dir = BASE_DIR / "static"
        static_dir.mkdir(exist_ok=True)
        self.app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

        self.session_results = {}
        self.security = HTTPBasic()
        self.templates = Jinja2Templates(directory=BASE_DIR / "templates")
        self._setup_routes()
            
    def _init_components(self):
        try:
            self.progress_tracker = ProgressTracker(max_sessions=100, session_timeout=3600)
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
            print(f"📊 RAG Status: {json.dumps(rag_status, indent=2)}")
            
            self.live_monitoring = create_enhanced_live_monitoring_service(
                config_manager=self.config,
                report_generator=self.report_generator,
                ssh_reader_factory=self._create_ssh_reader
            )
        
            self.pdf_converter = create_enhanced_pdf_converter()
            self.pdf_api_handlers = create_enhanced_pdf_api_handlers(
                Path(self.config.paths.reports_dir)
            )
            
            print(" All components with charts initialized")
            
        except Exception as e:
            print(f"❌ Component initialization failed: {e}")
            raise
    
    def _create_ssh_reader(self):
        return SmartSSHLogReader(
            host=self.config.ssh.host,
            username=self.config.ssh.username,
            password=self.config.ssh.password,
            port=self.config.ssh.port,
            alerts_path=self.config.wazuh.alerts_file_path,
            archives_base_path=self.config.wazuh.archives_base_path
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
    def _require_optional_object(root: Dict[str, Any], field: str, index: int) -> Dict[str, Any]:
        value = root.get(field, {})
        if value in (None, ""):
            value = {}
        if not isinstance(value, dict):
            raise ValueError(f"Alert {index}: '{field}' must be a JSON object when provided")
        return value

    def _normalize_uploaded_alert_shape(self, alert: Dict[str, Any], index: int) -> Dict[str, Any]:
        """Validate and lightly normalize uploaded alerts to match the live Wazuh shape."""
        normalized_alert = json.loads(json.dumps(alert))
        root = self._get_alert_root_for_validation(normalized_alert, index)

        rule = self._require_optional_object(root, "rule", index)
        agent = self._require_optional_object(root, "agent", index)
        data = self._require_optional_object(root, "data", index)
        if rule is not root.get("rule"):
            root["rule"] = rule
        if agent is not root.get("agent"):
            root["agent"] = agent
        if data is not root.get("data"):
            root["data"] = data

        # Accept a few flat convenience fields, but normalize them into the Wazuh-style
        # locations consumed by AlertAnalyzer.clean_log_data.
        if root.get("rule_id") and not rule.get("id"):
            rule["id"] = root.get("rule_id")
        if root.get("rule_description") and not rule.get("description"):
            rule["description"] = root.get("rule_description")
        if root.get("rule_level") is not None and rule.get("level") is None:
            rule["level"] = root.get("rule_level")
        if root.get("src_ip") and not data.get("src_ip"):
            data["src_ip"] = root.get("src_ip")
        if root.get("dest_ip") and not data.get("dest_ip"):
            data["dest_ip"] = root.get("dest_ip")
        if root.get("dst_ip") and not data.get("dest_ip"):
            data["dest_ip"] = root.get("dst_ip")

        alert_data = self._require_optional_object(data, "alert", index)
        if alert_data is not data.get("alert"):
            data["alert"] = alert_data
        if root.get("alert_signature") and not alert_data.get("signature"):
            alert_data["signature"] = root.get("alert_signature")
        if root.get("alert_category") and not alert_data.get("category"):
            alert_data["category"] = root.get("alert_category")
        if root.get("signature_id") and not alert_data.get("signature_id"):
            alert_data["signature_id"] = root.get("signature_id")

        for nested_field in ("http", "tls", "email", "threat", "ioc", "process", "flow", "metadata", "smb", "modbus"):
            self._require_optional_object(data, nested_field, index)

        dns = self._require_optional_object(data, "dns", index)
        query = dns.get("query")
        if isinstance(query, dict):
            dns["query"] = [query]
        elif query is not None and not isinstance(query, list):
            raise ValueError(f"Alert {index}: 'data.dns.query' must be an array of objects when provided")

        files = data.get("files")
        if files is not None and not isinstance(files, list):
            raise ValueError(f"Alert {index}: 'data.files' must be an array when provided")
        fileinfo = data.get("fileinfo")
        if fileinfo not in (None, ""):
            if not isinstance(fileinfo, dict):
                raise ValueError(f"Alert {index}: 'data.fileinfo' must be a JSON object when provided")
            if files is None:
                data["files"] = [fileinfo]

        if not rule.get("description") and not alert_data.get("signature"):
            raise ValueError(
                f"Alert {index}: provide either 'rule.description' or "
                "'data.alert.signature' so the alert survives cleaning"
            )

        return normalized_alert

    def _pre_read_upload_error(self, file: UploadFile) -> Optional[str]:
        filename = file.filename or ""
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

    def _parse_uploaded_alert_template(self, file_content: bytes, filename: str) -> List[Dict[str, Any]]:
        """Parse uploaded JSON alert templates for offline/manual testing."""
        if not filename.lower().endswith(".json"):
            raise ValueError("Alert template must be a .json file")

        try:
            text = file_content.decode("utf-8-sig")
        except UnicodeDecodeError:
            text = file_content.decode("utf-8", errors="replace")

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
            else:
                alerts = [payload]
        elif isinstance(payload, list):
            alerts = payload
        else:
            raise ValueError("Alert template must be a JSON object, an array, or an object with an 'alerts' array")

        if not alerts:
            raise ValueError("Alert template contains no alerts")
        if len(alerts) > 1000:
            raise ValueError("Alert template may contain at most 1000 alerts")
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
        
        @self.app.get("/", response_class=HTMLResponse)
        async def dashboard(request: Request, username: str = Depends(authenticate)):
            """Enhanced dashboard with live monitoring and PDF conversion"""
            config_summary = self.config.get_summary()
            
            existing_reports = []
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
                        with open(report_file, 'r', encoding='utf-8') as f:
                            content = f.read()
                        
                        stat = report_file.stat()
                        existing_reports.append({
                            "filename": report_file.name,
                            "timestamp": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                            "created_at": stat.st_mtime,
                            "size": f"{stat.st_size / 1024:.1f} KB",
                            "content": content,
                            "preview": content[:500] + "..." if len(content) > 500 else content
                        })
                    except Exception as e:
                        print(f"⚠️ Error reading {report_file.name}: {e}")
            
            existing_reports.sort(key=lambda r: r.get("created_at", 0), reverse=True)
            
            print(f"📊 Total reports loaded: {len(existing_reports)}")
            total_existing = len(existing_reports)
            total_existing_pages = math.ceil(total_existing / existing_page_size) if total_existing else 0
            if total_existing_pages and existing_page > total_existing_pages:
                existing_page = total_existing_pages
            start = (existing_page - 1) * existing_page_size if total_existing else 0
            end = start + existing_page_size
            paginated_existing = existing_reports[start:end]
            
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
                    print(f"❌ Progress WebSocket error for {session_id}: {e}")
                    
            except Exception as e:
                print(f"❌ Progress WebSocket setup error for {session_id}: {e}")
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
            username: str = Depends(authenticate)
        ):
            existing_status = self.report_generator.get_rag_status()
            has_existing_data = (
                existing_status.get('alerts_with_embeddings', 0) > 0 or 
                existing_status.get('docs_with_embeddings', 0) > 0
            )
            
            if not use_archives and not use_uploads and not has_existing_data:
                raise HTTPException(
                    status_code=400, 
                    detail="No existing RAG data found. Please select at least one source (archives or uploads) for initial build."
                )
            
            session_id = generate_session_id()
            
            uploaded_files = []
            if use_uploads and customFiles:
                print(f"\n📤 Queuing {len(customFiles)} uploaded files for pgvector storage...")
                batch_hashes = set()
                for file in customFiles:
                    if file.filename:
                        try:
                            pre_read_error = self._pre_read_upload_error(file)
                            if pre_read_error:
                                print(f"⚠️ Skipping {file.filename}: {pre_read_error}")
                                continue
                            content = await file.read()
                            content_hash = hashlib.sha256(content).hexdigest()
                            if content_hash in batch_hashes:
                                print(f"⚠️ Duplicate in current upload batch skipped: {file.filename}")
                                continue
                            batch_hashes.add(content_hash)
                            uploaded_files.append({
                                "filename": file.filename,
                                "content": content
                            })
                            print(f"✅ Queued {file.filename} for background extraction")
                        except Exception as e:
                            print(f"❌ Error reading {file.filename}: {e}")
                
                if uploaded_files:
                    print(f"💾 Total uploaded files queued for extraction: {len(uploaded_files)}")
                else:
                    print(f"⚠️ No new documents to add (all may be duplicates)")
            
            asyncio.create_task(self._build_rag_with_progress(
                session_id=session_id,
                use_archives=use_archives,
                use_uploads=use_uploads,
                archive_days=ragDays,
                custom_docs=[],
                uploaded_files=uploaded_files
            ))
            
            return {"session_id": session_id, "message": "RAG context refresh started"}
        @self.app.post("/generate-visual-report")
        async def generate_visual_report(username: str = Depends(authenticate)):
            """Generate a visual report with charts only"""
            session_id = generate_session_id()
            asyncio.create_task(self._generate_visual_report_with_progress(session_id))
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
                        content = await alertTemplate.read()
                        selected_alerts = self._parse_uploaded_alert_template(content, alertTemplate.filename)
                        alert_source = f"Uploaded JSON alert template: {alertTemplate.filename}"
                        print(f"Loaded {len(selected_alerts)} alerts from uploaded template {alertTemplate.filename}")
                    except ValueError as e:
                        raise HTTPException(status_code=400, detail=str(e))

                asyncio.create_task(self._analyze_alerts_with_progress(
                    session_id, 
                    selected_alerts=selected_alerts,
                    include_charts=include_charts,
                    alert_source=alert_source
                ))
                
                response = {"session_id": session_id, "message": "Alert analysis started"}
                print(f"✅ Returning response: {response}")
                return response
                
            except HTTPException:
                raise
            except Exception as e:
                print(f"❌ Error in /analyze-alerts: {e}")
                import traceback
                traceback.print_exc()
                raise HTTPException(
                    status_code=500,
                    detail=f"Failed to start analysis: {str(e)}"
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
                raise HTTPException(
                    status_code=500, 
                    detail=f"PDF conversion error: {str(e)}"
                )
        
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
                raise HTTPException(
                    status_code=500, 
                    detail=f"Batch conversion error: {str(e)}"
                )
        
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
                data = await request.json()
                enabled = data.get('enabled', False)
                
                self.auto_convert_enabled = enabled
                
                return {
                    "success": True,
                    "enabled": enabled,
                    "message": f"Auto-convert {'enabled' if enabled else 'disabled'}"
                }
            except Exception as e:
                raise HTTPException(
                    status_code=500,
                    detail=f"Failed to set auto-convert: {str(e)}"
                )
        
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
            return self.report_generator.get_rag_status()

        @self.app.post("/clear-rag-context")
        async def clear_rag_context(username: str = Depends(authenticate)):
            """Testing-only endpoint: drop and recreate the configured RAG database."""
            try:
                result = self.report_generator.clear_rag_database()
                return result
            except Exception as e:
                raise HTTPException(
                    status_code=500,
                    detail=f"Failed to clear RAG database: {str(e)}"
                )
        
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

            try:
                markdown_text = report_path.read_text(encoding="utf-8")
                parsed_report = ReportParser.parse_report(markdown_text)
            except Exception as e:
                raise HTTPException(status_code=500, detail=f"Failed to load report: {str(e)}")

            report_id = uuid.uuid4().hex
            metadata = parsed_report.setdefault("metadata", {})
            metadata["source_filename"] = filename
            self.draft_reports[report_id] = parsed_report

            return RedirectResponse(url=f"/review-report/{report_id}", status_code=303)
        
        @self.app.get("/test-connection")
        async def test_connection(username: str = Depends(authenticate)):
            """Test SSH connection to Wazuh server"""
            ssh_reader = self._create_ssh_reader()
            
            if ssh_reader.connect():
                try:
                    alerts = ssh_reader.read_alerts(1000)
                    ssh_reader.disconnect()
                    return {
                        "status": "success",
                        "message": f"Connected successfully to {self.config.ssh.host}",
                        "alerts_count": len(alerts),
                        "alerts_path": self.config.wazuh.alerts_file_path
                    }
                except Exception as e:
                    ssh_reader.disconnect()
                    return {"status": "error", "message": f"File access error: {str(e)}"}
            else:
                return {"status": "error", "message": "Failed to establish SSH connection"}
        
        @self.app.get("/system-status")
        async def system_status(username: str = Depends(authenticate)):
            """Get system status including chart capabilities"""
            is_env_valid, env_issues = validate_environment()
            
            chart_capabilities = self.report_generator.get_chart_capabilities()
            
            return {
                "config": self.config.get_summary(),
                "environment": {
                    "valid": is_env_valid,
                    "issues": env_issues
                },
                "components": {
                    "rag_ready": self.report_generator.rag_ready,
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
                    "persistent_ssh": True,
                    "auto_start_monitoring": True,
                    "continuous_alert_detection": True,
                    "auto_report_generation": True,
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
            duplicates = []
            
            for file in files:
                if file.filename:
                    try:
                        pre_read_error = self._pre_read_upload_error(file)
                        if pre_read_error:
                            print(f"⚠️ Skipping duplicate check for {file.filename}: {pre_read_error}")
                            continue
                        content = await file.read()
                        await file.seek(0)  
                        
                        is_dup, hash_or_msg = self.document_processor.check_duplicate(
                            content, file.filename
                        )
                        
                        if is_dup:
                            import re
                            hash_match = re.search(r'hash: ([a-f0-9]+)', hash_or_msg)
                            file_hash = hash_match.group(1) if hash_match else "unknown"
                            
                            duplicates.append({
                                "filename": file.filename,
                                "hash": file_hash,
                                "message": hash_or_msg
                            })
                    except Exception as e:
                        print(f"⚠️ Error checking duplicate for {file.filename}: {e}")
            
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
                data = await request.json()
                existing = self.draft_reports.get(report_id, {})
                if (
                    isinstance(existing, dict)
                    and existing.get("preserved_appendix_markdown")
                    and not data.get("preserved_appendix_markdown")
                ):
                    data["preserved_appendix_markdown"] = existing["preserved_appendix_markdown"]
                self.draft_reports[report_id] = data
                print(f"💾 Draft saved: {report_id}")
                return {"success": True, "message": "Draft saved successfully"}
            except Exception as e:
                raise HTTPException(status_code=500, detail=f"Failed to save draft: {str(e)}")
        
        @self.app.post("/api/approve-report/{report_id}")
        async def approve_report(report_id: str, request: Request, username: str = Depends(authenticate)):
            """Finalize and save approved report"""
            try:
                data = await request.json()
                existing = self.draft_reports.get(report_id, {})
                if (
                    isinstance(existing, dict)
                    and existing.get("preserved_appendix_markdown")
                    and not data.get("preserved_appendix_markdown")
                ):
                    data["preserved_appendix_markdown"] = existing["preserved_appendix_markdown"]
                
                # Validate first
                is_valid, errors = ReportParser.validate_report(data)
                if not is_valid:
                    return JSONResponse(
                        status_code=400,
                        content={"valid": False, "errors": errors}
                    )
                
                markdown = ReportParser.serialize_to_markdown(data)
                
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"APPROVED_Threat_analysis_{timestamp}.md"
                report_path = Path(self.config.paths.reports_dir) / filename
                
                with open(report_path, 'w', encoding='utf-8') as f:
                    f.write(markdown)
                
                print(f"✅ Approved report saved: {filename}")
                
                self.report_generator.mark_report_approved()
                try:
                    loop = asyncio.get_event_loop()
                    await loop.run_in_executor(
                        None,
                        self.report_generator.index_approved_report,
                        markdown,
                        filename
                    )
                except Exception as e:
                    print(f"WARNING: Approved report saved but RAG indexing failed: {e}")
                
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
                
            except Exception as e:
                raise HTTPException(status_code=500, detail=f"Failed to approve report: {str(e)}")
        
        @self.app.post("/api/preview-report")
        async def preview_report(request: Request, username: str = Depends(authenticate)):
            """Generate markdown preview from edited data"""
            try:
                data = await request.json()
                markdown = ReportParser.serialize_to_markdown(data)
                return {"markdown": markdown}
            except Exception as e:
                raise HTTPException(status_code=500, detail=f"Preview generation failed: {str(e)}")
        
        @self.app.post("/api/validate-report")
        async def validate_report(request: Request, username: str = Depends(authenticate)):
            """Validate report data before approval"""
            try:
                data = await request.json()
                is_valid, errors = ReportParser.validate_report(data)
                return {"valid": is_valid, "errors": errors}
            except Exception as e:
                raise HTTPException(status_code=500, detail=f"Validation failed: {str(e)}")
            
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
                return [
                    {"id": "T1566", "name": "Phishing", "tactic": "Initial Access", "deprecated": False},
                    {"id": "T1071", "name": "Application Layer Protocol", "tactic": "Command and Control", "deprecated": False},
                    {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution", "deprecated": False}
                ]
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
               
                connected = await self.live_monitoring.persistent_ssh.ensure_connection()
                if not connected or not self.live_monitoring.persistent_ssh.ssh_reader:
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
                
                raw_alerts = await asyncio.get_event_loop().run_in_executor(
                    None,
                    self.live_monitoring.persistent_ssh.ssh_reader.alerts_reader.read_alerts,
                    1000  
                )
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

                    processed_page_alerts = await asyncio.get_event_loop().run_in_executor(
                        None,
                        self.report_generator.alert_analyzer.clean_log_data,
                        page_alerts_for_processing
                    )
                    for processed_alert in processed_page_alerts:
                        alert_uuid = processed_alert.get("alert_uuid")
                        if alert_uuid:
                            processed_by_uuid[alert_uuid] = processed_alert
                except Exception as processing_error:
                    print(f"WARNING: Live alert enrichment skipped: {processing_error}")
                
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
                        'raw_alert': alert  # Store raw for later processing
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
                import traceback
                print(f"❌ {traceback.format_exc()}")
                raise HTTPException(status_code=500, detail=str(e))

        @self.app.post("/analyze-selected-alerts")
        async def analyze_selected_alerts(
            request: Request,
            username: str = Depends(authenticate)
        ):
            """Analyze selected alerts by re-fetching recent Wazuh alerts."""
            try:
                data = await request.json()
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
                connected = await self.live_monitoring.persistent_ssh.ensure_connection()
                if not connected or not self.live_monitoring.persistent_ssh.ssh_reader:
                    raise HTTPException(
                        status_code=503,
                        detail="Wazuh server is unavailable. Upload a JSON alert template from the dashboard for offline testing."
                    )
                raw_alerts = await asyncio.get_event_loop().run_in_executor(
                    None,
                    self.live_monitoring.persistent_ssh.ssh_reader.alerts_reader.read_alerts,
                    1000
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
                loop = asyncio.get_event_loop()
                processed_alerts = await loop.run_in_executor(
                    None,
                    self.report_generator.alert_analyzer.clean_log_data,
                    selected_raw
                )
                if not processed_alerts:
                    raise HTTPException(status_code=400, detail="No valid alerts after processing")
                
                print(f" Processed {len(processed_alerts)} alerts")
                
                # Generate report
                session_id = generate_session_id()
                asyncio.create_task(self._analyze_alerts_with_progress(
                    session_id, 
                    selected_alerts=processed_alerts
                ))
                
                return {
                    "session_id": session_id,
                    "message": f"Analyzing {len(processed_alerts)} alerts",
                    "selected_count": len(processed_alerts)
                }
                
            except HTTPException:
                raise
            except Exception as e:
                import traceback
                print(f"❌ {traceback.format_exc()}")
                raise HTTPException(status_code=500, detail=str(e))      
            
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
                    text, metadata = await asyncio.to_thread(
                        self.document_processor.process_upload,
                        content,
                        filename,
                        False
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
                    return {
                        "filename": filename,
                        "status": "skipped",
                        "message": str(ve)
                    }
                except Exception as e:
                    return {
                        "filename": filename,
                        "status": "error",
                        "message": str(e)
                    }

        custom_docs = []
        tasks = [asyncio.create_task(process_one(uploaded_file)) for uploaded_file in uploaded_files]
        completed = 0

        for task in asyncio.as_completed(tasks):
            result = await task
            completed += 1
            filename = result.get("filename", "uploaded_document")
            if result.get("status") == "ok":
                custom_docs.append(result["document"])
                message = f"✅ Extracted {filename} ({completed}/{total_files})"
            elif result.get("status") == "skipped":
                message = f"⚠️ Skipped {filename}: {result.get('message', 'not processed')}"
            else:
                message = f"❌ Error extracting {filename}: {result.get('message', 'unknown error')}"

            progress = 55 + int((completed / total_files) * 5)
            await self.progress_tracker.send_progress(session_id, message, progress)

        return custom_docs
    
    async def _build_rag_with_progress(self, session_id: str, use_archives: bool, 
                                 use_uploads: bool, archive_days: Optional[int], 
                                 custom_docs: List[Any],
                                 uploaded_files: Optional[List[Dict[str, Any]]] = None):
        """Build RAG context with progress tracking"""
        try:
            archive_logs = []
            existing_status = self.report_generator.get_rag_status()
            has_existing_data = (
                existing_status.get('alerts_with_embeddings', 0) > 0 or 
                existing_status.get('docs_with_embeddings', 0) > 0
            )
            
            # Check if we're just refreshing existing data
            if not use_archives and not use_uploads:
                await self.progress_tracker.send_progress(
                    session_id, "🔄 Refreshing RAG context from persistent database...", 50
                )
                
                # Just verify the existing data is ready
                if self.report_generator.rag_ready:
                    await self.progress_tracker.send_progress(
                        session_id, "✅ RAG context ready from persistent database!", 100, "success"
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
                
                ssh_reader = self._create_ssh_reader()
                
                archive_ssh_connected = ssh_reader.connect()
                if not archive_ssh_connected:
                    await self.progress_tracker.send_progress(
                        session_id,
                        "WARNING: Unable to reach Wazuh over SSH. Historical archives will not be used; continuing with uploaded CTI documents or existing RAG data.",
                        35,
                        "warning"
                    )
                    archive_logs = []
                    class OfflineArchiveReader:
                        def read_archives_smart(self, *_args, **_kwargs):
                            return []

                        def disconnect(self):
                            return None

                    ssh_reader = OfflineArchiveReader()
                
                await self.progress_tracker.send_progress(
                    session_id, f"📁 Reading archive logs ({archive_days} days)...", 30
                )
                
                archive_logs = ssh_reader.read_archives_smart(archive_days)
                ssh_reader.disconnect()
                
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
                        session_id, "⏭️ No new documents to store (may be duplicates).", 60
                    )
            await self.progress_tracker.send_progress(
                session_id, "🧠 Building/Updating RAG vector store...", 70
            )
            
            if not archive_logs and not custom_docs and not has_existing_data:
                await self.progress_tracker.send_progress(
                    session_id,
                    "ERROR: No RAG data available. Wazuh archives were unavailable or empty, and no CTI documents were uploaded.",
                    0,
                    "error"
                )
                return False

            def build_rag():
                try:
                    self.report_generator.build_rag_context(archive_logs, custom_docs)
                    return self.report_generator.rag_ready
                except Exception as e:
                    print(f"❌ RAG build exception: {e}")
                    return False
            
            loop = asyncio.get_event_loop()
            success = await loop.run_in_executor(None, build_rag)
            
            if success:
                await self.progress_tracker.send_progress(
                    session_id, "✅ RAG context ready! Enhanced monitoring now available.", 100, "success"
                )
                
                # Auto-start monitoring if enabled
                print("🚀 RAG ready - Auto-starting alert monitoring...")
                monitoring_success = self.live_monitoring.start_monitoring(continuous=False)
                if monitoring_success:
                    print("✅ Alert monitoring started automatically")
                    await asyncio.sleep(1)
                    stats = self.live_monitoring.get_statistics()
                    print(f"📊 Monitoring stats: polls={stats['total_polls']}, started={stats['monitoring_started']}")
                else:
                    print("⚠️ Failed to auto-start alert monitoring")
                
                return True
            else:
                await self.progress_tracker.send_progress(
                    session_id, "❌ RAG build failed or no data available", 0, "error"
                )
                return False
                
        except Exception as e:
            await self.progress_tracker.send_progress(
                session_id, f"❌ Error: {str(e)}", 0, "error"
            )
            return False
    
    async def _generate_visual_report_with_progress(self, session_id: str):
        """Generate visual report with progress tracking"""
        try:
            await self.progress_tracker.send_progress(
                session_id, "🔌 Connecting to get current alerts...", 10
            )
            
            ssh_reader = self._create_ssh_reader()
            
            if not ssh_reader.connect():
                await self.progress_tracker.send_progress(
                    session_id, "❌ Failed to connect to SSH", 0, "error"
                )
                return None
            
            await self.progress_tracker.send_progress(
                session_id, "📁 Reading current alerts...", 30
            )
            
            current_alerts = ssh_reader.read_alerts()
            ssh_reader.disconnect()
            
            await self.progress_tracker.send_progress(
                session_id, f"📊 Found {len(current_alerts)} alerts, generating charts...", 50
            )
            
            # Generate visual report
            def generate_visual():
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"VISUAL_Analysis_{timestamp}.md"
                filepath = Path(self.config.paths.reports_dir) / filename
                
                return self.report_generator.generate_visual_report(
                    current_alerts, str(filepath)
                )
            
            loop = asyncio.get_event_loop()
            
            try:
                report = await asyncio.wait_for(
                    loop.run_in_executor(None, generate_visual), 
                    timeout=60  # Shorter timeout for visual reports
                )
            except asyncio.TimeoutError:
                await self.progress_tracker.send_progress(
                    session_id, "❌ Visual report generation timed out", 0, "error"
                )
                return None
            
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
            await self.progress_tracker.send_progress(
                session_id, f"❌ Error: {str(e)}", 0, "error"
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
                
                ssh_reader = self._create_ssh_reader()
                
                # Retry SSH connection with exponential backoff
                max_retries = 3
                retry_delay = 2
                connected = False
                
                for attempt in range(max_retries):
                    try:
                        print(f"📡 SSH connection attempt {attempt + 1}/{max_retries}...")
                        if ssh_reader.connect():
                            connected = True
                            print("✅ SSH connected successfully")
                            break
                        else:
                            print(f"❌ SSH connection failed (attempt {attempt + 1})")
                    except Exception as e:
                        print(f"❌ SSH connection error: {e}")
                    
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
                
                try:
                    current_alerts = ssh_reader.read_alerts(1000)
                finally:
                    ssh_reader.disconnect()
                
                loop = asyncio.get_event_loop()
                current_alerts = await loop.run_in_executor(
                    None,
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
            
            loop = asyncio.get_event_loop()
            
            try:
                report = await asyncio.wait_for(
                    loop.run_in_executor(None, generate_report), 
                    timeout=self.config.llm.timeout
                )
                
                report_end_time = loop.time()
                generation_time = report_end_time - report_start_time
                
            except asyncio.TimeoutError:
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
                report_id = generate_session_id()
                self.draft_reports[report_id] = parsed_report
                
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
                self.session_results[session_id] = result  
                return result
                
            except Exception as e:
                print(f"❌ Failed to parse report: {e}")
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"MANUAL_Threat_analysis_{timestamp}.md"
                report_path = Path(self.config.paths.reports_dir) / filename
                
                with open(report_path, 'w', encoding='utf-8') as f:
                    f.write(report)
                
                await self.progress_tracker.send_progress(
                    session_id, f"⚠️ Report saved (parsing failed): {filename}", 100, "success"
                )
                return filename
            
        except Exception as e:
            await self.progress_tracker.send_progress(
                session_id, f"❌ Error: {str(e)}", 0, "error"
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
            print(f"⚠️ Auto-convert to PDF failed: {e}")
    
    async def _restore_monitoring_state(self):
        try:
            print("🔄 Checking if monitoring should auto-start...")
        
            if self.report_generator.rag_ready:
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
            else:
                print("⚠️ RAG not ready - monitoring will start after RAG build")
        except Exception as e:
            print(f"❌ Error in restore_monitoring_state: {e}")
            import traceback
            traceback.print_exc()
    
    def run(self, host: str = None, port: int = None):
        host = host or self.config.web.host
        port = port or self.config.web.port
        
        print(f"📊 Dashboard: http://{host}:{port}")
        print(f"🔧 Config summary: {self.config.get_summary()}")
        print(f"🚨 Alert Detection: AUTOMATIC after RAG build (Level >= {self.live_monitoring.high_severity_threshold})")

        def signal_handler(sig, frame):
            print("\n🛑 Received shutdown signal, cleaning up...")
            if self.live_monitoring.monitoring_enabled:
                self.live_monitoring.stop_monitoring()
            sys.exit(0)
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
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
        finally:
            if self.live_monitoring.monitoring_enabled:
                self.live_monitoring.stop_monitoring()


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
        print(f"❌ Application startup failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
