#!/usr/bin/env python3
import json
from charts import SOCChartGenerator
from pathlib import Path
import asyncio
import uuid
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional
from contextlib import asynccontextmanager 
import uvicorn
from fastapi import FastAPI, HTTPException, Depends, status, Form, WebSocket, UploadFile, File, Request, WebSocketDisconnect
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.staticfiles import StaticFiles
import secrets
import sys
import signal


BASE_DIR = Path(__file__).resolve().parent

from config import ConfigManager, validate_environment
from ssh import SmartSSHLogReader
from report import ReportGenerator
from rag import DocumentProcessor
from progress import ProgressTracker, generate_session_id
from report_parser import ReportParser

from live_monitoring import (
    EnhancedLiveMonitoringService, 
    EnhancedMonitoringWebSocketHandler,
    create_enhanced_live_monitoring_service
)
from pdf_converter import (
    EnhancedPDFConverter,
    EnhancedPDFAPIHandlers,
    create_enhanced_pdf_converter,
    create_enhanced_pdf_api_handlers
)

def update_config_for_charts(config_manager):
    reports_dir = Path(config_manager.paths.reports_dir)
    charts_dir = reports_dir / "charts"
    charts_dir.mkdir(parents=True, exist_ok=True)
    
    print(f"📊 Charts directory created: {charts_dir}")
    return str(charts_dir)


class SOCApplication:   
    @asynccontextmanager
    async def lifespan(self, app: FastAPI):
        await self.progress_tracker.start_cleanup_task()        
        await self._restore_monitoring_state()
        yield
        
        print("🔧 Ending FIXED application lifespan...")
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
        
        self.selection_cache = {}
        self.selection_cache_lock = asyncio.Lock()
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
                db_config=db_config
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
            
            print("✅ All ENHANCED components with charts initialized")
            
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
        
        @self.app.get("/", response_class=HTMLResponse)
        async def dashboard(request: Request, username: str = Depends(authenticate)):
            """Enhanced dashboard with live monitoring and PDF conversion"""
            config_summary = self.config.get_summary()
            
            existing_reports = []
            reports_dir = Path(self.config.paths.reports_dir)
            
            if reports_dir.exists():
                for report_file in sorted(reports_dir.glob("*.md"), reverse=True):
                    try:
                        with open(report_file, 'r', encoding='utf-8') as f:
                            content = f.read()
                        
                        stat = report_file.stat()
                        existing_reports.append({
                            "filename": report_file.name,
                            "timestamp": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                            "size": f"{stat.st_size / 1024:.1f} KB",
                            "content": content,
                            "preview": content[:500] + "..." if len(content) > 500 else content
                        })
                        print(f"✅ Loaded report: {report_file.name}")
                    except Exception as e:
                        print(f"⚠️ Error reading {report_file.name}: {e}")
            
            print(f"📊 Total reports loaded: {len(existing_reports)}")
            
            context = {
                "request": request,
                "config_summary": config_summary,
                "existing_reports": existing_reports  # 🆕 Pass reports to template
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
                except:
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
            
            custom_docs = []
            if use_uploads and customFiles:
                print(f"\n📤 Processing {len(customFiles)} uploaded files for pgvector storage...")
                for file in customFiles:
                    if file.filename:
                        try:
                            content = await file.read()
                            text, metadata = self.document_processor.process_upload(
                                content, file.filename, save_to_disk=False
                            )
                            if text.strip():
                                custom_docs.append(text)
                                print(f"✅ Processed {file.filename} - will be stored in pgvector database")
                        except ValueError as ve:
                            # Duplicate file
                            print(f"⚠️ {ve}")
                        except Exception as e:
                            print(f"❌ Error processing {file.filename}: {e}")
                
                if custom_docs:
                    print(f"💾 Total docs ready for database storage: {len(custom_docs)}")
                else:
                    print(f"⚠️ No new documents to add (all may be duplicates)")
            
            asyncio.create_task(self._build_rag_with_progress(
                session_id=session_id,
                use_archives=use_archives,
                use_uploads=use_uploads,
                archive_days=ragDays,
                custom_docs=custom_docs
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
        async def analyze_alerts(include_charts: bool = Form(True),username: str = Depends(authenticate)):
            """Analyze current alerts with RAG"""
            session_id = generate_session_id()
            asyncio.create_task(self._analyze_alerts_with_progress(session_id))
            return {"session_id": session_id, "message": "Alert analysis started"}
        
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
                    raise HTTPException(
                        status_code=500, 
                        detail=result["error"]
                    )
                    
            except Exception as e:
                raise HTTPException(
                    status_code=500, 
                    detail=f"PDF conversion error: {str(e)}"
                )
        
        @self.app.post("/batch-convert-pdf")
        async def batch_convert_pdf(username: str = Depends(authenticate)):
            """FIXED: Convert all markdown reports to PDF"""
            try:
                result = await self.pdf_api_handlers.handle_batch_conversion()
                
                if result["success"]:
                    return result["results"]
                else:
                    raise HTTPException(
                        status_code=500,
                        detail=result["error"]
                    )
                    
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
        
        @self.app.get("/reports")
        async def list_reports(username: str = Depends(authenticate)):
            """List generated reports (both MD and PDF)"""
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
            return reports
        
        @self.app.get("/reports/{filename}")
        async def download_report(filename: str, username: str = Depends(authenticate)):
            """Download or view report"""
            report_path = Path(self.config.paths.reports_dir) / filename
            
            if not report_path.exists():
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
                    "visual_analysis": True  # NEW
                }
            }
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
        async def check_analysis_result(session_id: str) -> Dict[str, Any]:
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
                # Return basic set if file not found
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
                print(f"🔄 Fetching alerts with tail...")
                
                await self.live_monitoring.persistent_ssh.ensure_connection()
                
                raw_alerts = await asyncio.get_event_loop().run_in_executor(
                    None,
                    self.live_monitoring.persistent_ssh.ssh_reader.alerts_reader.read_alerts,
                    1000  
                )
                raw_alerts.reverse()
                
                if min_severity > 0:
                    filtered = [a for a in raw_alerts if a.get('rule', {}).get('level', 0) >= min_severity]
                else:
                    filtered = raw_alerts
                
                total = len(filtered)
                total_pages = (total + page_size - 1) // page_size if total > 0 else 1
                start = (page - 1) * page_size
                end = start + page_size
                page_alerts = filtered[start:end]
                
                minimal_alerts = []
                for idx, alert in enumerate(page_alerts):
                    rule = alert.get('rule', {})
                    data = alert.get('data', {})
                    
                    minimal_alerts.append({
                        'alert_id': start + idx,
                        'timestamp': alert.get('timestamp', ''),
                        'rule_level': rule.get('level', 0),
                        'rule_description': rule.get('description', 'N/A'),
                        'src_ip': data.get('src_ip', '-'),
                        'dest_ip': data.get('dest_ip', '-'),
                        'agent_name': alert.get('agent', {}).get('name', 'N/A'),
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
            """Analyze selected alerts - NO CACHE, re-fetch if needed"""
            try:
                data = await request.json()
                selected_ids = data.get('selected_ids', [])
                
                if not selected_ids:
                    raise HTTPException(status_code=400, detail="No alerts selected")
                
                print(f"📊 Analyzing {len(selected_ids)} selected alerts...")
                
                # Re-fetch alerts (fast with tail)
                await self.live_monitoring.persistent_ssh.ensure_connection()
                raw_alerts = await asyncio.get_event_loop().run_in_executor(
                    None,
                    self.live_monitoring.persistent_ssh.ssh_reader.alerts_reader.read_alerts,
                    1000
                )
                
                print(f"✅ Re-fetched {len(raw_alerts)} alerts")
                
                # Get selected raw alerts by ID
                selected_raw = []
                for alert_id in selected_ids:
                    if 0 <= alert_id < len(raw_alerts):
                        selected_raw.append(raw_alerts[alert_id])
                
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
                
                print(f"✅ Processed {len(processed_alerts)} alerts")
                print(f"🔍 First alert sample: {str(processed_alerts[0])[:200] if processed_alerts else 'NONE'}")
                
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
    
    async def _build_rag_with_progress(self, session_id: str, use_archives: bool, 
                                 use_uploads: bool, archive_days: Optional[int], 
                                 custom_docs: List[str]):
        """Build RAG context with progress tracking"""
        try:
            archive_logs = []
            
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
                
                if not ssh_reader.connect():
                    await self.progress_tracker.send_progress(
                        session_id, "❌ Failed to connect to SSH", 0, "error"
                    )
                    return False
                
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
            
            if use_uploads:
                if custom_docs:
                    await self.progress_tracker.send_progress(
                        session_id, f"💾 Storing {len(custom_docs)} documents to pgvector database...", 60
                    )
                else:
                    await self.progress_tracker.send_progress(
                        session_id, "⏭️ No new documents to store (may be duplicates).", 60
                    )
            await self.progress_tracker.send_progress(
                session_id, "🧠 Building/Updating RAG vector store...", 70
            )
            
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
                
                # Auto-convert to PDF if available
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"VISUAL_Analysis_{timestamp}.md"
                report_path = Path(self.config.paths.reports_dir) / filename
                
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
    
    async def _analyze_alerts_with_progress(self, session_id: str, selected_alerts: List[Dict] = None):
        try:
            if not self.report_generator.rag_ready:
                await self.progress_tracker.send_progress(
                    session_id, "❌ RAG context not ready", 0, "error"
                )
                return None
            
            # Use provided alerts
            if selected_alerts is not None:
                current_alerts = selected_alerts
                print(f"📊 DEBUG: Using {len(current_alerts)} selected alerts")
                # ADD THIS DEBUG:
                if current_alerts:
                    print(f"📊 DEBUG: First alert keys: {list(current_alerts[0].keys())}")
                    print(f"📊 DEBUG: First alert: {str(current_alerts[0])[:300]}")
                await self.progress_tracker.send_progress(
                    session_id, f"📊 Analyzing {len(current_alerts)} selected alerts", 50
                )
            else:
                # Fetch from SSH if no alerts provided
                await self.progress_tracker.send_progress(
                    session_id, "🔌 Connecting to get current alerts...", 10
                )
                
                ssh_reader = self._create_ssh_reader()
                
                if not ssh_reader.connect():
                    await self.progress_tracker.send_progress(
                        session_id, "❌ Failed to connect to SSH", 0, "error"
                    )
                    return None
                
                current_alerts = ssh_reader.read_alerts(1000)
                ssh_reader.disconnect()
                
                # Process them
                loop = asyncio.get_event_loop()
                current_alerts = await loop.run_in_executor(
                    None,
                    self.report_generator.alert_analyzer.clean_log_data,
                    current_alerts
                )
            
            # CRITICAL CHECK: Are there actually alerts?
            if not current_alerts or len(current_alerts) == 0:
                await self.progress_tracker.send_progress(
                    session_id, "❌ No alerts to analyze", 0, "error"
                )
                return None
            
            print(f"📊 About to call generate_report_with_rag with {len(current_alerts)} alerts")
            
            await self.progress_tracker.send_progress(
                session_id, "🧠 Generating report...", 60
            )
            
            def generate_report():
                print(f"🔍 INSIDE generate_report: Got {len(current_alerts)} alerts")
                return self.report_generator.generate_report_with_rag(
                    current_alerts,  # These alerts MUST be processed (cleaned)
                    self.config.ssh.host
                )
            
            loop = asyncio.get_event_loop()
            
            try:
                report = await asyncio.wait_for(
                    loop.run_in_executor(None, generate_report), 
                    timeout=self.config.llm.timeout
                )
            except asyncio.TimeoutError:
                await self.progress_tracker.send_progress(
                    session_id, "❌ Report generation timed out", 0, "error"
                )
                return None
            
            await self.progress_tracker.send_progress(
                session_id, "💾 Saving enhanced report...", 90
            )
            
            # Parse report into editable structure
            await self.progress_tracker.send_progress(
                session_id, "📝 Preparing report for review...", 95
            )
            # 🔍 DEBUG: Log the raw LLM output
            print("=" * 100)
            print("🔍 RAW LLM OUTPUT (before parsing):")
            print("=" * 100)
            print(report[:2000])  # First 2000 chars
            print("=" * 100)

            try:
                parsed_report = ReportParser.parse_report(report)
                
                # 🔍 DEBUG: Log the parsed result
                print("=" * 100)
                print("🔍 PARSED REPORT (after parsing):")
                print("=" * 100)
                import json
                print(json.dumps(parsed_report, indent=2)[:2000])
                print("=" * 100)
                report_id = generate_session_id()
                self.draft_reports[report_id] = parsed_report
                
                print(f"📝 Draft report created: {report_id}")
                print(f"   → Redirect to: /review-report/{report_id}")
                
                await self.progress_tracker.send_progress(
                    session_id, 
                    f"✅ Report ready for review! Redirecting to editor...", 
                    100, 
                    "success"
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
        print(f"❌ FIXED Application startup failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()