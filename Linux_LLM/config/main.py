#!/usr/bin/env python3
from charts import SOCChartGenerator
from report import EnhancedReportGenerator
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
import secrets
import json

BASE_DIR = Path(__file__).resolve().parent

# Import our modular components
from config import ConfigManager, validate_environment
from ssh import SmartSSHLogReader
from report import ReportGenerator
from rag import DocumentProcessor
from progress import ProgressTracker, generate_session_id

# Import enhanced components
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
    """Update configuration to support chart generation"""
    # Ensure charts directory exists
    reports_dir = Path(config_manager.paths.reports_dir)
    charts_dir = reports_dir / "charts"
    charts_dir.mkdir(parents=True, exist_ok=True)
    
    print(f"📊 Charts directory created: {charts_dir}")
    return str(charts_dir)


class FixedSOCApplication:
    """Fixed SOC application with enhanced monitoring and PDF conversion"""
    
    @asynccontextmanager
    async def lifespan(self, app: FastAPI):
        """Manages application startup and shutdown events."""
        print("🔧 Starting FIXED application lifespan...")
        await self.progress_tracker.start_cleanup_task()
        
        # Start live monitoring if it was previously enabled
        await self._restore_monitoring_state()
        
        yield
        
        # Cleanup on shutdown
        print("🔧 Ending FIXED application lifespan...")
        self.progress_tracker.stop_cleanup_task()
        
        # Stop live monitoring gracefully
        if self.live_monitoring.monitoring_enabled:
            self.live_monitoring.stop_monitoring()

    def __init__(self, config_file: str = None):
        # Load configuration
        self.config = ConfigManager(config_file)
        is_valid, errors = self.config.validate_all()
        if not is_valid:
            print("❌ Configuration validation failed:")
            for error in errors:
                print(f"  - {error}")
            raise ValueError("Invalid configuration")
        
        # Initialize components
        self._init_components()

        # Initialize FastAPI app
        self.app = FastAPI(
            title="FIXED SOC Threat Analysis with Enhanced Monitoring",
            description="Fixed cybersecurity threat analysis with proper alert filtering and PDF reports",
            version="3.1.0",
            lifespan=self.lifespan
        )
        
        # Setup FastAPI specifics
        self.security = HTTPBasic()
        self.templates = Jinja2Templates(directory=BASE_DIR / "templates")
        
        # Setup routes
        self._setup_routes()
        
        print("🚀 FIXED SOC Application initialized successfully!")
    
    def _init_components(self):
        """Initialize all application components with chart support"""
        try:
            # Core components
            self.progress_tracker = ProgressTracker(max_sessions=100, session_timeout=3600)
            self.document_processor = DocumentProcessor(self.config.paths.uploads_dir)
            
            # ENHANCED: Use the enhanced report generator with charts
            self.report_generator = EnhancedReportGenerator(
                llm_config=self.config.llm,  
                templates_dir=self.config.paths.templates_dir,
                reports_dir=self.config.paths.reports_dir  # Pass reports directory
            )
            
            # Live monitoring service
            self.live_monitoring = create_enhanced_live_monitoring_service(
                config_manager=self.config,
                report_generator=self.report_generator,
                ssh_reader_factory=self._create_ssh_reader
            )
                        
            # PDF conversion service
            self.pdf_converter = create_enhanced_pdf_converter()
            self.pdf_api_handlers = create_enhanced_pdf_api_handlers(
                Path(self.config.paths.reports_dir)
            )
            
            print("✅ All ENHANCED components with charts initialized")
            
        except Exception as e:
            print(f"❌ Component initialization failed: {e}")
            raise
    
    def _create_ssh_reader(self):
        """Factory method to create SSH reader instances"""
        return SmartSSHLogReader(
            host=self.config.ssh.host,
            username=self.config.ssh.username,
            password=self.config.ssh.password,
            port=self.config.ssh.port,
            alerts_path=self.config.wazuh.alerts_file_path,
            archives_base_path=self.config.wazuh.archives_base_path
        )
    
    def _setup_routes(self):
        """Setup all FastAPI routes with enhancements and fixes"""
        
        # Authentication dependency
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
        
        # Enhanced dashboard route
        @self.app.get("/", response_class=HTMLResponse)
        async def dashboard(request: Request, username: str = Depends(authenticate)):
            """Enhanced dashboard with live monitoring and PDF conversion"""
            config_summary = self.config.get_summary()
            context = {
                "request": request,
                "config_summary": config_summary
            }
            return self.templates.TemplateResponse("dashboard.html", context)
        
        # Progress tracking WebSocket (existing)
        @self.app.websocket("/ws/progress/{session_id}")
        async def websocket_progress(websocket: WebSocket, session_id: str):
            """Fixed progress WebSocket"""
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
                        data = await asyncio.wait_for(websocket.receive_text(), timeout=60.0)
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
            """Build RAG context from selected sources"""
            if not use_archives and not use_uploads:
                raise HTTPException(
                    status_code=400, 
                    detail="At least one RAG source (archives or uploads) must be selected."
                )
            
            session_id = generate_session_id()
            
            # Process custom files
            custom_docs = []
            if use_uploads and customFiles:
                for file in customFiles:
                    if file.filename:
                        try:
                            content = await file.read()
                            text, metadata = self.document_processor.process_upload(
                                content, file.filename, save_to_disk=False
                            )
                            if text.strip():
                                custom_docs.append(text)
                                print(f"📄 Processed upload (memory-only): {file.filename}")
                        except Exception as e:
                            print(f"⚠️ Error processing {file.filename}: {e}")
            
            # Start background RAG build task
            asyncio.create_task(self._build_rag_with_progress(
                session_id=session_id,
                use_archives=use_archives,
                use_uploads=use_uploads,
                archive_days=ragDays,
                custom_docs=custom_docs
            ))
            
            return {"session_id": session_id, "message": "RAG build started"}
        @self.app.post("/generate-visual-report")
        async def generate_visual_report(username: str = Depends(authenticate)):
            """Generate a visual report with charts only"""
            session_id = generate_session_id()
            asyncio.create_task(self._generate_visual_report_with_progress(session_id))
            return {"session_id": session_id, "message": "Visual report generation started"}
        
        # NEW: Chart capabilities endpoint
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
        
        # FIXED: Enhanced PDF conversion endpoints
        @self.app.post("/convert-to-pdf")
        async def convert_to_pdf(
            filename: str = Form(...),
            username: str = Depends(authenticate)
        ):
            """FIXED: Convert a single markdown report to PDF"""
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
        

        # Auto-convert functionality endpoints
        @self.app.post("/set-auto-convert")
        async def set_auto_convert(
            request: Request,
            username: str = Depends(authenticate)
        ):
            """Set auto-convert to PDF setting"""
            try:
                data = await request.json()
                enabled = data.get('enabled', False)
                
                # Store the setting (you can make this persistent later)
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
        
        # Existing endpoints (status, reports, etc.)
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
                    alerts = ssh_reader.read_alerts()
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
    async def _build_rag_with_progress(self, session_id: str, use_archives: bool, 
                                 use_uploads: bool, archive_days: Optional[int], 
                                 custom_docs: List[str]):
        """Build RAG context with progress tracking"""
        try:
            archive_logs = []
            
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
                await self.progress_tracker.send_progress(
                    session_id, f"📄 Processing {len(custom_docs)} uploaded files...", 60
                )
            else:
                await self.progress_tracker.send_progress(
                    session_id, "⏭️ Skipping file uploads as requested.", 60
                )
            
            await self.progress_tracker.send_progress(
                session_id, "🧠 Building RAG vector store...", 70
            )
            
            # Build RAG context
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
                
                print("🚀 RAG ready - Auto-starting alert monitoring...")
                monitoring_success = self.live_monitoring.start_monitoring(continuous=False)
                if monitoring_success:
                    print("✅ Alert monitoring started automatically")
                else:
                    print("⚠️ Failed to auto-start alert monitoring")
                
                return True
            else:
                await self.progress_tracker.send_progress(
                    session_id, "❌ RAG build failed or no data provided", 0, "error"
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
    
    async def _analyze_alerts_with_progress(self, session_id: str, include_charts: bool = True):
        """Enhanced alert analysis with optional chart generation"""
        try:
            if not self.report_generator.rag_ready:
                await self.progress_tracker.send_progress(
                    session_id, "❌ RAG context not ready", 0, "error"
                )
                return None
            
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
                session_id, f"📊 Found {len(current_alerts)} current alerts", 50
            )
            
            progress_message = "🧠 Generating enhanced report"
            if include_charts:
                progress_message += " with visual analysis"
            progress_message += "..."
            
            await self.progress_tracker.send_progress(
                session_id, progress_message, 60
            )
            
            # Generate report with charts if requested
            def generate_report():
                # The enhanced report generator will automatically include charts
                return self.report_generator.generate_report_with_rag(
                    current_alerts, self.config.ssh.host
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
            
            # Save report
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            suffix = "_with_charts" if include_charts else ""
            filename = f"MANUAL_Threat_analysis{suffix}_{timestamp}.md"
            report_path = Path(self.config.paths.reports_dir) / filename
            
            try:
                with open(report_path, 'w', encoding='utf-8') as f:
                    f.write(report)
                print(f"📄 Enhanced report saved to: {report_path}")
                
                # Auto-convert to PDF if available
                if self.pdf_converter.conversion_available:
                    await self._auto_convert_report(report_path)
                
            except Exception as e:
                await self.progress_tracker.send_progress(
                    session_id, f"❌ Failed to save report: {str(e)}", 0, "error"
                )
                return None
            
            success_message = f"✅ Enhanced report saved: {filename}"
            if include_charts:
                success_message += " (includes visual analysis)"
            
            await self.progress_tracker.send_progress(
                session_id, success_message, 100, "success"
            )
            return filename
            
        except Exception as e:
            await self.progress_tracker.send_progress(
                session_id, f"❌ Error: {str(e)}", 0, "error"
            )
            return None
    
    async def _auto_convert_report(self, report_path: Path):
        """Automatically convert report to PDF if auto-convert is enabled"""
        try:
            # Only convert if auto-convert is enabled
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
        """Restore monitoring state if it was previously active"""
        # In a production system, you might persist monitoring state
        # For now, monitoring starts stopped
        pass
    
    def run(self, host: str = None, port: int = None):
        """Run the FIXED application"""
        host = host or self.config.web.host
        port = port or self.config.web.port
        
        print(f"🚀 Starting FIXED SOC Threat Analysis...")
        print(f"📊 Dashboard: http://{host}:{port}")
        print(f"🔧 Config summary: {self.config.get_summary()}")
        print(f"🚨 Alert Detection: AUTOMATIC after RAG build (Level >= {self.live_monitoring.high_severity_threshold})")
        print(f"📄 PDF conversion: {self.pdf_converter.conversion_method}")
        print(f"🔌 Persistent SSH: Active throughout session")
        print(f"⚡ Auto-monitoring: Starts when RAG context is ready")
        
        try:
            uvicorn.run(self.app, host=host, port=port)
        except KeyboardInterrupt:
            print("🛑 Shutting down FIXED application...")


def main():
    """Main entry point for FIXED application"""
    import sys
    
    # Check environment
    is_valid, issues = validate_environment()
    if not is_valid:
        print("❌ Environment validation failed:")
        for issue in issues:
            print(f"  - {issue}")
        sys.exit(1)
    
    # Initialize and run FIXED application
    try:
        config_file = sys.argv[1] if len(sys.argv) > 1 else None
        app = FixedSOCApplication(config_file)
        app.run()
    except Exception as e:
        print(f"❌ FIXED Application startup failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()