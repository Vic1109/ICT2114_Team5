#!/usr/bin/env python3

from pathlib import Path
import asyncio
import uuid
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional
from contextlib import asynccontextmanager 
import uvicorn
from fastapi import FastAPI, HTTPException, Depends, status, Form, WebSocket, UploadFile, File, Request
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.templating import Jinja2Templates
from fastapi.security import HTTPBasic, HTTPBasicCredentials
import secrets
BASE_DIR = Path(__file__).resolve().parent
# Import our modular components
from config import ConfigManager, validate_environment
from ssh import SmartSSHLogReader
from report import ReportGenerator
from rag import DocumentProcessor
from progress import ProgressTracker, generate_session_id


class SOCApplication:
    """Main SOC Threat Analysis Application"""
    
    # <<< MODIFIED: Lifespan is now a method of the class
    @asynccontextmanager
    async def lifespan(self, app: FastAPI):
        """Manages application startup and shutdown events."""
        # Code to run on startup
        print("🔧 Starting application lifespan...")
        await self.progress_tracker.start_cleanup_task()
        yield
        # Code to run on shutdown
        print("🔧 Ending application lifespan...")
        self.progress_tracker.stop_cleanup_task()

    def __init__(self, config_file: str = None):
        # <<< MODIFIED: Re-ordered initialization for correctness
        
        # 1. Load configuration
        self.config = ConfigManager(config_file)
        is_valid, errors = self.config.validate_all()
        if not is_valid:
            print("❌ Configuration validation failed:")
            for error in errors:
                print(f"  - {error}")
            raise ValueError("Invalid configuration")
        
        # 2. Initialize all components (like progress_tracker)
        self._init_components()

        # 3. Initialize FastAPI app, now that all dependencies are ready
        self.app = FastAPI(
            title="SOC Threat Analysis with RAG",
            description="Cybersecurity threat analysis using RAG and LLM",
            version="2.0.0",
            lifespan=self.lifespan  # Pass the class method
        )
        
        # 4. Setup remaining FastAPI specifics
        self.security = HTTPBasic()
        self.templates = Jinja2Templates(directory=BASE_DIR / "templates")        
        # 5. Setup routes
        self._setup_routes()
        
        print("🚀 SOC Application initialized successfully!")
    
    def _init_components(self):
        """Initialize all application components"""
        try:
            # This now runs BEFORE the FastAPI app is created
            self.progress_tracker = ProgressTracker(max_sessions=100, session_timeout=3600)
            
            self.document_processor = DocumentProcessor(self.config.paths.uploads_dir)
            
            self.report_generator = ReportGenerator(
                llm_config=self.config.llm,  
                templates_dir=self.config.paths.templates_dir
            )
            
            print("✅ All components initialized")
            
        except Exception as e:
            print(f"❌ Component initialization failed: {e}")
            raise
    
    # ... (the rest of your _setup_routes and other methods are perfect and need no changes) ...
    def _setup_routes(self):
        """Setup all FastAPI routes"""
        
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
        
        # <<< MODIFIED: Dashboard route now uses TemplateResponse
        @self.app.get("/", response_class=HTMLResponse)
        async def dashboard(request: Request, username: str = Depends(authenticate)):
            """Main dashboard with RAG configuration and analysis interface"""
            config_summary = self.config.get_summary()
            context = {
                "request": request,
                "config_summary": config_summary
            }
            return self.templates.TemplateResponse("dashboard.html", context)
        
        # WebSocket for progress tracking
        @self.app.websocket("/ws/progress/{session_id}")
        async def websocket_progress(websocket: WebSocket, session_id: str):
            await self.progress_tracker.connect(session_id, websocket, "progress_tracking")
            try:
                while True:
                    await websocket.receive_text()
            except:
                self.progress_tracker.disconnect(session_id)
        
        # RAG build endpoint
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
            
            # Process custom files MEMORY-ONLY (no disk saving)
            custom_docs = []
            if use_uploads and customFiles:
                for file in customFiles:
                    if file.filename:
                        try:
                            content = await file.read()
                            # FIXED: save_to_disk=False for memory-only processing
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
        
        # Analysis endpoint
        @self.app.post("/analyze-alerts")
        async def analyze_alerts(username: str = Depends(authenticate)):
            """Analyze current alerts with RAG"""
            session_id = generate_session_id()
            
            # Start background analysis task
            asyncio.create_task(self._analyze_alerts_with_progress(session_id))
            
            return {"session_id": session_id, "message": "Alert analysis started"}
        
        # RAG status endpoint
        @self.app.get("/rag-status")
        async def get_rag_status(username: str = Depends(authenticate)):
            """Get current RAG status"""
            return self.report_generator.get_rag_status()
        
        # Reports management
        @self.app.get("/reports")
        async def list_reports(username: str = Depends(authenticate)):
            """List generated reports"""
            reports = []
            reports_path = Path(self.config.paths.reports_dir)
            
            if reports_path.exists():
                for report_file in reports_path.glob("*.md"):
                    stat = report_file.stat()
                    reports.append({
                        "filename": report_file.name,
                        "created": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                        "size": f"{stat.st_size / 1024:.1f} KB"
                    })
            
            reports.sort(key=lambda x: x["created"], reverse=True)
            return reports
        
        @self.app.get("/reports/{filename}")
        async def download_report(filename: str, username: str = Depends(authenticate)):
            """Download or view report"""
            report_path = Path(self.config.paths.reports_dir) / filename
            
            if not report_path.exists() or not filename.endswith('.md'):
                raise HTTPException(status_code=404, detail="Report not found")
            
            return FileResponse(
                path=report_path,
                filename=filename,
                media_type='text/markdown'
            )
        
        # System status and testing
        @self.app.get("/test-connection")
        async def test_connection(username: str = Depends(authenticate)):
            """Test SSH connection to Wazuh server"""
            ssh_reader = SmartSSHLogReader(
                host=self.config.ssh.host,
                username=self.config.ssh.username,
                password=self.config.ssh.password,
                port=self.config.ssh.port,
                alerts_path=self.config.wazuh.alerts_file_path,
                archives_base_path=self.config.wazuh.archives_base_path
            )
            
            if ssh_reader.connect():
                try:
                    # Try to access the alerts file
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
            """Get system status and configuration summary"""
            is_env_valid, env_issues = validate_environment()
            
            return {
                "config": self.config.get_summary(),
                "environment": {
                    "valid": is_env_valid,
                    "issues": env_issues
                },
                "components": {
                    "rag_ready": self.report_generator.rag_ready,
                    "progress_sessions": len(self.progress_tracker.websockets),
                    "document_processor": "ready"
                },
                "stats": self.progress_tracker.get_all_stats()
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
                
                ssh_reader = SmartSSHLogReader(
                    host=self.config.ssh.host,
                    username=self.config.ssh.username,
                    password=self.config.ssh.password,
                    port=self.config.ssh.port,
                    alerts_path=self.config.wazuh.alerts_file_path,
                    archives_base_path=self.config.wazuh.archives_base_path
                )
                
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
                    session_id, "✅ RAG context ready!", 100, "success"
                )
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
    
    async def _analyze_alerts_with_progress(self, session_id: str):
        """Analyze current alerts with RAG and progress tracking"""
        try:
            if not self.report_generator.rag_ready:
                await self.progress_tracker.send_progress(
                    session_id, "❌ RAG context not ready", 0, "error"
                )
                return None
            
            await self.progress_tracker.send_progress(
                session_id, "🔌 Connecting to get current alerts...", 10
            )
            
            ssh_reader = SmartSSHLogReader(
                host=self.config.ssh.host,
                username=self.config.ssh.username,
                password=self.config.ssh.password,
                port=self.config.ssh.port,
                alerts_path=self.config.wazuh.alerts_file_path,
                archives_base_path=self.config.wazuh.archives_base_path
            )
            
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
            
            await self.progress_tracker.send_progress(
                session_id, "🧠 Generating report with RAG...", 60
            )
            
            # Generate report
            def generate_report():
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
                session_id, "💾 Saving report...", 90
            )
            
            # Save report
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"Threat_analysis_{timestamp}.md"
            report_path = Path(self.config.paths.reports_dir) / filename
            
            try:
                with open(report_path, 'w', encoding='utf-8') as f:
                    f.write(report)
                print(f"📄 Report saved to: {report_path}")
            except Exception as e:
                await self.progress_tracker.send_progress(
                    session_id, f"❌ Failed to save report: {str(e)}", 0, "error"
                )
                return None
            
            await self.progress_tracker.send_progress(
                session_id, f"✅ Report saved: {filename}", 100, "success"
            )
            return filename
            
        except Exception as e:
            await self.progress_tracker.send_progress(
                session_id, f"❌ Error: {str(e)}", 0, "error"
            )
            return None
    
    def run(self, host: str = None, port: int = None):
        """Run the application"""
        host = host or self.config.web.host
        port = port or self.config.web.port
        
        print(f"🚀 Starting SOC Threat Analysis with RAG...")
        print(f"📊 Dashboard: http://{host}:{port}")
        print(f"🔧 Config summary: {self.config.get_summary()}")
        
        try:
            uvicorn.run(self.app, host=host, port=port)
        except KeyboardInterrupt:
            print("🛑 Shutting down...")
        # <<< MODIFIED: The finally block is no longer needed, as lifespan handles shutdown.

def main():
    """Main entry point"""
    import sys
    
    # Check environment
    is_valid, issues = validate_environment()
    if not is_valid:
        print("❌ Environment validation failed:")
        for issue in issues:
            print(f"  - {issue}")
        sys.exit(1)
    
    # Initialize and run application
    try:
        config_file = sys.argv[1] if len(sys.argv) > 1 else None
        app = SOCApplication(config_file)
        app.run()
    except Exception as e:
        print(f"❌ Application startup failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()