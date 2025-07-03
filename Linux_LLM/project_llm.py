import json
import os
import subprocess
import tempfile
import uuid
import asyncio
import gzip
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Any, Optional
import paramiko
from fastapi import FastAPI, HTTPException, Depends, status, Form, WebSocket, UploadFile, File
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel
import secrets
import uvicorn
from jinja2 import Template
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain_community.vectorstores import FAISS
from langchain_huggingface import HuggingFaceEmbeddings
from langchain.schema import Document
import PyPDF2
import io

app = FastAPI(title="SOC Threat Analysis with RAG")
security = HTTPBasic()

# Configuration
class Config:
    def __init__(self):
        # Web Authentication
        self.username = "admin"
        self.password = "admin"
        
        # SSH Configuration
        self.ssh_host = "100.78.175.127"
        self.ssh_username = "wazuh-user"
        self.ssh_password = "wazuh"
        self.ssh_port = 22
        
        # File paths
        self.alerts_file_path = "/var/ossec/logs/alerts/alerts.json"
        self.archives_base_path = "/var/ossec/logs/archives"
        self.model_path = "/home/itp15student/Desktop/Qwen3-8B-Q4_K_M.gguf" # gemma-3-4b-it-Q3_K_S.gguf / Qwen3-4B-Q4_K_M.gguf
        self.llama_cpp_path = "/home/itp15student/Desktop/llama.cpp/build/bin/llama-cli"
        self.reports_dir = "/home/itp15student/Desktop/ICT2114_Team15/Linux_LLM/reports"
        self.templates_dir = "/home/itp15student/Desktop/ICT2114_Team15/Linux_LLM/templates"
        self.uploads_dir = "/home/itp15student/Desktop/ICT2114_Team15/Linux_LLM/uploads"
        
config = Config()

# Progress tracking for WebSocket
class ProgressTracker:
    def __init__(self):
        self.websockets: Dict[str, WebSocket] = {}
        
    async def connect(self, session_id: str, websocket: WebSocket):
        await websocket.accept()
        self.websockets[session_id] = websocket
        
    def disconnect(self, session_id: str):
        if session_id in self.websockets:
            del self.websockets[session_id]
            
    async def send_progress(self, session_id: str, message: str, progress: int = 0):
        if session_id in self.websockets:
            try:
                await self.websockets[session_id].send_json({
                    "message": message,
                    "progress": progress,
                    "timestamp": datetime.now().strftime("%H:%M:%S")
                })
            except:
                self.disconnect(session_id)

progress_tracker = ProgressTracker()

# Authentication
def authenticate(credentials: HTTPBasicCredentials = Depends(security)):
    username_match = secrets.compare_digest(credentials.username, config.username)
    password_match = secrets.compare_digest(credentials.password, config.password)
    if not (username_match and password_match):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username

class SmartSSHLogReader:
    def __init__(self):
        self.host = config.ssh_host
        self.username = config.ssh_username
        self.password = config.ssh_password
        self.port = config.ssh_port
        self.alerts_path = config.alerts_file_path
        self.archives_base = config.archives_base_path
        
    def connect(self):
        """Establish SSH connection"""
        try:
            print(f"🔌 Connecting to {self.host}:{self.port} as {self.username}...")
            self.ssh = paramiko.SSHClient()
            self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.ssh.connect(self.host, port=self.port, username=self.username, 
                           password=self.password, timeout=30)
            self.sftp = self.ssh.open_sftp()
            print(f"✅ Successfully connected to {self.host}")
            return True
        except Exception as e:
            print(f"❌ SSH connection failed: {e}")
            return False
            
    def disconnect(self):
        """Close SSH connection"""
        try:
            if hasattr(self, 'sftp'):
                self.sftp.close()
            if hasattr(self, 'ssh'):
                self.ssh.close()
            print("🔌 SSH connection closed")
        except:
            pass
    
    def read_alerts(self) -> List[Dict]:
        """Read current alerts from alerts.json"""
        alerts = []
        
        try:
            try:
                file_stat = self.sftp.stat(self.alerts_path)
                print(f"📁 Found alerts file: {self.alerts_path} ({file_stat.st_size} bytes)")
            except IOError:
                print(f"❌ Alerts file not found: {self.alerts_path}")
                return alerts
            
            with self.sftp.open(self.alerts_path, 'r') as f:
                line_count = 0
                for line in f:
                    line_count += 1
                    line = line.strip()
                    if line:
                        try:
                            alert = json.loads(line)
                            alerts.append(alert)
                        except json.JSONDecodeError as e:
                            print(f"⚠️ JSON decode error at line {line_count}: {e}")
                            
            print(f"📊 Processed {line_count} lines, found {len(alerts)} alerts")
                            
        except Exception as e:
            print(f"❌ Error reading alerts file: {e}")
            
        return alerts

    def get_smart_archive_dates(self, past_days: int) -> List[datetime]:
        """Generate smart date list that handles month/year boundaries"""
        dates = []
        current = datetime.now()
        
        for i in range(1, past_days + 1):
            target_date = current - timedelta(days=i)
            dates.append(target_date)
            
        return dates

    def read_archives_smart(self, past_days=7) -> List[Dict]:
        """Read archive logs with smart date boundary handling"""
        logs = []
        dates = self.get_smart_archive_dates(past_days)
        
        print(f"📅 Looking for archives across {len(dates)} days:")
        for date in dates[:3]:  # Show first 3 dates as example
            print(f"   {date.strftime('%Y-%m-%d (%b)')}")
        if len(dates) > 3:
            print(f"   ... and {len(dates)-3} more dates")

        for day in dates:
            year = day.year
            month_name = day.strftime("%b")
            day_num = day.strftime("%d")
            base_path = f"{self.archives_base}/{year}/{month_name}"
            json_path = f"{base_path}/ossec-archive-{day_num}.json"
            gz_path = f"{base_path}/ossec-archive-{day_num}.json.gz"
            print(f"🔍 Attempting to stat: {json_path}")  # ← ADD THIS
            try:
                # Try JSON file first
                try:
                    if self.sftp.stat(json_path).st_size > 0:
                        with self.sftp.open(json_path, 'r') as f:
                            day_logs = 0
                            for line in f:
                                line = line.strip()
                                if line:
                                    try:
                                        log = json.loads(line)
                                        logs.append(log)
                                        day_logs += 1
                                    except json.JSONDecodeError:
                                        continue
                        print(f"✅ {day.strftime('%Y-%m-%d')}: {day_logs} logs from JSON")
                        continue
                except IOError:
                    pass

                # Try compressed file
                try:
                    if self.sftp.stat(gz_path).st_size > 0:
                        with self.sftp.open(gz_path, 'rb') as f:
                            with gzip.GzipFile(fileobj=f) as gz_f:
                                day_logs = 0
                                for line in gz_f:
                                    line = line.decode('utf-8', errors='ignore').strip()
                                    if line:
                                        try:
                                            log = json.loads(line)
                                            logs.append(log)
                                            day_logs += 1
                                        except json.JSONDecodeError:
                                            continue
                        print(f"✅ {day.strftime('%Y-%m-%d')}: {day_logs} logs from GZ")
                except IOError:
                    print(f"⚠️ {day.strftime('%Y-%m-%d')}: No archives found")
                    
            except Exception as e:
                print(f"⚠️ Error reading archive for {day.strftime('%Y-%m-%d')}: {e}")
                continue
                
        print(f"📊 Total loaded: {len(logs)} archive entries from {past_days} days")
        return logs

class DocumentProcessor:
    @staticmethod
    def extract_text_from_pdf(file_content: bytes) -> str:
        """Extract text from PDF file"""
        try:
            pdf_file = io.BytesIO(file_content)
            pdf_reader = PyPDF2.PdfReader(pdf_file)
            text = ""
            for page in pdf_reader.pages:
                text += page.extract_text() + "\n"
            return text
        except Exception as e:
            print(f"⚠️ PDF extraction error: {e}")
            return ""
    
    @staticmethod
    def process_upload(file_content: bytes, filename: str) -> str:
        """Process uploaded file and extract text"""
        file_ext = Path(filename).suffix.lower()
        
        if file_ext == '.pdf':
            return DocumentProcessor.extract_text_from_pdf(file_content)
        elif file_ext in ['.txt', '.md']:
            return file_content.decode('utf-8', errors='ignore')
        else:
            print(f"⚠️ Unsupported file type: {file_ext}")
            return ""

class LlamaCppClient:
    def __init__(self):
        self.model_path = config.model_path
        self.llama_cpp_path = config.llama_cpp_path
        self.chat_template = self._load_chat_template()
        
    def _load_chat_template(self) -> str:
        """Load Qwen chat template"""
        template_path = Path(config.templates_dir) / "qwen_chat.j2"
        if template_path.exists():
            with open(template_path, 'r') as f:
                return f.read()
        return ""
    
    def _format_messages(self, system_prompt: str, user_message: str) -> str:
        """Format messages using Qwen chat template"""
        if self.chat_template:
            try:
                template = Template(self.chat_template)
                messages = [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_message}
                ]
                return template.render(messages=messages, add_generation_prompt=True, enable_thinking=False)
            except Exception as e:
                print(f"⚠️ Template formatting error: {e}")
        
        return f"<|im_start|>system\n{system_prompt}<|im_end|>\n<|im_start|>user\n{user_message}<|im_end|>\n<|im_start|>assistant\n"
    
    def generate_response(self, system_prompt: str, user_message: str) -> str:
        try:
            formatted_prompt = self._format_messages(system_prompt, user_message)
            
            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as temp_file:
                temp_file.write(formatted_prompt)
                temp_file_path = temp_file.name
            
            cmd = [
                self.llama_cpp_path,
                "-m", self.model_path,
                "-f", temp_file_path,
                "--temp", "0.7", #0.7 for qwen
                "--top-p", "0.95", #0.9 for qwen
                "--top-k", "64", #64 for qwen
                "-c", "8192",
                "-n", "4096",
                "--no-display-prompt",
                "--single-turn",
                "--jinja"
            ]
            
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, 
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            
            try:
                stdout, stderr = process.communicate(timeout=1200)
                
                try:
                    os.unlink(temp_file_path)
                except:
                    pass
                
                if process.returncode != 0:
                    print(f"❌ Llama.cpp error (return code {process.returncode})")
                    return f"Error: Command failed with return code {process.returncode}"
                
                response = stdout.strip()
                if formatted_prompt in response:
                    response = response.replace(formatted_prompt, '').strip()
                
                response = response.replace('>', '').replace('$ ', '').strip()
                return response
                
            except subprocess.TimeoutExpired:
                print("❌ LLM generation timed out")
                process.kill()
                try:
                    os.unlink(temp_file_path)
                except:
                    pass
                return "Error: LLM generation timed out after 20 minutes."
                
        except Exception as e:
            print(f"❌ LLM generation error: {e}")
            return f"Error: {str(e)}"

class ReportGenerator:
    def __init__(self):
        self.llm = LlamaCppClient()
        self.embeddings = HuggingFaceEmbeddings(
            model_name="all-MiniLM-L6-v2",
            model_kwargs={'device': 'cpu'},
            encode_kwargs={'normalize_embeddings': False}
        )
        self.system_prompt = self._load_system_prompt()
        
        # RAG state
        self.vectorstore = None
        self.rag_ready = False
        self.archive_logs = []
        self.custom_docs = []
        
    def _load_system_prompt(self) -> str:
        """Load cybersecurity analyst system prompt"""
        template_path = Path(config.templates_dir) / "cti.j2"
        if template_path.exists():
            try:
                with open(template_path, 'r') as f:
                    template_content = f.read()
                template = Template(template_content)
                return template.render()
            except Exception as e:
                print(f"⚠️ System prompt template error: {e}")
        
        return """You are an expert cybersecurity analyst specializing in threat detection and intrusion analysis for a Security Operations Center (SOC). 
Your primary role is to analyze security incidents from Wazuh logs and generate comprehensive intrusion analysis reports following the MITRE ATT&CK framework.

Generate structured reports with:
1. Executive Summary
2. Key Findings  
3. MITRE ATT&CK Mapping
4. Indicators of Compromise
5. Recommendations

Focus on actionable insights for SME security teams."""
    
    def add_custom_documents(self, docs: List[str]):
        """Add custom uploaded documents to RAG"""
        self.custom_docs.extend(docs)
        print(f"📄 Added {len(docs)} custom documents to RAG context")
    
    # MODIFIED: Now handles potentially empty lists for either source
    def build_rag_context(self, archive_logs: List[Dict] = None, custom_docs: List[str] = None):
        """Build combined RAG context from archives and/or custom docs"""
        try:
            print("🔄 Building RAG context...")
            
            if archive_logs:
                self.archive_logs = archive_logs
            elif not hasattr(self, 'archive_logs'):
                self.archive_logs = []

            # Handle custom docs - EXTEND instead of replace
            if custom_docs:
                if not hasattr(self, 'custom_docs'):
                    self.custom_docs = []
                self.custom_docs.extend(custom_docs)  # ← ADD to existing instead of replacing
            elif not hasattr(self, 'custom_docs'):
                self.custom_docs = []

            documents = []
            text_splitter = RecursiveCharacterTextSplitter(chunk_size=500, chunk_overlap=50)
            
            # Process archive logs if provided
            if self.archive_logs:
                for log in self.archive_logs:
                    log_text_parts = []
                    if log.get("rule", {}).get("description"):
                        log_text_parts.append(f"Rule: {log['rule']['description']}")
                    if log.get("data", {}).get("alert", {}).get("signature"):
                        log_text_parts.append(f"Alert: {log['data']['alert']['signature']}")
                    if log.get("full_log"):
                        log_text_parts.append(log["full_log"])
                    
                    log_text = " | ".join(log_text_parts)
                    
                    if log_text:
                        splits = text_splitter.split_text(log_text)
                        for chunk in splits:
                            documents.append(Document(
                                page_content=chunk,
                                metadata={
                                    "source": "archive",
                                    "timestamp": log.get("timestamp", ""),
                                    "rule_level": log.get("rule", {}).get("level", 0)
                                }
                            ))
            
            # Process custom documents if provided
            if self.custom_docs:
                for doc_content in self.custom_docs:
                    if doc_content.strip():
                        splits = text_splitter.split_text(doc_content)
                        for chunk in splits:
                            documents.append(Document(
                                page_content=chunk,
                                metadata={"source": "custom_upload"}
                            ))
            
            if not documents:
                print("⚠️ No documents provided to build RAG context. Aborting.")
                self.rag_ready = False
                return

            # Create vector store
            self.vectorstore = FAISS.from_documents(documents, self.embeddings)
            self.rag_ready = True
            
            print(f"✅ RAG context built: {len(self.archive_logs)} archive logs, {len(self.custom_docs)} custom docs")
            print(f"📊 Total vector chunks: {len(documents)}")
            
        except Exception as e:
            print(f"❌ RAG context build failed: {e}")
            self.rag_ready = False

    def get_rag_status(self) -> Dict[str, Any]:
        """Get current RAG status"""
        return {
            "ready": self.rag_ready,
            "archive_logs": len(self.archive_logs),
            "custom_docs": len(self.custom_docs),
            "total_context": len(self.archive_logs) + len(self.custom_docs)
        }
    
    def generate_report_with_rag(self, current_alerts: List[Dict]) -> str:
        """Generate threat analysis report using RAG context"""
        if not self.rag_ready:
            return "❌ Error: RAG context not ready. Please build RAG context first."
        
        try:
            print(f"🧠 Generating report for {len(current_alerts)} current alerts with RAG...")
            
            # Clean current alerts
            cleaned_alerts = self._clean_log_data(current_alerts)
            
            # Get RAG context using retrieval
            retriever = self.vectorstore.as_retriever(search_kwargs={"k": 10})
            
            # Create query from current alerts for RAG retrieval
            alert_queries = []
            for alert in cleaned_alerts[:5]:  # Use top 5 alerts for context
                if alert.get("rule_description"):
                    alert_queries.append(alert["rule_description"])
                if alert.get("alert_signature"):
                    alert_queries.append(alert["alert_signature"])
            
            query_text = " ".join(alert_queries)
            if not query_text:
                query_text = "security threats malware attacks suspicious activity"
            
            # Retrieve relevant context
            relevant_docs = retriever.get_relevant_documents(query_text)
            rag_context = "\n".join([doc.page_content for doc in relevant_docs[:100]])
            
            # Analyze current alerts
            analysis = self._analyze_current_alerts(cleaned_alerts)
            
            # Create comprehensive context
            context = f"""
CURRENT ALERTS ANALYSIS:
- Total Current Alerts: {len(cleaned_alerts)}
- Severity Distribution: {analysis['severity_breakdown']}
- Top Alert Types: {dict(list(analysis['rule_breakdown'].items())[:5])}
- Critical Events: {len(analysis['critical_events'])}

RAG CONTEXT (Historical Patterns & Custom Intelligence):
{rag_context[:1500]}

SAMPLE CURRENT ALERTS:
{json.dumps(cleaned_alerts[:5], indent=1) if cleaned_alerts else "No current alerts"}
"""
            
            # Generate report
            user_prompt = f"""
Based on the current alerts and RAG context, generate a comprehensive cybersecurity threat analysis report.

{context}

The report should include:
1. **Executive Summary** (key findings and immediate threats)
2. **Current Alert Analysis** (breakdown of active alerts)
3. **Historical Context** (patterns from RAG that relate to current alerts)
4. **MITRE ATT&CK Mapping** (techniques observed)
5. **Threat Intelligence** (insights from custom uploads if any)
6. **Risk Assessment** (severity and urgency)
7. **Immediate Recommendations** (actionable steps)
8. **Technical Details** (detailed analysis with RAG insights)

Focus on correlating current alerts with historical patterns and custom intelligence.
Format in Markdown with clear sections.
"""
            
            report_content = self.llm.generate_response(self.system_prompt, user_prompt)
            
            # Add report header
            rag_status = self.get_rag_status()
            report_header = f"""#  SOC Threat Analysis Report

**Report Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  
**Current Alerts Analyzed:** {len(cleaned_alerts)}  
**RAG Context:** {rag_status['archive_logs']} archive logs + {rag_status['custom_docs']} custom documents  
**Analysis Method:** RAG-powered analysis  
**Wazuh Server:** {config.ssh_host}  

---

"""
            
            return report_header + report_content
            
        except Exception as e:
            error_report = f"""# Error Generating Report

**Error:** {str(e)}  
**Timestamp:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Alert Summary
- Current Alerts: {len(current_alerts)}
- RAG Status: {self.rag_ready}

Please check the system configuration and try again.
"""
            print(f"❌ Report generation error: {e}")
            return error_report
    
    def _clean_log_data(self, logs: List[Dict]) -> List[Dict]:
        """Clean and minimize log data"""
        cleaned_logs = []
        
        for log in logs:
            cleaned_log = {
                "timestamp": log.get("timestamp"),
                "rule_level": log.get("rule", {}).get("level"),
                "rule_description": log.get("rule", {}).get("description"),
                "rule_id": log.get("rule", {}).get("id"),
                "agent_ip": log.get("agent", {}).get("ip")
            }
            
            data = log.get("data", {})
            if data:
                cleaned_log.update({
                    "src_ip": data.get("src_ip"),
                    "dest_ip": data.get("dest_ip"),
                    "proto": data.get("proto")
                })
                
                alert = data.get("alert", {})
                if alert:
                    cleaned_log.update({
                        "alert_signature": alert.get("signature"),
                        "alert_category": alert.get("category"),
                        "alert_severity": alert.get("severity")
                    })
            
            if cleaned_log.get("rule_description") or cleaned_log.get("alert_signature"):
                cleaned_logs.append(cleaned_log)
        
        return cleaned_logs
    
    def _analyze_current_alerts(self, alerts: List[Dict]) -> Dict[str, Any]:
        """Analyze current alerts"""
        analysis = {
            "total_alerts": len(alerts),
            "severity_breakdown": {},
            "rule_breakdown": {},
            "critical_events": []
        }
        
        for alert in alerts:
            level = alert.get('rule_level', 0)
            if level >= 10:
                severity = "Critical"
                analysis["critical_events"].append(alert)
            elif level >= 7:
                severity = "High" 
            elif level >= 4:
                severity = "Medium"
            else:
                severity = "Low"
                
            analysis["severity_breakdown"][severity] = analysis["severity_breakdown"].get(severity, 0) + 1
            
            rule_desc = alert.get('rule_description', 'Unknown')
            analysis["rule_breakdown"][rule_desc] = analysis["rule_breakdown"].get(rule_desc, 0) + 1
        
        return analysis

# Initialize components
report_generator = ReportGenerator()

# Ensure directories exist
os.makedirs(config.reports_dir, exist_ok=True)
os.makedirs(config.templates_dir, exist_ok=True)
os.makedirs(config.uploads_dir, exist_ok=True)

# Async functions
# MODIFIED: Now accepts flags to determine which RAG sources to use
async def build_rag_with_progress(session_id: str, use_archives: bool, use_uploads: bool, archive_days: Optional[int], custom_docs: List[str]):
    """Build RAG context with progress tracking based on selected sources."""
    try:
        archive_logs = []
        
        if use_archives:
            if not archive_days:
                await progress_tracker.send_progress(session_id, "❌ Error: Archive days not specified.", 0)
                return False
            
            await progress_tracker.send_progress(session_id, "🔌 Connecting to Wazuh server...", 10)
            ssh_reader = SmartSSHLogReader()
            if not ssh_reader.connect():
                await progress_tracker.send_progress(session_id, "❌ Failed to connect to SSH", 0)
                return False
            
            await progress_tracker.send_progress(session_id, f"📁 Reading archive logs ({archive_days} days)...", 30)
            archive_logs = ssh_reader.read_archives_smart(archive_days)
            ssh_reader.disconnect()
            await progress_tracker.send_progress(session_id, f"📊 Loaded {len(archive_logs)} archive logs", 50)
            if archive_logs:
                total_log_size = sum(len(str(log)) for log in archive_logs)
                await progress_tracker.send_progress(session_id, f"🔍 Debug: {total_log_size} bytes total log data", 55)
        else:
            await progress_tracker.send_progress(session_id, "⏭️ Skipping OSSEC archive retrieval as requested.", 50)

        if use_uploads:
            await progress_tracker.send_progress(session_id, f"📄 Processing {len(custom_docs)} uploaded files...", 60)
        else:
            await progress_tracker.send_progress(session_id, "⏭️ Skipping file uploads as requested.", 60)

        await progress_tracker.send_progress(session_id, "🧠 Building RAG vector store...", 70)
        
        def build_rag():
            try:
                report_generator.build_rag_context(archive_logs, custom_docs)
                return report_generator.rag_ready
            except Exception as e:
                print(f"❌ RAG build exception: {e}")
                return False
        
        loop = asyncio.get_event_loop()
        success = await loop.run_in_executor(None, build_rag)
        
        if success:
            await progress_tracker.send_progress(session_id, "✅ RAG context ready!", 100)
            return True
        else:
            await progress_tracker.send_progress(session_id, "❌ RAG build failed or no data provided", 0)
            return False
        
    except Exception as e:
        await progress_tracker.send_progress(session_id, f"❌ Error: {str(e)}", 0)
        return False

async def analyze_alerts_with_progress(session_id: str):
    """Analyze current alerts with RAG"""
    try:
        if not report_generator.rag_ready:
            await progress_tracker.send_progress(session_id, "❌ RAG context not ready", 0)
            return None
        
        await progress_tracker.send_progress(session_id, "🔌 Connecting to get current alerts...", 10)
        
        ssh_reader = SmartSSHLogReader()
        if not ssh_reader.connect():
            await progress_tracker.send_progress(session_id, "❌ Failed to connect to SSH", 0)
            return None
        
        await progress_tracker.send_progress(session_id, "📁 Reading current alerts...", 30)
        current_alerts = ssh_reader.read_alerts()
        ssh_reader.disconnect()
        
        await progress_tracker.send_progress(session_id, f"📊 Found {len(current_alerts)} current alerts", 50)
        
        await progress_tracker.send_progress(session_id, "🧠 Generating report with RAG...", 60)
        
        def generate_report():
            return report_generator.generate_report_with_rag(current_alerts)
        
        loop = asyncio.get_event_loop()
        
        try:
            report = await asyncio.wait_for(
                loop.run_in_executor(None, generate_report), 
                timeout=1200
            )
        except asyncio.TimeoutError:
            await progress_tracker.send_progress(session_id, "❌ Report generation timed out", 0)
            return None
        
        await progress_tracker.send_progress(session_id, "💾 Saving report...", 90)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"Threat_analysis_{timestamp}.md"
        report_path = Path(config.reports_dir) / filename
        
        try:
            with open(report_path, 'w', encoding='utf-8') as f:
                f.write(report)
            print(f"📄 Report saved to: {report_path}")
        except Exception as e:
            await progress_tracker.send_progress(session_id, f"❌ Failed to save report: {str(e)}", 0)
            return None
            
        await progress_tracker.send_progress(session_id, f"✅ Report saved: {filename}", 100)
        return filename
        
    except Exception as e:
        await progress_tracker.send_progress(session_id, f"❌ Error: {str(e)}", 0)
        return None

# WebSocket endpoints
@app.websocket("/ws/progress/{session_id}")
async def websocket_progress(websocket: WebSocket, session_id: str):
    await progress_tracker.connect(session_id, websocket)
    try:
        while True:
            await websocket.receive_text()
    except:
        progress_tracker.disconnect(session_id)

# API Endpoints
# MODIFIED: Updated HTML and JavaScript for flexible RAG source selection
@app.get("/", response_class=HTMLResponse)
async def dashboard(username: str = Depends(authenticate)):
    """Dashboard with flexible RAG source selection"""
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title> SOC Threat Analysis with RAG</title>
        <style>
            body {{
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background-color: #1e1e1e;
                color: white;
                margin: 0;
                padding: 20px;
                line-height: 1.6;
            }}
            .container {{
                max-width: 1000px;
                margin: 0 auto;
                background-color: #252931;
                border-radius: 10px;
                padding: 30px;
                box-shadow: 0 4px 15px rgba(53, 149, 249, 0.3);
            }}
            h1 {{
                color: #3595F9;
                text-align: center;
                margin-bottom: 30px;
            }}
            .server-info {{
                background-color: #1e1e1e;
                padding: 15px;
                border-radius: 5px;
                margin-bottom: 30px;
                border-left: 4px solid #3595F9;
            }}
            .section {{
                background-color: #1e1e1e;
                padding: 20px;
                border-radius: 5px;
                margin-bottom: 20px;
                border-left: 4px solid #3595F9;
            }}
            .rag-section {{
                border-left: 4px solid #28a745;
                background-color: #1a2e1a;
            }}
            .analysis-section {{
                border-left: 4px solid #ffc107;
                background-color: #2e2a1a;
            }}
            .form-group {{
                margin-bottom: 20px;
            }}
            .checkbox-group {{
                display: flex;
                align-items: center;
                gap: 10px;
                margin-bottom: 15px;
            }}
            label {{
                display: block;
                margin-bottom: 5px;
                font-weight: bold;
                color: #ddd;
            }}
            .checkbox-group label {{
                margin-bottom: 0;
            }}
            select, input[type="file"] {{
                width: 100%;
                padding: 10px;
                border: 1px solid #3595F9;
                border-radius: 5px;
                background-color: #1e1e1e;
                color: white;
                font-size: 16px;
                box-sizing: border-box;
            }}
            input[type="checkbox"] {{
                width: 20px;
                height: 20px;
            }}
            button {{
                background-color: #3595F9;
                color: white;
                padding: 12px 30px;
                border: none;
                border-radius: 5px;
                font-size: 16px;
                font-weight: bold;
                cursor: pointer;
                width: 100%;
                margin-top: 10px;
                transition: background-color 0.3s;
            }}
            button:hover {{
                background-color: #1c6dd0;
            }}
            button:disabled {{
                background-color: #555;
                cursor: not-allowed;
            }}
            .status-indicator {{
                display: flex;
                align-items: center;
                padding: 10px;
                border-radius: 5px;
                margin: 15px 0;
                font-weight: bold;
            }}
            .status-indicator.ready {{ background-color: #28a745; color: white; }}
            .status-indicator.not-ready {{ background-color: #dc3545; color: white; }}
            .progress-container {{ margin-top: 20px; }}
            .progress-bar {{ background: #1e1e1e; height: 20px; border-radius: 10px; overflow: hidden; margin-bottom: 10px; }}
            .progress-fill {{ background: #3595F9; height: 100%; transition: width 0.3s ease; }}
            .progress-log {{ background: #000; color: #0f0; font-family: monospace; padding: 10px; border-radius: 5px; height: 200px; overflow-y: auto; font-size: 12px; white-space: pre-wrap; }}
            .reports-list {{ margin-top: 30px; border-top: 1px solid #3595F9; padding-top: 20px; }}
            .report-item {{ background-color: #1e1e1e; padding: 15px; margin-bottom: 10px; border-radius: 5px; border-left: 4px solid #3595F9; }}
            .report-item a {{ color: #3595F9; text-decoration: none; font-weight: bold; }}
            .report-item a:hover {{ text-decoration: underline; }}
            .options-container {{ padding-left: 25px; border-left: 2px solid #444; margin-top: 10px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🛡️ SOC Threat Analysis with RAG</h1>
            
            <div class="server-info">
                <strong>📡 Wazuh Server:</strong> {config.ssh_host}:{config.ssh_port}<br>
                <strong>🤖 Model:</strong> {config.model_path.split('/')[-1]}
            </div>
            
            <!-- RAG Configuration Section -->
            <div class="section rag-section">
                <h2>🧠 RAG Context Configuration</h2>
                <p>Select one or more sources to build the RAG context. At least one source must be selected.</p>
                
                <div class="checkbox-group">
                    <input type="checkbox" id="useArchivesCheck" onchange="toggleOptions()">
                    <label for="useArchivesCheck">Use OSSEC Archives</label>
                </div>
                <div id="archiveOptions" class="options-container" style="display:none;">
                    <div class="form-group">
                        <label for="ragDays">Archive History Range:</label>
                        <select id="ragDays">
                            <option value="1">1 Day</option>
                            <option value="3">3 Days</option>
                            <option value="7" selected>1 Week</option>
                            <option value="14">2 Weeks</option>
                            <option value="30">1 Month</option>
                        </select>
                    </div>
                </div>

                <div class="checkbox-group" style="margin-top: 20px;">
                    <input type="checkbox" id="useUploadsCheck" onchange="toggleOptions()">
                    <label for="useUploadsCheck">Use Uploaded Files</label>
                </div>
                <div id="uploadOptions" class="options-container" style="display:none;">
                    <div class="form-group">
                        <label for="customDocs">Custom RAG Documents (Optional):</label>
                        <input type="file" id="customDocs" multiple accept=".pdf,.txt,.md">
                        <small style="color: #aaa;">Upload threat intel, procedures, reports (PDF, TXT, MD)</small>
                    </div>
                </div>
                
                <button id="buildRagBtn" onclick="buildRAG()" disabled>🔄 Build RAG Context</button>
                
                <div id="ragStatus" class="status-indicator not-ready">
                    <span id="ragStatusText">⏳ RAG not initialized - Configure and build the context first</span>
                </div>
            </div>
            
            <!-- Analysis Section -->
            <div class="section analysis-section">
                <h2>🔍 Current Alerts Analysis</h2>
                <p>Analyze current alerts using the RAG context for deeper insights and historical correlation.</p>
                <button id="analyzeBtn" disabled onclick="analyzeAlerts()">🎯 Analyze Current Alerts with RAG</button>
            </div>
            
            <div id="status" style="margin-top: 20px;"></div>
            
            <div class="reports-list">
                <h3>📊 Generated Reports</h3>
                <div id="reportsList"><p>Loading reports...</p></div>
                <button onclick="loadReports()" style="width: auto; margin-top: 10px;">🔄 Refresh List</button>
            </div>
        </div>

        <script>
            let ragReady = false;
            
            function toggleOptions() {{
                document.getElementById('archiveOptions').style.display = document.getElementById('useArchivesCheck').checked ? 'block' : 'none';
                document.getElementById('uploadOptions').style.display = document.getElementById('useUploadsCheck').checked ? 'block' : 'none';
                updateBuildButtonState();
            }}

            function updateBuildButtonState() {{
                const useArchives = document.getElementById('useArchivesCheck').checked;
                const useUploads = document.getElementById('useUploadsCheck').checked;
                document.getElementById('buildRagBtn').disabled = !(useArchives || useUploads);
            }}

            function updateRAGStatus(ready, message) {{
                const statusDiv = document.getElementById('ragStatus');
                const statusText = document.getElementById('ragStatusText');
                const analyzeBtn = document.getElementById('analyzeBtn');
                
                ragReady = ready;
                statusText.textContent = message;
                
                statusDiv.className = ready ? 'status-indicator ready' : 'status-indicator not-ready';
                analyzeBtn.disabled = !ready;
            }}
            
            function showProgress(sessionId, operation) {{
                const progressDiv = document.createElement('div');
                progressDiv.className = 'progress-container';
                progressDiv.innerHTML = `
                    <div class="progress-bar"><div id="progress-fill" class="progress-fill" style="width: 0%;"></div></div>
                    <div id="progress-text" style="margin-bottom: 10px; font-weight: bold;">Starting ${{operation}}...</div>
                    <div id="progress-log" class="progress-log"></div>
                `;
                document.getElementById('status').innerHTML = '';
                document.getElementById('status').appendChild(progressDiv);
                
                const ws = new WebSocket(`ws://${{window.location.host}}/ws/progress/${{sessionId}}`);
                
                ws.onmessage = function(event) {{
                    const data = JSON.parse(event.data);
                    document.getElementById('progress-fill').style.width = data.progress + '%';
                    document.getElementById('progress-text').textContent = `${{data.progress}}% - ${{data.message}}`;
                    const log = document.getElementById('progress-log');
                    log.textContent += `[${{data.timestamp}}] ${{data.message}}\\n`;
                    log.scrollTop = log.scrollHeight;
                    
                    if (data.progress === 100) {{
                        ws.close();
                        if (operation === 'RAG build') {{
                            updateRAGStatus(true, '✅ RAG context ready! You can now analyze alerts.');
                        }} else if (operation === 'analysis') {{
                            loadReports();
                        }}
                    }}
                }};
                
                ws.onclose = function() {{
                    document.getElementById('buildRagBtn').disabled = false;
                    document.getElementById('buildRagBtn').textContent = '🔄 Build RAG Context';
                    if (ragReady) {{
                        document.getElementById('analyzeBtn').disabled = false;
                        document.getElementById('analyzeBtn').textContent = '🎯 Analyze Current Alerts with RAG';
                    }}
                    updateBuildButtonState();
                }};
            }}

            async function buildRAG() {{
                const useArchives = document.getElementById('useArchivesCheck').checked;
                const useUploads = document.getElementById('useUploadsCheck').checked;

                if (!useArchives && !useUploads) {{
                    alert("Please select at least one source for the RAG context.");
                    return;
                }}

                const btn = document.getElementById('buildRagBtn');
                btn.disabled = true;
                btn.textContent = '⏳ Building RAG...';
                updateRAGStatus(false, '🔄 Building RAG context...');
                
                const formData = new FormData();
                formData.append('use_archives', useArchives);
                formData.append('use_uploads', useUploads);

                if (useArchives) {{
                    formData.append('ragDays', document.getElementById('ragDays').value);
                }}
                if (useUploads) {{
                    const customFiles = document.getElementById('customDocs').files;
                    for (let i = 0; i < customFiles.length; i++) {{
                        formData.append('customFiles', customFiles[i]);
                    }}
                }}
                
                try {{
                    const response = await fetch('/build-rag', {{ method: 'POST', body: formData }});
                    if (response.ok) {{
                        const result = await response.json();
                        showProgress(result.session_id, 'RAG build');
                    }} else {{
                        const error = await response.json();
                        updateRAGStatus(false, `❌ Error: ${{error.detail}}`);
                        btn.disabled = false;
                        btn.textContent = '🔄 Build RAG Context';
                        updateBuildButtonState();
                    }}
                }} catch (error) {{
                    updateRAGStatus(false, `❌ Network error: ${{error.message}}`);
                    btn.disabled = false;
                    btn.textContent = '🔄 Build RAG Context';
                    updateBuildButtonState();
                }}
            }}

            async function analyzeAlerts() {{
                if (!ragReady) {{
                    alert('Please build RAG context first!');
                    return;
                }}
                const btn = document.getElementById('analyzeBtn');
                btn.disabled = true;
                btn.textContent = '⏳ Analyzing...';
                
                try {{
                    const response = await fetch('/analyze-alerts', {{ method: 'POST' }});
                    if (response.ok) {{
                        const result = await response.json();
                        showProgress(result.session_id, 'analysis');
                    }} else {{
                        const error = await response.json();
                        alert(`Error: ${{error.detail}}`);
                        btn.disabled = false;
                        btn.textContent = '🎯 Analyze Current Alerts with RAG';
                    }}
                }} catch (error) {{
                    alert(`Network error: ${{error.message}}`);
                    btn.disabled = false;
                    btn.textContent = '🎯 Analyze Current Alerts with RAG';
                }}
            }}

            async function loadReports() {{
                try {{
                    const response = await fetch('/reports');
                    const reports = await response.json();
                    const reportsList = document.getElementById('reportsList');
                    if (reports.length === 0) {{
                        reportsList.innerHTML = '<p>No reports generated yet.</p>';
                    }} else {{
                        reportsList.innerHTML = reports.map(report => `
                            <div class="report-item">
                                <a href="/reports/${{report.filename}}" target="_blank">${{report.filename}}</a><br>
                                <small>Generated: ${{report.created}} | Size: ${{report.size}}</small>
                            </div>
                        `).join('');
                    }}
                }} catch (error) {{ console.error('Error loading reports:', error); }}
            }}

            async function checkRAGStatus() {{
                try {{
                    const response = await fetch('/rag-status');
                    const status = await response.json();
                    if (status.ready) {{
                        updateRAGStatus(true, `✅ RAG Ready: ${{status.archive_logs}} archive logs + ${{status.custom_docs}} custom docs`);
                    }} else {{
                        updateRAGStatus(false, '⏳ RAG not initialized - Configure and build the context first');
                    }}
                }} catch (error) {{
                    updateRAGStatus(false, '❌ Unable to check RAG status');
                }}
            }}

            // Initial setup on page load
            loadReports();
            checkRAGStatus();
            toggleOptions();
        </script>
    </body>
    </html>
    """
    return html_content

# MODIFIED: Now accepts flags to determine which sources to use
@app.post("/build-rag")
async def build_rag(
    use_archives: bool = Form(False),
    use_uploads: bool = Form(False),
    ragDays: Optional[int] = Form(None),
    customFiles: List[UploadFile] = File([]),
    username: str = Depends(authenticate)
):
    """Build RAG context from selected sources."""
    if not use_archives and not use_uploads:
        raise HTTPException(status_code=400, detail="At least one RAG source (archives or uploads) must be selected.")

    session_id = str(uuid.uuid4())
    
    custom_docs = []
    if use_uploads and customFiles:
        for file in customFiles:
            if file.filename:
                try:
                    content = await file.read()
                    text = DocumentProcessor.process_upload(content, file.filename)
                    if text.strip():
                        custom_docs.append(text)
                        save_path = Path(config.uploads_dir) / file.filename
                        with open(save_path, 'wb') as f:
                            f.write(content)
                        print(f"📄 Processed upload: {file.filename}")
                except Exception as e:
                    print(f"⚠️ Error processing {file.filename}: {e}")
    
    # Start background task with the new parameters
    asyncio.create_task(build_rag_with_progress(
        session_id=session_id,
        use_archives=use_archives,
        use_uploads=use_uploads,
        archive_days=ragDays,
        custom_docs=custom_docs
    ))
    
    return {"session_id": session_id, "message": "RAG build started"}

@app.post("/analyze-alerts")
async def analyze_alerts(username: str = Depends(authenticate)):
    """Analyze current alerts with RAG"""
    session_id = str(uuid.uuid4())
    
    # Start background task
    asyncio.create_task(analyze_alerts_with_progress(session_id))
    
    return {"session_id": session_id, "message": "Alert analysis started"}

@app.get("/rag-status")
async def get_rag_status(username: str = Depends(authenticate)):
    """Get current RAG status"""
    return report_generator.get_rag_status()

@app.get("/reports")
async def list_reports(username: str = Depends(authenticate)):
    """List generated reports"""
    reports = []
    reports_path = Path(config.reports_dir)
    
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

@app.get("/reports/{filename}")
async def download_report(filename: str, username: str = Depends(authenticate)):
    """Download or view report"""
    report_path = Path(config.reports_dir) / filename
    
    if not report_path.exists() or not filename.endswith('.md'):
        raise HTTPException(status_code=404, detail="Report not found")
    
    return FileResponse(
        path=report_path,
        filename=filename,
        media_type='text/markdown'
    )

@app.get("/test-connection")
async def test_connection(username: str = Depends(authenticate)):
    """Test SSH connection to Wazuh server"""
    ssh_reader = SmartSSHLogReader()
    
    if ssh_reader.connect():
        try:
            file_stat = ssh_reader.sftp.stat(config.alerts_file_path)
            ssh_reader.disconnect()
            return {
                "status": "success", 
                "message": f"Connected successfully to {config.ssh_host}",
                "file_size": f"{file_stat.st_size} bytes",
                "file_path": config.alerts_file_path
            }
        except Exception as e:
            ssh_reader.disconnect()
            return {"status": "error", "message": f"File access error: {str(e)}"}
    else:
        return {"status": "error", "message": "Failed to establish SSH connection"}

if __name__ == "__main__":
    print("🚀 Starting SOC Threat Analysis with RAG...")
    print(f"📂 Reports directory: {config.reports_dir}")
    print(f"📁 Uploads directory: {config.uploads_dir}")
    print(f"🔧 Model path: {config.model_path}")
    print(f"🖥️ SSH target: {config.ssh_host}:{config.ssh_port}")
    
    if not Path(config.model_path).exists():
        print(f"⚠️ Model file not found: {config.model_path}")
    
    if not Path(config.llama_cpp_path).exists():
        print(f"⚠️ Llama.cpp binary not found: {config.llama_cpp_path}")
    
    uvicorn.run(app, host="0.0.0.0", port=8000)