import json
import os
import subprocess
import tempfile
import uuid
import asyncio
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Any, Optional
import paramiko
from fastapi import FastAPI, HTTPException, Depends, status, Form, WebSocket
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel
import secrets
import uvicorn
from jinja2 import Environment, FileSystemLoader
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain_community.vectorstores import FAISS
from langchain_huggingface import HuggingFaceEmbeddings
from langchain.schema import Document

app = FastAPI(title="SOC Threat Analysis Report Generator")
security = HTTPBasic()

# Configuration
class Config:
    def __init__(self):
        # Web Authentication
        self.username = "admin"
        self.password = "admin"
        
        # SSH Configuration - UPDATE THESE VALUES
        self.ssh_host = "100.78.175.127"  # Your Wazuh server IP
        self.ssh_username = "wazuh-user"      # Your SSH username
        self.ssh_password = "wazuh"   # Your SSH password
        self.ssh_port = 22
        
        # File paths
        self.alerts_file_path = "/var/ossec/logs/alerts/alerts.json"
        self.model_path = "/home/itp15student/Desktop/Qwen3-8B-Q4_K_M.gguf"
        self.llama_cpp_path = "/home/itp15student/Desktop/llama.cpp/build/bin/llama-cli"
        self.reports_dir = "/home/itp15student/Desktop/ICT2114_Team15/Linux_LLM/reports"
        self.templates_dir = "/home/itp15student/Desktop/ICT2114_Team15/Linux_LLM/templates"
        
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

# Models
class ReportRequest(BaseModel):
    period: str  # "daily", "weekly", "monthly"
    custom_days: Optional[int] = None
    report_type: str = "comprehensive"  # "comprehensive", "summary", "indicators_only"

class AlertData:
    def __init__(self, alerts: List[Dict], period: str, start_date: datetime, end_date: datetime):
        self.alerts = alerts
        self.period = period
        self.start_date = start_date
        self.end_date = end_date
        self.total_alerts = len(alerts)

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

class SSHAlertReader:
    def __init__(self):
        self.host = config.ssh_host
        self.username = config.ssh_username
        self.password = config.ssh_password
        self.port = config.ssh_port
        self.alerts_path = config.alerts_file_path
        
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
    
    def read_alerts(self, days_back: int = 7) -> List[Dict]:
        """Read and filter alerts from the single alerts.json file"""
        alerts = []
        
        try:
            # Check if alerts file exists
            try:
                file_stat = self.sftp.stat(self.alerts_path)
                print(f"📁 Found alerts file: {self.alerts_path} ({file_stat.st_size} bytes)")
            except IOError:
                print(f"❌ Alerts file not found: {self.alerts_path}")
                return alerts
            
            # Calculate date filter
            cutoff_date = datetime.now() - timedelta(days=days_back)
            
            # Read alerts from the file
            with self.sftp.open(self.alerts_path, 'r') as f:
                line_count = 0
                for line in f:
                    line_count += 1
                    line = line.strip()
                    if line:
                        try:
                            alert = json.loads(line)
                            
                            # Filter by date if timestamp exists
                            timestamp_str = alert.get('timestamp')
                            if timestamp_str:
                                try:
                                    # Parse Wazuh timestamp format
                                    alert_time = datetime.strptime(timestamp_str[:19], '%Y-%m-%dT%H:%M:%S')
                                    if alert_time >= cutoff_date:
                                        alerts.append(alert)
                                except ValueError:
                                    # If timestamp parsing fails, include the alert
                                    alerts.append(alert)
                            else:
                                # If no timestamp, include the alert
                                alerts.append(alert)
                                
                        except json.JSONDecodeError as e:
                            print(f"⚠️ JSON decode error at line {line_count}: {e}")
                            
            print(f"📊 Processed {line_count} lines, found {len(alerts)} alerts in the last {days_back} days")
                            
        except Exception as e:
            print(f"❌ Error reading alerts file: {e}")
            
        return alerts

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
        return ""  # Fallback to default if template not found
    
    def _format_messages(self, system_prompt: str, user_message: str) -> str:
        """Format messages using Qwen chat template"""
        if self.chat_template:
            try:
                from jinja2 import Template
                template = Template(self.chat_template)
                messages = [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_message}
                ]
                return template.render(messages=messages, add_generation_prompt=True, enable_thinking=False)
            except Exception as e:
                print(f"⚠️ Template formatting error: {e}")
        
        # Fallback format for Qwen
        return f"<|im_start|>system\n{system_prompt}<|im_end|>\n<|im_start|>user\n{user_message}<|im_end|>\n<|im_start|>assistant\n"
    
    # --- FIX START: This function is now correctly indented and has 'self' ---
    def generate_response(self, system_prompt: str, user_message: str) -> str:
        try:
            formatted_prompt = self._format_messages(system_prompt, user_message)
            
            # Create temporary file for prompt
            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as temp_file:
                temp_file.write(formatted_prompt)
                temp_file_path = temp_file.name
            
            # Simplified llama.cpp command
            cmd = [
                self.llama_cpp_path,
                "-m", self.model_path,
                "-f", temp_file_path,
                "--temp", "0.7",
                "--top-p", "0.9",
                "--top-k", "40",
                "-c", "8192",
                "-n", "4096",
                "--no-display-prompt",
                "--single-turn",
                "--jinja" # Using --jinja flag if your llama.cpp version supports it    
            ]
            
            print(f"📝 Input size: {len(formatted_prompt)} characters")
            
            # Use Popen instead of subprocess.run for better output capture
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, 
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            
            # Read output in real-time
            output_lines = []
            error_lines = []
            
            try:
                # Wait for process with timeout
                stdout, stderr = process.communicate(timeout=600)
                
                # Clean up temp file
                try:
                    os.unlink(temp_file_path)
                except:
                    pass
                
                if process.returncode != 0:
                    print(f"❌ Llama.cpp error (return code {process.returncode})")
                    print(f"❌ Stderr: {stderr}")
                    print(f"❌ Stdout: {stdout}")
                    return f"Error: Command failed with return code {process.returncode}\nOutput: {stdout}\nError: {stderr}"
                
                response = stdout.strip()
                print(f"✅ Generated {len(response)} characters")
                
                if formatted_prompt in response:
                    response = response.replace(formatted_prompt, '').strip()
                
                # Remove common artifacts
                response = response.replace('>', '').replace('$ ', '').strip()
                
                print(f"✅ Interactive response: {len(response)} characters")
                return response
                
            except subprocess.TimeoutExpired:
                print("❌ LLM generation timed out")
                process.kill()
                try:
                    os.unlink(temp_file_path)
                except:
                    pass
                return "Error: LLM generation timed out after 5 minutes."
                
        except Exception as e:
            print(f"❌ LLM generation error: {e}")
            try:
                os.unlink(temp_file_path)
            except:
                pass
            return f"Error: {str(e)}"
    # --- FIX END ---

class ReportGenerator:
    def __init__(self):
        self.llm = LlamaCppClient()
        self.embeddings = HuggingFaceEmbeddings(
            model_name="all-MiniLM-L6-v2",
            model_kwargs={'device': 'cpu'},
            encode_kwargs={'normalize_embeddings': False}
        )
        self.system_prompt = self._load_system_prompt()
        
    def _load_system_prompt(self) -> str:
        """Load cybersecurity analyst system prompt"""
        template_path = Path(config.templates_dir) / "cti.j2"
        if template_path.exists():
            try:
                from jinja2 import Template
                with open(template_path, 'r') as f:
                    template_content = f.read()
                template = Template(template_content)
                return template.render()
            except Exception as e:
                print(f"⚠️ System prompt template error: {e}")
        
        # Fallback system prompt
        return """You are an expert cybersecurity analyst specializing in threat detection and intrusion analysis for a Security Operations Center (SOC). 
Your primary role is to analyze security incidents from Wazuh alerts and generate comprehensive intrusion analysis reports following the MITRE ATT&CK framework.

Generate structured reports with:
1. Executive Summary
2. Key Findings  
3. MITRE ATT&CK Mapping
4. Indicators of Compromise
5. Recommendations

Focus on actionable insights for SME security teams."""
    
    def _create_vectorstore(self, alerts: List[Dict]) -> FAISS:
        """Create vector store from alerts for RAG"""
        documents = []
        text_splitter = RecursiveCharacterTextSplitter(chunk_size=500, chunk_overlap=50)
        
        for alert in alerts:
            # Convert alert to text representation
            alert_text = json.dumps(alert, indent=2)
            splits = text_splitter.split_text(alert_text)
            for chunk in splits:
                documents.append(Document(page_content=chunk))
        
        if not documents:
            # Create dummy document if no alerts
            documents.append(Document(page_content="No alerts found for the specified period."))
        
        try:
            # Initialize embeddings with explicit numpy handling
            embeddings = HuggingFaceEmbeddings(
                model_name="all-MiniLM-L6-v2",
                model_kwargs={'device': 'cpu'},
                encode_kwargs={'normalize_embeddings': False}
            )
            return FAISS.from_documents(documents, embeddings)
        except Exception as e:
            print(f"⚠️ Vector store creation failed: {e}")
            # Fallback: create minimal vector store
            dummy_doc = Document(page_content="System initialized with minimal vector store.")
            return FAISS.from_documents([dummy_doc], embeddings)
    
    def _analyze_alerts(self, alert_data: AlertData) -> Dict[str, Any]:
        """Perform comprehensive analysis of alerts"""
        analysis = {
            "total_alerts": alert_data.total_alerts,
            "period": alert_data.period,
            "date_range": f"{alert_data.start_date.strftime('%Y-%m-%d')} to {alert_data.end_date.strftime('%Y-%m-%d')}",
            "severity_breakdown": {},
            "rule_breakdown": {},
            "top_sources": {},
            "top_destinations": {},
            "mitre_techniques": set(),
            "critical_alerts": []
        }
        
        for alert in alert_data.alerts:
            # Extract severity
            rule = alert.get('rule', {})
            level = rule.get('level', 0)
            if level >= 10:
                severity = "Critical"
            elif level >= 7:
                severity = "High" 
            elif level >= 4:
                severity = "Medium"
            else:
                severity = "Low"
                
            analysis["severity_breakdown"][severity] = analysis["severity_breakdown"].get(severity, 0) + 1
            
            # Rule breakdown
            rule_desc = rule.get('description', 'Unknown')
            analysis["rule_breakdown"][rule_desc] = analysis["rule_breakdown"].get(rule_desc, 0) + 1
            
            # Source/destination analysis
            data = alert.get('data', {})
            src_ip = data.get('srcip')
            dst_ip = data.get('dstip')
            if src_ip:
                analysis["top_sources"][src_ip] = analysis["top_sources"].get(src_ip, 0) + 1
            if dst_ip:
                analysis["top_destinations"][dst_ip] = analysis["top_destinations"].get(dst_ip, 0) + 1
                
            # Critical alerts
            if level >= 10:
                analysis["critical_alerts"].append(alert)
                
            # MITRE techniques (if present in rule)
            mitre_tags = rule.get('mitre', {})
            if mitre_tags:
                for technique in mitre_tags.get('technique', []):
                    analysis["mitre_techniques"].add(technique)
        
        # Convert sets to lists for JSON serialization
        analysis["mitre_techniques"] = list(analysis["mitre_techniques"])
        
        return analysis
    
    def generate_report(self, alert_data: AlertData, report_type: str = "comprehensive") -> str:
        """Generate threat analysis report"""
        try:
            print(f"📊 Generating {report_type} report for {alert_data.total_alerts} alerts...")
            
            # SAMPLE ALERTS IF TOO MANY
            if len(alert_data.alerts) > 1000:
                print("⚠️ Too many alerts, sampling 1000 for analysis...")
                import random
                sampled_alerts = random.sample(alert_data.alerts, 1000)
                alert_data.alerts = sampled_alerts
                alert_data.total_alerts = len(sampled_alerts)
            
            # Create vector store for RAG
            vectorstore = self._create_vectorstore(alert_data.alerts)
            
            # Perform analysis
            analysis = self._analyze_alerts(alert_data)
            
            # Prepare context for LLM - LIMIT THE DATA
            top_rules = dict(list(analysis['rule_breakdown'].items())[:5])  # Only top 5
            top_sources = dict(list(analysis['top_sources'].items())[:5])   # Only top 5
            
            context = f"""
Alert Analysis Summary:
- Total Alerts: {analysis['total_alerts']}
- Period: {analysis['period']} ({analysis['date_range']})
- Severity Breakdown: {analysis['severity_breakdown']}
- Top 5 Rules: {top_rules}
- Top 5 Sources: {top_sources}
- Critical Alerts Count: {len(analysis['critical_alerts'])}
- MITRE Techniques: {analysis['mitre_techniques'][:10]}
            """
            
            # Generate report using LLM
            user_prompt = f"""
Please generate a comprehensive cybersecurity threat analysis report based on the following Wazuh alerts data:

{context}

The report should follow this structure:
1. **Executive Summary** (2-3 paragraphs highlighting key findings)
2. **Key Findings** (bullet points of critical discoveries)
3. **MITRE ATT&CK Analysis** (mapping observed activities to MITRE framework)
4. **Indicators of Compromise** (extracted IoCs if any)
5. **Risk Assessment** (severity levels and threat priorities)
6. **Recommendations** (actionable steps for SME security teams)
7. **Technical Details** (detailed alert breakdown)

Focus on actionable insights for small-to-medium enterprise security teams with limited resources.
Format the output in Markdown. /no_think 
            """
            
            report_content = self.llm.generate_response(self.system_prompt, user_prompt)
            
            # Add header with metadata
            report_header = f"""# Security Operations Center - Threat Analysis Report

**Report Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  
**Analysis Period:** {analysis['date_range']} ({analysis['period']})  
**Total Alerts Analyzed:** {analysis['total_alerts']}  
**Report Type:** {report_type.title()}  
**Wazuh Server:** {config.ssh_host}

---

"""
            
            return report_header + report_content
            
        except Exception as e:
            error_report = f"""# Error Generating Report

**Error:** {str(e)}  
**Timestamp:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Alert Summary
- Total Alerts: {alert_data.total_alerts}
- Period: {alert_data.period}
- Date Range: {alert_data.start_date.strftime('%Y-%m-%d')} to {alert_data.end_date.strftime('%Y-%m-%d')}

Please check the system configuration and try again.
"""
            print(f"❌ Report generation error: {e}")
            return error_report

# Initialize components
report_generator = ReportGenerator()

# Ensure directories exist
os.makedirs(config.reports_dir, exist_ok=True)
os.makedirs(config.templates_dir, exist_ok=True)

def get_date_range(period: str, custom_days: Optional[int] = None) -> tuple:
    """Calculate date range based on period"""
    end_date = datetime.now()
    
    if period == "daily":
        start_date = end_date - timedelta(days=1)
        days_back = 1
    elif period == "weekly":
        start_date = end_date - timedelta(days=7)
        days_back = 7
    elif period == "monthly":
        start_date = end_date - timedelta(days=30)
        days_back = 30
    elif period == "custom" and custom_days:
        start_date = end_date - timedelta(days=custom_days)
        days_back = custom_days
    else:
        start_date = end_date - timedelta(days=7)
        days_back = 7
        
    return start_date, end_date, days_back

# Async report generation with progress tracking
async def generate_report_with_progress(session_id: str, period: str, custom_days: int, report_type: str):
    try:
        await progress_tracker.send_progress(session_id, "🔌 Connecting to Wazuh server...", 10)
        
        start_date, end_date, days_back = get_date_range(period, custom_days)
        ssh_reader = SSHAlertReader()
        
        if not ssh_reader.connect():
            await progress_tracker.send_progress(session_id, "❌ Failed to connect to SSH", 0)
            return None
            
        await progress_tracker.send_progress(session_id, "📁 Reading alerts file...", 20)
        
        try:
            alerts = ssh_reader.read_alerts(days_back)
            await progress_tracker.send_progress(session_id, f"📊 Found {len(alerts)} alerts", 40)
            
            if not alerts:
                # Generate a report even with no alerts
                await progress_tracker.send_progress(session_id, "⚠️ No alerts found, generating empty report...", 50)
                alerts = []  # Continue with empty list
                
        finally:
            ssh_reader.disconnect()
            await progress_tracker.send_progress(session_id, "🔌 SSH connection closed", 50)
        
        alert_data = AlertData(alerts, period, start_date, end_date)
        
        await progress_tracker.send_progress(session_id, "🧠 Analyzing alerts with AI...", 60)
        report_content = await generate_report_async(alert_data, report_type, session_id)
        
        # Check if report generation failed
        if report_content.startswith("Error"):
            await progress_tracker.send_progress(session_id, f"❌ {report_content}", 0)
            return None
        
        await progress_tracker.send_progress(session_id, "💾 Saving report...", 90)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"threat_analysis_{period}_{timestamp}.md"
        report_path = Path(config.reports_dir) / filename
        
        try:
            with open(report_path, 'w', encoding='utf-8') as f:
                f.write(report_content)
            print(f"📄 Report saved to: {report_path}")
        except Exception as e:
            await progress_tracker.send_progress(session_id, f"❌ Failed to save report: {str(e)}", 0)
            return None
            
        await progress_tracker.send_progress(session_id, f"✅ Report saved: {filename}", 100)
        return filename
        
    except Exception as e:
        error_msg = f"❌ Error: {str(e)}"
        print(error_msg)
        await progress_tracker.send_progress(session_id, error_msg, 0)
        return None

async def generate_report_async(alert_data, report_type, session_id):
    try:
        await progress_tracker.send_progress(session_id, "📈 Performing statistical analysis...", 65)
        
        # Run the LLM in a thread to avoid blocking, but with better error handling
        def run_llm():
            try:
                print(f"🧠 Starting report generation in thread...")
                result = report_generator.generate_report(alert_data, report_type)
                print(f"✅ Report generation completed in thread")
                return result
            except Exception as e:
                print(f"❌ Error in LLM thread: {e}")
                return f"Error in report generation: {str(e)}"
        
        await progress_tracker.send_progress(session_id, "🤖 Generating report with Qwen3-8B...", 70)
        
        loop = asyncio.get_event_loop()
        
        # Add timeout to the executor as well
        try:
            report = await asyncio.wait_for(
                loop.run_in_executor(None, run_llm), 
                timeout=600  # 6 minute timeout
            )
        except asyncio.TimeoutError:
            await progress_tracker.send_progress(session_id, "❌ Report generation timed out", 0)
            return "Error: Report generation timed out. Please try with a smaller dataset or check system resources."
        
        await progress_tracker.send_progress(session_id, "📝 Finalizing report structure...", 85)
        return report
        
    except Exception as e:
        await progress_tracker.send_progress(session_id, f"❌ Error in async generation: {str(e)}", 0)
        return f"Error in async generation: {str(e)}"

# WebSocket endpoint for progress tracking
@app.websocket("/ws/progress/{session_id}")
async def websocket_progress(websocket: WebSocket, session_id: str):
    await progress_tracker.connect(session_id, websocket)
    try:
        while True:
            await websocket.receive_text()  # Keep connection alive
    except:
        progress_tracker.disconnect(session_id)

# API Endpoints
@app.get("/", response_class=HTMLResponse)
async def dashboard(username: str = Depends(authenticate)):
    """Main dashboard"""
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>SOC Threat Analysis Report Generator</title>
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
                max-width: 800px;
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
                margin-bottom: 20px;
                border-left: 4px solid #3595F9;
            }}
            .form-group {{
                margin-bottom: 20px;
            }}
            label {{
                display: block;
                margin-bottom: 5px;
                font-weight: bold;
                color: #ddd;
            }}
            select, input {{
                width: 100%;
                padding: 10px;
                border: 1px solid #3595F9;
                border-radius: 5px;
                background-color: #1e1e1e;
                color: white;
                font-size: 16px;
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
            .status {{
                margin-top: 20px;
                padding: 15px;
                border-radius: 5px;
                display: none;
            }}
            .status.success {{
                background-color: #28a745;
                display: block;
            }}
            .status.error {{
                background-color: #dc3545;
                display: block;
            }}
            .status.info {{
                background-color: #17a2b8;
                display: block;
            }}
            .reports-list {{
                margin-top: 30px;
                border-top: 1px solid #3595F9;
                padding-top: 20px;
            }}
            .report-item {{
                background-color: #1e1e1e;
                padding: 15px;
                margin-bottom: 10px;
                border-radius: 5px;
                border-left: 4px solid #3595F9;
            }}
            .report-item a {{
                color: #3595F9;
                text-decoration: none;
                font-weight: bold;
            }}
            .report-item a:hover {{
                text-decoration: underline;
            }}
            .progress-container {{
                margin-top: 20px;
            }}
            .progress-bar {{
                background: #1e1e1e;
                height: 20px;
                border-radius: 10px;
                overflow: hidden;
                margin-bottom: 10px;
            }}
            .progress-fill {{
                background: #3595F9;
                height: 100%;
                transition: width 0.3s ease;
            }}
            .progress-log {{
                background: #000;
                color: #0f0;
                font-family: monospace;
                padding: 10px;
                border-radius: 5px;
                height: 200px;
                overflow-y: auto;
                font-size: 12px;
                white-space: pre-wrap;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🛡️ SOC Threat Analysis Report Generator</h1>
            
            <div class="server-info">
                <strong>📡 Connected to Wazuh Server:</strong> {config.ssh_host}:{config.ssh_port}<br>
                <strong>📁 Alerts File:</strong> {config.alerts_file_path}<br>
                <strong>🤖 Model:</strong> {config.model_path.split('/')[-1]}
            </div>
            
            <form id="reportForm">
                <div class="form-group">
                    <label for="period">Report Period:</label>
                    <select id="period" name="period" onchange="toggleCustomDays()">
                        <option value="daily">Daily (Last 24 hours)</option>
                        <option value="weekly" selected>Weekly (Last 7 days)</option>
                        <option value="monthly">Monthly (Last 30 days)</option>
                        <option value="custom">Custom Period</option>
                    </select>
                </div>
                
                <div class="form-group" id="customDaysGroup" style="display: none;">
                    <label for="customDays">Number of Days:</label>
                    <input type="number" id="customDays" name="customDays" min="1" max="365" value="7">
                </div>
                
                <div class="form-group">
                    <label for="reportType">Report Type:</label>
                    <select id="reportType" name="reportType">
                        <option value="comprehensive" selected>Comprehensive Analysis</option>
                        <option value="summary">Executive Summary</option>
                        <option value="indicators_only">Indicators Only</option>
                    </select>
                </div>
                
                <button type="submit" id="generateBtn">🔍 Generate Report</button>
            </form>
            
            <div id="status" class="status"></div>
            
            <div class="reports-list">
                <h3>📊 Recent Reports</h3>
                <div id="reportsList">
                    <p>No reports generated yet.</p>
                </div>
                <button onclick="loadReports()" style="width: auto; margin-top: 10px;">🔄 Refresh List</button>
            </div>
        </div>

        <script>
            function toggleCustomDays() {{
                const period = document.getElementById('period').value;
                const customGroup = document.getElementById('customDaysGroup');
                customGroup.style.display = period === 'custom' ? 'block' : 'none';
            }}

            function showStatus(message, type) {{
                const status = document.getElementById('status');
                status.innerHTML = message;
                status.className = `status ${{type}}`;
            }}

            // Form submit handler with WebSocket progress tracking
            document.getElementById('reportForm').addEventListener('submit', async function(e) {{
                e.preventDefault();
                
                const btn = document.getElementById('generateBtn');
                const formData = new FormData(e.target);
                
                btn.disabled = true;
                btn.textContent = '⏳ Starting...';
                
                try {{
                    const response = await fetch('/generate-report', {{
                        method: 'POST',
                        body: formData
                    }});
                    
                    if (response.ok) {{
                        const result = await response.json();
                        startProgressTracking(result.session_id);
                    }} else {{
                        const error = await response.json();
                        showStatus(`❌ Error: ${{error.detail}}`, 'error');
                        btn.disabled = false;
                        btn.textContent = '🔍 Generate Report';
                    }}
                }} catch (error) {{
                    showStatus(`❌ Network error: ${{error.message}}`, 'error');
                    btn.disabled = false;
                    btn.textContent = '🔍 Generate Report';
                }}
            }});

            function startProgressTracking(sessionId) {{
                const progressDiv = document.createElement('div');
                progressDiv.className = 'progress-container';
                progressDiv.innerHTML = `
                    <div class="progress-bar">
                        <div id="progress-fill" class="progress-fill" style="width: 0%;"></div>
                    </div>
                    <div id="progress-text" style="margin-bottom: 10px; font-weight: bold;">Starting...</div>
                    <div id="progress-log" class="progress-log"></div>
                `;
                
                document.getElementById('status').innerHTML = '';
                document.getElementById('status').appendChild(progressDiv);
                document.getElementById('status').className = 'status info';
                
                const ws = new WebSocket(`ws://${{window.location.host}}/ws/progress/${{sessionId}}`);
                
                ws.onmessage = function(event) {{
                    const data = JSON.parse(event.data);
                    
                    // Update progress bar
                    document.getElementById('progress-fill').style.width = data.progress + '%';
                    document.getElementById('progress-text').textContent = `${{data.progress}}% - ${{data.message}}`;
                    
                    // Add to log
                    const log = document.getElementById('progress-log');
                    log.textContent += `[${{data.timestamp}}] ${{data.message}}\n`;
                    log.scrollTop = log.scrollHeight;
                    
                    // Check if complete
                    if (data.progress === 100) {{
                        ws.close();
                        document.getElementById('generateBtn').disabled = false;
                        document.getElementById('generateBtn').textContent = '🔍 Generate Report';
                        loadReports();
                        
                        setTimeout(() => {{
                            showStatus('✅ Report generation completed!', 'success');
                        }}, 2000);
                    }}
                }};
                
                ws.onclose = function() {{
                    document.getElementById('generateBtn').disabled = false;
                    document.getElementById('generateBtn').textContent = '🔍 Generate Report';
                }};
                
                ws.onerror = function(error) {{
                    console.error('WebSocket error:', error);
                    showStatus('❌ Connection error during progress tracking', 'error');
                    document.getElementById('generateBtn').disabled = false;
                    document.getElementById('generateBtn').textContent = '🔍 Generate Report';
                }};
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
                                <a href="/reports/${{report.filename}}" target="_blank">${{report.filename}}</a>
                                <br>
                                <small>Generated: ${{report.created}} | Size: ${{report.size}}</small>
                            </div>
                        `).join('');
                    }}
                }} catch (error) {{
                    console.error('Error loading reports:', error);
                }}
            }}

            // Load reports on page load
            loadReports();
        </script>
    </body>
    </html>
    """
    return html_content

@app.post("/generate-report")
async def generate_report(
    period: str = Form(...),
    customDays: Optional[int] = Form(None),
    reportType: str = Form("comprehensive"),
    username: str = Depends(authenticate)
):
    """Generate threat analysis report with progress tracking"""
    session_id = str(uuid.uuid4())
    
    # Start background task
    asyncio.create_task(generate_report_with_progress(session_id, period, customDays, reportType))
    
    return {"session_id": session_id, "message": "Report generation started"}

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
    
    # Sort by creation time (newest first)
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
    ssh_reader = SSHAlertReader()
    
    if ssh_reader.connect():
        try:
            # Test file access
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
    print("🚀 Starting SOC Threat Analysis Report Generator...")
    print(f"📂 Reports directory: {config.reports_dir}")
    print(f"🔧 Model path: {config.model_path}")
    print(f"🖥️ SSH target: {config.ssh_host}:{config.ssh_port}")
    print(f"📁 Alerts file: {config.alerts_file_path}")
    print(f"👤 SSH user: {config.ssh_username}")
    
    # Test model and llama.cpp availability
    if not Path(config.model_path).exists():
        print(f"⚠️ Model file not found: {config.model_path}")
    
    if not Path(config.llama_cpp_path).exists():
        print(f"⚠️ Llama.cpp binary not found: {config.llama_cpp_path}")
    
    uvicorn.run(app, host="0.0.0.0", port=8000)