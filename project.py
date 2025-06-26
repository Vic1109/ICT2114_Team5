#!/usr/bin/env python3
"""
SOC Threat Analysis Report Generator with Gemini API
- FastAPI web interface with authentication
- SSH connection to Wazuh server
- RAG (Retrieval-Augmented Generation) for enhanced analysis
- WebSocket progress tracking
- Comprehensive threat analysis reports using Gemini AI
"""

import json
import os
import asyncio
import gzip
import uuid
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
from jinja2 import Template
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain_community.vectorstores import FAISS
from langchain_huggingface import HuggingFaceEmbeddings
from langchain.schema import Document
import google.generativeai as genai

app = FastAPI(title="SOC Threat Analysis Report Generator")
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
        self.reports_dir = "./gemini_reports"
        self.templates_dir = "/home/itp15student/Desktop/ICT2114_Team15/templates"
        
        # Gemini API Configuration
        self.gemini_api_key = "AIzaSyAwleKhZrh4lsOkaIV52Sav4Mn0nF5Q5bA"
        self.gemini_model = "gemini-2.5-flash-preview-05-20"
        self.max_tokens = 800000
        
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
class LogData:
    def __init__(self, logs: List[Dict], data_type: str, date_range: str = ""):
        self.logs = logs
        self.data_type = data_type  # "alerts" or "archives"
        self.total_logs = len(logs)
        self.date_range = date_range

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

class SSHLogReader:
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
        """Read all available alerts from alerts.json"""
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

    def read_archives(self, past_days=7) -> List[Dict]:
        """Read archive logs from remote server"""
        logs = []
        today = datetime.now()

        for i in range(past_days):
            day = today - timedelta(days=i)
            year = day.year
            month_name = day.strftime("%b")
            day_num = day.strftime("%d")
            base_path = f"{self.archives_base}/{year}/{month_name}"
            json_path = f"{base_path}/ossec-archive-{day_num}.json"
            gz_path = f"{base_path}/ossec-archive-{day_num}.json.gz"

            try:
                # Try JSON file first
                try:
                    if self.sftp.stat(json_path).st_size > 0:
                        with self.sftp.open(json_path, 'r') as f:
                            for line in f:
                                line = line.strip()
                                if line:
                                    try:
                                        log = json.loads(line)
                                        logs.append(log)
                                    except json.JSONDecodeError:
                                        continue
                        continue
                except IOError:
                    pass

                # Try compressed file
                try:
                    if self.sftp.stat(gz_path).st_size > 0:
                        with self.sftp.open(gz_path, 'rb') as f:
                            with gzip.GzipFile(fileobj=f) as gz_f:
                                for line in gz_f:
                                    line = line.decode('utf-8', errors='ignore').strip()
                                    if line:
                                        try:
                                            log = json.loads(line)
                                            logs.append(log)
                                        except json.JSONDecodeError:
                                            continue
                except IOError:
                    print(f"⚠️ Archive not found: {json_path} / {gz_path}")
                    
            except Exception as e:
                print(f"⚠️ Error reading archive for {day_num}: {e}")
                
        print(f"📊 Loaded {len(logs)} archive entries from {past_days} days")
        return logs

class GeminiClient:
    def __init__(self):
        self.api_key = config.gemini_api_key
        self.model_name = config.gemini_model
        self.max_tokens = config.max_tokens
        
        # Initialize Gemini
        genai.configure(api_key=self.api_key)
        self.model = genai.GenerativeModel(self.model_name)
        
        # Reserve tokens for system prompt and response overhead
        self.prompt_overhead = 2000
        self.usable_tokens = self.max_tokens - self.prompt_overhead
        
    def count_tokens(self, text: str) -> int:
        """Count tokens using Gemini's official method"""
        try:
            token_count = self.model.count_tokens(text)
            return token_count.total_tokens
        except Exception as e:
            print(f"⚠️ Error counting tokens: {e}")
            # Fallback: rough estimation (1 token ≈ 4 characters)
            return len(text) // 4
        
    def generate_response(self, system_prompt: str, user_message: str) -> str:
        """Generate response using Gemini API"""
        try:
            # Combine system prompt and user message
            full_prompt = f"{system_prompt}\n\n{user_message}"
            
            # Check token count
            prompt_tokens = self.count_tokens(full_prompt)
            print(f"📊 Prompt tokens: {prompt_tokens}")
            
            if prompt_tokens > self.usable_tokens:
                print(f"⚠️ Prompt too long ({prompt_tokens} tokens), truncating...")
                # Truncate the user message to fit
                max_user_tokens = self.usable_tokens - self.count_tokens(system_prompt) - 100
                max_chars = max_user_tokens * 4  # Rough estimation
                user_message = user_message[:max_chars] + "... [TRUNCATED]"
                full_prompt = f"{system_prompt}\n\n{user_message}"
            
            # Generate response
            response = self.model.generate_content(full_prompt)
            
            # Log token usage
            if hasattr(response, 'usage_metadata'):
                usage = response.usage_metadata
                print(f"📈 Token usage - Prompt: {usage.prompt_token_count}, "
                      f"Response: {usage.candidates_token_count}, "
                      f"Total: {usage.total_token_count}")
            
            return response.text
            
        except Exception as e:
            print(f"❌ Gemini API error: {e}")
            return f"Error generating response: {str(e)}"

class ReportGenerator:
    def __init__(self):
        self.llm = GeminiClient()
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
    
    def _create_vectorstore(self, logs: List[Dict]) -> FAISS:
        """Create vector store from cleaned logs for RAG"""
        documents = []
        text_splitter = RecursiveCharacterTextSplitter(chunk_size=300, chunk_overlap=25)
        
        for log in logs:
            # Convert cleaned log to concise text representation for better embeddings
            log_text_parts = []
            
            if log.get("rule_description"):
                log_text_parts.append(f"Rule: {log['rule_description']}")
            if log.get("alert_signature"):
                log_text_parts.append(f"Alert: {log['alert_signature']}")
            if log.get("alert_category"):
                log_text_parts.append(f"Category: {log['alert_category']}")
            if log.get("src_ip"):
                log_text_parts.append(f"Source: {log['src_ip']}")
            if log.get("dest_ip"):
                log_text_parts.append(f"Destination: {log['dest_ip']}")
            if log.get("tunnel_src_ip"):
                log_text_parts.append(f"Tunnel Source: {log['tunnel_src_ip']}")
            if log.get("tunnel_dest_ip"):
                log_text_parts.append(f"Tunnel Destination: {log['tunnel_dest_ip']}")
            if log.get("tunnel_proto"):
                log_text_parts.append(f"Tunnel Protocol: {log['tunnel_proto']}")
            if log.get("proto"):
                log_text_parts.append(f"Protocol: {log['proto']}")
            if log.get("rule_level"):
                log_text_parts.append(f"Severity: {log['rule_level']}")
            
            log_text = " | ".join(log_text_parts)
            
            if log_text:
                splits = text_splitter.split_text(log_text)
                for chunk in splits:
                    documents.append(Document(page_content=chunk))
        
        if not documents:
            documents.append(Document(page_content="No logs found for analysis."))
        
        try:
            return FAISS.from_documents(documents, self.embeddings)
        except Exception as e:
            print(f"⚠️ Vector store creation failed: {e}")
            dummy_doc = Document(page_content="System initialized with minimal vector store.")
            return FAISS.from_documents([dummy_doc], self.embeddings)
    
    def _analyze_logs(self, log_data: LogData) -> Dict[str, Any]:
        """Perform comprehensive analysis of cleaned logs"""
        analysis = {
            "total_logs": log_data.total_logs,
            "data_type": log_data.data_type,
            "date_range": log_data.date_range,
            "severity_breakdown": {},
            "rule_breakdown": {},
            "top_sources": {},
            "top_destinations": {},
            "critical_events": []
        }
        
        for log in log_data.logs:
            # Analyze cleaned log structure
            level = log.get('rule_level', 0)
            if level >= 10:
                severity = "Critical"
                analysis["critical_events"].append(log)
            elif level >= 7:
                severity = "High" 
            elif level >= 4:
                severity = "Medium"
            else:
                severity = "Low"
                
            analysis["severity_breakdown"][severity] = analysis["severity_breakdown"].get(severity, 0) + 1
            
            # Rule analysis
            rule_desc = log.get('rule_description', 'Unknown')
            analysis["rule_breakdown"][rule_desc] = analysis["rule_breakdown"].get(rule_desc, 0) + 1
            
            # Source/destination analysis (including tunnel IPs)
            src_ip = log.get('src_ip')
            dst_ip = log.get('dest_ip')
            tunnel_src_ip = log.get('tunnel_src_ip')
            tunnel_dst_ip = log.get('tunnel_dest_ip')
            
            if src_ip:
                analysis["top_sources"][src_ip] = analysis["top_sources"].get(src_ip, 0) + 1
            if dst_ip:
                analysis["top_destinations"][dst_ip] = analysis["top_destinations"].get(dst_ip, 0) + 1
            if tunnel_src_ip:
                analysis["top_sources"][f"{tunnel_src_ip} (tunnel)"] = analysis["top_sources"].get(f"{tunnel_src_ip} (tunnel)", 0) + 1
            if tunnel_dst_ip:
                analysis["top_destinations"][f"{tunnel_dst_ip} (tunnel)"] = analysis["top_destinations"].get(f"{tunnel_dst_ip} (tunnel)", 0) + 1
        
        return analysis
    
    def _clean_log_data(self, logs: List[Dict]) -> List[Dict]:
        """Clean and minimize log data to reduce token count"""
        cleaned_logs = []
        
        for log in logs:
            # Extract only essential fields for security analysis
            cleaned_log = {
                "timestamp": log.get("timestamp"),
                "rule_level": log.get("rule", {}).get("level"),
                "rule_description": log.get("rule", {}).get("description"),
                "rule_id": log.get("rule", {}).get("id"),
                "agent_ip": log.get("agent", {}).get("ip")
            }
            
            # Extract essential data fields
            data = log.get("data", {})
            if data:
                cleaned_log.update({
                    "src_ip": data.get("src_ip"),
                    "dest_ip": data.get("dest_ip"),
                    "proto": data.get("proto")
                })
                
                # Extract tunnel information if present
                tunnel = data.get("tunnel", {})
                if tunnel:
                    cleaned_log.update({
                        "tunnel_src_ip": tunnel.get("src_ip"),
                        "tunnel_dest_ip": tunnel.get("dest_ip"),
                        "tunnel_proto": tunnel.get("proto")
                    })
                
                # Extract alert specifics
                alert = data.get("alert", {})
                if alert:
                    cleaned_log.update({
                        "alert_signature": alert.get("signature"),
                        "alert_category": alert.get("category"),
                        "alert_severity": alert.get("severity"),
                        "alert_action": alert.get("action")
                    })
                    
                    # Only keep critical metadata
                    metadata = alert.get("metadata", {})
                    if metadata:
                        cleaned_log["metadata_tags"] = metadata.get("tag", [])
                        cleaned_log["confidence"] = metadata.get("confidence", [])
            
            # Only add if we have meaningful data
            if cleaned_log.get("rule_description") or cleaned_log.get("alert_signature"):
                cleaned_logs.append(cleaned_log)
        
        return cleaned_logs

    def generate_report(self, log_data: LogData, report_type: str = "comprehensive") -> str:
        """Generate threat analysis report with RAG"""
        try:
            print(f"📊 Generating {report_type} report for {log_data.total_logs} {log_data.data_type}...")
            
            # Clean the logs first to reduce token count
            print("🧹 Cleaning log data to reduce tokens...")
            original_token_estimate = len(json.dumps(log_data.logs)) // 4
            cleaned_logs = self._clean_log_data(log_data.logs)
            cleaned_token_estimate = len(json.dumps(cleaned_logs)) // 4
            
            print(f"📊 Token reduction: ~{original_token_estimate:,} → ~{cleaned_token_estimate:,} tokens "
                  f"({((original_token_estimate - cleaned_token_estimate) / original_token_estimate * 100):.1f}% reduction)")
            
            # Sort by timestamp and take most recent 100 logs for optimal analysis
            if len(cleaned_logs) > 100:
                print(f"⚠️ Too many logs ({len(cleaned_logs)}), taking most recent 100 for analysis...")
                
                # Sort by timestamp (most recent first)
                try:
                    cleaned_logs.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
                    sampled_logs = cleaned_logs[:100]
                    print(f"📅 Date range of selected logs: {sampled_logs[-1].get('timestamp', 'Unknown')} to {sampled_logs[0].get('timestamp', 'Unknown')}")
                except Exception as e:
                    print(f"⚠️ Error sorting logs by timestamp: {e}, taking first 100...")
                    sampled_logs = cleaned_logs[:100]
                
                log_data.logs = sampled_logs
                log_data.total_logs = len(sampled_logs)
                final_token_estimate = len(json.dumps(sampled_logs)) // 4
                print(f"📊 Final dataset: {len(sampled_logs)} logs, ~{final_token_estimate:,} tokens")
            else:
                log_data.logs = cleaned_logs
                log_data.total_logs = len(cleaned_logs)
                print(f"📊 Using all {len(cleaned_logs)} cleaned logs for analysis")
            
            # Create vector store for RAG
            vectorstore = self._create_vectorstore(log_data.logs)
            analysis = self._analyze_logs(log_data)
            
            # Get top items for context
            top_rules = dict(list(analysis['rule_breakdown'].items())[:5])
            top_sources = dict(list(analysis['top_sources'].items())[:5])
            
            # Retrieve relevant context using RAG (optimized for cleaned data)
            retriever = vectorstore.as_retriever(search_kwargs={"k": 8})  # Reduced from 10 for token efficiency
            relevant_docs = retriever.get_relevant_documents("security threats malware attacks suspicious activity CVE exploit")
            rag_context = "\n".join([doc.page_content for doc in relevant_docs[:2]])  # Reduced to top 2 for token efficiency
            
            # Create concise context for analysis
            context = f"""
SECURITY ANALYSIS DATASET:
- Data Type: {analysis['data_type'].title()}
- Total Logs Analyzed: {analysis['total_logs']}
- Time Period: {analysis['date_range']}
- Severity Distribution: {analysis['severity_breakdown']}
- Critical Events: {len(analysis['critical_events'])}

TOP SECURITY RULES TRIGGERED:
{json.dumps(dict(list(top_rules.items())[:3]), indent=1)}

TOP SOURCE IPs:
{json.dumps(dict(list(top_sources.items())[:3]), indent=1)}

CRITICAL SECURITY EVENTS:
{json.dumps(analysis['critical_events'][:1], indent=1) if analysis['critical_events'] else "None detected"}

RAG CONTEXT (Relevant Security Patterns):
{rag_context[:800]}
            """
            
            # Generate report using Gemini with RAG context
            user_prompt = f"""
Please generate a comprehensive cybersecurity threat analysis report based on the following Wazuh {analysis['data_type']} data:

{context}

The report should follow this structure:
1. **Executive Summary** (2-3 paragraphs highlighting key findings)
2. **Key Findings** (bullet points of critical discoveries)
3. **MITRE ATT&CK Analysis** (mapping observed activities to MITRE framework)
4. **Indicators of Compromise** (extracted IoCs if any)
5. **Risk Assessment** (severity levels and threat priorities)
6. **Recommendations** (actionable steps for SME security teams)
7. **Technical Details** (detailed log breakdown with RAG insights)

Focus on actionable insights for small-to-medium enterprise security teams with limited resources.
Use the RAG context to provide deeper analysis of the security events.
Format the output in Markdown.
            """
            
            report_content = self.llm.generate_response(self.system_prompt, user_prompt)
            
            # Add header with metadata
            report_header = f"""# Security Operations Center - Threat Analysis Report

**Report Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  
**Data Source:** {analysis['data_type'].title()} Logs  
**Analysis Period:** {analysis['date_range']}  
**Total Logs Analyzed:** {analysis['total_logs']}  
**Report Type:** {report_type.title()}  
**Wazuh Server:** {config.ssh_host}  
**AI Model:** {config.gemini_model}

---

"""
            
            return report_header + report_content
            
        except Exception as e:
            error_report = f"""# Error Generating Report

**Error:** {str(e)}  
**Timestamp:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Log Summary
- Data Type: {log_data.data_type}
- Total Logs: {log_data.total_logs}
- Date Range: {log_data.date_range}

Please check the system configuration and try again.
"""
            print(f"❌ Report generation error: {e}")
            return error_report

# Initialize components
report_generator = ReportGenerator()

# Ensure directories exist
os.makedirs(config.reports_dir, exist_ok=True)
os.makedirs(config.templates_dir, exist_ok=True)

# Async report generation with progress tracking
async def generate_report_with_progress(session_id: str, data_source: str, archive_days: int, report_type: str):
    try:
        await progress_tracker.send_progress(session_id, "🔌 Connecting to Wazuh server...", 10)
        
        ssh_reader = SSHLogReader()
        
        if not ssh_reader.connect():
            await progress_tracker.send_progress(session_id, "❌ Failed to connect to SSH", 0)
            return None
            
        if data_source == "alerts":
            await progress_tracker.send_progress(session_id, "📁 Reading alerts file...", 30)
            logs = ssh_reader.read_alerts()
            date_range = "Current alerts"
        else:  # archives
            await progress_tracker.send_progress(session_id, f"📁 Reading archive logs ({archive_days} days)...", 30)
            logs = ssh_reader.read_archives(archive_days)
            end_date = datetime.now()
            start_date = end_date - timedelta(days=archive_days)
            date_range = f"{start_date.strftime('%Y-%m-%d')} to {end_date.strftime('%Y-%m-%d')}"
        
        ssh_reader.disconnect()
        await progress_tracker.send_progress(session_id, f"📊 Found {len(logs)} {data_source}", 50)
        
        log_data = LogData(logs, data_source, date_range)
        
        await progress_tracker.send_progress(session_id, "🧠 Analyzing logs with Gemini AI and RAG...", 60)
        report_content = await generate_report_async(log_data, report_type, session_id)
        
        if report_content.startswith("Error"):
            await progress_tracker.send_progress(session_id, f"❌ {report_content}", 0)
            return None
        
        await progress_tracker.send_progress(session_id, "💾 Saving report...", 90)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"threat_analysis_{data_source}_{timestamp}.md"
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

async def generate_report_async(log_data, report_type, session_id):
    try:
        await progress_tracker.send_progress(session_id, "📈 Performing statistical analysis...", 70)
        
        def run_llm():
            try:
                print(f"🧠 Starting report generation with Gemini + RAG...")
                result = report_generator.generate_report(log_data, report_type)
                print(f"✅ Report generation completed")
                return result
            except Exception as e:
                print(f"❌ Error in Gemini generation: {e}")
                return f"Error in report generation: {str(e)}"
        
        await progress_tracker.send_progress(session_id, "🤖 Generating report with Gemini API + RAG...", 80)
        
        loop = asyncio.get_event_loop()
        
        try:
            report = await asyncio.wait_for(
                loop.run_in_executor(None, run_llm), 
                timeout=600  # 10 minutes timeout for Gemini API
            )
        except asyncio.TimeoutError:
            await progress_tracker.send_progress(session_id, "❌ Report generation timed out", 0)
            return "Error: Report generation timed out."
        
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
            await websocket.receive_text()
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
                max-width: 900px;
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
            .two-column {{
                display: grid;
                grid-template-columns: 1fr 1fr;
                gap: 20px;
            }}
            @media (max-width: 768px) {{
                .two-column {{
                    grid-template-columns: 1fr;
                }}
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🛡️ SOC Threat Analysis Report Generator</h1>
            
            <div class="server-info">
                <strong>📡 Connected to Wazuh Server:</strong> {config.ssh_host}:{config.ssh_port}<br>
                <strong>📁 Alerts File:</strong> {config.alerts_file_path}<br>
                <strong>📁 Archives Path:</strong> {config.archives_base_path}<br>
                <strong>🤖 AI Model:</strong> {config.gemini_model} (Gemini API)<br>
                <strong>🧠 Max Tokens:</strong> {config.max_tokens:,}
            </div>
            
            <div class="two-column">
                <!-- Alerts Analysis -->
                <div class="section">
                    <h2>🚨 Current Alerts Analysis</h2>
                    <p>Analyze the current alerts.json file for immediate threats and incidents using Gemini AI.</p>
                    
                    <form id="alertsForm">
                        <div class="form-group">
                            <label for="alertsReportType">Report Type:</label>
                            <select id="alertsReportType" name="reportType">
                                <option value="comprehensive" selected>Comprehensive Analysis</option>
                                <option value="summary">Executive Summary</option>
                                <option value="indicators_only">Indicators Only</option>
                            </select>
                        </div>
                        
                        <button type="submit" id="alertsBtn">🔍 Analyze Current Alerts</button>
                    </form>
                </div>
                
                <!-- Archives Analysis -->
                <div class="section">
                    <h2>📚 Historical Archives Analysis</h2>
                    <p>Analyze historical archive logs with custom date range using Gemini AI + RAG for deeper insights.</p>
                    
                    <form id="archivesForm">
                        <div class="form-group">
                            <label for="archiveDays">Date Range:</label>
                            <select id="archiveDays" name="archiveDays">
                                <option value="1">1 Day</option>
                                <option value="3">3 Days</option>
                                <option value="7" selected>1 Week</option>
                                <option value="14">2 Weeks</option>
                                <option value="30">1 Month</option>
                            </select>
                        </div>
                        
                        <div class="form-group">
                            <label for="archivesReportType">Report Type:</label>
                            <select id="archivesReportType" name="reportType">
                                <option value="comprehensive" selected>Comprehensive Analysis</option>
                                <option value="summary">Executive Summary</option>
                                <option value="indicators_only">Indicators Only</option>
                            </select>
                        </div>
                        
                        <button type="submit" id="archivesBtn">📊 Analyze Archives with Gemini + RAG</button>
                    </form>
                </div>
            </div>
            
            <div id="status" class="status"></div>
            
            <div class="reports-list">
                <h3>📊 Generated Reports</h3>
                <div id="reportsList">
                    <p>Loading reports...</p>
                </div>
                <button onclick="loadReports()" style="width: auto; margin-top: 10px;">🔄 Refresh List</button>
            </div>
        </div>

        <script>
            function showStatus(message, type) {{
                const status = document.getElementById('status');
                status.innerHTML = message;
                status.className = `status ${{type}}`;
            }}

            // Alerts form handler
            document.getElementById('alertsForm').addEventListener('submit', async function(e) {{
                e.preventDefault();
                generateReport('alerts', 0, e.target.reportType.value, 'alertsBtn');
            }});

            // Archives form handler
            document.getElementById('archivesForm').addEventListener('submit', async function(e) {{
                e.preventDefault();
                generateReport('archives', parseInt(e.target.archiveDays.value), e.target.reportType.value, 'archivesBtn');
            }});

            async function generateReport(dataSource, archiveDays, reportType, buttonId) {{
                const btn = document.getElementById(buttonId);
                
                btn.disabled = true;
                btn.textContent = '⏳ Starting...';
                
                const formData = new FormData();
                formData.append('dataSource', dataSource);
                formData.append('archiveDays', archiveDays);
                formData.append('reportType', reportType);
                
                try {{
                    const response = await fetch('/generate-report', {{
                        method: 'POST',
                        body: formData
                    }});
                    
                    if (response.ok) {{
                        const result = await response.json();
                        startProgressTracking(result.session_id, buttonId);
                    }} else {{
                        const error = await response.json();
                        showStatus(`❌ Error: ${{error.detail}}`, 'error');
                        btn.disabled = false;
                        btn.textContent = dataSource === 'alerts' ? '🔍 Analyze Current Alerts' : '📊 Analyze Archives with Gemini + RAG';
                    }}
                }} catch (error) {{
                    showStatus(`❌ Network error: ${{error.message}}`, 'error');
                    btn.disabled = false;
                    btn.textContent = dataSource === 'alerts' ? '🔍 Analyze Current Alerts' : '📊 Analyze Archives with Gemini + RAG';
                }}
            }}

            function startProgressTracking(sessionId, buttonId) {{
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
                    
                    document.getElementById('progress-fill').style.width = data.progress + '%';
                    document.getElementById('progress-text').textContent = `${{data.progress}}% - ${{data.message}}`;
                    
                    const log = document.getElementById('progress-log');
                    log.textContent += `[${{data.timestamp}}] ${{data.message}}\\n`;
                    log.scrollTop = log.scrollHeight;
                    
                    if (data.progress === 100) {{
                        ws.close();
                        const btn = document.getElementById(buttonId);
                        btn.disabled = false;
                        btn.textContent = buttonId === 'alertsBtn' ? '🔍 Analyze Current Alerts' : '📊 Analyze Archives with Gemini + RAG';
                        loadReports();
                        
                        setTimeout(() => {{
                            showStatus('✅ Report generation completed!', 'success');
                        }}, 2000);
                    }}
                }};
                
                ws.onclose = function() {{
                    const btn = document.getElementById(buttonId);
                    btn.disabled = false;
                    btn.textContent = buttonId === 'alertsBtn' ? '🔍 Analyze Current Alerts' : '📊 Analyze Archives with Gemini + RAG';
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
    dataSource: str = Form(...),
    archiveDays: int = Form(7),
    reportType: str = Form("comprehensive"),
    username: str = Depends(authenticate)
):
    """Generate threat analysis report"""
    session_id = str(uuid.uuid4())
    
    # Start background task
    asyncio.create_task(generate_report_with_progress(session_id, dataSource, archiveDays, reportType))
    
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
    ssh_reader = SSHLogReader()
    
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
    print("🚀 Starting SOC Threat Analysis Report Generator with Gemini AI...")
    print(f"📂 Reports directory: {config.reports_dir}")
    print(f"🤖 Gemini Model: {config.gemini_model}")
    print(f"🎯 Max tokens: {config.max_tokens:,}")
    print(f"🖥️ SSH target: {config.ssh_host}:{config.ssh_port}")
    print(f"📁 Alerts file: {config.alerts_file_path}")
    print(f"📁 Archives path: {config.archives_base_path}")
    print(f"👤 SSH user: {config.ssh_username}")
    
    # Test Gemini API availability
    try:
        genai.configure(api_key=config.gemini_api_key)
        model = genai.GenerativeModel(config.gemini_model)
        test_response = model.generate_content("Hello")
        print(f"✅ Gemini API connection successful")
    except Exception as e:
        print(f"⚠️ Gemini API test failed: {e}")
    
    uvicorn.run(app, host="0.0.0.0", port=8888)