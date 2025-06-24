#!/usr/bin/env python3
"""
Real-time Log Analysis with Local LLM
Integrates with SOC framework for automated threat detection and log summarization
"""

import asyncio
import json
import subprocess
import time
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
import re
import logging
from dataclasses import dataclass
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import requests
import pytz

# ——— CONFIGURATION ———
# Base directory where rsyslog writes monthly folders (e.g. 2025-06/) containing daily logs
LOG_BASE_DIR = "/var/log/wazuh_syslog"
LOG_PREFIX = "wazuh-"
LOG_SUFFIX = ".log"
# Directory where summaries will be saved (user-owned)
SUMMARY_DIR = "/home/itp15student/Desktop/ICT2114_Team15/Linux_LLM/summary"

# TAIL BEHAVIOR CONFIGURATION
START_FROM_TAIL = True  # True = skip existing logs (tail -f), False = process all logs
SHOW_EXISTING_LOG_STATS = True  # Show statistics about existing logs when starting

# Singapore timezone for consistent timestamp handling
TZ_SG = pytz.timezone('Asia/Singapore')

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('log_analyzer.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class LogEntry:
    timestamp: str
    source: str
    severity: str
    message: str
    raw_log: str

@dataclass
class AnalysisResult:
    threat_level: str
    summary: str
    mitre_tactics: List[str]
    mitre_techniques: List[str] = None
    attack_stage: str = None
    false_positive_likelihood: float = None
    business_impact: str = None
    recommended_actions: List[str] = None
    confidence: float = 0.0

class LlamaLLMAnalyzer:
    """Interface to local Llama LLM for log analysis"""
    
    def __init__(self, model_path: str, llama_binary: str = "./llama-cli"):
        self.model_path = model_path
        self.llama_binary = llama_binary
        self.context_window = []
        self.max_context = 5  # Keep last 5 log entries for context
        
    def _create_analysis_prompt(self, log_entry: LogEntry, context: List[LogEntry]) -> str:
        """Create a structured prompt for log analysis"""
        
        context_logs = "\n".join([f"- {entry.timestamp}: {entry.message}" for entry in context[-3:]])
        
        # Check if this is a complex security log (like Wazuh/Suricata)
        is_security_alert = any(keyword in log_entry.message.lower() for keyword in 
                              ['alert', 'exploit', 'cve', 'malware', 'intrusion', 'attack'])
        
        if is_security_alert:
            prompt = f"""You are a senior cybersecurity analyst reviewing a security alert from an IDS/SIEM system. This log contains pre-processed threat intelligence that needs contextual analysis and response prioritization.

RECENT SECURITY CONTEXT (last 3 events):
{context_logs}

CURRENT SECURITY ALERT TO ANALYZE:
Timestamp: {log_entry.timestamp}
Source System: {log_entry.source}
Alert Severity: {log_entry.severity}
Alert Details: {log_entry.message}

ANALYSIS REQUIREMENTS:
1. Assess the actual risk level considering the network environment
2. Determine if this is part of a coordinated attack campaign
3. Identify potential false positive indicators
4. Map to specific MITRE ATT&CK techniques (not just broad tactics)
5. Prioritize response actions based on business impact

Provide analysis in this JSON format:
{{
    "threat_level": "LOW|MEDIUM|HIGH|CRITICAL",
    "summary": "Contextual analysis of this alert's significance and business impact",
    "mitre_tactics": ["Initial_Access", "Execution", "Defense_Evasion", "etc"],
    "mitre_techniques": ["T1190", "T1059", "T1027", "etc"],
    "attack_stage": "reconnaissance|initial_access|persistence|privilege_escalation|defense_evasion|credential_access|discovery|lateral_movement|collection|exfiltration|impact",
    "false_positive_likelihood": 0.2,
    "business_impact": "LOW|MEDIUM|HIGH|CRITICAL",
    "recommended_actions": ["immediate", "short-term", "long-term actions"],
    "confidence": 0.85
}}

Consider:
- Is this exploit actively being used in current threat campaigns?
- Does the source/destination IP indicate internal compromise?
- Are there indicators this is automated scanning vs targeted attack?
- What systems could be affected if this attack succeeds?

Response (JSON only):"""
        else:
            prompt = f"""You are a cybersecurity analyst monitoring system logs for anomalies and potential security issues.

RECENT CONTEXT (last 3 logs):
{context_logs}

CURRENT LOG TO ANALYZE:
Timestamp: {log_entry.timestamp}
Source: {log_entry.source}
Severity: {log_entry.severity}
Message: {log_entry.message}

Provide analysis in this JSON format:
{{
    "threat_level": "LOW|MEDIUM|HIGH|CRITICAL",
    "summary": "Brief summary of the log entry and its significance",
    "mitre_tactics": ["list", "of", "relevant", "MITRE", "ATT&CK", "tactics"],
    "recommended_actions": ["list", "of", "recommended", "actions"],
    "confidence": 0.85
}}

Focus on:
1. Unusual authentication patterns
2. Network anomalies  
3. System access violations
4. Service failures that could indicate attacks
5. Configuration changes
6. User behavior anomalies

Response (JSON only):"""
        
        return prompt
    
    async def analyze_log(self, log_entry: LogEntry) -> Optional[AnalysisResult]:
        """Analyze a single log entry using the local LLM"""
        try:
            prompt = self._create_analysis_prompt(log_entry, self.context_window)
            
            # Call llama.cpp with the prompt
            cmd = [
                self.llama_binary,
                "-m", self.model_path,
                "-p", prompt,
                "-n", "500",  # Max tokens
                "--temp", "0.3",  # Lower temperature for more consistent analysis
                "-c", "4096",  # Context size
                "--no-cnv"  # No conversation mode
            ]
            
            logger.info(f"Analyzing log from {log_entry.source}...")
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                logger.error(f"LLM analysis failed: {stderr.decode()}")
                return None
            
            response = stdout.decode().strip()
            
            # Extract JSON from response
            json_match = re.search(r'\{.*\}', response, re.DOTALL)
            if json_match:
                analysis_data = json.loads(json_match.group())
                
                result = AnalysisResult(
                    threat_level=analysis_data.get("threat_level", "LOW"),
                    summary=analysis_data.get("summary", "No analysis available"),
                    mitre_tactics=analysis_data.get("mitre_tactics", []),
                    mitre_techniques=analysis_data.get("mitre_techniques", []),
                    attack_stage=analysis_data.get("attack_stage"),
                    false_positive_likelihood=analysis_data.get("false_positive_likelihood"),
                    business_impact=analysis_data.get("business_impact"),
                    recommended_actions=analysis_data.get("recommended_actions", []),
                    confidence=analysis_data.get("confidence", 0.0)
                )
                
                # Update context window
                self.context_window.append(log_entry)
                if len(self.context_window) > self.max_context:
                    self.context_window.pop(0)
                
                return result
            else:
                logger.warning("Could not parse JSON response from LLM")
                return None
                
        except Exception as e:
            logger.error(f"Error analyzing log: {e}")
            return None

class LogParser:
    """Parse different log formats"""
    
    @staticmethod
    def parse_wazuh_suricata(line: str) -> Optional[LogEntry]:
        """Parse Wazuh/Suricata JSON format"""
        try:
            log_data = json.loads(line)
            
            # Extract key information from complex JSON structure
            timestamp = log_data.get("timestamp", "")
            
            # Build source information
            agent_info = log_data.get("agent", {})
            agent_name = agent_info.get("name", "unknown")
            agent_ip = agent_info.get("ip", "unknown")
            source = f"{agent_name}({agent_ip})"
            
            # Extract rule information
            rule_info = log_data.get("rule", {})
            rule_level = rule_info.get("level", 0)
            rule_description = rule_info.get("description", "No description")
            rule_groups = rule_info.get("groups", [])
            
            # Map rule level to severity
            severity_map = {
                range(0, 4): "INFO",
                range(4, 7): "LOW", 
                range(7, 10): "MEDIUM",
                range(10, 13): "HIGH",
                range(13, 16): "CRITICAL"
            }
            
            severity = "INFO"
            for level_range, sev in severity_map.items():
                if rule_level in level_range:
                    severity = sev
                    break
            
            # Extract network data if available
            network_info = ""
            if "data" in log_data:
                data = log_data["data"]
                src_ip = data.get("src_ip", "")
                dest_ip = data.get("dest_ip", "")
                proto = data.get("proto", "")
                
                if src_ip and dest_ip:
                    network_info = f" | Traffic: {src_ip} -> {dest_ip} ({proto})"
                
                # Extract alert details if present
                if "alert" in data:
                    alert = data["alert"]
                    signature = alert.get("signature", "")
                    category = alert.get("category", "")
                    alert_severity = alert.get("severity", "")
                    
                    if signature:
                        network_info += f" | Signature: {signature}"
                    if category:
                        network_info += f" | Category: {category}"
            
            # Build comprehensive message
            message = f"Rule {rule_level}: {rule_description}"
            if rule_groups:
                message += f" | Groups: {', '.join(rule_groups)}"
            message += network_info
            
            return LogEntry(
                timestamp=timestamp,
                source=source,
                severity=severity,
                message=message,
                raw_log=line
            )
            
        except json.JSONDecodeError:
            logger.warning(f"Failed to parse JSON log: {line[:100]}...")
            return None
        except Exception as e:
            logger.error(f"Error parsing Wazuh log: {e}")
            return None
    
    @staticmethod
    def parse_syslog(line: str) -> Optional[LogEntry]:
        """Parse standard syslog format"""
        # Example: Jun 22 10:30:15 server01 sshd[1234]: Failed password for user from 192.168.1.100
        pattern = r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+):\s*(.*)'
        match = re.match(pattern, line)
        
        if match:
            timestamp, source, process, message = match.groups()
            severity = "INFO"  # Default, could be enhanced with severity detection
            
            # Determine severity based on keywords
            if any(keyword in message.lower() for keyword in ['failed', 'error', 'denied', 'invalid']):
                severity = "WARNING"
            if any(keyword in message.lower() for keyword in ['attack', 'intrusion', 'malware', 'breach']):
                severity = "CRITICAL"
                
            return LogEntry(
                timestamp=timestamp,
                source=source,
                severity=severity,
                message=message,
                raw_log=line
            )
        return None
    
    @staticmethod
    def parse_apache(line: str) -> Optional[LogEntry]:
        """Parse Apache access log format"""
        # Example: 192.168.1.100 - - [22/Jun/2024:10:30:15 +0000] "GET /admin HTTP/1.1" 401 -
        pattern = r'(\S+).*?\[(.*?)\]\s+"(\S+\s+\S+.*?)"\s+(\d+)'
        match = re.match(pattern, line)
        
        if match:
            ip, timestamp, request, status_code = match.groups()
            severity = "INFO"
            
            if int(status_code) >= 400:
                severity = "WARNING"
            if int(status_code) == 401 or int(status_code) == 403:
                severity = "WARNING"
                
            return LogEntry(
                timestamp=timestamp,
                source=f"web_server_{ip}",
                severity=severity,
                message=f"HTTP {status_code}: {request}",
                raw_log=line
            )
        return None
    
    @staticmethod
    def detect_format_and_parse(line: str) -> Optional[LogEntry]:
        """Auto-detect format and parse accordingly"""
        line = line.strip()
        
        # Try JSON format first (Wazuh/Suricata)
        if line.startswith('{') and line.endswith('}'):
            result = LogParser.parse_wazuh_suricata(line)
            if result:
                return result
        
        # Try Apache format
        if '[' in line and '"' in line and 'HTTP' in line:
            result = LogParser.parse_apache(line)
            if result:
                return result
        
        # Default to syslog
        return LogParser.parse_syslog(line)

class RealTimeHandler(FileSystemEventHandler):
    """Real-time handler for Wazuh logs with date-based file monitoring"""
    
    def __init__(self, llama_proc, analyzer=None, event_loop=None):
        super().__init__()
        self.llama = llama_proc
        self.analyzer = analyzer  # Optional LLM analyzer for enhanced analysis
        self.event_loop = event_loop  # Reference to main event loop
        os.makedirs(SUMMARY_DIR, exist_ok=True)
        self.reset_for_new_day()
    
    def reset_for_new_day(self):
        """Reset file monitoring for new day"""
        today = datetime.now(TZ_SG).date()
        month_folder = today.strftime("%Y-%m")
        self.current_dir = os.path.join(LOG_BASE_DIR, month_folder)
        self.current_file = os.path.join(
            self.current_dir,
            f"{LOG_PREFIX}{today.strftime('%Y-%m-%d')}{LOG_SUFFIX}"
        )
        # Simple per-day counter to keep filenames unique
        self.counter = 0
        
        # IMPORTANT: Start from end of existing file (tail -f behavior)
        if os.path.exists(self.current_file):
            try:
                with open(self.current_file, 'r') as f:
                    f.seek(0, 2)  # Seek to end of file
                    self.processed_bytes = f.tell()
                print(f"👀 Monitoring: {self.current_file} (starting from end, skipping {self.processed_bytes} existing bytes)")
            except Exception as e:
                logger.warning(f"Could not seek to end of {self.current_file}: {e}")
                self.processed_bytes = 0
        else:
            # New file, start from beginning
            self.processed_bytes = 0
            print(f"👀 Monitoring: {self.current_file} (new file)")
    
    def initialize_existing_file_position(self, file_path):
        """Initialize position for existing files to start from end"""
        if os.path.exists(file_path):
            try:
                with open(file_path, 'r') as f:
                    f.seek(0, 2)  # Seek to end
                    file_size = f.tell()
                    
                # Get line count for user info
                with open(file_path, 'r') as f:
                    line_count = sum(1 for _ in f)
                
                print(f"📄 Found existing file: {file_path}")
                print(f"   📊 Size: {file_size:,} bytes, ~{line_count:,} lines")
                print(f"   ⏭️  Starting from end (skipping existing logs)")
                
                return file_size
            except Exception as e:
                logger.warning(f"Could not check existing file {file_path}: {e}")
                return 0
        return 0
    
    def on_modified(self, event):
        """Handle file modification events for Wazuh logs"""
        if event.is_directory:
            return
        
        # Check if we need to reset for new day
        current_date = datetime.now(TZ_SG).date()
        expected_file = os.path.join(
            LOG_BASE_DIR,
            current_date.strftime("%Y-%m"),
            f"{LOG_PREFIX}{current_date.strftime('%Y-%m-%d')}{LOG_SUFFIX}"
        )
        
        if expected_file != self.current_file:
            self.reset_for_new_day()
        
        if os.path.normpath(event.src_path) != os.path.normpath(self.current_file):
            return
        
        # Read just the new bytes
        try:
            with open(self.current_file, 'r') as f:
                f.seek(self.processed_bytes)
                new_data = f.read()
                self.processed_bytes = f.tell()
            
            if not new_data.strip():
                return
            
            # Process with both original method and enhanced analysis
            if self.event_loop and self.event_loop.is_running():
                # Schedule async processing in the main event loop
                asyncio.run_coroutine_threadsafe(
                    self.process_new_data(new_data), 
                    self.event_loop
                )
            else:
                # Fallback to synchronous processing
                self.process_new_data_sync(new_data)
            
        except Exception as e:
            logger.error(f"Error processing file {self.current_file}: {e}")
    
    def process_new_data_sync(self, new_data):
        """Synchronous version of data processing for fallback"""
        try:
            # Original summary generation (synchronous)
            self.generate_summary_sync(new_data)
            
            # Enhanced analysis if analyzer is available (run in thread)
            if self.analyzer:
                import threading
                analysis_thread = threading.Thread(
                    target=self.enhanced_analysis_sync,
                    args=(new_data,)
                )
                analysis_thread.daemon = True
                analysis_thread.start()
        
        except Exception as e:
            logger.error(f"Error in synchronous data processing: {e}")
    
    async def process_new_data(self, new_data):
        """Process new log data with both summary generation and detailed analysis"""
        
        # Original summary generation
        await self.generate_summary(new_data)
        
        # Enhanced analysis if analyzer is available
        if self.analyzer:
            await self.enhanced_analysis(new_data)
    
    def generate_summary_sync(self, new_data):
        """Synchronous summary generation method"""
        try:
            # Build prompt for LLM
            payload = {
                "new_logs": new_data,
                "action": "summarize"
            }
            full_prompt = json.dumps(payload) + "\n/no_think\n"
            
            # Send to LLM process
            self.llama.stdin.write(full_prompt.encode())
            self.llama.stdin.flush()
            
            # Capture LLM reply until next '>' prompt
            summary_lines = []
            for line in iter(self.llama.stdout.readline, b''):
                line_str = line.decode().strip()
                if line_str.endswith(">"):
                    break
                summary_lines.append(line_str)
            
            new_summary = "\n".join(summary_lines).strip()
            # Increment counter and write to its own file
            self.counter += 1
            timestamp = datetime.now(TZ_SG).strftime("%H%M%S")
            summary_filename = (
                f"{LOG_PREFIX}{datetime.now(TZ_SG).strftime('%Y-%m-%d')}"
                f"_{timestamp}_{self.counter}.summary.log"
            )
            full_path = os.path.join(SUMMARY_DIR, summary_filename)
            
            with open(full_path, 'w') as out:
                out.write(new_summary + "\n")
            
            print(f"✅ Wrote summary payload #{self.counter} → {full_path}")
            
        except Exception as e:
            logger.error(f"Error generating summary: {e}")
    
    def enhanced_analysis_sync(self, new_data):
        """Synchronous enhanced analysis method"""
        try:
            # Split new data into individual log lines
            log_lines = [line.strip() for line in new_data.split('\n') if line.strip()]
            
            for line in log_lines:
                # Parse the log entry
                log_entry = LogParser.detect_format_and_parse(line)
                
                if log_entry:
                    # Run analysis in a new event loop
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                    try:
                        analysis = loop.run_until_complete(self.analyzer.analyze_log(log_entry))
                        
                        if analysis and analysis.threat_level in ['MEDIUM', 'HIGH', 'CRITICAL']:
                            # Save detailed analysis for significant threats
                            loop.run_until_complete(self.save_detailed_analysis(log_entry, analysis))
                    finally:
                        loop.close()
        
        except Exception as e:
            logger.error(f"Error in enhanced analysis: {e}")
    
    async def generate_summary(self, new_data):
        """Original summary generation method"""
        try:
            # Build prompt for LLM
            payload = {
                "new_logs": new_data,
                "action": "summarize"
            }
            full_prompt = json.dumps(payload) + "\n/no_think\n"
            
            # Send to LLM process
            self.llama.stdin.write(full_prompt.encode())
            self.llama.stdin.flush()
            
            # Capture LLM reply until next '>' prompt
            summary_lines = []
            for line in iter(self.llama.stdout.readline, b''):
                line_str = line.decode().strip()
                if line_str.endswith(">"):
                    break
                summary_lines.append(line_str)
            
            new_summary = "\n".join(summary_lines).strip()
            
            # Increment counter and write to its own file
            self.counter += 1
            timestamp = datetime.now(TZ_SG).strftime("%H%M%S")
            summary_filename = (
                f"{LOG_PREFIX}{datetime.now(TZ_SG).strftime('%Y-%m-%d')}"
                f"_{timestamp}_{self.counter}.summary.log"
            )
            full_path = os.path.join(SUMMARY_DIR, summary_filename)
            
            with open(full_path, 'w') as out:
                out.write(new_summary + "\n")
            
            print(f"✅ Wrote summary payload #{self.counter} → {full_path}")
            
        except Exception as e:
            logger.error(f"Error generating summary: {e}")
    
    async def enhanced_analysis(self, new_data):
        """Enhanced analysis using the detailed LLM analyzer"""
        try:
            # Split new data into individual log lines
            log_lines = [line.strip() for line in new_data.split('\n') if line.strip()]
            
            for line in log_lines:
                # Parse the log entry
                log_entry = LogParser.detect_format_and_parse(line)
                
                if log_entry:
                    # Analyze with enhanced LLM
                    analysis = await self.analyzer.analyze_log(log_entry)
                    
                    if analysis and analysis.threat_level in ['MEDIUM', 'HIGH', 'CRITICAL']:
                        # Save detailed analysis for significant threats
                        await self.save_detailed_analysis(log_entry, analysis)
        
        except Exception as e:
            logger.error(f"Error in enhanced analysis: {e}")
    
    async def save_detailed_analysis(self, log_entry: LogEntry, analysis: AnalysisResult):
        """Save detailed threat analysis"""
        try:
            timestamp = datetime.now(TZ_SG).strftime("%Y%m%d_%H%M%S")
            analysis_filename = f"threat_analysis_{timestamp}_{self.counter}.json"
            analysis_path = os.path.join(SUMMARY_DIR, analysis_filename)
            
            detailed_report = {
                'timestamp': datetime.now(TZ_SG).isoformat(),
                'log_entry': {
                    'timestamp': log_entry.timestamp,
                    'source': log_entry.source,
                    'severity': log_entry.severity,
                    'message': log_entry.message,
                    'raw_log': log_entry.raw_log
                },
                'analysis': {
                    'threat_level': analysis.threat_level,
                    'summary': analysis.summary,
                    'mitre_tactics': analysis.mitre_tactics,
                    'mitre_techniques': analysis.mitre_techniques,
                    'attack_stage': analysis.attack_stage,
                    'false_positive_likelihood': analysis.false_positive_likelihood,
                    'business_impact': analysis.business_impact,
                    'recommended_actions': analysis.recommended_actions,
                    'confidence': analysis.confidence
                },
                'analysis_type': 'real_time_enhanced'
            }
            
            with open(analysis_path, 'w') as f:
                json.dump(detailed_report, f, indent=2)
            
            # Also print immediate alert
            print(f"\n🚨 REAL-TIME THREAT ALERT - {analysis.threat_level} 🚨")
            print(f"Time: {log_entry.timestamp}")
            print(f"Source: {log_entry.source}")
            print(f"Summary: {analysis.summary}")
            print(f"Saved detailed analysis: {analysis_path}")
            print("-" * 60)
            
        except Exception as e:
            logger.error(f"Error saving detailed analysis: {e}")

class LogTailer(FileSystemEventHandler):
    """Monitor log files for new entries (general purpose)"""
    
    def __init__(self, analyzer: LlamaLLMAnalyzer, output_handler, event_loop=None):
        self.analyzer = analyzer
        self.output_handler = output_handler
        self.event_loop = event_loop
        self.file_positions = {}
        self.parsers = {
            'syslog': LogParser.parse_syslog,
            'apache': LogParser.parse_apache,
            'wazuh': LogParser.parse_wazuh_suricata,
        }
    
    def on_modified(self, event):
        """Handle file modification events"""
        if event.is_directory:
            return
            
        file_path = Path(event.src_path)
        if file_path.suffix in ['.log', '.txt'] or 'log' in file_path.name:
            if self.event_loop and self.event_loop.is_running():
                # Schedule async processing in the main event loop
                asyncio.run_coroutine_threadsafe(
                    self.process_new_lines(file_path), 
                    self.event_loop
                )
            else:
                # Fallback to synchronous processing
                self.process_new_lines_sync(file_path)
    
    def process_new_lines_sync(self, file_path: Path):
        """Synchronous version of line processing"""
        try:
            with open(file_path, 'r') as f:
                # Get current position or start from end for new files
                if str(file_path) not in self.file_positions:
                    f.seek(0, 2)  # Go to end of file
                    self.file_positions[str(file_path)] = f.tell()
                    return
                
                # Seek to last known position
                f.seek(self.file_positions[str(file_path)])
                
                new_lines = f.readlines()
                self.file_positions[str(file_path)] = f.tell()
                
                # Process each new line synchronously
                for line in new_lines:
                    line = line.strip()
                    if line:
                        self.process_log_line_sync(line, file_path)
                        
        except Exception as e:
            logger.error(f"Error processing file {file_path}: {e}")
    
    def process_log_line_sync(self, line: str, file_path: Path):
        """Synchronous version of log line processing"""
        try:
            # Use auto-detection parser for complex formats
            log_entry = LogParser.detect_format_and_parse(line)
            
            if log_entry:
                # Run analysis in a new event loop
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                try:
                    analysis = loop.run_until_complete(self.analyzer.analyze_log(log_entry))
                    if analysis:
                        loop.run_until_complete(self.output_handler(log_entry, analysis))
                finally:
                    loop.close()
        except Exception as e:
            logger.error(f"Error processing log line: {e}")
    
    async def process_new_lines(self, file_path: Path):
        """Process new lines added to log file"""
        try:
            with open(file_path, 'r') as f:
                # Get current position or start from end for new files
                if str(file_path) not in self.file_positions:
                    f.seek(0, 2)  # Go to end of file
                    self.file_positions[str(file_path)] = f.tell()
                    return
                
                # Seek to last known position
                f.seek(self.file_positions[str(file_path)])
                
                new_lines = f.readlines()
                self.file_positions[str(file_path)] = f.tell()
                
                # Process each new line
                for line in new_lines:
                    line = line.strip()
                    if line:
                        await self.process_log_line(line, file_path)
                        
        except Exception as e:
            logger.error(f"Error processing file {file_path}: {e}")
    
    async def process_log_line(self, line: str, file_path: Path):
        """Process a single log line"""
        # Use auto-detection parser for complex formats
        log_entry = LogParser.detect_format_and_parse(line)
        
        if log_entry:
            # Analyze with LLM
            analysis = await self.analyzer.analyze_log(log_entry)
            if analysis:
                await self.output_handler(log_entry, analysis)

class SOCReportGenerator:
    """Generate SOC reports and alerts"""
    
    def __init__(self, output_dir: str = "./soc_reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.alerts = []
    
    async def handle_analysis(self, log_entry: LogEntry, analysis: AnalysisResult):
        """Handle analysis results and generate appropriate outputs"""
        
        # Log the analysis
        logger.info(f"Analysis complete - Threat Level: {analysis.threat_level}, "
                   f"Confidence: {analysis.confidence:.2f}")
        
        # Create alert for medium+ threats
        if analysis.threat_level in ['MEDIUM', 'HIGH', 'CRITICAL']:
            alert = {
                'timestamp': datetime.now().isoformat(),
                'log_entry': log_entry.__dict__,
                'analysis': analysis.__dict__,
                'alert_id': f"ALR_{int(time.time())}"
            }
            
            self.alerts.append(alert)
            
            # Save immediate alert
            alert_file = self.output_dir / f"alert_{alert['alert_id']}.json"
            with open(alert_file, 'w') as f:
                json.dump(alert, f, indent=2)
            
            # Print to console for immediate attention
            print(f"\n🚨 SECURITY ALERT - {analysis.threat_level} 🚨")
            print(f"Time: {log_entry.timestamp}")
            print(f"Source: {log_entry.source}")
            print(f"Summary: {analysis.summary}")
            if analysis.mitre_tactics:
                print(f"MITRE Tactics: {', '.join(analysis.mitre_tactics)}")
            if analysis.recommended_actions:
                print("Recommended Actions:")
                for action in analysis.recommended_actions:
                    print(f"  • {action}")
            print(f"Confidence: {analysis.confidence:.2%}")
            print("-" * 60)
        
        # Generate daily summary reports
        await self.generate_daily_summary()
    
    async def generate_daily_summary(self):
        """Generate daily summary report"""
        today = datetime.now().strftime("%Y-%m-%d")
        today_alerts = [a for a in self.alerts if a['timestamp'].startswith(today)]
        
        if today_alerts:
            summary = {
                'date': today,
                'total_alerts': len(today_alerts),
                'threat_levels': {},
                'top_sources': {},
                'mitre_tactics': {},
                'alerts': today_alerts
            }
            
            # Aggregate statistics
            for alert in today_alerts:
                level = alert['analysis']['threat_level']
                source = alert['log_entry']['source']
                tactics = alert['analysis']['mitre_tactics']
                
                summary['threat_levels'][level] = summary['threat_levels'].get(level, 0) + 1
                summary['top_sources'][source] = summary['top_sources'].get(source, 0) + 1
                
                for tactic in tactics:
                    summary['mitre_tactics'][tactic] = summary['mitre_tactics'].get(tactic, 0) + 1
            
            # Save daily summary
            summary_file = self.output_dir / f"daily_summary_{today}.json"
            with open(summary_file, 'w') as f:
                json.dump(summary, f, indent=2)

async def main():
    """Main function to run the log analyzer with integrated Wazuh monitoring"""
    
    # Configuration
    LLAMA_BINARY = "/home/itp15student/Desktop/llama.cpp/build/bin/llama-cli"
    MODEL_PATH = "/home/itp15student/Desktop/Qwen3-8B-Q4_1.gguf"
    
    GENERAL_LOG_DIRECTORIES = [
        "/var/log"
    ]
    
    # Monitoring mode selection
    USE_WAZUH_MONITORING = True  # Set to True for Wazuh-specific monitoring
    USE_GENERAL_MONITORING = False  # Set to True for general log monitoring
    
    print("🔍 Starting Integrated SOC Log Analyzer with Local LLM")
    print(f"Model: {MODEL_PATH}")
    print(f"Wazuh Monitoring: {'Enabled' if USE_WAZUH_MONITORING else 'Disabled'}")
    print(f"General Monitoring: {'Enabled' if USE_GENERAL_MONITORING else 'Disabled'}")
    print(f"Tail Mode: {'Enabled (skip existing logs)' if START_FROM_TAIL else 'Disabled (process all logs)'}")
    
    # Get the current event loop
    current_loop = asyncio.get_running_loop()
    
    # Initialize components
    analyzer = LlamaLLMAnalyzer(MODEL_PATH, LLAMA_BINARY)
    report_generator = SOCReportGenerator()
    
    # Set up file system monitoring
    observer = Observer()
    
    # Wazuh-specific monitoring
    llama_proc = None
    wazuh_handler = None
    
    if USE_WAZUH_MONITORING:
        try:
            # Start persistent llama process for real-time summaries
            llama_cmd = [
                LLAMA_BINARY,
                "-m", MODEL_PATH,
                "-i",  # Interactive mode
                "--temp", "0.3",
                "-c", "4096"
            ]
            
            llama_proc = subprocess.Popen(
                llama_cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=False  # Use binary mode for better control
            )
            
            # Create Wazuh real-time handler with event loop reference
            wazuh_handler = RealTimeHandler(llama_proc, analyzer, current_loop)
            
            # Monitor the base log directory
            if os.path.exists(LOG_BASE_DIR):
                observer.schedule(wazuh_handler, LOG_BASE_DIR, recursive=True)
                print(f"✅ Wazuh monitoring: {LOG_BASE_DIR}")
                print(f"✅ Summaries will be saved to: {SUMMARY_DIR}")
            else:
                print(f"⚠️  Wazuh directory not found: {LOG_BASE_DIR}")
                USE_WAZUH_MONITORING = False
        
        except Exception as e:
            logger.error(f"Failed to start Wazuh monitoring: {e}")
            USE_WAZUH_MONITORING = False
    
    # General log monitoring
    if USE_GENERAL_MONITORING:
        # Create general log tailer with event loop reference
        general_tailer = LogTailer(analyzer, report_generator.handle_analysis, current_loop)
        
        for log_dir in GENERAL_LOG_DIRECTORIES:
            if Path(log_dir).exists():
                observer.schedule(general_tailer, log_dir, recursive=True)
                print(f"✅ General monitoring: {log_dir}")
            else:
                print(f"⚠️  Directory not found: {log_dir}")
    
    if not USE_WAZUH_MONITORING and not USE_GENERAL_MONITORING:
        print("❌ No monitoring enabled. Please check configuration.")
        return
    
    observer.start()
    print("\n🚀 Integrated log analyzer is running. Press Ctrl+C to stop.")
    print("\nMonitoring capabilities:")
    if USE_WAZUH_MONITORING:
        print("  📊 Wazuh logs: Real-time summaries + detailed threat analysis")
        print("  📁 Summary location: " + SUMMARY_DIR)
    if USE_GENERAL_MONITORING:
        print("  📋 General logs: Detailed threat analysis + SOC reports")
        print("  📁 Reports location: ./soc_reports/")
    
    if START_FROM_TAIL:
        print("\n⏭️  TAIL MODE: Only processing NEW log entries (like tail -f)")
        print("   📄 Existing logs will be skipped to avoid processing thousands of old entries")
        print("   🔄 To process existing logs, set START_FROM_TAIL = False in configuration")
    else:
        print("\n📄 FULL MODE: Processing ALL log entries including existing ones")
        print("   ⚠️  This may take time if there are many existing logs")
    
    print()
    
    try:
        while True:
            await asyncio.sleep(1)
            
            # Check if we need to reset for new day (Wazuh monitoring)
            if USE_WAZUH_MONITORING and wazuh_handler:
                current_time = datetime.now(TZ_SG)
                if current_time.hour == 0 and current_time.minute == 0:
                    wazuh_handler.reset_for_new_day()
                    print("🔄 Reset monitoring for new day")
    
    except KeyboardInterrupt:
        print("\n🛑 Stopping log analyzer...")
        observer.stop()
        
        # Clean up llama process if running
        if llama_proc:
            try:
                llama_proc.terminate()
                llama_proc.wait(timeout=5)
                print("✅ Llama process terminated")
            except:
                llama_proc.kill()
                print("✅ Llama process killed")
    
    observer.join()
    print("✅ Log analyzer stopped.")

if __name__ == "__main__":
    # Install required packages if needed
    required_packages = ["watchdog", "pytz"]
    
    for package in required_packages:
        try:
            __import__(package)
        except ImportError:
            print(f"Installing required package: {package}")
            subprocess.run(["pip", "install", package], check=True)
    
    # Import after potential installation
    import pytz
    
    asyncio.run(main())