#!/usr/bin/env python3
"""
Real-time Log Analysis with Local LLM using Jinja Templates and Qwen Chat Format
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
from dataclasses import dataclass, asdict
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import pytz
from jinja2 import Environment, FileSystemLoader

# ——— CONFIGURATION ———
CONFIG_FILE = "config.json"
DEFAULT_CONFIG = {
    "llm_settings": {
        "model_path": "/home/itp15student/Desktop/Qwen3-8B-Q4_1.gguf",
        "llama_binary": "/home/itp15student/Desktop/llama.cpp/build/bin/llama-cli",
        "temperature": 0.7,
        "top_p": 0.8,
        "top_k": 20,
        "min_p": 0,
        "context_size": 4096,
        "max_tokens": 2000,
        "chat_template_kwargs": {"enable_thinking": "false"}
    },  
    "monitoring": {
        "wazuh_enabled": True,
        "general_enabled": False,
        "start_from_tail": True
    },
    "paths": {
        "log_base_dir": "/var/log/wazuh_syslog",
        "summary_dir": "/home/itp15student/Desktop/ICT2114_Team15/Linux_LLM/summary",
        "templates_dir": "./templates",
        "reports_dir": "./soc_reports"
    },
    "log_format": {
        "prefix": "wazuh-",
        "suffix": ".log"
    },
    "analysis": {
        "context_window_size": 5,
        "alert_threshold_levels": ["MEDIUM", "HIGH", "CRITICAL"],
        "confidence_threshold": 0.7
    },
  "file_output": {
        "min_file_size_bytes": 50,  # Don't write files smaller than 50 bytes
        "min_summary_length": 20    # Don't write summaries shorter than 20 chars
    },
    "timezone": "Asia/Singapore"
    
}

# Global configuration
config = DEFAULT_CONFIG

# Configure logging - prevent \n spam
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
    indicators: List[str] = None
    context_notes: str = None

class ConfigManager:
    """Manages configuration loading"""
    
    @staticmethod
    def load_config() -> Dict:
        """Load configuration from JSON file"""
        global config
        
        if Path(CONFIG_FILE).exists():
            try:
                with open(CONFIG_FILE, 'r') as f:
                    loaded_config = json.load(f)
                config = {**DEFAULT_CONFIG, **loaded_config}
                logger.info(f"Configuration loaded from {CONFIG_FILE}")
                return config
            except Exception as e:
                logger.warning(f"Failed to load config: {e}. Using defaults.")
        
        config = DEFAULT_CONFIG
        logger.info("Using default configuration")
        return config

class TemplateManager:
    """Manages Jinja2 templates for prompts, reports, and alerts"""
    
    def __init__(self, templates_dir: str = None):
        self.templates_dir = Path(templates_dir or config["paths"]["templates_dir"])
        
        if not self.templates_dir.exists():
            logger.error(f"Templates directory not found: {self.templates_dir}")
            logger.error("Please run setup_templates.py first to create template files")
            raise FileNotFoundError(f"Templates directory missing: {self.templates_dir}")
        
        # Initialize Jinja environment
        self.env = Environment(
            loader=FileSystemLoader(self.templates_dir),
            trim_blocks=True,
            lstrip_blocks=True
        )
        
        # Custom filters
        self.env.filters['wordwrap'] = self._wordwrap_filter
        self.env.filters['truncate'] = self._truncate_filter
        self.env.filters['indent'] = self._indent_filter
    
    def _wordwrap_filter(self, text, width=70):
        """Word wrap filter"""
        import textwrap
        return '\n'.join(textwrap.wrap(str(text), width=width))
    
    def _truncate_filter(self, text, length=100):
        """Truncate filter"""
        text = str(text)
        return text[:length] + '...' if len(text) > length else text
    
    def _indent_filter(self, text, spaces=4):
        """Indent filter"""
        indent = ' ' * spaces
        return '\n'.join(indent + line for line in str(text).split('\n'))
    
    def render_security_analysis_prompt(self, log_entry: LogEntry, context: List[LogEntry], **kwargs) -> str:
        """Render security analysis prompt"""
        template = self.env.get_template('security_analysis_prompt.j2')
        return template.render(
            log_entry=log_entry,
            context=context[-3:],
            **kwargs
        )
    
    def render_general_analysis_prompt(self, log_entry: LogEntry, context: List[LogEntry], **kwargs) -> str:
        """Render general analysis prompt"""
        template = self.env.get_template('general_analysis_prompt.j2')
        return template.render(
            log_entry=log_entry,
            context=context[-3:],
            **kwargs
        )
    
    def render_alert_output(self, log_entry: LogEntry, analysis: AnalysisResult, 
                           alert_type: str = "SECURITY", file_path: str = None) -> str:
        """Render alert console output"""
        template = self.env.get_template('alert_console.j2')
        return template.render(
            log_entry=log_entry,
            analysis=analysis,
            alert_type=alert_type,
            file_path=file_path
        )
    
    def render_daily_summary(self, date: str, alerts: List[Dict], **kwargs) -> str:
        """Render daily summary report"""
        template = self.env.get_template('daily_summary.j2')
        
        # Calculate statistics
        total_alerts = len(alerts)
        threat_levels = {}
        top_sources = {}
        mitre_tactics = {}
        high_priority_alerts = []
        
        for alert in alerts:
            level = alert['analysis']['threat_level']
            source = alert['log_entry']['source']
            tactics = alert['analysis'].get('mitre_tactics', [])
            
            threat_levels[level] = threat_levels.get(level, 0) + 1
            top_sources[source] = top_sources.get(source, 0) + 1
            
            for tactic in tactics:
                mitre_tactics[tactic] = mitre_tactics.get(tactic, 0) + 1
            
            if level in ['HIGH', 'CRITICAL']:
                high_priority_alerts.append(alert)
        
        return template.render(
            date=date,
            total_alerts=total_alerts,
            threat_levels=threat_levels,
            top_sources=top_sources,
            mitre_tactics=mitre_tactics,
            high_priority_alerts=high_priority_alerts[:10],
            generation_time=datetime.now().isoformat(),
            **kwargs
        )
    
    def format_qwen_prompt(self, user_message: str, system_message: str = None) -> str:
        """Format prompt using Qwen chat template"""
        try:
            template = self.env.get_template('qwen_chat.j2')
            
            messages = []
            if system_message:
                messages.append({"role": "system", "content": system_message})
            messages.append({"role": "user", "content": user_message})
            
            return template.render(
                messages=messages,
                add_generation_prompt=True,
                enable_thinking=False,
                chat_template_kwargs={"enable_thinking": False}
            )
        except Exception as e:
            logger.error(f"Error formatting Qwen prompt: {e}")
            # Fallback to simple format
            if system_message:
                return f"<|im_start|>system\n{system_message}<|im_end|>\n<|im_start|>user\n{user_message}<|im_end|>\n<|im_start|>assistant\n"
            else:
                return f"<|im_start|>user\n{user_message}<|im_end|>\n<|im_start|>assistant\n"

class LlamaLLMAnalyzer:
    """Interface to local Llama LLM for log analysis with Jinja templates and Qwen formatting"""
    
    def __init__(self, template_manager: TemplateManager):
        self.llm_config = config["llm_settings"]
        self.template_manager = template_manager
        self.context_window = []
        self.max_context = config["analysis"]["context_window_size"]
        
    def _create_analysis_prompt(self, log_entry: LogEntry, context: List[LogEntry]) -> str:
        """Create analysis prompt using templates and Qwen format"""
        
        # Check if this is a security alert
        is_security_alert = any(keyword in log_entry.message.lower() for keyword in 
                              ['alert', 'exploit', 'cve', 'malware', 'intrusion', 'attack'])
        
        if is_security_alert:
            user_prompt = self.template_manager.render_security_analysis_prompt(
                log_entry=log_entry,
                context=context,
                false_positive_likelihood=0.2,
                confidence=0.85
            )
        else:
            user_prompt = self.template_manager.render_general_analysis_prompt(
                log_entry=log_entry,
                context=context,
                confidence=0.75
            )
        
        return self.template_manager.format_qwen_prompt(user_prompt)
    
    async def analyze_log(self, log_entry: LogEntry) -> Optional[AnalysisResult]:
        """Analyze log entry using local LLM with Qwen formatting"""
        try:
            prompt = self._create_analysis_prompt(log_entry, self.context_window)
            
            cmd = [
                self.llm_config["llama_binary"],
                "-m", self.llm_config["model_path"],
                "-p", prompt,
                "-n", str(self.llm_config["max_tokens"]),
                "--temp", str(self.llm_config["temperature"]),
                "--top-p", str(self.llm_config["top_p"]),
                "--top-k", str(self.llm_config["top_k"]),
                "--min-p", str(self.llm_config["min_p"]),
                "-c", str(self.llm_config["context_size"]),
                "--no-cnv"
            ]
            
            logger.info(f"Analyzing log from {log_entry.source}")
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                logger.error(f"LLM analysis failed: {stderr.decode().strip()}")
                return None
            
            response = stdout.decode().strip()
            
            # Extract JSON from response
            json_match = re.search(r'```json\s*(\{.*?\})\s*```', response, re.DOTALL)
            if not json_match:
                json_match = re.search(r'\{.*\}', response, re.DOTALL)
            
            if json_match:
                try:
                    json_text = json_match.group(1) if json_match.group(0).startswith('```') else json_match.group(0)
                    analysis_data = json.loads(json_text)
                    
                    result = AnalysisResult(
                        threat_level=analysis_data.get("threat_level", "LOW"),
                        summary=analysis_data.get("summary", "No analysis available"),
                        mitre_tactics=analysis_data.get("mitre_tactics", []),
                        mitre_techniques=analysis_data.get("mitre_techniques", []),
                        attack_stage=analysis_data.get("attack_stage"),
                        false_positive_likelihood=analysis_data.get("false_positive_likelihood"),
                        business_impact=analysis_data.get("business_impact"),
                        recommended_actions=analysis_data.get("recommended_actions", []),
                        confidence=analysis_data.get("confidence", 0.0),
                        indicators=analysis_data.get("indicators", []),
                        context_notes=analysis_data.get("context_notes")
                    )
                    
                    # Update context window
                    self.context_window.append(log_entry)
                    if len(self.context_window) > self.max_context:
                        self.context_window.pop(0)
                    
                    return result
                except json.JSONDecodeError as e:
                    logger.warning(f"JSON parse error: {str(e)}")
                    return None
            else:
                logger.warning("No JSON found in LLM response")
                return None
                
        except Exception as e:
            logger.error(f"Analysis error: {str(e)}")
            return None

class LogParser:
    """Parse different log formats"""
    
    @staticmethod
    def parse_wazuh_suricata(line: str) -> Optional[LogEntry]:
        """Parse Wazuh/Suricata JSON format"""
        try:
            log_data = json.loads(line)
            
            timestamp = log_data.get("timestamp", "")
            
            agent_info = log_data.get("agent", {})
            agent_name = agent_info.get("name", "unknown")
            agent_ip = agent_info.get("ip", "unknown")
            source = f"{agent_name}({agent_ip})"
            
            rule_info = log_data.get("rule", {})
            rule_level = rule_info.get("level", 0)
            rule_description = rule_info.get("description", "No description")
            rule_groups = rule_info.get("groups", [])
            
            # Map rule level to severity
            if rule_level >= 13:
                severity = "CRITICAL"
            elif rule_level >= 10:
                severity = "HIGH"
            elif rule_level >= 7:
                severity = "MEDIUM"
            elif rule_level >= 4:
                severity = "LOW"
            else:
                severity = "INFO"
            
            # Extract network data
            network_info = ""
            if "data" in log_data:
                data = log_data["data"]
                src_ip = data.get("src_ip", "")
                dest_ip = data.get("dest_ip", "")
                proto = data.get("proto", "")
                
                if src_ip and dest_ip:
                    network_info = f" | Traffic: {src_ip} -> {dest_ip} ({proto})"
                
                if "alert" in data:
                    alert = data["alert"]
                    signature = alert.get("signature", "")
                    category = alert.get("category", "")
                    
                    if signature:
                        network_info += f" | Signature: {signature}"
                    if category:
                        network_info += f" | Category: {category}"
            
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
            return None
        except Exception as e:
            logger.error(f"Wazuh parse error: {str(e)}")
            return None
    
    @staticmethod
    def parse_syslog(line: str) -> Optional[LogEntry]:
        """Parse standard syslog format"""
        pattern = r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+):\s*(.*)'
        match = re.match(pattern, line)
        
        if match:
            timestamp, source, process, message = match.groups()
            severity = "INFO"
            
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
        pattern = r'(\S+).*?\[(.*?)\]\s+"(\S+\s+\S+.*?)"\s+(\d+)'
        match = re.match(pattern, line)
        
        if match:
            ip, timestamp, request, status_code = match.groups()
            severity = "INFO"
            
            if int(status_code) >= 400:
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
        """Auto-detect format and parse"""
        line = line.strip()
        
        if line.startswith('{') and line.endswith('}'):
            result = LogParser.parse_wazuh_suricata(line)
            if result:
                return result
        
        if '[' in line and '"' in line and 'HTTP' in line:
            result = LogParser.parse_apache(line)
            if result:
                return result
        
        return LogParser.parse_syslog(line)

class RealTimeHandler(FileSystemEventHandler):
    """Real-time handler for Wazuh logs with enhanced analysis"""
    
    def __init__(self, llama_proc, analyzer=None, event_loop=None, template_manager=None):
        super().__init__()
        self.llama = llama_proc
        self.analyzer = analyzer
        self.event_loop = event_loop
        self.template_manager = template_manager
        os.makedirs(config["paths"]["summary_dir"], exist_ok=True)
        self.reset_for_new_day()
    
    def reset_for_new_day(self):
        """Reset file monitoring for new day"""
        TZ_SG = pytz.timezone(config["timezone"])
        today = datetime.now(TZ_SG).date()
        month_folder = today.strftime("%Y-%m")
        self.current_dir = os.path.join(config["paths"]["log_base_dir"], month_folder)
        self.current_file = os.path.join(
            self.current_dir,
            f"{config['log_format']['prefix']}{today.strftime('%Y-%m-%d')}{config['log_format']['suffix']}"
        )
        self.counter = 0
        
        if os.path.exists(self.current_file):
            try:
                with open(self.current_file, 'r') as f:
                    f.seek(0, 2)
                    self.processed_bytes = f.tell()
                logger.info(f"Monitoring: {self.current_file} (from end, skipping {self.processed_bytes} bytes)")
            except Exception as e:
                logger.warning(f"Could not seek to end: {str(e)}")
                self.processed_bytes = 0
        else:
            self.processed_bytes = 0
            logger.info(f"Monitoring: {self.current_file} (new file)")
    
    def on_modified(self, event):
        """Handle file modification events"""
        if event.is_directory:
            return
        
        # Check if we need to reset for new day
        TZ_SG = pytz.timezone(config["timezone"])
        current_date = datetime.now(TZ_SG).date()
        expected_file = os.path.join(
            config["paths"]["log_base_dir"],
            current_date.strftime("%Y-%m"),
            f"{config['log_format']['prefix']}{current_date.strftime('%Y-%m-%d')}{config['log_format']['suffix']}"
        )
        
        if expected_file != self.current_file:
            self.reset_for_new_day()
        
        if os.path.normpath(event.src_path) != os.path.normpath(self.current_file):
            return
        
        try:
            with open(self.current_file, 'r') as f:
                f.seek(self.processed_bytes)
                new_data = f.read()
                self.processed_bytes = f.tell()
            
            if not new_data.strip():
                return
            
            if self.event_loop and self.event_loop.is_running():
                asyncio.run_coroutine_threadsafe(
                    self.process_new_data(new_data), 
                    self.event_loop
                )
            else:
                self.process_new_data_sync(new_data)
            
        except Exception as e:
            logger.error(f"File processing error: {str(e)}")
    
    def process_new_data_sync(self, new_data):
        """Synchronous processing fallback"""
        try:
            self.generate_summary_sync(new_data)
            
            if self.analyzer:
                import threading
                analysis_thread = threading.Thread(
                    target=self.enhanced_analysis_sync,
                    args=(new_data,)
                )
                analysis_thread.daemon = True
                analysis_thread.start()
        except Exception as e:
            logger.error(f"Sync processing error: {str(e)}")
    
    async def process_new_data(self, new_data):
        """Process new log data"""
        await self.generate_summary(new_data)
        
        if self.analyzer:
            await self.enhanced_analysis(new_data)
    
    def generate_summary_sync(self, new_data):
        """Generate summary using original LLM process"""
        try:
            payload = {
                "new_logs": new_data,
                "action": "summarize"
            }
            full_prompt = json.dumps(payload) + "\n/no_think\n"
            
            self.llama.stdin.write(full_prompt.encode())
            self.llama.stdin.flush()
            
            summary_lines = []
            for line in iter(self.llama.stdout.readline, b''):
                line_str = line.decode().strip()
                if line_str.endswith(">"):
                    break
                if line_str:  # Prevent empty line spam
                    summary_lines.append(line_str)
            
            new_summary = "\n".join(summary_lines).strip()
            if not new_summary or len(new_summary) < config.get("file_output", {}).get("min_summary_length", 20):
                logger.debug(f"Skipping small summary: {len(new_summary)} chars")
                return  
                
            self.counter += 1
            TZ_SG = pytz.timezone(config["timezone"])
            timestamp = datetime.now(TZ_SG).strftime("%H%M%S")
            summary_filename = (
                f"{config['log_format']['prefix']}{datetime.now(TZ_SG).strftime('%Y-%m-%d')}"
                f"_{timestamp}_{self.counter}.summary.log"
            )
            full_path = os.path.join(config["paths"]["summary_dir"], summary_filename)
            if len(new_summary.encode('utf-8')) < config.get("file_output", {}).get("min_file_size_bytes", 50):
                logger.debug(f"Skipping small file: {len(new_summary.encode('utf-8'))} bytes")
                return
            with open(full_path, 'w') as out:
                out.write(new_summary + "\n")
            
            print(f"✅ Summary #{self.counter} → {full_path}")
            
        except Exception as e:
            logger.error(f"Summary generation error: {str(e)}")
    
    async def generate_summary(self, new_data):
        """Async summary generation"""
        try:
            payload = {
                "new_logs": new_data,
                "action": "summarize"
            }
            full_prompt = json.dumps(payload) + "\n/no_think\n"
            
            self.llama.stdin.write(full_prompt.encode())
            self.llama.stdin.flush()
            
            summary_lines = []
            for line in iter(self.llama.stdout.readline, b''):
                line_str = line.decode().strip()
                if line_str.endswith(">"):
                    break
                if line_str:
                    summary_lines.append(line_str)
            
            new_summary = "\n".join(summary_lines).strip()
            if not new_summary or len(new_summary) < config.get("file_output", {}).get("min_summary_length", 20):
                logger.debug(f"Skipping small summary: {len(new_summary)} chars")
                return
            self.counter += 1
            TZ_SG = pytz.timezone(config["timezone"])
            timestamp = datetime.now(TZ_SG).strftime("%H%M%S")
            summary_filename = (
                f"{config['log_format']['prefix']}{datetime.now(TZ_SG).strftime('%Y-%m-%d')}"
                f"_{timestamp}_{self.counter}.summary.log"
            )
            full_path = os.path.join(config["paths"]["summary_dir"], summary_filename)
            if len(new_summary.encode('utf-8')) < config.get("file_output", {}).get("min_file_size_bytes", 50):
                logger.debug(f"Skipping small file: {len(new_summary.encode('utf-8'))} bytes")
                return
            with open(full_path, 'w') as out:
                out.write(new_summary + "\n")
            
            print(f"✅ Summary #{self.counter} → {full_path}")
            
        except Exception as e:
            logger.error(f"Summary error: {str(e)}")
    
    def enhanced_analysis_sync(self, new_data):
        """Enhanced analysis (sync)"""
        try:
            log_lines = [line.strip() for line in new_data.split('\n') if line.strip()]
            
            for line in log_lines:
                log_entry = LogParser.detect_format_and_parse(line)
                
                if log_entry:
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                    try:
                        analysis = loop.run_until_complete(self.analyzer.analyze_log(log_entry))
                        
                        if analysis and analysis.threat_level in config["analysis"]["alert_threshold_levels"]:
                            loop.run_until_complete(self.save_detailed_analysis(log_entry, analysis))
                    finally:
                        loop.close()
        except Exception as e:
            logger.error(f"Enhanced analysis error: {str(e)}")
    
    async def enhanced_analysis(self, new_data):
        """Enhanced analysis using LLM analyzer"""
        try:
            log_lines = [line.strip() for line in new_data.split('\n') if line.strip()]
            
            for line in log_lines:
                log_entry = LogParser.detect_format_and_parse(line)
                
                if log_entry:
                    analysis = await self.analyzer.analyze_log(log_entry)
                    
                    if analysis and analysis.threat_level in config["analysis"]["alert_threshold_levels"]:
                        await self.save_detailed_analysis(log_entry, analysis)
        except Exception as e:
            logger.error(f"Enhanced analysis error: {str(e)}")
    
    async def save_detailed_analysis(self, log_entry: LogEntry, analysis: AnalysisResult):
        """Save detailed threat analysis"""
        try:
            TZ_SG = pytz.timezone(config["timezone"])
            timestamp = datetime.now(TZ_SG).strftime("%Y%m%d_%H%M%S")
            analysis_filename = f"threat_analysis_{timestamp}_{self.counter}.json"
            analysis_path = os.path.join(config["paths"]["summary_dir"], analysis_filename)
            
            detailed_report = {
                'timestamp': datetime.now(TZ_SG).isoformat(),
                'log_entry': asdict(log_entry),
                'analysis': asdict(analysis),
                'analysis_type': 'real_time_enhanced'
            }
            
            with open(analysis_path, 'w') as f:
                json.dump(detailed_report, f, indent=2)
            
            # Use template for console output
            if self.template_manager:
                alert_output = self.template_manager.render_alert_output(
                    log_entry=log_entry,
                    analysis=analysis,
                    alert_type="REAL-TIME THREAT",
                    file_path=analysis_path
                )
                print(alert_output)
            else:
                print(f"\n🚨 THREAT ALERT - {analysis.threat_level} 🚨")
                print(f"Time: {log_entry.timestamp}")
                print(f"Source: {log_entry.source}")
                print(f"Summary: {analysis.summary}")
                print(f"Analysis saved: {analysis_path}")
                print("-" * 60)
            
        except Exception as e:
            logger.error(f"Analysis save error: {str(e)}")

class SOCReportGenerator:
    """Generate SOC reports using templates"""
    
    def __init__(self, template_manager: TemplateManager):
        self.output_dir = Path(config["paths"]["reports_dir"])
        self.output_dir.mkdir(exist_ok=True)
        self.alerts = []
        self.template_manager = template_manager
    
    async def handle_analysis(self, log_entry: LogEntry, analysis: AnalysisResult):
        """Handle analysis results"""
        logger.info(f"Analysis: {analysis.threat_level}, Confidence: {analysis.confidence:.2f}")
        
        if analysis.threat_level in config["analysis"]["alert_threshold_levels"]:
            alert = {
                'timestamp': datetime.now().isoformat(),
                'log_entry': asdict(log_entry),
                'analysis': asdict(analysis),
                'alert_id': f"ALR_{int(time.time())}"
            }
            
            self.alerts.append(alert)
            
            alert_file = self.output_dir / f"alert_{alert['alert_id']}.json"
            with open(alert_file, 'w') as f:
                json.dump(alert, f, indent=2)
            
            alert_output = self.template_manager.render_alert_output(
                log_entry=log_entry,
                analysis=analysis,
                alert_type="SECURITY",
                file_path=str(alert_file)
            )
            
            print(alert_output)
        
        await self.generate_daily_summary()
    
    async def generate_daily_summary(self):
        """Generate daily summary using templates"""
        today = datetime.now().strftime("%Y-%m-%d")
        today_alerts = [a for a in self.alerts if a['timestamp'].startswith(today)]
        
        if today_alerts:
            summary_markdown = self.template_manager.render_daily_summary(
                date=today,
                alerts=today_alerts
            )
            
            summary_file = self.output_dir / f"daily_summary_{today}.md"
            with open(summary_file, 'w') as f:
                f.write(summary_markdown)
            
            summary_json = {
                'date': today,
                'total_alerts': len(today_alerts),
                'alerts': today_alerts,
                'generated_at': datetime.now().isoformat()
            }
            
            json_file = self.output_dir / f"daily_summary_{today}.json"
            with open(json_file, 'w') as f:
                json.dump(summary_json, f, indent=2)

async def main():
    """Main function"""
    
    # Load configuration
    global config
    config = ConfigManager.load_config()
    
    print("🔍 SOC Log Analyzer with Qwen Templates & Custom Parameters")
    print(f"Model: {config['llm_settings']['model_path']}")
    print(f"LLM Parameters: T={config['llm_settings']['temperature']}, "
          f"P={config['llm_settings']['top_p']}, K={config['llm_settings']['top_k']}, "
          f"MinP={config['llm_settings']['min_p']}")
    
    # Get event loop
    current_loop = asyncio.get_running_loop()
    
    # Initialize template manager
    try:
        template_manager = TemplateManager()
    except FileNotFoundError:
        print("❌ Templates not found. Please run: python setup_templates.py")
        return
    
    # Initialize components
    analyzer = LlamaLLMAnalyzer(template_manager)
    report_generator = SOCReportGenerator(template_manager)
    
    # Set up monitoring
    observer = Observer()
    
    if config["monitoring"]["wazuh_enabled"]:
        try:
            # Start persistent llama process
            llama_cmd = [
                config["llm_settings"]["llama_binary"],
                "-m", config["llm_settings"]["model_path"],
                "-i",
                "--temp", str(config["llm_settings"]["temperature"]),
                "-c", str(config["llm_settings"]["context_size"])
            ]
            
            llama_proc = subprocess.Popen(
                llama_cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=False
            )
            
            wazuh_handler = RealTimeHandler(llama_proc, analyzer, current_loop, template_manager)
            
            if os.path.exists(config["paths"]["log_base_dir"]):
                observer.schedule(wazuh_handler, config["paths"]["log_base_dir"], recursive=True)
                print(f"✅ Wazuh monitoring: {config['paths']['log_base_dir']}")
                print(f"✅ Summaries: {config['paths']['summary_dir']}")
            else:
                print(f"⚠️  Wazuh directory not found: {config['paths']['log_base_dir']}")
                return
        
        except Exception as e:
            logger.error(f"Failed to start Wazuh monitoring: {str(e)}")
            return
    
    observer.start()
    print(f"\n🚀 SOC analyzer running with Jinja templates!")
    print(f"📁 Templates: {config['paths']['templates_dir']}")
    print(f"📊 Reports: {config['paths']['reports_dir']}")
    
    try:
        while True:
            await asyncio.sleep(1)
            
            # Check for new day reset
            if config["monitoring"]["wazuh_enabled"]:
                TZ_SG = pytz.timezone(config["timezone"])
                current_time = datetime.now(TZ_SG)
                if current_time.hour == 0 and current_time.minute == 0:
                    wazuh_handler.reset_for_new_day()
                    logger.info("Reset monitoring for new day")
    
    except KeyboardInterrupt:
        print("\n🛑 Stopping analyzer...")
        observer.stop()
        
        if 'llama_proc' in locals():
            try:
                llama_proc.terminate()
                llama_proc.wait(timeout=5)
                logger.info("Llama process terminated")
            except:
                llama_proc.kill()
                logger.info("Llama process killed")
    
    observer.join()
    print("✅ Analyzer stopped.")

if __name__ == "__main__":
    # Install required packages
    required_packages = ["watchdog", "pytz", "jinja2"]
    
    for package in required_packages:
        try:
            __import__(package)
        except ImportError:
            print(f"Installing: {package}")
            subprocess.run(["pip", "install", package], check=True)
    
    asyncio.run(main())