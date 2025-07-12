import json
import os
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional
from jinja2 import Template
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain_community.vectorstores import FAISS
from langchain_huggingface import HuggingFaceEmbeddings
from langchain.schema import Document


class ChatTemplateManager:
    """Manages chat templates for LLM formatting"""
    
    def __init__(self, templates_dir: str):
        self.templates_dir = Path(templates_dir)
        self.chat_template = self._load_chat_template()
    
    def _load_chat_template(self) -> str:
        """Load Qwen chat template"""
        template_path = self.templates_dir / "qwen_chat.j2"
        if template_path.exists():
            try:
                with open(template_path, 'r') as f:
                    return f.read()
            except Exception as e:
                print(f"⚠️ Error loading chat template: {e}")
        else:
            print(f"⚠️ Chat template not found: {template_path}")
        return ""
    
    def format_messages(self, system_prompt: str, user_message: str) -> str:
        """Format messages using Qwen chat template"""
        if self.chat_template:
            try:
                template = Template(self.chat_template)
                messages = [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_message}
                ]
                return template.render(
                    messages=messages, 
                    add_generation_prompt=True, 
                    enable_thinking=False
                )
            except Exception as e:
                print(f"⚠️ Template formatting error: {e}")
        
        # Fallback format
        return f"<|im_start|>system\n{system_prompt}<|im_end|>\n<|im_start|>user\n{user_message}<|im_end|>\n<|im_start|>assistant\n"


class LlamaModelClient:
    """Handles LLM model inference using llama.cpp"""
    
    def __init__(self, model_path: str, llama_cpp_path: str, template_manager: ChatTemplateManager):
        self.model_path = model_path
        self.llama_cpp_path = llama_cpp_path
        self.template_manager = template_manager
    
    def generate_response(self, system_prompt: str, user_message: str) -> str:
        """Generate response using llama.cpp"""
        try:
            formatted_prompt = self.template_manager.format_messages(system_prompt, user_message)
            
            # Create temporary file for prompt
            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as temp_file:
                temp_file.write(formatted_prompt)
                temp_file_path = temp_file.name
            
            # Build command
            cmd = [
                self.llama_cpp_path,
                "-m", self.model_path,
                "-f", temp_file_path,
                "--temp", "0.7",
                "--top-p", "0.95", 
                "--top-k", "64",
                "-c", "8192",
                "-n", "4096",
                "--no-display-prompt",
                "--single-turn",
                "--jinja"
            ]
            
            # Execute model
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
                
                # Cleanup temp file
                try:
                    os.unlink(temp_file_path)
                except:
                    pass
                
                if process.returncode != 0:
                    print(f"❌ Llama.cpp error (return code {process.returncode})")
                    if stderr:
                        print(f"❌ Stderr: {stderr}")
                    return f"Error: Command failed with return code {process.returncode}"
                
                # Clean response
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


class RAGContextManager:
    """Manages RAG context including vector store and embeddings"""
    
    def __init__(self):
        self.embeddings = HuggingFaceEmbeddings(
            model_name="all-MiniLM-L6-v2",
            model_kwargs={'device': 'cpu'},
            encode_kwargs={'normalize_embeddings': False}
        )
        self.vectorstore = None
        self.rag_ready = False
        self.archive_logs = []
        self.custom_docs = []
    
    def add_custom_documents(self, docs: List[str]):
        """Add custom uploaded documents to RAG"""
        if not hasattr(self, 'custom_docs'):
            self.custom_docs = []
        self.custom_docs.extend(docs)
        print(f"📄 Added {len(docs)} custom documents to RAG context")
    
    def build_rag_context(self, archive_logs: List[Dict] = None, custom_docs: List[str] = None):
        """Build combined RAG context from archives and/or custom docs"""
        try:
            print("🔄 Building RAG context...")
            
            # Handle archive logs
            if archive_logs:
                self.archive_logs = archive_logs
            elif not hasattr(self, 'archive_logs'):
                self.archive_logs = []

            # Handle custom docs - EXTEND instead of replace
            if custom_docs:
                if not hasattr(self, 'custom_docs'):
                    self.custom_docs = []
                self.custom_docs.extend(custom_docs)
            elif not hasattr(self, 'custom_docs'):
                self.custom_docs = []

            documents = []
            text_splitter = RecursiveCharacterTextSplitter(chunk_size=500, chunk_overlap=50)
            
            # Process archive logs if provided
            if self.archive_logs:
                documents.extend(self._process_archive_logs(text_splitter))
            
            # Process custom documents if provided
            if self.custom_docs:
                documents.extend(self._process_custom_docs(text_splitter))
            
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
    
    def _process_archive_logs(self, text_splitter: RecursiveCharacterTextSplitter) -> List[Document]:
        """Process archive logs into documents"""
        documents = []
        
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
        
        return documents
    
    def _process_custom_docs(self, text_splitter: RecursiveCharacterTextSplitter) -> List[Document]:
        """Process custom documents into vector chunks"""
        documents = []
        
        for doc_content in self.custom_docs:
            if doc_content.strip():
                splits = text_splitter.split_text(doc_content)
                for chunk in splits:
                    documents.append(Document(
                        page_content=chunk,
                        metadata={"source": "custom_upload"}
                    ))
        
        return documents
    
    def get_retriever(self, k: int = 10):
        """Get retriever for RAG queries"""
        if not self.rag_ready or not self.vectorstore:
            return None
        return self.vectorstore.as_retriever(search_kwargs={"k": k})
    
    def get_rag_status(self) -> Dict[str, Any]:
        """Get current RAG status"""
        return {
            "ready": self.rag_ready,
            "archive_logs": len(self.archive_logs),
            "custom_docs": len(self.custom_docs),
            "total_context": len(self.archive_logs) + len(self.custom_docs)
        }


class AlertAnalyzer:
    """Analyzes and processes security alert data"""
    
    @staticmethod
    def clean_log_data(logs: List[Dict]) -> List[Dict]:
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
    
    @staticmethod
    def analyze_current_alerts(alerts: List[Dict]) -> Dict[str, Any]:
        """Analyze current alerts for patterns and statistics"""
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


class SystemPromptManager:
    """Manages system prompts for different analysis types"""
    
    def __init__(self, templates_dir: str):
        self.templates_dir = Path(templates_dir)
        self.system_prompt = self._load_system_prompt()
    
    def _load_system_prompt(self) -> str:
        """Load cybersecurity analyst system prompt"""
        template_path = self.templates_dir / "cti.j2"
        if template_path.exists():
            try:
                with open(template_path, 'r') as f:
                    template_content = f.read()
                template = Template(template_content)
                return template.render()
            except Exception as e:
                print(f"⚠️ System prompt template error: {e}")
        
        # Fallback system prompt
        return """You are an expert cybersecurity analyst specializing in threat detection and intrusion analysis for a Security Operations Center (SOC). 
Your primary role is to analyze security incidents from Wazuh logs and generate comprehensive intrusion analysis reports following the MITRE ATT&CK framework.

Generate structured reports with:
1. Executive Summary
2. Key Findings  
3. MITRE ATT&CK Mapping
4. Indicators of Compromise
5. Recommendations

Focus on actionable insights for SME security teams."""
    
    def get_system_prompt(self) -> str:
        """Get the system prompt"""
        return self.system_prompt


class ReportFormatter:
    """Handles report generation and formatting"""
    
    def __init__(self, llm_client: LlamaModelClient, rag_manager: RAGContextManager, 
                 alert_analyzer: AlertAnalyzer, system_prompt_manager: SystemPromptManager):
        self.llm_client = llm_client
        self.rag_manager = rag_manager
        self.alert_analyzer = alert_analyzer
        self.system_prompt_manager = system_prompt_manager
    
    def generate_report_with_rag(self, current_alerts: List[Dict], server_host: str = "unknown") -> str:
        """Generate threat analysis report using RAG context"""
        if not self.rag_manager.rag_ready:
            return "❌ Error: RAG context not ready. Please build RAG context first."
        
        try:
            print(f"🧠 Generating report for {len(current_alerts)} current alerts with RAG...")
            
            # Clean current alerts
            cleaned_alerts = self.alert_analyzer.clean_log_data(current_alerts)
            
            # Get RAG context using retrieval
            retriever = self.rag_manager.get_retriever(k=10)
            if not retriever:
                return "❌ Error: RAG retriever not available."
            
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
            analysis = self.alert_analyzer.analyze_current_alerts(cleaned_alerts)
            
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
            
            # Generate user prompt
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
            
            # Generate report content
            report_content = self.llm_client.generate_response(
                self.system_prompt_manager.get_system_prompt(), 
                user_prompt
            )
            
            # Add report header
            report_header = self._create_report_header(cleaned_alerts, server_host)
            
            return report_header + report_content
            
        except Exception as e:
            error_report = f"""# Error Generating Report

**Error:** {str(e)}  
**Timestamp:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Alert Summary
- Current Alerts: {len(current_alerts)}
- RAG Status: {self.rag_manager.rag_ready}

Please check the system configuration and try again.
"""
            print(f"❌ Report generation error: {e}")
            return error_report
    
    def _create_report_header(self, cleaned_alerts: List[Dict], server_host: str) -> str:
        """Create report header with metadata"""
        rag_status = self.rag_manager.get_rag_status()
        return f"""#  SOC Threat Analysis Report

**Report Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  
**Current Alerts Analyzed:** {len(cleaned_alerts)}  
**RAG Context:** {rag_status['archive_logs']} archive logs + {rag_status['custom_docs']} custom documents  
**Analysis Method:** RAG-powered analysis  
**Wazuh Server:** {server_host}  

---

"""


class ReportGenerator:
    """Main orchestrator for report generation with RAG capabilities"""
    
    def __init__(self, model_path: str, llama_cpp_path: str, templates_dir: str):
        # Initialize all components
        self.template_manager = ChatTemplateManager(templates_dir)
        self.llm_client = LlamaModelClient(model_path, llama_cpp_path, self.template_manager)
        self.rag_manager = RAGContextManager()
        self.alert_analyzer = AlertAnalyzer()
        self.system_prompt_manager = SystemPromptManager(templates_dir)
        self.report_formatter = ReportFormatter(
            self.llm_client, 
            self.rag_manager, 
            self.alert_analyzer,
            self.system_prompt_manager
        )
    
    # RAG Management Methods
    def build_rag_context(self, archive_logs: List[Dict] = None, custom_docs: List[str] = None):
        """Build RAG context from archive logs and/or custom documents"""
        return self.rag_manager.build_rag_context(archive_logs, custom_docs)
    
    def add_custom_documents(self, docs: List[str]):
        """Add custom documents to RAG context"""
        return self.rag_manager.add_custom_documents(docs)
    
    def get_rag_status(self) -> Dict[str, Any]:
        """Get current RAG status"""
        return self.rag_manager.get_rag_status()
    
    @property
    def rag_ready(self) -> bool:
        """Check if RAG context is ready"""
        return self.rag_manager.rag_ready
    
    # Report Generation Methods
    def generate_report_with_rag(self, current_alerts: List[Dict], server_host: str = "unknown") -> str:
        """Generate comprehensive threat analysis report using RAG"""
        return self.report_formatter.generate_report_with_rag(current_alerts, server_host)
    
    # Utility Methods
    def clean_log_data(self, logs: List[Dict]) -> List[Dict]:
        """Clean and minimize log data"""
        return self.alert_analyzer.clean_log_data(logs)
    
    def analyze_current_alerts(self, alerts: List[Dict]) -> Dict[str, Any]:
        """Analyze current alerts for patterns"""
        return self.alert_analyzer.analyze_current_alerts(alerts)


# Legacy compatibility class
class ReportGeneratorLegacy:
    """Legacy interface for backward compatibility"""
    
    def __init__(self):
        self._generator = None
        self.model_path = None
        self.llama_cpp_path = None
        self.templates_dir = None
    
    def _ensure_generator(self):
        """Ensure the generator is initialized"""
        if (self._generator is None and 
            all([self.model_path, self.llama_cpp_path, self.templates_dir])):
            self._generator = ReportGenerator(
                self.model_path, 
                self.llama_cpp_path, 
                self.templates_dir
            )
    
    def build_rag_context(self, archive_logs: List[Dict] = None, custom_docs: List[str] = None):
        """Build RAG context"""
        self._ensure_generator()
        if self._generator:
            return self._generator.build_rag_context(archive_logs, custom_docs)
    
    def generate_report_with_rag(self, current_alerts: List[Dict]) -> str:
        """Generate report with RAG"""
        self._ensure_generator()
        if self._generator:
            return self._generator.generate_report_with_rag(current_alerts)
        return "Error: Report generator not initialized"
    
    def get_rag_status(self) -> Dict[str, Any]:
        """Get RAG status"""
        self._ensure_generator()
        if self._generator:
            return self._generator.get_rag_status()
        return {"ready": False, "archive_logs": 0, "custom_docs": 0, "total_context": 0}
    
    @property
    def rag_ready(self) -> bool:
        """Check if RAG is ready"""
        self._ensure_generator()
        return self._generator.rag_ready if self._generator else False
    
    def add_custom_documents(self, docs: List[str]):
        """Add custom documents"""
        self._ensure_generator()
        if self._generator:
            return self._generator.add_custom_documents(docs)
    
    def _clean_log_data(self, logs: List[Dict]) -> List[Dict]:
        """Clean log data (legacy method name)"""
        self._ensure_generator()
        if self._generator:
            return self._generator.clean_log_data(logs)
        return []
    
    def _analyze_current_alerts(self, alerts: List[Dict]) -> Dict[str, Any]:
        """Analyze alerts (legacy method name)"""
        self._ensure_generator()
        if self._generator:
            return self._generator.analyze_current_alerts(alerts)
        return {"total_alerts": 0, "severity_breakdown": {}, "rule_breakdown": {}, "critical_events": []}
