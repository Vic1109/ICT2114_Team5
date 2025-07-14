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
    """Manages chat templates for LLM formatting with config integration"""
    
    def __init__(self, templates_dir: str, llm_config):
        self.templates_dir = Path(templates_dir)
        self.config = llm_config
        self.chat_template = self._load_chat_template()
        self.system_prompt_template = self._load_system_prompt_template()
    
    def _load_chat_template(self) -> str:
        """Load model-specific chat template from config"""
        template_path = self.templates_dir / self.config.chat_template_file
        
        if template_path.exists():
            try:
                with open(template_path, 'r', encoding='utf-8') as f:
                    template_content = f.read()
                print(f"✅ Loaded chat template: {template_path}")
                return template_content
            except Exception as e:
                print(f"⚠️ Error loading chat template: {e}")
        else:
            print(f"⚠️ Chat template not found: {template_path}")
        
        # Return default template based on model type
        return self._get_default_template()
    
    def _load_system_prompt_template(self) -> str:
        """Load system prompt template from config"""
        template_path = self.templates_dir / self.config.system_prompt_file
        
        if template_path.exists():
            try:
                with open(template_path, 'r', encoding='utf-8') as f:
                    template_content = f.read()
                print(f"✅ Loaded system prompt template: {template_path}")
                return template_content
            except Exception as e:
                print(f"⚠️ Error loading system prompt template: {e}")
        
        return self._get_default_system_prompt()
    
    def _get_default_template(self) -> str:
        """Get default template based on model type"""
        if self.config.model_type.lower() == "gemma":
            return """<bos>{% for message in messages %}{% if message.role == 'system' %}<start_of_turn>user
{{ message.content }}<end_of_turn>
<start_of_turn>model
I understand. I'll follow these instructions for our conversation.<end_of_turn>
{% elif message.role == 'user' %}<start_of_turn>user
{{ message.content }}<end_of_turn>
{% elif message.role == 'assistant' %}<start_of_turn>model
{{ message.content }}<end_of_turn>
{% endif %}{% endfor %}{% if add_generation_prompt %}<start_of_turn>model
{% endif %}"""
        else:
            # Fallback for other models
            return """<|im_start|>system
{{ messages[0].content }}<|im_end|>
<|im_start|>user
{{ messages[1].content }}<|im_end|>
<|im_start|>assistant
"""
    
    def _get_default_system_prompt(self) -> str:
        """Default cybersecurity analyst system prompt"""
        return """You are an expert cybersecurity analyst specializing in threat detection and intrusion analysis for a Security Operations Center (SOC). 
Your primary role is to analyze security incidents from Wazuh logs and generate comprehensive intrusion analysis reports following the MITRE ATT&CK framework.

Generate structured reports with:
1. Executive Summary
2. Key Findings  
3. MITRE ATT&CK Mapping
4. Indicators of Compromise
5. Recommendations

Focus on actionable insights for SME security teams. Generate ONLY cybersecurity analysis content."""
    
    def format_messages(self, system_prompt: str, user_message: str) -> str:
        """Format messages using the loaded chat template"""
        if self.chat_template:
            try:
                template = Template(self.chat_template)
                
                # Handle different model types
                if self.config.model_type.lower() == "gemma":
                    # For Gemma, system prompt is wrapped as user message
                    messages = [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_message}
                    ]
                else:
                    # For other models with dedicated system role
                    messages = [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_message}
                    ]
                
                formatted = template.render(
                    messages=messages, 
                    add_generation_prompt=True,
                    enable_thinking=False  # Disable thinking for cybersecurity analysis
                )
                
                return formatted
                
            except Exception as e:
                print(f"⚠️ Template formatting error: {e}")
        
        # Fallback format based on model type
        if self.config.model_type.lower() == "gemma":
            return f"<bos><start_of_turn>user\n{system_prompt}\n\n{user_message}<end_of_turn>\n<start_of_turn>model\n"
        else:
            return f"<|im_start|>system\n{system_prompt}<|im_end|>\n<|im_start|>user\n{user_message}<|im_end|>\n<|im_start|>assistant\n"
    
    def render_system_prompt(self, **kwargs) -> str:
        """Render system prompt template with custom variables"""
        try:
            template = Template(self.system_prompt_template)
            
            # Default variables for cybersecurity context
            default_vars = {
                'system_role': 'cybersecurity_analyst',
                'framework': 'MITRE_ATTACK_v12',
                'data_sources': ['suricata_alerts', 'wazuh_logs', 'network_traffic'],
                'custom_rules': kwargs.get('custom_rules', ''),
                'threat_intel_feeds': kwargs.get('threat_intel_feeds', [])
            }
            
            # Merge with provided kwargs
            default_vars.update(kwargs)
            
            rendered = template.render(**default_vars)
            return rendered
            
        except Exception as e:
            print(f"⚠️ System prompt rendering error: {e}")
            return self._get_default_system_prompt()
    
    def get_template_path(self) -> str:
        """Get full path to chat template file"""
        return str(self.templates_dir / self.config.chat_template_file)


class LlamaModelClient:
    """Handles LLM model inference using llama.cpp with config integration"""
    
    def __init__(self, llm_config, template_manager: ChatTemplateManager):
        self.config = llm_config
        self.template_manager = template_manager
    
    def generate_response(self, system_prompt: str, user_message: str, 
                         use_custom_template: bool = None, **template_vars) -> str:
        """Generate response using llama.cpp with config-based arguments"""
        try:
            # Render system prompt with custom variables if needed
            if template_vars:
                system_prompt = self.template_manager.render_system_prompt(**template_vars)
            
            # Format messages using chat template
            if use_custom_template is None:
                use_custom_template = self.config.use_custom_template
            
            if use_custom_template:
                formatted_prompt = self.template_manager.format_messages(system_prompt, user_message)
                template_path = self.template_manager.get_template_path()
            else:
                # Fallback to simple format
                formatted_prompt = self.template_manager.format_messages(system_prompt, user_message)
                template_path = None
            
            # Create temporary file for prompt
            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False, encoding='utf-8') as temp_file:
                temp_file.write(formatted_prompt)
                temp_file_path = temp_file.name
            
            # Build command using config
            cmd = [self.config.llama_cpp_path]
            cmd.extend(self.config.get_llama_args(template_path))
            cmd.extend(["-f", temp_file_path])
            
            print(f"🚀 Executing {self.config.model_type} model with {len(cmd)} arguments")
            
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
                stdout, stderr = process.communicate(timeout=self.config.timeout)
                
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
                
                # Clean response based on model type
                response = stdout.strip()
                
                # Remove the prompt from response if it's included
                if formatted_prompt in response:
                    response = response.replace(formatted_prompt, '').strip()
                
                # Model-specific cleanup
                if self.config.model_type.lower() == "gemma":
                    response = response.replace('<end_of_turn>', '').strip()
                    if response.endswith('<start_of_turn>'):
                        response = response[:-len('<start_of_turn>')].strip()
                else:
                    response = response.replace('<|im_end|>', '').strip()
                
                # Common cleanup
                response = response.replace('>', '').replace('$ ', '').strip()
                
                return response
                
            except subprocess.TimeoutExpired:
                print(f"❌ LLM generation timed out after {self.config.timeout} seconds")
                process.kill()
                try:
                    os.unlink(temp_file_path)
                except:
                    pass
                return f"Error: LLM generation timed out after {self.config.timeout} seconds."
                
        except Exception as e:
            print(f"❌ LLM generation error: {e}")
            return f"Error: {str(e)}"
    
    def test_model(self) -> Dict[str, Any]:
        """Test model functionality with a simple prompt"""
        test_system = "You are a helpful assistant."
        test_user = "Say 'Hello, I am working correctly!' and nothing else."
        
        try:
            start_time = datetime.now()
            response = self.generate_response(test_system, test_user)
            end_time = datetime.now()
            
            return {
                "success": True,
                "response": response,
                "response_time": (end_time - start_time).total_seconds(),
                "model_type": self.config.model_type,
                "template_used": self.config.chat_template_file
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "model_type": self.config.model_type,
                "template_used": self.config.chat_template_file
            }


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
    
    def __init__(self, template_manager: ChatTemplateManager):
        self.template_manager = template_manager
    
    def get_system_prompt(self, **kwargs) -> str:
        """Get the system prompt with custom variables"""
        return self.template_manager.render_system_prompt(**kwargs)


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
            system_prompt = self.system_prompt_manager.get_system_prompt()
            report_content = self.llm_client.generate_response(system_prompt, user_prompt)
            
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
    
    def __init__(self, llm_config, templates_dir: str):
        # Initialize all components with config integration
        self.template_manager = ChatTemplateManager(templates_dir, llm_config)
        self.llm_client = LlamaModelClient(llm_config, self.template_manager)
        self.rag_manager = RAGContextManager()
        self.alert_analyzer = AlertAnalyzer()
        self.system_prompt_manager = SystemPromptManager(self.template_manager)
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
    
    def test_model(self) -> Dict[str, Any]:
        """Test the LLM model functionality"""
        return self.llm_client.test_model()


# Legacy compatibility functions
def create_report_generator(model_path: str, llama_cpp_path: str, templates_dir: str):
    """Legacy function for creating report generator"""
    # Create a basic config for compatibility
    from config import LLMConfig
    
    config = LLMConfig()
    config.model_path = model_path
    config.llama_cpp_path = llama_cpp_path
    
    return ReportGenerator(config, templates_dir)