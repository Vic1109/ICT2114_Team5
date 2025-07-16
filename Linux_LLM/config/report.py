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
import shlex


class ChatTemplateManager:
    """Manages chat templates for LLM formatting - simplified for file-based system prompts"""
    
    def __init__(self, templates_dir: str, llm_config):
        self.templates_dir = Path(templates_dir)
        self.config = llm_config
        self.chat_template = self._load_chat_template()
    
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
        
        # Simple fallback for Gemma
        return """<bos>{% for message in messages %}<start_of_turn>{{ message.role }}
{{ message.content }}<end_of_turn>
{% endfor %}{% if add_generation_prompt %}<start_of_turn>model
{% endif %}"""
    
    def format_user_message(self, user_message: str) -> str:
        """Format user message only - system prompt comes from file"""
        if self.chat_template and self.config.use_custom_template:
            try:
                template = Template(self.chat_template)
                messages = [{"role": "user", "content": user_message}]
                
                formatted = template.render(
                    messages=messages, 
                    add_generation_prompt=True
                )
                return formatted
                
            except Exception as e:
                print(f"⚠️ Template formatting error: {e}")
        
        # Simple fallback for Gemma
        return f"<start_of_turn>user\n{user_message}<end_of_turn>\n<start_of_turn>model\n"
    
    def get_template_path(self) -> str:
        """Get full path to chat template file"""
        return str(self.templates_dir / self.config.chat_template_file)


class LlamaModelClient:
    """Handles LLM model inference using llama.cpp with file-based system prompts"""
    
    def __init__(self, llm_config, template_manager: ChatTemplateManager):
        self.config = llm_config
        self.template_manager = template_manager
    
    def generate_response(self, user_message: str) -> str:
        """Generate response using llama.cpp - system prompt comes from file"""
        try:
            # Format only the user message (system prompt handled by --system-prompt-file)
            formatted_prompt = self.template_manager.format_user_message(user_message)
            
            # Create temporary file for user message only
            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False, encoding='utf-8') as temp_file:
                temp_file.write(formatted_prompt)
                temp_file_path = temp_file.name
            
            # Build command using config
            template_path = self.template_manager.get_template_path() if self.config.use_custom_template else None
            
            cmd = [self.config.llama_cpp_path]
            cmd.extend(self.config.get_llama_args(
                templates_dir=str(self.template_manager.templates_dir),
                custom_template_path=template_path
            ))
            cmd.extend(["-f", temp_file_path])
            
            print(f"🚀 Executing {self.config.model_type} model with system prompt from file")
            print("⮞ FULL Command:")
            print("=" * 100)
            for i, arg in enumerate(cmd):
                print(f"  [{i:2d}] {arg}")
            print("=" * 100)

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
                
                # Clean response for Gemma
                response = stdout.strip()
                
                # Remove the prompt from response if included
                if formatted_prompt in response:
                    response = response.replace(formatted_prompt, '').strip()
                
                # Clean up Gemma artifacts
                response = response.replace('<end_of_turn>', '').strip()
                if response.endswith('<start_of_turn>'):
                    response = response[:-len('<start_of_turn>')].strip()
                
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
        test_user = "Say 'Hello, I am working correctly!' and nothing else."
        
        try:
            start_time = datetime.now()
            response = self.generate_response(test_user)
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
            
            if archive_logs:
                self.archive_logs = archive_logs
            elif not hasattr(self, 'archive_logs'):
                self.archive_logs = []

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
    
    def get_retriever(self, k: int = 5):  # Reduced from 10 to 5
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


import ipaddress
from typing import List, Dict, Any, Optional

class AlertAnalyzer:
    """Analyzes and processes security alert data with proper IP classification"""
    
    # Define your infrastructure IPs that should NOT be treated as threats
    INTERNAL_INFRASTRUCTURE = {
        '192.168.56.104',  # Your Suricata NIDS sensor
        '192.168.56.1',    # Likely your gateway
        # Add other internal infrastructure IPs here
    }
    
    # Define internal network ranges
    INTERNAL_NETWORKS = [
        ipaddress.ip_network('192.168.0.0/16'),
        ipaddress.ip_network('10.0.0.0/8'),
        ipaddress.ip_network('172.16.0.0/12'),
        ipaddress.ip_network('127.0.0.0/8'),
    ]
    
    @staticmethod
    def _is_internal_ip(ip_str: str) -> bool:
        """Check if an IP address is internal/private"""
        try:
            ip = ipaddress.ip_address(ip_str)
            return any(ip in network for network in AlertAnalyzer.INTERNAL_NETWORKS)
        except ValueError:
            return False
    
    @staticmethod
    def _is_infrastructure_ip(ip_str: str) -> bool:
        """Check if an IP is part of your security infrastructure"""
        return ip_str in AlertAnalyzer.INTERNAL_INFRASTRUCTURE
    
    @staticmethod
    def _classify_ip_context(ip_str: str) -> str:
        """Classify IP address context for threat analysis"""
        if not ip_str:
            return "unknown"
        
        if AlertAnalyzer._is_infrastructure_ip(ip_str):
            return "infrastructure"
        elif AlertAnalyzer._is_internal_ip(ip_str):
            return "internal"
        else:
            return "external"
    
    @staticmethod
    def _extract_geolocation(data: Dict, ip_field: str) -> Optional[Dict]:
        """Extract geolocation data with proper error handling"""
        # Check for root-level GeoLocation (your format)
        geo_data = data.get("GeoLocation", {})
        if geo_data and geo_data.get("country_name"):
            return {
                "country": geo_data.get("country_name"),
                "city": geo_data.get("city_name"),
                "latitude": geo_data.get("location", {}).get("lat"),
                "longitude": geo_data.get("location", {}).get("lon")
            }
        
        # Check for nested geoip data (alternative format)
        geoip_data = data.get("geoip", {})
        if geoip_data:
            ip_geo = geoip_data.get(ip_field, {})
            if ip_geo and ip_geo.get("country_name"):
                return {
                    "country": ip_geo.get("country_name"),
                    "city": ip_geo.get("city_name"),
                    "continent": ip_geo.get("continent_code"),
                    "latitude": ip_geo.get("location", {}).get("lat"),
                    "longitude": ip_geo.get("location", {}).get("lon")
                }
        
        return None
    
    @staticmethod
    def clean_log_data(logs: List[Dict]) -> List[Dict]:
        """Clean and minimize log data with enhanced context and proper IP classification"""
        cleaned_logs = []
        
        for log in logs:
            # Extract root-level data
            root_data = log.get("_source", log)  # Handle both formats
            data = root_data.get("data", {})
            
            # Basic alert information
            cleaned_log = {
                "timestamp": root_data.get("timestamp"),
                "rule_level": root_data.get("rule", {}).get("level"),
                "rule_description": root_data.get("rule", {}).get("description"),
                "rule_id": root_data.get("rule", {}).get("id"),
                "agent_ip": root_data.get("agent", {}).get("ip"),
                "agent_name": root_data.get("agent", {}).get("name")
            }
            
            if data:
                # Network context with IP classification
                src_ip = data.get("src_ip")
                dest_ip = data.get("dest_ip")
                
                cleaned_log.update({
                    "src_ip": src_ip,
                    "dest_ip": dest_ip,
                    "src_port": data.get("src_port"),
                    "dest_port": data.get("dest_port"),
                    "proto": data.get("proto"),
                    "app_proto": data.get("app_proto"),
                    "event_type": data.get("event_type"),
                    "direction": data.get("direction")
                })
                
                # Add IP classification context
                if src_ip:
                    cleaned_log["src_ip_context"] = AlertAnalyzer._classify_ip_context(src_ip)
                if dest_ip:
                    cleaned_log["dest_ip_context"] = AlertAnalyzer._classify_ip_context(dest_ip)
                
                # HTTP context (what's triggering the alert)
                http_data = data.get("http", {})
                if http_data:
                    cleaned_log["http_context"] = {
                        "hostname": http_data.get("hostname"),
                        "protocol": http_data.get("protocol"),
                        "method": http_data.get("http_method"),
                        "url": http_data.get("url"),
                        "status": http_data.get("status"),
                        "length": http_data.get("length")
                        # Intentionally omitting user_agent as requested
                    }
                
                # DNS context (for DNS-related alerts)
                dns_data = data.get("dns", {})
                if dns_data:
                    query_info = dns_data.get("query", [{}])[0] if dns_data.get("query") else {}
                    cleaned_log["dns_context"] = {
                        "query_name": query_info.get("rrname"),
                        "query_type": query_info.get("rrtype"),
                        "version": dns_data.get("version")
                    }
                
                # TLS/SSL context
                tls_data = data.get("tls", {})
                if tls_data:
                    cleaned_log["tls_context"] = {
                        "sni": tls_data.get("sni"),
                        "version": tls_data.get("version"),
                        "subject": tls_data.get("subject"),
                        "issuer": tls_data.get("issuer")
                    }
                
                # Enhanced geolocation handling
                geolocation = {}
                
                # For external IPs, try to extract geolocation
                if src_ip and not AlertAnalyzer._is_internal_ip(src_ip):
                    src_geo = AlertAnalyzer._extract_geolocation(root_data, "src_ip")
                    if src_geo:
                        geolocation["src"] = src_geo
                
                if dest_ip and not AlertAnalyzer._is_internal_ip(dest_ip):
                    dest_geo = AlertAnalyzer._extract_geolocation(root_data, "dest_ip")
                    if dest_geo:
                        geolocation["dest"] = dest_geo
                
                if geolocation:
                    cleaned_log["geolocation"] = geolocation
                
                # Flow context (connection details)
                flow_data = data.get("flow", {})
                if flow_data:
                    cleaned_log["flow_context"] = {
                        "pkts_toserver": flow_data.get("pkts_toserver"),
                        "pkts_toclient": flow_data.get("pkts_toclient"),
                        "bytes_toserver": flow_data.get("bytes_toserver"),
                        "bytes_toclient": flow_data.get("bytes_toclient"),
                        "start_time": flow_data.get("start")
                    }
                
                # Alert details
                alert = data.get("alert", {})
                if alert:
                    cleaned_log.update({
                        "alert_signature": alert.get("signature"),
                        "alert_category": alert.get("category"),
                        "alert_severity": alert.get("severity"),
                        "alert_action": alert.get("action"),
                        "signature_id": alert.get("signature_id"),
                        "gid": alert.get("gid")
                    })
                    
                    # MITRE ATT&CK mapping if available
                    metadata = alert.get("metadata", {})
                    if metadata:
                        cleaned_log["mitre_context"] = {
                            "confidence": metadata.get("confidence", [None])[0],
                            "created_at": metadata.get("created_at", [None])[0],
                            "updated_at": metadata.get("updated_at", [None])[0],
                            "signature_severity": metadata.get("signature_severity", [None])[0],
                            "affected_product": metadata.get("affected_product", [None])[0]
                        }
                
                # File context (for file-related alerts)
                files = data.get("files", [])
                if files:
                    file_info = files[0]  # Take first file
                    cleaned_log["file_context"] = {
                        "filename": file_info.get("filename"),
                        "size": file_info.get("size"),
                        "stored": file_info.get("stored"),
                        "state": file_info.get("state"),
                        "gaps": file_info.get("gaps")
                    }
                
                # Metadata context (flow indicators, etc.)
                metadata = data.get("metadata", {})
                if metadata:
                    cleaned_log["metadata_context"] = {}
                    
                    # Flow-related metadata
                    flowbits = metadata.get("flowbits", [])
                    if flowbits:
                        cleaned_log["metadata_context"]["flowbits"] = flowbits
                    
                    # HTTP anomaly counts
                    flowints = metadata.get("flowints", {})
                    if flowints:
                        cleaned_log["metadata_context"]["flowints"] = flowints
                
                # VLAN context if present
                vlan = data.get("vlan")
                if vlan:
                    cleaned_log["vlan"] = vlan
            
            # Apply threat classification logic
            threat_classification = AlertAnalyzer._classify_threat(cleaned_log)
            cleaned_log["threat_classification"] = threat_classification
            
            # Only keep logs with meaningful alert information
            if cleaned_log.get("rule_description") or cleaned_log.get("alert_signature"):
                # Remove None values and empty dicts to keep payload clean
                cleaned_log = {k: v for k, v in cleaned_log.items() 
                              if v is not None and v != {} and v != []}
                cleaned_logs.append(cleaned_log)
        
        return cleaned_logs
    
    @staticmethod
    def _classify_threat(alert: Dict) -> Dict[str, Any]:
        """Classify threat based on IP context and alert details"""
        classification = {
            "is_infrastructure_alert": False,
            "is_internal_threat": False,
            "is_external_threat": False,
            "threat_direction": "unknown",
            "confidence": "medium"
        }
        
        src_ip = alert.get("src_ip")
        dest_ip = alert.get("dest_ip")
        src_context = alert.get("src_ip_context", "unknown")
        dest_context = alert.get("dest_ip_context", "unknown")
        
        # Check if this is an infrastructure alert (should be low priority)
        if src_context == "infrastructure" or dest_context == "infrastructure":
            classification["is_infrastructure_alert"] = True
            classification["confidence"] = "low"
        
        # Determine threat direction and type
        if src_context == "internal" and dest_context == "external":
            classification["threat_direction"] = "outbound"
            classification["is_internal_threat"] = True
        elif src_context == "external" and dest_context == "internal":
            classification["threat_direction"] = "inbound"
            classification["is_external_threat"] = True
        elif src_context == "internal" and dest_context == "internal":
            classification["threat_direction"] = "lateral"
            classification["is_internal_threat"] = True
        elif src_context == "external" and dest_context == "external":
            classification["threat_direction"] = "external"
            classification["is_external_threat"] = True
        
        # Adjust confidence based on rule level
        rule_level = alert.get("rule_level", 0)
        if rule_level >= 12:
            classification["confidence"] = "high"
        elif rule_level >= 8:
            classification["confidence"] = "medium"
        else:
            classification["confidence"] = "low"
        
        return classification
    
    @staticmethod
    def analyze_current_alerts(alerts: List[Dict]) -> Dict[str, Any]:
        """Analyze current alerts for patterns and statistics with enhanced context"""
        analysis = {
            "total_alerts": len(alerts),
            "severity_breakdown": {},
            "rule_breakdown": {},
            "protocol_breakdown": {},
            "threat_classification": {
                "infrastructure_alerts": 0,
                "internal_threats": 0,
                "external_threats": 0,
                "inbound_threats": 0,
                "outbound_threats": 0,
                "lateral_threats": 0
            },
            "http_methods": {},
            "dns_queries": {},
            "geolocation_summary": {},
            "top_external_sources": {},
            "top_internal_sources": {},
            "critical_events": [],
            "infrastructure_noise": []
        }
        
        for alert in alerts:
            # Severity analysis
            level = alert.get('rule_level', 0)
            if level >= 12:
                severity = "Critical"
                analysis["critical_events"].append(alert)
            elif level >= 8:
                severity = "High"
            elif level >= 5:
                severity = "Medium"
            else:
                severity = "Low"
                
            analysis["severity_breakdown"][severity] = analysis["severity_breakdown"].get(severity, 0) + 1
            
            # Rule analysis
            rule_desc = alert.get('rule_description', 'Unknown')
            analysis["rule_breakdown"][rule_desc] = analysis["rule_breakdown"].get(rule_desc, 0) + 1
            
            # Protocol analysis
            proto = alert.get('proto', 'Unknown')
            analysis["protocol_breakdown"][proto] = analysis["protocol_breakdown"].get(proto, 0) + 1
            
            # Threat classification analysis
            threat_class = alert.get('threat_classification', {})
            if threat_class.get('is_infrastructure_alert'):
                analysis["threat_classification"]["infrastructure_alerts"] += 1
                analysis["infrastructure_noise"].append(alert)
            if threat_class.get('is_internal_threat'):
                analysis["threat_classification"]["internal_threats"] += 1
            if threat_class.get('is_external_threat'):
                analysis["threat_classification"]["external_threats"] += 1
            
            # Direction analysis
            direction = threat_class.get('threat_direction', 'unknown')
            if direction == "inbound":
                analysis["threat_classification"]["inbound_threats"] += 1
            elif direction == "outbound":
                analysis["threat_classification"]["outbound_threats"] += 1
            elif direction == "lateral":
                analysis["threat_classification"]["lateral_threats"] += 1
            
            # Source IP analysis (excluding infrastructure)
            src_ip = alert.get('src_ip')
            if src_ip and not threat_class.get('is_infrastructure_alert'):
                if alert.get('src_ip_context') == 'external':
                    analysis["top_external_sources"][src_ip] = analysis["top_external_sources"].get(src_ip, 0) + 1
                elif alert.get('src_ip_context') == 'internal':
                    analysis["top_internal_sources"][src_ip] = analysis["top_internal_sources"].get(src_ip, 0) + 1
            
            # HTTP method analysis
            http_context = alert.get('http_context', {})
            if http_context and http_context.get('method'):
                method = http_context['method']
                analysis["http_methods"][method] = analysis["http_methods"].get(method, 0) + 1
            
            # DNS query analysis
            dns_context = alert.get('dns_context', {})
            if dns_context and dns_context.get('query_name'):
                query = dns_context['query_name']
                analysis["dns_queries"][query] = analysis["dns_queries"].get(query, 0) + 1
            
            # Geolocation analysis (only for external IPs)
            geo = alert.get('geolocation', {})
            if geo:
                for direction in ['src', 'dest']:
                    if direction in geo and geo[direction].get('country'):
                        country = geo[direction]['country']
                        key = f"{direction}_{country}"
                        analysis["geolocation_summary"][key] = analysis["geolocation_summary"].get(key, 0) + 1
        
        # Sort top sources by frequency
        analysis["top_external_sources"] = dict(sorted(analysis["top_external_sources"].items(), 
                                                      key=lambda x: x[1], reverse=True)[:10])
        analysis["top_internal_sources"] = dict(sorted(analysis["top_internal_sources"].items(), 
                                                      key=lambda x: x[1], reverse=True)[:10])
        
        return analysis


class ReportFormatter:
    """Handles report generation and formatting - simplified for file-based system prompts"""
    
    def __init__(self, llm_client: LlamaModelClient, rag_manager: RAGContextManager, 
                 alert_analyzer: AlertAnalyzer):
        self.llm_client = llm_client
        self.rag_manager = rag_manager
        self.alert_analyzer = alert_analyzer
    
    def generate_report_with_rag(self, current_alerts: List[Dict], server_host: str = "unknown") -> str:
        """Generate threat analysis report using RAG context"""
        if not self.rag_manager.rag_ready:
            return "❌ Error: RAG context not ready. Please build RAG context first."
        
        try:
            print(f"🧠 Generating report for {len(current_alerts)} current alerts with RAG...")
            
            # Clean current alerts
            cleaned_alerts = self.alert_analyzer.clean_log_data(current_alerts)
            
            # Get minimal RAG context
            retriever = self.rag_manager.get_retriever(k=5)
            if not retriever:
                return "❌ Error: RAG retriever not available."
            
            # Create focused query from current alerts
            current_alert_signatures = []
            for alert in cleaned_alerts[:3]:
                if alert.get("rule_description"):
                    current_alert_signatures.append(alert["rule_description"])
                if alert.get("alert_signature"):
                    current_alert_signatures.append(alert["alert_signature"])
            
            query_text = " ".join(current_alert_signatures) if current_alert_signatures else "security incident detection"
            
            # Retrieve minimal relevant context
            relevant_docs = retriever.get_relevant_documents(query_text)
            filtered_rag_context = self._filter_relevant_context(relevant_docs, cleaned_alerts)
            
            # Analyze current alerts
            analysis = self.alert_analyzer.analyze_current_alerts(cleaned_alerts)
            
            # Create focused context
            context = f"""
CURRENT ALERTS ANALYSIS (PRIMARY FOCUS):
- Total Current Alerts: {len(cleaned_alerts)}
- Severity Distribution: {analysis['severity_breakdown']}
- Top Alert Types: {dict(list(analysis['rule_breakdown'].items())[:3])}
- Critical Events: {len(analysis['critical_events'])}

CURRENT ALERTS DATA:
{json.dumps(cleaned_alerts[:3], indent=1) if cleaned_alerts else "No current alerts"}

HISTORICAL REFERENCE CONTEXT (FOR BACKGROUND ONLY):
{filtered_rag_context}

IMPORTANT INSTRUCTIONS:
- Focus EXCLUSIVELY on the current alerts listed above
- Use historical context ONLY as background reference to understand attack patterns
- DO NOT include specific details from historical context in your analysis
- DO NOT mention historical incidents as if they are current
- Base all findings and recommendations on the current alerts only

Generate a report with:
1. **Executive Summary** (current threats only)
2. **Current Alert Analysis** (active alerts breakdown)
3. **MITRE ATT&CK Mapping** (for current alerts)
4. **Risk Assessment** (current severity)
5. **Immediate Recommendations** (actionable steps for current alerts)
6. **Technical Details** (current alert analysis)

Format in Markdown. Focus on actionable intelligence for the current security situation.
"""
            
            # Generate report content (system prompt comes from cti.txt file)
            report_content = self.llm_client.generate_response(context)
            
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
    
    def _filter_relevant_context(self, docs: List, current_alerts: List[Dict]) -> str:
        """Filter RAG context to only highly relevant information"""
        if not docs or not current_alerts:
            return "No relevant historical context found."
        
        # Extract key terms from current alerts
        current_terms = set()
        for alert in current_alerts[:3]:
            if alert.get("rule_description"):
                current_terms.update(alert["rule_description"].lower().split())
            if alert.get("alert_signature"):
                current_terms.update(alert["alert_signature"].lower().split())
        
        # Filter documents by relevance
        relevant_chunks = []
        for doc in docs[:2]:  # Only use top 2 documents
            doc_text = doc.page_content.lower()
            relevance_score = sum(1 for term in current_terms if term in doc_text and len(term) > 3)
            
            if relevance_score > 0:
                # Truncate to avoid overwhelming context
                truncated = doc.page_content[:150] + "..." if len(doc.page_content) > 150 else doc.page_content
                relevant_chunks.append(truncated)
        
        return "\n".join(relevant_chunks[:2]) if relevant_chunks else "No directly relevant historical patterns found."
    
    def _create_report_header(self, cleaned_alerts: List[Dict], server_host: str) -> str:
        """Create report header with metadata"""
        rag_status = self.rag_manager.get_rag_status()
        return f"""# SOC Threat Analysis Report - Current Alerts

**Report Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  
**Current Alerts Analyzed:** {len(cleaned_alerts)}  
**Analysis Scope:** Current alerts only (RAG context used as reference)  
**Wazuh Server:** {server_host}  

---

"""


class ReportGenerator:
    """Main orchestrator for report generation with file-based system prompts"""
    
    def __init__(self, llm_config, templates_dir: str):
        # Initialize simplified components
        self.template_manager = ChatTemplateManager(templates_dir, llm_config)
        self.llm_client = LlamaModelClient(llm_config, self.template_manager)
        self.rag_manager = RAGContextManager()
        self.alert_analyzer = AlertAnalyzer()
        self.report_formatter = ReportFormatter(
            self.llm_client, 
            self.rag_manager, 
            self.alert_analyzer
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