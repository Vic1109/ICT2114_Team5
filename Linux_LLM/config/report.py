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
import geoip2.database
import geoip2.errors
import ipaddress
from pathlib import Path
from typing import Optional, Dict, Any
from charts import SOCChartGenerator
import psycopg2
from psycopg2.extras import execute_values
import hashlib
from sentence_transformers import SentenceTransformer
import ipaddress
from typing import List, Dict, Any, Optional
import time #new


class GeoIPManager:
    def __init__(self, geoip_db_path: str = "/home/student/Desktop/GeoLite2-City.mmdb"):
        self.db_path = Path(geoip_db_path)
        self.reader = None
        self.available = False
        
        # Try to initialize the database
        self._initialize_database()
    
    def _initialize_database(self):
        try:
            if self.db_path.exists():
                self.reader = geoip2.database.Reader(str(self.db_path))
                self.available = True
                print(f"✅ GeoIP database loaded: {self.db_path}")
            else:
                print(f"⚠️ GeoIP database not found: {self.db_path}")
        except Exception as e:
            print(f"❌ Error initializing GeoIP database: {e}")
            self.available = False
    
    def get_location(self, ip_address: str) -> Optional[Dict[str, Any]]:
        if not self.available or not self.reader:
            return None
        
        try:
            if self._is_internal_ip(ip_address):
                return None
            
            response = self.reader.city(ip_address)
            
            return {
                "country": response.country.name,
                "country_code": response.country.iso_code,
                "city": response.city.name,
                "region": response.subdivisions.most_specific.name,
                "region_code": response.subdivisions.most_specific.iso_code,
                "latitude": float(response.location.latitude) if response.location.latitude else None,
                "longitude": float(response.location.longitude) if response.location.longitude else None,
                "timezone": response.location.time_zone,
                "postal_code": response.postal.code,
                "accuracy_radius": response.location.accuracy_radius
            }
            
        except geoip2.errors.AddressNotFoundError:
            return None
        except Exception as e:
            print(f"⚠️ GeoIP lookup error for {ip_address}: {e}")
            return None
    
    def _is_internal_ip(self, ip_str: str) -> bool:
        try:
            ip = ipaddress.ip_address(ip_str)
            return ip.is_private or ip.is_loopback or ip.is_link_local
        except ValueError:
            return True
    
    def close(self):
        if self.reader:
            self.reader.close()
            self.reader = None
            self.available = False

class ChatTemplateManager:
    def __init__(self, templates_dir: str, llm_config):
        self.templates_dir = Path(templates_dir)
        self.config = llm_config
        self.chat_template = self._load_chat_template()
    
    def _load_chat_template(self) -> str:
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
    
    def format_user_message(self, user_message: str) -> str:
        """Format user message only - system prompt comes from file"""
        if self.config.use_jinja:
            # llama.cpp will handle template formatting, just return raw message
            return user_message
        
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

    def get_template_path(self) -> str:
        """Get full path to chat template file"""
        return str(self.templates_dir / self.config.chat_template_file)


class LlamaModelClient:
    """Handles LLM model inference using llama.cpp with file-based system prompts"""
    
    def __init__(self, llm_config, template_manager: ChatTemplateManager):
        self.config = llm_config
        self.template_manager = template_manager
    
    def generate_response(self, user_message: str) -> str:
        try:
            formatted_prompt = self.template_manager.format_user_message(user_message)
            
            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False, encoding='utf-8') as temp_file:
                temp_file.write(formatted_prompt)
                temp_file_path = temp_file.name
            
            template_path = self.template_manager.get_template_path() if self.config.use_custom_template else None
            
            cmd = [self.config.llama_cpp_path]
            cmd.extend(self.config.get_llama_args(
                templates_dir=str(self.template_manager.templates_dir),
                custom_template_path=template_path
            ))
            cmd.extend(["--prompt", formatted_prompt])
            
            print(f"🚀 Executing {self.config.model_type} model with system prompt from file")
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
                
                try:
                    os.unlink(temp_file_path)
                except:
                    pass
                
                if process.returncode != 0:
                    print(f"❌ Llama.cpp error (return code {process.returncode})")
                    if stderr:
                        print(f"❌ Stderr: {stderr}")
                    return f"Error: Command failed with return code {process.returncode}"
                
                response = stdout.strip()
                
                if formatted_prompt in response:
                    response = response.replace(formatted_prompt, '').strip()
                
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

class RAGContextManager:
    """Manages RAG context including vector store and embeddings"""
    def __init__(self, db_config: dict):
        self.conn = psycopg2.connect(**db_config)
        self.embeddings = SentenceTransformer('Qwen/Qwen3-Embedding-0.6B', device='cpu') 
        if hasattr(self.embeddings, '_target_device'):
            self.embeddings._target_device = 'cpu'
        self._init_schema()
        self.rag_ready = self._check_ready()
    
    def _init_schema(self):
        """Initialize pgvector tables"""
        with self.conn.cursor() as cur:
            cur.execute("CREATE EXTENSION IF NOT EXISTS vector;")
            
            cur.execute("""
                CREATE TABLE IF NOT EXISTS alert_embeddings (
                    id SERIAL PRIMARY KEY,
                    alert_hash VARCHAR(64) UNIQUE,  -- Deduplication
                    content TEXT NOT NULL,
                    embedding vector(1024),  -- mpnet dimensions
                    metadata JSONB,  -- severity, timestamp, IPs, etc.
                    source VARCHAR(50),  -- 'archive' or 'custom'
                    created_at TIMESTAMP DEFAULT NOW(),
                    expires_at TIMESTAMP  -- Auto-expire old alerts
                );
                
                -- Index for fast similarity search
                CREATE INDEX IF NOT EXISTS alert_embedding_idx 
                ON alert_embeddings USING ivfflat (embedding vector_cosine_ops)
                WITH (lists = 100);
                
                -- Index for metadata filtering
                CREATE INDEX IF NOT EXISTS alert_metadata_idx 
                ON alert_embeddings USING gin (metadata);
            """)
            
            cur.execute("""
                CREATE TABLE IF NOT EXISTS custom_documents (
                    id SERIAL PRIMARY KEY,
                    doc_hash VARCHAR(64) UNIQUE,
                    filename VARCHAR(255),
                    content TEXT NOT NULL,
                    embedding vector(1024),
                    metadata JSONB,
                    created_at TIMESTAMP DEFAULT NOW()
                );
                
                CREATE INDEX IF NOT EXISTS doc_embedding_idx 
                ON custom_documents USING ivfflat (embedding vector_cosine_ops)
                WITH (lists = 100);
            """)
            
            self.conn.commit()

    def _check_ready(self) -> bool:
        try:
            with self.conn.cursor() as cur:
                cur.execute("""
                    SELECT 
                        (SELECT COUNT(*) FROM alert_embeddings WHERE embedding IS NOT NULL) as alerts,
                        (SELECT COUNT(*) FROM custom_documents WHERE embedding IS NOT NULL) as docs
                """)
                result = cur.fetchone()
                
                if result and (result[0] > 0 or result[1] > 0):
                    print(f"📊 RAG ready: {result[0]} alert embeddings, {result[1]} custom doc embeddings")
                    return True
                return False
        except:
            return False
        
    def build_rag_context(self, archive_logs: List[Dict] = None, custom_docs: List[str] = None):
        """Build RAG with persistence and deduplication"""
        try:
            if archive_logs:
                self._add_archive_logs(archive_logs)
            
            if custom_docs:
                self._add_custom_docs(custom_docs)
            
            self.rag_ready = True
            print(f"✅ Persistent RAG built - check database for embeddings")
            
        except Exception as e:
            print(f"❌ RAG build failed: {e}")
            self.rag_ready = False
    
    def _add_archive_logs(self, logs: List[Dict]):
        """Add archive logs with smart chunking and deduplication"""
        chunks = []
        
        for log in logs:
            chunk_text = self._create_semantic_chunk(log)
            chunk_hash = hashlib.sha256(chunk_text.encode()).hexdigest()
            
            metadata = {
                "severity": log.get("rule", {}).get("level", 0),
                "timestamp": log.get("timestamp"),
                "src_ip": log.get("data", {}).get("src_ip"),
                "dest_ip": log.get("data", {}).get("dest_ip"),
                "rule_id": log.get("rule", {}).get("id"),
                "proto": log.get("data", {}).get("proto")
            }
            
            chunks.append((chunk_hash, chunk_text, metadata))
        
        with self.conn.cursor() as cur:
            execute_values(cur, """
                INSERT INTO alert_embeddings (alert_hash, content, metadata, source)
                VALUES %s
                ON CONFLICT (alert_hash) DO NOTHING
                RETURNING id
            """, [(h, c, json.dumps(m), 'archive') for h, c, m in chunks])
            
            inserted = cur.rowcount
            print(f"📝 Added {inserted} new archive alerts (deduplicated)")
            self.conn.commit()

            cur.execute("""
                SELECT id, content FROM alert_embeddings 
                WHERE embedding IS NULL AND source = 'archive'
            """)
            
            to_embed = cur.fetchall()
            if to_embed:
                ids, texts = zip(*to_embed)
                embeddings = self.embeddings.encode(texts, show_progress_bar=True)
                
                execute_values(cur, """
                    UPDATE alert_embeddings AS a SET embedding = v.embedding::vector
                    FROM (VALUES %s) AS v(id, embedding)
                    WHERE a.id = v.id
                """, [(id, emb.tolist()) for id, emb in zip(ids, embeddings)])
            
            self.conn.commit()

    def _add_custom_docs(self, docs: List[str]):
        """Add custom documents with deduplication"""
        chunks = []
        
        for i, doc_content in enumerate(docs):
            if not doc_content.strip():
                continue
            
            doc_hash = hashlib.sha256(doc_content.encode()).hexdigest()
            filename = f"custom_doc_{i}"
            
            metadata = {
                "filename": filename,
                "length": len(doc_content),
                "added_at": datetime.now().isoformat()
            }
            
            chunks.append((doc_hash, filename, doc_content, metadata))
        
        with self.conn.cursor() as cur:
            execute_values(cur, """
                INSERT INTO custom_documents (doc_hash, filename, content, metadata)
                VALUES %s
                ON CONFLICT (doc_hash) DO NOTHING
            """, [(h, f, c, json.dumps(m)) for h, f, c, m in chunks])
            
            inserted = cur.rowcount
            print(f"📄 Added {inserted} new custom documents (deduplicated from {len(chunks)})")
            self.conn.commit()
            
            cur.execute("""
                SELECT id, content FROM custom_documents 
                WHERE embedding IS NULL
                LIMIT 1000
            """)
            
            to_embed = cur.fetchall()
            if to_embed:
                ids, texts = zip(*to_embed)
                print(f"🧮 Computing embeddings for {len(ids)} new documents...")
                embeddings = self.embeddings.encode(list(texts), show_progress_bar=True)
                
                update_data = [(id, emb.tolist()) for id, emb in zip(ids, embeddings)]
                execute_values(cur, """
                    UPDATE custom_documents AS d SET embedding = v.embedding::vector
                    FROM (VALUES %s) AS v(id, embedding)
                    WHERE d.id = v.id
                """, update_data)
                
                print(f"✅ Document embeddings computed and stored")
            
            self.conn.commit()

    def add_custom_documents(self, docs: List[str]):
        """Add custom documents to RAG context (public method)"""
        if not hasattr(self, 'custom_docs'):
            self.custom_docs = []
        self.custom_docs.extend(docs)
        self._add_custom_docs(docs)
        self.rag_ready = self._check_ready()
        print(f"📄 Added {len(docs)} custom documents to RAG context")

    def _create_semantic_chunk(self, log: Dict) -> str:
        """Create semantic-rich chunk from alert - preserves context"""
        parts = []
        
        # Rule information
        rule = log.get("rule", {})
        if rule.get("description"):
            parts.append(f"Rule: {rule['description']}")
        if rule.get("level"):
            parts.append(f"Severity: {rule['level']}")
        
        # Network context
        data = log.get("data", {})
        if data.get("src_ip") and data.get("dest_ip"):
            parts.append(f"Connection: {data['src_ip']}:{data.get('src_port', '?')} → {data['dest_ip']}:{data.get('dest_port', '?')}")
        
        # Alert signature
        alert = data.get("alert", {})
        if alert.get("signature"):
            parts.append(f"Alert: {alert['signature']}")
        
        # HTTP/DNS context if present
        if data.get("http", {}).get("hostname"):
            parts.append(f"HTTP Host: {data['http']['hostname']}")
        if data.get("dns", {}).get("query"):
            parts.append(f"DNS Query: {data['dns']['query'][0].get('rrname', '')}")
        
        # Full log as reference
        if log.get("full_log"):
            parts.append(f"Details: {log['full_log'][:500]}")
        
        return " | ".join(parts)
    
    def get_retriever(self, k: int = 15, metadata_filter: dict = None):
        """Get retriever with metadata filtering"""
        def retrieve(query: str) -> List[str]:
            # Embed query
            query_embedding = self.embeddings.encode([query])[0].tolist()
            
            with self.conn.cursor() as cur:
                # Build metadata filter
                filter_clause = "TRUE"
                if metadata_filter:
                    if "min_severity" in metadata_filter:
                        filter_clause += f" AND (metadata->>'severity')::int >= {metadata_filter['min_severity']}"
                    if "timeframe_hours" in metadata_filter:
                        filter_clause += f" AND created_at >= NOW() - INTERVAL '{metadata_filter['timeframe_hours']} hours'"
                
                # Semantic search with metadata filtering
                cur.execute(f"""
                    SELECT content, metadata, 1 - (embedding <=> %s::vector) AS similarity
                    FROM alert_embeddings
                    WHERE {filter_clause}
                    ORDER BY embedding <=> %s::vector
                    LIMIT %s
                """, (query_embedding, query_embedding, k))
                
                results = cur.fetchall()
                return [{"content": r[0], "metadata": r[1], "score": r[2]} for r in results]
        
        return retrieve
    
    def cleanup_old_alerts(self, days: int = 30):
        """Remove alerts older than N days"""
        with self.conn.cursor() as cur:
            cur.execute("""
                DELETE FROM alert_embeddings 
                WHERE source = 'archive' 
                AND created_at < NOW() - INTERVAL '%s days'
            """, (days,))
            deleted = cur.rowcount
            self.conn.commit()
            print(f"🧹 Removed {deleted} old alerts (>{days} days)")
    def get_rag_status(self) -> Dict[str, Any]:
        """Get current RAG status with database stats"""
        try:
            with self.conn.cursor() as cur:
                cur.execute("""
                    SELECT 
                        (SELECT COUNT(*) FROM alert_embeddings) as total_alerts,
                        (SELECT COUNT(*) FROM alert_embeddings WHERE embedding IS NOT NULL) as alerts_with_embeddings,
                        (SELECT COUNT(*) FROM custom_documents) as total_docs,
                        (SELECT COUNT(*) FROM custom_documents WHERE embedding IS NOT NULL) as docs_with_embeddings
                """)
                stats = cur.fetchone()
                
                return {
                    "ready": self.rag_ready,
                    "storage": "persistent_postgresql",
                    "total_alerts": stats[0],
                    "alerts_with_embeddings": stats[1],
                    "total_custom_docs": stats[2],
                    "docs_with_embeddings": stats[3],
                    "embedding_model": "Qwen3-Embedding-0.6B",
                    "vector_dimensions": 1024
                }
        except Exception as e:
            print(f"⚠️ Error getting RAG status: {e}")
            return {
                "ready": self.rag_ready,
                "storage": "persistent_postgresql",
                "error": str(e)
            }
    def refresh_context(self):
        """Refresh RAG context from existing database without adding new data"""
        try:
            self.rag_ready = self._check_ready()
            if self.rag_ready:
                print("✅ RAG context refreshed from persistent database")
                return True
            else:
                print("⚠️ No data found in persistent database")
                return False
        except Exception as e:
            print(f"❌ Error refreshing RAG context: {e}")
            return False    

class AlertAnalyzer:
    """Analyzes and processes security alert data with proper IP classification - FIXED"""
    def __init__(self):
        self.geoip_manager = GeoIPManager()
    
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
        """Classify IP address context for threat analysis - FIXED"""
        if not ip_str:
            return "unknown"
        
        # PRIORITY CHECK: Infrastructure first
        if AlertAnalyzer._is_infrastructure_ip(ip_str):
            return "infrastructure"
        elif AlertAnalyzer._is_internal_ip(ip_str):
            return "internal"
        else:
            return "external"
    
    @staticmethod
    def _extract_geolocation_with_geoip(data: Dict, ip_field: str, geoip_manager: GeoIPManager) -> Optional[Dict]:
        """Extract geolocation using GeoIP2 for external IPs - FIXED FOR INFRASTRUCTURE"""
        ip_address = data.get(ip_field)
        if not ip_address:
            return None
        
        # CRITICAL FIX: Skip infrastructure IPs first
        if AlertAnalyzer._is_infrastructure_ip(ip_address):
            return None
        
        # Skip internal IPs
        if AlertAnalyzer._is_internal_ip(ip_address):
            return None
        
        # Use GeoIP2 to get real location data (only for external IPs)
        location = geoip_manager.get_location(ip_address)
        if location:
            return {
                "country": location.get("country"),
                "country_code": location.get("country_code"),
                "city": location.get("city"),
                "region": location.get("region"),
                "latitude": location.get("latitude"),
                "longitude": location.get("longitude"),
                "timezone": location.get("timezone"),
                "accuracy_radius": location.get("accuracy_radius")
            }
        
        return None
    
    @staticmethod
    def _classify_threat(alert: Dict) -> Dict[str, Any]:
        """Classify threat based on IP context and alert details - ENHANCED"""
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
        
        # PRIORITY CHECK: Infrastructure alerts (should be low priority)
        if src_context == "infrastructure" or dest_context == "infrastructure":
            classification["is_infrastructure_alert"] = True
            classification["confidence"] = "low"
            classification["threat_direction"] = "infrastructure"
            # Don't classify as threats if infrastructure is involved
            return classification
        
        # Determine threat direction and type for non-infrastructure
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
        """Analyze current alerts for patterns and statistics - FIXED FOR INFRASTRUCTURE"""
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
            
            # Threat classification analysis - FIXED
            threat_class = alert.get('threat_classification', {})
            if threat_class.get('is_infrastructure_alert'):
                analysis["threat_classification"]["infrastructure_alerts"] += 1
                analysis["infrastructure_noise"].append(alert)
                continue  # Skip further processing for infrastructure alerts
            
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
            
            # Source IP analysis - FIXED (excluding infrastructure)
            src_ip = alert.get('src_ip')
            if src_ip and not threat_class.get('is_infrastructure_alert'):
                src_context = alert.get('src_ip_context', 'unknown')
                if src_context == 'external':
                    analysis["top_external_sources"][src_ip] = analysis["top_external_sources"].get(src_ip, 0) + 1
                elif src_context == 'internal':
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
            
            # Geolocation analysis - FIXED (only for external IPs, no infrastructure)
            geo = alert.get('geolocation', {})
            if geo and not threat_class.get('is_infrastructure_alert'):
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
    

    @staticmethod
    def clean_log_data(logs: List[Dict]) -> List[Dict]:
        """Clean and minimize log data with enhanced context and proper IP classification"""
        cleaned_logs = []
        geoip_manager = GeoIPManager()  # Initialize GeoIP manager
        for log in logs:
            # Extract root-level data
            root_data = log.get("_source", log)  # Handle both formats
            data = root_data.get("data", {})
            
            # Extract and convert rule_level to integer (Suricata sends as string)
            raw_level = root_data.get("rule", {}).get("level")
            try:
                rule_level = int(raw_level) if raw_level is not None else 0
            except (ValueError, TypeError):
                rule_level = 0
            
            # Basic alert information
            cleaned_log = {
                "timestamp": root_data.get("timestamp"),
                "rule_level": rule_level,  # Now guaranteed to be integer
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
                    src_geo = AlertAnalyzer._extract_geolocation_with_geoip(
                        {"src_ip": src_ip}, "src_ip", geoip_manager
                    )
                    if src_geo:
                        geolocation["src"] = src_geo
                
                # Get geolocation for external destination IPs
                if dest_ip and not AlertAnalyzer._is_internal_ip(dest_ip):
                    dest_geo = AlertAnalyzer._extract_geolocation_with_geoip(
                        {"dest_ip": dest_ip}, "dest_ip", geoip_manager
                    )
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
                
        geoip_manager.close() 
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
    
class ReportFormatter:
    def __init__(self, llm_client: LlamaModelClient, rag_manager: RAGContextManager, 
                 alert_analyzer: AlertAnalyzer):
        self.llm_client = llm_client
        self.rag_manager = rag_manager
        self.alert_analyzer = alert_analyzer
    
    def generate_report_with_rag(self, current_alerts: List[Dict], server_host: str = "unknown", 
                             is_automatic: bool = False, trigger_info: Dict = None) -> str:
        start_time = time.time() #new
        """Generate threat analysis report using simplified severity-based RAG logic"""
        if not self.rag_manager.rag_ready:
            return "❌ Error: RAG context not ready. Please build RAG context first."
        
        try:
            print(f"🧠 Generating report for {len(current_alerts)} current alerts with RAG...")
            
            # Clean current alerts
            cleaned_alerts = self.alert_analyzer.clean_log_data(current_alerts)
            
            # Check for high severity alerts (level > 8) for automatic reports only
            if is_automatic:
                high_severity_alerts = [alert for alert in cleaned_alerts 
                                    if alert.get("rule_level", 0) > 8]
                
                if high_severity_alerts:
                    # HIGH-SEVERITY AUTOMATIC: Use custom docs RAG only
                    print(f"🚨 High-severity automatic report: Using custom docs RAG for {len(high_severity_alerts)} alerts")
                    return self._generate_with_custom_docs_only(cleaned_alerts, high_severity_alerts, server_host, trigger_info)
            
            # MANUAL ANALYSIS or LOW-SEVERITY AUTOMATIC: Use full RAG context
            print(f"📊 Standard analysis: Using full RAG context for {len(cleaned_alerts)} alerts")
            return self._generate_with_full_rag(cleaned_alerts, server_host, is_automatic, trigger_info)
            
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
        
    def _generate_with_custom_docs_only(self, all_alerts: List[Dict], 
                                   high_severity_alerts: List[Dict], 
                                   server_host: str, trigger_info: Dict = None) -> str:
        """Generate report using ONLY custom docs (no alerts.json) - CLEAN VERSION"""
        
        # Get custom docs retriever only
        custom_context = self._get_custom_docs_context(high_severity_alerts)
        
        # Analyze current alerts
        analysis = self.alert_analyzer.analyze_current_alerts(all_alerts)
        
        # Create compact alert summary to prevent token overflow
        max_alerts_for_llm = 10
        compact_alerts = self._create_compact_alert_summary(high_severity_alerts, max_alerts_for_llm)
        more_alerts_count = max(0, len(high_severity_alerts) - max_alerts_for_llm)
        
        # Create context - NO INDENTATION ISSUES
        context = f"""ANALYSIS TYPE: HIGH-SEVERITY AUTOMATIC INCIDENT RESPONSE
    RAG STRATEGY: Custom Documentation Only (No Historical Alerts)

    CURRENT HIGH-SEVERITY INCIDENT DATA:
    - Total Alerts: {len(all_alerts)}
    - High-Severity Alerts (>8): {len(high_severity_alerts)}
    - Threat Distribution: {analysis['threat_classification']}

    HIGH-SEVERITY ALERTS (Compact View - Top {min(max_alerts_for_llm, len(high_severity_alerts))} of {len(high_severity_alerts)}):
    {compact_alerts}
    {f"... and {more_alerts_count} more high-severity alerts (similar patterns)" if more_alerts_count > 0 else ""}

    CUSTOM THREAT INTELLIGENCE REFERENCE:
    {custom_context}

    CONTEXT: This is an automatic high-severity incident requiring immediate response. Focus exclusively on current high-severity alerts. Use custom threat intelligence for attack pattern recognition only."""
        
        # Uses existing cti.txt system prompt via LLM client
        report_content = self.llm_client.generate_response(context)
        
        # Clean the response to remove forbidden elements
        report_content = self._clean_report_content(report_content)
        
        # Create ONE CLEAN HEADER with all information
        if trigger_info:
            # Automatic report header with trigger information
            report_header = f"""# HIGH-SEVERITY INCIDENT REPORT

    Auto-Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  
    Trigger: {trigger_info.get('trigger_count', 0)} HIGH severity alerts detected (Level >= {trigger_info.get('threshold', 8)})  
    Critical Alerts (>8): {trigger_info.get('high_severity_count', 0)}  
    Total Alerts Analyzed: {trigger_info.get('total_alerts', len(all_alerts))}  
    Server: {server_host}  
    RAG Strategy: Custom Docs Only  
    Response Priority: {trigger_info.get('response_priority', 'IMMEDIATE')}  

    Triggered High Severity Alerts
    """
            # Add triggered alerts summary
            for i, alert in enumerate(trigger_info.get('triggered_alerts', []), 1):
                level = alert.get("rule_level", 0)
                desc = alert.get("rule_description", "Unknown")
                alert_timestamp = alert.get("timestamp", "Unknown")
                priority_marker = "🔥" if level > 8 else "⚡"
                report_header += f"{i}. {priority_marker} Level {level} - {desc} ({alert_timestamp})\n"
            
            if trigger_info.get('trigger_count', 0) > 5:
                remaining = trigger_info.get('trigger_count', 0) - 5
                report_header += f"   ... and {remaining} more HIGH severity alerts\n"
            
            report_header += "\n---\n\n"
        else:
            # Manual report header
            report_header = f"""# 🚨 HIGH-SEVERITY INCIDENT REPORT

    Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  
    High-Severity Alerts: {len(high_severity_alerts)} (Level >8)  
    Total Alerts: {len(all_alerts)}  
    Server: {server_host}  
    RAG Mode: Custom Docs Only  

    ---

    """
        return report_header + report_content

    def _clean_report_content(self, content: str) -> str:
        """Clean report content to remove forbidden elements and fix formatting"""
        
        # Remove forbidden endings
        forbidden_endings = [
            "[end of text]",
            "Do you require further elaboration",
            "Would you like me to focus on",
            "Is there anything specific you'd like me to",
            "Please let me know if you need",
            "Further analysis can be provided"
        ]
        
        for ending in forbidden_endings:
            if ending in content:
                # Find and remove everything from this point onward
                index = content.find(ending)
                content = content[:index].strip()
        
        # Remove duplicate headers if they exist
        lines = content.split('\n')
        cleaned_lines = []
        seen_headers = set()
        
        for line in lines:
            # Check for duplicate headers
            if line.startswith('#'):
                if line in seen_headers:
                    continue  # Skip duplicate header
                seen_headers.add(line)
            
            # Fix indentation issues
            if line.strip() and not line.startswith('#') and not line.startswith('|'):
                # Remove excessive leading whitespace but preserve normal indentation
                line = line.lstrip()
            
            cleaned_lines.append(line)
        
        cleaned_content = '\n'.join(cleaned_lines)
        
        # Ensure proper ending format
        if "**Analysis Complete**" not in cleaned_content:
            cleaned_content += f"""

    ---
    **Analysis Complete**
    Report generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
    Threat level: CRITICAL
    Priority actions: 5 identified"""
        
        return cleaned_content


    def _generate_with_full_rag(self, cleaned_alerts: List[Dict], server_host: str, 
                           is_automatic: bool, trigger_info: Dict = None) -> str:
        """Generate report using full RAG context - CLEAN VERSION"""
        
        # Get full RAG context
        retriever = self.rag_manager.get_retriever(k=5)
        if not retriever:
            return "❌ Error: RAG retriever not available."
        
        # Create query and get context
        query_text = self._build_query_from_alerts(cleaned_alerts)
        relevant_docs = retriever(query_text)
        full_rag_context = self._filter_relevant_context(relevant_docs, cleaned_alerts)
        
        # Analyze current alerts
        analysis = self.alert_analyzer.analyze_current_alerts(cleaned_alerts)
        
        # Create context - NO INDENTATION ISSUES
        analysis_type = "MANUAL ANALYSIS" if not is_automatic else "AUTOMATIC STANDARD ANALYSIS"
        
        context = f"""ANALYSIS TYPE: {analysis_type}
    RAG STRATEGY: Full Context (Historical Alerts + Custom Documentation)

    CURRENT ALERTS DATA:
    - Total Alerts: {len(cleaned_alerts)}
    - Severity Distribution: {analysis['severity_breakdown']}
    - Threat Classification: {analysis['threat_classification']}

    CURRENT ALERTS:
    {json.dumps(cleaned_alerts[:5], indent=1) if cleaned_alerts else "No current alerts"}

    HISTORICAL AND CUSTOM REFERENCE CONTEXT:
    {full_rag_context}

    CONTEXT: {"Manual security analysis with comprehensive context." if not is_automatic else "Automatic analysis for standard-severity incidents."}"""
        
        # Uses existing cti.txt system prompt via LLM client
        report_content = self.llm_client.generate_response(context)
        
        # Clean the response to remove forbidden elements
        report_content = self._clean_report_content(report_content)
        
        # Create appropriate header
        if is_automatic and trigger_info:
            mode = "Automatic Analysis"
            report_header = f"""# SOC Threat Analysis Report - {mode}

    Auto-Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  
    Trigger: {trigger_info.get('trigger_count', 0)} alerts detected (Level >= {trigger_info.get('threshold', 8)})  
    Total Alerts Analyzed: {trigger_info.get('total_alerts', len(cleaned_alerts))}  
    Server: {server_host}  
    RAG Mode: Full Context  
    Response Priority: {trigger_info.get('response_priority', 'HIGH')}  

    ---

    """
        else:
            mode = "Manual Analysis" if not is_automatic else "Automatic Analysis"
            report_header = f"""# SOC Threat Analysis Report - {mode}

    Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  
    Alerts Analyzed: {len(cleaned_alerts)}  
    Server: {server_host}  
    RAG Mode: Full Context  

    ---

    """
        
        return report_header + report_content

    def _create_compact_alert_summary(self, alerts: List[Dict], max_alerts: int = 10) -> str:
        """Create a compact summary of alerts to reduce token usage"""
        sample = alerts[:max_alerts]
        summaries = []
        
        for i, alert in enumerate(sample, 1):
            compact = {
                "id": i,
                "level": alert.get("rule_level", 0),
                "rule": alert.get("rule_description", "Unknown")[:80],  # Truncate long descriptions
                "src": alert.get("src_ip", "?"),
                "dst": alert.get("dest_ip", "?"),
                "time": alert.get("timestamp", "?")[:19] if alert.get("timestamp") else "?"  # Just date+time
            }
            
            # Add key context if available
            if alert.get("alert_signature"):
                compact["sig"] = alert.get("alert_signature")[:60]
            
            summaries.append(compact)
        
        return json.dumps(summaries, indent=1)
    
    def _get_custom_docs_context(self, high_severity_alerts: List[Dict]) -> str:
        """Get context from custom documents only"""
        if not hasattr(self.rag_manager, 'custom_docs') or not self.rag_manager.custom_docs:
            return "No custom threat intelligence documentation available."
        
        # Simple approach: use relevant custom docs content directly
        query_terms = set()
        for alert in high_severity_alerts[:3]:
            if alert.get("rule_description"):
                query_terms.update(alert["rule_description"].lower().split())
            if alert.get("alert_signature"):
                query_terms.update(alert["alert_signature"].lower().split())
        
        relevant_content = []
        for doc in self.rag_manager.custom_docs:
            doc_lower = doc.lower()
            relevance = sum(1 for term in query_terms if term in doc_lower and len(term) > 3)
            if relevance > 0:
                # Take first 300 chars of relevant docs
                content = doc[:300] + "..." if len(doc) > 300 else doc
                relevant_content.append(content)
        
        return "\n\n".join(relevant_content[:2]) if relevant_content else "No directly relevant custom documentation found."

    def _build_query_from_alerts(self, alerts: List[Dict]) -> str:
        """Build query from current alerts"""
        query_parts = []
        for alert in alerts[:3]:
            if alert.get("rule_description"):
                query_parts.append(alert["rule_description"])
            if alert.get("alert_signature"):
                query_parts.append(alert["alert_signature"])
        
        return " ".join(query_parts) if query_parts else "security incident analysis"
    
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


# Enhanced classes with chart support
class EnhancedReportFormatter(ReportFormatter):
    """Enhanced report formatter with chart generation capabilities"""
    
    def __init__(self, llm_client: LlamaModelClient, rag_manager: RAGContextManager, 
                 alert_analyzer: AlertAnalyzer, reports_dir: str):
        super().__init__(llm_client, rag_manager, alert_analyzer)
        
        # Initialize chart generator
        charts_dir = Path(reports_dir) / "charts"
        self.chart_generator = SOCChartGenerator(str(charts_dir))
        
        # Clean up old charts on initialization
        cleaned = self.chart_generator.cleanup_old_charts(max_age_hours=48)
        if cleaned > 0:
            print(f"🧹 Cleaned up {cleaned} old chart files")
    
    def generate_report_with_rag(self, current_alerts: List[Dict], server_host: str = "unknown", 
                        is_automatic: bool = False, trigger_info: Dict = None) -> str:
        """Enhanced report generation with conditional IP analysis charts"""
        if not self.rag_manager.rag_ready:
            return "❌ Error: RAG context not ready. Please build RAG context first."
        
        try:
            print(f"🧠 Generating enhanced report for {len(current_alerts)} alerts...")
            include_charts = is_automatic or (trigger_info and trigger_info.get('include_charts', False))
            # Check if alerts are already cleaned (have 'threat_classification' key)
            if current_alerts and 'threat_classification' in current_alerts[0]:
                print(f"✅ Alerts already cleaned, using as-is")
                cleaned_alerts = current_alerts
            else:
                print(f"🔄 Cleaning raw alerts...")
                cleaned_alerts = self.alert_analyzer.clean_log_data(current_alerts)
            
            print(f"📊 Processing {len(cleaned_alerts)} cleaned alerts for report")
            
            # Generate charts ONLY if enabled
            chart_paths = []
            if include_charts:
                chart_timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                trigger_type = "automatic" if is_automatic else "manual"
                chart_prefix = f"{trigger_type}_report_{chart_timestamp}"
                
                print(f"📊 Generating charts with prefix: {chart_prefix}")
                
                try:
                    # Generate IP analysis charts
                    ip_charts = self.chart_generator.generate_ip_analysis_charts(
                        cleaned_alerts, chart_prefix
                    )
                    chart_paths.extend(ip_charts)
                    print(f"✅ Generated {len(ip_charts)} IP analysis charts")
                    
                    # Generate timeline chart if we have enough data
                    if len(cleaned_alerts) > 5:
                        timeline_path = self.chart_generator.generate_severity_timeline(
                            cleaned_alerts, chart_prefix
                        )
                        if timeline_path:
                            chart_paths.append(timeline_path)
                            print(f"✅ Generated severity timeline chart")
                    
                    print(f"📈 Total charts generated: {len(chart_paths)}")
                except Exception as chart_error:
                    print(f"⚠️ Chart generation failed: {chart_error}")
                    import traceback
                    traceback.print_exc()
                    # Continue without charts - don't fail the whole report
            else:
                print("📊 Skipping chart generation (not enabled for this report type)")
            
            # Generate the text report (existing logic)
            if is_automatic:
                high_severity_alerts = [alert for alert in cleaned_alerts 
                                    if alert.get("rule_level", 0) > 8]
                
                if high_severity_alerts:
                    text_report = self._generate_with_custom_docs_only(
                        cleaned_alerts, high_severity_alerts, server_host, trigger_info
                    )
                else:
                    text_report = self._generate_with_full_rag(
                        cleaned_alerts, server_host, is_automatic, trigger_info
                    )
            else:
                text_report = self._generate_with_full_rag(
                    cleaned_alerts, server_host, is_automatic, trigger_info
                )
            
            # Insert charts into the report ONLY if charts were generated
            if chart_paths:
                print(f"📊 Embedding {len(chart_paths)} charts into report")
                enhanced_report = self._insert_charts_into_report(
                    text_report, chart_paths, cleaned_alerts
                )
                return enhanced_report
            else:
                print("📊 No charts to embed - returning text-only report")
                return text_report
            
        except Exception as e:
            error_report = f"""# Error Generating Enhanced Report

    **Error:** {str(e)}  
    **Timestamp:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

    ## Alert Summary
    - Current Alerts: {len(current_alerts)}
    - RAG Status: {self.rag_manager.rag_ready}

    Please check the system configuration and try again.
    """
            print(f"❌ Enhanced report generation error: {e}")
            import traceback
            traceback.print_exc()
            return error_report
    
    def _insert_charts_into_report(self, text_report: str, chart_paths: List[str], 
                                 alerts: List[Dict]) -> str:
        """Insert charts into the report at appropriate locations"""
        try:
            # If we didn't find a good insertion point, add charts at the end
            if chart_paths:
                charts_section = self._create_charts_section(chart_paths, alerts)
                return text_report + '\n\n---\n\n' + charts_section
            return text_report
            
        except Exception as e:
            print(f"⚠️ Error inserting charts: {e}")
            return text_report
    
    def _create_charts_section(self, chart_paths: List[str], alerts: List[Dict]) -> str:
        """Create the charts section for the report"""
        if not chart_paths:
            return ""
        
        charts_section = f"""
## 📊 Visual Threat Analysis

The following charts provide visual insights into the IP address patterns and threat distribution:

**Key Metrics:**
- Total alerts analyzed: {len(alerts)}
- Charts generated: {len(chart_paths)}

"""
        
        for chart_path in chart_paths:
            chart_filename = Path(chart_path).name
            relative_path = f"./charts/{chart_filename}"
            charts_section += f"""
### 📈 {chart_filename.replace('_', ' ').title()}

![Chart]({relative_path})

"""
        
        return charts_section


class ReportGenerator:
    """Main orchestrator for report generation with chart capabilities"""
    
    def __init__(self, llm_config, templates_dir: str, reports_dir: str = None, db_config: dict = None):
        # Initialize base components
        self.template_manager = ChatTemplateManager(templates_dir, llm_config)
        self.llm_client = LlamaModelClient(llm_config, self.template_manager)
        
        # Database configuration
        if db_config is None:
            db_config = {
                "host": "localhost",
                "port": 5432,
                "database": "soc_rag",
                "user": "soc_user",
                "password": "soc_secure_pass_2024"
            }
        
        self.rag_manager = RAGContextManager(db_config)
        self.alert_analyzer = AlertAnalyzer()
        
        # Set reports directory
        self.reports_dir = reports_dir or str(Path(templates_dir).parent / "reports")
        
        # Use enhanced formatter with charts
        self.report_formatter = EnhancedReportFormatter(
            self.llm_client, 
            self.rag_manager, 
            self.alert_analyzer,
            self.reports_dir
        )
        
        self.report_metrics = {
            "reports_generated": 0,
            "total_generation_time": 0.0,
            "avg_generation_time": 0.0,
            "min_generation_time": float('inf'),
            "max_generation_time": 0.0,
            "report_history": []  # List of {"timestamp": ..., "duration": ..., "type": ...}
        }
    
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
    def generate_report_with_rag(self, current_alerts: List[Dict], server_host: str = "unknown", 
                             is_automatic: bool = False, trigger_info: Dict = None) -> str:
        """Generate comprehensive threat analysis report using severity-based RAG logic"""
        #new - Track report generation timing
        start_time = time.time()
        report_type = "automatic" if is_automatic else "manual"
        
        try:
            report_content = self.report_formatter.generate_report_with_rag(current_alerts, server_host, is_automatic, trigger_info)
            
            #new - Calculate and record generation time
            generation_time = time.time() - start_time
            self._update_report_metrics(generation_time, report_type, success=True)
            
            print(f"⏱️ Report generated in {generation_time:.2f} seconds ({report_type})")
            
            return report_content
        except Exception as e:
            #new - Track failed attempts too
            generation_time = time.time() - start_time
            self._update_report_metrics(generation_time, report_type, success=False)
            raise e
    
    #new - Helper method to update timing metrics
    def _update_report_metrics(self, generation_time: float, report_type: str, success: bool = True):
        """Update report generation timing metrics"""
        self.report_metrics["reports_generated"] += 1
        self.report_metrics["total_generation_time"] += generation_time
        
        # Update average
        self.report_metrics["avg_generation_time"] = (
            self.report_metrics["total_generation_time"] / self.report_metrics["reports_generated"]
        )
        
        # Update min/max
        self.report_metrics["min_generation_time"] = min(
            self.report_metrics["min_generation_time"], 
            generation_time
        )
        self.report_metrics["max_generation_time"] = max(
            self.report_metrics["max_generation_time"], 
            generation_time
        )
        
        # Add to history (keep last 100 reports)
        self.report_metrics["report_history"].append({
            "timestamp": datetime.now().isoformat(),
            "duration_seconds": round(generation_time, 2),
            "type": report_type,
            "success": success
        })
        
        # Keep only last 100 reports in history
        if len(self.report_metrics["report_history"]) > 100:
            self.report_metrics["report_history"] = self.report_metrics["report_history"][-100:]
    
    #new - Get formatted metrics report
    def get_generation_metrics(self) -> Dict[str, Any]:
        """Get formatted report generation metrics"""
        metrics = self.report_metrics.copy()
        
        # Format min/max times (handle infinity)
        if metrics["min_generation_time"] == float('inf'):
            metrics["min_generation_time"] = 0.0
        
        # Add formatted times
        metrics["min_generation_time_formatted"] = f"{metrics['min_generation_time']:.2f}s"
        metrics["max_generation_time_formatted"] = f"{metrics['max_generation_time']:.2f}s"
        metrics["avg_generation_time_formatted"] = f"{metrics['avg_generation_time']:.2f}s"
        metrics["total_generation_time_formatted"] = f"{metrics['total_generation_time']:.2f}s"
        
        # Calculate success rate
        if metrics["report_history"]:
            successful = sum(1 for r in metrics["report_history"] if r.get("success", True))
            metrics["success_rate"] = f"{(successful / len(metrics['report_history']) * 100):.1f}%"
        else:
            metrics["success_rate"] = "N/A"
        
        return metrics
    
    # Utility Methods
    def clean_log_data(self, logs: List[Dict]) -> List[Dict]:
        """Clean and minimize log data"""
        return self.alert_analyzer.clean_log_data(logs)
    
    def analyze_current_alerts(self, alerts: List[Dict]) -> Dict[str, Any]:
        """Analyze current alerts for patterns"""
        return self.alert_analyzer.analyze_current_alerts(alerts)

    def get_chart_capabilities(self) -> Dict[str, Any]:
        """Get information about chart generation capabilities"""
        return {
            "charts_available": True,
            "chart_types": [
                "external_sources_pie",
                "geolocation_pie", 
                "threat_directions_pie",
                "protocols_pie",
                "severity_timeline"
            ],
            "charts_directory": str(self.report_formatter.chart_generator.charts_dir),
            "supported_formats": ["PNG"],
            "auto_cleanup": "48 hours"
        }