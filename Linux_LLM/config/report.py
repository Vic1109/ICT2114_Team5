import json
import os
import re
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional
from jinja2 import Template
import geoip2.database
import geoip2.errors
import ipaddress
from charts import SOCChartGenerator
import psycopg2
from psycopg2.extras import execute_values
import hashlib
from sentence_transformers import SentenceTransformer
import time
import threading


class GeoIPManager:
    def __init__(self, geoip_db_path: str = None):
        self.db_path = Path(geoip_db_path) if geoip_db_path else None
        self.reader = None
        self.available = False
        
        # Try to initialize the database
        self._initialize_database()
    
    def _initialize_database(self):
        try:
            if not self.db_path:
                print("GeoIP database path not configured")
            elif self.db_path.exists():
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
                print(f" Template formatting error: {e}")

        return user_message

    def get_template_path(self) -> str:
        """Get full path to chat template file"""
        return str(self.templates_dir / self.config.chat_template_file)


class LlamaModelClient:
    """Handles LLM model inference using llama.cpp with file-based system prompts"""
    
    def __init__(self, llm_config, template_manager: ChatTemplateManager):
        self.config = llm_config
        self.template_manager = template_manager
    
    def generate_response(self, user_message: str) -> str:
        temp_file_path = None
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
            cmd.extend(["--file", temp_file_path])
            
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
        finally:
            if temp_file_path:
                try:
                    os.unlink(temp_file_path)
                except:
                    pass

class RAGContextManager:
    """Manages RAG context including vector store and embeddings"""
    def __init__(self, db_config: dict, rag_config=None):
        self.rag_config = rag_config
        self.embedding_model = getattr(rag_config, "embedding_model", "Qwen/Qwen3-Embedding-0.6B")
        self.embedding_device = getattr(rag_config, "embedding_device", "cpu")
        self.vector_dimensions = int(getattr(rag_config, "embedding_dimensions", 1024))
        self.chunk_size = int(getattr(rag_config, "chunk_size", 500))
        self.chunk_overlap = int(getattr(rag_config, "chunk_overlap", 50))
        self.max_retrieval_docs = int(getattr(rag_config, "max_retrieval_docs", 10))
        self.normalize_embeddings = bool(getattr(rag_config, "normalize_embeddings", False))
        self.db_lock = threading.RLock()
        self.conn = psycopg2.connect(**db_config)
        self.embeddings = SentenceTransformer(self.embedding_model, device=self.embedding_device) 
        if hasattr(self.embeddings, '_target_device'):
            self.embeddings._target_device = self.embedding_device
        self._init_schema()
        self.rag_ready = self._check_ready()

    @staticmethod
    def _safe_int(value: Any, default: int = 0) -> int:
        try:
            return int(value) if value is not None else default
        except (TypeError, ValueError):
            return default

    def _rollback_safely(self):
        try:
            self.conn.rollback()
        except Exception:
            pass

    def _encode_texts(self, texts: List[str]):
        return self.embeddings.encode(
            list(texts),
            show_progress_bar=True,
            normalize_embeddings=self.normalize_embeddings
        )

    def _to_vector_literal(self, embedding: Any) -> str:
        values = embedding.tolist() if hasattr(embedding, "tolist") else list(embedding)
        if len(values) != self.vector_dimensions:
            raise ValueError(
                f"Embedding dimension mismatch: expected {self.vector_dimensions}, got {len(values)}"
            )
        return "[" + ",".join(str(float(value)) for value in values) + "]"

    def _split_oversized_text(self, text: str) -> List[str]:
        """Split text that has no useful paragraph/sentence boundaries."""
        chunks = []
        step = max(1, self.chunk_size - self.chunk_overlap)
        for start in range(0, len(text), step):
            chunk = text[start:start + self.chunk_size].strip()
            if chunk:
                chunks.append(chunk)
            if start + self.chunk_size >= len(text):
                break
        return chunks

    def _split_long_paragraph(self, paragraph: str) -> List[str]:
        sentences = [
            sentence.strip()
            for sentence in re.split(r"(?<=[.!?])\s+", paragraph)
            if sentence.strip()
        ]
        if len(sentences) <= 1:
            return self._split_oversized_text(paragraph)

        chunks = []
        current = ""
        for sentence in sentences:
            if len(sentence) > self.chunk_size:
                if current:
                    chunks.append(current.strip())
                    current = ""
                chunks.extend(self._split_oversized_text(sentence))
                continue

            candidate = f"{current} {sentence}".strip() if current else sentence
            if len(candidate) <= self.chunk_size:
                current = candidate
            else:
                if current:
                    chunks.append(current.strip())
                current = sentence

        if current:
            chunks.append(current.strip())
        return chunks

    def _chunk_text(self, text: str) -> List[str]:
        """Create paragraph-aware chunks for embedding without discarding overlap entirely."""
        text = text.strip()
        if not text:
            return []
        if len(text) <= self.chunk_size:
            return [text]

        paragraphs = [
            paragraph.strip()
            for paragraph in re.split(r"\n\s*\n+", text)
            if paragraph.strip()
        ]
        if not paragraphs:
            return self._split_oversized_text(text)

        chunks = []
        current_parts = []
        current_len = 0

        for paragraph in paragraphs:
            paragraph_chunks = (
                [paragraph]
                if len(paragraph) <= self.chunk_size
                else self._split_long_paragraph(paragraph)
            )

            for part in paragraph_chunks:
                separator_len = 2 if current_parts else 0
                if current_parts and current_len + separator_len + len(part) > self.chunk_size:
                    chunks.append("\n\n".join(current_parts).strip())

                    overlap_parts = []
                    overlap_len = 0
                    for previous in reversed(current_parts):
                        previous_len = len(previous) + (2 if overlap_parts else 0)
                        if overlap_len + previous_len > self.chunk_overlap:
                            break
                        overlap_parts.insert(0, previous)
                        overlap_len += previous_len

                    current_parts = overlap_parts
                    current_len = sum(len(p) for p in current_parts) + max(0, len(current_parts) - 1) * 2

                current_parts.append(part)
                current_len += len(part) + (2 if len(current_parts) > 1 else 0)

        if current_parts:
            chunks.append("\n\n".join(current_parts).strip())

        return [chunk for chunk in chunks if chunk]
    
    def _init_schema(self):
        """Initialize pgvector tables"""
        with self.db_lock, self.conn.cursor() as cur:
            cur.execute("CREATE EXTENSION IF NOT EXISTS vector;")
            
            cur.execute(f"""
                CREATE TABLE IF NOT EXISTS alert_embeddings (
                    id SERIAL PRIMARY KEY,
                    alert_hash VARCHAR(64) UNIQUE,  -- Deduplication
                    content TEXT NOT NULL,
                    embedding vector({self.vector_dimensions}),
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
            
            cur.execute(f"""
                CREATE TABLE IF NOT EXISTS custom_documents (
                    id SERIAL PRIMARY KEY,
                    doc_hash VARCHAR(64) UNIQUE,
                    filename VARCHAR(255),
                    content TEXT NOT NULL,
                    embedding vector({self.vector_dimensions}),
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
            with self.db_lock, self.conn.cursor() as cur:
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
        except Exception as e:
            self._rollback_safely()
            print(f"WARNING: RAG readiness check failed: {e}")
            return False
        
    def build_rag_context(self, archive_logs: List[Dict] = None, custom_docs: List[str] = None):
        """Build RAG with persistence and deduplication"""
        try:
            if archive_logs:
                self._add_archive_logs(archive_logs)
            
            if custom_docs:
                self._add_custom_docs(custom_docs)
            
            self.rag_ready = self._check_ready()
            print(f"RAG ready: {self.rag_ready}")
            return self.rag_ready
            
        except Exception as e:
            self._rollback_safely()
            print(f"RAG build failed: {e}")
            self.rag_ready = False
            return False
    
    def _add_archive_logs(self, logs: List[Dict]):
        """Add archive logs with smart chunking and deduplication"""
        chunks = []
        
        for log in logs:
            chunk_text = self._create_semantic_chunk(log)
            if not chunk_text.strip():
                continue
            chunk_hash = hashlib.sha256(chunk_text.encode()).hexdigest()
            
            metadata = {
                "severity": self._safe_int(log.get("rule", {}).get("level", 0)),
                "timestamp": log.get("timestamp"),
                "src_ip": log.get("data", {}).get("src_ip"),
                "dest_ip": log.get("data", {}).get("dest_ip"),
                "rule_id": log.get("rule", {}).get("id"),
                "proto": log.get("data", {}).get("proto")
            }
            
            chunks.append((chunk_hash, chunk_text, metadata))

        if not chunks:
            print("WARNING: No archive log chunks to add")
            return
        
        with self.db_lock, self.conn.cursor() as cur:
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
                embeddings = self._encode_texts(list(texts))
                
                execute_values(cur, """
                    UPDATE alert_embeddings AS a SET embedding = v.embedding::vector
                    FROM (VALUES %s) AS v(id, embedding)
                    WHERE a.id = v.id
                """, [(id, self._to_vector_literal(emb)) for id, emb in zip(ids, embeddings)])
            
            self.conn.commit()

    def _add_custom_docs(self, docs: List[str]):
        """Add custom documents with deduplication"""
        chunks = []
        
        for i, doc_content in enumerate(docs):
            if not doc_content.strip():
                continue
            
            doc_chunks = self._chunk_text(doc_content)
            for chunk_index, chunk_text in enumerate(doc_chunks):
                doc_hash = hashlib.sha256(chunk_text.encode()).hexdigest()
                filename = f"custom_doc_{i}_chunk_{chunk_index}"
                
                metadata = {
                    "filename": filename,
                    "source_document": f"custom_doc_{i}",
                    "chunk_index": chunk_index,
                    "chunk_count": len(doc_chunks),
                    "length": len(chunk_text),
                    "added_at": datetime.now().isoformat()
                }
                
                chunks.append((doc_hash, filename, chunk_text, metadata))

        if not chunks:
            print("WARNING: No custom document chunks to add")
            return
        
        with self.db_lock, self.conn.cursor() as cur:
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
                embeddings = self._encode_texts(list(texts))
                
                update_data = [(id, self._to_vector_literal(emb)) for id, emb in zip(ids, embeddings)]
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
            parts.append(f"Connection: {data['src_ip']}:{data.get('src_port', '')}  {data['dest_ip']}:{data.get('dest_port', '')}")
        
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
    
    def get_retriever(self, k: int = None, metadata_filter: dict = None):
        """Get retriever with metadata filtering"""
        def retrieve(query: str) -> List[Dict[str, Any]]:
            limit = k or self.max_retrieval_docs
            # Embed query
            query_embedding = self._to_vector_literal(self._encode_texts([query])[0])
            
            with self.db_lock, self.conn.cursor() as cur:
                # Build metadata filter safely for archive alerts.
                filter_parts = ["embedding IS NOT NULL"]
                filter_params = []
                if metadata_filter:
                    if "min_severity" in metadata_filter:
                        filter_parts.append("(metadata->>'severity')::int >= %s")
                        filter_params.append(int(metadata_filter["min_severity"]))
                    if "timeframe_hours" in metadata_filter:
                        filter_parts.append("created_at >= NOW() - (%s * INTERVAL '1 hour')")
                        filter_params.append(int(metadata_filter["timeframe_hours"]))
                filter_clause = " AND ".join(filter_parts)
                
                # Semantic search archive alerts and custom documents, then merge by score.
                cur.execute(f"""
                    SELECT content, metadata, source, 1 - (embedding <=> %s::vector) AS similarity
                    FROM alert_embeddings
                    WHERE {filter_clause}
                    ORDER BY embedding <=> %s::vector
                    LIMIT %s
                """, (query_embedding, *filter_params, query_embedding, limit))
                
                alert_results = [
                    {"content": r[0], "metadata": r[1] or {}, "source": r[2], "score": r[3]}
                    for r in cur.fetchall()
                ]

                cur.execute("""
                    SELECT content, metadata, 1 - (embedding <=> %s::vector) AS similarity
                    FROM custom_documents
                    WHERE embedding IS NOT NULL
                    ORDER BY embedding <=> %s::vector
                    LIMIT %s
                """, (query_embedding, query_embedding, limit))

                doc_results = [
                    {"content": r[0], "metadata": r[1] or {}, "source": "custom_document", "score": r[2]}
                    for r in cur.fetchall()
                ]

                return sorted(
                    alert_results + doc_results,
                    key=lambda item: item.get("score") or 0,
                    reverse=True
                )[:limit]
        
        return retrieve

    def search_custom_documents(self, query: str, k: int = 2) -> List[Dict[str, Any]]:
        """Search only uploaded/custom CTI documents."""
        query_embedding = self._to_vector_literal(self._encode_texts([query])[0])

        with self.db_lock, self.conn.cursor() as cur:
            cur.execute("""
                SELECT content, metadata, 1 - (embedding <=> %s::vector) AS similarity
                FROM custom_documents
                WHERE embedding IS NOT NULL
                ORDER BY embedding <=> %s::vector
                LIMIT %s
            """, (query_embedding, query_embedding, k))

            return [
                {"content": r[0], "metadata": r[1] or {}, "source": "custom_document", "score": r[2]}
                for r in cur.fetchall()
            ]

    def search_archive_alerts(self, query: str, k: int = 5, metadata_filter: dict = None) -> List[Dict[str, Any]]:
        """Search only historical archive alerts."""
        query_embedding = self._to_vector_literal(self._encode_texts([query])[0])

        with self.db_lock, self.conn.cursor() as cur:
            filter_parts = ["embedding IS NOT NULL"]
            filter_params = []
            if metadata_filter:
                if "min_severity" in metadata_filter:
                    filter_parts.append("(metadata->>'severity')::int >= %s")
                    filter_params.append(int(metadata_filter["min_severity"]))
                if "timeframe_hours" in metadata_filter:
                    filter_parts.append("created_at >= NOW() - (%s * INTERVAL '1 hour')")
                    filter_params.append(int(metadata_filter["timeframe_hours"]))

            filter_clause = " AND ".join(filter_parts)
            cur.execute(f"""
                SELECT content, metadata, source, 1 - (embedding <=> %s::vector) AS similarity
                FROM alert_embeddings
                WHERE {filter_clause}
                ORDER BY embedding <=> %s::vector
                LIMIT %s
            """, (query_embedding, *filter_params, query_embedding, k))

            return [
                {"content": r[0], "metadata": r[1] or {}, "source": r[2], "score": r[3]}
                for r in cur.fetchall()
            ]
    
    def cleanup_old_alerts(self, days: int = 30):
        """Remove alerts older than N days"""
        with self.db_lock, self.conn.cursor() as cur:
            cur.execute("""
                DELETE FROM alert_embeddings 
                WHERE source = 'archive' 
                AND created_at < NOW() - (%s * INTERVAL '1 day')
            """, (days,))
            deleted = cur.rowcount
            self.conn.commit()
            print(f"🧹 Removed {deleted} old alerts (>{days} days)")
    def get_rag_status(self) -> Dict[str, Any]:
        """Get current RAG status with database stats"""
        try:
            with self.db_lock, self.conn.cursor() as cur:
                cur.execute("""
                    SELECT 
                        (SELECT COUNT(*) FROM alert_embeddings) as total_alerts,
                        (SELECT COUNT(*) FROM alert_embeddings WHERE embedding IS NOT NULL) as alerts_with_embeddings,
                        (SELECT COUNT(*) FROM custom_documents) as total_docs,
                        (SELECT COUNT(*) FROM custom_documents WHERE embedding IS NOT NULL) as docs_with_embeddings
                """)
                stats = cur.fetchone()
                ready = bool(stats and (stats[1] > 0 or stats[3] > 0))
                self.rag_ready = ready
                
                return {
                    "ready": ready,
                    "storage": "persistent_postgresql",
                    "total_alerts": stats[0],
                    "alerts_with_embeddings": stats[1],
                    "total_custom_docs": stats[2],
                    "docs_with_embeddings": stats[3],
                    "embedding_model": self.embedding_model,
                    "embedding_device": self.embedding_device,
                    "vector_dimensions": self.vector_dimensions,
                    "max_retrieval_docs": self.max_retrieval_docs
                }
        except Exception as e:
            self._rollback_safely()
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
    """Analyzes and processes security alert data with proper IP classification."""
    def __init__(self, geoip_db_path: str = None):
        self.geoip_db_path = geoip_db_path
        self.geoip_manager = GeoIPManager(geoip_db_path)
    
    # Local monitoring infrastructure that should not be treated as a threat.
    INTERNAL_INFRASTRUCTURE = {
        '192.168.56.104',  # Suricata NIDS sensor
        '192.168.56.1',    # Lab gateway
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
        """Classify IP address context for threat analysis."""
        if not ip_str:
            return "unknown"
        
        if AlertAnalyzer._is_infrastructure_ip(ip_str):
            return "infrastructure"
        elif AlertAnalyzer._is_internal_ip(ip_str):
            return "internal"
        else:
            return "external"
    
    @staticmethod
    def _extract_geolocation_with_geoip(data: Dict, ip_field: str, geoip_manager: GeoIPManager) -> Optional[Dict]:
        """Extract geolocation using GeoIP2 for external IPs."""
        ip_address = data.get(ip_field)
        if not ip_address:
            return None
        
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
    def analyze_current_alerts(alerts: List[Dict]) -> Dict[str, Any]:
        """Analyze current alerts for patterns and statistics."""
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
            
            # Source IP analysis, excluding infrastructure
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
            
            # Geolocation analysis for external IPs only
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
    

    def clean_log_data(self, logs: List[Dict]) -> List[Dict]:
        """Clean and minimize log data with enhanced context and proper IP classification"""
        cleaned_logs = []
        geoip_manager = GeoIPManager(self.geoip_db_path)  # Initialize GeoIP manager
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

            if root_data.get("_alert_uuid"):
                cleaned_log["alert_uuid"] = root_data.get("_alert_uuid")
            
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
        
        src_context = alert.get("src_ip_context", "unknown")
        dest_context = alert.get("dest_ip_context", "unknown")
        
        # Check if this is an infrastructure alert (should be low priority)
        if src_context == "infrastructure" or dest_context == "infrastructure":
            classification["is_infrastructure_alert"] = True
            classification["confidence"] = "low"
            classification["threat_direction"] = "infrastructure"
            return classification
        
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

    def _get_high_severity_threshold(self, trigger_info: Dict = None) -> int:
        if trigger_info and trigger_info.get("threshold") is not None:
            return RAGContextManager._safe_int(trigger_info.get("threshold"), 8)
        return 8

    def _alert_level(self, alert: Dict) -> int:
        return RAGContextManager._safe_int(alert.get("rule_level", 0), 0)

    def _select_representative_alerts(self, alerts: List[Dict], max_alerts: int = 12) -> List[Dict]:
        """Pick the most useful alerts for prompts/queries without assuming early alerts matter most."""
        if not alerts:
            return []

        indexed_alerts = list(enumerate(alerts))
        ranked_alerts = sorted(
            indexed_alerts,
            key=lambda item: (
                self._alert_level(item[1]),
                str(item[1].get("timestamp", "")),
                -item[0]
            ),
            reverse=True
        )

        selected = []
        seen = set()
        for original_index, alert in ranked_alerts:
            key = (
                str(alert.get("rule_id") or "").lower(),
                str(alert.get("rule_description") or "").lower(),
                str(alert.get("alert_signature") or "").lower(),
                str(alert.get("src_ip") or ""),
                str(alert.get("dest_ip") or "")
            )
            if key in seen:
                continue
            seen.add(key)
            selected.append({**alert, "_original_index": original_index + 1})
            if len(selected) >= max_alerts:
                break

        return selected or [dict(alerts[0], _original_index=1)]

    def _collect_alert_terms(self, alerts: List[Dict], max_alerts: int = 12) -> set:
        terms = set()
        for alert in self._select_representative_alerts(alerts, max_alerts=max_alerts):
            for field in ("rule_description", "alert_signature", "alert_category", "rule_id",
                          "src_ip", "dest_ip", "proto", "app_proto", "event_type", "direction"):
                value = alert.get(field)
                if value:
                    terms.update(
                        token.lower()
                        for token in re.findall(r"[A-Za-z0-9_.:/-]{4,}", str(value))
                    )
        return terms

    def _build_metadata_filter(self, alerts: List[Dict], is_automatic: bool = False,
                               trigger_info: Dict = None) -> Optional[Dict[str, Any]]:
        """Use archive metadata filters conservatively so retrieval stays relevant without going blind."""
        metadata_filter = {}
        levels = [self._alert_level(alert) for alert in alerts or []]
        max_level = max(levels) if levels else 0

        threshold = self._get_high_severity_threshold(trigger_info)
        if is_automatic and max_level >= threshold:
            metadata_filter["min_severity"] = threshold
        elif max_level >= 8:
            metadata_filter["min_severity"] = 5

        if trigger_info and trigger_info.get("timeframe_hours"):
            metadata_filter["timeframe_hours"] = RAGContextManager._safe_int(
                trigger_info.get("timeframe_hours"), 0
            )

        return metadata_filter or None

    def _create_current_alert_context(self, alerts: List[Dict], max_alerts: int = 12) -> str:
        representative = self._select_representative_alerts(alerts, max_alerts=max_alerts)
        compact_alerts = []
        for i, alert in enumerate(representative, 1):
            compact = {
                "representative_id": i,
                "original_batch_index": alert.get("_original_index", i),
                "level": self._alert_level(alert),
                "timestamp": alert.get("timestamp"),
                "rule_id": alert.get("rule_id"),
                "rule": alert.get("rule_description"),
                "signature": alert.get("alert_signature"),
                "category": alert.get("alert_category"),
                "src": alert.get("src_ip"),
                "dst": alert.get("dest_ip"),
                "proto": alert.get("proto"),
                "app_proto": alert.get("app_proto"),
                "event_type": alert.get("event_type"),
                "direction": alert.get("direction"),
                "http": alert.get("http_context"),
                "dns": alert.get("dns_context"),
                "tls": alert.get("tls_context"),
                "mitre": alert.get("mitre_context"),
                "threat_classification": alert.get("threat_classification")
            }
            compact_alerts.append({k: v for k, v in compact.items() if v not in (None, {}, [])})

        if not compact_alerts:
            return "No current alerts"

        return json.dumps(compact_alerts, indent=1)

    def _select_relevant_context_docs(self, docs: List[Any], current_alerts: List[Dict],
                                      max_docs: int = None, source_filter: str = None) -> List[Any]:
        if not docs:
            return []

        limit = max_docs or getattr(self.rag_manager, "max_retrieval_docs", 8)
        terms = self._collect_alert_terms(current_alerts)
        ranked = []

        for order, doc in enumerate(docs):
            if source_filter and isinstance(doc, dict) and doc.get("source") != source_filter:
                continue

            text = self._extract_context_text(doc)
            if not text:
                continue

            text_lower = text.lower()
            lexical_hits = sum(1 for term in terms if term in text_lower)
            similarity = 0.0
            if isinstance(doc, dict):
                similarity = float(doc.get("score") or 0.0)

            ranked.append((lexical_hits, similarity, -order, doc))

        ranked.sort(reverse=True, key=lambda item: item[:3])
        return [item[3] for item in ranked[:limit]]
    
    def generate_report_with_rag(self, current_alerts: List[Dict], server_host: str = "unknown", 
                             is_automatic: bool = False, trigger_info: Dict = None) -> str:
        """Generate threat analysis report using simplified severity-based RAG logic"""
        start_time = time.time()
        if not self.rag_manager.rag_ready:
            return " Error: RAG context not ready. Please build RAG context first."
        
        try:
            print(f"🧠 Generating report for {len(current_alerts)} current alerts with RAG...")
            
            # Clean current alerts
            cleaned_alerts = self.alert_analyzer.clean_log_data(current_alerts)
            
            # Check high severity alerts against the monitoring threshold for automatic reports.
            if is_automatic:
                threshold = self._get_high_severity_threshold(trigger_info)
                high_severity_alerts = [alert for alert in cleaned_alerts 
                                    if self._alert_level(alert) >= threshold]
                
                if high_severity_alerts:
                    # HIGH-SEVERITY AUTOMATIC: Use custom docs plus high-severity local history.
                    print(f" High-severity automatic report: Using custom docs and historical RAG for {len(high_severity_alerts)} alerts")
                    return self._generate_with_custom_docs_only(cleaned_alerts, high_severity_alerts, server_host, trigger_info)
            
            # MANUAL ANALYSIS or LOW-SEVERITY AUTOMATIC: Use full RAG context
            print(f"📊 Standard analysis: Using full RAG context for {len(cleaned_alerts)} alerts")
            return self._generate_with_full_rag(cleaned_alerts, server_host, is_automatic, trigger_info)
            
        except Exception as e:
            self.rag_manager._rollback_safely()
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
        """Generate high-severity automatic report with custom CTI and local historical context."""
        
        custom_docs = self._search_custom_doc_results(high_severity_alerts, k=4)
        historical_docs = self._search_historical_alert_results(high_severity_alerts, trigger_info, k=4)
        combined_context_docs = custom_docs + historical_docs
        custom_context = (
            self._format_context_docs(combined_context_docs, max_chars=900)
            if combined_context_docs
            else self._get_custom_docs_context(high_severity_alerts)
        )
        source_manifest = self._format_rag_sources(combined_context_docs)
        
        # Analyze current alerts
        analysis = self.alert_analyzer.analyze_current_alerts(all_alerts)
        
        # Create compact alert summary to prevent token overflow
        max_alerts_for_llm = 10
        compact_alerts = self._create_compact_alert_summary(high_severity_alerts, max_alerts_for_llm)
        more_alerts_count = max(0, len(high_severity_alerts) - max_alerts_for_llm)
        
        # Create context - NO INDENTATION ISSUES
        context = f"""ANALYSIS TYPE: HIGH-SEVERITY AUTOMATIC INCIDENT RESPONSE
    RAG STRATEGY: Custom Documentation + High-Severity Historical Alert Context

    CURRENT HIGH-SEVERITY INCIDENT DATA:
    - Total Alerts: {len(all_alerts)}
    - High-Severity Alerts (threshold >= {self._get_high_severity_threshold(trigger_info)}): {len(high_severity_alerts)}
    - Threat Distribution: {analysis['threat_classification']}

    HIGH-SEVERITY ALERTS (Compact View - Top {min(max_alerts_for_llm, len(high_severity_alerts))} of {len(high_severity_alerts)}):
    {compact_alerts}
    {f"... and {more_alerts_count} more high-severity alerts (similar patterns)" if more_alerts_count > 0 else ""}

    RAG REFERENCE CONTEXT:
    {custom_context}

    CONTEXT: This is an automatic high-severity incident requiring immediate response. Focus on current high-severity alerts while using uploaded CTI and local historical alert patterns as supporting evidence.
    INSTRUCTIONS: When using RAG evidence, cite the bracketed source label such as [RAG-1]."""
        
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
    High-Severity Alerts: {trigger_info.get('high_severity_count', 0)}  
    Total Alerts Analyzed: {trigger_info.get('total_alerts', len(all_alerts))}  
    Server: {server_host}  
    RAG Strategy: Custom Docs + High-Severity Historical Context  
    Response Priority: {trigger_info.get('response_priority', 'IMMEDIATE')}  

    Triggered High Severity Alerts
    """
            # Add triggered alerts summary
            for i, alert in enumerate(trigger_info.get('triggered_alerts', []), 1):
                level = alert.get("rule_level", 0)
                desc = alert.get("rule_description", "Unknown")
                alert_timestamp = alert.get("timestamp", "Unknown")
                priority_marker = "🔥" if level >= self._get_high_severity_threshold(trigger_info) else "⚡"
                report_header += f"{i}. {priority_marker} Level {level} - {desc} ({alert_timestamp})\n"
            
            if trigger_info.get('trigger_count', 0) > 5:
                remaining = trigger_info.get('trigger_count', 0) - 5
                report_header += f"   ... and {remaining} more HIGH severity alerts\n"
            
            report_header += "\n---\n\n"
        else:
            # Manual report header
            report_header = f"""# 🚨 HIGH-SEVERITY INCIDENT REPORT

    Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  
    High-Severity Alerts: {len(high_severity_alerts)} (Level >= {self._get_high_severity_threshold(trigger_info)})  
    Total Alerts: {len(all_alerts)}  
    Server: {server_host}  
    RAG Mode: Custom Docs + High-Severity Historical Context  

    ---

    """
        return report_header + report_content + source_manifest

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
        
        metadata_filter = self._build_metadata_filter(cleaned_alerts, is_automatic, trigger_info)
        retriever = self.rag_manager.get_retriever(metadata_filter=metadata_filter)
        if not retriever:
            return "❌ Error: RAG retriever not available."
        
        query_text = self._build_query_from_alerts(cleaned_alerts)
        relevant_docs = retriever(query_text)
        context_docs = self._select_relevant_context_docs(
            relevant_docs,
            cleaned_alerts,
            max_docs=min(getattr(self.rag_manager, "max_retrieval_docs", 8), 8)
        )
        full_rag_context = (
            self._format_context_docs(context_docs, max_chars=900)
            if context_docs
            else "No directly relevant historical patterns found."
        )
        source_manifest = self._format_rag_sources(context_docs)
        
        # Analyze current alerts
        analysis = self.alert_analyzer.analyze_current_alerts(cleaned_alerts)
        
        # Create context - NO INDENTATION ISSUES
        analysis_type = "MANUAL ANALYSIS" if not is_automatic else "AUTOMATIC STANDARD ANALYSIS"
        
        context = f"""ANALYSIS TYPE: {analysis_type}
    RAG STRATEGY: Full Context (Historical Alerts + Custom Documentation)

    CURRENT ALERTS DATA:
    - Total Alerts: {len(cleaned_alerts)}
    - Representative Alerts Shown: {min(12, len(cleaned_alerts))}
    - Severity Distribution: {analysis['severity_breakdown']}
    - Threat Classification: {analysis['threat_classification']}
    - Archive Metadata Filter: {metadata_filter or "none"}

    REPRESENTATIVE CURRENT ALERTS:
    {self._create_current_alert_context(cleaned_alerts, max_alerts=12)}

    HISTORICAL AND CUSTOM REFERENCE CONTEXT:
    {full_rag_context}

    CONTEXT: {"Manual security analysis with comprehensive context." if not is_automatic else "Automatic analysis for standard-severity incidents."}
    INSTRUCTIONS: When using RAG evidence, cite the bracketed source label such as [RAG-1]."""
        
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
        
        return report_header + report_content + source_manifest

    def _create_compact_alert_summary(self, alerts: List[Dict], max_alerts: int = 10) -> str:
        """Create a compact summary of alerts to reduce token usage"""
        sample = self._select_representative_alerts(alerts, max_alerts=max_alerts)
        summaries = []
        
        for i, alert in enumerate(sample, 1):
            timestamp = alert.get("timestamp")
            compact = {
                "id": i,
                "level": alert.get("rule_level", 0),
                "rule": str(alert.get("rule_description") or "Unknown")[:80],
                "src": alert.get("src_ip") or "?",
                "dst": alert.get("dest_ip") or "?",
                "time": str(timestamp)[:19] if timestamp else "?"
            }
            
            # Add key context if available
            signature = alert.get("alert_signature")
            if signature:
                compact["sig"] = str(signature)[:60]
            
            summaries.append(compact)
        
        return json.dumps(summaries, indent=1)

    def _search_custom_doc_results(self, alerts: List[Dict], k: int = 4) -> List[Dict[str, Any]]:
        if not hasattr(self.rag_manager, "search_custom_documents"):
            return []

        try:
            return self.rag_manager.search_custom_documents(self._build_query_from_alerts(alerts), k=k)
        except Exception as e:
            self.rag_manager._rollback_safely()
            print(f"WARNING: Custom document search failed: {e}")
            return []

    def _search_historical_alert_results(self, alerts: List[Dict], trigger_info: Dict = None,
                                         k: int = 4) -> List[Dict[str, Any]]:
        try:
            metadata_filter = self._build_metadata_filter(alerts, is_automatic=True, trigger_info=trigger_info)
            query_text = self._build_query_from_alerts(alerts)
            if hasattr(self.rag_manager, "search_archive_alerts"):
                docs = self.rag_manager.search_archive_alerts(query_text, k=k, metadata_filter=metadata_filter)
                return self._select_relevant_context_docs(docs, alerts, max_docs=k)

            retriever = self.rag_manager.get_retriever(k=max(k * 2, k), metadata_filter=metadata_filter)
            docs = retriever(query_text)
            return self._select_relevant_context_docs(
                docs,
                alerts,
                max_docs=k,
                source_filter="archive"
            )
        except Exception as e:
            self.rag_manager._rollback_safely()
            print(f"WARNING: Historical alert retrieval failed: {e}")
            return []
    
    def _get_custom_docs_context(self, high_severity_alerts: List[Dict]) -> str:
        """Get context from custom documents only"""
        db_docs = self._search_custom_doc_results(high_severity_alerts, k=4)
        db_context = self._format_context_docs(db_docs, max_chars=800)
        if db_context:
            return db_context

        if not hasattr(self.rag_manager, 'custom_docs') or not self.rag_manager.custom_docs:
            return "No custom threat intelligence documentation available."
        
        # Fallback for documents added during the current process but not searched from DB.
        query_terms = self._collect_alert_terms(high_severity_alerts)
        
        relevant_content = []
        for doc in self.rag_manager.custom_docs:
            doc_lower = doc.lower()
            relevance = sum(1 for term in query_terms if term in doc_lower and len(term) > 3)
            if relevance > 0:
                content = doc[:800] + "..." if len(doc) > 800 else doc
                relevant_content.append(content)
        
        return "\n\n".join(relevant_content[:4]) if relevant_content else "No directly relevant custom documentation found."

    def _extract_context_text(self, doc: Any) -> str:
        """Support pgvector dict results, document-like objects, and plain strings."""
        if isinstance(doc, dict):
            return str(doc.get("content") or doc.get("page_content") or "")
        if hasattr(doc, "page_content"):
            return str(doc.page_content or "")
        return str(doc or "")

    def _format_doc_metadata(self, doc: Any) -> str:
        if not isinstance(doc, dict):
            return "source=inline"

        metadata = doc.get("metadata") or {}
        source = doc.get("source") or "unknown"
        score = doc.get("score")
        parts = [f"source={source}"]
        if score is not None:
            try:
                parts.append(f"score={float(score):.3f}")
            except (TypeError, ValueError):
                parts.append(f"score={score}")

        for key in ("filename", "source_document", "chunk_index", "chunk_count",
                    "severity", "rule_id", "timestamp", "agent_name"):
            value = metadata.get(key)
            if value not in (None, "", [], {}):
                parts.append(f"{key}={value}")

        return "; ".join(parts)

    def _format_context_docs(self, docs: List[Any], max_chars: int = 800) -> str:
        chunks = []
        for i, doc in enumerate(docs, 1):
            text = self._extract_context_text(doc).strip()
            if not text:
                continue
            excerpt = text[:max_chars] + ("..." if len(text) > max_chars else "")
            chunks.append(f"[RAG-{i}] {self._format_doc_metadata(doc)}\n{excerpt}")
        return "\n\n".join(chunks)

    def _format_rag_sources(self, docs: List[Any]) -> str:
        if not docs:
            return ""

        lines = ["", "---", "", "## RAG Sources Used"]
        for i, doc in enumerate(docs, 1):
            lines.append(f"- [RAG-{i}] {self._format_doc_metadata(doc)}")
        return "\n".join(lines)

    def _build_query_from_alerts(self, alerts: List[Dict]) -> str:
        """Build query from representative alerts across the whole batch."""
        query_parts = []
        for alert in self._select_representative_alerts(alerts, max_alerts=12):
            for field in ("rule_description", "alert_signature", "alert_category", "rule_id",
                          "src_ip", "dest_ip", "proto", "app_proto", "event_type", "direction"):
                if alert.get(field):
                    query_parts.append(str(alert[field]))

            mitre_context = alert.get("mitre_context") or {}
            if isinstance(mitre_context, dict):
                for value in mitre_context.values():
                    if value:
                        query_parts.append(str(value))
        
        return " ".join(query_parts) if query_parts else "security incident analysis"
    
    def _filter_relevant_context(self, docs: List, current_alerts: List[Dict]) -> str:
        """Filter and format RAG context while preserving useful source metadata."""
        if not docs or not current_alerts:
            return "No relevant historical context found."

        selected_docs = self._select_relevant_context_docs(
            docs,
            current_alerts,
            max_docs=min(getattr(self.rag_manager, "max_retrieval_docs", 8), 8)
        )
        if selected_docs:
            return self._format_context_docs(selected_docs, max_chars=800)
        return "No directly relevant historical patterns found."
    
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
                threshold = self._get_high_severity_threshold(trigger_info)
                high_severity_alerts = [alert for alert in cleaned_alerts 
                                    if self._alert_level(alert) >= threshold]
                
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
            self.rag_manager._rollback_safely()
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
    
    def __init__(self, llm_config, templates_dir: str, reports_dir: str = None, db_config: dict = None,
                 rag_config=None, geoip_db_path: str = None):
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
        
        self.rag_manager = RAGContextManager(db_config, rag_config)
        self.alert_analyzer = AlertAnalyzer(geoip_db_path)
        
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
            "reports_approved": 0,
            "total_generation_time": 0.0,
            "avg_generation_time": 0.0,
            "min_generation_time": float('inf'),
            "max_generation_time": 0.0,
            "last_approval_time": None,
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
        start_time = time.time()
        report_type = "automatic" if is_automatic else "manual"
        
        try:
            report_content = self.report_formatter.generate_report_with_rag(current_alerts, server_host, is_automatic, trigger_info)
            
            generation_time = time.time() - start_time
            self._update_report_metrics(generation_time, report_type, success=True)
            
            print(f"⏱️ Report generated in {generation_time:.2f} seconds ({report_type})")
            
            return report_content
        except Exception as e:
            generation_time = time.time() - start_time
            self._update_report_metrics(generation_time, report_type, success=False)
            raise
    
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

    def mark_report_approved(self):
        """Track human approval of a report in runtime metrics."""
        self.report_metrics["reports_approved"] += 1
        self.report_metrics["last_approval_time"] = datetime.now().isoformat()
        print(f"SUCCESS: Report approval recorded ({self.report_metrics['reports_approved']} total)")

    def generate_visual_report(self, alerts: List[Dict], output_path: str) -> Optional[str]:
        """Generate and save a charts-only markdown report."""
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)

        cleaned_alerts = (
            alerts
            if alerts and isinstance(alerts[0], dict) and "threat_classification" in alerts[0]
            else self.alert_analyzer.clean_log_data(alerts)
        )

        if not cleaned_alerts:
            return None

        chart_prefix = output_file.stem
        chart_paths = self.report_formatter.chart_generator.generate_ip_analysis_charts(
            cleaned_alerts, chart_prefix
        )

        if len(cleaned_alerts) > 5:
            timeline_path = self.report_formatter.chart_generator.generate_severity_timeline(
                cleaned_alerts, chart_prefix
            )
            if timeline_path:
                chart_paths.append(timeline_path)

        if not chart_paths:
            return None

        analysis = self.alert_analyzer.analyze_current_alerts(cleaned_alerts)
        markdown = [
            "# SOC Visual Threat Analysis\n\n",
            f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  \n",
            f"**Alerts Analyzed:** {len(cleaned_alerts)}  \n",
            "**Report Type:** Charts-only visual analysis\n\n",
            "---\n\n",
            "## Summary\n\n",
            f"- Severity distribution: {analysis.get('severity_breakdown', {})}\n",
            f"- Threat classification: {analysis.get('threat_classification', {})}\n",
            f"- Top external sources: {analysis.get('top_external_sources', {})}\n",
            f"- Top internal sources: {analysis.get('top_internal_sources', {})}\n\n",
            "## Charts\n\n"
        ]

        for chart_path in chart_paths:
            chart_filename = Path(chart_path).name
            markdown.append(f"### {chart_filename.replace('_', ' ').title()}\n\n")
            markdown.append(f"![Chart](./charts/{chart_filename})\n\n")

        markdown.extend([
            "---\n\n",
            "**Analysis Complete**\n",
            f"Report generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        ])

        output_file.write_text("".join(markdown), encoding="utf-8")
        print(f"SUCCESS: Visual report saved: {output_file.name}")
        return str(output_file)
    
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
