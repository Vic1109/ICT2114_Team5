import json
import re
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional, Iterable
import geoip2.database
import geoip2.errors
import ipaddress
from charts import SOCChartGenerator
from llm_client import ChatTemplateManager, LlamaModelClient
import psycopg2
from psycopg2 import sql
from psycopg2.extras import execute_values
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
import hashlib
from sentence_transformers import SentenceTransformer
import time
import threading
from cti_artifacts import CTIArtifactExtractor


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

class RAGContextManager:
    """Manages RAG context including vector store and embeddings"""
    def __init__(self, db_config: dict, rag_config=None):
        self.db_config = dict(db_config)
        self.rag_config = rag_config
        self.embedding_model = getattr(rag_config, "embedding_model", "Qwen/Qwen3-Embedding-0.6B")
        self.embedding_device = getattr(rag_config, "embedding_device", "cpu")
        self.vector_dimensions = int(getattr(rag_config, "embedding_dimensions", 1024))
        self.chunk_size = int(getattr(rag_config, "chunk_size", 500))
        self.chunk_overlap = int(getattr(rag_config, "chunk_overlap", 50))
        self.document_chunk_size = int(getattr(rag_config, "document_chunk_size", max(self.chunk_size, 1200)))
        self.document_chunk_overlap = int(getattr(rag_config, "document_chunk_overlap", max(self.chunk_overlap, 120)))
        self.max_retrieval_docs = int(getattr(rag_config, "max_retrieval_docs", 10))
        self.normalize_embeddings = bool(getattr(rag_config, "normalize_embeddings", False))
        self.similarity_threshold = float(getattr(rag_config, "similarity_threshold", 0.2))
        self.embedding_batch_size = max(1, int(getattr(rag_config, "embedding_batch_size", 32)))
        self.embedding_devices = self._normalize_embedding_devices(
            getattr(rag_config, "embedding_devices", None)
        )
        self.embedding_multi_gpu_min_chunks = max(
            2,
            int(getattr(rag_config, "embedding_multi_gpu_min_chunks", 64))
        )
        self.retrieval_candidate_multiplier = max(
            1,
            int(getattr(rag_config, "retrieval_candidate_multiplier", 4))
        )
        self.embedding_query_instruction = str(
            getattr(
                rag_config,
                "embedding_query_instruction",
                "Retrieve cybersecurity incidents, IoCs, TTPs, and CTI passages relevant to this SOC alert."
            ) or ""
        ).strip()
        self.embedding_document_instruction = str(
            getattr(rag_config, "embedding_document_instruction", "") or ""
        ).strip()
        self.db_lock = threading.RLock()
        self.conn = self._connect_with_database_bootstrap(db_config)
        self.embeddings = SentenceTransformer(self.embedding_model, device=self.embedding_device) 
        if hasattr(self.embeddings, '_target_device'):
            self.embeddings._target_device = self.embedding_device
        if len(self.embedding_devices) > 1:
            print(
                "Bulk embedding multi-GPU devices configured: "
                f"{', '.join(self.embedding_devices)} "
                f"(min chunks: {self.embedding_multi_gpu_min_chunks})"
            )
        self._init_schema()
        self.rag_ready = self._check_ready()

    @staticmethod
    def _normalize_embedding_devices(value: Any) -> List[str]:
        if not value:
            return []
        if isinstance(value, str):
            devices = [item.strip() for item in value.split(",")]
        elif isinstance(value, (list, tuple, set)):
            devices = [str(item).strip() for item in value]
        else:
            return []

        normalized = []
        seen = set()
        for device in devices:
            if not device:
                continue
            key = device.lower()
            if key in seen:
                continue
            seen.add(key)
            normalized.append(device)
        return normalized

    @staticmethod
    def _is_missing_database_error(error: Exception) -> bool:
        if getattr(error, "pgcode", None) == "3D000":
            return True

        message = str(error).lower()
        return "database" in message and "does not exist" in message

    @classmethod
    def _connect_with_database_bootstrap(cls, db_config: dict):
        try:
            return psycopg2.connect(**db_config)
        except psycopg2.OperationalError as error:
            if not cls._is_missing_database_error(error):
                raise

            database_name = db_config.get("database") or db_config.get("dbname")
            if not database_name:
                raise

            print(f"Database '{database_name}' does not exist. Creating it for this environment...")
            cls._create_database(db_config, database_name)
            return psycopg2.connect(**db_config)

    @staticmethod
    def _create_database(db_config: dict, database_name: str):
        admin_config = dict(db_config)
        admin_config.pop("database", None)
        admin_config.pop("dbname", None)

        last_error = None
        for maintenance_db in ("postgres", "template1"):
            try:
                admin_conn = psycopg2.connect(**admin_config, database=maintenance_db)
                admin_conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
                try:
                    with admin_conn.cursor() as cur:
                        cur.execute(
                            sql.SQL("CREATE DATABASE {}").format(
                                sql.Identifier(database_name)
                            )
                        )
                    print(f"Created PostgreSQL database '{database_name}'.")
                    return
                finally:
                    admin_conn.close()
            except psycopg2.errors.DuplicateDatabase:
                print(f"PostgreSQL database '{database_name}' already exists.")
                return
            except psycopg2.OperationalError as error:
                last_error = error
                continue
            except psycopg2.Error as error:
                raise RuntimeError(
                    f"Database '{database_name}' does not exist and could not be created. "
                    "Ensure the configured PostgreSQL user has CREATEDB permission, or create "
                    "the database manually."
                ) from error

        raise RuntimeError(
            f"Database '{database_name}' does not exist and the maintenance databases "
            f"'postgres' and 'template1' could not be reached: {last_error}"
        )

    @staticmethod
    def _drop_database(db_config: dict, database_name: str):
        admin_config = dict(db_config)
        admin_config.pop("database", None)
        admin_config.pop("dbname", None)

        last_error = None
        for maintenance_db in ("postgres", "template1"):
            try:
                admin_conn = psycopg2.connect(**admin_config, database=maintenance_db)
                admin_conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
                try:
                    with admin_conn.cursor() as cur:
                        cur.execute(
                            """
                            SELECT pg_terminate_backend(pid)
                            FROM pg_stat_activity
                            WHERE datname = %s
                            AND pid <> pg_backend_pid()
                            """,
                            (database_name,)
                        )
                        cur.execute(
                            sql.SQL("DROP DATABASE IF EXISTS {}").format(
                                sql.Identifier(database_name)
                            )
                        )
                    print(f"Dropped PostgreSQL database '{database_name}'.")
                    return
                finally:
                    admin_conn.close()
            except psycopg2.OperationalError as error:
                last_error = error
                continue
            except psycopg2.Error as error:
                raise RuntimeError(
                    f"Database '{database_name}' could not be dropped. Ensure the configured "
                    "PostgreSQL user has permission to terminate connections and drop databases."
                ) from error

        raise RuntimeError(
            f"Database '{database_name}' could not be dropped because the maintenance databases "
            f"'postgres' and 'template1' could not be reached: {last_error}"
        )

    def clear_database(self) -> Dict[str, Any]:
        """Drop and recreate the configured database for testing resets."""
        database_name = self.db_config.get("database") or self.db_config.get("dbname")
        if not database_name:
            raise RuntimeError("Cannot clear RAG context because the database name is not configured.")

        with self.db_lock:
            try:
                if self.conn:
                    self.conn.close()
                self.conn = None

                self._drop_database(self.db_config, database_name)
                self._create_database(self.db_config, database_name)
                self.conn = self._connect_with_database_bootstrap(self.db_config)
                self._init_schema()
                self.rag_ready = False
                if hasattr(self, "custom_docs"):
                    self.custom_docs = []

                return {
                    "success": True,
                    "ready": False,
                    "database": database_name,
                    "message": f"Database '{database_name}' was dropped and recreated."
                }
            except Exception:
                if self.conn is None or getattr(self.conn, "closed", 1):
                    try:
                        self.conn = self._connect_with_database_bootstrap(self.db_config)
                    except Exception:
                        pass
                self.rag_ready = False
                raise

    @staticmethod
    def _safe_int(value: Any, default: int = 0) -> int:
        try:
            return int(value) if value is not None else default
        except (TypeError, ValueError):
            return default

    @staticmethod
    def _strip_nul_chars(value: Any) -> Any:
        """PostgreSQL text/jsonb values cannot contain NUL bytes."""
        if isinstance(value, str):
            return value.replace("\x00", "")
        if isinstance(value, dict):
            return {
                RAGContextManager._strip_nul_chars(k): RAGContextManager._strip_nul_chars(v)
                for k, v in value.items()
            }
        if isinstance(value, list):
            return [RAGContextManager._strip_nul_chars(item) for item in value]
        if isinstance(value, tuple):
            return tuple(RAGContextManager._strip_nul_chars(item) for item in value)
        return value

    def _rollback_safely(self):
        try:
            self.conn.rollback()
        except Exception:
            pass

    @staticmethod
    def _normalize_for_embedding(text: Any, max_chars: int = 6000) -> str:
        normalized = re.sub(r"\s+", " ", str(text or "")).strip()
        if len(normalized) > max_chars:
            return normalized[:max_chars].rstrip()
        return normalized

    def _prepare_embedding_inputs(self, texts: List[str], is_query: bool = False) -> List[str]:
        instruction = (
            self.embedding_query_instruction
            if is_query
            else self.embedding_document_instruction
        )
        prepared = []
        for text in texts:
            normalized = self._normalize_for_embedding(text)
            if instruction:
                prepared.append(f"Instruction: {instruction}\nInput: {normalized}")
            else:
                prepared.append(normalized)
        return prepared

    def _should_use_multi_gpu_encoding(self, text_count: int, is_query: bool) -> bool:
        if is_query:
            return False
        if text_count < self.embedding_multi_gpu_min_chunks:
            return False
        return len(self.embedding_devices) > 1

    def _encode_texts_multi_gpu(self, prepared_texts: List[str]):
        pool = None
        try:
            print(
                f"Encoding {len(prepared_texts)} chunks across "
                f"{len(self.embedding_devices)} GPUs: {', '.join(self.embedding_devices)}"
            )
            pool = self.embeddings.start_multi_process_pool(self.embedding_devices)
            try:
                return self.embeddings.encode_multi_process(
                    prepared_texts,
                    pool,
                    batch_size=self.embedding_batch_size,
                    normalize_embeddings=self.normalize_embeddings
                )
            except TypeError:
                return self.embeddings.encode_multi_process(
                    prepared_texts,
                    pool,
                    batch_size=self.embedding_batch_size
                )
        finally:
            if pool is not None:
                self.embeddings.stop_multi_process_pool(pool)

    def _encode_texts_single_device(self, prepared_texts: List[str]):
        return self.embeddings.encode(
            prepared_texts,
            show_progress_bar=len(prepared_texts) > 1,
            normalize_embeddings=self.normalize_embeddings,
            batch_size=self.embedding_batch_size
        )

    def _encode_texts(self, texts: List[str], is_query: bool = False):
        prepared_texts = self._prepare_embedding_inputs(list(texts), is_query=is_query)
        if not prepared_texts:
            return []
        if self._should_use_multi_gpu_encoding(len(prepared_texts), is_query):
            try:
                return self._encode_texts_multi_gpu(prepared_texts)
            except Exception as e:
                print(f"WARNING: Multi-GPU embedding failed; falling back to {self.embedding_device}: {e}")
        return self._encode_texts_single_device(prepared_texts)

    def _to_vector_literal(self, embedding: Any) -> str:
        values = embedding.tolist() if hasattr(embedding, "tolist") else list(embedding)
        if len(values) != self.vector_dimensions:
            raise ValueError(
                f"Embedding dimension mismatch: expected {self.vector_dimensions}, got {len(values)}"
            )
        return "[" + ",".join(str(float(value)) for value in values) + "]"

    @staticmethod
    def _parse_event_timestamp(value: Any):
        if not value:
            return None
        text = str(value).strip()
        if not text:
            return None
        try:
            return datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            return None

    @staticmethod
    def _first_dict(value: Any) -> Dict[str, Any]:
        if isinstance(value, dict):
            return value
        if isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    return item
        return {}

    @staticmethod
    def _append_part(parts: List[str], label: str, value: Any):
        if value in (None, "", [], {}):
            return
        if isinstance(value, list):
            value = ", ".join(str(item) for item in value if item not in (None, "", [], {}))
        if isinstance(value, dict):
            value = json.dumps(value, sort_keys=True, default=str)
        text = str(value).strip()
        if text:
            parts.append(f"{label}: {text}")

    @staticmethod
    def _stable_json_hash(value: Any) -> str:
        return hashlib.sha256(
            json.dumps(value, sort_keys=True, default=str).encode("utf-8")
        ).hexdigest()

    def _split_oversized_text(self, text: str, chunk_size: int = None, chunk_overlap: int = None) -> List[str]:
        """Split text that has no useful paragraph/sentence boundaries."""
        chunk_size = chunk_size or self.chunk_size
        chunk_overlap = self.chunk_overlap if chunk_overlap is None else chunk_overlap
        chunks = []
        step = max(1, chunk_size - chunk_overlap)
        for start in range(0, len(text), step):
            chunk = text[start:start + chunk_size].strip()
            if chunk:
                chunks.append(chunk)
            if start + chunk_size >= len(text):
                break
        return chunks

    def _split_long_paragraph(self, paragraph: str, chunk_size: int = None, chunk_overlap: int = None) -> List[str]:
        chunk_size = chunk_size or self.chunk_size
        chunk_overlap = self.chunk_overlap if chunk_overlap is None else chunk_overlap
        sentences = [
            sentence.strip()
            for sentence in re.split(r"(?<=[.!?])\s+", paragraph)
            if sentence.strip()
        ]
        if len(sentences) <= 1:
            return self._split_oversized_text(paragraph, chunk_size, chunk_overlap)

        chunks = []
        current = ""
        for sentence in sentences:
            if len(sentence) > chunk_size:
                if current:
                    chunks.append(current.strip())
                    current = ""
                chunks.extend(self._split_oversized_text(sentence, chunk_size, chunk_overlap))
                continue

            candidate = f"{current} {sentence}".strip() if current else sentence
            if len(candidate) <= chunk_size:
                current = candidate
            else:
                if current:
                    chunks.append(current.strip())
                current = sentence

        if current:
            chunks.append(current.strip())
        return chunks

    def _chunk_text(self, text: str, chunk_size: int = None, chunk_overlap: int = None) -> List[str]:
        """Create paragraph-aware chunks for embedding without discarding overlap entirely."""
        chunk_size = chunk_size or self.chunk_size
        chunk_overlap = self.chunk_overlap if chunk_overlap is None else chunk_overlap
        text = text.strip()
        if not text:
            return []
        if len(text) <= chunk_size:
            return [text]

        paragraphs = [
            paragraph.strip()
            for paragraph in re.split(r"\n\s*\n+", text)
            if paragraph.strip()
        ]
        if not paragraphs:
            return self._split_oversized_text(text, chunk_size, chunk_overlap)

        chunks = []
        current_parts = []
        current_len = 0

        for paragraph in paragraphs:
            paragraph_chunks = (
                [paragraph]
                if len(paragraph) <= chunk_size
                else self._split_long_paragraph(paragraph, chunk_size, chunk_overlap)
            )

            for part in paragraph_chunks:
                separator_len = 2 if current_parts else 0
                if current_parts and current_len + separator_len + len(part) > chunk_size:
                    chunks.append("\n\n".join(current_parts).strip())

                    overlap_parts = []
                    overlap_len = 0
                    for previous in reversed(current_parts):
                        previous_len = len(previous) + (2 if overlap_parts else 0)
                        if overlap_len + previous_len > chunk_overlap:
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

    @staticmethod
    def _detect_section_heading(paragraph: str) -> Optional[tuple[int, str]]:
        """Detect likely CTI section headings from Markdown, PDFs, and plain text."""
        lines = [line.strip() for line in str(paragraph or "").splitlines() if line.strip()]
        if not lines:
            return None
        if len(lines) > 3:
            return None

        first = re.sub(r"\s+", " ", lines[0]).strip()
        if re.fullmatch(r"-{3,}\s*Page\s+\d+\s*-{3,}", first, flags=re.IGNORECASE):
            return None

        markdown = re.match(r"^(#{1,6})\s+(.+?)\s*$", first)
        if markdown:
            return len(markdown.group(1)), markdown.group(2).strip(" #:")

        numbered = re.match(r"^(\d+(?:\.\d+){0,4})[.)]?\s+(.+?)\s*$", first)
        if numbered and len(first) <= 120:
            level = min(6, numbered.group(1).count(".") + 1)
            return level, numbered.group(2).strip(" :")

        keyword_heading = re.search(
            r"\b(?:indicator|ioc|infrastructure|victim|target|ttp|technique|"
            r"mitre|attribution|actor|campaign|malware|remediation|mitigation|"
            r"detection|recommendation|timeline|overview|summary|analysis)\b",
            first,
            flags=re.IGNORECASE,
        )
        sentence_like = bool(re.search(r"[.!?]\s+\w", first))
        if len(first) <= 90 and keyword_heading and not sentence_like:
            return 2, first.strip(" :")

        if len(first) <= 70 and first.endswith(":") and keyword_heading:
            return 3, first.strip(" :")

        return None

    @staticmethod
    def _update_section_stack(stack: List[tuple[int, str]], level: int, heading: str) -> List[tuple[int, str]]:
        stack = [item for item in stack if item[0] < level]
        stack.append((level, heading))
        return stack[-6:]

    def _chunk_text_with_sections(
        self,
        text: str,
        chunk_size: int = None,
        chunk_overlap: int = None,
    ) -> List[Dict[str, Any]]:
        """Create chunks while carrying the nearest section heading path."""
        chunk_size = chunk_size or self.document_chunk_size
        chunk_overlap = self.document_chunk_overlap if chunk_overlap is None else chunk_overlap
        text = str(text or "").strip()
        if not text:
            return []

        paragraphs = [
            paragraph.strip()
            for paragraph in re.split(r"\n\s*\n+", text)
            if paragraph.strip()
        ]
        if not paragraphs:
            return [{"text": chunk, "section_path": "", "section_heading": ""} for chunk in self._chunk_text(text, chunk_size, chunk_overlap)]

        entries = []
        section_stack: List[tuple[int, str]] = []
        for paragraph in paragraphs:
            heading = self._detect_section_heading(paragraph)
            if heading:
                section_stack = self._update_section_stack(section_stack, heading[0], heading[1])

            section_path = " > ".join(item[1] for item in section_stack)
            parts = (
                [paragraph]
                if len(paragraph) <= chunk_size
                else self._split_long_paragraph(paragraph, chunk_size, chunk_overlap)
            )
            for part in parts:
                entries.append({
                    "text": part,
                    "section_path": section_path,
                    "section_heading": section_stack[-1][1] if section_stack else "",
                })

        chunks: List[Dict[str, Any]] = []
        current_entries: List[Dict[str, Any]] = []
        current_len = 0

        for entry in entries:
            part = entry["text"]
            separator_len = 2 if current_entries else 0
            if current_entries and current_len + separator_len + len(part) > chunk_size:
                chunk_text = "\n\n".join(item["text"] for item in current_entries).strip()
                section_path = next((item.get("section_path", "") for item in reversed(current_entries) if item.get("section_path")), "")
                chunks.append({
                    "text": chunk_text,
                    "section_path": section_path,
                    "section_heading": section_path.split(" > ")[-1] if section_path else "",
                })

                overlap_entries: List[Dict[str, Any]] = []
                overlap_len = 0
                for previous in reversed(current_entries):
                    previous_len = len(previous["text"]) + (2 if overlap_entries else 0)
                    if overlap_len + previous_len > chunk_overlap:
                        break
                    overlap_entries.insert(0, previous)
                    overlap_len += previous_len

                current_entries = overlap_entries
                current_len = sum(len(item["text"]) for item in current_entries) + max(0, len(current_entries) - 1) * 2

            current_entries.append(entry)
            current_len += len(part) + (2 if len(current_entries) > 1 else 0)

        if current_entries:
            chunk_text = "\n\n".join(item["text"] for item in current_entries).strip()
            section_path = next((item.get("section_path", "") for item in reversed(current_entries) if item.get("section_path")), "")
            chunks.append({
                "text": chunk_text,
                "section_path": section_path,
                "section_heading": section_path.split(" > ")[-1] if section_path else "",
            })

        return [chunk for chunk in chunks if chunk.get("text")]
    
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
                    event_timestamp TIMESTAMPTZ,
                    expires_at TIMESTAMP  -- Auto-expire old alerts
                );

                ALTER TABLE alert_embeddings
                ADD COLUMN IF NOT EXISTS event_timestamp TIMESTAMPTZ;
                 
                -- Index for fast similarity search
                CREATE INDEX IF NOT EXISTS alert_embedding_idx 
                ON alert_embeddings USING ivfflat (embedding vector_cosine_ops)
                WITH (lists = 100);
                
                -- Index for metadata filtering
                CREATE INDEX IF NOT EXISTS alert_metadata_idx 
                ON alert_embeddings USING gin (metadata);

                CREATE INDEX IF NOT EXISTS alert_event_timestamp_idx
                ON alert_embeddings (event_timestamp);

                CREATE INDEX IF NOT EXISTS alert_content_fts_idx
                ON alert_embeddings USING gin (
                    to_tsvector('simple', coalesce(content, '') || ' ' || coalesce(metadata::text, ''))
                );
            """)
            
            cur.execute(f"""
                CREATE TABLE IF NOT EXISTS custom_documents (
                    id SERIAL PRIMARY KEY,
                    doc_hash VARCHAR(64) UNIQUE,
                    filename VARCHAR(255),
                    content TEXT NOT NULL,
                    embedding vector({self.vector_dimensions}),
                    metadata JSONB,
                    event_timestamp TIMESTAMPTZ,
                    created_at TIMESTAMP DEFAULT NOW()
                );

                ALTER TABLE custom_documents
                ADD COLUMN IF NOT EXISTS event_timestamp TIMESTAMPTZ;
                 
                CREATE INDEX IF NOT EXISTS doc_embedding_idx 
                ON custom_documents USING ivfflat (embedding vector_cosine_ops)
                WITH (lists = 100);

                CREATE INDEX IF NOT EXISTS doc_content_fts_idx
                ON custom_documents USING gin (
                    to_tsvector('simple', coalesce(content, '') || ' ' || coalesce(metadata::text, ''))
                );
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
                    print(f"RAG ready: {result[0]} alert embeddings, {result[1]} custom document chunk embeddings")
                    return True
                return False
        except Exception as e:
            self._rollback_safely()
            print(f"WARNING: RAG readiness check failed: {e}")
            return False
        
    def build_rag_context(self, archive_logs: List[Dict] = None, custom_docs: List[Any] = None):
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
            root_data = log.get("_source", log) if isinstance(log, dict) else {}
            data = root_data.get("data", {}) or {}
            rule = root_data.get("rule", {}) or {}
            alert = data.get("alert", {}) or {}
            http_data = data.get("http", {}) or {}
            dns_data = data.get("dns", {}) or {}
            tls_data = data.get("tls", {}) or {}
            ioc_data = data.get("ioc", {}) or {}
            process_data = data.get("process", {}) or {}
            threat_data = data.get("threat", {}) or {}
            flow_data = data.get("flow", {}) or {}
            file_data = self._first_dict(data.get("files"))
            dns_query_info = self._first_dict(dns_data.get("query"))
            rule_mitre = rule.get("mitre", {}) or {}

            chunk_text = self._strip_nul_chars(self._create_semantic_chunk(log))
            if not chunk_text.strip():
                continue
            chunk_hash = hashlib.sha256(chunk_text.encode()).hexdigest()
            event_timestamp_raw = root_data.get("timestamp")
            event_timestamp = self._parse_event_timestamp(event_timestamp_raw)
            dns_query = (
                dns_query_info.get("rrname")
                or dns_data.get("rrname")
                or dns_data.get("query_name")
            )
            
            metadata = {
                "severity": self._safe_int(rule.get("level", 0)),
                "event_timestamp": event_timestamp_raw,
                "timestamp": event_timestamp_raw,
                "rule_id": rule.get("id"),
                "rule_description": rule.get("description"),
                "signature_id": alert.get("signature_id"),
                "alert_signature": alert.get("signature"),
                "alert_category": alert.get("category"),
                "alert_severity": alert.get("severity"),
                "alert_action": alert.get("action"),
                "src_ip": data.get("src_ip"),
                "dest_ip": data.get("dest_ip"),
                "src_port": data.get("src_port"),
                "dest_port": data.get("dest_port"),
                "proto": data.get("proto"),
                "app_proto": data.get("app_proto"),
                "direction": data.get("direction"),
                "event_type": data.get("event_type"),
                "agent_name": (root_data.get("agent") or {}).get("name"),
                "agent_ip": (root_data.get("agent") or {}).get("ip"),
                "http_hostname": http_data.get("hostname"),
                "http_url": http_data.get("url"),
                "http_method": http_data.get("http_method"),
                "http_user_agent": http_data.get("http_user_agent") or http_data.get("user_agent"),
                "dns_query": dns_query,
                "dns_query_type": dns_query_info.get("rrtype") or dns_data.get("rrtype"),
                "tls_sni": tls_data.get("sni"),
                "tls_subject": tls_data.get("subject"),
                "tls_issuer": tls_data.get("issuer") or tls_data.get("issuerdn"),
                "tls_ja3": tls_data.get("ja3"),
                "tls_ja3s": tls_data.get("ja3s"),
                "ioc_domain": ioc_data.get("domain"),
                "ioc_ip": ioc_data.get("ip"),
                "ioc_url": ioc_data.get("url"),
                "ioc_hash": ioc_data.get("hash"),
                "process_name": process_data.get("name"),
                "parent_process": process_data.get("parent_process"),
                "process_file": process_data.get("file"),
                "process_path": process_data.get("path"),
                "process_command_line": process_data.get("command_line"),
                "threat_actor": threat_data.get("actor"),
                "threat_campaign": threat_data.get("campaign"),
                "threat_confidence": threat_data.get("confidence"),
                "flow_pkts_toserver": flow_data.get("pkts_toserver"),
                "flow_pkts_toclient": flow_data.get("pkts_toclient"),
                "flow_bytes_toserver": flow_data.get("bytes_toserver"),
                "flow_bytes_toclient": flow_data.get("bytes_toclient"),
                "file_name": file_data.get("filename"),
                "file_state": file_data.get("state"),
                "file_size": file_data.get("size"),
                "mitre_ids": rule_mitre.get("id"),
                "mitre_tactics": rule_mitre.get("tactic"),
                "mitre_techniques": rule_mitre.get("technique"),
                "source_file": root_data.get("_archive_source") or log.get("_archive_source"),
                "raw_alert_hash": self._stable_json_hash(root_data),
            }
            metadata = self._strip_nul_chars({k: v for k, v in metadata.items() if v not in (None, "", [], {})})
            
            chunks.append((chunk_hash, chunk_text, metadata, event_timestamp))

        if not chunks:
            print("WARNING: No archive log chunks to add")
            return
        
        with self.db_lock, self.conn.cursor() as cur:
            inserted_alerts = execute_values(cur, """
                INSERT INTO alert_embeddings (alert_hash, content, metadata, source, event_timestamp)
                VALUES %s
                ON CONFLICT (alert_hash) DO NOTHING
                RETURNING id
            """, [(h, c, json.dumps(m), 'archive', ts) for h, c, m, ts in chunks], fetch=True)
            
            inserted = len(inserted_alerts)
            print(f"📝 Added {inserted} new archive alerts (deduplicated)")
            self.conn.commit()

            cur.execute("""
                SELECT id, content FROM alert_embeddings 
                WHERE embedding IS NULL AND source = 'archive'
            """)
            
            to_embed = cur.fetchall()
            if to_embed:
                ids, texts = zip(*to_embed)
                embeddings = self._encode_texts(list(texts), is_query=False)
                
                execute_values(cur, """
                    UPDATE alert_embeddings AS a SET embedding = v.embedding::vector
                    FROM (VALUES %s) AS v(id, embedding)
                    WHERE a.id = v.id
                """, [(id, self._to_vector_literal(emb)) for id, emb in zip(ids, embeddings)])
            
            self.conn.commit()

    def _add_custom_docs(self, docs: List[Any]):
        """Add uploaded documents as chunk rows with deduplication."""
        chunks = []
        upload_summaries = []
        
        for i, doc in enumerate(docs):
            if isinstance(doc, dict):
                doc_content = str(doc.get("content") or doc.get("text") or "")
                source_metadata = doc.get("metadata") or {}
            else:
                doc_content = str(doc or "")
                source_metadata = {}

            doc_content = self._strip_nul_chars(doc_content)
            source_metadata = self._strip_nul_chars(source_metadata)

            if not doc_content.strip():
                continue

            original_filename = (
                source_metadata.get("filename")
                or source_metadata.get("original_filename")
                or f"custom_doc_{i}"
            )
            original_filename = self._strip_nul_chars(original_filename)
            safe_stem = re.sub(r"[^A-Za-z0-9_.-]+", "_", Path(original_filename).stem or f"custom_doc_{i}")[:80]
            raw_document_hash = hashlib.sha256(doc_content.encode("utf-8")).hexdigest()
            source_artifacts = source_metadata.get("cti_artifacts") if isinstance(source_metadata, dict) else {}
            if not isinstance(source_artifacts, dict):
                source_artifacts = {}
            if not source_artifacts:
                source_artifacts = CTIArtifactExtractor.extract(doc_content)
            document_quality = source_metadata.get("document_quality") if isinstance(source_metadata, dict) else {}
            if not isinstance(document_quality, dict):
                document_quality = {}
            
            doc_chunks = self._chunk_text_with_sections(
                doc_content,
                chunk_size=self.document_chunk_size,
                chunk_overlap=self.document_chunk_overlap
            )
            upload_summaries.append({
                "filename": original_filename,
                "chunks": len(doc_chunks),
                "characters": len(doc_content),
                "artefacts": CTIArtifactExtractor.count_by_type(source_artifacts),
            })
            for chunk_index, chunk_info in enumerate(doc_chunks):
                if isinstance(chunk_info, dict):
                    chunk_text = str(chunk_info.get("text") or "")
                    section_path = str(chunk_info.get("section_path") or "").strip()
                    section_heading = str(chunk_info.get("section_heading") or "").strip()
                else:
                    chunk_text = str(chunk_info or "")
                    section_path = ""
                    section_heading = ""
                chunk_text = self._strip_nul_chars(chunk_text)
                section_path = self._strip_nul_chars(section_path)
                section_heading = self._strip_nul_chars(section_heading)
                section_analysis_text = (
                    f"Section: {section_path}\n\n{chunk_text}"
                    if section_path
                    else chunk_text
                )
                chunk_artifacts = CTIArtifactExtractor.extract(chunk_text)
                chunk_context_artifacts = CTIArtifactExtractor.for_cti_context(chunk_artifacts)
                section_labels = CTIArtifactExtractor.classify_context(section_path)
                chunk_context_labels = CTIArtifactExtractor._unique(
                    section_labels + CTIArtifactExtractor.classify_context(section_analysis_text)
                )[:4]
                chunk_behavior_tags = CTIArtifactExtractor.infer_behavior_tags(section_analysis_text)
                chunk_artifact_dispositions = CTIArtifactExtractor.classify_artifact_dispositions(
                    section_analysis_text,
                    chunk_artifacts,
                )
                chunk_artifact_dispositions = CTIArtifactExtractor.apply_section_context_to_dispositions(
                    chunk_artifact_dispositions,
                    chunk_context_labels,
                )
                artifact_context = CTIArtifactExtractor.format_for_context(chunk_context_artifacts)
                context_label_line = CTIArtifactExtractor.format_context_labels(chunk_context_labels)
                behavior_line = CTIArtifactExtractor.format_behavior_tags(chunk_behavior_tags)
                disposition_line = CTIArtifactExtractor.summarize_dispositions(chunk_artifact_dispositions)
                section_line = f"CTI Section Context | {section_path}" if section_path else ""
                context_lines = [
                    line for line in (section_line, context_label_line, behavior_line, disposition_line, artifact_context) if line
                ]
                context_header = "\n".join(context_lines)
                content_for_storage = (
                    f"{context_header}\n\n{chunk_text}"
                    if context_lines
                    else chunk_text
                )
                doc_hash = hashlib.sha256(
                    f"{raw_document_hash}:{chunk_index}:{chunk_text}".encode("utf-8")
                ).hexdigest()
                filename = f"{safe_stem}_chunk_{chunk_index}"
                
                metadata = {
                    "filename": filename,
                    "original_filename": original_filename,
                    "source_document": original_filename,
                    "chunk_index": chunk_index,
                    "chunk_count": len(doc_chunks),
                    "length": len(chunk_text),
                    "added_at": datetime.now().isoformat(),
                    "content_hash": source_metadata.get("content_hash"),
                    "document_type": source_metadata.get("type"),
                    "pages": source_metadata.get("pages"),
                    "processed_at": source_metadata.get("processed_at"),
                    "document_quality": document_quality,
                    "raw_document_hash": raw_document_hash,
                    "cti_section_path": section_path,
                    "cti_section_heading": section_heading,
                    "cti_artifacts": chunk_artifacts,
                    "artifact_counts": CTIArtifactExtractor.count_by_type(chunk_artifacts),
                    "cti_context_labels": chunk_context_labels,
                    "cti_behavior_tags": chunk_behavior_tags,
                    "cti_artifact_dispositions": chunk_artifact_dispositions,
                    "document_artifact_counts": CTIArtifactExtractor.count_by_type(source_artifacts),
                }
                metadata = self._strip_nul_chars({k: v for k, v in metadata.items() if v not in (None, "", [], {})})
                
                chunks.append((doc_hash, filename[:255], self._strip_nul_chars(content_for_storage), metadata))

        if not chunks:
            print("WARNING: No custom document chunks to add")
            return

        print(
            f"Preparing {len(chunks)} text chunks from {len(upload_summaries)} uploaded files "
            "for pgvector storage."
        )
        for summary in upload_summaries:
            artefact_note = (
                f", artefacts={summary['artefacts']}"
                if summary.get("artefacts")
                else ""
            )
            print(
                f"  - {summary['filename']}: {summary['chunks']} chunks "
                f"from {summary['characters']} characters{artefact_note}"
            )
        
        with self.db_lock, self.conn.cursor() as cur:
            inserted_chunks = execute_values(cur, """
                INSERT INTO custom_documents (doc_hash, filename, content, metadata, event_timestamp)
                VALUES %s
                ON CONFLICT (doc_hash) DO NOTHING
                RETURNING id, content
            """, [(h, f, c, json.dumps(m), None) for h, f, c, m in chunks], fetch=True)
            
            inserted = len(inserted_chunks)
            skipped = len(chunks) - inserted
            print(
                f"Added {inserted} new custom document chunks "
                f"({skipped} duplicate chunks skipped from this upload)."
            )
            self.conn.commit()

            to_embed = inserted_chunks
            if not to_embed:
                cur.execute("""
                    SELECT id, content FROM custom_documents 
                    WHERE embedding IS NULL
                    LIMIT 1000
                """)
                to_embed = cur.fetchall()

            if to_embed:
                ids, texts = zip(*to_embed)
                print(
                    f"Computing embeddings for {len(ids)} document chunks."
                )
                embeddings = self._encode_texts(list(texts), is_query=False)
                
                update_data = [(id, self._to_vector_literal(emb)) for id, emb in zip(ids, embeddings)]
                execute_values(cur, """
                    UPDATE custom_documents AS d SET embedding = v.embedding::vector
                    FROM (VALUES %s) AS v(id, embedding)
                    WHERE d.id = v.id
                """, update_data)
                
                print("Document chunk embeddings computed and stored")
            
            self.conn.commit()

    def add_custom_documents(self, docs: List[Any]):
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
        root_data = log.get("_source", log) if isinstance(log, dict) else {}
        source_file = root_data.get("_archive_source") or (log.get("_archive_source") if isinstance(log, dict) else None)
        if source_file:
            parts.append(f"Source File: {source_file}")
        if root_data.get("timestamp"):
            parts.append(f"Event Time: {root_data['timestamp']}")
        if root_data.get("agent"):
            agent = root_data.get("agent") or {}
            agent_bits = [agent.get("name"), agent.get("ip")]
            parts.append("Agent: " + " ".join(str(bit) for bit in agent_bits if bit))
        
        # Rule information
        rule = root_data.get("rule", {}) or {}
        if rule.get("description"):
            parts.append(f"Rule: {rule['description']}")
        if rule.get("level"):
            parts.append(f"Severity: {rule['level']}")
        if rule.get("id"):
            parts.append(f"Rule ID: {rule['id']}")
        
        # Network context
        data = root_data.get("data", {}) or {}
        if data.get("src_ip") and data.get("dest_ip"):
            parts.append(f"Connection: {data['src_ip']}:{data.get('src_port', '')} -> {data['dest_ip']}:{data.get('dest_port', '')}")
        if data.get("proto") or data.get("app_proto") or data.get("direction"):
            parts.append(f"Protocol: {data.get('proto', '')} {data.get('app_proto', '')} {data.get('direction', '')}".strip())
        if data.get("event_type"):
            parts.append(f"Event Type: {data['event_type']}")
        if data.get("flow"):
            flow_data = data.get("flow") or {}
            flow_bits = {
                "pkts_toserver": flow_data.get("pkts_toserver"),
                "pkts_toclient": flow_data.get("pkts_toclient"),
                "bytes_toserver": flow_data.get("bytes_toserver"),
                "bytes_toclient": flow_data.get("bytes_toclient"),
            }
            self._append_part(parts, "Flow", {k: v for k, v in flow_bits.items() if v not in (None, "", [], {})})
        
        # Alert signature
        alert = data.get("alert", {}) or {}
        if alert.get("signature"):
            parts.append(f"Alert: {alert['signature']}")
        if alert.get("signature_id"):
            parts.append(f"Signature ID: {alert['signature_id']}")
        if alert.get("category"):
            parts.append(f"Category: {alert['category']}")
        if alert.get("action"):
            parts.append(f"Action: {alert['action']}")
        
        # HTTP/DNS context if present
        http_data = data.get("http", {}) or {}
        if http_data.get("hostname"):
            parts.append(f"HTTP Host: {http_data['hostname']}")
        if http_data.get("url"):
            parts.append(f"HTTP URL: {http_data['url']}")
        if http_data.get("http_method"):
            parts.append(f"HTTP Method: {http_data['http_method']}")
        if http_data.get("http_user_agent") or http_data.get("user_agent"):
            parts.append(f"HTTP User-Agent: {http_data.get('http_user_agent') or http_data.get('user_agent')}")
        dns_data = data.get("dns", {}) or {}
        query_info = self._first_dict(dns_data.get("query"))
        dns_name = query_info.get("rrname") or dns_data.get("rrname") or dns_data.get("query_name")
        if dns_name:
            parts.append(f"DNS Query: {dns_name}")
        if query_info.get("rrtype") or dns_data.get("rrtype"):
            parts.append(f"DNS Type: {query_info.get('rrtype') or dns_data.get('rrtype')}")
        tls_data = data.get("tls", {}) or {}
        if tls_data.get("sni"):
            parts.append(f"TLS SNI: {tls_data['sni']}")
        if tls_data.get("subject") or tls_data.get("issuer") or tls_data.get("issuerdn"):
            parts.append(f"TLS Certificate: subject={tls_data.get('subject', '')} issuer={tls_data.get('issuer') or tls_data.get('issuerdn', '')}".strip())
        if tls_data.get("ja3") or tls_data.get("ja3s"):
            parts.append(f"TLS Fingerprints: ja3={tls_data.get('ja3', '')} ja3s={tls_data.get('ja3s', '')}".strip())

        ioc_data = data.get("ioc", {}) or {}
        if ioc_data:
            self._append_part(parts, "IoC Domain", ioc_data.get("domain"))
            self._append_part(parts, "IoC IP", ioc_data.get("ip"))
            self._append_part(parts, "IoC URL", ioc_data.get("url"))
            self._append_part(parts, "IoC Hash", ioc_data.get("hash"))

        process_data = data.get("process", {}) or {}
        if process_data:
            process_bits = {
                "name": process_data.get("name"),
                "parent": process_data.get("parent_process"),
                "file": process_data.get("file"),
                "path": process_data.get("path"),
                "command_line": process_data.get("command_line"),
            }
            self._append_part(parts, "Process", {k: v for k, v in process_bits.items() if v not in (None, "", [], {})})

        threat_data = data.get("threat", {}) or {}
        if threat_data:
            threat_bits = {
                "actor": threat_data.get("actor"),
                "campaign": threat_data.get("campaign"),
                "confidence": threat_data.get("confidence"),
            }
            self._append_part(parts, "Threat Intel", {k: v for k, v in threat_bits.items() if v not in (None, "", [], {})})

        file_data = self._first_dict(data.get("files"))
        if file_data:
            file_bits = {
                "filename": file_data.get("filename"),
                "state": file_data.get("state"),
                "size": file_data.get("size"),
                "stored": file_data.get("stored"),
            }
            self._append_part(parts, "File", {k: v for k, v in file_bits.items() if v not in (None, "", [], {})})

        mitre_data = rule.get("mitre", {}) or {}
        if mitre_data:
            self._append_part(parts, "MITRE IDs", mitre_data.get("id"))
            self._append_part(parts, "MITRE Tactics", mitre_data.get("tactic"))
            self._append_part(parts, "MITRE Techniques", mitre_data.get("technique"))
        
        # Full log as reference
        if root_data.get("full_log"):
            parts.append(f"Details: {root_data['full_log'][:500]}")
        
        return " | ".join(parts)
    
    def _archive_filter(self, metadata_filter: dict = None, require_embedding: bool = False) -> tuple[str, List[Any]]:
        parts = []
        params: List[Any] = []
        if require_embedding:
            parts.append("embedding IS NOT NULL")
        if metadata_filter:
            if "min_severity" in metadata_filter:
                parts.append("(metadata->>'severity')::int >= %s")
                params.append(int(metadata_filter["min_severity"]))
            if "timeframe_hours" in metadata_filter:
                parts.append("COALESCE(event_timestamp, created_at AT TIME ZONE 'UTC') >= NOW() - (%s * INTERVAL '1 hour')")
                params.append(int(metadata_filter["timeframe_hours"]))
        return (" AND ".join(parts) if parts else "TRUE"), params

    @staticmethod
    def _normalize_exact_values(values: Any) -> List[str]:
        if not values:
            return []
        if isinstance(values, (str, int, float)):
            raw_values = [values]
        else:
            raw_values = values
        normalized = []
        seen = set()
        for value in raw_values:
            text = str(value).strip()
            if text and text not in seen:
                seen.add(text)
                normalized.append(text)
        return normalized

    @staticmethod
    def _like_patterns(values: List[str]) -> List[str]:
        return [f"%{value}%" for value in values if len(value) >= 3]

    @staticmethod
    def _is_ip_term(term: str) -> bool:
        try:
            ipaddress.ip_address(str(term).strip())
            return True
        except ValueError:
            return False

    @staticmethod
    def _is_domain_term(term: str) -> bool:
        text = str(term or "").strip().lower().strip(".")
        if not text or "/" in text or "://" in text:
            return False
        if RAGContextManager._is_ip_term(text):
            return False
        return bool(CTIArtifactExtractor.DOMAIN_RE.fullmatch(text))

    @staticmethod
    def _term_regex(term: str, term_type: str = None):
        if not term:
            return None
        escaped = re.escape(str(term).strip())
        if term_type == "ip" or RAGContextManager._is_ip_term(term):
            return re.compile(rf"(?<![\w.]){escaped}(?![\w.])", re.IGNORECASE)
        if term_type in {"domain", "url"} or RAGContextManager._is_domain_term(term):
            return re.compile(rf"(?<![\w.-]){escaped}(?![\w.-])", re.IGNORECASE)
        if re.fullmatch(r"[A-Za-z0-9_.:/-]+", str(term)):
            return re.compile(rf"(?<![\w./:-]){escaped}(?![\w./:-])", re.IGNORECASE)
        return re.compile(escaped, re.IGNORECASE)

    @classmethod
    def _contains_exact_term(cls, text: str, term: str, term_type: str = None) -> bool:
        text = str(text or "")
        term = str(term or "").strip()
        if not text or not term:
            return False
        if term_type == "ip" or cls._is_ip_term(term):
            try:
                normalized_ip = str(ipaddress.ip_address(term))
            except ValueError:
                return False
            return normalized_ip in CTIArtifactExtractor._extract_ips(text)
        if term_type == "url":
            cleaned_term = CTIArtifactExtractor._clean_url(term).lower()
            urls = [
                CTIArtifactExtractor._clean_url(match.group(0)).lower()
                for match in CTIArtifactExtractor.URL_RE.finditer(text)
            ]
            return cleaned_term in urls
        if term_type == "domain" or cls._is_domain_term(term):
            domain_term = term.lower().strip(".")
            urls = [
                CTIArtifactExtractor._clean_url(match.group(0))
                for match in CTIArtifactExtractor.URL_RE.finditer(text)
            ]
            return domain_term in CTIArtifactExtractor._extract_domains(text, urls)
        pattern = cls._term_regex(term, term_type)
        return bool(pattern.search(text)) if pattern else False

    @staticmethod
    def _metadata_artifact_values(metadata: Dict[str, Any], artifact_keys: tuple[str, ...]) -> List[str]:
        values = []
        artifacts = metadata.get("cti_artifacts") if isinstance(metadata, dict) else {}
        if isinstance(artifacts, dict):
            for key in artifact_keys:
                raw_values = artifacts.get(key)
                if isinstance(raw_values, list):
                    values.extend(raw_values)
                elif raw_values not in (None, "", [], {}):
                    values.append(raw_values)
        return values

    @staticmethod
    def _evidence_snippet(text: str, term: str, radius: int = 90, term_type: str = None) -> str:
        if not text or not term:
            return ""
        pattern = RAGContextManager._term_regex(term, term_type)
        match = pattern.search(text) if pattern else None
        if not match:
            return ""
        start = max(0, match.start() - radius)
        end = min(len(text), match.end() + radius)
        prefix = "..." if start > 0 else ""
        suffix = "..." if end < len(text) else ""
        snippet = re.sub(r"\s+", " ", text[start:end]).strip()
        return f"{prefix}{snippet}{suffix}"

    def _exact_match_evidence(self, content: str, metadata: Dict[str, Any],
                              exact_terms: dict = None, max_items: int = 6) -> List[str]:
        if not exact_terms:
            return []

        content = str(content or "")
        metadata = metadata or {}
        evidence: List[str] = []

        term_groups = [
            ("rule_id", "rule_ids", ("rule_id",)),
            ("signature_id", "signature_ids", ("signature_id",)),
            ("source ip", "source_ips", ("src_ip",)),
            ("destination ip", "destination_ips", ("dest_ip",)),
            ("ip", "ips", ("src_ip", "dest_ip", "agent_ip", "ioc_ip")),
            ("domain", "domains", ("http_hostname", "dns_query", "tls_sni", "ioc_domain")),
            ("url", "urls", ("http_url", "ioc_url")),
            ("signature", "alert_signatures", ("alert_signature",)),
            ("indicator", "keywords", ("ioc_hash", "process_name", "parent_process", "process_file", "process_path", "process_command_line", "threat_actor", "threat_campaign", "file_name")),
        ]

        for label, exact_key, metadata_keys in term_groups:
            for term in self._normalize_exact_values(exact_terms.get(exact_key)):
                term_type = None
                if "ip" in label:
                    term_type = "ip"
                elif label == "domain":
                    term_type = "domain"
                elif label == "url":
                    term_type = "url"
                found = False
                for metadata_key in metadata_keys:
                    raw_metadata_value = metadata.get(metadata_key)
                    metadata_values = raw_metadata_value if isinstance(raw_metadata_value, list) else [raw_metadata_value]
                    if any(str(value or "").lower() == term.lower() for value in metadata_values):
                        evidence.append(f"{label} matched metadata {metadata_key}={term}")
                        found = True
                        break

                if label in {"source ip", "destination ip"}:
                    if len(evidence) >= max_items:
                        return evidence
                    continue

                if not found and term_type:
                    artifact_keys = {
                        "ip": ("ips", "public_ips", "non_public_ips"),
                        "domain": ("domains",),
                        "url": ("urls",),
                    }.get(term_type, ())
                    artifact_values = self._metadata_artifact_values(metadata, artifact_keys)
                    if any(str(value or "").lower() == term.lower() for value in artifact_values):
                        evidence.append(f"{label} matched extracted CTI artifact {term}")
                        found = True

                if not found and len(term) >= 3:
                    snippet = self._evidence_snippet(content, term, term_type=term_type)
                    if snippet:
                        evidence.append(f"{label} matched content \"{term}\" near: {snippet}")
                        found = True

                if not found and len(term) >= 3:
                    metadata_text = json.dumps(metadata, sort_keys=True, default=str)
                    snippet = self._evidence_snippet(metadata_text, term, term_type=term_type)
                    if snippet and self._contains_exact_term(metadata_text, term, term_type=term_type):
                        evidence.append(f"{label} matched metadata text \"{term}\" near: {snippet}")

                if len(evidence) >= max_items:
                    return evidence

        return evidence

    def _lexical_match_evidence(self, query: str, content: str, metadata: Dict[str, Any],
                                max_items: int = 5) -> List[str]:
        haystack = f"{content or ''} {json.dumps(metadata or {}, sort_keys=True, default=str)}"
        terms = []
        for token in re.findall(r"[A-Za-z0-9_.:/-]{4,}", str(query or "")):
            normalized = token.lower()
            if normalized not in terms and self._contains_exact_term(haystack, token):
                terms.append(normalized)
            if len(terms) >= max_items:
                break
        return [f"lexical token matched \"{term}\"" for term in terms]

    def _semantic_match_evidence(self, score: Any) -> List[str]:
        try:
            return [f"semantic nearest-neighbor similarity={float(score):.3f}"]
        except (TypeError, ValueError):
            return ["semantic nearest-neighbor match"]

    def _exact_archive_condition(self, exact_terms: dict = None) -> tuple[str, List[Any]]:
        if not exact_terms:
            return "", []

        conditions = []
        params: List[Any] = []

        rule_ids = self._normalize_exact_values(exact_terms.get("rule_ids"))
        if rule_ids:
            conditions.append("metadata->>'rule_id' = ANY(%s)")
            params.append(rule_ids)

        signature_ids = self._normalize_exact_values(exact_terms.get("signature_ids"))
        if signature_ids:
            conditions.append("metadata->>'signature_id' = ANY(%s)")
            params.append(signature_ids)

        source_ips = self._normalize_exact_values(exact_terms.get("source_ips"))
        if source_ips:
            conditions.append("metadata->>'src_ip' = ANY(%s)")
            params.append(source_ips)

        destination_ips = self._normalize_exact_values(exact_terms.get("destination_ips"))
        if destination_ips:
            conditions.append("metadata->>'dest_ip' = ANY(%s)")
            params.append(destination_ips)

        ips = self._normalize_exact_values(exact_terms.get("ips"))
        if ips:
            conditions.append("(metadata->>'src_ip' = ANY(%s) OR metadata->>'dest_ip' = ANY(%s) OR metadata->>'ioc_ip' = ANY(%s))")
            params.extend([ips, ips, ips])

        domains = self._normalize_exact_values(exact_terms.get("domains"))
        if domains:
            domain_patterns = self._like_patterns(domains)
            conditions.append("(metadata->>'http_hostname' = ANY(%s) OR metadata->>'dns_query' = ANY(%s) OR metadata->>'tls_sni' = ANY(%s) OR metadata->>'ioc_domain' = ANY(%s) OR content ILIKE ANY(%s))")
            params.extend([domains, domains, domains, domains, domain_patterns])

        urls = self._normalize_exact_values(exact_terms.get("urls"))
        if urls:
            url_patterns = self._like_patterns(urls)
            conditions.append("(metadata->>'http_url' = ANY(%s) OR metadata->>'ioc_url' = ANY(%s) OR content ILIKE ANY(%s))")
            params.extend([urls, urls, url_patterns])

        signatures = self._normalize_exact_values(exact_terms.get("alert_signatures"))
        if signatures:
            signature_patterns = self._like_patterns(signatures)
            conditions.append("(metadata->>'alert_signature' = ANY(%s) OR content ILIKE ANY(%s))")
            params.extend([signatures, signature_patterns])

        keywords = self._normalize_exact_values(exact_terms.get("keywords"))
        if keywords:
            keyword_patterns = self._like_patterns(keywords)
            if keyword_patterns:
                conditions.append("(content ILIKE ANY(%s) OR metadata::text ILIKE ANY(%s))")
                params.extend([keyword_patterns, keyword_patterns])

        return (" OR ".join(conditions), params) if conditions else ("", [])

    def _exact_document_condition(self, exact_terms: dict = None) -> tuple[str, List[Any]]:
        if not exact_terms:
            return "", []

        values = []
        for key in ("rule_ids", "signature_ids", "source_ips", "destination_ips",
                    "ips", "domains", "urls", "alert_signatures", "keywords"):
            values.extend(self._normalize_exact_values(exact_terms.get(key)))
        patterns = self._like_patterns(values)
        if not patterns:
            return "", []
        return "(content ILIKE ANY(%s) OR metadata::text ILIKE ANY(%s))", [patterns, patterns]

    @staticmethod
    def _row_key(item: Dict[str, Any]) -> tuple:
        return (
            item.get("source"),
            item.get("id"),
            hashlib.sha256(str(item.get("content", "")).encode("utf-8")).hexdigest()
        )

    def _merge_hybrid_results(self, candidates: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        merged: Dict[tuple, Dict[str, Any]] = {}
        for item in candidates:
            key = self._row_key(item)
            existing = merged.get(key)
            if not existing:
                item["match_types"] = sorted(set(item.get("match_types", [])))
                merged[key] = item
                continue

            if float(item.get("score") or 0.0) > float(existing.get("score") or 0.0):
                existing["score"] = item.get("score")
            if item.get("semantic_score") is not None:
                existing["semantic_score"] = max(
                    float(existing.get("semantic_score") or 0.0),
                    float(item.get("semantic_score") or 0.0)
                )
            if item.get("lexical_score") is not None:
                existing["lexical_score"] = max(
                    float(existing.get("lexical_score") or 0.0),
                    float(item.get("lexical_score") or 0.0)
                )
            existing["match_types"] = sorted(
                set(existing.get("match_types", [])) | set(item.get("match_types", []))
            )
            evidence = []
            for value in existing.get("match_evidence", []) + item.get("match_evidence", []):
                if value and value not in evidence:
                    evidence.append(value)
            existing["match_evidence"] = evidence[:8]

        return sorted(merged.values(), key=lambda item: float(item.get("score") or 0.0), reverse=True)

    def _apply_source_diversity(self, results: List[Dict[str, Any]], limit: int) -> List[Dict[str, Any]]:
        if not results or limit <= 0:
            return []
        source_cap = max(1, (limit * 2 + 2) // 3)
        selected = []
        source_counts: Dict[str, int] = {}

        for item in results:
            source = item.get("source") or "unknown"
            if source_counts.get(source, 0) >= source_cap:
                continue
            selected.append(item)
            source_counts[source] = source_counts.get(source, 0) + 1
            if len(selected) >= limit:
                return selected

        seen = {self._row_key(item) for item in selected}
        for item in results:
            key = self._row_key(item)
            if key in seen:
                continue
            selected.append(item)
            seen.add(key)
            if len(selected) >= limit:
                break
        return selected

    def _hybrid_search(self, query: str, k: int, metadata_filter: dict = None,
                       exact_terms: dict = None, sources: tuple[str, ...] = ("archive", "custom_document"),
                       enforce_diversity: bool = True) -> List[Dict[str, Any]]:
        query = self._normalize_for_embedding(query, max_chars=4000)
        limit = k or self.max_retrieval_docs
        candidate_limit = max(limit * self.retrieval_candidate_multiplier, limit)
        query_embedding = self._to_vector_literal(self._encode_texts([query], is_query=True)[0])
        candidates: List[Dict[str, Any]] = []

        with self.db_lock, self.conn.cursor() as cur:
            if "archive" in sources:
                semantic_filter, semantic_params = self._archive_filter(metadata_filter, require_embedding=True)
                cur.execute(f"""
                    SELECT id, content, metadata, source, 1 - (embedding <=> %s::vector) AS similarity
                    FROM alert_embeddings
                    WHERE {semantic_filter}
                    AND (1 - (embedding <=> %s::vector)) >= %s
                    ORDER BY embedding <=> %s::vector
                    LIMIT %s
                """, (query_embedding, *semantic_params, query_embedding, self.similarity_threshold, query_embedding, candidate_limit))
                candidates.extend([
                    {
                        "id": r[0], "content": r[1], "metadata": r[2] or {}, "source": r[3],
                        "score": float(r[4] or 0.0), "semantic_score": float(r[4] or 0.0),
                        "match_types": ["semantic"],
                        "match_evidence": (
                            self._exact_match_evidence(r[1], r[2] or {}, exact_terms)
                            or self._semantic_match_evidence(r[4])
                        )
                    }
                    for r in cur.fetchall()
                ])

                exact_condition, exact_params = self._exact_archive_condition(exact_terms)
                if exact_condition:
                    archive_filter, archive_params = self._archive_filter(metadata_filter, require_embedding=False)
                    cur.execute(f"""
                        SELECT id, content, metadata, source
                        FROM alert_embeddings
                        WHERE {archive_filter}
                        AND ({exact_condition})
                        ORDER BY COALESCE(event_timestamp, created_at AT TIME ZONE 'UTC') DESC NULLS LAST
                        LIMIT %s
                    """, (*archive_params, *exact_params, candidate_limit))
                    for r in cur.fetchall():
                        evidence = self._exact_match_evidence(r[1], r[2] or {}, exact_terms)
                        if not evidence:
                            continue
                        candidates.append({
                            "id": r[0], "content": r[1], "metadata": r[2] or {}, "source": r[3],
                            "score": 1.25, "match_types": ["exact"],
                            "match_evidence": evidence
                        })

                archive_filter, archive_params = self._archive_filter(metadata_filter, require_embedding=False)
                cur.execute(f"""
                    SELECT id, content, metadata, source,
                           ts_rank_cd(
                               to_tsvector('simple', coalesce(content, '') || ' ' || coalesce(metadata::text, '')),
                               plainto_tsquery('simple', %s)
                           ) AS lexical_score
                    FROM alert_embeddings
                    WHERE {archive_filter}
                    AND to_tsvector('simple', coalesce(content, '') || ' ' || coalesce(metadata::text, ''))
                        @@ plainto_tsquery('simple', %s)
                    ORDER BY lexical_score DESC
                    LIMIT %s
                """, (query, *archive_params, query, candidate_limit))
                candidates.extend([
                    {
                        "id": r[0], "content": r[1], "metadata": r[2] or {}, "source": r[3],
                        "score": min(1.1, 0.35 + float(r[4] or 0.0)),
                        "lexical_score": float(r[4] or 0.0),
                        "match_types": ["lexical"],
                        "match_evidence": self._lexical_match_evidence(query, r[1], r[2] or {})
                    }
                    for r in cur.fetchall()
                ])

            if "custom_document" in sources:
                cur.execute("""
                    SELECT id, content, metadata, 1 - (embedding <=> %s::vector) AS similarity
                    FROM custom_documents
                    WHERE embedding IS NOT NULL
                    AND (1 - (embedding <=> %s::vector)) >= %s
                    ORDER BY embedding <=> %s::vector
                    LIMIT %s
                """, (query_embedding, query_embedding, self.similarity_threshold, query_embedding, candidate_limit))
                candidates.extend([
                    {
                        "id": r[0], "content": r[1], "metadata": r[2] or {}, "source": "custom_document",
                        "score": float(r[3] or 0.0), "semantic_score": float(r[3] or 0.0),
                        "match_types": ["semantic"],
                        "match_evidence": (
                            self._exact_match_evidence(r[1], r[2] or {}, exact_terms)
                            or self._semantic_match_evidence(r[3])
                        )
                    }
                    for r in cur.fetchall()
                ])

                exact_condition, exact_params = self._exact_document_condition(exact_terms)
                if exact_condition:
                    cur.execute(f"""
                        SELECT id, content, metadata
                        FROM custom_documents
                        WHERE {exact_condition}
                        ORDER BY created_at DESC
                        LIMIT %s
                    """, (*exact_params, candidate_limit))
                    for r in cur.fetchall():
                        evidence = self._exact_match_evidence(r[1], r[2] or {}, exact_terms)
                        if not evidence:
                            continue
                        candidates.append({
                            "id": r[0], "content": r[1], "metadata": r[2] or {}, "source": "custom_document",
                            "score": 1.15, "match_types": ["exact"],
                            "match_evidence": evidence
                        })

                cur.execute("""
                    SELECT id, content, metadata,
                           ts_rank_cd(
                               to_tsvector('simple', coalesce(content, '') || ' ' || coalesce(metadata::text, '')),
                               plainto_tsquery('simple', %s)
                           ) AS lexical_score
                    FROM custom_documents
                    WHERE to_tsvector('simple', coalesce(content, '') || ' ' || coalesce(metadata::text, ''))
                        @@ plainto_tsquery('simple', %s)
                    ORDER BY lexical_score DESC
                    LIMIT %s
                """, (query, query, candidate_limit))
                candidates.extend([
                    {
                        "id": r[0], "content": r[1], "metadata": r[2] or {}, "source": "custom_document",
                        "score": min(1.05, 0.3 + float(r[3] or 0.0)),
                        "lexical_score": float(r[3] or 0.0),
                        "match_types": ["lexical"],
                        "match_evidence": self._lexical_match_evidence(query, r[1], r[2] or {})
                    }
                    for r in cur.fetchall()
                ])

        merged = self._merge_hybrid_results(candidates)
        return self._apply_source_diversity(merged, limit) if enforce_diversity else merged[:limit]

    def get_retriever(self, k: int = None, metadata_filter: dict = None, exact_terms: dict = None):
        """Get a hybrid retriever with exact, lexical, and semantic matching."""
        def retrieve(query: str) -> List[Dict[str, Any]]:
            return self._hybrid_search(
                query,
                k or self.max_retrieval_docs,
                metadata_filter=metadata_filter,
                exact_terms=exact_terms,
                sources=("archive", "custom_document"),
                enforce_diversity=True
            )

        return retrieve

    def search_custom_documents(self, query: str, k: int = 2, exact_terms: dict = None) -> List[Dict[str, Any]]:
        """Search only uploaded/custom CTI documents."""
        return self._hybrid_search(
            query,
            k,
            exact_terms=exact_terms,
            sources=("custom_document",),
            enforce_diversity=False
        )

    def search_archive_alerts(self, query: str, k: int = 5, metadata_filter: dict = None,
                              exact_terms: dict = None) -> List[Dict[str, Any]]:
        """Search only historical archive alerts."""
        return self._hybrid_search(
            query,
            k,
            metadata_filter=metadata_filter,
            exact_terms=exact_terms,
            sources=("archive",),
            enforce_diversity=False
        )
    
    def cleanup_old_alerts(self, days: int = 30):
        """Remove alerts older than N days"""
        with self.db_lock, self.conn.cursor() as cur:
            cur.execute("""
                DELETE FROM alert_embeddings 
                WHERE source = 'archive' 
                AND COALESCE(event_timestamp, created_at AT TIME ZONE 'UTC') < NOW() - (%s * INTERVAL '1 day')
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
                        (SELECT COUNT(*) FROM custom_documents WHERE embedding IS NOT NULL) as docs_with_embeddings,
                        (
                            SELECT COUNT(DISTINCT COALESCE(
                                metadata->>'raw_document_hash',
                                metadata->>'content_hash',
                                metadata->>'source_document',
                                filename
                            ))
                            FROM custom_documents
                        ) as total_source_docs,
                        (
                            SELECT COUNT(DISTINCT COALESCE(
                                metadata->>'raw_document_hash',
                                metadata->>'content_hash',
                                metadata->>'source_document',
                                filename
                            ))
                            FROM custom_documents
                            WHERE embedding IS NOT NULL
                        ) as source_docs_with_embeddings
                """)
                stats = cur.fetchone()
                ready = bool(stats and (stats[1] > 0 or stats[3] > 0))
                self.rag_ready = ready
                
                return {
                    "ready": ready,
                    "storage": "persistent_postgresql",
                    "total_alerts": stats[0],
                    "alerts_with_embeddings": stats[1],
                    "total_uploaded_documents": stats[4],
                    "uploaded_documents_with_embeddings": stats[5],
                    "total_custom_doc_chunks": stats[2],
                    "custom_doc_chunks_with_embeddings": stats[3],
                    "total_custom_docs": stats[2],
                    "docs_with_embeddings": stats[3],
                    "embedding_model": self.embedding_model,
                    "embedding_device": self.embedding_device,
                    "embedding_devices": self.embedding_devices,
                    "vector_dimensions": self.vector_dimensions,
                    "embedding_batch_size": self.embedding_batch_size,
                    "embedding_multi_gpu_min_chunks": self.embedding_multi_gpu_min_chunks,
                    "normalize_embeddings": self.normalize_embeddings,
                    "similarity_threshold": self.similarity_threshold,
                    "retrieval_candidate_multiplier": self.retrieval_candidate_multiplier,
                    "query_instruction_enabled": bool(self.embedding_query_instruction),
                    "document_instruction_enabled": bool(self.embedding_document_instruction),
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
    """Analyzes and processes security alert data with configurable asset awareness."""

    DEFAULT_INFRASTRUCTURE_IPS = [
        "192.168.56.104",  # Suricata NIDS sensor
        "192.168.56.1",    # Lab gateway
    ]
    DEFAULT_OWNED_CIDRS = [
        "66.96.0.0/16",
        "129.126.144.226/32",
    ]
    DEFAULT_INTERNAL_CIDRS = [
        "192.168.0.0/16",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "127.0.0.0/8",
    ]

    def __init__(self, geoip_db_path: str = None, asset_config: Any = None):
        self.geoip_db_path = geoip_db_path
        self.geoip_manager = GeoIPManager(geoip_db_path)
        self.infrastructure_ips = set(self._inventory_list(
            asset_config, "infrastructure_ips", self.DEFAULT_INFRASTRUCTURE_IPS
        ))
        self.owned_networks = self._compile_networks(self._inventory_list(
            asset_config, "owned_cidrs", self.DEFAULT_OWNED_CIDRS
        ))
        self.internal_networks = self._compile_networks(self._inventory_list(
            asset_config, "internal_cidrs", self.DEFAULT_INTERNAL_CIDRS
        ))

    @staticmethod
    def _inventory_list(asset_config: Any, attr: str, default: List[str]) -> List[str]:
        if asset_config is None:
            return list(default)
        if isinstance(asset_config, dict):
            value = asset_config.get(attr)
        else:
            value = getattr(asset_config, attr, None)
        if value is None:
            return list(default)
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        return [str(item).strip() for item in value if str(item).strip()]

    @staticmethod
    def _compile_networks(network_values: List[str]) -> List[ipaddress._BaseNetwork]:
        networks = []
        for value in network_values:
            try:
                networks.append(ipaddress.ip_network(value, strict=False))
            except ValueError:
                print(f"WARNING: Invalid asset network ignored: {value}")
        return networks

    def get_inventory_summary(self) -> Dict[str, Any]:
        return {
            "owned_cidrs": [str(network) for network in self.owned_networks],
            "infrastructure_ips": sorted(self.infrastructure_ips),
            "internal_cidrs": [str(network) for network in self.internal_networks],
        }

    def get_inventory_prompt(self) -> str:
        summary = self.get_inventory_summary()
        return (
            "Owned protected CIDRs/IPs: " + ", ".join(summary["owned_cidrs"]) + "\n"
            "Monitoring/noise infrastructure IPs: " + ", ".join(summary["infrastructure_ips"]) + "\n"
            "Private/internal CIDRs: " + ", ".join(summary["internal_cidrs"]) + "\n"
            "Classification rule: monitoring infrastructure is noise when it is the alerting source; "
            "owned and private ranges are protected assets for inbound, outbound, and lateral movement analysis."
        )

    def _is_infrastructure_ip(self, ip_str: str) -> bool:
        return bool(ip_str) and ip_str in self.infrastructure_ips

    def _ip_in_networks(self, ip_str: str, networks: List[ipaddress._BaseNetwork]) -> bool:
        try:
            ip = ipaddress.ip_address(ip_str)
            return any(ip in network for network in networks)
        except ValueError:
            return False

    def _is_owned_asset_ip(self, ip_str: str) -> bool:
        return self._ip_in_networks(ip_str, self.owned_networks)

    def _is_internal_ip(self, ip_str: str) -> bool:
        return self._ip_in_networks(ip_str, self.internal_networks)

    def _is_local_asset_ip(self, ip_str: str) -> bool:
        return self._is_owned_asset_ip(ip_str) or self._is_internal_ip(ip_str)

    def _classify_ip_context(self, ip_str: str) -> str:
        """Classify IP address context for threat analysis."""
        if not ip_str:
            return "unknown"

        if self._is_infrastructure_ip(ip_str):
            return "infrastructure"
        if self._is_owned_asset_ip(ip_str):
            return "owned"
        if self._is_internal_ip(ip_str):
            return "internal"
        return "external"

    def _extract_geolocation_with_geoip(self, data: Dict, ip_field: str, geoip_manager: GeoIPManager) -> Optional[Dict]:
        """Extract geolocation using GeoIP2 for external IPs."""
        ip_address = data.get(ip_field)
        if not ip_address:
            return None
        
        if self._is_infrastructure_ip(ip_address):
            return None
        
        # Skip local assets and private IPs.
        if self._is_local_asset_ip(ip_address):
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
    
    def analyze_current_alerts(self, alerts: List[Dict]) -> Dict[str, Any]:
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
                elif src_context in ('internal', 'owned'):
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
    
    @staticmethod
    def _dedupe_values(values: List[Any]) -> List[str]:
        deduped = []
        seen = set()
        for value in values:
            if value in (None, "", [], {}):
                continue
            text = str(value).strip()
            if not text or text.lower() in seen:
                continue
            seen.add(text.lower())
            deduped.append(text)
        return deduped

    def _extract_observed_iocs(self, alert: Dict[str, Any]) -> Dict[str, List[str]]:
        iocs = {
            "ips": [],
            "domains": [],
            "urls": [],
            "hashes": [],
            "processes": [],
            "rule_ids": [],
            "signature_ids": [],
            "ports": [],
        }

        for key in ("src_ip", "dest_ip", "agent_ip"):
            if alert.get(key):
                iocs["ips"].append(alert.get(key))
        for key in ("src_port", "dest_port"):
            if alert.get(key):
                iocs["ports"].append(alert.get(key))
        if alert.get("rule_id"):
            iocs["rule_ids"].append(alert.get("rule_id"))
        if alert.get("signature_id"):
            iocs["signature_ids"].append(alert.get("signature_id"))

        http_context = alert.get("http_context") or {}
        if isinstance(http_context, dict):
            iocs["domains"].append(http_context.get("hostname"))
            iocs["urls"].append(http_context.get("url"))

        dns_context = alert.get("dns_context") or {}
        if isinstance(dns_context, dict):
            iocs["domains"].append(dns_context.get("query_name"))

        tls_context = alert.get("tls_context") or {}
        if isinstance(tls_context, dict):
            iocs["domains"].append(tls_context.get("sni"))

        ioc_context = alert.get("ioc_context") or {}
        if isinstance(ioc_context, dict):
            iocs["domains"].append(ioc_context.get("domain"))
            iocs["ips"].append(ioc_context.get("ip"))
            iocs["urls"].append(ioc_context.get("url"))
            iocs["hashes"].append(ioc_context.get("hash"))

        process_context = alert.get("process_context") or {}
        if isinstance(process_context, dict):
            for key in ("name", "parent_process", "file", "path", "command_line"):
                iocs["processes"].append(process_context.get(key))

        cleaned = {}
        for key, values in iocs.items():
            deduped = self._dedupe_values(values)
            if deduped:
                cleaned[key] = deduped
        return cleaned

    def _build_retrieval_fingerprint(self, alert: Dict[str, Any], observed_iocs: Dict[str, List[str]]) -> str:
        parts = [
            f"level={alert.get('rule_level')}",
            f"direction={(alert.get('threat_classification') or {}).get('threat_direction', 'unknown')}",
            f"src_context={alert.get('src_ip_context', 'unknown')}",
            f"dest_context={alert.get('dest_ip_context', 'unknown')}",
        ]

        for field in ("rule_id", "rule_description", "alert_signature", "alert_category",
                      "proto", "app_proto", "event_type", "direction",
                      "priority_reason", "directional_focus"):
            if alert.get(field):
                parts.append(f"{field}={alert.get(field)}")

        for key in ("behavior_tags", "response_focus"):
            values = alert.get(key) or []
            if isinstance(values, list) and values:
                parts.append(f"{key}={', '.join(str(value) for value in values[:8])}")

        for key in ("ips", "domains", "urls", "hashes", "processes", "rule_ids", "signature_ids", "ports"):
            values = observed_iocs.get(key) or []
            if values:
                parts.append(f"{key}={', '.join(values[:8])}")

        return " | ".join(parts)

    def _build_priority_reason(self, alert: Dict[str, Any]) -> str:
        classification = alert.get("threat_classification") or {}
        direction = classification.get("threat_direction", "unknown")
        level = alert.get("rule_level", 0)

        if classification.get("is_infrastructure_alert"):
            return "Monitoring/noise infrastructure source; treat as low-priority unless corroborated by protected-asset activity."
        if direction == "outbound":
            return f"Protected asset initiated external communication under alert level {level}; investigate possible compromise, C2, or exfiltration."
        if direction == "inbound":
            return f"External source targeted a protected asset under alert level {level}; assess exploit attempt and exposed service risk."
        if direction == "lateral":
            return f"Internal-to-internal alert under level {level}; investigate post-compromise movement or policy violation."
        if direction == "external":
            return "External-to-external traffic with no configured protected asset involvement; lower relevance unless rule context proves impact."
        return f"Insufficient IP direction context; rely on rule, signature, and IoC evidence for priority."

    def _build_directional_focus(self, alert: Dict[str, Any]) -> str:
        classification = alert.get("threat_classification") or {}
        direction = classification.get("threat_direction", "unknown")
        src_ip = alert.get("src_ip") or "unknown source"
        dest_ip = alert.get("dest_ip") or "unknown destination"
        dest_port = alert.get("dest_port")
        service = alert.get("app_proto") or alert.get("proto") or "observed service"
        service_text = f"{service}/{dest_port}" if dest_port else service

        if classification.get("is_infrastructure_alert"):
            return (
                f"Source {src_ip} is monitoring/noise infrastructure; suppress as noise unless "
                "the destination or payload shows independent compromise evidence."
            )
        if direction == "inbound":
            return (
                f"Prioritize external source {src_ip} as attacker/infrastructure and destination "
                f"{dest_ip} {service_text} as the protected target."
            )
        if direction == "outbound":
            return (
                f"Prioritize source {src_ip} as the potentially compromised asset and destination "
                f"{dest_ip} {service_text} as possible C2, exfiltration, or malicious service."
            )
        if direction == "lateral":
            return (
                f"Treat {src_ip} -> {dest_ip} as internal lateral movement or policy violation; "
                "do not infer public threat actor attribution from private IPs alone."
            )
        if direction == "external":
            return (
                f"Both endpoints appear outside configured protected inventory; keep relevance low "
                "unless the alert rule or payload explicitly ties it to owned assets."
            )
        return "Use rule, signature, service, and explicit IoCs to decide whether source or destination is more important."

    def _infer_behavior_tags(self, alert: Dict[str, Any]) -> List[str]:
        """Infer high-level alert behaviors to improve retrieval and remediation."""
        parts = []
        for field in (
            "rule_description", "alert_signature", "alert_category",
            "proto", "app_proto", "event_type", "direction",
        ):
            if alert.get(field):
                parts.append(str(alert.get(field)))

        for context_key in ("http_context", "dns_context", "tls_context", "ioc_context", "process_context", "mitre_context"):
            context = alert.get(context_key) or {}
            if isinstance(context, dict):
                parts.extend(str(value) for value in context.values() if value not in (None, "", [], {}))

        text = " ".join(parts).lower()
        dest_port = str(alert.get("dest_port") or "")
        src_port = str(alert.get("src_port") or "")
        classification = alert.get("threat_classification") or {}
        direction = classification.get("threat_direction", "unknown")

        tags = []

        def add(tag: str):
            if tag not in tags:
                tags.append(tag)

        if re.search(r"\b(?:scan|scanner|nmap|masscan|recon|probe|enumerat|portscan|port scan)\b", text):
            add("reconnaissance_or_scanning")
        if re.search(r"\b(?:brute force|bruteforce|authentication failure|failed login|password guess|ssh login)\b", text):
            add("credential_attack")
        if re.search(r"\b(?:c2|command and control|callback|beacon|cnc|botnet)\b", text):
            add("possible_c2")
        if re.search(r"\b(?:exfil|data leak|data theft|upload|staging|archive collected)\b", text):
            add("possible_exfiltration")
        if re.search(r"\b(?:ransomware|destructive|encryptor|file write|smb file|et malware)\b", text):
            add("malware_or_destructive_activity")
        if re.search(r"\b(?:lateral movement|smb|windows admin share|psexec|rdp|winrm)\b", text) or dest_port in {"445", "3389", "5985", "5986"}:
            add("lateral_movement_candidate")
        if re.search(r"\b(?:web|http|uri|url|rce|remote code execution|sql injection|xss|traversal|php|cgi|cve-)\b", text) or dest_port in {"80", "443", "8080", "8443"}:
            add("web_or_exploit_attempt")
        if re.search(r"\b(?:malware|trojan|backdoor|dropper|payload|shellcode|powershell|cmd\.exe)\b", text):
            add("malware_execution_candidate")
        if re.search(r"\b(?:dns|domain|sni|tls|certificate)\b", text):
            add("domain_or_tls_indicator")

        if direction == "outbound" and ("possible_c2" in tags or "domain_or_tls_indicator" in tags):
            add("compromised_asset_egress")
        if direction == "inbound" and ("web_or_exploit_attempt" in tags or "reconnaissance_or_scanning" in tags):
            add("external_to_protected_asset")
        if direction == "lateral":
            add("internal_lateral_activity")

        if src_port or dest_port:
            if dest_port in {"22"}:
                add("ssh_service_activity")
            elif dest_port in {"445"}:
                add("smb_service_activity")
            elif dest_port in {"53"}:
                add("dns_service_activity")

        return tags[:8]

    def _build_response_focus(self, alert: Dict[str, Any], behavior_tags: List[str]) -> List[str]:
        """Build direction-aware response hints for the LLM."""
        classification = alert.get("threat_classification") or {}
        direction = classification.get("threat_direction", "unknown")
        src_ip = alert.get("src_ip")
        dest_ip = alert.get("dest_ip")
        dest_port = alert.get("dest_port")
        service = alert.get("app_proto") or alert.get("proto") or "service"
        service_text = f"{service}/{dest_port}" if dest_port else service
        tags = set(behavior_tags or [])

        focus = []

        def add(item: str):
            if item and item not in focus:
                focus.append(item)

        if classification.get("is_infrastructure_alert"):
            add("Suppress monitoring/noise infrastructure unless corroborated by destination compromise evidence.")
            return focus

        if direction == "inbound":
            add(f"Validate exposure and logs on destination {dest_ip or 'protected asset'} {service_text}.")
            if "reconnaissance_or_scanning" in tags:
                add(f"Rate-limit or block repeated external scanner {src_ip or 'source'} if activity persists.")
            if "web_or_exploit_attempt" in tags:
                add(f"Review web/app logs and patch/harden affected service on {dest_ip or 'destination'}.")
        elif direction == "outbound":
            add(f"Investigate source asset {src_ip or 'source'} as potentially compromised.")
            if "possible_c2" in tags or "compromised_asset_egress" in tags:
                add(f"Contain {src_ip or 'source'} and review egress/DNS/TLS logs for C2.")
            if "possible_exfiltration" in tags:
                add(f"Check data transfer volume and sensitive file access from {src_ip or 'source'}.")
        elif direction == "lateral":
            add(f"Investigate internal path {src_ip or 'source'} -> {dest_ip or 'destination'} for lateral movement.")
            if "smb_service_activity" in tags or "lateral_movement_candidate" in tags:
                add("Audit SMB/admin-share access, credentials, and endpoint process activity.")
        else:
            add("Prioritize current alert fields and asset inventory before applying generic CTI remediation.")

        if "malware_or_destructive_activity" in tags:
            add("Isolate affected endpoint(s) and preserve forensic evidence before remediation.")
        if "credential_attack" in tags:
            add("Review authentication logs, lockouts, MFA status, and exposed remote access services.")
        if "domain_or_tls_indicator" in tags:
            add("Search DNS/TLS/proxy logs for related domains, SNI, certificates, and repeated callbacks.")

        return focus[:6]


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
                    cleaned_log["src_ip_context"] = self._classify_ip_context(src_ip)
                if dest_ip:
                    cleaned_log["dest_ip_context"] = self._classify_ip_context(dest_ip)
                
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

                threat_data = data.get("threat", {}) or {}
                if threat_data:
                    cleaned_log["threat_context"] = {
                        "actor": threat_data.get("actor"),
                        "campaign": threat_data.get("campaign"),
                        "confidence": threat_data.get("confidence")
                    }

                ioc_data = data.get("ioc", {}) or {}
                if ioc_data:
                    cleaned_log["ioc_context"] = {
                        "domain": ioc_data.get("domain"),
                        "ip": ioc_data.get("ip"),
                        "url": ioc_data.get("url"),
                        "hash": ioc_data.get("hash")
                    }

                process_data = data.get("process", {}) or {}
                if process_data:
                    cleaned_log["process_context"] = {
                        "name": process_data.get("name"),
                        "parent_process": process_data.get("parent_process"),
                        "file": process_data.get("file"),
                        "path": process_data.get("path"),
                        "command_line": process_data.get("command_line")
                    }
                
                # Enhanced geolocation handling
                geolocation = {}
                
                # For external IPs, try to extract geolocation
                if src_ip and not self._is_local_asset_ip(src_ip):
                    src_geo = self._extract_geolocation_with_geoip(
                        {"src_ip": src_ip}, "src_ip", geoip_manager
                    )
                    if src_geo:
                        geolocation["src"] = src_geo
                
                # Get geolocation for external destination IPs
                if dest_ip and not self._is_local_asset_ip(dest_ip):
                    dest_geo = self._extract_geolocation_with_geoip(
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
            threat_classification = self._classify_threat(cleaned_log)
            cleaned_log["threat_classification"] = threat_classification
            behavior_tags = self._infer_behavior_tags(cleaned_log)
            if behavior_tags:
                cleaned_log["behavior_tags"] = behavior_tags
            response_focus = self._build_response_focus(cleaned_log, behavior_tags)
            if response_focus:
                cleaned_log["response_focus"] = response_focus
            observed_iocs = self._extract_observed_iocs(cleaned_log)
            if observed_iocs:
                cleaned_log["observed_iocs"] = observed_iocs
            cleaned_log["priority_reason"] = self._build_priority_reason(cleaned_log)
            cleaned_log["directional_focus"] = self._build_directional_focus(cleaned_log)
            cleaned_log["retrieval_fingerprint"] = self._build_retrieval_fingerprint(cleaned_log, observed_iocs)
            
            # Only keep logs with meaningful alert information
            if cleaned_log.get("rule_description") or cleaned_log.get("alert_signature"):
                # Remove None values and empty dicts to keep payload clean
                cleaned_log = {k: v for k, v in cleaned_log.items() 
                              if v is not None and v != {} and v != []}
                cleaned_logs.append(cleaned_log)
                
        geoip_manager.close() 
        return cleaned_logs
    
    def _classify_threat(self, alert: Dict) -> Dict[str, Any]:
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
        local_contexts = {"internal", "owned"}
        
        # Check if this is an infrastructure alert (should be low priority)
        if src_context == "infrastructure":
            classification["is_infrastructure_alert"] = True
            classification["confidence"] = "low"
            classification["threat_direction"] = "infrastructure"
            return classification
        
        # Determine threat direction and type
        if src_context in local_contexts and dest_context == "external":
            classification["threat_direction"] = "outbound"
            classification["is_internal_threat"] = True
        elif src_context == "external" and dest_context in local_contexts:
            classification["threat_direction"] = "inbound"
            classification["is_external_threat"] = True
        elif src_context in local_contexts and dest_context in local_contexts:
            classification["threat_direction"] = "lateral"
            classification["is_internal_threat"] = True
        elif dest_context == "infrastructure":
            classification["threat_direction"] = "inbound"
            classification["is_external_threat"] = src_context == "external"
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
    _mitre_catalog_cache: Optional[Dict[str, Dict[str, Any]]] = None

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
                          "signature_id", "src_ip", "dest_ip", "proto", "app_proto", "event_type",
                          "direction", "priority_reason", "directional_focus",
                          "retrieval_fingerprint"):
                value = alert.get(field)
                if value:
                    terms.update(
                        token.lower()
                        for token in re.findall(r"[A-Za-z0-9_.:/-]{4,}", str(value))
                    )
            for context_key, fields in (
                ("http_context", ("hostname", "url", "method")),
                ("dns_context", ("query_name",)),
                ("tls_context", ("sni", "issuer", "subject")),
                ("ioc_context", ("domain", "ip", "url", "hash")),
                ("process_context", ("name", "parent_process", "file", "path", "command_line")),
                ("threat_context", ("actor", "campaign")),
            ):
                context = alert.get(context_key) or {}
                if isinstance(context, dict):
                    for field in fields:
                        value = context.get(field)
                        if value:
                            terms.update(
                                token.lower()
                                for token in re.findall(r"[A-Za-z0-9_.:/-]{4,}", str(value))
                            )
            for field in ("behavior_tags", "response_focus"):
                values = alert.get(field) or []
                for value in values if isinstance(values, list) else [values]:
                    if value:
                        terms.update(
                            token.lower()
                            for token in re.findall(r"[A-Za-z0-9_.:/-]{4,}", str(value))
                        )
            observed_iocs = alert.get("observed_iocs") or {}
            if isinstance(observed_iocs, dict):
                for values in observed_iocs.values():
                    for value in values if isinstance(values, list) else [values]:
                        if value:
                            terms.update(
                                token.lower()
                                for token in re.findall(r"[A-Za-z0-9_.:/-]{4,}", str(value))
                            )
        return terms

    def _build_exact_terms_from_alerts(self, alerts: List[Dict]) -> Dict[str, List[str]]:
        exact_terms = {
            "rule_ids": [],
            "signature_ids": [],
            "source_ips": [],
            "destination_ips": [],
            "ips": [],
            "domains": [],
            "urls": [],
            "alert_signatures": [],
            "keywords": [],
        }

        def add(key: str, value: Any):
            if value in (None, "", [], {}):
                return
            text = str(value).strip()
            if text and text not in exact_terms[key]:
                exact_terms[key].append(text)

        for alert in self._select_representative_alerts(alerts, max_alerts=12):
            add("rule_ids", alert.get("rule_id"))
            add("signature_ids", alert.get("signature_id"))
            add("source_ips", alert.get("src_ip"))
            add("destination_ips", alert.get("dest_ip"))
            add("ips", alert.get("src_ip"))
            add("ips", alert.get("dest_ip"))
            add("alert_signatures", alert.get("alert_signature"))

            http_context = alert.get("http_context") or {}
            if isinstance(http_context, dict):
                add("domains", http_context.get("hostname"))
                add("urls", http_context.get("url"))

            dns_context = alert.get("dns_context") or {}
            if isinstance(dns_context, dict):
                add("domains", dns_context.get("query_name"))

            tls_context = alert.get("tls_context") or {}
            if isinstance(tls_context, dict):
                add("domains", tls_context.get("sni"))

            ioc_context = alert.get("ioc_context") or {}
            if isinstance(ioc_context, dict):
                add("domains", ioc_context.get("domain"))
                add("ips", ioc_context.get("ip"))
                add("urls", ioc_context.get("url"))
                add("keywords", ioc_context.get("hash"))

            process_context = alert.get("process_context") or {}
            if isinstance(process_context, dict):
                for field in ("name", "parent_process", "file", "path", "command_line"):
                    add("keywords", process_context.get(field))

            threat_context = alert.get("threat_context") or {}
            if isinstance(threat_context, dict):
                add("keywords", threat_context.get("actor"))
                add("keywords", threat_context.get("campaign"))
                add("threat_actors", threat_context.get("actor"))
                add("threat_actors", threat_context.get("campaign"))

            observed_iocs = alert.get("observed_iocs") or {}
            if isinstance(observed_iocs, dict):
                for value in observed_iocs.get("ips", []):
                    add("ips", value)
                for value in observed_iocs.get("domains", []):
                    add("domains", value)
                for value in observed_iocs.get("urls", []):
                    add("urls", value)
                for value in observed_iocs.get("hashes", []):
                    add("keywords", value)
                for value in observed_iocs.get("processes", []):
                    add("keywords", value)
                for value in observed_iocs.get("rule_ids", []):
                    add("rule_ids", value)
                for value in observed_iocs.get("signature_ids", []):
                    add("signature_ids", value)

        return {key: values for key, values in exact_terms.items() if values}

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
                "src_context": alert.get("src_ip_context"),
                "dst_context": alert.get("dest_ip_context"),
                "proto": alert.get("proto"),
                "app_proto": alert.get("app_proto"),
                "event_type": alert.get("event_type"),
                "direction": alert.get("direction"),
                "http": alert.get("http_context"),
                "dns": alert.get("dns_context"),
                "tls": alert.get("tls_context"),
                "ioc": alert.get("ioc_context"),
                "process": alert.get("process_context"),
                "threat": alert.get("threat_context"),
                "mitre": alert.get("mitre_context"),
                "observed_iocs": alert.get("observed_iocs"),
                "behavior_tags": alert.get("behavior_tags"),
                "response_focus": alert.get("response_focus"),
                "priority_reason": alert.get("priority_reason"),
                "directional_focus": alert.get("directional_focus"),
                "retrieval_fingerprint": alert.get("retrieval_fingerprint"),
                "threat_classification": alert.get("threat_classification")
            }
            compact_alerts.append({k: v for k, v in compact.items() if v not in (None, {}, [])})

        if not compact_alerts:
            return "No current alerts"

        return json.dumps(compact_alerts, indent=1)

    def _compact_exact_terms_for_prompt(self, exact_terms: Dict[str, List[str]], max_items: int = 8) -> Dict[str, List[str]]:
        compacted = {}
        for key, values in (exact_terms or {}).items():
            if not values:
                continue
            compacted[key] = [str(value) for value in values[:max_items]]
            remaining = len(values) - len(compacted[key])
            if remaining > 0:
                compacted[key].append(f"... {remaining} more")
        return compacted

    @staticmethod
    def _limited_values(values: List[str], max_items: int = 8) -> List[str]:
        cleaned = []
        seen = set()
        for value in values or []:
            text = str(value or "").strip()
            if not text:
                continue
            key = text.lower()
            if key in seen:
                continue
            seen.add(key)
            cleaned.append(text)
            if len(cleaned) >= max_items:
                break
        return cleaned

    def _current_observed_artifacts(self, alerts: List[Dict]) -> Dict[str, List[str]]:
        observed = {
            "ips": [],
            "domains": [],
            "urls": [],
            "hashes": [],
            "rule_ids": [],
            "signature_ids": [],
            "alert_signatures": [],
            "mitre_techniques": [],
        }

        def add(key: str, value: Any):
            if value in (None, "", [], {}):
                return
            if isinstance(value, list):
                for item in value:
                    add(key, item)
                return
            text = str(value).strip()
            if text:
                observed[key].append(text)

        for alert in alerts or []:
            add("ips", alert.get("src_ip"))
            add("ips", alert.get("dest_ip"))
            add("ips", alert.get("agent_ip"))
            add("rule_ids", alert.get("rule_id"))
            add("signature_ids", alert.get("signature_id"))
            add("alert_signatures", alert.get("alert_signature"))

            for context_key, mappings in (
                ("http_context", {"hostname": "domains", "url": "urls"}),
                ("dns_context", {"query_name": "domains"}),
                ("tls_context", {"sni": "domains"}),
                ("ioc_context", {"domain": "domains", "ip": "ips", "url": "urls", "hash": "hashes"}),
            ):
                context = alert.get(context_key) or {}
                if isinstance(context, dict):
                    for field, target_key in mappings.items():
                        add(target_key, context.get(field))

            mitre_context = alert.get("mitre_context") or {}
            if isinstance(mitre_context, dict):
                for value in mitre_context.values():
                    add("mitre_techniques", value)

            observed_iocs = alert.get("observed_iocs") or {}
            if isinstance(observed_iocs, dict):
                for key in ("ips", "domains", "urls", "hashes", "rule_ids", "signature_ids"):
                    add(key, observed_iocs.get(key))

        return {
            key: self._limited_values(values, max_items=50)
            for key, values in observed.items()
            if values
        }

    def _doc_artifacts_for_audit(self, doc: Dict[str, Any]) -> Dict[str, List[str]]:
        metadata = doc.get("metadata") or {}
        text = self._extract_context_text(doc)
        artifacts = metadata.get("cti_artifacts")
        if not isinstance(artifacts, dict):
            artifacts = CTIArtifactExtractor.extract(text)
        else:
            artifacts = {
                key: self._limited_values(list(value) if isinstance(value, list) else [value], max_items=50)
                for key, value in artifacts.items()
                if value not in (None, "", [], {})
            }

        metadata_values = {
            "ips": [metadata.get("src_ip"), metadata.get("dest_ip"), metadata.get("agent_ip"), metadata.get("ioc_ip")],
            "domains": [metadata.get("http_hostname"), metadata.get("dns_query"), metadata.get("tls_sni"), metadata.get("ioc_domain")],
            "urls": [metadata.get("http_url"), metadata.get("ioc_url")],
            "hashes": [metadata.get("ioc_hash")],
            "rule_ids": [metadata.get("rule_id")],
            "signature_ids": [metadata.get("signature_id")],
            "alert_signatures": [metadata.get("alert_signature")],
            "mitre_techniques": [metadata.get("mitre_ids"), metadata.get("mitre_techniques")],
            "threat_actors": [metadata.get("threat_actor"), metadata.get("threat_campaign")],
        }
        for key, values in metadata_values.items():
            combined = list(artifacts.get(key, []))
            for value in values:
                if isinstance(value, list):
                    combined.extend(value)
                elif value not in (None, "", [], {}):
                    combined.append(value)
            if combined:
                artifacts[key] = self._limited_values(combined, max_items=50)

        return artifacts

    @staticmethod
    def _overlap_by_type(current: Dict[str, List[str]], candidate: Dict[str, List[str]]) -> Dict[str, List[str]]:
        overlap = {}
        for key, values in current.items():
            candidate_values = {str(value).lower() for value in candidate.get(key, []) if value}
            matches = [
                str(value)
                for value in values
                if str(value).lower() in candidate_values
            ]
            if matches:
                overlap[key] = matches[:8]
        return overlap

    def _source_reliability_label(self, doc: Dict[str, Any]) -> str:
        metadata = doc.get("metadata") or {}
        source = doc.get("source") or "unknown"
        if metadata.get("human_validated"):
            return "analyst_approved_historical_report"
        if source == "archive":
            return "local_security_telemetry"
        if source == "custom_document":
            return "uploaded_cti_document"
        return source

    @staticmethod
    def _doc_context_labels(doc: Dict[str, Any]) -> List[str]:
        metadata = doc.get("metadata") or {}
        labels = metadata.get("cti_context_labels")
        if isinstance(labels, list):
            return [str(label) for label in labels if label]
        if labels:
            return [str(labels)]
        return []

    @staticmethod
    def _doc_behavior_tags(doc: Dict[str, Any]) -> List[str]:
        metadata = doc.get("metadata") or {}
        tags = metadata.get("cti_behavior_tags") or doc.get("cti_behavior_tags")
        if isinstance(tags, list):
            return [str(tag) for tag in tags if tag]
        if tags:
            return [str(tags)]
        return []

    @staticmethod
    def _current_behavior_tags(alerts: List[Dict]) -> List[str]:
        tags = []
        for alert in alerts or []:
            values = alert.get("behavior_tags") if isinstance(alert, dict) else []
            if isinstance(values, list):
                tags.extend(str(value) for value in values if value)
            elif values:
                tags.append(str(values))
        return CTIArtifactExtractor._unique(tags)

    @classmethod
    def _behavior_overlap(cls, current_tags: Iterable[Any], doc_tags: Iterable[Any]) -> List[str]:
        current = {str(tag).lower() for tag in current_tags or [] if tag}
        overlap = [
            str(tag)
            for tag in doc_tags or []
            if str(tag).lower() in current
        ]
        return CTIArtifactExtractor._unique(overlap)

    @staticmethod
    def _doc_artifact_dispositions(doc: Dict[str, Any]) -> Dict[str, Dict[str, str]]:
        metadata = doc.get("metadata") or {}
        dispositions = metadata.get("cti_artifact_dispositions") or doc.get("cti_artifact_dispositions")
        return dispositions if isinstance(dispositions, dict) else {}

    @staticmethod
    def _disposition_for_overlap(
        overlap: Dict[str, List[str]],
        dispositions: Dict[str, Dict[str, str]],
        desired: set[str],
    ) -> bool:
        for artifact_type, values in overlap.items():
            typed_dispositions = dispositions.get(artifact_type) or {}
            for value in values:
                if str(typed_dispositions.get(value) or "").lower() in desired:
                    return True
        return False

    def _annotate_context_docs(self, docs: List[Any], current_alerts: List[Dict]) -> List[Any]:
        current_artifacts = self._current_observed_artifacts(current_alerts)
        current_behavior_tags = self._current_behavior_tags(current_alerts)
        annotated = []

        for doc in docs or []:
            if not isinstance(doc, dict):
                annotated.append(doc)
                continue

            match_types = set(doc.get("match_types") or [])
            doc_artifacts = self._doc_artifacts_for_audit(doc)
            overlap = self._overlap_by_type(current_artifacts, doc_artifacts)
            overlap_count = sum(len(values) for values in overlap.values())
            reliability = self._source_reliability_label(doc)
            context_labels = self._doc_context_labels(doc)
            behavior_tags = self._doc_behavior_tags(doc)
            behavior_overlap = self._behavior_overlap(current_behavior_tags, behavior_tags)
            behavior_mismatch = bool(current_behavior_tags and behavior_tags and not behavior_overlap)
            artifact_dispositions = self._doc_artifact_dispositions(doc)
            malicious_overlap = self._disposition_for_overlap(overlap, artifact_dispositions, {"malicious"})
            non_attacker_overlap = self._disposition_for_overlap(
                overlap,
                artifact_dispositions,
                {"victim", "analysis_environment", "benign"},
            )

            if "exact" in match_types and overlap_count > 0 and not non_attacker_overlap:
                evidence_strength = "high"
            elif malicious_overlap and overlap_count > 0:
                evidence_strength = "high"
            elif "exact" in match_types or overlap_count >= 2:
                evidence_strength = "medium"
            elif "lexical" in match_types and overlap_count > 0:
                evidence_strength = "medium"
            else:
                evidence_strength = "low"

            notes = []
            if doc.get("source") == "custom_document":
                notes.append("uploaded CTI is historical/contextual unless current alert has exact overlap")
            if "semantic" in match_types and "exact" not in match_types:
                notes.append("semantic-only support; do not use alone for attribution")
            if overlap_count == 0:
                notes.append("no exact current-alert IoC overlap")
            if doc.get("source") == "custom_document" and "analysis_environment" in context_labels:
                notes.append("analysis-environment details may not be malicious infrastructure")
            if doc.get("source") == "custom_document" and "victim_infrastructure" in context_labels:
                notes.append("victim/target infrastructure should not be treated as attacker infrastructure")
            if non_attacker_overlap:
                notes.append("current overlap is marked benign, victim, or analysis-environment, not attacker infrastructure")
            if behavior_mismatch:
                notes.append("CTI behavior tags do not align with current alert behavior")
            document_quality = (doc.get("metadata") or {}).get("document_quality") or {}
            if isinstance(document_quality, dict) and document_quality.get("quality") in {"low", "empty"}:
                warnings = ", ".join(document_quality.get("warnings") or [])
                notes.append(
                    "source document extraction quality is "
                    f"{document_quality.get('quality')}"
                    + (f" ({warnings})" if warnings else "")
                )
            if evidence_strength == "low":
                notes.append("use only for weak background context")

            historical_only = {}
            for key in ("ips", "domains", "urls", "hashes", "mitre_techniques"):
                current_values = {str(value).lower() for value in current_artifacts.get(key, [])}
                extras = [
                    value for value in doc_artifacts.get(key, [])
                    if str(value).lower() not in current_values
                ]
                if extras:
                    historical_only[key] = self._limited_values(extras, max_items=5)

            doc["source_reliability"] = reliability
            doc["evidence_strength"] = evidence_strength
            doc["cti_context_labels"] = context_labels
            doc["cti_behavior_tags"] = behavior_tags
            doc["behavior_overlap"] = behavior_overlap
            doc["behavior_mismatch"] = behavior_mismatch
            doc["cti_artifact_dispositions"] = artifact_dispositions
            doc["current_ioc_overlap"] = overlap
            doc["historical_only_artifacts"] = historical_only
            doc["retrieval_cautions"] = notes[:6]
            annotated.append(doc)

        return annotated

    def _filter_context_docs_by_evidence_quality(self, docs: List[Any], limit: int) -> List[Any]:
        """Keep weak semantic background from crowding out stronger evidence."""
        if not docs or limit <= 0:
            return []

        passthrough = [doc for doc in docs if not isinstance(doc, dict)]
        structured = [doc for doc in docs if isinstance(doc, dict)]
        strong = [
            doc for doc in structured
            if str(doc.get("evidence_strength") or "").lower() in {"high", "medium"}
        ]
        weak = [
            doc for doc in structured
            if str(doc.get("evidence_strength") or "").lower() not in {"high", "medium"}
        ]

        selected = []
        selected.extend(passthrough[:limit])
        remaining = max(0, limit - len(selected))
        selected.extend(strong[:remaining])
        remaining = max(0, limit - len(selected))

        if remaining <= 0:
            return selected[:limit]

        if strong:
            weak_cap = min(1, remaining)
        else:
            weak_cap = remaining
        selected.extend(weak[:weak_cap])
        return selected[:limit]

    def _select_relevant_context_docs(self, docs: List[Any], current_alerts: List[Dict],
                                      max_docs: int = None, source_filter: str = None) -> List[Any]:
        if not docs:
            return []

        limit = max_docs or getattr(self.rag_manager, "max_retrieval_docs", 8)
        terms = self._collect_alert_terms(current_alerts)
        current_behavior_tags = self._current_behavior_tags(current_alerts)
        ranked = []

        for order, doc in enumerate(docs):
            if source_filter and isinstance(doc, dict) and doc.get("source") != source_filter:
                continue

            text = self._extract_context_text(doc)
            if not text:
                continue

            metadata = doc.get("metadata", {}) if isinstance(doc, dict) else {}
            haystack = f"{text} {json.dumps(metadata, sort_keys=True, default=str)}".lower()
            lexical_hits = sum(
                1 for term in terms
                if len(term) >= 4 and self.rag_manager._contains_exact_term(haystack, term)
            )
            similarity = 0.0
            match_types = set()
            evidence_count = 0
            if isinstance(doc, dict):
                similarity = float(doc.get("score") or 0.0)
                match_types = set(doc.get("match_types") or [])
                evidence_count = len(doc.get("match_evidence") or [])

            severity_boost = 0.0
            try:
                severity = int(metadata.get("severity") or 0)
                if severity >= 12:
                    severity_boost = 0.5
                elif severity >= 8:
                    severity_boost = 0.25
            except (TypeError, ValueError):
                pass

            source_boost = 0.25 if isinstance(doc, dict) and doc.get("source") == "custom_document" else 0.1
            exact_boost = 2.0 if "exact" in match_types else 0.0
            lexical_boost = min(lexical_hits, 10) * 0.18
            semantic_boost = min(max(similarity, 0.0), 1.5) * 1.2
            evidence_boost = min(evidence_count, 5) * 0.15
            doc_behavior_tags = self._doc_behavior_tags(doc) if isinstance(doc, dict) else []
            behavior_overlap = self._behavior_overlap(current_behavior_tags, doc_behavior_tags)
            behavior_boost = min(len(behavior_overlap), 3) * 0.35
            behavior_penalty = (
                -0.45
                if current_behavior_tags and doc_behavior_tags and not behavior_overlap and "exact" not in match_types
                else 0.0
            )
            rank_score = (
                exact_boost + lexical_boost + semantic_boost + evidence_boost
                + severity_boost + source_boost + behavior_boost + behavior_penalty
            )

            if isinstance(doc, dict):
                doc["context_rank_score"] = round(rank_score, 3)

            ranked.append((rank_score, lexical_hits, similarity, -order, doc))

        ranked.sort(reverse=True, key=lambda item: item[:4])
        annotated = self._annotate_context_docs([item[4] for item in ranked[:limit]], current_alerts)
        return self._filter_context_docs_by_evidence_quality(annotated, limit)

    def _context_doc_key(self, doc: Any) -> tuple:
        if isinstance(doc, dict):
            metadata = doc.get("metadata") or {}
            stable_id = (
                doc.get("source"),
                doc.get("id"),
                metadata.get("raw_alert_hash"),
                metadata.get("raw_document_hash"),
                metadata.get("content_hash"),
                metadata.get("source_document"),
                metadata.get("chunk_index"),
            )
            if any(value not in (None, "", [], {}) for value in stable_id):
                return stable_id
        return ("content", hashlib.sha256(self._extract_context_text(doc).encode("utf-8")).hexdigest())

    def _dedupe_context_docs(self, docs: List[Any]) -> List[Any]:
        merged: Dict[tuple, Any] = {}
        for doc in docs:
            key = self._context_doc_key(doc)
            existing = merged.get(key)
            if not existing:
                merged[key] = doc
                continue

            if not isinstance(existing, dict) or not isinstance(doc, dict):
                continue

            if float(doc.get("score") or 0.0) > float(existing.get("score") or 0.0):
                existing["score"] = doc.get("score")
            if doc.get("context_rank_score") is not None:
                existing["context_rank_score"] = max(
                    float(existing.get("context_rank_score") or 0.0),
                    float(doc.get("context_rank_score") or 0.0)
                )
            existing["match_types"] = sorted(set(existing.get("match_types", [])) | set(doc.get("match_types", [])))
            evidence = []
            for item in existing.get("match_evidence", []) + doc.get("match_evidence", []):
                if item and item not in evidence:
                    evidence.append(item)
            existing["match_evidence"] = evidence[:8]

            queries = []
            for query in [existing.get("retrieval_query"), doc.get("retrieval_query")]:
                if query and query not in queries:
                    queries.append(query)
            if queries:
                existing["retrieval_query"] = " || ".join(queries[:3])

        return list(merged.values())

    def _build_focused_retrieval_queries(self, alerts: List[Dict], max_queries: int = 5) -> List[str]:
        queries = [self._build_query_from_alerts(alerts)]
        for alert in self._select_representative_alerts(alerts, max_alerts=max(1, max_queries - 1)):
            parts = []
            for field in ("retrieval_fingerprint", "priority_reason", "rule_description",
                          "alert_signature", "alert_category", "rule_id", "signature_id",
                          "directional_focus", "src_ip", "dest_ip", "proto",
                          "app_proto", "event_type"):
                if alert.get(field):
                    parts.append(str(alert.get(field)))

            for field in ("behavior_tags", "response_focus"):
                values = alert.get(field) or []
                if isinstance(values, list):
                    parts.extend(str(value) for value in values if value not in (None, "", [], {}))
                elif values not in (None, "", [], {}):
                    parts.append(str(values))

            classification = alert.get("threat_classification") or {}
            if isinstance(classification, dict):
                parts.append(" ".join(str(value) for value in classification.values() if value not in (None, "", [], {})))

            observed_iocs = alert.get("observed_iocs") or {}
            if isinstance(observed_iocs, dict):
                for values in observed_iocs.values():
                    if isinstance(values, list):
                        parts.extend(str(value) for value in values if value not in (None, "", [], {}))
                    elif values not in (None, "", [], {}):
                        parts.append(str(values))

            query = " ".join(parts).strip()
            if query:
                queries.append(query)

        unique_queries = []
        seen = set()
        for query in queries:
            normalized = re.sub(r"\s+", " ", query).strip()
            if not normalized:
                continue
            key = normalized.lower()
            if key in seen:
                continue
            seen.add(key)
            unique_queries.append(normalized)
            if len(unique_queries) >= max_queries:
                break
        return unique_queries or ["security incident analysis"]

    def _retrieve_context_for_alerts(self, alerts: List[Dict], k: int = None,
                                     metadata_filter: dict = None,
                                     source_mode: str = "all") -> List[Dict[str, Any]]:
        limit = k or min(getattr(self.rag_manager, "max_retrieval_docs", 8), 8)
        exact_terms = self._build_exact_terms_from_alerts(alerts)
        queries = self._build_focused_retrieval_queries(alerts)
        candidates: List[Dict[str, Any]] = []

        for query in queries:
            try:
                if source_mode == "custom":
                    docs = self.rag_manager.search_custom_documents(query, k=max(limit * 2, limit), exact_terms=exact_terms)
                elif source_mode == "archive":
                    docs = self.rag_manager.search_archive_alerts(
                        query,
                        k=max(limit * 2, limit),
                        metadata_filter=metadata_filter,
                        exact_terms=exact_terms
                    )
                else:
                    retriever = self.rag_manager.get_retriever(
                        k=max(limit * 2, limit),
                        metadata_filter=metadata_filter,
                        exact_terms=exact_terms
                    )
                    docs = retriever(query)

                for doc in docs:
                    if isinstance(doc, dict):
                        doc["retrieval_query"] = query[:240]
                candidates.extend(docs)
            except Exception as e:
                self.rag_manager._rollback_safely()
                print(f"WARNING: Focused retrieval failed for query '{query[:80]}': {e}")

        deduped = self._dedupe_context_docs(candidates)
        source_filter = None
        if source_mode == "archive":
            source_filter = "archive"
        elif source_mode == "custom":
            source_filter = "custom_document"
        return self._select_relevant_context_docs(deduped, alerts, max_docs=limit, source_filter=source_filter)

    def _create_retrieval_summary(self, docs: List[Any]) -> str:
        if not docs:
            return "No RAG sources selected after focused retrieval and reranking."

        sources: Dict[str, int] = {}
        match_types: Dict[str, int] = {}
        evidence_strengths: Dict[str, int] = {}
        reliability_labels: Dict[str, int] = {}
        behavior_alignment = {"overlap": 0, "mismatch": 0, "unknown": 0}
        caution_count = 0
        top_scores = []
        for doc in docs:
            if not isinstance(doc, dict):
                sources["inline"] = sources.get("inline", 0) + 1
                continue
            source = doc.get("source") or "unknown"
            sources[source] = sources.get(source, 0) + 1
            strength = doc.get("evidence_strength") or "unknown"
            evidence_strengths[strength] = evidence_strengths.get(strength, 0) + 1
            reliability = doc.get("source_reliability") or "unknown"
            reliability_labels[reliability] = reliability_labels.get(reliability, 0) + 1
            if doc.get("behavior_overlap"):
                behavior_alignment["overlap"] += 1
            elif doc.get("behavior_mismatch"):
                behavior_alignment["mismatch"] += 1
            else:
                behavior_alignment["unknown"] += 1
            if doc.get("retrieval_cautions"):
                caution_count += 1
            for match_type in doc.get("match_types") or []:
                match_types[match_type] = match_types.get(match_type, 0) + 1
            top_scores.append({
                "source": source,
                "reliability": reliability,
                "evidence_strength": strength,
                "score": doc.get("score"),
                "rank_score": doc.get("context_rank_score"),
                "matches": doc.get("match_types"),
                "current_ioc_overlap": doc.get("current_ioc_overlap") or {},
                "behavior_overlap": doc.get("behavior_overlap") or [],
                "behavior_mismatch": bool(doc.get("behavior_mismatch")),
            })

        return json.dumps(
            {
                "selected_sources": len(docs),
                "source_counts": sources,
                "match_type_counts": match_types,
                "evidence_strength_counts": evidence_strengths,
                "source_reliability_counts": reliability_labels,
                "behavior_alignment_counts": behavior_alignment,
                "sources_with_cautions": caution_count,
                "top_ranked_sources": top_scores[:5],
            },
            indent=1,
            default=str
        )
    
    def generate_report_with_rag(self, current_alerts: List[Dict], server_host: str = "unknown", 
                             is_automatic: bool = False, trigger_info: Dict = None) -> str:
        """Generate threat analysis report using simplified severity-based RAG logic"""
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
        
        historical_filter = self._build_metadata_filter(
            high_severity_alerts,
            is_automatic=True,
            trigger_info=trigger_info
        )
        custom_docs = self._retrieve_context_for_alerts(high_severity_alerts, k=4, source_mode="custom")
        historical_docs = self._retrieve_context_for_alerts(
            high_severity_alerts,
            k=4,
            metadata_filter=historical_filter,
            source_mode="archive"
        )
        combined_context_docs = self._select_relevant_context_docs(
            custom_docs + historical_docs,
            high_severity_alerts,
            max_docs=4
        )
        custom_context = (
            self._format_context_docs(combined_context_docs, max_chars=500)
            if combined_context_docs
            else self._get_custom_docs_context(high_severity_alerts)
        )
        source_manifest = self._format_rag_sources(combined_context_docs)
        retrieval_summary = self._create_retrieval_summary(combined_context_docs)
        
        # Analyze current alerts
        analysis = self.alert_analyzer.analyze_current_alerts(all_alerts)
        
        # Create compact alert summary to prevent token overflow
        max_alerts_for_llm = 6
        compact_alerts = self._create_compact_alert_summary(high_severity_alerts, max_alerts_for_llm)
        more_alerts_count = max(0, len(high_severity_alerts) - max_alerts_for_llm)
        exact_terms = self._build_exact_terms_from_alerts(high_severity_alerts)
        prompt_exact_terms = self._compact_exact_terms_for_prompt(exact_terms)
        
        # Build the compact incident context for the LLM.
        context = f"""ANALYSIS TYPE: HIGH-SEVERITY AUTOMATIC INCIDENT RESPONSE
    RAG STRATEGY: Custom Documentation + High-Severity Historical Alert Context

    CURRENT HIGH-SEVERITY INCIDENT DATA:
    - Total Alerts: {len(all_alerts)}
    - High-Severity Alerts (threshold >= {self._get_high_severity_threshold(trigger_info)}): {len(high_severity_alerts)}
    - Threat Distribution: {analysis['threat_classification']}
    - Exact Retrieval Hints: {prompt_exact_terms or "none"}
    - Semantic Similarity Threshold: {getattr(self.rag_manager, "similarity_threshold", "not configured")}
    - Retrieval Quality Summary: {retrieval_summary}
    - RAG Evidence Audit: Use evidence_strength/source_reliability/current_ioc_overlap/cautions from each source. Low-strength or semantic-only sources are background context only.

    CONFIGURED ASSET INVENTORY:
    {self.alert_analyzer.get_inventory_prompt()}

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
        qa_appendix = self._format_report_quality_findings(
            self._audit_report_claims(report_content, combined_context_docs, high_severity_alerts)
        )
        
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
        return report_header + report_content + qa_appendix + source_manifest

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
        """Generate report using full RAG context."""
        
        metadata_filter = self._build_metadata_filter(cleaned_alerts, is_automatic, trigger_info)
        exact_terms = self._build_exact_terms_from_alerts(cleaned_alerts)
        prompt_exact_terms = self._compact_exact_terms_for_prompt(exact_terms)
        context_docs = self._retrieve_context_for_alerts(
            cleaned_alerts,
            k=min(getattr(self.rag_manager, "max_retrieval_docs", 5), 5),
            metadata_filter=metadata_filter,
            source_mode="all"
        )
        full_rag_context = (
            self._format_context_docs(context_docs, max_chars=500)
            if context_docs
            else "No directly relevant historical patterns found."
        )
        source_manifest = self._format_rag_sources(context_docs)
        retrieval_summary = self._create_retrieval_summary(context_docs)
        
        # Analyze current alerts
        analysis = self.alert_analyzer.analyze_current_alerts(cleaned_alerts)
        
        # Build the compact incident context for the LLM.
        analysis_type = "MANUAL ANALYSIS" if not is_automatic else "AUTOMATIC STANDARD ANALYSIS"
        
        context = f"""ANALYSIS TYPE: {analysis_type}
    RAG STRATEGY: Full Context (Historical Alerts + Custom Documentation)

    CURRENT ALERTS DATA:
    - Total Alerts: {len(cleaned_alerts)}
    - Representative Alerts Shown: {min(6, len(cleaned_alerts))}
    - Severity Distribution: {analysis['severity_breakdown']}
    - Threat Classification: {analysis['threat_classification']}
    - Archive Metadata Filter: {metadata_filter or "none"}
    - Exact Retrieval Hints: {prompt_exact_terms or "none"}
    - Semantic Similarity Threshold: {getattr(self.rag_manager, "similarity_threshold", "not configured")}
    - Retrieval Quality Summary: {retrieval_summary}
    - RAG Evidence Audit: Use evidence_strength/source_reliability/current_ioc_overlap/cautions from each source. Low-strength or semantic-only sources are background context only.

    CONFIGURED ASSET INVENTORY:
    {self.alert_analyzer.get_inventory_prompt()}

    REPRESENTATIVE CURRENT ALERTS:
    {self._create_current_alert_context(cleaned_alerts, max_alerts=6)}

    HISTORICAL AND CUSTOM REFERENCE CONTEXT:
    {full_rag_context}

    CONTEXT: {"Manual security analysis with comprehensive context." if not is_automatic else "Automatic analysis for standard-severity incidents."}
    INSTRUCTIONS: When using RAG evidence, cite the bracketed source label such as [RAG-1]."""
        
        # Uses existing cti.txt system prompt via LLM client
        report_content = self.llm_client.generate_response(context)
        
        # Clean the response to remove forbidden elements
        report_content = self._clean_report_content(report_content)
        qa_appendix = self._format_report_quality_findings(
            self._audit_report_claims(report_content, context_docs, cleaned_alerts)
        )
        
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
        
        return report_header + report_content + qa_appendix + source_manifest

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
                "src_context": alert.get("src_ip_context"),
                "dst_context": alert.get("dest_ip_context"),
                "time": str(timestamp)[:19] if timestamp else "?",
                "priority_reason": alert.get("priority_reason")
            }
            
            # Add key context if available
            signature = alert.get("alert_signature")
            if signature:
                compact["sig"] = str(signature)[:60]
            if alert.get("ioc_context"):
                compact["ioc"] = alert.get("ioc_context")
            if alert.get("process_context"):
                compact["process"] = alert.get("process_context")
            if alert.get("threat_context"):
                compact["threat"] = alert.get("threat_context")
            if alert.get("observed_iocs"):
                compact["observed_iocs"] = alert.get("observed_iocs")
            if alert.get("threat_classification"):
                compact["classification"] = alert.get("threat_classification")
            
            summaries.append(compact)
        
        return json.dumps(summaries, indent=1)

    def _search_custom_doc_results(self, alerts: List[Dict], k: int = 4) -> List[Dict[str, Any]]:
        if not hasattr(self.rag_manager, "search_custom_documents"):
            return []

        try:
            return self._retrieve_context_for_alerts(alerts, k=k, source_mode="custom")
        except Exception as e:
            self.rag_manager._rollback_safely()
            print(f"WARNING: Custom document search failed: {e}")
            return []

    def _search_historical_alert_results(self, alerts: List[Dict], trigger_info: Dict = None,
                                         k: int = 4) -> List[Dict[str, Any]]:
        try:
            metadata_filter = self._build_metadata_filter(alerts, is_automatic=True, trigger_info=trigger_info)
            return self._retrieve_context_for_alerts(
                alerts,
                k=k,
                metadata_filter=metadata_filter,
                source_mode="archive"
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
            doc_text = doc.get("content", "") if isinstance(doc, dict) else str(doc)
            doc_lower = doc_text.lower()
            relevance = sum(1 for term in query_terms if term in doc_lower and len(term) > 3)
            if relevance > 0:
                content = doc_text[:800] + "..." if len(doc_text) > 800 else doc_text
                relevant_content.append(content)
        
        return "\n\n".join(relevant_content[:4]) if relevant_content else "No directly relevant custom documentation found."

    def _extract_context_text(self, doc: Any) -> str:
        """Support pgvector dict results, document-like objects, and plain strings."""
        if isinstance(doc, dict):
            return str(doc.get("content") or doc.get("page_content") or "")
        if hasattr(doc, "page_content"):
            return str(doc.page_content or "")
        return str(doc or "")

    @staticmethod
    def _normalize_claim_token(value: Any) -> str:
        return re.sub(r"\s+", " ", str(value or "")).strip().lower()

    @classmethod
    def _load_mitre_catalog(cls) -> Dict[str, Dict[str, Any]]:
        if cls._mitre_catalog_cache is not None:
            return cls._mitre_catalog_cache

        catalog_path = Path(__file__).resolve().parent / "mitre_techniques.json"
        catalog: Dict[str, Dict[str, Any]] = {}
        try:
            raw_catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
            if isinstance(raw_catalog, list):
                for entry in raw_catalog:
                    if not isinstance(entry, dict):
                        continue
                    technique_id = cls._normalize_claim_token(entry.get("id"))
                    if technique_id:
                        catalog[technique_id] = entry
        except Exception as error:
            print(f"Warning: Could not load MITRE technique catalog: {error}")

        cls._mitre_catalog_cache = catalog
        return catalog

    def _supported_doc_subset(self, docs: List[Any], min_strengths: set[str] = None) -> List[Dict[str, Any]]:
        strengths = min_strengths or {"high", "medium"}
        return [
            doc for doc in docs or []
            if isinstance(doc, dict) and str(doc.get("evidence_strength") or "").lower() in strengths
        ]

    def _report_mentions_value(self, report_text: str, value: Any, term_type: str = None) -> bool:
        text = str(report_text or "")
        term = str(value or "").strip()
        if not text or not term or len(term) < 3:
            return False
        return RAGContextManager._contains_exact_term(text, term, term_type=term_type)

    def _supported_attribution_terms(
        self,
        current_artifacts: Dict[str, List[str]],
        supported_docs: List[Dict[str, Any]],
    ) -> set[str]:
        terms = {
            self._normalize_claim_token(value)
            for value in current_artifacts.get("threat_actors", [])
            if value
        }
        for doc in supported_docs:
            labels = set(doc.get("cti_context_labels") or [])
            if "attribution" not in labels:
                continue
            if not doc.get("current_ioc_overlap"):
                continue
            doc_artifacts = self._doc_artifacts_for_audit(doc)
            terms.update(
                self._normalize_claim_token(value)
                for value in doc_artifacts.get("threat_actors", [])
                if value
            )
        return terms

    @staticmethod
    def _remediation_action_labels(text: str) -> List[str]:
        labels = []
        action_patterns = {
            "block": r"\b(?:block|denylist|blacklist|firewall rule|drop traffic)\b",
            "isolate": r"\b(?:isolate|quarantine|contain)\b",
            "disable": r"\b(?:disable|deactivate|shut down|turn off)\b",
            "monitor": r"\b(?:monitor|hunt for|detect|alert on)\b",
        }
        for label, pattern in action_patterns.items():
            if re.search(pattern, text, flags=re.IGNORECASE):
                labels.append(label)
        return labels

    def _remediation_targets_in_report(self, report_text: str) -> Dict[str, Dict[str, List[str]]]:
        """Find artifacts mentioned near remediation verbs in generated text."""
        targets: Dict[str, Dict[str, List[str]]] = {}
        artifacts = CTIArtifactExtractor.extract(report_text)
        for artifact_type, term_type in (("ips", "ip"), ("domains", "domain"), ("urls", "url"), ("hashes", None)):
            for value in artifacts.get(artifact_type, [])[:40]:
                contexts = CTIArtifactExtractor._artifact_contexts(
                    report_text,
                    value,
                    term_type=term_type,
                    radius=120,
                    sentence_local=True,
                )
                action_labels = []
                for context in contexts:
                    action_labels.extend(self._remediation_action_labels(context))
                action_labels = CTIArtifactExtractor._unique(action_labels)
                if action_labels:
                    targets.setdefault(artifact_type, {})[str(value)] = action_labels
        return targets

    @staticmethod
    def _disposition_for_value(
        docs: List[Any],
        artifact_type: str,
        value: Any,
    ) -> Optional[str]:
        needle = str(value or "").lower()
        if not needle:
            return None
        for doc in docs or []:
            if not isinstance(doc, dict):
                continue
            metadata = doc.get("metadata") or {}
            dispositions = doc.get("cti_artifact_dispositions") or metadata.get("cti_artifact_dispositions") or {}
            if not isinstance(dispositions, dict):
                continue
            typed_dispositions = dispositions.get(artifact_type) or {}
            for candidate, disposition in typed_dispositions.items():
                if str(candidate).lower() == needle and disposition:
                    return str(disposition).lower()
        return None

    def _audit_report_claims(
        self,
        report_text: str,
        context_docs: List[Any],
        current_alerts: List[Dict],
    ) -> List[str]:
        """Create reviewer-facing warnings for claims that need stronger support."""
        report_text = str(report_text or "")
        if not report_text.strip():
            return []

        findings = []
        lower_report = report_text.lower()
        current_artifacts = self._current_observed_artifacts(current_alerts)
        supported_docs = self._supported_doc_subset(context_docs)

        attribution_supported = any(
            "attribution" in (doc.get("cti_context_labels") or [])
            and doc.get("current_ioc_overlap")
            for doc in supported_docs
        )
        actor_terms = sorted(set(CTIArtifactExtractor.ATTACK_GROUP_RE.findall(report_text)))
        attribution_language = re.search(
            r"\b(?:attributed to|associated with|linked to|ties to|campaign|threat actor|"
            r"malware family|operator|nation[- ]state)\b",
            report_text,
            flags=re.IGNORECASE,
        )
        if (actor_terms or attribution_language) and not attribution_supported:
            actor_note = f" ({', '.join(actor_terms[:5])})" if actor_terms else ""
            findings.append(
                "Attribution language appears in the report"
                f"{actor_note}, but no high/medium-strength attribution RAG source "
                "with current-alert overlap was selected. Treat actor/family attribution as low confidence."
            )
        if actor_terms:
            supported_actor_terms = self._supported_attribution_terms(current_artifacts, supported_docs)
            unsupported_actor_terms = sorted(
                term.upper()
                for term in {
                    self._normalize_claim_token(value)
                    for value in actor_terms
                    if value
                }
                if term not in supported_actor_terms
            )
            if unsupported_actor_terms:
                findings.append(
                    "Specific threat actor term(s) appear without matching current-alert or high/medium attribution support: "
                    + ", ".join(unsupported_actor_terms[:8])
                    + ". Verify actor attribution before approval."
                )

        current_mitre = {
            self._normalize_claim_token(value)
            for value in current_artifacts.get("mitre_techniques", [])
        }
        current_behavior_tags = self._current_behavior_tags(current_alerts)
        supported_mitre = set()
        for doc in supported_docs:
            doc_artifacts = self._doc_artifacts_for_audit(doc)
            labels = set(doc.get("cti_context_labels") or [])
            if "ttp_behavior" not in labels and "vulnerability" not in labels:
                continue
            doc_behavior_tags = self._doc_behavior_tags(doc)
            if current_behavior_tags and doc_behavior_tags and not self._behavior_overlap(current_behavior_tags, doc_behavior_tags):
                continue
            supported_mitre.update(
                self._normalize_claim_token(value)
                for value in doc_artifacts.get("mitre_techniques", [])
            )

        report_mitre = {
            self._normalize_claim_token(value)
            for value in CTIArtifactExtractor.MITRE_TECHNIQUE_RE.findall(report_text)
        }
        mitre_catalog = self._load_mitre_catalog()
        if mitre_catalog and report_mitre:
            unknown_mitre = sorted(
                value.upper()
                for value in report_mitre
                if value not in mitre_catalog
            )
            deprecated_mitre = sorted(
                value.upper()
                for value in report_mitre
                if str(mitre_catalog.get(value, {}).get("deprecated", "")).lower() == "true"
            )
            if unknown_mitre:
                findings.append(
                    "MITRE technique ID(s) are not present in the local ATT&CK catalog: "
                    + ", ".join(unknown_mitre[:8])
                    + ". Verify for typo, stale mapping, or unsupported generated technique ID."
                )
            if deprecated_mitre:
                findings.append(
                    "MITRE technique ID(s) are marked deprecated in the local ATT&CK catalog: "
                    + ", ".join(deprecated_mitre[:8])
                    + ". Prefer current ATT&CK mappings where possible."
                )
        unsupported_mitre = sorted(
            value.upper()
            for value in report_mitre
            if value not in current_mitre and value not in supported_mitre
        )
        if unsupported_mitre:
            findings.append(
                "MITRE technique(s) appear without direct current-alert or high/medium TTP support: "
                + ", ".join(unsupported_mitre[:8])
                + ". Verify mapping before approval."
            )

        weak_docs = self._supported_doc_subset(context_docs, min_strengths={"low"})
        leaked_artifacts = []
        for doc in weak_docs:
            historical_only = doc.get("historical_only_artifacts") or {}
            for key, term_type in (("ips", "ip"), ("domains", "domain"), ("urls", "url"), ("hashes", None)):
                for value in historical_only.get(key, [])[:8]:
                    if self._report_mentions_value(report_text, value, term_type=term_type):
                        leaked_artifacts.append(str(value))

        if leaked_artifacts:
            findings.append(
                "Report mentions artifact(s) that only appeared in low-strength historical context: "
                + ", ".join(self._limited_values(leaked_artifacts, max_items=8))
                + ". Label these as historical/contextual or remove incident-specific wording."
            )

        if "block" in lower_report or "isolate" in lower_report or "disable" in lower_report:
            if not any(doc.get("evidence_strength") in {"high", "medium"} for doc in context_docs if isinstance(doc, dict)):
                findings.append(
                    "Containment/remediation actions are recommended while all selected RAG support is weak. "
                    "Ensure actions are grounded in current alert fields and asset direction."
                )
            remediation_targets = self._remediation_targets_in_report(report_text)
            unobserved_targets = []
            non_actionable_targets = []
            for artifact_type, values in remediation_targets.items():
                current_values = {
                    str(value).lower()
                    for value in current_artifacts.get(artifact_type, [])
                    if value
                }
                for value, action_labels in values.items():
                    if str(value).lower() not in current_values:
                        unobserved_targets.append(f"{value} ({'/'.join(action_labels)})")
                    disposition = self._disposition_for_value(context_docs, artifact_type, value)
                    action_set = {str(action).lower() for action in action_labels}
                    if disposition in {"benign", "analysis_environment", "remediation_reference"}:
                        non_actionable_targets.append(f"{value}={disposition}")
                    elif disposition == "victim" and action_set.intersection({"block", "disable"}):
                        non_actionable_targets.append(f"{value}=victim")

            if unobserved_targets:
                findings.append(
                    "Remediation action target(s) were not observed in current alert artifacts: "
                    + ", ".join(self._limited_values(unobserved_targets, max_items=8))
                    + ". Phrase as historical/proactive blocking unless independently observed."
                )
            if non_actionable_targets:
                findings.append(
                    "Remediation action target(s) are labeled benign, victim-side, analysis-environment, or remediation-reference in RAG: "
                    + ", ".join(self._limited_values(non_actionable_targets, max_items=8))
                    + ". Verify the intended target and action before approval."
                )

        return self._limited_values(findings, max_items=8)

    def _format_report_quality_findings(self, findings: List[str]) -> str:
        if not findings:
            return ""
        lines = ["", "---", "", "## Report QA Findings"]
        lines.append("")
        lines.append(
            "These reviewer-facing checks flag claims that may need stronger evidence before approval."
        )
        lines.append("")
        for finding in findings:
            lines.append(f"- {finding}")
        return "\n".join(lines) + "\n"

    def _format_doc_metadata(self, doc: Any) -> str:
        if not isinstance(doc, dict):
            return "source=inline"

        metadata = doc.get("metadata") or {}
        source = doc.get("source") or "unknown"
        score = doc.get("score")
        parts = [f"source={source}"]
        match_types = doc.get("match_types")
        if match_types:
            parts.append(f"match={'+'.join(match_types)}")
        if doc.get("evidence_strength"):
            parts.append(f"evidence_strength={doc.get('evidence_strength')}")
        if doc.get("source_reliability"):
            parts.append(f"source_reliability={doc.get('source_reliability')}")
        section_path = metadata.get("cti_section_path")
        if section_path:
            parts.append(f"cti_section={section_path}")
        context_labels = doc.get("cti_context_labels") or metadata.get("cti_context_labels")
        if context_labels:
            if isinstance(context_labels, list):
                parts.append(f"cti_context={'+'.join(str(label) for label in context_labels if label)}")
            else:
                parts.append(f"cti_context={context_labels}")
        behavior_tags = doc.get("cti_behavior_tags") or metadata.get("cti_behavior_tags")
        if behavior_tags:
            if isinstance(behavior_tags, list):
                parts.append(f"cti_behavior={'+'.join(str(tag) for tag in behavior_tags if tag)}")
            else:
                parts.append(f"cti_behavior={behavior_tags}")
        if doc.get("behavior_overlap"):
            parts.append("behavior_overlap=" + "+".join(str(tag) for tag in doc.get("behavior_overlap") if tag))
        if doc.get("behavior_mismatch"):
            parts.append("behavior_mismatch=true")
        dispositions = doc.get("cti_artifact_dispositions") or metadata.get("cti_artifact_dispositions")
        disposition_summary = CTIArtifactExtractor.summarize_dispositions(dispositions) if isinstance(dispositions, dict) else ""
        if disposition_summary:
            parts.append(disposition_summary.replace("CTI Artifact Disposition | ", "artifact_disposition="))
        document_quality = metadata.get("document_quality")
        if isinstance(document_quality, dict) and document_quality.get("quality"):
            quality_text = str(document_quality.get("quality"))
            warnings = document_quality.get("warnings") or []
            if warnings:
                quality_text += f"({','.join(str(item) for item in warnings[:4])})"
            parts.append(f"document_quality={quality_text}")
        if score is not None:
            try:
                parts.append(f"score={float(score):.3f}")
            except (TypeError, ValueError):
                parts.append(f"score={score}")
        if doc.get("context_rank_score") is not None:
            parts.append(f"rank={doc.get('context_rank_score')}")
        if doc.get("retrieval_query"):
            query_hint = re.sub(r"\s+", " ", str(doc.get("retrieval_query"))).strip()
            if len(query_hint) > 120:
                query_hint = query_hint[:117].rstrip() + "..."
            parts.append(f"query={query_hint}")
        if doc.get("current_ioc_overlap"):
            parts.append(
                "current_ioc_overlap="
                + json.dumps(doc.get("current_ioc_overlap"), sort_keys=True, default=str)
            )

        for key in ("filename", "source_document", "chunk_index", "chunk_count",
                    "original_filename", "severity", "rule_id", "signature_id",
                    "alert_signature", "src_ip", "dest_ip", "event_timestamp",
                    "timestamp", "agent_name", "source_file"):
            value = metadata.get(key)
            if value not in (None, "", [], {}):
                parts.append(f"{key}={value}")

        return "; ".join(parts)

    def _format_match_evidence(self, doc: Any, max_items: int = 4) -> List[str]:
        if not isinstance(doc, dict):
            return []
        evidence = doc.get("match_evidence") or []
        formatted = []
        for item in evidence[:max_items]:
            text = re.sub(r"\s+", " ", str(item)).strip()
            if len(text) > 260:
                text = text[:257].rstrip() + "..."
            if text:
                formatted.append(text)
        return formatted

    def _format_context_docs(self, docs: List[Any], max_chars: int = 800) -> str:
        chunks = []
        for i, doc in enumerate(docs, 1):
            text = self._extract_context_text(doc).strip()
            if not text:
                continue
            excerpt = text[:max_chars] + ("..." if len(text) > max_chars else "")
            audit_lines = []
            if isinstance(doc, dict):
                section_path = (doc.get("metadata") or {}).get("cti_section_path")
                if section_path:
                    audit_lines.append(f"CTI section: {section_path}")
                context_labels = doc.get("cti_context_labels")
                if context_labels:
                    audit_lines.append("CTI context labels: " + ", ".join(str(label) for label in context_labels))
                behavior_tags = doc.get("cti_behavior_tags")
                if behavior_tags:
                    audit_lines.append("CTI behavior tags: " + ", ".join(str(tag) for tag in behavior_tags))
                if doc.get("behavior_overlap"):
                    audit_lines.append("Behavior overlap: " + ", ".join(str(tag) for tag in doc.get("behavior_overlap")))
                if doc.get("behavior_mismatch"):
                    audit_lines.append("Behavior alignment: mismatch with current alert behavior")
                dispositions = doc.get("cti_artifact_dispositions")
                disposition_summary = (
                    CTIArtifactExtractor.summarize_dispositions(dispositions)
                    if isinstance(dispositions, dict)
                    else ""
                )
                if disposition_summary:
                    audit_lines.append(disposition_summary)
                document_quality = (doc.get("metadata") or {}).get("document_quality")
                if isinstance(document_quality, dict) and document_quality.get("quality"):
                    quality_line = f"Document extraction quality: {document_quality.get('quality')}"
                    if document_quality.get("warnings"):
                        quality_line += " (" + ", ".join(str(item) for item in document_quality.get("warnings")[:4]) + ")"
                    audit_lines.append(quality_line)
                if doc.get("current_ioc_overlap"):
                    audit_lines.append(
                        "Current-alert overlap: "
                        + json.dumps(doc.get("current_ioc_overlap"), sort_keys=True, default=str)
                    )
                if doc.get("retrieval_cautions"):
                    audit_lines.append("Cautions: " + "; ".join(doc.get("retrieval_cautions")[:3]))
                if doc.get("historical_only_artifacts"):
                    audit_lines.append(
                        "Historical-only artifacts: "
                        + json.dumps(doc.get("historical_only_artifacts"), sort_keys=True, default=str)
                    )
            evidence_lines = "\n".join(
                f"Matched: {evidence}" for evidence in self._format_match_evidence(doc, max_items=3)
            )
            detail_lines = "\n".join(line for line in audit_lines + ([evidence_lines] if evidence_lines else []) if line)
            if detail_lines:
                chunks.append(f"[RAG-{i}] {self._format_doc_metadata(doc)}\n{detail_lines}\n{excerpt}")
            else:
                chunks.append(f"[RAG-{i}] {self._format_doc_metadata(doc)}\n{excerpt}")
        return "\n\n".join(chunks)

    def _format_rag_sources(self, docs: List[Any]) -> str:
        if not docs:
            return ""

        lines = ["", "---", "", "## RAG Sources Used"]
        for i, doc in enumerate(docs, 1):
            lines.append(f"- [RAG-{i}] {self._format_doc_metadata(doc)}")
            for evidence in self._format_match_evidence(doc):
                lines.append(f"  - Matched: {evidence}")
            if isinstance(doc, dict) and doc.get("retrieval_cautions"):
                lines.append(f"  - Cautions: {'; '.join(doc.get('retrieval_cautions')[:3])}")
        return "\n".join(lines)

    def _build_query_from_alerts(self, alerts: List[Dict]) -> str:
        """Build query from representative alerts across the whole batch."""
        query_parts = []
        for alert in self._select_representative_alerts(alerts, max_alerts=12):
            for field in ("rule_description", "alert_signature", "alert_category", "rule_id",
                          "signature_id", "src_ip", "dest_ip", "proto", "app_proto", "event_type",
                          "direction", "priority_reason", "directional_focus",
                          "retrieval_fingerprint"):
                if alert.get(field):
                    query_parts.append(str(alert[field]))

            for field in ("behavior_tags", "response_focus"):
                values = alert.get(field) or []
                if isinstance(values, list):
                    query_parts.extend(str(value) for value in values if value not in (None, "", [], {}))
                elif values not in (None, "", [], {}):
                    query_parts.append(str(values))

            mitre_context = alert.get("mitre_context") or {}
            if isinstance(mitre_context, dict):
                for value in mitre_context.values():
                    if value:
                        query_parts.append(str(value))

            for context_key, fields in (
                ("http_context", ("hostname", "url", "method")),
                ("dns_context", ("query_name",)),
                ("tls_context", ("sni", "issuer", "subject")),
                ("ioc_context", ("domain", "ip", "url", "hash")),
                ("process_context", ("name", "parent_process", "file", "path", "command_line")),
                ("threat_context", ("actor", "campaign")),
            ):
                context = alert.get(context_key) or {}
                if isinstance(context, dict):
                    for field in fields:
                        if context.get(field):
                            query_parts.append(str(context[field]))

            observed_iocs = alert.get("observed_iocs") or {}
            if isinstance(observed_iocs, dict):
                for values in observed_iocs.values():
                    if isinstance(values, list):
                        query_parts.extend(str(value) for value in values if value not in (None, "", [], {}))
                    elif values not in (None, "", [], {}):
                        query_parts.append(str(values))
        
        return " ".join(query_parts) if query_parts else "security incident analysis"
    
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
                 rag_config=None, geoip_db_path: str = None, asset_config: Any = None):
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
        self.alert_analyzer = AlertAnalyzer(geoip_db_path, asset_config)
        
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
    def build_rag_context(self, archive_logs: List[Dict] = None, custom_docs: List[Any] = None):
        """Build RAG context from archive logs and/or custom documents"""
        return self.rag_manager.build_rag_context(archive_logs, custom_docs)
    
    def add_custom_documents(self, docs: List[Any]):
        """Add custom documents to RAG context"""
        return self.rag_manager.add_custom_documents(docs)
    
    def get_rag_status(self) -> Dict[str, Any]:
        """Get current RAG status"""
        return self.rag_manager.get_rag_status()

    def clear_rag_database(self) -> Dict[str, Any]:
        """Drop and recreate the configured RAG database for testing resets."""
        return self.rag_manager.clear_database()
    
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

    @staticmethod
    def _strip_generated_appendices_for_indexing(markdown: str) -> str:
        """Remove generated QA/RAG/chart appendices before feedback into RAG."""
        text = str(markdown or "").strip()
        if not text:
            return ""

        appendix_heading = re.compile(
            r"^\s*##\s+.*(?:Report QA Findings|RAG Sources Used|Visual Threat Analysis)\s*$",
            re.IGNORECASE,
        )
        lines = text.splitlines()
        appendix_start = None
        for index, line in enumerate(lines):
            if appendix_heading.search(line):
                appendix_start = index
                break

        if appendix_start is None:
            return text

        start = appendix_start
        previous = appendix_start - 1
        while previous >= 0 and not lines[previous].strip():
            previous -= 1
        if previous >= 0 and lines[previous].strip() == "---":
            start = previous

        cleaned = "\n".join(lines[:start]).strip()
        return cleaned or text

    def index_approved_report(self, markdown: str, filename: str) -> bool:
        """Store analyst-approved reports as historical CTI for future RAG retrieval."""
        if not markdown or not markdown.strip():
            return False

        indexed_markdown = self._strip_generated_appendices_for_indexing(markdown)
        content_hash = hashlib.sha256(indexed_markdown.encode("utf-8")).hexdigest()
        original_content_hash = hashlib.sha256(markdown.encode("utf-8")).hexdigest()
        doc = {
            "content": indexed_markdown,
            "metadata": {
                "filename": filename,
                "original_filename": filename,
                "type": "approved_report",
                "source_document": filename,
                "content_hash": content_hash,
                "original_content_hash": original_content_hash,
                "processed_at": datetime.now().isoformat(),
                "human_validated": True,
                "generated_appendices_stripped": indexed_markdown != markdown.strip(),
            }
        }
        self.add_custom_documents([doc])
        print(f"Indexed approved report into RAG: {filename} (generated appendices stripped)")
        return True

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
