import json
import os
import re
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional, Iterable
from uuid import uuid4
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
from urllib.parse import urlparse
from sentence_transformers import SentenceTransformer
import time
import threading
from cti_artifacts import CTIArtifactExtractor
from runtime_utils import atomic_write_text, configure_console_encoding, log_sanitized_exception


configure_console_encoding()


def _first_dict_value(value: Any) -> Dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, list):
        for item in value:
            if isinstance(item, dict):
                return item
    return {}


def _expand_alert_records(logs: Optional[Iterable[Any]]) -> List[Any]:
    expanded = []
    for item in logs or []:
        if isinstance(item, dict) and isinstance(item.get("alerts"), list):
            expanded.extend(alert for alert in item.get("alerts") if isinstance(alert, dict))
        else:
            expanded.append(item)
    return expanded


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
                print("GeoIP database loaded")
            else:
                print("Configured GeoIP database was not found")
        except Exception as e:
            log_sanitized_exception("GeoIP database initialization failed", e)
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
            log_sanitized_exception("GeoIP lookup failed", e)
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
    CORPUS_SCHEMA_VERSION = "content-corpus-v1"
    RETRIEVAL_INDEX_VERSION = "hybrid-canonical-v2"
    CORPUS_LIST_LIMIT = 20
    CORPUS_LIST_MAX_LIMIT = 50

    def __init__(self, db_config: dict, rag_config=None):
        self.db_config = dict(db_config)
        self.auto_create_database = bool(
            self.db_config.pop("_auto_create_database", False)
        )
        self.rag_config = rag_config
        self.embedding_model = getattr(rag_config, "embedding_model", "Qwen/Qwen3-Embedding-0.6B")
        self.embedding_device = getattr(rag_config, "embedding_device", "cpu")
        self.vector_dimensions = int(getattr(rag_config, "embedding_dimensions", 1024))
        self.document_chunk_size = int(getattr(rag_config, "document_chunk_size", 1200))
        self.document_chunk_overlap = int(getattr(rag_config, "document_chunk_overlap", 120))
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
        # Serializes corpus selection across a complete build, additive update,
        # explicit activation, or multi-query retrieval in this process.
        self.corpus_state_lock = threading.RLock()
        self.conn = self._connect_with_database_bootstrap(
            self.db_config,
            auto_create_database=self.auto_create_database,
        )
        try:
            self.embeddings = SentenceTransformer(self.embedding_model, device=self.embedding_device)
            if hasattr(self.embeddings, '_target_device'):
                self.embeddings._target_device = self.embedding_device
            if len(self.embedding_devices) > 1:
                print(
                    "Multiple bulk embedding devices configured "
                    f"(count={len(self.embedding_devices)}, "
                    f"min_chunks={self.embedding_multi_gpu_min_chunks})"
                )
            self._init_schema()
            self.active_corpus_id = self._ensure_active_corpus()
            self.rag_ready = self._check_ready()
        except Exception:
            if self.conn is not None and not getattr(self.conn, "closed", True):
                self.conn.close()
            raise

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
    def _connect_with_database_bootstrap(
        cls,
        db_config: dict,
        auto_create_database: bool = False,
    ):
        try:
            return psycopg2.connect(**db_config)
        except psycopg2.OperationalError as error:
            if not cls._is_missing_database_error(error):
                raise

            database_name = db_config.get("database") or db_config.get("dbname")
            if not database_name:
                raise

            if not auto_create_database:
                raise RuntimeError(
                    f"PostgreSQL database '{database_name}' does not exist. "
                    "Create it explicitly or opt in with DB_AUTO_CREATE=true."
                ) from error

            print("Configured PostgreSQL database does not exist; attempting opt-in creation")
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
                    print("Configured PostgreSQL database created")
                    return
                finally:
                    admin_conn.close()
            except psycopg2.errors.DuplicateDatabase:
                print("Configured PostgreSQL database already exists")
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
            # The PostgreSQL connection is shared by this manager.  A rollback
            # must observe the same ownership boundary as every cursor/commit;
            # otherwise a retrieval error can roll back a concurrent build.
            with self.db_lock:
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
                log_sanitized_exception("Multi-GPU embedding failed; using primary device", e)
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
        return _first_dict_value(value)

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
        chunk_size = chunk_size or self.document_chunk_size
        chunk_overlap = self.document_chunk_overlap if chunk_overlap is None else chunk_overlap
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
        chunk_size = chunk_size or self.document_chunk_size
        chunk_overlap = self.document_chunk_overlap if chunk_overlap is None else chunk_overlap
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
        chunk_size = chunk_size or self.document_chunk_size
        chunk_overlap = self.document_chunk_overlap if chunk_overlap is None else chunk_overlap
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

    def corpus_version_manifest(self) -> Dict[str, Any]:
        """Return every deterministic version input that defines an index."""
        return {
            "corpus_schema_version": self.CORPUS_SCHEMA_VERSION,
            "retrieval_index_version": self.RETRIEVAL_INDEX_VERSION,
            "extraction_pipeline_version": CTIArtifactExtractor.EXTRACTION_PIPELINE_VERSION,
            "embedding_model": self.embedding_model,
            "embedding_dimensions": self.vector_dimensions,
            "normalize_embeddings": self.normalize_embeddings,
            "document_chunk_size": self.document_chunk_size,
            "document_chunk_overlap": self.document_chunk_overlap,
            "embedding_document_instruction": self.embedding_document_instruction,
        }

    @staticmethod
    def _stored_corpus_versions(manifest: Any) -> Dict[str, Any]:
        if not isinstance(manifest, dict):
            return {}
        versions = manifest.get("versions")
        return dict(versions) if isinstance(versions, dict) else {}

    def _corpus_version_mismatches(self, manifest: Any) -> Dict[str, Dict[str, Any]]:
        """Compare stored index inputs with the configured runtime inputs.

        Dimensions alone are not sufficient compatibility evidence: a model,
        normalization, instruction, extraction, or chunking change invalidates
        the stored vectors even when their shape is unchanged.
        """
        stored = self._stored_corpus_versions(manifest)
        configured = self.corpus_version_manifest()
        mismatches: Dict[str, Dict[str, Any]] = {}
        for key in sorted(set(stored) | set(configured)):
            stored_value = stored.get(key)
            configured_value = configured.get(key)
            if (
                key not in stored
                or key not in configured
                or json.dumps(stored_value, sort_keys=True, default=str)
                != json.dumps(configured_value, sort_keys=True, default=str)
            ):
                mismatches[key] = {
                    "stored": stored_value if key in stored else None,
                    "configured": configured_value if key in configured else None,
                }
        return mismatches

    def _corpus_manifest_is_compatible(self, manifest: Any) -> bool:
        return not self._corpus_version_mismatches(manifest)

    def build_cache_key(
        self,
        alert_or_evidence: Any,
        selected_context_hash: str = "",
        model_id: str = "",
        prompt_version: str = "",
    ) -> str:
        """Build a corpus/version-complete key for any future reusable result cache."""
        if not self.active_corpus_id:
            raise ValueError("Cannot build a RAG cache key without an active corpus")
        payload = {
            "active_corpus_id": self.active_corpus_id,
            "alert_evidence_hash": self._stable_json_hash(alert_or_evidence),
            "selected_context_hash": str(selected_context_hash or ""),
            "model_id": str(model_id or ""),
            "prompt_version": str(prompt_version or ""),
            "versions": self.corpus_version_manifest(),
        }
        return hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
        ).hexdigest()

    def derive_corpus_id(self, document_hashes: Iterable[Any]) -> str:
        """Derive corpus identity from content hashes and index configuration."""
        return self._derive_corpus_id_with_versions(
            document_hashes,
            self.corpus_version_manifest(),
        )

    @staticmethod
    def _derive_corpus_id_with_versions(
        document_hashes: Iterable[Any],
        versions: Dict[str, Any],
    ) -> str:
        """Derive corpus identity using the versions recorded in a manifest."""
        hashes = sorted({
            str(value).strip().lower()
            for value in document_hashes or []
            if str(value or "").strip()
        })
        payload = {
            "document_content_hashes": hashes,
            "versions": versions or {},
        }
        return hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()

    @staticmethod
    def _document_content_hash(doc: Any) -> str:
        if isinstance(doc, dict):
            metadata = doc.get("metadata") or {}
            content = str(doc.get("content") or doc.get("text") or "")
            value = metadata.get("content_hash") or metadata.get("raw_document_hash")
            if value:
                return str(value).strip().lower()
        else:
            content = str(doc or "")
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    @staticmethod
    def _canonical_archive_record(record: Any) -> Any:
        """Remove transport-only provenance before deriving archive identity."""
        if not isinstance(record, dict):
            return record
        canonical = dict(record)
        canonical.pop("_archive_source", None)
        if isinstance(canonical.get("_source"), dict):
            source = dict(canonical["_source"])
            source.pop("_archive_source", None)
            canonical["_source"] = source
        return canonical

    @classmethod
    def _archive_record_payload(cls, record: Any) -> Any:
        canonical = cls._canonical_archive_record(record)
        if isinstance(canonical, dict):
            return canonical.get("_source", canonical)
        return canonical

    @staticmethod
    def _corpus_source_tokens(
        custom_document_hashes: Iterable[Any],
        archive_record_hashes: Iterable[Any],
    ) -> List[str]:
        """Return type-qualified source identities for corpus ID derivation."""
        custom_tokens = {
            f"custom:{str(value).strip().lower()}"
            for value in custom_document_hashes or []
            if str(value or "").strip()
        }
        archive_tokens = {
            f"archive:{str(value).strip().lower()}"
            for value in archive_record_hashes or []
            if str(value or "").strip()
        }
        return sorted(custom_tokens | archive_tokens)

    def _build_corpus_manifest(
        self,
        custom_document_hashes: Iterable[Any],
        archive_record_hashes: Iterable[Any],
        *,
        extended_from: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Build the canonical, content-derived source inventory for a corpus."""
        custom_hashes = sorted({
            str(value).strip().lower()
            for value in custom_document_hashes or []
            if str(value or "").strip()
        })
        archive_hashes = sorted({
            str(value).strip().lower()
            for value in archive_record_hashes or []
            if str(value or "").strip()
        })
        source_tokens = self._corpus_source_tokens(custom_hashes, archive_hashes)
        corpus_id = self.derive_corpus_id(source_tokens)
        manifest = {
            "corpus_id": corpus_id,
            # Kept for compatibility with existing lifecycle tooling.  The
            # typed inventories below are authoritative because the same hash
            # could otherwise be ambiguous across source kinds.
            "document_content_hashes": sorted(set(custom_hashes) | set(archive_hashes)),
            "custom_document_hashes": custom_hashes,
            "archive_record_hashes": archive_hashes,
            "custom_document_count": len(custom_hashes),
            "archive_record_count": len(archive_hashes),
            "source_item_count": len(custom_hashes) + len(archive_hashes),
            "document_count": len(custom_hashes) + len(archive_hashes),
            "versions": self.corpus_version_manifest(),
        }
        if extended_from:
            manifest["extended_from"] = str(extended_from)
        return manifest

    @staticmethod
    def _empty_corpus_inventory() -> Dict[str, Any]:
        return {
            "custom_document_hashes": set(),
            "archive_record_hashes": set(),
            "embedded_custom_document_hashes": set(),
            "embedded_archive_record_hashes": set(),
            "custom_chunks": 0,
            "archive_chunks": 0,
            "embedded_custom_chunks": 0,
            "embedded_archive_chunks": 0,
            "total_chunks": 0,
            "embedded_chunks": 0,
        }

    @staticmethod
    def _manifest_uses_typed_source_inventory(manifest: Any) -> bool:
        if not isinstance(manifest, dict):
            return False
        has_custom = "custom_document_hashes" in manifest
        has_archive = "archive_record_hashes" in manifest
        if has_custom != has_archive:
            raise ValueError(
                "Corpus validation failed: typed source inventory is incomplete"
            )
        return has_custom and has_archive

    def _corpus_source_inventory(self, cur, corpus_id: str) -> Dict[str, Any]:
        """Read the exact source and chunk inventory stored in one namespace."""
        inventory = self._empty_corpus_inventory()
        cur.execute("""
            SELECT COALESCE(
                       NULLIF(metadata->>'content_hash', ''),
                       NULLIF(metadata->>'raw_document_hash', ''),
                       doc_hash
                   ) AS source_hash,
                   COUNT(*) AS chunk_count,
                   COUNT(embedding) AS embedded_chunk_count
            FROM custom_documents
            WHERE corpus_id = %s
            GROUP BY source_hash
        """, (corpus_id,))
        for source_hash, chunk_count, embedded_chunk_count in cur.fetchall():
            source_hash = str(source_hash or "").strip().lower()
            if not source_hash:
                continue
            chunk_count = int(chunk_count or 0)
            embedded_chunk_count = int(embedded_chunk_count or 0)
            inventory["custom_document_hashes"].add(source_hash)
            inventory["custom_chunks"] += chunk_count
            inventory["embedded_custom_chunks"] += embedded_chunk_count
            if chunk_count > 0 and chunk_count == embedded_chunk_count:
                inventory["embedded_custom_document_hashes"].add(source_hash)

        cur.execute("""
            SELECT COALESCE(
                       NULLIF(metadata->>'raw_alert_hash', ''),
                       alert_hash
                   ) AS source_hash,
                   COUNT(*) AS chunk_count,
                   COUNT(embedding) AS embedded_chunk_count
            FROM alert_embeddings
            WHERE corpus_id = %s
            GROUP BY source_hash
        """, (corpus_id,))
        for source_hash, chunk_count, embedded_chunk_count in cur.fetchall():
            source_hash = str(source_hash or "").strip().lower()
            if not source_hash:
                continue
            chunk_count = int(chunk_count or 0)
            embedded_chunk_count = int(embedded_chunk_count or 0)
            inventory["archive_record_hashes"].add(source_hash)
            inventory["archive_chunks"] += chunk_count
            inventory["embedded_archive_chunks"] += embedded_chunk_count
            if chunk_count > 0 and chunk_count == embedded_chunk_count:
                inventory["embedded_archive_record_hashes"].add(source_hash)

        inventory["total_chunks"] = (
            inventory["custom_chunks"] + inventory["archive_chunks"]
        )
        inventory["embedded_chunks"] = (
            inventory["embedded_custom_chunks"]
            + inventory["embedded_archive_chunks"]
        )
        return inventory

    @staticmethod
    def _validate_fully_embedded_inventory(inventory: Dict[str, Any]) -> None:
        if int(inventory.get("total_chunks") or 0) <= 0:
            raise ValueError("Corpus validation failed: no source chunks were indexed")
        if int(inventory.get("total_chunks") or 0) != int(
            inventory.get("embedded_chunks") or 0
        ):
            raise ValueError("Corpus validation failed: one or more chunks lack embeddings")
        if set(inventory.get("custom_document_hashes") or set()) != set(
            inventory.get("embedded_custom_document_hashes") or set()
        ):
            raise ValueError("Corpus validation failed: a custom document is incomplete")
        if set(inventory.get("archive_record_hashes") or set()) != set(
            inventory.get("embedded_archive_record_hashes") or set()
        ):
            raise ValueError("Corpus validation failed: an archive record is incomplete")

    def _validate_corpus_completeness(
        self,
        cur,
        corpus_id: str,
        manifest: Dict[str, Any],
        *,
        lifecycle_chunk_count: Optional[int] = None,
        lifecycle_source_count: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Prove exact source membership and complete embeddings before activation."""
        if not self._manifest_uses_typed_source_inventory(manifest):
            raise ValueError(
                "Corpus validation failed: typed source inventory is missing"
            )
        inventory = self._corpus_source_inventory(cur, corpus_id)
        self._validate_fully_embedded_inventory(inventory)
        expected_custom = {
            str(value).strip().lower()
            for value in manifest.get("custom_document_hashes") or []
            if str(value or "").strip()
        }
        expected_archive = {
            str(value).strip().lower()
            for value in manifest.get("archive_record_hashes") or []
            if str(value or "").strip()
        }
        derived_corpus_id = self._derive_corpus_id_with_versions(
            self._corpus_source_tokens(expected_custom, expected_archive),
            manifest.get("versions") or {},
        )
        if (
            str(manifest.get("corpus_id") or "").strip().lower() != corpus_id
            or derived_corpus_id != corpus_id
        ):
            raise ValueError(
                "Corpus validation failed: manifest corpus identity is inconsistent"
            )
        if inventory["custom_document_hashes"] != expected_custom:
            raise ValueError(
                "Corpus validation failed: custom document membership is incomplete"
            )
        if inventory["archive_record_hashes"] != expected_archive:
            raise ValueError(
                "Corpus validation failed: archive record membership is incomplete"
            )
        if int(inventory["archive_chunks"]) != len(expected_archive):
            raise ValueError(
                "Corpus validation failed: archive record rows are duplicated"
            )
        expected_source_count = len(expected_custom) + len(expected_archive)
        if int(manifest.get("custom_document_count", -1)) != len(expected_custom):
            raise ValueError(
                "Corpus validation failed: manifest custom document count is inconsistent"
            )
        if int(manifest.get("archive_record_count", -1)) != len(expected_archive):
            raise ValueError(
                "Corpus validation failed: manifest archive record count is inconsistent"
            )
        if int(manifest.get("source_item_count", -1)) != expected_source_count:
            raise ValueError("Corpus validation failed: manifest source count is inconsistent")
        if int(manifest.get("document_count", -1)) != expected_source_count:
            raise ValueError("Corpus validation failed: manifest document count is inconsistent")
        compatibility_hashes = {
            str(value).strip().lower()
            for value in manifest.get("document_content_hashes") or []
            if str(value or "").strip()
        }
        if compatibility_hashes != expected_custom | expected_archive:
            raise ValueError(
                "Corpus validation failed: manifest compatibility inventory is inconsistent"
            )
        if (
            lifecycle_chunk_count is not None
            and int(lifecycle_chunk_count) != int(inventory["total_chunks"])
        ):
            raise ValueError(
                "Corpus validation failed: lifecycle chunk count is inconsistent"
            )
        if (
            lifecycle_source_count is not None
            and int(lifecycle_source_count) != expected_source_count
        ):
            raise ValueError(
                "Corpus validation failed: lifecycle source count is inconsistent"
            )
        return inventory

    def _validate_legacy_corpus_completeness(
        self,
        cur,
        corpus_id: str,
        manifest: Dict[str, Any],
        *,
        lifecycle_chunk_count: Optional[int] = None,
        lifecycle_source_count: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Prove an untyped legacy manifest before permitting migration.

        Legacy manifests combine document and archive identities in one list.
        That is less expressive than the typed contract, but an exact combined
        set comparison still detects historical row-deduplication losses.
        """
        if not isinstance(manifest, dict) or "document_content_hashes" not in manifest:
            raise ValueError(
                "Corpus validation failed: legacy source inventory is missing"
            )
        expected_sources = {
            str(value).strip().lower()
            for value in manifest.get("document_content_hashes") or []
            if str(value or "").strip()
        }
        if not expected_sources:
            raise ValueError(
                "Corpus validation failed: legacy source inventory is empty"
            )
        derived_corpus_id = self._derive_corpus_id_with_versions(
            expected_sources,
            manifest.get("versions") or {},
        )
        if (
            str(manifest.get("corpus_id") or "").strip().lower() != corpus_id
            or derived_corpus_id != corpus_id
        ):
            raise ValueError(
                "Corpus validation failed: legacy manifest identity is inconsistent"
            )

        inventory = self._corpus_source_inventory(cur, corpus_id)
        self._validate_fully_embedded_inventory(inventory)
        stored_sources = (
            set(inventory["custom_document_hashes"])
            | set(inventory["archive_record_hashes"])
        )
        if stored_sources != expected_sources:
            raise ValueError(
                "Corpus validation failed: legacy source membership is incomplete"
            )
        expected_source_count = len(expected_sources)
        if int(manifest.get("document_count", -1)) != expected_source_count:
            raise ValueError(
                "Corpus validation failed: legacy manifest source count is inconsistent"
            )
        if (
            lifecycle_chunk_count is not None
            and int(lifecycle_chunk_count) != int(inventory["total_chunks"])
        ):
            raise ValueError(
                "Corpus validation failed: lifecycle chunk count is inconsistent"
            )
        if (
            lifecycle_source_count is not None
            and int(lifecycle_source_count) != expected_source_count
        ):
            raise ValueError(
                "Corpus validation failed: lifecycle source count is inconsistent"
            )
        return inventory

    def _set_active_corpus(self, cur, corpus_id: str) -> None:
        cur.execute("""
            INSERT INTO rag_runtime_state (key, value, updated_at)
            VALUES ('active_corpus_id', jsonb_build_object('corpus_id', %s), NOW())
            ON CONFLICT (key) DO UPDATE
            SET value = EXCLUDED.value, updated_at = EXCLUDED.updated_at
        """, (corpus_id,))
        cur.execute("""
            UPDATE rag_corpora
            SET activated_at = NOW()
            WHERE corpus_id = %s AND status = 'ready'
        """, (corpus_id,))

    def activate_corpus(self, corpus_id: str) -> bool:
        with self.corpus_state_lock:
            return self._activate_corpus(corpus_id)

    def _activate_corpus(self, corpus_id: str) -> bool:
        """Explicitly activate one validated corpus namespace."""
        corpus_id = str(corpus_id or "").strip().lower()
        if not re.fullmatch(r"[a-f0-9]{64}", corpus_id):
            raise ValueError("Corpus ID must be a 64-character SHA-256 value")
        with self.db_lock, self.conn.cursor() as cur:
            cur.execute("""
                SELECT status, manifest, chunk_count, document_count
                FROM rag_corpora
                WHERE corpus_id = %s
            """, (corpus_id,))
            row = cur.fetchone()
            if not row or row[0] != "ready":
                self.conn.rollback()
                raise ValueError(f"Corpus {corpus_id} is not validated and ready")
            mismatches = self._corpus_version_mismatches(row[1])
            if mismatches:
                self.conn.rollback()
                raise ValueError(
                    "Corpus index versions are incompatible with the configured RAG runtime; "
                    "build a replacement corpus before activation"
                )
            manifest = row[1] or {}
            try:
                if self._manifest_uses_typed_source_inventory(manifest):
                    self._validate_corpus_completeness(
                        cur,
                        corpus_id,
                        manifest,
                        lifecycle_chunk_count=row[2],
                        lifecycle_source_count=row[3],
                    )
                else:
                    self._validate_legacy_corpus_completeness(
                        cur,
                        corpus_id,
                        manifest,
                        lifecycle_chunk_count=row[2],
                        lifecycle_source_count=row[3],
                    )
            except Exception:
                self.conn.rollback()
                raise
            self._set_active_corpus(cur, corpus_id)
            self.conn.commit()
        self.active_corpus_id = corpus_id
        self.active_corpus_version_mismatches = {}
        self.rag_ready = self._check_ready()
        return self.rag_ready

    def _ensure_active_corpus(self) -> Optional[str]:
        """Load active state and migrate legacy unscoped rows deterministically."""
        with self.db_lock, self.conn.cursor() as cur:
            cur.execute("""
                SELECT state.value->>'corpus_id', corpora.manifest
                FROM rag_runtime_state AS state
                LEFT JOIN rag_corpora AS corpora
                  ON corpora.corpus_id = state.value->>'corpus_id'
                WHERE state.key = 'active_corpus_id'
            """)
            row = cur.fetchone()
            if row and row[0]:
                corpus_id = str(row[0])
                self.active_corpus_version_mismatches = self._corpus_version_mismatches(row[1])
                if self.active_corpus_version_mismatches:
                    print(
                        "Configured active RAG corpus is version-incompatible; "
                        "retrieval remains disabled until a replacement corpus is activated"
                    )
                return corpus_id

            cur.execute("""
                SELECT EXISTS(
                    SELECT 1 FROM custom_documents WHERE corpus_id IS NULL
                ) OR EXISTS(
                    SELECT 1 FROM alert_embeddings WHERE corpus_id IS NULL
                )
            """)
            legacy_unscoped = bool(cur.fetchone()[0])
            if legacy_unscoped:
                # There is no trustworthy manifest proving which model,
                # normalization, or chunking settings produced legacy vectors.
                # Keep them untouched for backup/recovery, but never relabel
                # them with the current versions or activate them implicitly.
                print(
                    "Legacy unscoped RAG rows were found but cannot be version-verified; "
                    "build a replacement corpus before retrieval"
                )

            cur.execute("""
                SELECT corpus_id, manifest, chunk_count, document_count
                FROM rag_corpora
                WHERE status = 'ready' AND manifest->'versions' = %s::jsonb
                ORDER BY activated_at DESC NULLS LAST, validated_at DESC NULLS LAST
                LIMIT 1
            """, (json.dumps(self.corpus_version_manifest()),))
            row = cur.fetchone()
            if row and row[0]:
                corpus_id = str(row[0])
                manifest = row[1] or {}
                try:
                    if self._manifest_uses_typed_source_inventory(manifest):
                        self._validate_corpus_completeness(
                            cur,
                            corpus_id,
                            manifest,
                            lifecycle_chunk_count=row[2],
                            lifecycle_source_count=row[3],
                        )
                    else:
                        self._validate_legacy_corpus_completeness(
                            cur,
                            corpus_id,
                            manifest,
                            lifecycle_chunk_count=row[2],
                            lifecycle_source_count=row[3],
                        )
                except ValueError:
                    print(
                        "Latest compatible ready RAG corpus failed integrity validation; "
                        "it was not activated"
                    )
                else:
                    self._set_active_corpus(cur, corpus_id)
                    self.conn.commit()
                    self.active_corpus_version_mismatches = {}
                    return corpus_id
            self.conn.commit()
            self.active_corpus_version_mismatches = {}
            return None

    def list_corpora(self, limit: int = None) -> Dict[str, Any]:
        """Return a bounded lifecycle summary, always including the active row.

        Corpus manifests can grow with the source hash inventory, so this API
        deliberately returns only lifecycle counters and compatibility fields.
        """
        bounded_limit = max(
            1,
            min(
                self._safe_int(limit, self.CORPUS_LIST_LIMIT),
                self.CORPUS_LIST_MAX_LIMIT,
            ),
        )
        with self.db_lock, self.conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM rag_corpora")
            count_row = cur.fetchone()
            total = int(count_row[0] or 0) if count_row else 0
            cur.execute("""
                SELECT corpus_id, status, document_count, chunk_count,
                       created_at, validated_at, activated_at,
                       manifest->'versions' AS stored_versions
                FROM rag_corpora
                ORDER BY COALESCE(activated_at, validated_at, created_at) DESC,
                         corpus_id DESC
                LIMIT %s
            """, (bounded_limit,))
            rows = list(cur.fetchall())

            if self.active_corpus_id and not any(row[0] == self.active_corpus_id for row in rows):
                cur.execute("""
                    SELECT corpus_id, status, document_count, chunk_count,
                           created_at, validated_at, activated_at,
                           manifest->'versions' AS stored_versions
                    FROM rag_corpora
                    WHERE corpus_id = %s
                """, (self.active_corpus_id,))
                active_row = cur.fetchone()
                if active_row:
                    rows = [active_row] + rows[: max(0, bounded_limit - 1)]

        summaries = []
        for row in rows[:bounded_limit]:
            mismatch_fields = sorted(
                self._corpus_version_mismatches({"versions": row[7] or {}})
            )
            summaries.append({
                "corpus_id": row[0],
                "status": row[1],
                "document_count": row[2],
                "chunk_count": row[3],
                "created_at": row[4],
                "validated_at": row[5],
                "activated_at": row[6],
                "active": row[0] == self.active_corpus_id,
                "version_compatible": not mismatch_fields,
                "version_mismatch_fields": mismatch_fields,
            })
        return {
            "corpora": summaries,
            "total": total,
            "returned": len(summaries),
            "truncated": total > len(summaries),
            "limit": bounded_limit,
        }
    
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

                ALTER TABLE alert_embeddings
                ADD COLUMN IF NOT EXISTS corpus_id VARCHAR(64);

                CREATE UNIQUE INDEX IF NOT EXISTS alert_corpus_hash_unique_idx
                ON alert_embeddings (corpus_id, alert_hash);
                 
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
                    to_tsvector('simple', coalesce(content, ''))
                );
            """)
            cur.execute("""
                SELECT EXISTS(
                    SELECT 1 FROM pg_constraint
                    WHERE conrelid = 'alert_embeddings'::regclass
                      AND conname = 'alert_embeddings_alert_hash_key'
                )
            """)
            if cur.fetchone()[0]:
                cur.execute(
                    "ALTER TABLE alert_embeddings "
                    "DROP CONSTRAINT alert_embeddings_alert_hash_key"
                )
            
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

                ALTER TABLE custom_documents
                ADD COLUMN IF NOT EXISTS corpus_id VARCHAR(64);

                CREATE UNIQUE INDEX IF NOT EXISTS doc_corpus_hash_unique_idx
                ON custom_documents (corpus_id, doc_hash);

                CREATE INDEX IF NOT EXISTS doc_corpus_idx
                ON custom_documents (corpus_id);
                 
                CREATE INDEX IF NOT EXISTS doc_embedding_idx 
                ON custom_documents USING ivfflat (embedding vector_cosine_ops)
                WITH (lists = 100);

                CREATE INDEX IF NOT EXISTS doc_content_fts_idx
                ON custom_documents USING gin (
                    to_tsvector('simple', coalesce(content, ''))
                );
            """)
            cur.execute("""
                SELECT EXISTS(
                    SELECT 1 FROM pg_constraint
                    WHERE conrelid = 'custom_documents'::regclass
                      AND conname = 'custom_documents_doc_hash_key'
                )
            """)
            if cur.fetchone()[0]:
                cur.execute(
                    "ALTER TABLE custom_documents "
                    "DROP CONSTRAINT custom_documents_doc_hash_key"
                )

            cur.execute("""
                CREATE TABLE IF NOT EXISTS rag_corpora (
                    corpus_id VARCHAR(64) PRIMARY KEY,
                    status VARCHAR(20) NOT NULL,
                    manifest JSONB NOT NULL,
                    document_count INTEGER NOT NULL DEFAULT 0,
                    chunk_count INTEGER NOT NULL DEFAULT 0,
                    error TEXT,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    validated_at TIMESTAMPTZ,
                    activated_at TIMESTAMPTZ
                );

                CREATE TABLE IF NOT EXISTS rag_runtime_state (
                    key VARCHAR(100) PRIMARY KEY,
                    value JSONB NOT NULL,
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                );
            """)

            self.conn.commit()

    def _check_ready(self) -> bool:
        corpus_id = getattr(self, "active_corpus_id", None)
        if not corpus_id:
            return False
        try:
            with self.db_lock, self.conn.cursor() as cur:
                cur.execute("""
                    SELECT status, manifest, chunk_count, document_count
                    FROM rag_corpora
                    WHERE corpus_id = %s
                """, (corpus_id,))
                result = cur.fetchone()

                if not result or result[0] != "ready":
                    return False
                self.active_corpus_version_mismatches = self._corpus_version_mismatches(result[1])
                if self.active_corpus_version_mismatches:
                    return False
                manifest = result[1] or {}
                if self._manifest_uses_typed_source_inventory(manifest):
                    inventory = self._validate_corpus_completeness(
                        cur,
                        corpus_id,
                        manifest,
                        lifecycle_chunk_count=result[2],
                        lifecycle_source_count=result[3],
                    )
                else:
                    inventory = self._validate_legacy_corpus_completeness(
                        cur,
                        corpus_id,
                        manifest,
                        lifecycle_chunk_count=result[2],
                        lifecycle_source_count=result[3],
                    )
                print(
                    f"RAG ready for corpus {corpus_id[:12]}: "
                    f"{inventory['embedded_archive_chunks']} alert embeddings, "
                    f"{inventory['embedded_custom_chunks']} custom document chunk embeddings"
                )
                return True
        except Exception as e:
            self._rollback_safely()
            log_sanitized_exception("RAG readiness check failed", e)
            return False

    def _validate_custom_document_sources(self, docs: List[Any]) -> None:
        """Fail closed unless every requested custom source can contribute text."""
        for index, doc in enumerate(docs):
            if isinstance(doc, dict):
                content = str(doc.get("content") or doc.get("text") or "")
                metadata = doc.get("metadata") or {}
                if not isinstance(metadata, dict):
                    raise ValueError(
                        f"Custom document source {index + 1} has invalid metadata"
                    )
            else:
                content = str(doc or "")
                metadata = {}

            content = self._strip_nul_chars(content)
            metadata = self._strip_nul_chars(metadata)
            if not content.strip():
                raise ValueError(
                    f"Custom document source {index + 1} contains no indexable text"
                )

            artifacts = metadata.get("cti_artifacts") or {}
            if not isinstance(artifacts, dict):
                artifacts = {}
            if not artifacts:
                artifacts = CTIArtifactExtractor.extract(content)

            quality = metadata.get("document_quality") or {}
            if not isinstance(quality, dict):
                quality = {}
            if quality.get("quality") == "empty":
                raise ValueError(
                    f"Custom document source {index + 1} was classified as empty"
                )
            if (
                quality.get("quality") == "low"
                and len(content.strip()) < 200
                and not any(artifacts.values())
            ):
                raise ValueError(
                    f"Custom document source {index + 1} is too low quality to index"
                )

            chunks = self._chunk_text_with_sections(
                content,
                chunk_size=self.document_chunk_size,
                chunk_overlap=self.document_chunk_overlap,
            )
            has_indexable_chunk = False
            for chunk in chunks:
                chunk_text = str(chunk.get("text") or "") if isinstance(chunk, dict) else str(chunk or "")
                chunk_artifacts = CTIArtifactExtractor.extract(chunk_text)
                if len(chunk_text.strip()) >= 80 or any(chunk_artifacts.values()):
                    has_indexable_chunk = True
                    break

            has_summary = bool(
                any(CTIArtifactExtractor.for_cti_context(artifacts).values())
                or CTIArtifactExtractor.format_context_labels(
                    CTIArtifactExtractor.classify_context(content)
                )
                or CTIArtifactExtractor.format_behavior_tags(
                    CTIArtifactExtractor.infer_behavior_tags(content)
                )
            )
            if not has_indexable_chunk and not has_summary:
                raise ValueError(
                    f"Custom document source {index + 1} produced no indexable chunks"
                )

    def _validate_archive_sources(self, logs: List[Any]) -> List[Dict[str, Any]]:
        """Return expanded archive records only when every record is indexable."""
        records = _expand_alert_records(logs)
        for index, record in enumerate(records):
            payload = self._archive_record_payload(record)
            if not isinstance(payload, dict):
                raise ValueError(f"Archive source record {index + 1} is not an object")
            if not self._strip_nul_chars(self._create_semantic_chunk(record)).strip():
                raise ValueError(
                    f"Archive source record {index + 1} produced no indexable text"
                )
        return records
        
    def build_rag_context(self, archive_logs: List[Dict] = None, custom_docs: List[Any] = None):
        with self.corpus_state_lock:
            return self._build_rag_context(archive_logs, custom_docs)

    def _build_rag_context(self, archive_logs: List[Dict] = None, custom_docs: List[Any] = None):
        """Build and atomically activate a content-derived corpus namespace."""
        previous_corpus_id = self.active_corpus_id
        previous_ready = self.rag_ready
        try:
            custom_docs = list(custom_docs or [])
            archive_logs = self._validate_archive_sources(list(archive_logs or []))
            # Validate all requested sources before reusing an existing corpus
            # or writing any archive rows.  A mixed request is all-or-nothing.
            self._validate_custom_document_sources(custom_docs)
            custom_document_hashes = {
                self._document_content_hash(doc) for doc in custom_docs
            }
            archive_record_hashes = {
                self._stable_json_hash(self._archive_record_payload(log))
                for log in archive_logs
            }
            if not custom_document_hashes and not archive_record_hashes:
                self.rag_ready = self._check_ready()
                return False
            manifest = self._build_corpus_manifest(
                custom_document_hashes,
                archive_record_hashes,
            )
            corpus_id = manifest["corpus_id"]

            with self.db_lock, self.conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT status, manifest, chunk_count, document_count
                    FROM rag_corpora WHERE corpus_id = %s
                    """,
                    (corpus_id,),
                )
                existing = cur.fetchone()
                if (
                    existing
                    and existing[0] == "ready"
                    and not self._corpus_manifest_is_compatible(existing[1])
                ):
                    raise ValueError(
                        "Stored ready corpus has incompatible index versions"
                    )
                if (
                    existing
                    and existing[0] == "ready"
                    and self._corpus_manifest_is_compatible(existing[1])
                ):
                    self._validate_corpus_completeness(
                        cur,
                        corpus_id,
                        existing[1] or {},
                        lifecycle_chunk_count=existing[2],
                        lifecycle_source_count=existing[3],
                    )
                    self._set_active_corpus(cur, corpus_id)
                    self.conn.commit()
                    self.active_corpus_id = corpus_id
                    self.rag_ready = self._check_ready()
                    return self.rag_ready

                cur.execute("""
                    INSERT INTO rag_corpora (
                        corpus_id, status, manifest, document_count, chunk_count, error
                    ) VALUES (%s, 'building', %s::jsonb, %s, 0, NULL)
                    ON CONFLICT (corpus_id) DO UPDATE
                    SET status = 'building', manifest = EXCLUDED.manifest,
                        document_count = EXCLUDED.document_count, error = NULL
                """, (corpus_id, json.dumps(manifest), manifest["document_count"]))
                # A ready namespace is immutable.  Only a prior failed or
                # interrupted attempt with this content-derived ID is reset.
                cur.execute(
                    "DELETE FROM custom_documents WHERE corpus_id = %s",
                    (corpus_id,),
                )
                cur.execute(
                    "DELETE FROM alert_embeddings WHERE corpus_id = %s",
                    (corpus_id,),
                )
                # Persist lifecycle state before ingestion so a later rollback
                # cannot erase the failed-build audit row.
                self.conn.commit()

            if archive_logs:
                self._add_archive_logs(archive_logs, corpus_id=corpus_id)
            
            if custom_docs:
                self._add_custom_docs(custom_docs, corpus_id=corpus_id, manifest=manifest)

            with self.db_lock, self.conn.cursor() as cur:
                inventory = self._validate_corpus_completeness(
                    cur, corpus_id, manifest
                )
                cur.execute("""
                    UPDATE rag_corpora
                    SET status = 'ready', chunk_count = %s, validated_at = NOW(), error = NULL
                    WHERE corpus_id = %s
                """, (inventory["total_chunks"], corpus_id))
                self._set_active_corpus(cur, corpus_id)
                self.conn.commit()

            self.active_corpus_id = corpus_id
            self.rag_ready = self._check_ready()
            print(f"RAG ready: {self.rag_ready}")
            return self.rag_ready
            
        except Exception as e:
            self._rollback_safely()
            corpus_id = locals().get("corpus_id")
            if corpus_id:
                try:
                    with self.db_lock, self.conn.cursor() as cur:
                        cur.execute("""
                            UPDATE rag_corpora SET status = 'failed', error = %s
                            WHERE corpus_id = %s AND status <> 'ready'
                        """, (f"{type(e).__name__}: corpus build failed", corpus_id))
                        self.conn.commit()
                except Exception:
                    self._rollback_safely()
            log_sanitized_exception("RAG corpus build failed", e)
            self.active_corpus_id = previous_corpus_id
            self.rag_ready = self._check_ready() if previous_corpus_id else previous_ready
            return False
    
    def _add_archive_logs(self, logs: List[Dict], corpus_id: Optional[str] = None):
        """Add archive logs with smart chunking and deduplication"""
        corpus_id = corpus_id or self.active_corpus_id
        if not corpus_id:
            raise ValueError("A corpus ID is required before indexing archive alerts")
        chunks = []
        
        for log in _expand_alert_records(logs):
            root_data = self._archive_record_payload(log)
            if not isinstance(root_data, dict):
                continue
            data = root_data.get("data", {}) or {}
            rule = root_data.get("rule", {}) or {}
            alert = data.get("alert", {}) or {}
            http_data = data.get("http", {}) or {}
            dns_data = data.get("dns", {}) or {}
            tls_data = data.get("tls", {}) or {}
            email_data = data.get("email", {}) or {}
            ioc_data = data.get("ioc", {}) or {}
            process_data = data.get("process", {}) or {}
            threat_data = data.get("threat", {}) or {}
            flow_data = data.get("flow", {}) or {}
            file_data = self._first_dict(data.get("files") or data.get("fileinfo"))
            smb_data = data.get("smb", {}) or {}
            modbus_data = data.get("modbus", {}) or {}
            dns_query_info = self._first_dict(dns_data.get("query"))
            rule_mitre = rule.get("mitre", {}) or {}

            chunk_text = self._strip_nul_chars(self._create_semantic_chunk(log))
            if not chunk_text.strip():
                continue
            # Archive identity follows the canonical source record, not its
            # rendered semantic text.  This makes exact duplicate records
            # idempotent while ensuring distinct records cannot collapse just
            # because they render to the same abbreviated chunk.
            chunk_hash = self._stable_json_hash(root_data)
            event_timestamp_raw = root_data.get("timestamp")
            event_timestamp = self._parse_event_timestamp(event_timestamp_raw)
            dns_query = (
                dns_query_info.get("rrname")
                or dns_data.get("rrname")
                or dns_data.get("query_name")
            )
            
            metadata = {
                "corpus_id": corpus_id,
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
                "email_from": email_data.get("from"),
                "email_to": email_data.get("to"),
                "email_subject": email_data.get("subject"),
                "email_attachment": email_data.get("attachment"),
                "email_mail_from_domain": email_data.get("mail_from_domain"),
                "email_url": email_data.get("url"),
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
                "file_md5": file_data.get("md5"),
                "file_sha1": file_data.get("sha1"),
                "file_sha256": file_data.get("sha256"),
                "smb_command": smb_data.get("command"),
                "smb_share": smb_data.get("share"),
                "smb_filename": smb_data.get("filename"),
                "smb_disposition": smb_data.get("disposition"),
                "modbus_function": modbus_data.get("function"),
                "modbus_unit_id": modbus_data.get("unit_id"),
                "modbus_address": modbus_data.get("address"),
                "modbus_quantity": modbus_data.get("quantity"),
                "mitre_ids": rule_mitre.get("id"),
                "mitre_tactics": rule_mitre.get("tactic"),
                "mitre_techniques": rule_mitre.get("technique"),
                "raw_alert_hash": chunk_hash,
            }
            metadata = self._strip_nul_chars({k: v for k, v in metadata.items() if v not in (None, "", [], {})})
            
            chunks.append((chunk_hash, chunk_text, metadata, event_timestamp))

        if not chunks:
            print("WARNING: No archive log chunks to add")
            return
        
        with self.db_lock, self.conn.cursor() as cur:
            inserted_alerts = execute_values(cur, """
                INSERT INTO alert_embeddings (corpus_id, alert_hash, content, metadata, source, event_timestamp)
                VALUES %s
                ON CONFLICT (corpus_id, alert_hash) DO NOTHING
                RETURNING id
            """, [(corpus_id, h, c, json.dumps(m), 'archive', ts) for h, c, m, ts in chunks], fetch=True)
            
            inserted = len(inserted_alerts)
            print(f"📝 Added {inserted} new archive alerts (deduplicated)")
            cur.execute("""
                SELECT id, content FROM alert_embeddings 
                WHERE corpus_id = %s AND embedding IS NULL AND source = 'archive'
            """, (corpus_id,))
            
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

    def _add_custom_docs(
        self,
        docs: List[Any],
        corpus_id: Optional[str] = None,
        manifest: Optional[Dict[str, Any]] = None,
    ):
        """Add uploaded documents as chunk rows with deduplication."""
        corpus_id = corpus_id or self.active_corpus_id
        if not corpus_id:
            raise ValueError("A corpus ID is required before indexing custom documents")
        chunks = []
        upload_summaries = []
        
        for i, doc in enumerate(docs):
            source_chunk_start = len(chunks)
            if isinstance(doc, dict):
                doc_content = str(doc.get("content") or doc.get("text") or "")
                source_metadata = doc.get("metadata") or {}
            else:
                doc_content = str(doc or "")
                source_metadata = {}

            doc_content = self._strip_nul_chars(doc_content)
            source_metadata = self._strip_nul_chars(source_metadata)
            if not isinstance(source_metadata, dict):
                raise ValueError(f"Custom document source {i + 1} has invalid metadata")

            if not doc_content.strip():
                raise ValueError(f"Custom document source {i + 1} contains no indexable text")

            original_filename = (
                source_metadata.get("filename")
                or source_metadata.get("original_filename")
                or f"custom_doc_{i}"
            )
            original_filename = self._strip_nul_chars(original_filename)
            safe_stem = re.sub(r"[^A-Za-z0-9_.-]+", "_", Path(original_filename).stem or f"custom_doc_{i}")[:80]
            raw_document_hash = hashlib.sha256(doc_content.encode("utf-8")).hexdigest()
            # Chunk identity is scoped to the canonical source identity used
            # by the corpus manifest. Two byte-distinct PDFs can legitimately
            # extract to identical text; keeping the source identity here
            # preserves both sources without creating ambiguous manifest rows.
            source_identity_hash = self._document_content_hash(doc)
            source_artifacts = source_metadata.get("cti_artifacts") if isinstance(source_metadata, dict) else {}
            if not isinstance(source_artifacts, dict):
                source_artifacts = {}
            if not source_artifacts:
                source_artifacts = CTIArtifactExtractor.extract(doc_content)
            document_quality = source_metadata.get("document_quality") if isinstance(source_metadata, dict) else {}
            if not isinstance(document_quality, dict):
                document_quality = {}
            if document_quality.get("quality") == "empty":
                raise ValueError(f"Custom document source {i + 1} was classified as empty")
            if (
                document_quality.get("quality") == "low"
                and len(doc_content.strip()) < 200
                and not any(source_artifacts.values())
            ):
                raise ValueError(
                    f"Custom document source {i + 1} is too low quality to index"
                )

            source_context_artifacts = CTIArtifactExtractor.for_cti_context(source_artifacts)
            source_context_labels = CTIArtifactExtractor.classify_context(doc_content)
            source_behavior_tags = CTIArtifactExtractor.infer_behavior_tags(doc_content)
            source_artifact_dispositions = CTIArtifactExtractor.classify_artifact_dispositions(
                doc_content,
                source_context_artifacts,
                context_window=120,
                max_items_per_type=50,
            )
            document_artifact_line = CTIArtifactExtractor.format_for_context(
                source_context_artifacts,
                max_items_per_type=60,
            )
            document_context_line = CTIArtifactExtractor.format_context_labels(source_context_labels)
            document_behavior_line = CTIArtifactExtractor.format_behavior_tags(source_behavior_tags)
            document_disposition_line = CTIArtifactExtractor.summarize_dispositions(
                source_artifact_dispositions,
                max_items=20,
            )
            document_summary_lines = [
                "CTI Document Summary",
                f"Document type: {source_metadata.get('type')}" if source_metadata.get("type") else "",
                f"Document quality: {document_quality.get('quality')}" if document_quality.get("quality") else "",
                document_context_line,
                document_behavior_line,
                document_disposition_line,
                document_artifact_line,
            ]
            document_summary_text = "\n".join(line for line in document_summary_lines if line).strip()
            if document_summary_text and (
                any(source_context_artifacts.values())
                or document_context_line
                or document_behavior_line
            ):
                summary_hash = hashlib.sha256(
                    f"{source_identity_hash}:document_summary".encode("utf-8")
                ).hexdigest()
                summary_filename = f"{safe_stem}_document_summary"
                summary_metadata = {
                    "corpus_id": corpus_id,
                    "filename": summary_filename,
                    "original_filename": original_filename,
                    "source_document": original_filename,
                    "chunk_index": -1,
                    "chunk_role": "document_summary",
                    "length": len(document_summary_text),
                    "added_at": datetime.now().isoformat(),
                    "content_hash": source_metadata.get("content_hash"),
                    "document_type": source_metadata.get("type"),
                    "pages": source_metadata.get("pages"),
                    "processed_at": source_metadata.get("processed_at"),
                    "processor_version": source_metadata.get("processor_version"),
                    "document_quality": document_quality,
                    "raw_document_hash": raw_document_hash,
                    "cti_section_path": "Document Summary",
                    "cti_section_heading": "Document Summary",
                    "cti_artifacts": source_context_artifacts,
                    "source_cti_artifacts": source_context_artifacts,
                    "artifact_counts": CTIArtifactExtractor.count_by_type(source_context_artifacts),
                    "cti_context_labels": source_context_labels,
                    "cti_behavior_tags": source_behavior_tags,
                    "cti_artifact_dispositions": source_artifact_dispositions,
                    "document_artifact_counts": CTIArtifactExtractor.count_by_type(source_artifacts),
                }
                summary_metadata = self._strip_nul_chars({
                    k: v for k, v in summary_metadata.items()
                    if v not in (None, "", [], {})
                })
                chunks.append((
                    summary_hash,
                    summary_filename[:255],
                    self._strip_nul_chars(document_summary_text),
                    summary_metadata,
                ))
            
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
                if len(chunk_text.strip()) < 80 and not any(chunk_artifacts.values()):
                    continue
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
                    f"{source_identity_hash}:{chunk_index}:{chunk_text}".encode("utf-8")
                ).hexdigest()
                filename = f"{safe_stem}_chunk_{chunk_index}"
                
                metadata = {
                    "corpus_id": corpus_id,
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
                    "processor_version": source_metadata.get("processor_version"),
                    "document_quality": document_quality,
                    "raw_document_hash": raw_document_hash,
                    "cti_section_path": section_path,
                    "cti_section_heading": section_heading,
                    "cti_artifacts": chunk_artifacts,
                    "source_cti_artifacts": source_context_artifacts,
                    "artifact_counts": CTIArtifactExtractor.count_by_type(chunk_artifacts),
                    "cti_context_labels": chunk_context_labels,
                    "cti_behavior_tags": chunk_behavior_tags,
                    "cti_artifact_dispositions": chunk_artifact_dispositions,
                    "document_artifact_counts": CTIArtifactExtractor.count_by_type(source_artifacts),
                }
                metadata = self._strip_nul_chars({k: v for k, v in metadata.items() if v not in (None, "", [], {})})
                
                chunks.append((doc_hash, filename[:255], self._strip_nul_chars(content_for_storage), metadata))

            if len(chunks) == source_chunk_start:
                raise ValueError(
                    f"Custom document source {i + 1} produced no indexable chunks"
                )

        if not chunks:
            raise ValueError("No custom document chunks were produced")

        print(
            f"Preparing {len(chunks)} text chunks from {len(upload_summaries)} uploaded files "
            "for pgvector storage."
        )
        if upload_summaries:
            artifact_count = sum(
                sum(int(count) for count in item["artefacts"].values())
                for item in upload_summaries
            )
            print(
                "Document extraction summary: "
                f"sources={len(upload_summaries)}, "
                f"characters={sum(item['characters'] for item in upload_summaries)}, "
                f"artifacts={artifact_count}"
            )
        
        with self.db_lock, self.conn.cursor() as cur:
            inserted_chunks = execute_values(cur, """
                INSERT INTO custom_documents (corpus_id, doc_hash, filename, content, metadata, event_timestamp)
                VALUES %s
                ON CONFLICT (corpus_id, doc_hash) DO NOTHING
                RETURNING id, content
            """, [(corpus_id, h, f, c, json.dumps(m), None) for h, f, c, m in chunks], fetch=True)
            
            inserted = len(inserted_chunks)
            skipped = len(chunks) - inserted
            print(
                f"Added {inserted} new custom document chunks "
                f"({skipped} duplicate chunks skipped from this upload)."
            )
            to_embed = inserted_chunks
            if not to_embed:
                cur.execute("""
                    SELECT id, content FROM custom_documents 
                    WHERE corpus_id = %s AND embedding IS NULL
                    LIMIT 1000
                """, (corpus_id,))
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
        """Compatibility wrapper for additive custom-document ingestion."""
        return self.extend_rag_context(custom_docs=docs)

    def extend_rag_context(
        self,
        archive_logs: List[Dict] = None,
        custom_docs: List[Any] = None,
    ):
        """Atomically union new sources with the complete active corpus."""
        with self.corpus_state_lock:
            return self._extend_rag_context_atomically(archive_logs, custom_docs)

    def _add_custom_documents_atomically(self, docs: List[Any]):
        """Compatibility wrapper for callers of the previous private helper."""
        return self._extend_rag_context_atomically(custom_docs=docs)

    def _extend_rag_context_atomically(
        self,
        archive_logs: List[Dict] = None,
        custom_docs: List[Any] = None,
    ):
        """Create and activate a copy-on-write union namespace.

        The existing active rows are copied unchanged, new sources are
        deduplicated into that namespace, and the pointer moves only after the
        exact requested source inventory and every embedding are verified.
        """
        custom_docs = list(custom_docs or [])
        archive_logs = self._validate_archive_sources(list(archive_logs or []))
        if not custom_docs and not archive_logs:
            return self.rag_ready
        self._validate_custom_document_sources(custom_docs)
        previous_corpus_id = self.active_corpus_id
        previous_ready = self.rag_ready
        if not previous_corpus_id:
            self.rag_ready = self._build_rag_context(
                archive_logs=archive_logs,
                custom_docs=custom_docs,
            )
            return self.rag_ready

        new_custom_hashes = {
            self._document_content_hash(doc) for doc in custom_docs
        }
        new_archive_hashes = {
            self._stable_json_hash(self._archive_record_payload(log))
            for log in archive_logs
        }
        corpus_id = None
        try:
            with self.db_lock, self.conn.cursor() as cur:
                cur.execute("""
                    SELECT status, manifest, chunk_count, document_count
                    FROM rag_corpora
                    WHERE corpus_id = %s
                """, (previous_corpus_id,))
                active_row = cur.fetchone()
                if not active_row or active_row[0] != "ready":
                    raise ValueError("Active corpus is not validated and ready")
                old_manifest = active_row[1] or {}
                if not self._corpus_manifest_is_compatible(old_manifest):
                    raise ValueError(
                        "Active corpus index versions are incompatible with the configured RAG runtime"
                    )
                if self._manifest_uses_typed_source_inventory(old_manifest):
                    active_inventory = self._validate_corpus_completeness(
                        cur,
                        previous_corpus_id,
                        old_manifest,
                        lifecycle_chunk_count=active_row[2],
                        lifecycle_source_count=active_row[3],
                    )
                else:
                    active_inventory = self._validate_legacy_corpus_completeness(
                        cur,
                        previous_corpus_id,
                        old_manifest,
                        lifecycle_chunk_count=active_row[2],
                        lifecycle_source_count=active_row[3],
                    )

                existing_custom_hashes = set(
                    active_inventory["custom_document_hashes"]
                )
                existing_archive_hashes = set(
                    active_inventory["archive_record_hashes"]
                )
                pending_custom_hashes = set()
                custom_docs_to_add = []
                for doc in custom_docs:
                    source_hash = self._document_content_hash(doc)
                    if (
                        source_hash in existing_custom_hashes
                        or source_hash in pending_custom_hashes
                    ):
                        continue
                    pending_custom_hashes.add(source_hash)
                    custom_docs_to_add.append(doc)

                pending_archive_hashes = set()
                archive_logs_to_add = []
                for log in archive_logs:
                    source_hash = self._stable_json_hash(
                        self._archive_record_payload(log)
                    )
                    if (
                        source_hash in existing_archive_hashes
                        or source_hash in pending_archive_hashes
                    ):
                        continue
                    pending_archive_hashes.add(source_hash)
                    archive_logs_to_add.append(log)

                target_custom_hashes = (
                    existing_custom_hashes
                    | new_custom_hashes
                )
                target_archive_hashes = (
                    existing_archive_hashes
                    | new_archive_hashes
                )
                manifest = self._build_corpus_manifest(
                    target_custom_hashes,
                    target_archive_hashes,
                    extended_from=previous_corpus_id,
                )
                corpus_id = manifest["corpus_id"]
                cur.execute(
                    """
                    SELECT status, manifest, chunk_count, document_count
                    FROM rag_corpora WHERE corpus_id = %s
                    """,
                    (corpus_id,),
                )
                existing = cur.fetchone()
                if (
                    existing
                    and existing[0] == "ready"
                    and not self._corpus_manifest_is_compatible(existing[1])
                ):
                    raise ValueError(
                        "Stored ready corpus has incompatible index versions"
                    )
                if existing and existing[0] == "ready":
                    self._validate_corpus_completeness(
                        cur,
                        corpus_id,
                        existing[1] or {},
                        lifecycle_chunk_count=existing[2],
                        lifecycle_source_count=existing[3],
                    )
                    self._set_active_corpus(cur, corpus_id)
                    self.conn.commit()
                    self.active_corpus_id = corpus_id
                    self.rag_ready = self._check_ready()
                    return self.rag_ready
                cur.execute("""
                    INSERT INTO rag_corpora (
                        corpus_id, status, manifest, document_count, chunk_count
                    ) VALUES (%s, 'building', %s::jsonb, %s, 0)
                    ON CONFLICT (corpus_id) DO UPDATE
                    SET status='building', manifest=EXCLUDED.manifest,
                        document_count=EXCLUDED.document_count,
                        chunk_count=0, validated_at=NULL, error=NULL
                """, (
                    corpus_id,
                    json.dumps(manifest),
                    manifest["document_count"],
                ))
                # Failed/interrupted targets are disposable.  Ready corpus
                # namespaces never reach this branch and remain immutable.
                cur.execute(
                    "DELETE FROM custom_documents WHERE corpus_id = %s",
                    (corpus_id,),
                )
                cur.execute(
                    "DELETE FROM alert_embeddings WHERE corpus_id = %s",
                    (corpus_id,),
                )
                cur.execute("""
                    INSERT INTO custom_documents (
                        corpus_id, doc_hash, filename, content, embedding,
                        metadata, event_timestamp, created_at
                    )
                    SELECT %s, doc_hash, filename, content, embedding,
                           jsonb_set(
                               COALESCE(metadata, '{}'::jsonb),
                               '{corpus_id}', to_jsonb(%s::text), true
                           ),
                           event_timestamp, created_at
                    FROM custom_documents WHERE corpus_id = %s
                    ON CONFLICT (corpus_id, doc_hash) DO NOTHING
                """, (corpus_id, corpus_id, previous_corpus_id))
                cur.execute("""
                    INSERT INTO alert_embeddings (
                        corpus_id, alert_hash, content, embedding, metadata,
                        source, created_at, event_timestamp, expires_at
                    )
                    SELECT %s,
                           COALESCE(
                               NULLIF(metadata->>'raw_alert_hash', ''),
                               alert_hash
                           ),
                           content, embedding,
                           jsonb_set(
                               COALESCE(metadata, '{}'::jsonb),
                               '{corpus_id}', to_jsonb(%s::text), true
                           ),
                           source, created_at, event_timestamp, expires_at
                    FROM alert_embeddings WHERE corpus_id = %s
                    ON CONFLICT (corpus_id, alert_hash) DO NOTHING
                """, (corpus_id, corpus_id, previous_corpus_id))
                self.conn.commit()

            if archive_logs_to_add:
                self._add_archive_logs(
                    archive_logs_to_add,
                    corpus_id=corpus_id,
                )
            if custom_docs_to_add:
                self._add_custom_docs(
                    custom_docs_to_add,
                    corpus_id=corpus_id,
                    manifest=manifest,
                )
            with self.db_lock, self.conn.cursor() as cur:
                inventory = self._validate_corpus_completeness(
                    cur, corpus_id, manifest
                )
                cur.execute("""
                    UPDATE rag_corpora
                    SET status='ready', document_count=%s, chunk_count=%s,
                        manifest=%s::jsonb, validated_at=NOW(), error=NULL
                    WHERE corpus_id=%s
                """, (
                    manifest["document_count"],
                    inventory["total_chunks"],
                    json.dumps(manifest),
                    corpus_id,
                ))
                self._set_active_corpus(cur, corpus_id)
                self.conn.commit()
        except Exception as error:
            self._rollback_safely()
            if corpus_id and corpus_id != previous_corpus_id:
                try:
                    with self.db_lock, self.conn.cursor() as cur:
                        cur.execute("""
                            UPDATE rag_corpora
                            SET status='failed', error=%s
                            WHERE corpus_id=%s AND status <> 'ready'
                        """, (
                            f"{type(error).__name__}: corpus extension failed",
                            corpus_id,
                        ))
                        self.conn.commit()
                except Exception:
                    self._rollback_safely()
            self.active_corpus_id = previous_corpus_id
            self.rag_ready = self._check_ready() if previous_corpus_id else previous_ready
            raise
        self.active_corpus_id = corpus_id
        self.rag_ready = self._check_ready()
        print(
            "Extended RAG context with "
            f"{len(pending_custom_hashes)} new custom document(s) and "
            f"{len(pending_archive_hashes)} new archive record(s)"
        )
        return self.rag_ready

    def _create_semantic_chunk(self, log: Dict) -> str:
        """Create semantic-rich chunk from alert - preserves context"""
        parts = []
        root_data = log.get("_source", log) if isinstance(log, dict) else {}
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

        email_data = data.get("email", {}) or {}
        if email_data:
            email_bits = {
                "from": email_data.get("from"),
                "to": email_data.get("to"),
                "subject": email_data.get("subject"),
                "attachment": email_data.get("attachment"),
                "mail_from_domain": email_data.get("mail_from_domain"),
                "url": email_data.get("url"),
            }
            self._append_part(parts, "Email", {k: v for k, v in email_bits.items() if v not in (None, "", [], {})})

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

        file_data = self._first_dict(data.get("files") or data.get("fileinfo"))
        if file_data:
            file_bits = {
                "filename": file_data.get("filename"),
                "state": file_data.get("state"),
                "size": file_data.get("size"),
                "stored": file_data.get("stored"),
                "md5": file_data.get("md5"),
                "sha1": file_data.get("sha1"),
                "sha256": file_data.get("sha256"),
            }
            self._append_part(parts, "File", {k: v for k, v in file_bits.items() if v not in (None, "", [], {})})

        smb_data = data.get("smb", {}) or {}
        if smb_data:
            smb_bits = {
                "command": smb_data.get("command"),
                "share": smb_data.get("share"),
                "filename": smb_data.get("filename"),
                "disposition": smb_data.get("disposition"),
            }
            self._append_part(parts, "SMB", {k: v for k, v in smb_bits.items() if v not in (None, "", [], {})})

        modbus_data = data.get("modbus", {}) or {}
        if modbus_data:
            modbus_bits = {
                "function": modbus_data.get("function"),
                "unit_id": modbus_data.get("unit_id"),
                "address": modbus_data.get("address"),
                "quantity": modbus_data.get("quantity"),
            }
            self._append_part(parts, "Modbus", {k: v for k, v in modbus_bits.items() if v not in (None, "", [], {})})

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
        if not self.active_corpus_id:
            return "FALSE", []
        parts = ["corpus_id = %s"]
        params: List[Any] = [self.active_corpus_id]
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
    def _is_high_signal_search_value(value: Any) -> bool:
        text = str(value or "").strip()
        if not text:
            return False
        lowered = text.lower()
        generic_terms = {
            "true", "false", "none", "unknown", "medium", "high", "low", "critical",
            "external", "internal", "inbound", "outbound", "lateral", "protected",
            "asset", "assets", "source", "destination", "alert", "alerts", "security",
            "incident", "analysis", "manual", "automatic", "context", "threat",
            "telemetry", "current", "historical", "evidence", "priority",
            "malware", "phishing", "suspicious", "archive", "delivered", "executable",
            "notification", "domain", "download", "payload", "attachment", "document",
            "review", "required", "attempted", "detected", "allowed", "blocked",
            "network", "trojan", "reputation", "low-reputation", "windows",
            "administrator", "privilege", "gain", "query",
            "powershell.exe", "powershell", "pwsh.exe", "cmd.exe", "rundll32.exe",
            "regsvr32.exe", "wscript.exe", "cscript.exe", "mshta.exe", "svchost.exe",
            "explorer.exe", "winword.exe", "excel.exe", "acrord32.exe",
            "executionpolicy", "windowstyle", "hidden", "bypass", "startw",
        }
        if lowered in generic_terms:
            return False
        if CTIArtifactExtractor.HASH_RE.fullmatch(text):
            return True
        if CTIArtifactExtractor.CVE_RE.fullmatch(text) or CTIArtifactExtractor.MITRE_TECHNIQUE_RE.fullmatch(text):
            return True
        if RAGContextManager._is_ip_term(text) or RAGContextManager._is_domain_term(text):
            return True
        if "://" in text or "@" in text:
            return True
        if any(separator in text for separator in (".", "_", "-", "/", "\\")) and len(text) >= 5:
            return True
        return len(text) >= 8 and not lowered.isdigit()

    @staticmethod
    def _refang_text(text: Any) -> str:
        """Normalize common CTI defanging so alert IoCs match report IoCs."""
        normalized = str(text or "")
        if not normalized:
            return ""
        normalized = normalized.replace("\u200b", "").replace("\ufeff", "")
        normalized = re.sub(
            r"\s*(?:\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)|\{dot\})\s*",
            ".",
            normalized,
            flags=re.IGNORECASE,
        )
        normalized = re.sub(
            r"\s*(?:\[:\]|\[colon\]|\(colon\)|\{colon\})\s*",
            ":",
            normalized,
            flags=re.IGNORECASE,
        )
        normalized = re.sub(r"\bhxxps(?=://)", "https", normalized, flags=re.IGNORECASE)
        normalized = re.sub(r"\bhxxp(?=://)", "http", normalized, flags=re.IGNORECASE)
        return normalized

    @staticmethod
    def _escape_like_value(value: str) -> str:
        return (
            str(value)
            .replace("\\", "\\\\")
            .replace("%", "\\%")
            .replace("_", "\\_")
        )

    @classmethod
    def _indicator_variants(cls, value: Any, max_variants: int = 24) -> List[str]:
        text = str(value or "").strip()
        if not text:
            return []

        variants = []

        def add(candidate: str):
            candidate = str(candidate or "").strip()
            if candidate and candidate.lower() not in {item.lower() for item in variants}:
                variants.append(candidate)

        add(text)
        refanged = cls._refang_text(text)
        add(refanged)

        dot_tokens = ("[.]", "(.)", "{.}", "[dot]")
        colon_tokens = ("[:]", "[colon]")
        for base in list(variants):
            if "." in base:
                for token in dot_tokens:
                    add(base.replace(".", token))
            if "://" in base:
                for token in colon_tokens:
                    add(base.replace("://", f"{token}//"))
                if base.lower().startswith("https://"):
                    hxxps = re.sub(r"^https", "hxxps", base, flags=re.IGNORECASE)
                    add(hxxps)
                    for token in colon_tokens:
                        add(hxxps.replace("://", f"{token}//"))
                elif base.lower().startswith("http://"):
                    hxxp = re.sub(r"^http", "hxxp", base, flags=re.IGNORECASE)
                    add(hxxp)
                    for token in colon_tokens:
                        add(hxxp.replace("://", f"{token}//"))

        return variants[:max_variants]

    @staticmethod
    def _casefold_exact_values(values: Any) -> List[str]:
        normalized = []
        seen = set()
        for value in RAGContextManager._normalize_exact_values(values):
            key = value.lower()
            if key in seen:
                continue
            seen.add(key)
            normalized.append(key)
        return normalized

    @classmethod
    def _like_patterns(cls, values: List[str]) -> List[str]:
        patterns = []
        seen = set()
        for value in values or []:
            for variant in cls._indicator_variants(value):
                if len(variant) < 3:
                    continue
                escaped = cls._escape_like_value(variant)
                pattern = f"%{escaped}%"
                key = pattern.lower()
                if key in seen:
                    continue
                seen.add(key)
                patterns.append(pattern)
        return patterns

    @staticmethod
    def _is_ip_term(term: str) -> bool:
        try:
            ipaddress.ip_address(RAGContextManager._refang_text(term).strip())
            return True
        except ValueError:
            return False

    @staticmethod
    def _is_domain_term(term: str) -> bool:
        text = RAGContextManager._refang_text(term).strip().lower().strip(".")
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
        term = cls._refang_text(term).strip()
        if not text or not term:
            return False
        refanged_text = cls._refang_text(text)
        search_texts = [text]
        if refanged_text != text:
            search_texts.append(refanged_text)

        if term_type == "ip" or cls._is_ip_term(term):
            try:
                normalized_ip = str(ipaddress.ip_address(term))
            except ValueError:
                return False
            return any(normalized_ip in CTIArtifactExtractor._extract_ips(candidate) for candidate in search_texts)
        if term_type == "url":
            cleaned_term = CTIArtifactExtractor._clean_url(term).lower()
            for candidate_text in search_texts:
                urls = [
                    CTIArtifactExtractor._clean_url(match.group(0)).lower()
                    for match in CTIArtifactExtractor.URL_RE.finditer(candidate_text)
                ]
                if cleaned_term in urls:
                    return True
            return False
        if term_type == "domain" or cls._is_domain_term(term):
            domain_term = term.lower().strip(".")
            for candidate_text in search_texts:
                urls = [
                    CTIArtifactExtractor._clean_url(match.group(0))
                    for match in CTIArtifactExtractor.URL_RE.finditer(candidate_text)
                ]
                if domain_term in CTIArtifactExtractor._extract_domains(candidate_text, urls):
                    return True
            return False
        pattern = cls._term_regex(term, term_type)
        return any(pattern.search(candidate) for candidate in search_texts) if pattern else False

    @staticmethod
    def _metadata_artifact_values(metadata: Dict[str, Any], artifact_keys: tuple[str, ...]) -> List[str]:
        values = []
        if not isinstance(metadata, dict):
            return values
        for metadata_key in ("cti_artifacts", "source_cti_artifacts"):
            artifacts = metadata.get(metadata_key)
            if isinstance(artifacts, dict):
                for key in artifact_keys:
                    raw_values = artifacts.get(key)
                    if isinstance(raw_values, list):
                        values.extend(raw_values)
                    elif raw_values not in (None, "", [], {}):
                        values.append(raw_values)
        return values

    @staticmethod
    def _ranking_metadata(metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Exclude display/provenance labels from every scoring/evidence haystack."""
        if not isinstance(metadata, dict):
            return {}
        display_only = {
            "filename", "original_filename", "source_document", "source_file",
            "path", "source_path", "relative_path", "archive_path", "zip_index",
            "insertion_order", "pdf_title",
        }
        return {key: value for key, value in metadata.items() if key not in display_only}

    @staticmethod
    def _evidence_snippet(text: str, term: str, radius: int = 90, term_type: str = None) -> str:
        if not text or not term:
            return ""
        match = None
        for variant in RAGContextManager._indicator_variants(term):
            pattern = RAGContextManager._term_regex(variant, term_type)
            match = pattern.search(text) if pattern else None
            if match:
                break
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
        metadata = self._ranking_metadata(metadata or {})
        evidence: List[str] = []

        term_groups = [
            ("rule_id", "rule_ids", ("rule_id",)),
            ("signature_id", "signature_ids", ("signature_id",)),
            ("source ip", "source_ips", ("src_ip",)),
            ("destination ip", "destination_ips", ("dest_ip",)),
            ("ip", "ips", ("src_ip", "dest_ip", "agent_ip", "ioc_ip")),
            ("domain", "domains", ("http_hostname", "dns_query", "tls_sni", "email_mail_from_domain", "ioc_domain")),
            ("url", "urls", ("http_url", "email_url", "ioc_url")),
            ("hash", "hashes", ("ioc_hash", "file_md5", "file_sha1", "file_sha256")),
            ("cve", "cves", ("cves",)),
            ("mitre technique", "mitre_techniques", ("mitre_ids", "mitre_techniques")),
            ("signature", "alert_signatures", ("alert_signature",)),
            ("threat actor", "threat_actors", ("threat_actor",)),
            ("related actor alias", "threat_actor_aliases", ("threat_actor_aliases",)),
            ("malware family", "malware_families", ("malware_family", "malware")),
            ("campaign", "campaigns", ("threat_campaign",)),
            ("tool", "tools", ("tool",)),
            ("course of action", "courses_of_action", ("course_of_action",)),
            ("indicator", "keywords", (
                "ioc_hash", "process_name", "parent_process", "process_file", "process_path", "process_command_line",
                "threat_actor", "threat_campaign", "file_name", "file_md5", "file_sha1", "file_sha256",
                "email_from", "email_to", "email_subject", "email_attachment",
                "tls_ja3", "tls_ja3s", "smb_command", "smb_share", "smb_filename", "smb_disposition",
                "modbus_function", "modbus_unit_id", "modbus_address", "modbus_quantity",
            )),
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
                elif label == "hash":
                    term_type = "hash"
                found = False
                for metadata_key in metadata_keys:
                    raw_metadata_value = metadata.get(metadata_key)
                    metadata_values = raw_metadata_value if isinstance(raw_metadata_value, list) else [raw_metadata_value]
                    if any(self._refang_text(value).lower() == self._refang_text(term).lower() for value in metadata_values):
                        evidence.append(f"{label} matched metadata {metadata_key}={term}")
                        found = True
                        break

                if label in {"source ip", "destination ip"}:
                    if len(evidence) >= max_items:
                        return evidence
                    continue

                if not found and exact_key in {
                    "cves", "mitre_techniques", "threat_actor_aliases", "malware_families",
                    "campaigns", "tools", "courses_of_action",
                }:
                    artifact_values = self._metadata_artifact_values(metadata, (exact_key,))
                    if any(self._refang_text(value).lower() == self._refang_text(term).lower() for value in artifact_values):
                        evidence.append(f"{label} matched extracted CTI artifact {term}")
                        found = True

                if not found and term_type:
                    artifact_keys = {
                        "ip": ("ips", "public_ips", "non_public_ips"),
                        "domain": ("domains",),
                        "url": ("urls",),
                        "hash": ("hashes",),
                    }.get(term_type, ())
                    artifact_values = self._metadata_artifact_values(metadata, artifact_keys)
                    if any(self._refang_text(value).lower() == self._refang_text(term).lower() for value in artifact_values):
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
        haystack = f"{content or ''} {json.dumps(self._ranking_metadata(metadata or {}), sort_keys=True, default=str)}"
        terms = []
        for token in re.findall(r"[A-Za-z0-9_.:/-]{4,}", str(query or "")):
            if not self._is_high_signal_search_value(token):
                continue
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

    @staticmethod
    def _score_exact_candidate(evidence: List[str], source: str = "") -> float:
        """Score exact matches by evidence quality, not just by match type."""
        joined = " ".join(str(item or "").lower() for item in evidence or [])
        if not joined:
            return 1.02

        if "hash matched" in joined:
            score = 1.45
        elif "url matched" in joined or "domain matched" in joined:
            score = 1.36
        elif re.search(r"(?<!source )(?<!destination )\bip matched", joined):
            score = 1.32
        elif "threat actor matched" in joined:
            score = 1.24
        elif "indicator matched" in joined:
            score = 1.12
        elif "signature matched" in joined or "signature_id matched" in joined or "rule_id matched" in joined:
            score = 1.08
        elif "mitre technique matched" in joined:
            # Technique IDs are broad behavioral context shared by many unrelated
            # reports; they must not outrank a distinctive semantic description.
            score = 0.52
        else:
            score = 1.10

        if source == "custom_document":
            score += 0.04
        return round(min(score, 1.5), 3)

    def _exact_archive_condition(self, exact_terms: dict = None) -> tuple[str, List[Any]]:
        if not exact_terms:
            return "", []

        conditions = []
        params: List[Any] = []

        rule_ids = self._normalize_exact_values(exact_terms.get("rule_ids"))
        if rule_ids:
            conditions.append("LOWER(metadata->>'rule_id') = ANY(%s)")
            params.append(self._casefold_exact_values(rule_ids))

        signature_ids = self._normalize_exact_values(exact_terms.get("signature_ids"))
        if signature_ids:
            conditions.append("LOWER(metadata->>'signature_id') = ANY(%s)")
            params.append(self._casefold_exact_values(signature_ids))

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
            folded_domains = self._casefold_exact_values(domains)
            conditions.append("(LOWER(metadata->>'http_hostname') = ANY(%s) OR LOWER(metadata->>'dns_query') = ANY(%s) OR LOWER(metadata->>'tls_sni') = ANY(%s) OR LOWER(metadata->>'email_mail_from_domain') = ANY(%s) OR LOWER(metadata->>'ioc_domain') = ANY(%s) OR content ILIKE ANY(%s))")
            params.extend([folded_domains, folded_domains, folded_domains, folded_domains, folded_domains, domain_patterns])

        urls = self._normalize_exact_values(exact_terms.get("urls"))
        if urls:
            url_patterns = self._like_patterns(urls)
            folded_urls = self._casefold_exact_values(urls)
            conditions.append("(LOWER(metadata->>'http_url') = ANY(%s) OR LOWER(metadata->>'email_url') = ANY(%s) OR LOWER(metadata->>'ioc_url') = ANY(%s) OR content ILIKE ANY(%s))")
            params.extend([folded_urls, folded_urls, folded_urls, url_patterns])

        hashes = self._normalize_exact_values(exact_terms.get("hashes"))
        if hashes:
            hash_patterns = self._like_patterns(hashes)
            folded_hashes = self._casefold_exact_values(hashes)
            conditions.append("(LOWER(metadata->>'ioc_hash') = ANY(%s) OR LOWER(metadata->>'file_md5') = ANY(%s) OR LOWER(metadata->>'file_sha1') = ANY(%s) OR LOWER(metadata->>'file_sha256') = ANY(%s) OR content ILIKE ANY(%s))")
            params.extend([folded_hashes, folded_hashes, folded_hashes, folded_hashes, hash_patterns])

        signatures = self._normalize_exact_values(exact_terms.get("alert_signatures"))
        if signatures:
            signature_patterns = self._like_patterns(signatures)
            conditions.append("(LOWER(metadata->>'alert_signature') = ANY(%s) OR content ILIKE ANY(%s))")
            params.extend([self._casefold_exact_values(signatures), signature_patterns])

        keywords = self._normalize_exact_values(exact_terms.get("keywords"))
        if keywords:
            keyword_patterns = self._like_patterns(keywords)
            if keyword_patterns:
                conditions.append("content ILIKE ANY(%s)")
                params.append(keyword_patterns)

        return (" OR ".join(conditions), params) if conditions else ("", [])

    def _exact_document_condition(self, exact_terms: dict = None) -> tuple[str, List[Any]]:
        if not exact_terms:
            return "", []

        conditions = []
        params: List[Any] = []

        artifact_key_map = {
            "cti_ips": "ips",
            "domains": "domains",
            "urls": "urls",
            "hashes": "hashes",
            "cves": "cves",
            "mitre_techniques": "mitre_techniques",
            "threat_actors": "threat_actors",
            "threat_actor_aliases": "threat_actor_aliases",
            "malware_families": "malware_families",
            "campaigns": "campaigns",
            "tools": "tools",
            "courses_of_action": "courses_of_action",
        }
        for exact_key, artifact_key in artifact_key_map.items():
            key_values = self._normalize_exact_values(exact_terms.get(exact_key))
            if exact_key == "cti_ips":
                key_values = [
                    value for value in key_values
                    if CTIArtifactExtractor.is_public_ip(value)
                    and str(value).strip() not in CTIArtifactExtractor.LOW_SIGNAL_CTI_IPS
                ]
            if not key_values:
                continue
            artifact_conditions = []
            for metadata_key in ("cti_artifacts", "source_cti_artifacts"):
                artifact_conditions.append(f"""
                    EXISTS (
                        SELECT 1
                        FROM jsonb_array_elements_text(
                            CASE
                                WHEN jsonb_typeof(metadata->'{metadata_key}'->'{artifact_key}') = 'array'
                                THEN metadata->'{metadata_key}'->'{artifact_key}'
                                WHEN metadata->'{metadata_key}'->'{artifact_key}' IS NULL
                                THEN '[]'::jsonb
                                ELSE jsonb_build_array(metadata->'{metadata_key}'->'{artifact_key}')
                            END
                        ) AS artifact_value(value)
                        WHERE LOWER(artifact_value.value) = ANY(%s)
                    )
                """)
                params.append(self._casefold_exact_values(key_values))
            conditions.append("(" + " OR ".join(artifact_conditions) + ")")

        values = []
        document_ip_values = self._normalize_exact_values(exact_terms.get("cti_ips"))
        if not document_ip_values:
            document_ip_values = self._normalize_exact_values(exact_terms.get("ips"))
        document_ip_values = [
            value for value in document_ip_values
            if CTIArtifactExtractor.is_public_ip(value)
            and str(value).strip() not in CTIArtifactExtractor.LOW_SIGNAL_CTI_IPS
        ]

        for key in ("rule_ids", "signature_ids", "domains", "urls", "hashes",
                    "cves", "mitre_techniques", "alert_signatures", "threat_actors",
                    "threat_actor_aliases", "malware_families", "campaigns", "tools",
                    "courses_of_action", "keywords"):
            key_values = self._normalize_exact_values(exact_terms.get(key))
            if key == "keywords":
                key_values = [
                    value for value in key_values
                    if self._is_high_signal_search_value(value)
                ]
            values.extend(key_values)
        values.extend(document_ip_values)
        patterns = self._like_patterns(values)
        if patterns:
            conditions.append("content ILIKE ANY(%s)")
            params.append(patterns)
        return (" OR ".join(conditions), params) if conditions else ("", [])

    @staticmethod
    def _row_key(item: Dict[str, Any]) -> tuple:
        return (
            item.get("source"),
            item.get("id"),
            hashlib.sha256(str(item.get("content", "")).encode("utf-8")).hexdigest()
        )

    @staticmethod
    def _canonical_result_key(item: Dict[str, Any]) -> tuple:
        metadata = item.get("metadata") or {}
        identity = (
            metadata.get("raw_document_hash")
            or metadata.get("content_hash")
            or metadata.get("raw_alert_hash")
            or hashlib.sha256(str(item.get("content", "")).encode("utf-8")).hexdigest()
            or item.get("id")
        )
        return (item.get("source") or "unknown", str(identity))

    @classmethod
    def _best_exact_candidate_per_canonical_document(
        cls,
        candidates: List[Dict[str, Any]],
        limit: int,
    ) -> List[Dict[str, Any]]:
        """Select each document's strongest validated exact-match chunk.

        SQL can cheaply identify rows containing any supplied term, but the
        boundary-, type-, and disposition-aware evidence validator is Python.
        Choosing an arbitrary newest matching row before validation can discard
        a document's strong domain/hash chunk in favor of a weak metadata match.
        """
        best: Dict[tuple, Dict[str, Any]] = {}
        for item in candidates:
            key = cls._canonical_result_key(item)
            quality = (
                float(item.get("score") or 0.0),
                len(item.get("match_evidence") or []),
                -int(item.get("id") or 0),
            )
            existing = best.get(key)
            if existing is None:
                best[key] = item
                continue
            existing_quality = (
                float(existing.get("score") or 0.0),
                len(existing.get("match_evidence") or []),
                -int(existing.get("id") or 0),
            )
            if quality > existing_quality:
                best[key] = item
        return sorted(
            best.values(),
            key=lambda item: (
                float(item.get("score") or 0.0),
                len(item.get("match_evidence") or []),
                -int(item.get("id") or 0),
            ),
            reverse=True,
        )[:limit]

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
        source_cap = 2
        selected = []
        source_counts: Dict[str, int] = {}

        for item in results:
            metadata = item.get("metadata") or {}
            source = item.get("source") or "unknown"
            canonical_source = str(
                metadata.get("raw_document_hash")
                or metadata.get("content_hash")
                or metadata.get("raw_alert_hash")
                or hashlib.sha256(str(item.get("content", "")).encode("utf-8")).hexdigest()
            )
            source_key = f"{source}:{canonical_source}"
            if source_counts.get(source_key, 0) >= source_cap:
                continue
            selected.append(item)
            source_counts[source_key] = source_counts.get(source_key, 0) + 1
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
        if not self.active_corpus_id or not self.rag_ready:
            return []
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
                            "score": self._score_exact_candidate(evidence, r[3]), "match_types": ["exact"],
                            "match_evidence": evidence
                        })

                archive_filter, archive_params = self._archive_filter(metadata_filter, require_embedding=False)
                cur.execute(f"""
                    SELECT id, content, metadata, source,
                           ts_rank_cd(
                               to_tsvector('simple', coalesce(content, '')),
                               plainto_tsquery('simple', %s)
                           ) AS lexical_score
                    FROM alert_embeddings
                    WHERE {archive_filter}
                    AND to_tsvector('simple', coalesce(content, ''))
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
                    WITH scored AS (
                        SELECT id, content, metadata,
                               1 - (embedding <=> %s::vector) AS similarity,
                               row_number() OVER (
                                   PARTITION BY coalesce(
                                       metadata->>'raw_document_hash',
                                       metadata->>'content_hash',
                                       id::text
                                   )
                                   ORDER BY embedding <=> %s::vector
                               ) AS document_rank
                        FROM custom_documents
                        WHERE corpus_id = %s AND embedding IS NOT NULL
                        AND (1 - (embedding <=> %s::vector)) >= %s
                    )
                    SELECT id, content, metadata, similarity
                    FROM scored
                    WHERE document_rank = 1
                    ORDER BY similarity DESC
                    LIMIT %s
                """, (
                    query_embedding, query_embedding, self.active_corpus_id,
                    query_embedding, self.similarity_threshold, candidate_limit,
                ))
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
                        WHERE corpus_id = %s AND ({exact_condition})
                    """, (self.active_corpus_id, *exact_params))
                    exact_candidates = []
                    for r in cur.fetchall():
                        evidence = self._exact_match_evidence(r[1], r[2] or {}, exact_terms)
                        if not evidence:
                            continue
                        exact_candidates.append({
                            "id": r[0], "content": r[1], "metadata": r[2] or {}, "source": "custom_document",
                            "score": self._score_exact_candidate(evidence, "custom_document"), "match_types": ["exact"],
                            "match_evidence": evidence
                        })
                    candidates.extend(self._best_exact_candidate_per_canonical_document(
                        exact_candidates,
                        candidate_limit,
                    ))

                cur.execute("""
                    WITH scored AS (
                        SELECT id, content, metadata,
                               ts_rank_cd(
                                   to_tsvector('simple', coalesce(content, '')),
                                   plainto_tsquery('simple', %s)
                               ) AS lexical_score
                        FROM custom_documents
                        WHERE corpus_id = %s
                          AND to_tsvector('simple', coalesce(content, ''))
                            @@ plainto_tsquery('simple', %s)
                    ), ranked AS (
                        SELECT *, row_number() OVER (
                            PARTITION BY coalesce(
                                metadata->>'raw_document_hash',
                                metadata->>'content_hash',
                                id::text
                            )
                            ORDER BY lexical_score DESC, id DESC
                        ) AS document_rank
                        FROM scored
                    )
                    SELECT id, content, metadata, lexical_score
                    FROM ranked
                    WHERE document_rank = 1
                    ORDER BY lexical_score DESC
                    LIMIT %s
                """, (query, self.active_corpus_id, query, candidate_limit))
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

            if "custom_document" in sources:
                candidates.extend(
                    self._expand_custom_document_context_from_exact_hits(
                        cur,
                        candidates,
                        per_seed_limit=4,
                        total_limit=max(limit, 4),
                    )
                )

        merged = self._merge_hybrid_results(candidates)
        return self._apply_source_diversity(merged, limit) if enforce_diversity else merged[:limit]

    @staticmethod
    def _metadata_int(metadata: Dict[str, Any], key: str) -> Optional[int]:
        try:
            value = metadata.get(key)
            if value in (None, ""):
                return None
            return int(value)
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _context_like_pattern(value: Any) -> Optional[str]:
        text = re.sub(r"\s+", " ", str(value or "").strip())
        if len(text) < 3:
            return None
        return f"%{text}%"

    @classmethod
    def _source_context_patterns_for_seed(cls, seed: Dict[str, Any]) -> List[str]:
        """Build actor/document-aware section patterns for CTI source expansion."""
        metadata = seed.get("metadata") or {}
        raw_values: List[Any] = []

        def add(value: Any):
            if value in (None, "", [], {}):
                return
            if isinstance(value, dict):
                for item in value.values():
                    add(item)
                return
            if isinstance(value, (list, tuple, set)):
                for item in value:
                    add(item)
                return
            raw_values.append(value)

        for artifact_key in ("cti_artifacts", "source_cti_artifacts"):
            artifacts = metadata.get(artifact_key) or {}
            if isinstance(artifacts, dict):
                for entity_key in (
                    "threat_actors",
                    "threat_actor_aliases",
                    "malware_families",
                    "campaigns",
                    "tools",
                    "courses_of_action",
                ):
                    add(artifacts.get(entity_key))

        for key in ("cti_section_path",):
            value = metadata.get(key)
            if value:
                stem = Path(str(value)).stem.replace("_", " ").replace("-", " ")
                for token in re.findall(r"\b[A-Za-z][A-Za-z0-9]{2,}\b", stem):
                    if token.lower() not in {"chunk", "document", "summary", "processed", "pdf"}:
                        add(token)

        generic_cti_sections = [
            "Executive Summary",
            "Overview",
            "Background",
            "Attribution",
            "Threat Actor",
            "Campaign",
            "Malware",
            "Technical Analysis",
            "Initial Compromise",
            "Delivery",
            "Execution",
            "Persistence",
            "Privilege Escalation",
            "Defense Evasion",
            "Credential Access",
            "Discovery",
            "Lateral Movement",
            "Command and Control",
            "Exfiltration",
            "Impact",
            "MITRE",
            "ATT&CK",
            "Indicators of Compromise",
            "Recommendations",
            "Remediation",
            "Mitigation",
            "Detection",
            "Hunting",
        ]
        raw_values.extend(generic_cti_sections)

        patterns = []
        seen = set()
        for value in raw_values:
            pattern = cls._context_like_pattern(value)
            if not pattern:
                continue
            key = pattern.lower()
            if key in seen:
                continue
            seen.add(key)
            patterns.append(pattern)
            if len(patterns) >= 36:
                break
        return patterns

    def _expand_custom_document_context_from_exact_hits(
        self,
        cur,
        candidates: List[Dict[str, Any]],
        per_seed_limit: int = 4,
        total_limit: int = 8,
    ) -> List[Dict[str, Any]]:
        """Pull source-document background around exact uploaded-CTI IoC hits.

        Exact IoC matches often land in an appendix/table chunk. Nearby and
        named sections from the same source document provide campaign context,
        but are labelled as source_context so they are not mistaken for direct
        evidence in the current alert.
        """
        if not candidates or total_limit <= 0:
            return []

        seeds = []
        seen_seed_keys = set()
        for item in candidates:
            if item.get("source") != "custom_document":
                continue
            if "exact" not in set(item.get("match_types") or []):
                continue

            metadata = item.get("metadata") or {}
            source_document = metadata.get("raw_document_hash") or metadata.get("content_hash")
            chunk_index = self._metadata_int(metadata, "chunk_index")
            if not source_document or chunk_index is None:
                continue

            seed_key = (source_document, chunk_index)
            if seed_key in seen_seed_keys:
                continue
            seen_seed_keys.add(seed_key)
            seeds.append((item, source_document, chunk_index))

        if not seeds:
            return []

        existing_keys = {self._row_key(item) for item in candidates}
        expanded = []

        for seed, source_document, chunk_index in seeds:
            if len(expanded) >= total_limit:
                break

            linked_evidence = list(seed.get("match_evidence") or [])
            linked_query = seed.get("retrieval_query") or seed.get("query")
            linked_metadata = seed.get("metadata") or {}
            rows = []
            range_center = max(0, chunk_index)
            range_start = 0 if chunk_index < 0 else max(0, chunk_index - 2)
            range_end = max(per_seed_limit + 1, 3) if chunk_index < 0 else chunk_index + 2

            cur.execute(
                """
                SELECT id, content, metadata
                FROM custom_documents
                WHERE corpus_id = %s
                  AND COALESCE(metadata->>'raw_document_hash', metadata->>'content_hash') = %s
                  AND coalesce(metadata->>'chunk_role', '') <> 'document_summary'
                  AND (metadata->>'chunk_index') ~ '^-?[0-9]+$'
                  AND (metadata->>'chunk_index')::int BETWEEN %s AND %s
                ORDER BY ABS((metadata->>'chunk_index')::int - %s), (metadata->>'chunk_index')::int
                LIMIT %s
                """,
                (
                    self.active_corpus_id,
                    source_document,
                    range_start,
                    range_end,
                    range_center,
                    max(1, per_seed_limit),
                ),
            )
            rows.extend(cur.fetchall())

            remaining = max(0, per_seed_limit - len(rows))
            if remaining:
                where_parts = []
                params: List[Any] = [self.active_corpus_id, source_document]
                context_patterns = self._source_context_patterns_for_seed(seed)
                for pattern in context_patterns:
                    where_parts.append(
                        "(content ILIKE %s OR coalesce(metadata->>'cti_section_path', '') ILIKE %s)"
                    )
                    params.extend([pattern, pattern])

                if where_parts:
                    cur.execute(
                        f"""
                        SELECT id, content, metadata
                        FROM custom_documents
                        WHERE corpus_id = %s
                          AND COALESCE(metadata->>'raw_document_hash', metadata->>'content_hash') = %s
                          AND coalesce(metadata->>'chunk_role', '') <> 'document_summary'
                          AND ({' OR '.join(where_parts)})
                        ORDER BY
                          CASE
                            WHEN (metadata->>'chunk_index') ~ '^[0-9]+$' THEN (metadata->>'chunk_index')::int
                            ELSE 999999
                          END
                        LIMIT %s
                        """,
                        (*params, remaining),
                    )
                    rows.extend(cur.fetchall())

            for row_id, content, metadata in rows:
                linked_score = self._score_exact_candidate(linked_evidence, "custom_document")
                context_item = {
                    "id": row_id,
                    "content": content,
                    "metadata": metadata or {},
                    "source": "custom_document",
                    "score": round(max(1.05, min(1.28, linked_score - 0.15)), 3),
                    "match_types": ["source_context"],
                    "match_evidence": [
                        "same uploaded CTI document as exact IoC match"
                    ] + linked_evidence[:3],
                    "linked_exact_source_document": source_document,
                    "linked_exact_chunk_index": chunk_index,
                    "linked_exact_filename": linked_metadata.get("filename"),
                    "linked_exact_match_evidence": linked_evidence[:5],
                    "linked_exact_query": linked_query,
                }
                key = self._row_key(context_item)
                if key in existing_keys:
                    continue
                existing_keys.add(key)
                expanded.append(context_item)
                if len(expanded) >= total_limit:
                    break

        return expanded

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

    def get_selected_document_passages(
        self,
        selected_doc: Dict[str, Any],
        preferred_terms: Iterable[str] = (),
        limit: int = 4,
    ) -> List[Dict[str, Any]]:
        """Expand one already-selected document without participating in ranking.

        This deliberately runs after canonical retrieval and only reads chunks
        from the selected document.  It cannot introduce a new source or alter
        the ranked result set.
        """
        if not isinstance(selected_doc, dict) or selected_doc.get("source") != "custom_document":
            return []
        metadata = selected_doc.get("metadata") or {}
        source_document = metadata.get("raw_document_hash") or metadata.get("content_hash")
        if not source_document or not self.active_corpus_id:
            return []

        terms = []
        for value in preferred_terms or ():
            value = re.sub(r"\s+", " ", str(value or "")).strip()
            if len(value) >= 4 and value.lower() not in {item.lower() for item in terms}:
                terms.append(value[:120])
            if len(terms) >= 18:
                break

        with self.db_lock, self.conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, content, metadata
                FROM custom_documents
                WHERE corpus_id = %s
                  AND COALESCE(metadata->>'raw_document_hash', metadata->>'content_hash') = %s
                  AND coalesce(metadata->>'chunk_role', '') <> 'document_summary'
                ORDER BY CASE
                    WHEN (metadata->>'chunk_index') ~ '^-?[0-9]+$'
                    THEN (metadata->>'chunk_index')::int ELSE 999999 END
                """,
                (self.active_corpus_id, source_document),
            )
            rows = cur.fetchall()

        seed_index = self._metadata_int(metadata, "chunk_index")
        scored = []
        section_terms = (
            "overview", "background", "technical analysis", "malware", "capabilities",
            "command and control", "detection", "hunting", "attribution", "conclusion",
        )
        for row_id, content, row_metadata in rows:
            row_metadata = row_metadata or {}
            haystack = f"{row_metadata.get('cti_section_path', '')} {content or ''}".lower()
            term_hits = sum(1 for term in terms if term.lower() in haystack)
            section_hits = sum(1 for term in section_terms if term in haystack)
            row_index = self._metadata_int(row_metadata, "chunk_index")
            proximity = 0.0
            if seed_index is not None and row_index is not None:
                proximity = max(0.0, 2.0 - min(abs(seed_index - row_index), 4) * 0.5)
            score = term_hits * 5.0 + section_hits * 1.5 + proximity
            scored.append((score, row_index if row_index is not None else 999999, row_id, content, row_metadata))

        selected = []
        seen_text = set()
        for score, _, row_id, content, row_metadata in sorted(scored, key=lambda item: (-item[0], item[1])):
            normalized = re.sub(r"\s+", " ", str(content or "")).strip().lower()
            if not normalized or normalized in seen_text:
                continue
            seen_text.add(normalized)
            selected.append({
                "id": row_id,
                "content": content,
                "metadata": row_metadata,
                "source": "custom_document",
                "score": score,
                "match_types": ["selected_document_expansion"],
                "match_evidence": ["complementary passage from already-selected canonical document"],
                "parent_source_document": source_document,
            })
            if len(selected) >= max(2, min(int(limit or 4), 4)):
                break
        return selected

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

    def get_recent_custom_documents(self, k: int = 4) -> List[Dict[str, Any]]:
        """Return recent uploaded CTI chunks as a persistent last-resort context."""
        limit = max(1, min(self._safe_int(k, 4), 20))
        try:
            with self.db_lock, self.conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT id, content, metadata
                    FROM custom_documents
                    WHERE corpus_id = %s
                    ORDER BY
                      CASE
                        WHEN coalesce(metadata->>'chunk_role', '') = 'document_summary' THEN 0
                        ELSE 1
                      END,
                      created_at DESC,
                      id DESC
                    LIMIT %s
                    """,
                    (self.active_corpus_id, limit),
                )
                return [
                    {
                        "id": row_id,
                        "content": content,
                        "metadata": metadata or {},
                        "source": "custom_document",
                        "score": 0.0,
                        "match_types": ["persistent_fallback"],
                        "match_evidence": [
                            "recent uploaded CTI document fallback; no focused retrieval match"
                        ],
                    }
                    for row_id, content, metadata in cur.fetchall()
                ]
        except Exception as error:
            self._rollback_safely()
            log_sanitized_exception("Recent custom document fallback failed", error)
            raise RuntimeError("Recent custom document fallback failed") from None

    def get_rag_status(self) -> Dict[str, Any]:
        """Get current RAG status with database stats"""
        try:
            with self.db_lock, self.conn.cursor() as cur:
                cur.execute("""
                    SELECT 
                        (
                            SELECT COUNT(DISTINCT COALESCE(
                                NULLIF(metadata->>'raw_alert_hash', ''),
                                alert_hash
                            ))
                            FROM alert_embeddings WHERE corpus_id = %s
                        ) as total_alerts,
                        (
                            SELECT COUNT(DISTINCT COALESCE(
                                NULLIF(metadata->>'raw_alert_hash', ''),
                                alert_hash
                            ))
                            FROM alert_embeddings
                            WHERE corpus_id = %s AND embedding IS NOT NULL
                        ) as alerts_with_embeddings,
                        (SELECT COUNT(*) FROM custom_documents WHERE corpus_id = %s) as total_docs,
                        (SELECT COUNT(*) FROM custom_documents WHERE corpus_id = %s AND embedding IS NOT NULL) as docs_with_embeddings,
                        (
                            SELECT COUNT(DISTINCT COALESCE(
                                metadata->>'content_hash',
                                metadata->>'raw_document_hash',
                                id::text
                            ))
                            FROM custom_documents
                            WHERE corpus_id = %s
                        ) as total_source_docs,
                        (
                            SELECT COUNT(DISTINCT COALESCE(
                                metadata->>'content_hash',
                                metadata->>'raw_document_hash',
                                id::text
                            ))
                            FROM custom_documents
                            WHERE corpus_id = %s AND embedding IS NOT NULL
                        ) as source_docs_with_embeddings,
                        (
                            SELECT COUNT(*)
                            FROM custom_documents
                            WHERE corpus_id = %s AND COALESCE(metadata->>'processor_version', '') <> %s
                        ) as stale_doc_chunks,
                        (
                            SELECT COUNT(DISTINCT COALESCE(
                                metadata->>'content_hash',
                                metadata->>'raw_document_hash',
                                id::text
                            ))
                            FROM custom_documents
                            WHERE corpus_id = %s AND COALESCE(metadata->>'processor_version', '') <> %s
                        ) as stale_source_docs,
                        (
                            SELECT manifest->'versions'
                            FROM rag_corpora
                            WHERE corpus_id = %s
                        ) as active_corpus_versions,
                        (
                            SELECT status
                            FROM rag_corpora
                            WHERE corpus_id = %s
                        ) as active_corpus_status,
                        (
                            SELECT manifest
                            FROM rag_corpora
                            WHERE corpus_id = %s
                        ) as active_corpus_manifest,
                        (
                            SELECT chunk_count
                            FROM rag_corpora
                            WHERE corpus_id = %s
                        ) as lifecycle_chunk_count,
                        (
                            SELECT document_count
                            FROM rag_corpora
                            WHERE corpus_id = %s
                        ) as lifecycle_source_count
                """, (
                    self.active_corpus_id,
                    self.active_corpus_id,
                    self.active_corpus_id,
                    self.active_corpus_id,
                    self.active_corpus_id,
                    self.active_corpus_id,
                    self.active_corpus_id,
                    CTIArtifactExtractor.EXTRACTION_PIPELINE_VERSION,
                    self.active_corpus_id,
                    CTIArtifactExtractor.EXTRACTION_PIPELINE_VERSION,
                    self.active_corpus_id,
                    self.active_corpus_id,
                    self.active_corpus_id,
                    self.active_corpus_id,
                    self.active_corpus_id,
                ))
                stats = cur.fetchone()
                exact_inventory_complete = False
                integrity_error = None
                active_manifest = (
                    dict(stats[10])
                    if stats and isinstance(stats[10], dict)
                    else {}
                )
                if (
                    stats
                    and self.active_corpus_id
                    and stats[9] == "ready"
                ):
                    try:
                        if self._manifest_uses_typed_source_inventory(
                            active_manifest
                        ):
                            self._validate_corpus_completeness(
                                cur,
                                self.active_corpus_id,
                                active_manifest,
                                lifecycle_chunk_count=stats[11],
                                lifecycle_source_count=stats[12],
                            )
                        else:
                            self._validate_legacy_corpus_completeness(
                                cur,
                                self.active_corpus_id,
                                active_manifest,
                                lifecycle_chunk_count=stats[11],
                                lifecycle_source_count=stats[12],
                            )
                        exact_inventory_complete = True
                    except ValueError as error:
                        integrity_error = str(error)
            if not stats:
                raise RuntimeError("RAG status query returned no row")

            configured_versions = self.corpus_version_manifest()
            active_versions = dict(stats[8]) if isinstance(stats[8], dict) else {}
            version_mismatches = (
                self._corpus_version_mismatches({"versions": active_versions})
                if self.active_corpus_id
                else {}
            )
            version_compatible = bool(
                self.active_corpus_id
                and stats[9] == "ready"
                and active_versions
                and not version_mismatches
            )
            active_chunks_complete = bool(
                exact_inventory_complete
                and
                (int(stats[0] or 0) + int(stats[2] or 0)) > 0
                and int(stats[0] or 0) == int(stats[1] or 0)
                and int(stats[2] or 0) == int(stats[3] or 0)
                and int(stats[4] or 0) == int(stats[5] or 0)
            )
            ready = bool(active_chunks_complete and version_compatible)
            self.active_corpus_version_mismatches = version_mismatches
            self.rag_ready = ready
            stale_doc_chunks = int(stats[6] or 0)
            stale_source_docs = int(stats[7] or 0)
            active_archive_records = int(stats[0] or 0)
            active_embedded_archive_records = int(stats[1] or 0)
            active_document_chunks = int(stats[2] or 0)
            active_embedded_document_chunks = int(stats[3] or 0)
            active_source_documents = int(stats[4] or 0)
            active_embedded_source_documents = int(stats[5] or 0)
            active_total_chunks = active_archive_records + active_document_chunks
            active_embedded_chunks = (
                active_embedded_archive_records
                + active_embedded_document_chunks
            )
            active_source_items = (
                active_archive_records + active_source_documents
            )
            warnings = []
            if stale_doc_chunks:
                warnings.append(
                    "Uploaded CTI documents were indexed with an older extraction pipeline; "
                    "build a replacement corpus and re-upload PDFs for current extraction and retrieval fixes."
                )
            if version_mismatches:
                warnings.append(
                    "The stored active corpus was built with incompatible index versions; "
                    "retrieval is disabled until a replacement corpus is built and activated."
                )
            if integrity_error:
                warnings.append(
                    "The stored active corpus failed exact source/chunk validation; "
                    "retrieval is disabled until a validated corpus is activated."
                )

            lifecycle = self.list_corpora()
            return {
                "ready": ready,
                "active_corpus_id": self.active_corpus_id,
                # This is the stored active version record, not the configured
                # values presented as though the index were compatible.
                "corpus_versions": active_versions or None,
                "active_corpus_versions": active_versions or None,
                "configured_corpus_versions": configured_versions,
                "active_corpus_version_compatible": version_compatible,
                "active_corpus_version_mismatches": version_mismatches,
                "active_corpus_status": stats[9],
                "active_corpus_integrity_valid": exact_inventory_complete,
                "active_corpus_integrity_error": integrity_error,
                "available_corpora": lifecycle["corpora"],
                "available_corpora_total": lifecycle["total"],
                "available_corpora_returned": lifecycle["returned"],
                "available_corpora_truncated": lifecycle["truncated"],
                "storage": "persistent_postgresql",
                # Explicit active-union counters.  These are derived only from
                # rows in the selected immutable corpus namespace, so the UI
                # never has to infer sources from historical corpus totals.
                "active_archive_records": active_archive_records,
                "active_source_documents": active_source_documents,
                "active_document_chunks": active_document_chunks,
                "active_total_chunks": active_total_chunks,
                "active_embedded_chunks": active_embedded_chunks,
                "active_source_items": active_source_items,
                "active_union_counts": {
                    "source_items": active_source_items,
                    "uploaded_documents": active_source_documents,
                    "archive_records": active_archive_records,
                    "document_chunks": active_document_chunks,
                    "total_chunks": active_total_chunks,
                    "embedded_chunks": active_embedded_chunks,
                    "embedded_uploaded_documents": active_embedded_source_documents,
                    "embedded_archive_records": active_embedded_archive_records,
                },
                "total_alerts": stats[0],
                "alerts_with_embeddings": stats[1],
                "total_uploaded_documents": stats[4],
                "uploaded_documents_with_embeddings": stats[5],
                "total_custom_doc_chunks": stats[2],
                "custom_doc_chunks_with_embeddings": stats[3],
                "total_custom_docs": stats[2],
                "docs_with_embeddings": stats[3],
                "current_processor_version": CTIArtifactExtractor.EXTRACTION_PIPELINE_VERSION,
                "stale_custom_doc_chunks": stale_doc_chunks,
                "stale_uploaded_documents": stale_source_docs,
                "rag_rebuild_recommended": bool(stale_doc_chunks or version_mismatches),
                "warnings": warnings,
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
                "max_retrieval_docs": self.max_retrieval_docs,
            }
        except Exception as e:
            self._rollback_safely()
            log_sanitized_exception("RAG status check failed", e)
            self.rag_ready = False
            return {
                "ready": False,
                "storage": "persistent_postgresql",
                "error": "RAG status is temporarily unavailable"
            }
    def close(self) -> None:
        """Close the persistent PostgreSQL connection."""
        with self.db_lock:
            if self.conn is not None and not getattr(self.conn, "closed", True):
                self.conn.close()

class AlertAnalyzer:
    """Analyzes and processes security alert data with configurable asset awareness."""

    DEFAULT_INFRASTRUCTURE_IPS: List[str] = []
    DEFAULT_OWNED_CIDRS: List[str] = []
    DEFAULT_INTERNAL_CIDRS = [
        "192.168.0.0/16",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "127.0.0.0/8",
    ]
    _mitre_validation_catalog: Optional[Dict[str, Dict[str, Any]]] = None
    _mitre_catalog_version: Optional[str] = None

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
    def _first_dict(value: Any) -> Dict[str, Any]:
        return _first_dict_value(value)

    @classmethod
    def _load_mitre_validation_catalog(cls) -> tuple[Dict[str, Dict[str, Any]], str]:
        if cls._mitre_validation_catalog is not None and cls._mitre_catalog_version:
            return cls._mitre_validation_catalog, cls._mitre_catalog_version
        catalog_path = Path(__file__).resolve().parent / "mitre_techniques.json"
        try:
            payload = catalog_path.read_bytes()
            entries = json.loads(payload.decode("utf-8-sig"))
            catalog = {
                str(entry.get("id") or "").strip().upper(): entry
                for entry in entries
                if isinstance(entry, dict) and entry.get("id")
            }
            version = "sha256:" + hashlib.sha256(payload).hexdigest()
        except Exception:
            catalog = {}
            version = "unavailable"
        cls._mitre_validation_catalog = catalog
        cls._mitre_catalog_version = version
        return catalog, version

    @classmethod
    def _merge_mitre_values(cls, *sources: Any) -> Dict[str, Any]:
        """Normalize and validate explicit ATT&CK metadata from common alert shapes."""
        merged = {
            "id": [],
            "tactic": [],
            "technique": [],
            "confidence": [],
            "created_at": [],
            "updated_at": [],
            "signature_severity": [],
            "affected_product": [],
        }
        aliases = {
            "id": "id",
            "ids": "id",
            "technique_id": "id",
            "technique_ids": "id",
            "mitre_id": "id",
            "mitre_ids": "id",
            "tactic": "tactic",
            "tactics": "tactic",
            "technique": "technique",
            "techniques": "technique",
            "technique_name": "technique",
            "technique_names": "technique",
            "name": "technique",
            "confidence": "confidence",
            "created_at": "created_at",
            "updated_at": "updated_at",
            "signature_severity": "signature_severity",
            "affected_product": "affected_product",
        }

        invalid_ids: List[str] = []

        def add(target_key: str, value: Any):
            if value in (None, "", [], {}):
                return
            if isinstance(value, (list, tuple, set)):
                for item in value:
                    add(target_key, item)
                return
            text = str(value).strip()
            if text and text not in merged[target_key]:
                merged[target_key].append(text)

        def visit(value: Any, hinted_key: Optional[str] = None):
            if value in (None, "", [], {}):
                return
            if isinstance(value, dict):
                for raw_key, child in value.items():
                    normalized_key = str(raw_key).strip().lower()
                    visit(child, aliases.get(normalized_key, hinted_key if normalized_key in {"value", "values"} else None))
                return
            if isinstance(value, (list, tuple, set)):
                for child in value:
                    visit(child, hinted_key)
                return
            text = str(value).strip()
            if not text:
                return
            discovered_ids = re.findall(r"\bT\d{4}(?:\.\d{3})?\b", text, flags=re.IGNORECASE)
            if hinted_key == "id" or discovered_ids:
                if discovered_ids:
                    for technique_id in discovered_ids:
                        add("id", technique_id.upper())
                elif hinted_key == "id":
                    invalid_ids.append(text)
                return
            if hinted_key:
                add(hinted_key, text)
            elif re.fullmatch(r"T\d{4}(?:\.\d{3})?", text, flags=re.IGNORECASE):
                add("id", text.upper())

        for source in sources:
            visit(source)

        catalog, catalog_version = cls._load_mitre_validation_catalog()
        validated_ids = []
        deprecated_ids = []
        name_mismatches = []
        for technique_id in merged["id"]:
            normalized_id = technique_id.upper()
            entry = catalog.get(normalized_id)
            if catalog and not entry:
                invalid_ids.append(normalized_id)
                continue
            validated_ids.append(normalized_id)
            if entry and bool(entry.get("deprecated")):
                deprecated_ids.append(normalized_id)
            name_index = len(validated_ids) - 1
            supplied_name = merged["technique"][name_index] if name_index < len(merged["technique"]) else None
            catalog_name = str((entry or {}).get("name") or "").strip()
            supplied_name_key = re.sub(r"[^a-z0-9]+", "", str(supplied_name or "").lower())
            if supplied_name_key and catalog_name:
                if supplied_name_key != re.sub(r"[^a-z0-9]+", "", catalog_name.lower()):
                    name_mismatches.append({
                        "id": normalized_id,
                        "supplied_name": str(supplied_name),
                        "catalog_name": catalog_name,
                    })
        merged["id"] = list(dict.fromkeys(validated_ids))

        result = {
            key: values[0] if len(values) == 1 and key not in {"id", "tactic", "technique"} else values
            for key, values in merged.items()
            if values
        }
        if invalid_ids:
            result["invalid_ids"] = list(dict.fromkeys(invalid_ids))
        if deprecated_ids:
            result["deprecated_ids"] = deprecated_ids
        if name_mismatches:
            result["name_mismatches"] = name_mismatches
        result["catalog_version"] = catalog_version
        return result

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
        try:
            if not CTIArtifactExtractor.is_public_ip(ip_str):
                return "non_global"
        except ValueError:
            return "unknown"
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
            "emails": [],
            "hashes": [],
            "cves": [],
            "mitre_techniques": [],
            "threat_actors": [],
            "threat_actor_aliases": [],
            "malware_families": [],
            "campaigns": [],
            "tools": [],
            "courses_of_action": [],
            "processes": [],
            "files": [],
            "keywords": [],
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

        email_context = alert.get("email_context") or {}
        if isinstance(email_context, dict):
            iocs["domains"].append(email_context.get("mail_from_domain"))
            iocs["urls"].append(email_context.get("url"))
            for key in ("from", "to"):
                iocs["emails"].append(email_context.get(key))
            iocs["files"].append(email_context.get("attachment"))
            iocs["keywords"].append(email_context.get("subject"))

        ioc_context = alert.get("ioc_context") or {}
        if isinstance(ioc_context, dict):
            iocs["domains"].append(ioc_context.get("domain"))
            iocs["ips"].append(ioc_context.get("ip"))
            iocs["urls"].append(ioc_context.get("url"))
            for key in ("hash", "md5", "sha1", "sha256"):
                iocs["hashes"].append(ioc_context.get(key))

        process_context = alert.get("process_context") or {}
        if isinstance(process_context, dict):
            for key in ("name", "parent_process", "file", "path", "command_line"):
                iocs["processes"].append(process_context.get(key))

        file_context = alert.get("file_context") or {}
        if isinstance(file_context, dict):
            for key in ("md5", "sha1", "sha256"):
                iocs["hashes"].append(file_context.get(key))
            for key in ("filename", "state", "stored"):
                iocs["files"].append(file_context.get(key))

        smb_context = alert.get("smb_context") or {}
        if isinstance(smb_context, dict):
            for key in ("command", "share", "filename", "disposition"):
                iocs["files"].append(smb_context.get(key))

        modbus_context = alert.get("modbus_context") or {}
        if isinstance(modbus_context, dict):
            for key in ("function", "unit_id", "address", "quantity"):
                iocs["processes"].append(modbus_context.get(key))

        for context_key in ("ics_context", "windows_context", "network_context"):
            context = alert.get(context_key) or {}
            if isinstance(context, dict):
                for value in context.values():
                    if value not in (None, "", [], {}):
                        iocs["keywords"].append(value)

        vulnerability_context = alert.get("vulnerability_context") or {}
        if isinstance(vulnerability_context, dict):
            for key in ("cve", "cve_id", "id"):
                value = vulnerability_context.get(key)
                if value and re.fullmatch(r"CVE-\d{4}-\d{4,7}", str(value), re.IGNORECASE):
                    iocs["cves"].append(str(value).upper())
            for key in ("product", "vendor", "version", "service"):
                iocs["keywords"].append(vulnerability_context.get(key))

        raw_artifacts = alert.get("raw_alert_artifacts") or {}
        if isinstance(raw_artifacts, dict):
            for key in (
                "ips", "domains", "urls", "emails", "hashes", "cves", "mitre_techniques",
                "threat_actors", "threat_actor_aliases", "malware_families",
                "campaigns", "tools", "courses_of_action",
            ):
                target_key = key if key in iocs else "keywords"
                values = raw_artifacts.get(key, [])
                if key == "mitre_techniques":
                    values = self._merge_mitre_values(values).get("id", [])
                for value in values:
                    iocs[target_key].append(value)

        threat_context = alert.get("threat_context") or {}
        if isinstance(threat_context, dict):
            iocs["threat_actors"].append(threat_context.get("actor"))
            iocs["campaigns"].append(threat_context.get("campaign"))
            iocs["malware_families"].append(threat_context.get("malware"))
            iocs["malware_families"].append(threat_context.get("malware_family"))
            iocs["tools"].append(threat_context.get("tool"))

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

        for key in ("ips", "domains", "urls", "emails", "hashes", "cves", "mitre_techniques",
                    "threat_actors", "threat_actor_aliases", "malware_families",
                    "campaigns", "tools", "courses_of_action",
                    "processes", "files", "keywords", "rule_ids", "signature_ids", "ports"):
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

        for context_key in (
            "http_context", "dns_context", "tls_context", "email_context",
            "ioc_context", "process_context", "file_context", "smb_context",
            "modbus_context", "mitre_context",
        ):
            context = alert.get(context_key) or {}
            if isinstance(context, dict):
                parts.extend(str(value) for value in context.values() if value not in (None, "", [], {}))

        text = " ".join(parts).lower()
        rule_text = " ".join(
            str(alert.get(field) or "")
            for field in ("rule_description", "alert_signature", "alert_category")
        ).lower()
        http_context = alert.get("http_context") or {}
        dns_context = alert.get("dns_context") or {}
        tls_context = alert.get("tls_context") or {}
        email_context = alert.get("email_context") or {}
        ioc_context = alert.get("ioc_context") or {}
        corroborating_network_indicator = any((
            isinstance(http_context, dict) and bool(http_context.get("hostname")),
            isinstance(dns_context, dict) and bool(dns_context.get("query_name")),
            isinstance(tls_context, dict) and any(tls_context.get(key) for key in ("sni", "subject", "issuer", "ja3", "ja3s")),
            isinstance(email_context, dict) and bool(email_context.get("mail_from_domain")),
            isinstance(ioc_context, dict) and any(ioc_context.get(key) for key in ("domain", "url")),
            bool(re.search(r"\b(?:dns|domain|sni|certificate|callback|beacon)\b", rule_text)),
        ))
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
        if re.search(r"\b(?:brute force|bruteforce|authentication failure|failed login|password guess|ssh login|phish|smtp|email attachment|mail_from)\b", text):
            add("credential_attack")
        if re.search(r"\b(?:phish|spearphish|smtp|email|attachment|macro|document review)\b", text):
            add("phishing_or_email_delivery")
        if re.search(r"\b(?:c2|command and control|callback|beacon|cnc|botnet)\b", text):
            add("possible_c2")
        if re.search(r"\b(?:exfil|data leak|data theft|upload|staging|archive collected)\b", text):
            add("possible_exfiltration")
        if re.search(r"\b(?:ransomware|destructive|encryptor|file write|smb file|et malware)\b", text):
            add("malware_or_destructive_activity")
        if re.search(r"\b(?:lateral movement|smb|windows admin share|psexec|rdp|winrm)\b", text) or dest_port in {"445", "3389", "5985", "5986"}:
            add("lateral_movement_candidate")
        if re.search(r"\b(?:exploit|rce|remote code execution|sql injection|xss|traversal|web shell|php injection|cgi exploit|cve-\d{4}-\d{4,7})\b", text):
            add("web_or_exploit_attempt")
        if (
            re.search(r"\b(?:download(?:ed|ing)?|delivered|transfer(?:red)?|retrieved|fetched|payload|fileinfo|filename)\b", text)
            and re.search(r"\b(?:https?|url|uri|\.exe|\.dll|\.scr|\.zip|\.ps1|md5|sha1|sha256|hash)\b", text)
        ):
            add("ingress_tool_transfer")
        if re.search(r"\b(?:malware|trojan|backdoor|dropper|payload|shellcode)\b", text):
            add("malware_execution_candidate")
        if re.search(r"\b(?:powershell|pwsh|cmd\.exe|wscript|cscript|bash|sh\s+-c)\b", text):
            add("script_execution_candidate")
        if re.search(r"\b(?:rundll32|regsvr32|mshta)\b", text):
            add("signed_binary_proxy_execution")
        if re.search(r"\b(?:vssadmin|wmic)\b.{0,80}\b(?:delete|remove)\b.{0,80}\bshadow", text) or re.search(r"\bshadow copies?\b.{0,40}\b(?:delete|remove|disable)", text):
            add("inhibit_system_recovery")
        if corroborating_network_indicator:
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
        if "ingress_tool_transfer" in tags:
            add("Preserve and analyze downloaded payloads, file hashes, HTTP metadata, and endpoint execution evidence.")
        if "credential_attack" in tags:
            add("Review authentication logs, lockouts, MFA status, and exposed remote access services.")
        if "domain_or_tls_indicator" in tags:
            add("Search DNS/TLS/proxy logs for related domains, SNI, certificates, and repeated callbacks.")

        return focus[:6]


    def clean_log_data(self, logs: List[Dict]) -> List[Dict]:
        """Clean and minimize log data with enhanced context and proper IP classification"""
        cleaned_logs = []
        geoip_manager = self.geoip_manager
        for log in _expand_alert_records(logs):
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

            for key in (
                "_canonical_normalized_version", "_evidence_provenance",
                "_unknown_security_fields",
            ):
                value = log.get(key) if isinstance(log, dict) else None
                if value in (None, "", [], {}):
                    value = root_data.get(key) if isinstance(root_data, dict) else None
                if value not in (None, "", [], {}):
                    cleaned_log[key] = value

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
                        "length": http_data.get("length"),
                        "user_agent": http_data.get("user_agent"),
                        "referrer": http_data.get("referrer")
                    }
                
                # DNS context (for DNS-related alerts)
                dns_data = data.get("dns", {})
                if dns_data:
                    query_info = self._first_dict(dns_data.get("query"))
                    cleaned_log["dns_context"] = {
                        "query_name": query_info.get("rrname") or dns_data.get("rrname") or dns_data.get("query_name"),
                        "query_type": query_info.get("rrtype") or dns_data.get("rrtype") or dns_data.get("type"),
                        "rcode": dns_data.get("rcode"),
                        "version": dns_data.get("version")
                    }
                
                # TLS/SSL context
                tls_data = data.get("tls", {})
                if tls_data:
                    cleaned_log["tls_context"] = {
                        "sni": tls_data.get("sni"),
                        "version": tls_data.get("version"),
                        "subject": tls_data.get("subject"),
                        "issuer": tls_data.get("issuer") or tls_data.get("issuerdn"),
                        "ja3": tls_data.get("ja3"),
                        "ja3s": tls_data.get("ja3s")
                    }

                email_data = data.get("email", {}) or {}
                if email_data:
                    cleaned_log["email_context"] = {
                        "from": email_data.get("from"),
                        "to": email_data.get("to"),
                        "subject": email_data.get("subject"),
                        "attachment": email_data.get("attachment"),
                        "mail_from_domain": email_data.get("mail_from_domain"),
                        "url": email_data.get("url")
                    }

                threat_data = data.get("threat", {}) or {}
                if threat_data:
                    cleaned_log["threat_context"] = {
                        "actor": threat_data.get("actor"),
                        "campaign": threat_data.get("campaign"),
                        "malware": threat_data.get("malware"),
                        "malware_family": threat_data.get("malware_family"),
                        "tool": threat_data.get("tool"),
                        "confidence": threat_data.get("confidence")
                    }

                ioc_data = data.get("ioc", {}) or {}
                if ioc_data:
                    cleaned_log["ioc_context"] = {
                        "domain": ioc_data.get("domain"),
                        "ip": ioc_data.get("ip"),
                        "url": ioc_data.get("url"),
                        "hash": ioc_data.get("hash"),
                        "md5": ioc_data.get("md5"),
                        "sha1": ioc_data.get("sha1"),
                        "sha256": ioc_data.get("sha256"),
                        "role": ioc_data.get("role") or ioc_data.get("ip_role"),
                        "disposition": ioc_data.get("disposition"),
                        "confidence": ioc_data.get("confidence"),
                    }

                process_data = data.get("process", {}) or {}
                if process_data:
                    cleaned_log["process_context"] = {
                        "name": process_data.get("name"),
                        "parent_process": process_data.get("parent_process"),
                        "file": process_data.get("file"),
                        "path": process_data.get("path"),
                        "command_line": process_data.get("command_line") or process_data.get("commandLine") or process_data.get("cmdline"),
                        "pid": process_data.get("pid") or process_data.get("process_id"),
                        "user": process_data.get("user"),
                    }

                # Preserve structured security telemetry instead of reducing it to
                # generic text. Downstream code retains the original field names so
                # each current-alert fact keeps its provenance.
                for source_key, target_key in (
                    ("ics", "ics_context"),
                    ("windows", "windows_context"),
                    ("network", "network_context"),
                    ("vulnerability", "vulnerability_context"),
                ):
                    structured_value = data.get(source_key)
                    if isinstance(structured_value, dict) and structured_value:
                        cleaned_log[target_key] = {
                            key: value for key, value in structured_value.items()
                            if value not in (None, "", [], {})
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

                mitre_context = self._merge_mitre_values(
                    root_data.get("rule", {}).get("mitre"),
                    data.get("mitre"),
                    alert.get("metadata", {}) if isinstance(alert, dict) else {},
                )
                if mitre_context.get("id") or mitre_context.get("technique") or mitre_context.get("invalid_ids"):
                    mitre_context["provenance"] = [
                        source_name
                        for source_name, source_value in (
                            ("rule.mitre", root_data.get("rule", {}).get("mitre")),
                            ("data.mitre", data.get("mitre")),
                            ("data.alert.metadata", alert.get("metadata") if isinstance(alert, dict) else None),
                        )
                        if source_value not in (None, "", [], {})
                    ]
                    cleaned_log["mitre_context"] = mitre_context
                
                # File context (for file-related alerts)
                file_info = self._first_dict(data.get("files") or data.get("fileinfo"))
                if file_info:
                    cleaned_log["file_context"] = {
                        "filename": file_info.get("filename"),
                        "size": file_info.get("size"),
                        "stored": file_info.get("stored"),
                        "state": file_info.get("state"),
                        "gaps": file_info.get("gaps"),
                        "md5": file_info.get("md5"),
                        "sha1": file_info.get("sha1"),
                        "sha256": file_info.get("sha256")
                    }

                smb_data = data.get("smb", {}) or {}
                if smb_data:
                    cleaned_log["smb_context"] = {
                        "command": smb_data.get("command"),
                        "share": smb_data.get("share"),
                        "filename": smb_data.get("filename"),
                        "disposition": smb_data.get("disposition")
                    }

                modbus_data = data.get("modbus", {}) or {}
                if modbus_data:
                    cleaned_log["modbus_context"] = {
                        "function": modbus_data.get("function"),
                        "unit_id": modbus_data.get("unit_id"),
                        "address": modbus_data.get("address"),
                        "quantity": modbus_data.get("quantity")
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

            try:
                # Scan canonical values only. Provenance/dotted-key labels such as
                # "source.ip" are field names, not observed domains or indicators.
                artifact_payload = {
                    "rule": root_data.get("rule"),
                    "data": root_data.get("data"),
                    "full_log": root_data.get("full_log"),
                }
                raw_alert_text = json.dumps(artifact_payload, sort_keys=True, default=str)
                raw_artifacts = CTIArtifactExtractor.extract(raw_alert_text)
                if raw_artifacts:
                    cleaned_log["raw_alert_artifacts"] = raw_artifacts
            except Exception:
                pass
            
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
                
        return cleaned_logs

    def close(self) -> None:
        self.geoip_manager.close()
    
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
                 alert_analyzer: AlertAnalyzer, reports_dir: str = None):
        self.llm_client = llm_client
        self.rag_manager = rag_manager
        self.alert_analyzer = alert_analyzer
        self.reports_dir = Path(reports_dir) if reports_dir else None
        self.diagnostic_trace_enabled = str(os.getenv("REPORT_DIAGNOSTIC_TRACE", "false")).lower() in {
            "1", "true", "yes", "on"
        }
        configured_trace_dir = os.getenv("REPORT_DIAGNOSTIC_TRACE_DIR", "").strip()
        self.diagnostic_trace_dir = (
            Path(configured_trace_dir).expanduser()
            if configured_trace_dir else (self.reports_dir / "diagnostic-traces" if self.reports_dir else None)
        )
        self._active_trace: Optional[Dict[str, Any]] = None
        self._last_trace_path: Optional[Path] = None

    @staticmethod
    def _trace_safe(value: Any) -> Any:
        """Keep evidence and outputs, never hidden reasoning or model internals."""
        if isinstance(value, str):
            return ReportFormatter._strip_reasoning_text(value)
        if isinstance(value, dict):
            return {str(key): ReportFormatter._trace_safe(item) for key, item in value.items()}
        if isinstance(value, (list, tuple)):
            return [ReportFormatter._trace_safe(item) for item in value]
        return value

    def _start_diagnostic_trace(self, **initial: Any) -> None:
        if not self.diagnostic_trace_enabled or not self.diagnostic_trace_dir:
            self._active_trace = None
            return
        self._active_trace = {
            "trace_version": 1,
            "created_at": datetime.now().isoformat(),
            "corpus_id": self.rag_manager.active_corpus_id,
            **self._trace_safe(initial),
        }

    def _record_diagnostic_trace(self, stage: str, value: Any) -> None:
        if getattr(self, "_active_trace", None) is not None:
            self._active_trace[stage] = self._trace_safe(value)

    def _flush_diagnostic_trace(self) -> Optional[str]:
        if self._active_trace is None or not self.diagnostic_trace_dir:
            return None
        try:
            self.diagnostic_trace_dir.mkdir(parents=True, exist_ok=True, mode=0o750)
            os.chmod(self.diagnostic_trace_dir, 0o750)
            path = self.diagnostic_trace_dir / (
                f"report-trace-{datetime.now().strftime('%Y%m%d-%H%M%S-%f')}-{uuid4().hex[:8]}.json"
            )
            atomic_write_text(path, json.dumps(self._active_trace, indent=2, ensure_ascii=False, default=str))
            self._last_trace_path = path
            return str(path)
        except Exception as exc:
            log_sanitized_exception("Diagnostic trace write failed", exc)
            return None
        finally:
            self._active_trace = None

    def record_last_trace_stage(self, stage: str, value: Any) -> None:
        """Append parser/editor lifecycle evidence to the latest opt-in trace."""
        path = self._last_trace_path
        if not self.diagnostic_trace_enabled or not path or not path.is_file():
            return
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            payload[str(stage)] = self._trace_safe(value)
            atomic_write_text(path, json.dumps(payload, indent=2, ensure_ascii=False, default=str))
        except Exception as exc:
            log_sanitized_exception("Diagnostic trace append failed", exc)

    @staticmethod
    def _document_identity(doc: Any) -> str:
        if not isinstance(doc, dict):
            return "inline"
        metadata = doc.get("metadata") or {}
        return str(
            metadata.get("raw_document_hash")
            or metadata.get("content_hash")
            or metadata.get("source_identity")
            or metadata.get("filename")
            or doc.get("id")
            or "unknown"
        )

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

        def add_tokens(value: Any):
            for token in re.findall(r"[A-Za-z0-9_.:/-]{4,}", str(value or "")):
                if self.rag_manager._is_high_signal_search_value(token):
                    terms.add(token.lower())

        for alert in self._select_representative_alerts(alerts, max_alerts=max_alerts):
            for field in ("rule_description", "alert_signature", "alert_category", "rule_id",
                          "signature_id", "src_ip", "dest_ip", "proto", "app_proto", "event_type",
                          "direction", "priority_reason", "directional_focus",
                          "retrieval_fingerprint"):
                value = alert.get(field)
                if value:
                    add_tokens(value)
            for context_key, fields in (
                ("http_context", ("hostname", "url", "method")),
                ("dns_context", ("query_name",)),
                ("tls_context", ("sni", "issuer", "subject")),
                ("email_context", ("from", "to", "subject", "attachment", "mail_from_domain", "url")),
                ("ioc_context", ("domain", "ip", "url", "hash")),
                ("process_context", ("name", "parent_process", "file", "path", "command_line")),
                ("file_context", ("filename", "md5", "sha1", "sha256")),
                ("smb_context", ("command", "share", "filename", "disposition")),
                ("modbus_context", ("function", "unit_id", "address", "quantity")),
                ("threat_context", ("actor", "campaign", "malware", "malware_family", "tool")),
            ):
                context = alert.get(context_key) or {}
                if isinstance(context, dict):
                    for field in fields:
                        value = context.get(field)
                        if value:
                            add_tokens(value)
            for field in ("behavior_tags", "response_focus"):
                values = alert.get(field) or []
                for value in values if isinstance(values, list) else [values]:
                    if value:
                        add_tokens(value)
            observed_iocs = alert.get("observed_iocs") or {}
            if isinstance(observed_iocs, dict):
                for values in observed_iocs.values():
                    for value in values if isinstance(values, list) else [values]:
                        if value:
                            add_tokens(value)
        return terms

    def _build_exact_terms_from_alerts(self, alerts: List[Dict]) -> Dict[str, List[str]]:
        exact_terms = {
            "rule_ids": [],
            "signature_ids": [],
            "source_ips": [],
            "destination_ips": [],
            "ips": [],
            "cti_ips": [],
            "domains": [],
            "urls": [],
            "hashes": [],
            "cves": [],
            "mitre_techniques": [],
            "alert_signatures": [],
            "threat_actors": [],
            "threat_actor_aliases": [],
            "malware_families": [],
            "campaigns": [],
            "tools": [],
            "courses_of_action": [],
            "keywords": [],
        }

        def add(key: str, value: Any):
            if value in (None, "", [], {}):
                return
            if isinstance(value, (list, tuple, set)):
                for item in value:
                    add(key, item)
                return
            if key not in exact_terms:
                exact_terms[key] = []
            text = str(value).strip()
            if self._is_low_signal_cti_exact_value(key, text):
                return
            if text and text not in exact_terms[key]:
                exact_terms[key].append(text)

        for alert in self._select_representative_alerts(alerts, max_alerts=12):
            add("rule_ids", alert.get("rule_id"))
            add("signature_ids", alert.get("signature_id"))
            add("source_ips", alert.get("src_ip"))
            add("destination_ips", alert.get("dest_ip"))
            add("ips", alert.get("src_ip"))
            add("ips", alert.get("dest_ip"))
            for ip_value in self._attacker_relevant_cti_ips(alert):
                add("cti_ips", ip_value)
            add("alert_signatures", alert.get("alert_signature"))
            for text_value in (alert.get("rule_description"), alert.get("alert_signature")):
                extracted = CTIArtifactExtractor.extract(str(text_value or ""))
                for value in extracted.get("cves", []):
                    add("cves", value)
                for value in extracted.get("mitre_techniques", []):
                    add("mitre_techniques", value)
            raw_alert_artifacts = alert.get("raw_alert_artifacts") or {}
            if isinstance(raw_alert_artifacts, dict):
                add("cves", raw_alert_artifacts.get("cves"))
                add("mitre_techniques", AlertAnalyzer._merge_mitre_values(
                    raw_alert_artifacts.get("mitre_techniques")
                ).get("id", []))
                add("threat_actors", raw_alert_artifacts.get("threat_actors"))
                add("threat_actor_aliases", raw_alert_artifacts.get("threat_actor_aliases"))
                add("malware_families", raw_alert_artifacts.get("malware_families"))
                add("campaigns", raw_alert_artifacts.get("campaigns"))
                add("tools", raw_alert_artifacts.get("tools"))
                add("courses_of_action", raw_alert_artifacts.get("courses_of_action"))

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
                add("keywords", tls_context.get("ja3"))
                add("keywords", tls_context.get("ja3s"))

            email_context = alert.get("email_context") or {}
            if isinstance(email_context, dict):
                add("domains", email_context.get("mail_from_domain"))
                add("urls", email_context.get("url"))
                for field in ("from", "to", "subject", "attachment"):
                    add("keywords", email_context.get(field))

            ioc_context = alert.get("ioc_context") or {}
            if isinstance(ioc_context, dict):
                add("domains", ioc_context.get("domain"))
                add("ips", ioc_context.get("ip"))
                add("urls", ioc_context.get("url"))
                add("hashes", ioc_context.get("hash"))
                add("keywords", ioc_context.get("hash"))

            process_context = alert.get("process_context") or {}
            if isinstance(process_context, dict):
                for field in ("name", "parent_process", "file", "path", "command_line"):
                    add("keywords", process_context.get(field))

            file_context = alert.get("file_context") or {}
            if isinstance(file_context, dict):
                for field in ("md5", "sha1", "sha256"):
                    add("hashes", file_context.get(field))
                    add("keywords", file_context.get(field))
                for field in ("filename", "state", "stored"):
                    add("keywords", file_context.get(field))

            smb_context = alert.get("smb_context") or {}
            if isinstance(smb_context, dict):
                for field in ("command", "share", "filename", "disposition"):
                    add("keywords", smb_context.get(field))

            modbus_context = alert.get("modbus_context") or {}
            if isinstance(modbus_context, dict):
                for field in ("function", "unit_id", "address", "quantity"):
                    add("keywords", modbus_context.get(field))

            threat_context = alert.get("threat_context") or {}
            if isinstance(threat_context, dict):
                add("keywords", threat_context.get("actor"))
                add("keywords", threat_context.get("campaign"))
                add("keywords", threat_context.get("malware"))
                add("keywords", threat_context.get("malware_family"))
                add("keywords", threat_context.get("tool"))
                add("threat_actors", threat_context.get("actor"))
                add("campaigns", threat_context.get("campaign"))
                add("malware_families", threat_context.get("malware"))
                add("malware_families", threat_context.get("malware_family"))
                add("tools", threat_context.get("tool"))

            mitre_context = alert.get("mitre_context") or {}
            if isinstance(mitre_context, dict):
                extracted = CTIArtifactExtractor.extract(json.dumps(mitre_context, sort_keys=True, default=str))
                for value in extracted.get("cves", []):
                    add("cves", value)
                for value in extracted.get("mitre_techniques", []):
                    add("mitre_techniques", value)

            observed_iocs = alert.get("observed_iocs") or {}
            if isinstance(observed_iocs, dict):
                for value in observed_iocs.get("ips", []):
                    add("ips", value)
                for value in observed_iocs.get("domains", []):
                    add("domains", value)
                for value in observed_iocs.get("urls", []):
                    add("urls", value)
                for value in observed_iocs.get("emails", []):
                    add("keywords", value)
                for value in observed_iocs.get("hashes", []):
                    add("hashes", value)
                    add("keywords", value)
                for value in observed_iocs.get("cves", []):
                    add("cves", value)
                for value in observed_iocs.get("mitre_techniques", []):
                    add("mitre_techniques", value)
                for value in observed_iocs.get("threat_actors", []):
                    add("threat_actors", value)
                for value in observed_iocs.get("threat_actor_aliases", []):
                    add("threat_actor_aliases", value)
                for value in observed_iocs.get("malware_families", []):
                    add("malware_families", value)
                for value in observed_iocs.get("campaigns", []):
                    add("campaigns", value)
                for value in observed_iocs.get("tools", []):
                    add("tools", value)
                for value in observed_iocs.get("courses_of_action", []):
                    add("courses_of_action", value)
                for value in observed_iocs.get("processes", []):
                    add("keywords", value)
                for value in observed_iocs.get("files", []):
                    add("keywords", value)
                for value in observed_iocs.get("keywords", []):
                    add("keywords", value)
                for value in observed_iocs.get("rule_ids", []):
                    add("rule_ids", value)
                for value in observed_iocs.get("signature_ids", []):
                    add("signature_ids", value)

        return {key: values for key, values in exact_terms.items() if values}

    @staticmethod
    def _attacker_relevant_cti_ips(alert: Dict[str, Any]) -> List[str]:
        """Return IPs suitable for uploaded CTI matching.

        Archive retrieval can use all endpoints. Uploaded CTI documents should
        not be pulled just because they mention a protected/victim public IP.
        """
        if not isinstance(alert, dict):
            return []

        selected: List[str] = []

        def add(value: Any):
            text = str(value or "").strip()
            if (
                text
                and text not in CTIArtifactExtractor.LOW_SIGNAL_CTI_IPS
                and CTIArtifactExtractor.is_public_ip(text)
                and text not in selected
            ):
                selected.append(text)

        ioc_context = alert.get("ioc_context") or {}
        if isinstance(ioc_context, dict):
            role = str(ioc_context.get("role") or ioc_context.get("ip_role") or "").strip().lower()
            disposition = str(ioc_context.get("disposition") or "").strip().lower()
            if role not in {"victim", "local_asset", "source_asset", "benign", "reference", "example"} and disposition not in {
                "victim", "benign", "analysis_environment", "remediation_reference", "private", "reserved", "documentation"
            }:
                add(ioc_context.get("ip"))

        direction = str(
            (alert.get("threat_classification") or {}).get("threat_direction")
            or alert.get("direction")
            or ""
        ).lower()
        src_context = str(alert.get("src_ip_context") or "").lower()
        dest_context = str(alert.get("dest_ip_context") or "").lower()
        src_ip = alert.get("src_ip")
        dest_ip = alert.get("dest_ip")
        protected_contexts = {"internal", "owned", "infrastructure"}

        if direction == "inbound" or (src_context == "external" and dest_context in protected_contexts):
            add(src_ip)
        elif direction == "outbound" or (src_context in protected_contexts and dest_context == "external"):
            add(dest_ip)
        elif direction == "external" or (src_context == "external" and dest_context == "external"):
            add(src_ip)
        elif not direction:
            if src_context == "external":
                add(src_ip)
            if dest_context == "external":
                add(dest_ip)

        return selected

    @staticmethod
    def _is_low_signal_cti_exact_value(key: str, value: str) -> bool:
        if not value:
            return False

        lowered = str(value).strip().lower()
        if key in {"ips", "cti_ips"}:
            return lowered in CTIArtifactExtractor.LOW_SIGNAL_CTI_IPS
        if key == "domains":
            return lowered.strip(".") in CTIArtifactExtractor.LOW_SIGNAL_CTIDOMAINS
        if key == "urls":
            try:
                parsed = urlparse(lowered)
                hostname = (parsed.hostname or "").lower()
            except ValueError:
                parsed = None
                hostname = ""
            if not hostname:
                path_only = lowered.split("?", 1)[0].split("#", 1)[0].strip()
                if path_only in {"", "/"} or len(path_only) < 5:
                    return True
            return bool(hostname and hostname in CTIArtifactExtractor.LOW_SIGNAL_CTIDOMAINS)
        if key == "keywords":
            normalized = lowered.strip("\"'")
            if re.fullmatch(r"\d+(?:\.\d+){1,3}", normalized):
                return True
            basename = re.split(r"[\\/]+", normalized)[-1]
            common_processes = {
                "powershell.exe", "powershell", "pwsh.exe", "cmd.exe", "rundll32.exe",
                "regsvr32.exe", "wscript.exe", "cscript.exe", "mshta.exe", "svchost.exe",
                "explorer.exe", "winword.exe", "excel.exe", "acrord32.exe", "osql.exe",
            }
            if normalized in common_processes or basename in common_processes:
                return True
            if normalized in {"executionpolicy", "windowstyle", "hidden", "bypass", "startw"}:
                return True
            filename_suffix = Path(basename).suffix
            filename_tokens = set(re.findall(r"[a-z]+", Path(basename).stem))
            generic_filename_tokens = {
                "attachment", "backdoor", "document", "dropper", "exploit", "file",
                "invoice", "malware", "payload", "report", "sample", "suspicious",
                "trojan", "unknown", "update",
            }
            if (
                filename_suffix
                and filename_tokens
                and filename_tokens.issubset(generic_filename_tokens)
            ):
                return True
        return False

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
                "email": alert.get("email_context"),
                "ioc": alert.get("ioc_context"),
                "process": alert.get("process_context"),
                "file": alert.get("file_context"),
                "smb": alert.get("smb_context"),
                "modbus": alert.get("modbus_context"),
                "ics": alert.get("ics_context"),
                "windows": alert.get("windows_context"),
                "network": alert.get("network_context"),
                "vulnerability": alert.get("vulnerability_context"),
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
            "cves": [],
            "rule_ids": [],
            "signature_ids": [],
            "alert_signatures": [],
            "mitre_techniques": [],
            "threat_actors": [],
            "threat_actor_aliases": [],
            "malware_families": [],
            "campaigns": [],
            "tools": [],
            "courses_of_action": [],
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
            for text_value in (alert.get("rule_description"), alert.get("alert_signature")):
                extracted = CTIArtifactExtractor.extract(str(text_value or ""))
                add("cves", extracted.get("cves"))
                add("mitre_techniques", extracted.get("mitre_techniques"))
            raw_alert_artifacts = alert.get("raw_alert_artifacts") or {}
            if isinstance(raw_alert_artifacts, dict):
                add("cves", raw_alert_artifacts.get("cves"))
                add("mitre_techniques", AlertAnalyzer._merge_mitre_values(
                    raw_alert_artifacts.get("mitre_techniques")
                ).get("id", []))
                add("threat_actors", raw_alert_artifacts.get("threat_actors"))
                add("threat_actor_aliases", raw_alert_artifacts.get("threat_actor_aliases"))
                add("malware_families", raw_alert_artifacts.get("malware_families"))
                add("campaigns", raw_alert_artifacts.get("campaigns"))
                add("tools", raw_alert_artifacts.get("tools"))
                add("courses_of_action", raw_alert_artifacts.get("courses_of_action"))

            for context_key, mappings in (
                ("http_context", {"hostname": "domains", "url": "urls"}),
                ("dns_context", {"query_name": "domains"}),
                ("tls_context", {"sni": "domains"}),
                ("email_context", {"mail_from_domain": "domains", "url": "urls"}),
                ("ioc_context", {"domain": "domains", "ip": "ips", "url": "urls", "hash": "hashes"}),
            ):
                context = alert.get(context_key) or {}
                if isinstance(context, dict):
                    for field, target_key in mappings.items():
                        add(target_key, context.get(field))

            file_context = alert.get("file_context") or {}
            if isinstance(file_context, dict):
                for key in ("md5", "sha1", "sha256"):
                    add("hashes", file_context.get(key))

            mitre_context = alert.get("mitre_context") or {}
            if isinstance(mitre_context, dict):
                add("mitre_techniques", mitre_context.get("id"))

            threat_context = alert.get("threat_context") or {}
            if isinstance(threat_context, dict):
                add("threat_actors", threat_context.get("actor"))
                add("campaigns", threat_context.get("campaign"))
                add("malware_families", threat_context.get("malware"))
                add("malware_families", threat_context.get("malware_family"))
                add("tools", threat_context.get("tool"))

            observed_iocs = alert.get("observed_iocs") or {}
            if isinstance(observed_iocs, dict):
                for key in (
                    "ips", "domains", "urls", "hashes", "cves", "mitre_techniques",
                    "threat_actors", "threat_actor_aliases", "malware_families", "campaigns", "tools",
                    "courses_of_action", "rule_ids", "signature_ids",
                ):
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
            refanged_text = RAGContextManager._refang_text(text)
            if refanged_text != text:
                refanged_artifacts = CTIArtifactExtractor.extract(refanged_text)
                for key, values in refanged_artifacts.items():
                    combined = list(artifacts.get(key, []))
                    combined.extend(values)
                    artifacts[key] = self._limited_values(combined, max_items=50)
        else:
            artifacts = {
                key: self._limited_values(list(value) if isinstance(value, list) else [value], max_items=50)
                for key, value in artifacts.items()
                if value not in (None, "", [], {})
            }

        source_artifacts = metadata.get("source_cti_artifacts")
        if isinstance(source_artifacts, dict):
            for key, value in source_artifacts.items():
                if value in (None, "", [], {}):
                    continue
                combined = list(artifacts.get(key, []))
                combined.extend(value if isinstance(value, list) else [value])
                artifacts[key] = self._limited_values(combined, max_items=50)

        metadata_values = {
            "ips": [metadata.get("src_ip"), metadata.get("dest_ip"), metadata.get("agent_ip"), metadata.get("ioc_ip")],
            "domains": [metadata.get("http_hostname"), metadata.get("dns_query"), metadata.get("tls_sni"), metadata.get("email_mail_from_domain"), metadata.get("ioc_domain")],
            "urls": [metadata.get("http_url"), metadata.get("email_url"), metadata.get("ioc_url")],
            "hashes": [metadata.get("ioc_hash"), metadata.get("file_md5"), metadata.get("file_sha1"), metadata.get("file_sha256")],
            "rule_ids": [metadata.get("rule_id")],
            "signature_ids": [metadata.get("signature_id")],
            "alert_signatures": [metadata.get("alert_signature")],
            "mitre_techniques": [metadata.get("mitre_ids"), metadata.get("mitre_techniques")],
            "threat_actors": [metadata.get("threat_actor")],
            "campaigns": [metadata.get("threat_campaign")],
            "malware_families": [metadata.get("malware_family"), metadata.get("malware")],
            "tools": [metadata.get("tool")],
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
            candidate_values = {
                RAGContextManager._refang_text(value).lower()
                for value in candidate.get(key, [])
                if value
            }
            matches = [
                str(value)
                for value in values
                if RAGContextManager._refang_text(value).lower() in candidate_values
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
            normalized_dispositions = {
                RAGContextManager._refang_text(candidate).lower(): disposition
                for candidate, disposition in typed_dispositions.items()
            }
            for value in values:
                key = RAGContextManager._refang_text(value).lower()
                if str(normalized_dispositions.get(key) or "").lower() in desired:
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
            strong_overlap = any(overlap.get(key) for key in ("ips", "domains", "urls", "hashes"))
            substantive_overlap = any(
                overlap.get(key) for key in (
                    "ips", "domains", "urls", "hashes", "cves", "threat_actors",
                    "threat_actor_aliases", "malware_families", "campaigns", "tools",
                    "courses_of_action",
                )
            )
            weak_overlap = bool(overlap_count and not substantive_overlap)
            exact_evidence = " ".join(str(item).lower() for item in doc.get("match_evidence") or [])
            linked_exact_evidence = " ".join(
                str(item).lower() for item in doc.get("linked_exact_match_evidence") or []
            )
            decisive_exact_labels = (
                "hash matched", "domain matched", "url matched", "ip matched",
                "cve matched", "rule_id matched", "signature_id matched",
                "signature matched", "threat actor matched", "malware family matched",
                "campaign matched", "tool matched", "course of action matched",
                "indicator matched",
            )
            decisive_exact = any(label in exact_evidence for label in decisive_exact_labels)
            decisive_linked_exact = any(label in linked_exact_evidence for label in decisive_exact_labels)

            if "exact" in match_types and strong_overlap and not non_attacker_overlap:
                evidence_strength = "high"
            elif malicious_overlap and overlap_count > 0:
                evidence_strength = "high"
            elif "source_context" in match_types and decisive_linked_exact:
                evidence_strength = "medium"
            elif "exact" in match_types and (decisive_exact or substantive_overlap):
                evidence_strength = "medium"
            elif "lexical" in match_types and substantive_overlap:
                evidence_strength = "medium"
            else:
                evidence_strength = "low"

            notes = []
            if doc.get("source") == "custom_document":
                notes.append("uploaded CTI is historical/contextual unless current alert has exact overlap")
            if "source_context" in match_types:
                notes.append("same uploaded CTI document as an exact IoC match; use for campaign background, not direct observation")
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
            if weak_overlap:
                notes.append("current overlap is technique/signature/context only; do not use alone for attribution")
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
            for key in (
                "ips", "domains", "urls", "hashes", "cves", "mitre_techniques",
                "threat_actors", "threat_actor_aliases", "malware_families",
                "campaigns", "tools", "courses_of_action",
            ):
                current_values = {
                    RAGContextManager._refang_text(value).lower()
                    for value in current_artifacts.get(key, [])
                }
                extras = [
                    value for value in doc_artifacts.get(key, [])
                    if RAGContextManager._refang_text(value).lower() not in current_values
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
            # Weak-only semantic context is useful for background, but allowing a
            # full prompt of low-strength sources is a common path to irrelevant
            # attribution and remediation.
            weak_cap = min(2, remaining)
        selected.extend(weak[:weak_cap])
        return selected[:limit]

    @staticmethod
    def _context_source_document_key(doc: Any) -> Optional[tuple]:
        if not isinstance(doc, dict):
            return None
        metadata = doc.get("metadata") or {}
        source = doc.get("source") or "unknown"
        if source == "custom_document":
            document_id = (
                metadata.get("raw_document_hash")
                or metadata.get("source_document")
                or metadata.get("original_filename")
            )
            return (source, document_id) if document_id else None
        if source == "archive":
            alert_id = metadata.get("raw_alert_hash")
            return (source, alert_id) if alert_id else None
        return None

    def _apply_context_source_document_diversity(self, docs: List[Any], limit: int) -> List[Any]:
        """Prefer distinct CTI articles over repeated chunks from one article."""
        if not docs or limit <= 0:
            return []

        selected: List[Any] = []
        deferred: List[Any] = []
        seen_documents = set()
        seen_keys = set()

        for doc in docs:
            key = self._context_doc_key(doc)
            if key in seen_keys:
                continue
            document_key = self._context_source_document_key(doc)
            if document_key and document_key in seen_documents:
                deferred.append(doc)
                continue
            selected.append(doc)
            seen_keys.add(key)
            if document_key:
                seen_documents.add(document_key)
            if len(selected) >= limit:
                return selected[:limit]

        # Rank and format canonical documents, not a top-k list crowded by
        # repeated chunks from one verbose article. Supporting chunks remain
        # reachable through exact/source-context metadata on the representative.
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
            exact_signal = (
                self.rag_manager._score_exact_candidate(doc.get("match_evidence") or [], doc.get("source"))
                if isinstance(doc, dict) and "exact" in match_types
                else 0.0
            )
            exact_boost = (
                max(0.8, min(2.25, exact_signal * 1.45))
                if "exact" in match_types
                else 0.0
            )
            source_context_boost = 1.15 if "source_context" in match_types else 0.0
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
                + severity_boost + source_boost + source_context_boost
                + behavior_boost + behavior_penalty
            )

            if isinstance(doc, dict):
                doc["context_rank_score"] = round(rank_score, 3)

            ranked.append((rank_score, lexical_hits, similarity, -order, doc))

        ranked.sort(reverse=True, key=lambda item: item[:4])
        diverse_docs = self._apply_context_source_document_diversity(
            [item[4] for item in ranked],
            limit,
        )
        annotated = self._annotate_context_docs(diverse_docs, current_alerts)
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
        exact_terms = self._build_exact_terms_from_alerts(alerts)
        query_seed_parts = []
        for key in (
            "rule_ids", "signature_ids", "source_ips", "destination_ips", "cti_ips", "ips",
            "domains", "urls", "hashes", "cves", "mitre_techniques",
            "alert_signatures", "threat_actors", "threat_actor_aliases", "malware_families",
            "campaigns", "tools", "courses_of_action",
        ):
            query_seed_parts.extend(str(value) for value in exact_terms.get(key, [])[:8])
        entity_phrase_values = []
        for key in ("threat_actors", "threat_actor_aliases", "malware_families", "campaigns", "tools", "courses_of_action"):
            for value in exact_terms.get(key, [])[:8]:
                phrase = re.sub(r"\s+", " ", str(value or "")).strip()
                if len(phrase) >= 3 and phrase.lower() not in {item.lower() for item in entity_phrase_values}:
                    entity_phrase_values.append(phrase)
        query_seed_parts.extend(
            str(value)
            for value in exact_terms.get("keywords", [])
            if self.rag_manager._is_high_signal_search_value(value)
        )
        query_seed_parts.extend(self._current_behavior_tags(alerts)[:8])
        queries = [" ".join(query_seed_parts).strip()]

        for alert in self._select_representative_alerts(alerts, max_alerts=max(1, max_queries - 1)):
            parts = []
            for field in ("rule_id", "signature_id", "src_ip", "dest_ip",
                          "alert_signature", "alert_category", "rule_description"):
                if alert.get(field):
                    parts.append(str(alert.get(field)))

            for field in ("behavior_tags", "response_focus"):
                values = alert.get(field) or []
                if isinstance(values, list):
                    parts.extend(str(value) for value in values if value not in (None, "", [], {}))
                elif values not in (None, "", [], {}):
                    parts.append(str(values))

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
            high_signal_tokens = [
                token for token in re.findall(r"[A-Za-z0-9_.:/@\\-]{4,}", normalized)
                if self.rag_manager._is_high_signal_search_value(token)
            ]
            high_signal_phrases = [
                phrase for phrase in entity_phrase_values
                if phrase.lower() in normalized.lower()
            ]
            if not high_signal_tokens and not high_signal_phrases:
                continue
            normalized = " ".join(high_signal_phrases + high_signal_tokens[:40])
            key = normalized.lower()
            if key in seen:
                continue
            seen.add(key)
            unique_queries.append(normalized)
            if len(unique_queries) >= max_queries:
                break
        return unique_queries or [" ".join(self._current_behavior_tags(alerts)[:6]) or "security incident analysis"]

    def _retrieve_context_for_alerts(self, alerts: List[Dict], k: int = None,
                                     metadata_filter: dict = None,
                                     source_mode: str = "all") -> List[Dict[str, Any]]:
        with self.rag_manager.corpus_state_lock:
            return self._retrieve_context_for_alerts_locked(
                alerts,
                k=k,
                metadata_filter=metadata_filter,
                source_mode=source_mode,
            )

    def _retrieve_context_for_alerts_locked(self, alerts: List[Dict], k: int = None,
                                            metadata_filter: dict = None,
                                            source_mode: str = "all") -> List[Dict[str, Any]]:
        limit = k or min(getattr(self.rag_manager, "max_retrieval_docs", 8), 8)
        selected_corpus_id = self.rag_manager.active_corpus_id
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
                        doc_corpus_id = (
                            doc.get("corpus_id")
                            or (doc.get("metadata") or {}).get("corpus_id")
                        )
                        if doc_corpus_id and doc_corpus_id != selected_corpus_id:
                            continue
                        doc["retrieval_query"] = query[:240]
                        candidates.append(doc)
                    else:
                        candidates.append(doc)
            except Exception as e:
                self.rag_manager._rollback_safely()
                log_sanitized_exception("Focused RAG retrieval failed", e)
                raise RuntimeError("Focused RAG retrieval failed") from None

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

    @staticmethod
    def _strip_reasoning_text(content: str) -> str:
        text = str(content or "").strip()
        if not text:
            return ""
        text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL | re.IGNORECASE).strip()
        if re.match(r"^\s*<think\b", text, flags=re.IGNORECASE):
            heading = re.search(
                r"(?im)^(?:#{1,6}\s*)?(?:\*\*)?(?:executive summary|key findings|top .*threat|mitre|immediate actions?)",
                text,
            )
            return text[heading.start():].strip() if heading else ""
        return re.sub(r"</?think>", "", text, flags=re.IGNORECASE).strip()

    @staticmethod
    def _has_heading(content: str, heading: str) -> bool:
        pattern = rf"(?im)^\s*(?:#{{1,6}}\s*)?(?:\*\*)?{re.escape(heading)}s?(?:\*\*)?\s*:?"
        return bool(re.search(pattern, str(content or "")))

    def _validate_generated_report(self, content: str) -> List[str]:
        """Return blocking quality issues that make a generated report unusable."""
        text = self._strip_reasoning_text(content)
        issues = []
        if not text.strip():
            return ["empty model output"]
        if text.lower().startswith("error:"):
            issues.append("model invocation returned an error")
        if len(re.sub(r"\s+", " ", text).strip()) < 350:
            issues.append("report is too short to be a complete CTI assessment")
        if not self._has_heading(text, "Executive Summary"):
            issues.append("missing Executive Summary")
        if not self._has_heading(text, "Key Finding"):
            issues.append("missing Key Findings")
        finding_match = re.search(
            r"(?is)(?:executive summary.*?\n)?(?:#{1,6}\s*)?(?:\*\*)?key findings?(?:\*\*)?\s*:?\s*(.*?)(?=\n\s*(?:#{1,6}\s*|\*\*?(?:top|mitre|immediate|technical)|---|\Z))",
            text,
        )
        finding_text = finding_match.group(1) if finding_match else ""
        finding_count = len(re.findall(r"(?m)^\s*(?:[-*]|\d+\.)\s+\S", finding_text))
        if finding_count == 0:
            issues.append("Key Findings contains no bullet or numbered findings")
        if not (
            self._has_heading(text, "Immediate Action")
            or self._has_heading(text, "Recommendation")
            or self._has_heading(text, "Priority Action")
        ):
            issues.append("missing recommendations or immediate actions")
        return issues

    @staticmethod
    def _severity_label(level: Any) -> str:
        try:
            numeric = int(level or 0)
        except (TypeError, ValueError):
            numeric = 0
        if numeric >= 12:
            return "CRITICAL"
        if numeric >= 8:
            return "HIGH"
        if numeric >= 5:
            return "MEDIUM"
        return "LOW"

    def _overall_threat_level(self, alerts: List[Dict]) -> str:
        max_level = max((self._alert_level(alert) for alert in alerts or []), default=0)
        if any((alert.get("threat_classification") or {}).get("threat_direction") == "outbound" for alert in alerts or []):
            max_level = max(max_level, 8)
        if any((alert.get("threat_classification") or {}).get("threat_direction") == "lateral" for alert in alerts or []):
            max_level = max(max_level, 10)
        return self._severity_label(max_level)

    def _alert_activity_text(self, alert: Dict[str, Any]) -> str:
        parts = [
            alert.get("alert_signature"),
            alert.get("rule_description"),
            alert.get("app_proto") or alert.get("proto"),
        ]
        dest_port = alert.get("dest_port")
        if dest_port:
            parts.append(f"port {dest_port}")
        text = " / ".join(str(part) for part in parts if part not in (None, "", [], {}))
        text = re.sub(r"\s+", " ", text).strip()
        return text[:120] if text else "Suspicious activity"

    def _top_priority_threat_rows(self, alerts: List[Dict], max_rows: int = 5) -> List[Dict[str, Any]]:
        grouped: Dict[tuple, Dict[str, Any]] = {}
        for alert in alerts or []:
            classification = alert.get("threat_classification") or {}
            if classification.get("is_infrastructure_alert"):
                continue
            direction = classification.get("threat_direction") or "unknown"
            if direction == "outbound":
                indicator = alert.get("dest_ip") or alert.get("dest_ip_context") or "external destination"
                entity_type = "Destination"
            elif direction == "lateral":
                indicator = alert.get("dest_ip") or alert.get("src_ip") or "internal peer"
                entity_type = "Internal"
            else:
                indicator = alert.get("src_ip") or alert.get("dest_ip") or "unknown"
                entity_type = "Source"

            key = (str(indicator), direction)
            row = grouped.setdefault(
                key,
                {
                    "indicator": indicator,
                    "type": entity_type,
                    "direction": direction,
                    "activity": self._alert_activity_text(alert),
                    "severity": self._severity_label(alert.get("rule_level")),
                    "count": 0,
                    "max_level": 0,
                },
            )
            row["count"] += 1
            row["max_level"] = max(row["max_level"], self._alert_level(alert))
            row["severity"] = self._severity_label(row["max_level"])
            if len(row["activity"]) < 20:
                row["activity"] = self._alert_activity_text(alert)

        rows = sorted(grouped.values(), key=lambda item: (item["max_level"], item["count"]), reverse=True)
        return rows[:max_rows]

    @staticmethod
    def _behavior_mitre_mappings() -> Dict[str, tuple[str, str, str, str]]:
        return {
            "reconnaissance_or_scanning": ("Reconnaissance", "T1595", "Active Scanning", "Scanning or probing behavior in alert telemetry"),
            "credential_attack": ("Credential Access", "T1110", "Brute Force", "Authentication or credential attack indicators"),
            "phishing_or_email_delivery": ("Initial Access", "T1566", "Phishing", "Suspicious email delivery or attachment indicators"),
            "possible_c2": ("Command and Control", "T1071", "Application Layer Protocol", "Potential callback or command-and-control communication"),
            "possible_exfiltration": ("Exfiltration", "T1041", "Exfiltration Over C2 Channel", "Possible data transfer from a protected asset"),
            "lateral_movement_candidate": ("Lateral Movement", "T1021", "Remote Services", "Internal remote-service or SMB movement candidate"),
            "web_or_exploit_attempt": ("Initial Access", "T1190", "Exploit Public-Facing Application", "Web or exploit attempt against exposed service"),
            "ingress_tool_transfer": ("Command and Control", "T1105", "Ingress Tool Transfer", "Payload/tool transfer or download observed"),
            "script_execution_candidate": ("Execution", "T1059", "Command and Scripting Interpreter", "Command or script interpreter observed"),
            "signed_binary_proxy_execution": ("Defense Evasion", "T1218", "System Binary Proxy Execution", "Signed system binary used to execute another payload"),
            "inhibit_system_recovery": ("Impact", "T1490", "Inhibit System Recovery", "Shadow-copy deletion or recovery inhibition observed"),
        }

    def _mitre_evidence_categories(self, alerts: List[Dict], context_docs: List[Any]) -> Dict[str, List[str]]:
        """Keep explicit, inferred-current, and historical-only ATT&CK IDs separate."""
        catalog = self._load_mitre_catalog()

        def valid(values: Iterable[Any]) -> List[str]:
            selected = []
            for value in values or []:
                for technique_id in re.findall(r"\bT\d{4}(?:\.\d{3})?\b", str(value), re.IGNORECASE):
                    normalized = technique_id.upper()
                    if catalog and normalized.lower() not in catalog:
                        continue
                    if normalized not in selected:
                        selected.append(normalized)
            return selected

        explicit = []
        for alert in alerts or []:
            mitre_context = alert.get("mitre_context") or {}
            if isinstance(mitre_context, dict):
                explicit.extend(valid(mitre_context.get("id") or []))
        explicit = list(dict.fromkeys(explicit))

        mappings = self._behavior_mitre_mappings()
        inferred = []
        for behavior_tag in self._current_behavior_tags(alerts):
            mapping = mappings.get(behavior_tag)
            if not mapping:
                continue
            technique_id = mapping[1]
            if technique_id not in explicit and technique_id not in inferred:
                inferred.append(technique_id)

        historical = []
        for doc in context_docs or []:
            if not isinstance(doc, dict):
                continue
            artifacts = self._doc_artifacts_for_audit(doc)
            for technique_id in valid(artifacts.get("mitre_techniques") or []):
                if technique_id not in explicit and technique_id not in inferred and technique_id not in historical:
                    historical.append(technique_id)
        return {
            "explicit_current": explicit,
            "inferred_current": inferred,
            "historical_only": historical,
        }

    def _format_mitre_evidence_for_prompt(self, alerts: List[Dict], context_docs: List[Any]) -> str:
        categories = self._mitre_evidence_categories(alerts, context_docs)
        return json.dumps({
            "explicit_current_alert_metadata": categories["explicit_current"],
            "inferred_from_current_behavior": categories["inferred_current"],
            "historical_cti_context_only_not_observed": categories["historical_only"],
        }, indent=1)

    def _expand_selected_document_evidence(
        self,
        context_docs: List[Any],
        alerts: List[Dict],
        limit: int = 4,
    ) -> List[Dict[str, Any]]:
        """Read complementary passages from the top selected canonical source."""
        top_document = next(
            (
                doc for doc in context_docs or []
                if isinstance(doc, dict) and doc.get("source") == "custom_document"
            ),
            None,
        )
        if not top_document:
            return []
        exact_terms = self._build_exact_terms_from_alerts(alerts)
        preferred_terms = []
        for values in exact_terms.values():
            preferred_terms.extend(values or [])
        preferred_terms.extend(self._current_behavior_tags(alerts))
        return self.rag_manager.get_selected_document_passages(
            top_document,
            preferred_terms=preferred_terms,
            limit=limit,
        )

    def _build_incident_synthesis(
        self,
        alerts: List[Dict],
        context_docs: List[Any],
        expanded_passages: List[Any],
    ) -> Dict[str, Any]:
        """Create a source-aware incident object before report prose is drafted."""
        alerts = alerts or []
        representative = self._select_representative_alerts(alerts, max_alerts=8)
        facts = []
        directions = []
        outcomes = []
        sequences = []
        gaps = []
        for index, alert in enumerate(representative, 1):
            direction = str(alert.get("direction") or "unknown").lower()
            if direction not in directions:
                directions.append(direction)
            http = alert.get("http_context") or {}
            action = str(alert.get("alert_action") or "unknown").lower()
            status = http.get("status") if isinstance(http, dict) else None
            outcome = "network action was not recorded"
            if action in {"allowed", "pass", "accepted"}:
                outcome = "network transaction was allowed"
            elif action in {"blocked", "drop", "dropped", "denied", "reject", "rejected"}:
                outcome = "network transaction was blocked"
            if status not in (None, ""):
                outcome += f"; HTTP status {status} was observed"
                if str(status).startswith("2"):
                    outcome += ", which confirms an HTTP response but not payload execution"
            outcomes.append(outcome)
            fact = {
                "alert_ref": f"ALERT-{alert.get('_original_index') or index}",
                "timestamp": alert.get("timestamp"),
                "rule": alert.get("rule_description") or alert.get("alert_signature"),
                "rule_id": alert.get("rule_id"),
                "severity": alert.get("rule_level"),
                "asset": alert.get("agent_name") or alert.get("agent_ip") or alert.get("dest_ip"),
                "source_ip": alert.get("src_ip"),
                "destination_ip": alert.get("dest_ip"),
                "direction": direction,
                "network_action": action,
                "http": http,
                "file": alert.get("file_context") or {},
                "observed_iocs": alert.get("observed_iocs") or {},
            }
            facts.append(fact)
            event_bits = [fact.get("rule")]
            if isinstance(http, dict) and (http.get("hostname") or http.get("url")):
                event_bits.append(f"HTTP {http.get('method') or 'request'} {http.get('hostname') or ''}{http.get('url') or ''}")
            filename = (fact.get("file") or {}).get("filename")
            if filename:
                event_bits.append(f"file named {filename} was identified in network telemetry")
            sequences.append({
                "timestamp": fact.get("timestamp"),
                "events": [item for item in event_bits if item],
                "execution_status": "not established by the alert",
            })

        current_artifacts = self._current_observed_artifacts(alerts)
        supported_docs = self._supported_doc_subset(context_docs)
        correlations = []
        for index, doc in enumerate(context_docs or [], 1):
            if not isinstance(doc, dict):
                continue
            overlap = doc.get("current_ioc_overlap") or {}
            evidence = list(doc.get("match_evidence") or [])
            strength = str(doc.get("evidence_strength") or "low").lower()
            correlations.append({
                "source_ref": f"RAG-{index}",
                "document_identity": self._document_identity(doc),
                "strength": strength,
                "current_overlap": overlap,
                "matched_evidence": evidence[:5],
                "limitations": list(doc.get("retrieval_cautions") or [])[:4]
                or (["semantic or lexical similarity alone is contextual, not incident proof"] if not overlap else []),
            })

        family_terms = []
        actor_terms = []
        for doc in supported_docs:
            artifacts = self._doc_artifacts_for_audit(doc)
            if doc.get("current_ioc_overlap") or doc.get("linked_exact_match_evidence"):
                family_terms.extend(artifacts.get("malware_families", []) or [])
                if "attribution" in set(doc.get("cti_context_labels") or []) and self._has_attribution_supporting_overlap(doc):
                    actor_terms.extend(artifacts.get("threat_actors", []) or [])
        family_terms = self._limited_values(family_terms, max_items=5)
        actor_terms = self._limited_values(actor_terms, max_items=5)
        if not actor_terms:
            gaps.append("Specific threat-actor attribution is not established by overlapping current-alert evidence.")
        if not any((alert.get("file_context") or {}).get(key) for alert in alerts for key in ("md5", "sha1", "sha256")):
            gaps.append("No current-alert cryptographic file hash is available to verify the payload.")
        gaps.append("Payload execution and post-download host activity are not established by the network alert alone.")

        mitre = self._mitre_evidence_categories(alerts, context_docs)
        top_assets = self._limited_values(
            [alert.get("agent_name") or alert.get("agent_ip") or alert.get("dest_ip") for alert in alerts if alert],
            max_items=6,
        )
        actions = []
        for asset in top_assets:
            actions.append({"priority": "P1", "action": f"Preserve and review endpoint telemetry for {asset} in the alert window", "basis": "current alert asset"})
        for filename in current_artifacts.get("files", [])[:3]:
            actions.append({"priority": "P1", "action": f"Acquire and hash {filename}; determine whether it executed", "basis": "current alert file"})
        for domain in current_artifacts.get("domains", [])[:3]:
            actions.append({"priority": "P2", "action": f"Hunt DNS, proxy, TLS, and endpoint telemetry for {domain}; validate before enforcement", "basis": "current alert domain"})
        actions.append({"priority": "P2", "action": "Correlate child processes, persistence changes, and outbound callbacks after the alert timestamp", "basis": "execution remains unconfirmed"})
        actions.append({"priority": "P3", "action": "Treat historical CTI-only indicators as hunt hypotheses until independently observed", "basis": "evidence boundary"})

        return {
            "current_alert_facts_with_provenance": facts,
            "affected_assets": top_assets,
            "network_direction": directions or ["unknown"],
            "ip_actionability": {
                "note": "Direction and actionability are separate judgments.",
                "public_current_ips": [value for value in current_artifacts.get("ips", []) if CTIArtifactExtractor.is_public_ip(value)],
                "non_global_or_context_only_ips": [value for value in current_artifacts.get("ips", []) if not CTIArtifactExtractor.is_public_ip(value)],
            },
            "action_and_response_outcome": self._limited_values(outcomes, max_items=8),
            "event_sequences": sequences,
            "cti_correlations": correlations,
            "expanded_selected_document_passages": [
                {
                    "source_ref": "RAG-1",
                    "section": (passage.get("metadata") or {}).get("cti_section_path"),
                    "text": self._extract_context_text(passage)[:1200],
                }
                for passage in expanded_passages or [] if isinstance(passage, dict)
            ],
            "malware_family_association": {
                "candidates": family_terms,
                "confidence": "moderate" if family_terms else "insufficient",
                "boundary": "Family similarity or association is not threat-actor attribution.",
            },
            "actor_attribution": {
                "candidates": actor_terms,
                "confidence": "supported" if actor_terms else "insufficient",
                "abstention": None if actor_terms else "Insufficient evidence for specific actor attribution.",
            },
            "likely_incident_stage": "delivery / ingress tool transfer" if "ingress_tool_transfer" in self._current_behavior_tags(alerts) else "requires analyst determination",
            "potential_impact": "Malware execution and follow-on compromise are plausible but not confirmed; validate on the affected asset.",
            "alternative_explanations": ["The transfer may have completed without execution.", "The signature may identify a suspicious payload pattern without proving a specific malware family."],
            "gaps_and_questions": gaps,
            "mitre_evidence_classes": mitre,
            "prioritized_actions": actions[:8],
            "hunt_hypotheses": [
                "Look for execution of the observed filename and child processes after the network event.",
                "Look for persistence, credential access, lateral movement, or callbacks only after confirming corresponding telemetry.",
            ],
        }

    def _build_deterministic_report(
        self,
        alerts: List[Dict],
        analysis: Dict[str, Any],
        context_docs: List[Any],
        report_kind: str,
        issues: List[str],
    ) -> str:
        """Build a complete CTI report without LLM output."""
        alerts = alerts or []
        analysis = analysis or self.alert_analyzer.analyze_current_alerts(alerts)
        total_alerts = len(alerts)
        threat_level = self._overall_threat_level(alerts)
        threat_counts = analysis.get("threat_classification", {})
        severity_breakdown = analysis.get("severity_breakdown", {})
        top_rows = self._top_priority_threat_rows(alerts)
        mitre_categories = self._mitre_evidence_categories(alerts, context_docs)
        mitre_catalog = self._load_mitre_catalog()

        def mitre_rows_for(category: str) -> List[Dict[str, str]]:
            rows = []
            for technique_id in mitre_categories[category][:5]:
                entry = mitre_catalog.get(technique_id.lower(), {})
                rows.append({
                    "tactic": str(entry.get("tactic") or "Observed Behavior"),
                    "id": technique_id,
                    "name": str(entry.get("name") or "ATT&CK technique"),
                })
            return rows
        behavior_tags = self._current_behavior_tags(alerts)
        current_artifacts = self._current_observed_artifacts(alerts)
        supported_docs = self._supported_doc_subset(context_docs)
        current_actor_terms = {
            self._normalize_claim_token(value): str(value)
            for value in current_artifacts.get("threat_actors", []) if value
        }
        attribution_doc_actor_terms: set[str] = set()
        for doc in supported_docs:
            if "attribution" not in set(doc.get("cti_context_labels") or []):
                continue
            if not self._has_attribution_supporting_overlap(doc):
                continue
            attribution_doc_actor_terms.update(
                self._normalize_claim_token(value)
                for value in self._doc_artifacts_for_audit(doc).get("threat_actors", [])
                if value
            )
        supported_current_actors = [
            display for normalized, display in current_actor_terms.items()
            if normalized in attribution_doc_actor_terms
        ]
        source_count = len(context_docs or [])
        high_quality_sources = sum(
            1 for doc in context_docs or []
            if isinstance(doc, dict) and str(doc.get("evidence_strength") or "").lower() in {"high", "medium"}
        )
        issue_note = "; ".join(issues or ["LLM output failed report validation"])
        attribution_summary = (
            f"Current and attribution-labelled CTI evidence jointly support {', '.join(supported_current_actors[:2])}. "
            if supported_current_actors else
            "Insufficient overlapping evidence exists for specific actor attribution. "
        )

        synthesis = self._build_incident_synthesis(alerts, context_docs, [])
        primary_fact = (synthesis.get("current_alert_facts_with_provenance") or [{}])[0]
        primary_http = primary_fact.get("http") or {}
        asset = primary_fact.get("asset") or "the observed asset"
        observed_event = primary_fact.get("rule") or "a security event"
        direction = primary_fact.get("direction") or "unknown"
        outcome = (synthesis.get("action_and_response_outcome") or ["outcome was not established"])[0]
        stage = synthesis.get("likely_incident_stage") or "requires analyst determination"
        summary = (
            f"A {threat_level.lower()}-priority {direction} event on {asset} matched {observed_event}. "
            f"The {outcome}. The likely incident stage is {stage}; payload execution and follow-on compromise remain unconfirmed. "
            f"{attribution_summary}Preserve endpoint evidence and determine whether the observed file or request led to execution. "
            f"The model draft was unusable ({issue_note}), so this evidence-bounded incident synthesis was generated deterministically."
        )

        findings = [
            f"[ALERT-1] {observed_event} affected {asset} with explicit network direction {direction}; IP actionability is assessed separately.",
            f"[ALERT-1] {outcome.capitalize()}.",
            f"[ALERT-1] Current telemetry identifies {primary_http.get('hostname') or 'no hostname'}{primary_http.get('url') or ''}; it does not establish payload execution.",
            f"Incident stage is assessed as {stage}, with post-delivery activity requiring endpoint validation.",
            f"CTI correlation includes {high_quality_sources} high/medium-strength source(s); sources without current overlap remain background context.",
        ]
        if current_artifacts:
            artifact_bits = [
                f"{key}={', '.join(values[:5])}"
                for key, values in current_artifacts.items()
                if values
            ]
            if artifact_bits:
                findings.append("Current alert artifacts: " + "; ".join(artifact_bits[:4]) + ".")
        if supported_current_actors:
            findings.append(
                "Supported actor attribution: " + ", ".join(supported_current_actors[:2])
                + "; current-alert evidence overlaps an attribution-labelled CTI source."
            )
        else:
            findings.append("Specific actor attribution: insufficient overlapping current-alert and CTI attribution evidence.")

        lines = [
            "**Executive Summary:**",
            "",
            summary,
            "",
            "**Key Findings:**",
            "",
        ]
        lines.extend(f"- {finding}" for finding in findings[:6])
        lines.extend([
            "",
            "**Incident Assessment:**",
            "",
            f"- Sequence: {primary_fact.get('timestamp') or 'timestamp unavailable'} — {observed_event}; {outcome}.",
            f"- Likely stage: {stage}.",
            "- Impact boundary: malware execution and follow-on compromise are plausible but not confirmed by the network alert.",
            "- Alternative explanation: the transfer or response may have occurred without successful execution.",
            "- Unanswered question: did the observed payload execute or create child processes, persistence, or callbacks?",
            "",
            "**Attribution Assessment:**",
            "",
            f"- Malware-family association: {', '.join((synthesis.get('malware_family_association') or {}).get('candidates') or []) or 'insufficient evidence for a specific family'}.",
            f"- Actor attribution: {(synthesis.get('actor_attribution') or {}).get('abstention') or ', '.join((synthesis.get('actor_attribution') or {}).get('candidates') or [])}.",
            "- Evidence boundary: malware-family similarity is not equivalent to actor attribution.",
        ])
        lines.extend(["", "**Top 5 Priority Threats:**", ""])
        lines.append("| Indicator | Type | Direction | Activity | Severity | Count |")
        lines.append("|-----------|------|-----------|----------|----------|-------|")
        if top_rows:
            for row in top_rows:
                lines.append(
                    f"| {row['indicator']} | {row['type']} | {row['direction']} | "
                    f"{row['activity']} | {row['severity']} | {row['count']} |"
                )
        else:
            lines.append("| None | N/A | N/A | No actionable non-infrastructure threat entity identified | LOW | 0 |")

        for heading, category, evidence_label in (
            ("MITRE ATT&CK — Explicit Current Alert Metadata", "explicit_current", "Explicit alert metadata"),
            ("MITRE ATT&CK — Inferred from Current Behavior", "inferred_current", "Deterministic current-behavior inference"),
            ("MITRE ATT&CK — Historical CTI Context Only (Not Observed)", "historical_only", "Historical context only; not observed in this incident"),
        ):
            lines.extend(["", f"**{heading}:**", ""])
            lines.append("| Tactic | Technique ID | Technique Name | Evidence Classification |")
            lines.append("|--------|--------------|----------------|-------------------------|")
            category_rows = mitre_rows_for(category)
            if category_rows:
                for row in category_rows:
                    lines.append(f"| {row['tactic']} | {row['id']} | {row['name']} | {evidence_label} |")
            else:
                lines.append(f"| Not mapped | N/A | No supported techniques | {evidence_label} |")
        lines.extend(["", "Confidence: Explicit IDs are authoritative; inferred IDs require analyst validation; historical IDs are context only."])

        action_targets = []
        for row in top_rows:
            indicator = str(row.get("indicator") or "")
            if indicator and indicator.lower() not in {"unknown", "none"}:
                action_targets.append(indicator)
        actions: List[str] = []

        def add_action(value: Any):
            text = re.sub(r"\s+", " ", str(value or "")).strip()
            if text and text not in actions:
                actions.append(text)

        for alert in alerts:
            for response_item in alert.get("response_focus") or []:
                add_action(response_item)
            host = alert.get("agent_name") or alert.get("agent_ip") or alert.get("src_ip")
            process = (alert.get("process_context") or {}).get("name")
            command = (alert.get("process_context") or {}).get("command_line")
            filename = (alert.get("file_context") or {}).get("filename")
            if host and (process or command):
                add_action(f"Investigate host {host} for observed process/command evidence: {command or process}.")
            if host and filename:
                add_action(f"Preserve and analyze observed file {filename} on host {host}; verify its current-alert hashes before containment decisions.")
            if host:
                add_action(f"Review and preserve endpoint/network telemetry for observed host {host} in the alert time window.")
            vulnerability = alert.get("vulnerability_context") or {}
            if isinstance(vulnerability, dict):
                cve = vulnerability.get("id") or vulnerability.get("cve")
                product = vulnerability.get("product") or vulnerability.get("name")
                if cve and product:
                    add_action(f"Validate exposure and remediation status for observed {product} affected by {cve} on {host}.")
        for domain in current_artifacts.get("domains", [])[:3]:
            add_action(f"Hunt DNS, proxy, and TLS telemetry for the current-alert domain {domain}; validate disposition before enforcement.")
        for value in current_artifacts.get("hashes", [])[:3]:
            add_action(f"Hunt endpoints for the current-alert file hash {value}; preserve confirmed matching artifacts for analysis.")
        add_action("Treat historical-only CTI indicators as hunt/watchlist context; do not block them unless independently observed or validated.")
        if len(actions) < 2:
            add_action("Preserve the current Wazuh/Suricata event and correlate its observed host, service, process, and network fields in the same time window.")
        actions = actions[:7]

        lines.extend(["", "**Immediate Actions:**", ""])
        lines.extend(f"{index}. **{action.split(':', 1)[0]}**: {action.split(':', 1)[1].strip()}" if ":" in action else f"{index}. {action}" for index, action in enumerate(actions, 1))
        lines.append("")
        lines.append(f"Priority: {threat_level} - Execute according to SOC severity handling.")

        lines.extend(["", "**Technical Summary:**", ""])
        lines.append(f"Attack vector: {', '.join(behavior_tags[:5]) if behavior_tags else 'Insufficient behavior detail in current alerts'}")
        lines.append(f"Target services: {analysis.get('protocol_breakdown') or 'Unavailable'}")
        lines.append(f"Threat actor infrastructure: {analysis.get('top_external_sources') or 'No confirmed external attacker infrastructure after filtering'}")
        lines.append("C2 indicators: Present only if supported by current alert behavior tags or exact IoC overlap.")
        lines.append("Exfiltration indicators: Present only if supported by current alert flow, protocol, or behavioral evidence.")
        lines.extend([
            "",
            "---",
            "",
            "**Analysis Complete**",
            "",
            f"Report generated: {datetime.now().isoformat()}",
            f"Threat level: {threat_level}",
            f"Priority actions: {len(actions)} identified",
            f"Threats requiring immediate blocking: {len(action_targets[:5])}",
            f"Suspected compromises: {'Review required' if threat_counts.get('outbound_threats', 0) or threat_counts.get('lateral_threats', 0) else 'None detected'}",
        ])
        return "\n".join(lines)

    def _generate_llm_report_with_guardrails(
        self,
        context: str,
        alerts: List[Dict],
        context_docs: List[Any],
        analysis: Dict[str, Any],
        report_kind: str,
    ) -> str:
        """Generate with the LLM, retry once if sections are missing, then fallback."""
        self._record_diagnostic_trace("exact_prompt_context", context)
        first = self._clean_report_content(self.llm_client.generate_response(context))
        self._record_diagnostic_trace("raw_model_draft", first)
        first_issues = self._validate_generated_report(first)
        self._record_diagnostic_trace("structural_findings", first_issues)
        if not first_issues:
            return first

        print(f"WARNING: LLM report failed validation: {first_issues}. Retrying once with strict section requirements.")
        repair_context = f"""{context}

STRICT REPAIR INSTRUCTIONS:
The previous model output was rejected because: {', '.join(first_issues)}.
Return a complete markdown CTI report now. It must begin with **Executive Summary:**, include **Key Findings:** with at least 4 bullets, include **Immediate Actions:**, and end with **Analysis Complete**. Do not include reasoning tags, chain-of-thought, preamble, or questions.
"""
        second = self._clean_report_content(self.llm_client.generate_response(repair_context))
        self._record_diagnostic_trace("single_model_repair_draft", second)
        second_issues = self._validate_generated_report(second)
        if not second_issues:
            return second

        print(f"WARNING: LLM retry failed validation: {second_issues}. Using deterministic report fallback.")
        return self._build_deterministic_report(
            alerts=alerts,
            analysis=analysis,
            context_docs=context_docs,
            report_kind=report_kind,
            issues=second_issues or first_issues,
        )

    @staticmethod
    def _classify_audit_findings(findings: List[str]) -> List[Dict[str, str]]:
        classified = []
        for finding in findings or []:
            claim_type = "evidence_gap"
            severity = "ADVISORY"
            if finding.startswith("Blocking structural issue:"):
                claim_type, severity = "report_structure", "BLOCKING"
            elif finding.startswith(("Attribution language", "Specific threat actor")):
                claim_type, severity = "actor_attribution", "REPAIRABLE"
            elif finding.startswith("Invalid threat-actor label"):
                claim_type, severity = "actor_attribution", "REPAIRABLE"
            elif finding.startswith("MITRE technique"):
                claim_type, severity = "mitre_technique", "REPAIRABLE"
            elif finding.startswith("Report mentions artifact"):
                claim_type, severity = "historical_artifact", "REPAIRABLE"
            elif finding.startswith(("Remediation action target", "Remediation recommends", "Patching is recommended")):
                claim_type, severity = "response_action", "REPAIRABLE"
            elif finding.startswith("Incident direction contradicts"):
                claim_type, severity = "incident_direction", "REPAIRABLE"
            elif finding.startswith("Network action outcome contradicts"):
                claim_type, severity = "network_outcome", "REPAIRABLE"
            elif finding.startswith("IP actionability/geolocation"):
                claim_type, severity = "ip_actionability", "REPAIRABLE"
            elif finding.startswith("CTI conflict is resolved by overriding"):
                claim_type, severity = "cti_correlation", "REPAIRABLE"
            elif finding.startswith("Incident impact overstates"):
                claim_type, severity = "incident_impact", "REPAIRABLE"
            elif finding.startswith("No selected high/medium-strength"):
                claim_type, severity = "correlation_gap", "ADVISORY"
            classified.append({"severity": severity, "claim_type": claim_type, "message": finding})
        return classified

    def _apply_targeted_audit_repairs(
        self,
        report_text: str,
        findings: List[Dict[str, str]],
        current_alerts: List[Dict] = None,
        context_docs: List[Any] = None,
    ) -> tuple[str, List[Dict[str, str]]]:
        """Repair only affected claim classes and preserve the rest of the draft."""
        repaired = str(report_text or "")
        applied = []
        claim_types = {item.get("claim_type") for item in findings if item.get("severity") == "REPAIRABLE"}

        if {"incident_direction", "network_outcome"}.intersection(claim_types):
            facts = self._build_incident_synthesis(current_alerts or [], [], [])
            directions = ", ".join(facts.get("network_direction") or ["unknown"])
            outcome = "; ".join(facts.get("action_and_response_outcome") or ["outcome unavailable"])
            repaired_lines = []
            for line in repaired.splitlines():
                sentences = re.split(r"(?<=[.!?])(?=\s|$)", line)
                kept = []
                for sentence in sentences:
                    remove = False
                    if "incident_direction" in claim_types and re.search(
                        r"\boutbound\b|\bfrom (?:the )?internal (?:host|asset).{0,100}\bto (?:the )?external\b",
                        sentence,
                        re.IGNORECASE,
                    ):
                        remove = True
                    if "network_outcome" in claim_types and re.search(
                        r"\b(?:blocked|dropped|denied|rejected)\b|"
                        r"\b(?:confirmed|confirming)\b.{0,70}\b(?:successful )?download(?:ed)?\b|"
                        r"\bdownload(?:ed)?\b.{0,90}\bconfirm(?:ed|ing)?\b|"
                        r"\bsuccessful download(?:ed)?\b",
                        sentence,
                        re.IGNORECASE,
                    ):
                        remove = True
                    if not remove:
                        kept.append(sentence)
                repaired_lines.append("".join(kept).strip() if line.strip() else "")
            repaired = "\n".join(repaired_lines).strip()
            repaired += (
                "\n\n**Current-Alert Direction and Outcome:**\n\n"
                f"The alert explicitly records {directions} direction. {outcome.capitalize()}. "
                "Direction is preserved independently from whether an IP is globally routable or actionable."
            )
            repaired = re.sub(r"\bmalicious file name\b", "suspicious file name", repaired, flags=re.IGNORECASE)
            applied.append({"claim_type": "incident_facts", "repair": "removed contradictory direction/outcome sentences and inserted authoritative current-alert facts"})

        if "cti_correlation" in claim_types:
            conflict_lines = []
            for line in repaired.splitlines():
                if re.search(r"\b(?:RAG-\d+|current alert).{0,140}\boverride(?:s|d)?\b", line, re.IGNORECASE):
                    prefix = "- " if line.lstrip().startswith(("-", "*")) else ""
                    line = prefix + "Conflicting CTI dispositions remain unresolved and require analyst validation; no retrieved source overrides current-alert facts."
                line = re.sub(
                    r"The most reliable evidence supports malicious intent\.\s*",
                    "",
                    line,
                    flags=re.IGNORECASE,
                )
                line = re.sub(
                    r"CTI correlation with (RAG-\d+) confirms?[^.\n]{0,180}\bmalicious\b[^.\n]*\.\s*",
                    r"CTI correlation with \1 shows exact overlap, but source dispositions conflict and do not independently prove malicious ownership. ",
                    line,
                    flags=re.IGNORECASE,
                )
                conflict_lines.append(line)
            repaired = "\n".join(conflict_lines)
            applied.append({"claim_type": "cti_correlation", "repair": "replaced unsupported source-precedence claim with an explicit unresolved conflict"})

        if "incident_impact" in claim_types:
            repaired = re.sub(
                r"\bcompromised (?:system|host|asset|endpoint)\b",
                "potentially affected system",
                repaired,
                flags=re.IGNORECASE,
            )
            repaired = re.sub(
                r"\bconfirmed compromise\b",
                "possible compromise requiring validation",
                repaired,
                flags=re.IGNORECASE,
            )
            applied.append({"claim_type": "incident_impact", "repair": "qualified compromise language where execution/impact was not confirmed"})

        if "ip_actionability" in claim_types:
            messages = " ".join(item.get("message", "") for item in findings if item.get("claim_type") == "ip_actionability")
            affected_ips = set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", messages))
            lines = []
            for line in repaired.splitlines():
                if any(ip in line for ip in affected_ips):
                    line = re.sub(r"\bUnited States\b", "Non-global / no public geolocation", line, flags=re.IGNORECASE)
                    line = re.sub(r"\bexternal IP\b", "network endpoint", line, flags=re.IGNORECASE)
                    line = re.sub(r"\bmalicious infrastructure\b", "context requiring validation", line, flags=re.IGNORECASE)
                    line = re.sub(r"\b(?:are|is) marked as malicious\b", "have conflicting CTI classifications", line, flags=re.IGNORECASE)
                    line = re.sub(r"\bmalicious disposition\b", "conflicting historical disposition", line, flags=re.IGNORECASE)
                    line = re.sub(r"\bsource is external\b", "source address is outside the configured internal range but is non-global", line, flags=re.IGNORECASE)
                    line = re.sub(r"\(external\)", "(non-global)", line, flags=re.IGNORECASE)
                    line = re.sub(r"Threat actor infrastructure:", "Infrastructure assessment:", line, flags=re.IGNORECASE)
                lines.append(line)
            repaired = "\n".join(lines)
            applied.append({"claim_type": "ip_actionability", "repair": "removed public geolocation and attacker-infrastructure labels from non-global IPs"})

        if "actor_attribution" in claim_types:
            actor_messages = " ".join(
                item.get("message", "") for item in findings
                if item.get("claim_type") == "actor_attribution"
            )
            unsupported_actor_terms = []
            for match in re.findall(
                r"Specific threat actor term\(s\).*?:\s*(.*?)\.\s*Verify",
                actor_messages,
                re.IGNORECASE,
            ):
                unsupported_actor_terms.extend(value.strip() for value in match.split(",") if value.strip())
            for actor_term in unsupported_actor_terms:
                repaired = re.sub(
                    rf"(?<![A-Za-z0-9]){re.escape(actor_term)}(?![A-Za-z0-9])",
                    "unsupported actor label",
                    repaired,
                    flags=re.IGNORECASE,
                )
            repaired = re.sub(
                r"(?i)\b(?:is|was|has been)\s+(?:directly\s+)?attributed to\b",
                "is historically associated in the cited CTI with",
                repaired,
            )
            repaired = re.sub(
                r"(?is)(?<!\w)[^.\n]*[\"']?(?:rated\s+)?(?:critical|high|medium|low)[\"']?\s+threat actor[^.\n]*\.\s*",
                "",
                repaired,
            )
            boundary = "Specific actor attribution for this incident remains unconfirmed unless current-alert evidence independently supports it."
            if boundary.lower() not in repaired.lower():
                repaired += f"\n\n**Attribution Evidence Boundary:**\n\n{boundary}"
            applied.append({"claim_type": "actor_attribution", "repair": "qualified definitive attribution and added an incident-specific abstention"})

        if "mitre_technique" in claim_types:
            messages = " ".join(item.get("message", "") for item in findings if item.get("claim_type") == "mitre_technique")
            unsupported_ids = {value.upper() for value in re.findall(r"\bT\d{4}(?:\.\d{3})?\b", messages, re.IGNORECASE)}
            mitre_categories = self._mitre_evidence_categories(current_alerts or [], context_docs or [])
            historical_ids = {value.upper() for value in mitre_categories["historical_only"]}
            lines = []
            for line in repaired.splitlines():
                affected = unsupported_ids.intersection(
                    value.upper() for value in re.findall(r"\bT\d{4}(?:\.\d{3})?\b", line, re.IGNORECASE)
                )
                if affected:
                    if affected.issubset(historical_ids):
                        if not re.search(r"historical|context only|not observed|hunt|hypothesis", line, re.IGNORECASE):
                            line = line.rstrip() + " — Historical CTI context only; not observed in the current alert."
                    else:
                        continue
                lines.append(line)
            repaired = "\n".join(lines)
            repaired = re.sub(
                r"(?m)(\|[- |]+\|\n)(\s*\nConfidence:)",
                r"\1| Not mapped | N/A | No supported technique in this evidence class | N/A |\n\2",
                repaired,
            )
            missing_explicit = [
                value for value in mitre_categories["explicit_current"]
                if not re.search(rf"\b{re.escape(value)}\b", repaired, re.IGNORECASE)
            ]
            if missing_explicit:
                repaired += "\n\n**MITRE ATT&CK — Explicit Current Alert Metadata:**\n\n" + "\n".join(
                    f"- {value} — explicit current-alert metadata." for value in missing_explicit
                )
            applied.append({"claim_type": "mitre_technique", "repair": "relabelled unsupported techniques as historical context"})

        if {"historical_artifact", "response_action"}.intersection(claim_types):
            response_messages = " ".join(
                item.get("message", "") for item in findings
                if item.get("claim_type") == "response_action"
            )
            unobserved_targets = set()
            if "were not observed in current alert artifacts" in response_messages:
                unobserved_targets.update(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", response_messages))
            lines = []
            for line in repaired.splitlines():
                if unobserved_targets and any(value in line for value in unobserved_targets):
                    continue
                if re.search(r"\b(?:block|blocklist|blocked|blocking|disable)\b", line, re.IGNORECASE):
                    if "Threats requiring immediate blocking" in line:
                        line = line.replace("Threats requiring immediate blocking", "Threats requiring actionability validation")
                    else:
                        line = re.sub(r"(?i)\b(?:blocklist|blocked|blocking|block)\b", "hunt and validation list", line)
                    line = re.sub(r"(?i)\bdisable\b", "validate", line)
                if re.search(r"\b(?:isolate|quarantine)\b", line, re.IGNORECASE) and re.search(
                    r"historical|CTI|RAG|indicator|IoC", line, re.IGNORECASE
                ):
                    line = re.sub(r"(?i)\b(?:isolate|quarantine)\b", "investigate", line)
                lines.append(line)
            repaired = "\n".join(lines)
            applied.append({"claim_type": "response_action", "repair": "downgraded enforcement of historical-only targets to validation/hunting"})

        if any(item.get("message", "").startswith("Patching is recommended") for item in findings):
            repaired = re.sub(
                r"(?im)^.*\b(?:patch|upgrade|apply (?:a )?(?:security )?update)\b.*$",
                "- Validate the affected product and vulnerability evidence before considering patching or upgrades.",
                repaired,
            )
            applied.append({"claim_type": "response_action", "repair": "made patching conditional on current vulnerability evidence"})
        repaired = re.sub(r"\.\s*(Therefore|However|While)\b", r". \1", repaired)
        return repaired, applied

    def _build_analyst_review_required_report(self, alerts: List[Dict], reason: str) -> str:
        """Fail closed with current-alert facts only when deterministic repair is unsafe."""
        alerts = alerts or []
        lines = [
            "**Executive Summary:**",
            "",
            "Analyst review is required. The generated draft and deterministic repair did not pass the evidence audit, so unsupported historical or inferred claims were withheld.",
            "",
            "**Key Findings:**",
            "",
            f"- {len(alerts)} current alert(s) were retained for review.",
            "- Specific actor attribution: insufficient evidence.",
            "- Historical CTI indicators and techniques are not treated as current observations.",
            "- Remediation below is limited to facts present in the current alert.",
        ]
        for alert in alerts[:3]:
            host = alert.get("agent_name") or alert.get("agent_ip") or alert.get("src_ip") or "observed asset"
            process = (alert.get("process_context") or {}).get("name")
            command = (alert.get("process_context") or {}).get("command_line")
            filename = (alert.get("file_context") or {}).get("filename")
            lines.append(f"- Current alert on {host}: {alert.get('alert_signature') or alert.get('rule_description') or 'security event'}.")
            if process or command:
                lines.append(f"- Observed process/command on {host}: {command or process}.")
            if filename:
                lines.append(f"- Observed file on {host}: {filename}.")

        lines.extend(["", "**MITRE ATT&CK — Explicit Current Alert Metadata:**", ""])
        explicit_ids = self._mitre_evidence_categories(alerts, [])["explicit_current"]
        if explicit_ids:
            lines.extend(f"- {technique_id} — explicit current-alert metadata." for technique_id in explicit_ids)
        else:
            lines.append("- No valid explicit ATT&CK technique ID was present in the current alert.")

        lines.extend(["", "**Immediate Actions:**", ""])
        action_number = 1
        for alert in alerts[:3]:
            host = alert.get("agent_name") or alert.get("agent_ip") or alert.get("src_ip") or "the observed asset"
            process = (alert.get("process_context") or {}).get("name")
            filename = (alert.get("file_context") or {}).get("filename")
            lines.append(f"{action_number}. Review and preserve endpoint/network telemetry for {host} in the alert time window.")
            action_number += 1
            if process or filename:
                lines.append(f"{action_number}. Investigate the observed artifact on {host}: {process or filename}.")
                action_number += 1
        lines.extend([
            f"{action_number}. Keep historical-only indicators as hunt context until independently validated.",
            "",
            "**Technical Summary:**",
            "",
            f"Finalization status: analyst review required ({reason}).",
            "",
            "---",
            "",
            "**Analysis Complete**",
        ])
        return "\n".join(lines)

    def _finalize_report_with_audit(
        self,
        report_text: str,
        context_docs: List[Any],
        current_alerts: List[Dict],
        analysis: Dict[str, Any],
        report_kind: str,
    ) -> tuple[str, str]:
        """Classify findings and repair individual claims before considering fallback."""
        raw_findings = self._audit_report_claims(report_text, context_docs, current_alerts)
        structural_findings = [
            f"Blocking structural issue: {issue}"
            for issue in self._validate_generated_report(report_text)
        ]
        classified = self._classify_audit_findings(structural_findings + raw_findings)
        self._record_diagnostic_trace("classified_claim_audit", classified)
        if not classified:
            return report_text, ""

        repaired, repairs = self._apply_targeted_audit_repairs(
            report_text, classified, current_alerts, context_docs
        )
        self._record_diagnostic_trace("targeted_repairs", repairs)
        repair_findings = self._audit_report_claims(repaired, context_docs, current_alerts)
        remaining = self._classify_audit_findings(repair_findings)
        high_risk_remaining = [item for item in remaining if item["severity"] == "REPAIRABLE"]
        structurally_unusable = bool(self._validate_generated_report(repaired))
        pervasive = len(high_risk_remaining) >= 4
        status = f"targeted deterministic repair applied to {len(repairs)} claim class(es); model analysis preserved"
        if structurally_unusable or pervasive:
            repaired = self._build_analyst_review_required_report(
                current_alerts,
                "draft was structurally unusable or retained pervasive high-risk claims after targeted repair",
            )
            status = "analyst review required; unusable or pervasively unsupported draft was quarantined"

        appendix = "\n\n---\n\n## Report Finalization\n\n" + status.capitalize() + ".\n"
        if remaining:
            appendix += "\nAdvisory findings retained for analyst review:\n" + "\n".join(
                f"- [{item['severity']}] {item['message']}" for item in remaining[:8]
            ) + "\n"
        self._record_diagnostic_trace("post_repair_audit", remaining)
        return repaired, appendix
    
    def _generate_with_custom_docs_only(self, all_alerts: List[Dict], 
                                   high_severity_alerts: List[Dict], 
                                   server_host: str, trigger_info: Dict = None) -> str:
        """Generate high-severity automatic report with custom CTI and local historical context."""
        self._start_diagnostic_trace(
            report_mode="automatic-high-severity",
            current_alert_evidence=high_severity_alerts,
        )
        historical_filter = self._build_metadata_filter(
            high_severity_alerts,
            is_automatic=True,
            trigger_info=trigger_info
        )
        combined_context_docs = self._retrieve_automatic_context_snapshot(
            high_severity_alerts,
            historical_filter,
            max_docs=4,
        )
        expanded_passages = self._expand_selected_document_evidence(
            combined_context_docs, high_severity_alerts, limit=4
        )
        incident_synthesis = self._build_incident_synthesis(
            high_severity_alerts, combined_context_docs, expanded_passages
        )
        self._record_diagnostic_trace("selected_documents", [
            {"rank": index, "identity": self._document_identity(doc), "score": doc.get("score")}
            for index, doc in enumerate(combined_context_docs, 1) if isinstance(doc, dict)
        ])
        self._record_diagnostic_trace("selected_document_passages", expanded_passages)
        self._record_diagnostic_trace("incident_synthesis", incident_synthesis)
        custom_context = (
            self._format_context_docs(combined_context_docs, max_chars=500)
            if combined_context_docs
            else "No directly relevant custom or historical context was selected."
        )
        expanded_context = self._format_context_docs(expanded_passages, max_chars=1200)
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

    CURRENT ALERT — AUTHORITATIVE OBSERVATIONS:
    {self._create_current_alert_context(high_severity_alerts, max_alerts=6)}

    CANONICAL INCIDENT SYNTHESIS — ORGANIZE THE REPORT AROUND THIS OBJECT:
    {json.dumps(incident_synthesis, indent=1, ensure_ascii=False, default=str)}

    RAG REFERENCE CONTEXT:
    {custom_context}

    COMPLEMENTARY PASSAGES FROM THE ALREADY-SELECTED TOP DOCUMENT:
    {expanded_context or "No complementary passages were available within the selected document."}

    CONTEXT: This is an automatic high-severity incident requiring immediate response. Focus on current high-severity alerts while using uploaded CTI and local historical alert patterns as supporting evidence.
    INSTRUCTIONS: When using RAG evidence, cite the bracketed source label such as [RAG-1].

    OUTPUT CONTRACT:
    - Do not output reasoning, <think> blocks, preamble, or questions.
    - Write a decision-ready incident narrative with event sequence, correlation strength/limits, alternatives, gaps, and P1/P2/P3 response priorities.
    - Keep malware-family association separate from actor attribution and abstain when actor evidence is insufficient.
    - Current high-severity alerts are authoritative for observed incident facts.
    - If RAG is low-strength, semantic-only, behavior-mismatched, or has no current-alert overlap, use it only as background.
    - Do not name actors, malware families, observed IoCs, or remediation targets unless supported by current alerts or high/medium-strength RAG with current-alert overlap.
    - MITRE mapping rules: HTTP/file/hash payload download or tool transfer maps to T1105, not T1190/T1203/T1059 unless exploit, client-side execution, or command/script interpreter evidence is directly observed. CVE/RCE/web exploit attempts map to T1190. Command/script interpreters map to T1059 only when the interpreter is observed.
    - Begin with **Executive Summary:** and include **Key Findings:**, **Incident Assessment:**, **Attribution Assessment:**, **Top 5 Priority Threats:**, the three MITRE evidence classes, **Prioritized Response Plan:**, **Immediate Actions:**, **Technical Summary:**, and **Analysis Complete**."""
        
        report_content = self._generate_llm_report_with_guardrails(
            context=context,
            alerts=high_severity_alerts,
            context_docs=combined_context_docs,
            analysis=analysis,
            report_kind="high-severity automatic incident response",
        )
        report_content, qa_appendix = self._finalize_report_with_audit(
            report_content,
            combined_context_docs,
            high_severity_alerts,
            analysis,
            "high-severity automatic incident response",
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
        final_markdown = report_header + report_content + qa_appendix + source_manifest
        self._record_diagnostic_trace("pre_parser_report", report_content + qa_appendix)
        self._record_diagnostic_trace("final_generated_markdown", final_markdown)
        self._flush_diagnostic_trace()
        return final_markdown

    def _retrieve_automatic_context_snapshot(
        self,
        alerts: List[Dict],
        historical_filter: Dict[str, Any],
        max_docs: int = 4,
    ) -> List[Dict[str, Any]]:
        """Retrieve custom, archive, and fallback context under one corpus snapshot."""
        with self.rag_manager.corpus_state_lock:
            selected_corpus_id = self.rag_manager.active_corpus_id
            custom_docs = self._retrieve_context_for_alerts(
                alerts,
                k=max_docs,
                source_mode="custom",
            )
            historical_docs = self._retrieve_context_for_alerts(
                alerts,
                k=max_docs,
                metadata_filter=historical_filter,
                source_mode="archive",
            )

            def belongs_to_snapshot(doc: Any) -> bool:
                if not selected_corpus_id or not isinstance(doc, dict):
                    return not selected_corpus_id
                metadata = doc.get("metadata") or {}
                return (
                    doc.get("corpus_id") or metadata.get("corpus_id")
                ) == selected_corpus_id

            candidates = [
                doc for doc in custom_docs + historical_docs
                if belongs_to_snapshot(doc)
            ]
            selected = self._select_relevant_context_docs(
                candidates,
                alerts,
                max_docs=max_docs,
            )
            if selected or not hasattr(self.rag_manager, "get_recent_custom_documents"):
                return selected

            fallback = [
                doc for doc in self.rag_manager.get_recent_custom_documents(k=max_docs)
                if belongs_to_snapshot(doc)
            ]
            return self._select_relevant_context_docs(
                self._annotate_context_docs(fallback, alerts),
                alerts,
                max_docs=max_docs,
                source_filter="custom_document",
            )

    def _clean_report_content(self, content: str) -> str:
        """Clean report content to remove forbidden elements and fix formatting"""
        content = self._strip_reasoning_text(content)
        if not content.strip():
            return ""
        
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
    Threat level: See report assessment
    Priority actions: See Immediate Actions section"""
        
        return cleaned_content


    def _generate_with_full_rag(self, cleaned_alerts: List[Dict], server_host: str, 
                           is_automatic: bool, trigger_info: Dict = None) -> str:
        """Generate report using full RAG context."""
        self._start_diagnostic_trace(
            report_mode="automatic" if is_automatic else "manual",
            current_alert_evidence=cleaned_alerts,
        )
        metadata_filter = self._build_metadata_filter(cleaned_alerts, is_automatic, trigger_info)
        exact_terms = self._build_exact_terms_from_alerts(cleaned_alerts)
        prompt_exact_terms = self._compact_exact_terms_for_prompt(exact_terms)
        context_docs = self._retrieve_context_for_alerts(
            cleaned_alerts,
            k=min(getattr(self.rag_manager, "max_retrieval_docs", 5), 5),
            metadata_filter=metadata_filter,
            source_mode="all"
        )
        expanded_passages = self._expand_selected_document_evidence(context_docs, cleaned_alerts, limit=4)
        incident_synthesis = self._build_incident_synthesis(
            cleaned_alerts,
            context_docs,
            expanded_passages,
        )
        self._record_diagnostic_trace("selected_documents", [
            {
                "rank": index,
                "identity": self._document_identity(doc),
                "source": doc.get("source") if isinstance(doc, dict) else "inline",
                "score": doc.get("score") if isinstance(doc, dict) else None,
                "evidence_strength": doc.get("evidence_strength") if isinstance(doc, dict) else None,
                "match_evidence": doc.get("match_evidence") if isinstance(doc, dict) else None,
            }
            for index, doc in enumerate(context_docs, 1)
        ])
        self._record_diagnostic_trace("selected_document_passages", expanded_passages)
        self._record_diagnostic_trace("incident_synthesis", incident_synthesis)
        full_rag_context = (
            self._format_context_docs(context_docs, max_chars=500)
            if context_docs
            else "No directly relevant historical patterns found."
        )
        expanded_context = self._format_context_docs(expanded_passages, max_chars=1200)
        source_manifest = self._format_rag_sources(context_docs)
        retrieval_summary = self._create_retrieval_summary(context_docs)
        mitre_evidence = self._format_mitre_evidence_for_prompt(cleaned_alerts, context_docs)
        
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

    CURRENT ALERT — AUTHORITATIVE OBSERVATIONS:
    {self._create_current_alert_context(cleaned_alerts, max_alerts=6)}

    CURRENT ALERT — EXPLICIT / INFERRED MITRE EVIDENCE:
    {mitre_evidence}

    CANONICAL INCIDENT SYNTHESIS — ORGANIZE THE REPORT AROUND THIS OBJECT:
    {json.dumps(incident_synthesis, indent=1, ensure_ascii=False, default=str)}

    RETRIEVED HISTORICAL CTI — SOURCE-BOUND EXCERPTS:
    {full_rag_context}

    COMPLEMENTARY PASSAGES FROM THE ALREADY-SELECTED TOP DOCUMENT:
    {expanded_context or "No complementary passages were available within the selected document."}

    CONFLICTS / LIMITATIONS:
    - Historical CTI indicators and techniques are not current observations unless they independently appear in the CURRENT ALERT sections.
    - Conflicting or weak attribution requires explicit abstention.

    ATTRIBUTION POLICY:
    Name an actor only when current-alert evidence overlaps a high/medium attribution source. Otherwise state: Insufficient evidence for specific actor attribution.

    CONTEXT: {"Manual security analysis with comprehensive context." if not is_automatic else "Automatic analysis for standard-severity incidents."}
    INSTRUCTIONS: When using RAG evidence, cite the bracketed source label such as [RAG-1].

    OUTPUT CONTRACT:
    - Do not output reasoning, <think> blocks, preamble, or questions.
    - Write an incident narrative, not a restatement of alert counts or retrieval metadata.
    - Executive Summary: state what happened, affected asset, direction, allowed/blocked outcome, what is confirmed, what is only associated, likely stage, and the two most urgent next steps.
    - Key Findings: each finding must connect evidence to an operational conclusion and cite [ALERT-n] and/or [RAG-n].
    - Include **Incident Assessment:** with a concise event sequence, correlation strength/limits, impact, alternative explanations, and unanswered questions.
    - Include **Attribution Assessment:** and keep malware-family association separate from actor attribution. Abstain explicitly when actor support is insufficient.
    - Include **Prioritized Response Plan:** grouped as P1/P2/P3, with concrete current-alert targets and hunt hypotheses.
    - Current alerts are authoritative for observed incident facts.
    - If RAG is low-strength, semantic-only, behavior-mismatched, or has no current-alert overlap, use it only as background.
    - Do not name actors, malware families, observed IoCs, or remediation targets unless supported by current alerts or high/medium-strength RAG with current-alert overlap.
    - Preserve the three MITRE categories exactly: explicit current-alert metadata, inferred current behavior, and historical CTI context only. Never present a historical-only technique as current.
    - MITRE mapping rules: HTTP/file/hash payload download or tool transfer maps to T1105, not T1190/T1203/T1059 unless exploit, client-side execution, or command/script interpreter evidence is directly observed. CVE/RCE/web exploit attempts map to T1190. Command/script interpreters map to T1059 only when the interpreter is observed.
    - Begin with **Executive Summary:** and include **Key Findings:**, **Incident Assessment:**, **Attribution Assessment:**, **Top 5 Priority Threats:**, the three evidence-class MITRE sections, **Prioritized Response Plan:**, **Immediate Actions:**, **Technical Summary:**, and **Analysis Complete**."""
        
        report_content = self._generate_llm_report_with_guardrails(
            context=context,
            alerts=cleaned_alerts,
            context_docs=context_docs,
            analysis=analysis,
            report_kind=analysis_type.lower(),
        )
        report_content, qa_appendix = self._finalize_report_with_audit(
            report_content,
            context_docs,
            cleaned_alerts,
            analysis,
            analysis_type.lower(),
        )
        self._record_diagnostic_trace("pre_parser_report", report_content + qa_appendix)
        
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
        
        final_markdown = report_header + report_content + qa_appendix + source_manifest
        self._record_diagnostic_trace("final_generated_markdown", final_markdown)
        self._flush_diagnostic_trace()
        return final_markdown

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
            log_sanitized_exception("MITRE technique catalog could not be loaded", error)

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
            if not self._has_attribution_supporting_overlap(doc):
                continue
            doc_artifacts = self._doc_artifacts_for_audit(doc)
            terms.update(
                self._normalize_claim_token(value)
                for value in doc_artifacts.get("threat_actors", [])
                if value
            )
        return terms

    @classmethod
    def _has_attribution_supporting_overlap(cls, doc: Dict[str, Any]) -> bool:
        """Require attacker-relevant current IoC overlap before supporting attribution."""
        overlap = doc.get("current_ioc_overlap") or {}
        if not isinstance(overlap, dict):
            return False

        strong_overlap = {
            key: values
            for key, values in overlap.items()
            if key in {"ips", "domains", "urls", "hashes"} and values
        }
        if not strong_overlap:
            return False

        dispositions = cls._doc_artifact_dispositions(doc)
        non_attacker_dispositions = {"benign", "victim", "analysis_environment", "remediation_reference"}
        for artifact_type, values in strong_overlap.items():
            typed_dispositions = dispositions.get(artifact_type) or {}
            normalized_dispositions = {
                RAGContextManager._refang_text(candidate).lower(): str(disposition).lower()
                for candidate, disposition in typed_dispositions.items()
                if disposition
            }
            for value in values or []:
                key = RAGContextManager._refang_text(value).lower()
                if normalized_dispositions.get(key) not in non_attacker_dispositions:
                    return True
        return False

    @staticmethod
    def _actor_terms_in_text(text: str, candidate_terms: Iterable[Any] = None) -> List[str]:
        """Extract high-confidence actor tokens without promoting arbitrary noun phrases."""
        actors = list(CTIArtifactExtractor.ATTACK_GROUP_RE.findall(text or ""))
        for candidate in candidate_terms or []:
            value = str(candidate or "").strip()
            if len(value) < 3:
                continue
            if RAGContextManager._contains_exact_term(text or "", value):
                actors.append(value)
        return CTIArtifactExtractor._unique(str(actor).upper() for actor in actors if actor)

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
        needle = RAGContextManager._refang_text(value).lower()
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
                if RAGContextManager._refang_text(candidate).lower() == needle and disposition:
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

        explicit_directions = {
            str(alert.get("direction") or "").strip().lower()
            for alert in current_alerts or [] if alert.get("direction")
        }
        if explicit_directions == {"inbound"} and re.search(
            r"\boutbound\b|\bfrom (?:the )?internal (?:host|asset).{0,100}\bto (?:the )?external\b",
            report_text,
            re.IGNORECASE,
        ):
            findings.append(
                "Incident direction contradicts current-alert evidence: the alert explicitly records inbound traffic, not outbound traffic."
            )
        if explicit_directions == {"outbound"} and re.search(r"\binbound\b", report_text, re.IGNORECASE):
            findings.append(
                "Incident direction contradicts current-alert evidence: the alert explicitly records outbound traffic, not inbound traffic."
            )

        current_actions = {
            str(alert.get("alert_action") or "").strip().lower()
            for alert in current_alerts or [] if alert.get("alert_action")
        }
        if current_actions.intersection({"allowed", "pass", "accepted"}) and re.search(
            r"\b(?:payload|request|download|transaction|traffic)\b.{0,80}\b(?:blocked|dropped|denied|rejected)\b|"
            r"\b(?:blocked|dropped|denied|rejected)\b.{0,80}\b(?:payload|request|download|transaction|traffic)\b",
            report_text,
            re.IGNORECASE | re.DOTALL,
        ):
            findings.append(
                "Network action outcome contradicts current-alert evidence: the transaction was allowed; an HTTP response does not prove execution."
            )
        lacks_file_confirmation = not any(
            (alert.get("file_context") or {}).get(key)
            for alert in current_alerts or []
            for key in ("md5", "sha1", "sha256", "stored", "state")
        )
        if lacks_file_confirmation and re.search(
            r"\b(?:confirmed|confirming)\b.{0,70}\b(?:successful )?download(?:ed)?\b|"
            r"\bdownload(?:ed)?\b.{0,90}\bconfirm(?:ed|ing)?\b|"
            r"\bsuccessful download(?:ed)?\b",
            report_text,
            re.IGNORECASE | re.DOTALL,
        ):
            findings.append(
                "Network action outcome contradicts current-alert evidence: HTTP 200 confirms a response, but file persistence or execution is not established."
            )
        if re.search(
            r"\b(?:RAG-\d+|current alert).{0,100}\boverride(?:s|d)?\b",
            report_text,
            re.IGNORECASE | re.DOTALL,
        ):
            findings.append(
                "CTI conflict is resolved by overriding one retrieved source without a supported precedence rule. Preserve the conflict and current-alert evidence boundary."
            )
        elif re.search(
            r"creating a conflict.{0,180}most reliable evidence supports malicious intent",
            report_text,
            re.IGNORECASE | re.DOTALL,
        ):
            findings.append(
                "CTI conflict is resolved by overriding one retrieved source without a supported precedence rule. Preserve the conflict and current-alert evidence boundary."
            )
        elif re.search(r"\bconflicting CTI\b", report_text, re.IGNORECASE) and re.search(
            r"\b(?:RAG-\d+|CTI correlation).{0,100}\bconfirms?\b.{0,100}\bmalicious\b",
            report_text,
            re.IGNORECASE | re.DOTALL,
        ):
            findings.append(
                "CTI conflict is resolved by overriding one retrieved source without a supported precedence rule. Preserve the conflict and current-alert evidence boundary."
            )

        non_global_current_ips = {
            str(value) for value in current_artifacts.get("ips", [])
            if value and not CTIArtifactExtractor.is_public_ip(value)
        }
        mischaracterized_ips = []
        for value in non_global_current_ips:
            if re.search(
                rf"(?im)^.*{re.escape(value)}.*(?:\bUnited States\b|\bexternal IP\b|\bthreat actor infrastructure\b|\bmalicious infrastructure\b|\(external\)).*$",
                report_text,
            ):
                mischaracterized_ips.append(value)
        if mischaracterized_ips:
            findings.append(
                "IP actionability/geolocation claim conflicts with address classification for non-global current IP(s): "
                + ", ".join(sorted(mischaracterized_ips))
                + ". Keep network direction separate and do not assign public geolocation or attacker-infrastructure status."
            )

        current_hashes = self._limited_values(current_artifacts.get("hashes", []), max_items=6)
        if current_hashes:
            matched_hashes = set()
            for doc in supported_docs:
                overlap = doc.get("current_ioc_overlap") or {}
                for value in overlap.get("hashes", []) or []:
                    matched_hashes.add(str(value).lower())
            missing_hashes = [
                value for value in current_hashes
                if str(value).lower() not in matched_hashes
            ]
            if missing_hashes:
                findings.append(
                    "No selected high/medium-strength RAG source matched current file hash(es): "
                    + ", ".join(missing_hashes)
                    + ". If these hashes exist in uploaded CTI, rebuild or refresh the RAG context for that document."
                )

        attribution_supported = any(
            "attribution" in (doc.get("cti_context_labels") or [])
            and self._has_attribution_supporting_overlap(doc)
            for doc in supported_docs
        )
        actor_candidates = list(current_artifacts.get("threat_actors", []))
        for doc in context_docs or []:
            if not isinstance(doc, dict):
                continue
            actor_candidates.extend(self._doc_artifacts_for_audit(doc).get("threat_actors", []))
        actor_candidates = [
            value for value in actor_candidates
            if not re.search(
                r"(?i)^(?:rated\s+)?(?:critical|high|medium|low|unknown|threat actor|malware family)$",
                str(value or "").strip(),
            )
        ]
        if re.search(
            r"[\"']?(?:rated\s+)?(?:critical|high|medium|low)[\"']?\s+threat actor",
            report_text,
            re.IGNORECASE,
        ):
            findings.append(
                "Invalid threat-actor label was derived from a severity phrase; remove it rather than treating severity text as an entity."
            )
        actor_terms = sorted(set(self._actor_terms_in_text(report_text, actor_candidates)))
        attribution_language = re.search(
            r"\b(?:attributed to|actor attribution|threat actor|operator|nation[- ]state)\b",
            report_text,
            flags=re.IGNORECASE,
        )
        explicit_abstention = re.search(
            r"insufficient evidence.{0,120}(?:actor|attribution)|(?:actor|attribution).{0,120}insufficient evidence|"
            r"no confirmed.{0,80}(?:actor|attribution)|(?:actor|attribution).{0,80}(?:not confirmed|no confirmed)",
            report_text,
            flags=re.IGNORECASE | re.DOTALL,
        )
        if (actor_terms or (attribution_language and not explicit_abstention)) and not attribution_supported:
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

        mitre_categories = self._mitre_evidence_categories(current_alerts, context_docs)
        current_mitre = {
            self._normalize_claim_token(value)
            for value in mitre_categories["explicit_current"] + mitre_categories["inferred_current"]
        }
        historical_mitre = {
            self._normalize_claim_token(value)
            for value in mitre_categories["historical_only"]
        }

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
        unsupported_mitre = []
        for value in sorted(report_mitre):
            if value in current_mitre:
                continue
            line_match = re.search(rf"(?im)^.*\b{re.escape(value)}\b.*$", report_text)
            line = line_match.group(0) if line_match else ""
            historical_labelled = value in historical_mitre and bool(re.search(
                r"historical|context only|not observed|hunt|hypothesis",
                line,
                flags=re.IGNORECASE,
            ))
            if not historical_labelled:
                unsupported_mitre.append(value.upper())
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
                    if (
                        artifact_type == "ips"
                        and action_set.intersection({"block", "disable"})
                        and (
                            not CTIArtifactExtractor.is_public_ip(value)
                            or str(value) in CTIArtifactExtractor.LOW_SIGNAL_CTI_IPS
                        )
                    ):
                        non_actionable_targets.append(f"{value}=non_global_or_low_signal")
                    elif disposition in {"benign", "analysis_environment", "remediation_reference"}:
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

        direct_non_global_blocks = []
        for value in non_global_current_ips:
            if re.search(
                rf"(?im)^.*\b(?:block|blocklist|deny|firewall)\w*\b.*{re.escape(value)}.*$|"
                rf"^.*{re.escape(value)}.*\b(?:block|blocklist|deny|firewall)\w*\b.*$",
                report_text,
            ):
                direct_non_global_blocks.append(value)
        if direct_non_global_blocks:
            findings.append(
                "Remediation action target(s) use non-global current IPs as direct block targets: "
                + ", ".join(sorted(direct_non_global_blocks))
                + ". Preserve direction but require independent actionability validation."
            )
        if non_global_current_ips and re.search(
            r"Threats requiring immediate blocking:\s*[1-9]\d*",
            report_text,
            re.IGNORECASE,
        ):
            findings.append(
                "Remediation action target(s) use non-global current IPs as direct block targets: footer count requires actionability validation."
            )

        execution_confirmed = any(
            (alert.get("process_context") or {}).get(key)
            for alert in current_alerts or []
            for key in ("name", "command_line")
        )
        if not execution_confirmed and re.search(
            r"\b(?:compromised (?:system|host|asset|endpoint)|confirmed compromise)\b",
            report_text,
            re.IGNORECASE,
        ):
            findings.append(
                "Incident impact overstates confirmed compromise even though execution or post-delivery activity is not established."
            )

        current_hosts = {
            str(value).strip().lower()
            for alert in current_alerts or []
            for value in (alert.get("agent_name"), alert.get("agent_ip"), alert.get("src_ip"), alert.get("dest_ip"))
            if value
        }
        unobserved_hosts = []
        for match in re.finditer(
            r"\b(?:isolate|quarantine|contain)\s+(?:the\s+)?(?:(?:host|endpoint|system|asset)\s+)?[`*_]*([A-Za-z0-9_.-]+)",
            report_text,
            flags=re.IGNORECASE,
        ):
            candidate = match.group(1).strip("`*_.-")
            if candidate.lower() in {"affected", "observed", "source", "current", "current-alert", "compromised", "asset", "host", "endpoint", "for", "only", "when"}:
                continue
            if candidate and candidate.lower() not in current_hosts:
                unobserved_hosts.append(candidate)
        if unobserved_hosts:
            findings.append(
                "Remediation recommends isolation/containment of unobserved host(s): "
                + ", ".join(self._limited_values(unobserved_hosts, max_items=8))
                + ". Use only current-alert assets."
            )

        if re.search(r"\b(?:patch|upgrade|apply (?:a )?(?:security )?update)\b", report_text, re.IGNORECASE):
            supported_cves = {str(value).upper() for value in current_artifacts.get("cves", [])}
            report_cves = {str(value).upper() for value in CTIArtifactExtractor.extract(report_text).get("cves", [])}
            vulnerability_products = {
                str(value).strip().lower()
                for alert in current_alerts or []
                for value in (alert.get("vulnerability_context") or {}).values()
                if value not in (None, "", [], {})
            }
            if report_cves - supported_cves:
                findings.append(
                    "Patching is recommended for unsupported CVE(s): "
                    + ", ".join(sorted(report_cves - supported_cves))
                    + "."
                )
            if not supported_cves and not vulnerability_products:
                findings.append(
                    "Patching is recommended without a product or vulnerability supported by the current alert."
                )

        return self._limited_values(findings, max_items=16)

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
        if doc.get("linked_exact_source_document"):
            parts.append(f"linked_exact_source_document={doc.get('linked_exact_source_document')}")
        if doc.get("linked_exact_chunk_index") is not None:
            parts.append(f"linked_exact_chunk_index={doc.get('linked_exact_chunk_index')}")

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
                if doc.get("linked_exact_match_evidence"):
                    audit_lines.append(
                        "Linked exact CTI hit: "
                        + "; ".join(str(item) for item in doc.get("linked_exact_match_evidence")[:3])
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

# Enhanced classes with chart support
class EnhancedReportFormatter(ReportFormatter):
    """Enhanced report formatter with chart generation capabilities"""
    
    def __init__(self, llm_client: LlamaModelClient, rag_manager: RAGContextManager, 
                 alert_analyzer: AlertAnalyzer, reports_dir: str):
        super().__init__(llm_client, rag_manager, alert_analyzer, reports_dir=reports_dir)
        
        # Initialize chart generator
        charts_dir = Path(reports_dir) / "charts"
        self.chart_generator = SOCChartGenerator(str(charts_dir))
        
        # Clean up old charts on initialization
        cleaned = self.chart_generator.cleanup_old_charts(max_age_hours=48)
        if cleaned > 0:
            print(f"Cleaned up {cleaned} old chart files")
    
    def generate_report_with_rag(self, current_alerts: List[Dict], server_host: str = "unknown", 
                        is_automatic: bool = False, trigger_info: Dict = None) -> str:
        """Enhanced report generation with conditional IP analysis charts"""
        if not self.rag_manager.rag_ready:
            raise RuntimeError("RAG context is not ready")
        
        try:
            print(f"Generating enhanced report for {len(current_alerts)} alerts...")
            include_charts = is_automatic or (trigger_info and trigger_info.get('include_charts', False))
            # Check if alerts are already cleaned (have 'threat_classification' key)
            if current_alerts and 'threat_classification' in current_alerts[0]:
                print("Alerts already cleaned, using as-is")
                cleaned_alerts = current_alerts
            else:
                print("Cleaning raw alerts...")
                cleaned_alerts = self.alert_analyzer.clean_log_data(current_alerts)
            
            print(f"Processing {len(cleaned_alerts)} cleaned alerts for report")
            
            # Generate charts ONLY if enabled
            chart_paths = []
            if include_charts:
                chart_timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
                trigger_type = "automatic" if is_automatic else "manual"
                chart_prefix = f"{trigger_type}_report_{chart_timestamp}_{uuid4().hex[:8]}"
                
                print(f"Generating charts with prefix: {chart_prefix}")
                
                try:
                    # Generate IP analysis charts
                    ip_charts = self.chart_generator.generate_ip_analysis_charts(
                        cleaned_alerts, chart_prefix
                    )
                    chart_paths.extend(ip_charts)
                    print(f"Generated {len(ip_charts)} IP analysis charts")
                    
                    # Generate timeline chart if we have enough data
                    if len(cleaned_alerts) > 5:
                        timeline_path = self.chart_generator.generate_severity_timeline(
                            cleaned_alerts, chart_prefix
                        )
                        if timeline_path:
                            chart_paths.append(timeline_path)
                            print("Generated severity timeline chart")
                    
                    print(f"Total charts generated: {len(chart_paths)}")
                except Exception as chart_error:
                    print(f"WARNING: Chart generation failed ({type(chart_error).__name__})")
                    # Continue without charts - don't fail the whole report
            else:
                print("Skipping chart generation (not enabled for this report type)")
            
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
                print(f"Embedding {len(chart_paths)} charts into report")
                enhanced_report = self._insert_charts_into_report(
                    text_report, chart_paths, cleaned_alerts
                )
                return enhanced_report
            else:
                print("No charts to embed - returning text-only report")
                return text_report
            
        except Exception as e:
            self.rag_manager._rollback_safely()
            log_sanitized_exception("Enhanced report generation failed", e)
            raise RuntimeError("Enhanced report generation failed") from None
    
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
            log_sanitized_exception("Chart insertion failed", e)
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
            raise ValueError("Database configuration is required")
        
        # Set reports directory
        self.reports_dir = reports_dir or str(Path(templates_dir).parent / "reports")

        rag_manager = RAGContextManager(db_config, rag_config)
        alert_analyzer = None
        try:
            alert_analyzer = AlertAnalyzer(geoip_db_path, asset_config)
            report_formatter = EnhancedReportFormatter(
                self.llm_client,
                rag_manager,
                alert_analyzer,
                self.reports_dir,
            )
        except Exception:
            if alert_analyzer is not None:
                alert_analyzer.close()
            rag_manager.close()
            raise

        self.rag_manager = rag_manager
        self.alert_analyzer = alert_analyzer
        self.report_formatter = report_formatter
        # One local llama.cpp workload at a time protects shared GPU/RAM and
        # keeps manual and automatic generation from racing each other.
        self._generation_lock = threading.Lock()
        
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

    def extend_rag_context(
        self,
        archive_logs: List[Dict] = None,
        custom_docs: List[Any] = None,
    ):
        """Additively union archive records and/or documents into RAG."""
        return self.rag_manager.extend_rag_context(archive_logs, custom_docs)
    
    def add_custom_documents(self, docs: List[Any]):
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
        if not self._generation_lock.acquire(blocking=False):
            raise RuntimeError("A report generation is already in progress")
        if not self.llm_client.prepare_generation():
            self._generation_lock.release()
            raise RuntimeError("Report generation is shutting down")
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
        finally:
            self._generation_lock.release()

    @property
    def generation_active(self) -> bool:
        return self._generation_lock.locked()

    def cancel_active_generations(self, *, permanent: bool = False) -> int:
        """Stop active llama.cpp children and prevent compatibility retries."""
        return self.llm_client.cancel_active_generations(permanent=permanent)

    def close(self) -> None:
        """Release persistent resources owned by the report pipeline."""
        self.cancel_active_generations(permanent=True)
        self.alert_analyzer.close()
        self.rag_manager.close()
    
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

    def record_report_trace_stage(self, stage: str, value: Any) -> None:
        self.report_formatter.record_last_trace_stage(stage, value)

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
            r"^\s*##\s+.*(?:Report Finalization|Report QA Findings|RAG Sources Used|Visual Threat Analysis)\s*$",
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
        if not self.add_custom_documents([doc]):
            return False
        print("Indexed approved report into RAG (generated appendices stripped)")
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

        atomic_write_text(output_file, "".join(markdown))
        print(f"SUCCESS: Visual report saved: {output_file.name}")
        return str(output_file)
    
    # Utility Methods
    def clean_log_data(self, logs: List[Dict]) -> List[Dict]:
        """Clean and minimize log data"""
        return self.alert_analyzer.clean_log_data(logs)
    
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
            "supported_formats": ["PNG"],
            "auto_cleanup": "48 hours"
        }
