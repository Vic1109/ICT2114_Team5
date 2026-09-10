import json
import os
from pathlib import Path
from typing import Dict, Any, Optional, Tuple, List
from dataclasses import dataclass, field


CONFIG_DIR = Path(__file__).resolve().parent


def _state_root_from_environment() -> Path:
    return Path(
        os.getenv("XDG_STATE_HOME", str(Path.home() / ".local" / "state"))
    ).expanduser() / "soc-rag"


def _parse_bool(value: str) -> bool:
    normalized = str(value).strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ValueError("Boolean values must be true/false, yes/no, on/off, or 1/0")


STATE_ROOT = _state_root_from_environment()

@dataclass
class DatabaseConfig:
    host: str = "localhost"
    port: int = 5432
    database: str = "soc_rag"
    user: str = "soc_user"
    password: str = ""
    connect_timeout: int = 10
    auto_create_database: bool = False
    
    def validate(self) -> Tuple[bool, str]:
        if not self.host:
            return False, "Database host cannot be empty"
        if not self.database:
            return False, "Database name cannot be empty"
        if not self.user:
            return False, "Database user cannot be empty"
        if not self.password:
            return False, "Database password cannot be empty"
        if not (1 <= self.port <= 65535):
            return False, "Database port must be between 1 and 65535"
        if self.connect_timeout <= 0:
            return False, "Database connection timeout must be positive"
        return True, "Database config is valid"
    
    def get_dict(self) -> dict:
        return {
            "host": self.host,
            "port": self.port,
            "database": self.database,
            "user": self.user,
            "password": self.password,
            "connect_timeout": self.connect_timeout,
            "_auto_create_database": self.auto_create_database,
        }
@dataclass
class SSHConfig:
    """SSH connection configuration"""
    host: str = ""
    username: str = ""
    password: str = ""
    port: int = 22
    timeout: int = 30
    allow_unknown_host: bool = False
    known_hosts_path: Optional[str] = None
    
    def validate(self) -> Tuple[bool, str]:
        """Validate SSH configuration"""
        supplied = [bool(self.host), bool(self.username), bool(self.password)]
        if not any(supplied):
            return True, "SSH integration is disabled"
        if not self.host:
            return False, "SSH host is required when SSH integration is configured"
        if not self.username:
            return False, "SSH username is required when SSH integration is configured"
        if not self.password:
            return False, "SSH password is required when SSH integration is configured"
        if not (1 <= self.port <= 65535):
            return False, "SSH port must be between 1 and 65535"
        if self.timeout <= 0:
            return False, "SSH timeout must be positive"
        if self.known_hosts_path and not Path(self.known_hosts_path).expanduser().exists():
            return False, "Configured SSH known_hosts file does not exist"
        return True, "SSH config is valid"


@dataclass
class WazuhConfig:
    """Wazuh server configuration"""
    alerts_file_path: str = "/var/ossec/logs/alerts/alerts.json"
    archives_base_path: str = "/var/ossec/logs/archives"
    
    def validate(self) -> Tuple[bool, str]:
        """Validate Wazuh configuration"""
        if not self.alerts_file_path:
            return False, "Alerts file path cannot be empty"
        if not self.archives_base_path:
            return False, "Archives base path cannot be empty"
        return True, "Wazuh config is valid"


@dataclass
class AssetInventoryConfig:
    """Local asset inventory used for alert classification and prompt grounding."""
    owned_cidrs: List[str] = field(default_factory=list)
    infrastructure_ips: List[str] = field(default_factory=list)
    internal_cidrs: List[str] = field(default_factory=lambda: [
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
    ])

    def validate(self) -> Tuple[bool, str]:
        import ipaddress

        try:
            for cidr in self.owned_cidrs + self.internal_cidrs:
                ipaddress.ip_network(cidr, strict=False)
            for ip_value in self.infrastructure_ips:
                ipaddress.ip_address(ip_value)
        except ValueError:
            return False, "Asset inventory contains an invalid IP address or CIDR"
        return True, "Asset inventory config is valid"


@dataclass
class LLMConfig:
    model_path: str = ""
    llama_cpp_path: str = ""
    temperature: float = 0.2
    top_p: float = 0.8
    top_k: int = 20
    context_size: int = 16384
    max_tokens: int = 2048
    timeout: int = 1200

    # Preflight prompt budgeting. The prompt is written to a file and passed to
    # llama.cpp, which has no way to tell us it silently dropped the head of the
    # prompt, so the budget has to be enforced before the process is started.
    #   context_size >= system_tokens + prompt_tokens + reserved_output + margin
    # The margin absorbs chat-template wrappers, BOS/EOS tokens and the error of
    # the character-based token estimate below.
    prompt_safety_margin_tokens: int = 512
    # Characters per token used by the preflight estimator. Qwen BPE averages
    # ~3.5-4.0 chars/token on English prose but drops towards ~2.5 on JSON and
    # hex IoCs, so a low value here is deliberately pessimistic.
    prompt_chars_per_token: float = 3.0
    # Output reservation used when max_tokens is -1 (infinity) or -2 (fill
    # context), where there is no explicit number to reserve.
    prompt_unbounded_output_reserve_tokens: int = 2048

    model_type: str = "qwen"  
    
    use_custom_template: bool = True  
    chat_template_file: str = "qwen_chat.j2"  
    system_prompt_file: str = "cti.txt"
    
    no_display_prompt: bool = True  
    single_turn: bool = True     
    use_jinja: bool = True         
    conversation_mode: bool = False

    # auto: persistent llama-server when a sibling binary exists and GPU
    # offload is enabled; otherwise llama-cli. cli/server force one path.
    inference_backend: str = "auto"
    llama_server_url: str = ""
    llama_server_host: str = "127.0.0.1"
    llama_server_port: int = 8090
    llama_server_autostart: bool = True
    llama_server_path: str = ""
    
    gpu_layers: int = 99
    main_gpu: int = 0
    # Empty means llama.cpp equal-splits across visible GPUs. Set
    # LLM_TENSOR_SPLIT only for unequal cards (for example a display GPU).
    tensor_split: Optional[str] = None
    
    use_mmap: bool = True
    use_mlock: bool = True
    no_kv_offload: bool = False
    
    batch_size: int = 512
    ubatch_size: int = 256
    
    flash_attention: bool = False
    cache_type_k: str = "f16"
    cache_type_v: str = "f16"
    
    threads: int = 12
    threads_batch: int = 12
    
    repeat_penalty: float = 1.0
    presence_penalty: float = 0.0
    frequency_penalty: float = 0.0
    disable_thinking: bool = True
    debug_commands: bool = False

    @property
    def reserved_output_tokens(self) -> int:
        """Tokens the prompt must leave free so generation cannot be truncated.

        llama.cpp treats ``--predict -1``/``-2`` as "generate until the context
        is exhausted", so there is no configured number to reserve and we fall
        back to the configured unbounded reservation instead.
        """
        if self.max_tokens is None or self.max_tokens <= 0:
            return max(1, int(self.prompt_unbounded_output_reserve_tokens))
        return int(self.max_tokens)

    def validate(self) -> Tuple[bool, str]:
        """Validate LLM configuration"""
        if not self.model_path or not Path(self.model_path).is_file():
            return False, "Configured model file was not found"
        if not self.llama_cpp_path or not Path(self.llama_cpp_path).is_file():
            return False, "Configured llama.cpp binary was not found"
        if not os.access(self.llama_cpp_path, os.X_OK):
            return False, "Configured llama.cpp binary is not executable"
        if not (0.0 <= self.temperature <= 2.0):
            return False, "Temperature must be between 0.0 and 2.0"
        if not (0.0 <= self.top_p <= 1.0):
            return False, "Top-p must be between 0.0 and 1.0"
        if self.top_k <= 0:
            return False, "Top-k must be positive"
        if self.context_size <= 0:
            return False, "Context size must be positive"
        if self.max_tokens <= 0 and self.max_tokens not in [-1, -2]:
            return False, "Max tokens must be positive, -1 (infinity), or -2 (until context filled)"
        if self.timeout <= 0:
            return False, "Timeout must be positive"
        if self.prompt_safety_margin_tokens < 0:
            return False, "Prompt safety margin cannot be negative"
        if self.prompt_chars_per_token <= 0:
            return False, "Prompt chars-per-token must be positive"
        if self.prompt_unbounded_output_reserve_tokens <= 0:
            return False, "Prompt unbounded output reserve must be positive"
        if self.context_size <= self.reserved_output_tokens + self.prompt_safety_margin_tokens:
            return False, (
                "Context size leaves no room for a prompt after reserving "
                f"{self.reserved_output_tokens} output tokens and "
                f"{self.prompt_safety_margin_tokens} margin tokens"
            )
        if self.gpu_layers < 0:
            return False, "GPU layers must be non-negative"
        backend = str(self.inference_backend or "auto").strip().lower()
        if backend not in {"auto", "cli", "server"}:
            return False, "Inference backend must be auto, cli, or server"
        if self.llama_server_port <= 0 or self.llama_server_port > 65535:
            return False, "llama-server port must be between 1 and 65535"
        if self.batch_size <= 0:
            return False, "Batch size must be positive"
        if self.ubatch_size <= 0:
            return False, "Micro-batch size must be positive"
        if self.threads <= 0:
            return False, "Thread count must be positive"
        
        # Validate model type
        supported_models = ["qwen"]
        if self.model_type.lower() not in supported_models:
            return False, f"Unsupported model type: {self.model_type}. Supported: {supported_models}"
        
        return True, "LLM config is valid"
    
    def get_llama_args(
        self,
        templates_dir: str = None,
        custom_template_path: str = None,
        include_optional_qwen_args: bool = True
    ) -> list[str]:
        """Generate optimized llama.cpp command line arguments with enhanced flags"""
        args = [
            "--model", self.model_path,
            "--ctx-size", str(self.context_size),
            "--predict", str(self.max_tokens),
            "--temp", str(self.temperature),
            "--top-p", str(self.top_p),
            "--top-k", str(self.top_k),
            "--batch-size", str(self.batch_size),
            "--ubatch-size", str(self.ubatch_size),
            "--threads", str(self.threads),
            "--threads-batch", str(self.threads_batch),
            "--gpu-layers", str(self.gpu_layers),
            "--main-gpu", str(self.main_gpu),
            "--cache-type-k", self.cache_type_k,
            "--cache-type-v", self.cache_type_v,
        ]
        if templates_dir:
            args.extend(["--system-prompt-file", str(Path(templates_dir) / self.system_prompt_file)])
        if self.no_display_prompt:
            args.append("--no-display-prompt")
        
        if self.single_turn:
            args.append("--single-turn")
        
        if self.use_jinja:
            args.append("--jinja")
        
        if self.conversation_mode:
            args.append("--conversation")
        
        if custom_template_path and Path(custom_template_path).exists():
            args.extend(["--chat-template-file", custom_template_path])

        if include_optional_qwen_args and self.model_type.lower() == "qwen" and self.disable_thinking:
            args.extend(["--chat-template-kwargs", '{"enable_thinking": false}'])
        
        if self.repeat_penalty != 1.0:
            args.extend(["--repeat-penalty", str(self.repeat_penalty)])
        
        if self.presence_penalty != 0.0:
            args.extend(["--presence-penalty", str(self.presence_penalty)])
        
        if self.frequency_penalty != 0.0:
            args.extend(["--frequency-penalty", str(self.frequency_penalty)])
        
        # Memory and performance optimization flags
        if not self.use_mmap:
            args.append("--no-mmap")
        if self.use_mlock:
            args.append("--mlock")
        if self.no_kv_offload:
            args.append("--no-kv-offload")
        if self.flash_attention:
            args.append("--flash-attn")
        # --tensor-split is a multi-GPU layout. On CPU-only runs (gpu_layers=0)
        # a split string is meaningless and can confuse device init. When the
        # value is empty, llama.cpp equal-splits visible devices.
        tensor_split = str(self.tensor_split or "").strip()
        if tensor_split and int(self.gpu_layers or 0) != 0:
            args.extend(["--tensor-split", tensor_split])
        
        return args

    def resolved_llama_server_path(self) -> Optional[str]:
        """Path to llama-server: explicit setting, then sibling of llama-cli."""
        explicit = str(self.llama_server_path or "").strip()
        if explicit:
            return explicit
        cli_path = Path(str(self.llama_cpp_path or ""))
        if not cli_path.name:
            return None
        sibling = cli_path.with_name("llama-server")
        return str(sibling) if sibling.is_file() else None

    def get_llama_server_args(self) -> list[str]:
        """Arguments for a persistent llama-server process (no per-request prompt)."""
        args = [
            "--host", str(self.llama_server_host or "127.0.0.1"),
            "--port", str(int(self.llama_server_port or 8090)),
            "--model", self.model_path,
            "--ctx-size", str(self.context_size),
            "--batch-size", str(self.batch_size),
            "--ubatch-size", str(self.ubatch_size),
            "--threads", str(self.threads),
            "--threads-batch", str(self.threads_batch),
            "--gpu-layers", str(self.gpu_layers),
            "--main-gpu", str(self.main_gpu),
            "--parallel", "1",
            "--cache-type-k", self.cache_type_k,
            "--cache-type-v", self.cache_type_v,
            "--timeout", str(max(30, int(self.timeout or 1200))),
        ]
        if self.use_jinja:
            args.append("--jinja")
        if self.model_type.lower() == "qwen" and self.disable_thinking:
            args.extend(["--chat-template-kwargs", '{"enable_thinking": false}'])
        if not self.use_mmap:
            args.append("--no-mmap")
        if self.use_mlock:
            args.append("--mlock")
        if self.no_kv_offload:
            args.append("--no-kv-offload")
        # Pascal-class GPUs (GTX 1080 Ti) must not enable flash attention.
        args.extend(["--flash-attn", "on" if self.flash_attention else "off"])
        tensor_split = str(self.tensor_split or "").strip()
        if tensor_split and int(self.gpu_layers or 0) != 0:
            args.extend(["--tensor-split", tensor_split, "--split-mode", "layer"])
        elif int(self.gpu_layers or 0) != 0:
            args.extend(["--split-mode", "layer"])
        return args
    
@dataclass
class WebConfig:
    """Web server configuration"""
    username: str = ""
    password: str = ""
    host: str = "127.0.0.1"
    port: int = 8000
    
    def validate(self) -> Tuple[bool, str]:
        """Validate web configuration"""
        if not self.username:
            return False, "Web username cannot be empty"
        if not self.password:
            return False, "Web password cannot be empty"
        if not isinstance(self.host, str) or not self.host.strip():
            return False, "Web host cannot be empty"
        if any(character.isspace() for character in self.host):
            return False, "Web host cannot contain whitespace"
        if not (1 <= self.port <= 65535):
            return False, "Web port must be between 1 and 65535"
        return True, "Web config is valid"


@dataclass
class PathConfig:
    """File paths configuration"""
    reports_dir: str = field(default_factory=lambda: str(STATE_ROOT / "reports"))
    templates_dir: str = field(default_factory=lambda: str(CONFIG_DIR / "templates"))
    uploads_dir: str = field(default_factory=lambda: str(STATE_ROOT / "uploads"))
    geoip_db_path: str = ""

    def validate(self) -> Tuple[bool, str]:
        """Validate path configuration and create directories if needed"""
        templates = Path(self.templates_dir)
        if not templates.is_dir():
            return False, "Configured templates directory does not exist"

        for name, path in {"reports": self.reports_dir, "uploads": self.uploads_dir}.items():
            if not path:
                return False, f"{name.capitalize()} directory path cannot be empty"
            
            path_obj = Path(path)
            try:
                path_obj.mkdir(parents=True, exist_ok=True, mode=0o750)
                path_obj.chmod(0o750)
            except Exception as e:
                return False, f"Cannot create configured {name} directory ({type(e).__name__})"
        
        return True, "Path config is valid"


@dataclass
class RuntimeConfig:
    """Operational limits for uploads and transient in-process state."""

    max_alert_upload_bytes: int = 5 * 1024 * 1024
    max_alert_records: int = 1000
    max_document_files: int = 50
    max_document_batch_bytes: int = 100 * 1024 * 1024
    max_drafts: int = 100
    max_session_results: int = 200
    max_background_tasks: int = 8
    max_current_alert_lines: int = 1000
    max_current_alert_bytes: int = 20 * 1024 * 1024
    max_alert_line_bytes: int = 1024 * 1024
    max_archive_days: int = 31
    max_archive_records: int = 100000
    max_archive_bytes: int = 100 * 1024 * 1024
    max_archive_line_bytes: int = 1024 * 1024
    max_worker_threads: int = 4

    def validate(self) -> Tuple[bool, str]:
        values = {
            "max alert upload bytes": self.max_alert_upload_bytes,
            "max alert records": self.max_alert_records,
            "max document files": self.max_document_files,
            "max document batch bytes": self.max_document_batch_bytes,
            "max drafts": self.max_drafts,
            "max session results": self.max_session_results,
            "max background tasks": self.max_background_tasks,
            "max current alert lines": self.max_current_alert_lines,
            "max current alert bytes": self.max_current_alert_bytes,
            "max alert line bytes": self.max_alert_line_bytes,
            "max archive days": self.max_archive_days,
            "max archive records": self.max_archive_records,
            "max archive bytes": self.max_archive_bytes,
            "max archive line bytes": self.max_archive_line_bytes,
            "max worker threads": self.max_worker_threads,
        }
        invalid = [name for name, value in values.items() if int(value) <= 0]
        if invalid:
            return False, f"Runtime limits must be positive: {', '.join(invalid)}"
        return True, "Runtime config is valid"


@dataclass
class RAGConfig:
    """RAG configuration"""
    document_chunk_size: int = 1200
    document_chunk_overlap: int = 120
    embedding_model: str = "Qwen/Qwen3-Embedding-0.6B"
    embedding_device: str = "cpu"
    embedding_devices: List[str] = field(default_factory=list)
    embedding_dimensions: int = 1024
    embedding_batch_size: int = 4
    embedding_multi_gpu_min_chunks: int = 64
    max_retrieval_docs: int = 10
    normalize_embeddings: bool = True
    # Candidate-generation floor. Deliberately permissive: it only decides which
    # rows leave PostgreSQL, and hybrid merging/reranking runs afterwards.
    similarity_threshold: float = 0.2
    # Final evidence floor applied to semantic-only hits after hybrid merging.
    # Rows carrying an exact IoC match or a lexical match are never dropped by
    # this threshold. PROVISIONAL: calibrate with tools/calibrate_similarity.py
    # against the deployed corpus before trusting the default.
    evidence_similarity_threshold: float = 0.35
    # Emit per-query similarity distributions to the retrieval log so the
    # threshold above can be measured rather than guessed.
    similarity_instrumentation: bool = False
    retrieval_candidate_multiplier: int = 4
    # Upper bound on OR-composed lexical terms per full-text query. Keeps the
    # generated tsquery small enough to stay planner-friendly.
    max_lexical_terms: int = 24
    # Row cap for the broad ILIKE exact-document arm so a low-selectivity
    # pattern cannot stream a large share of the corpus into Python.
    max_exact_match_rows: int = 200

    # --- Vector index lifecycle (see _ensure_vector_indexes in report.py) ---
    # "ivfflat" | "hnsw" | "none". IVFFlat builds fast and is cheap to rebuild,
    # which suits a corpus that is periodically rebuilt from scratch. HNSW gives
    # better recall at a fixed latency but costs far more to build and cannot be
    # retrained incrementally, so it is opt-in rather than automatic.
    vector_index_type: str = "ivfflat"
    # Below this row count an exact sequential scan beats any approximate index,
    # and an IVFFlat index trained on a near-empty table has useless centroids.
    vector_index_min_rows: int = 1000
    # 0 = derive from row count (pgvector guidance: rows/1000 up to 1M rows).
    ivfflat_lists: int = 0
    # 0 = derive as sqrt(lists). More probes = better recall, linear latency cost.
    ivfflat_probes: int = 0
    hnsw_m: int = 16
    hnsw_ef_construction: int = 64
    # 0 = leave the server default (40).
    hnsw_ef_search: int = 0
    # Rebuild the index when the corpus has grown/shrunk by this factor since
    # the index was last trained, because IVFFlat centroids go stale.
    vector_index_rebuild_ratio: float = 3.0
    embedding_query_instruction: str = (
        "Retrieve cybersecurity incidents, IoCs, TTPs, and CTI passages relevant "
        "to this SOC alert."
    )
    embedding_document_instruction: str = ""

    def validate(self) -> Tuple[bool, str]:
        """Validate RAG configuration"""
        if self.document_chunk_size <= 0:
            return False, "Document chunk size must be positive"
        if self.document_chunk_overlap < 0:
            return False, "Document chunk overlap cannot be negative"
        if self.document_chunk_overlap >= self.document_chunk_size:
            return False, "Document chunk overlap must be less than document chunk size"
        if not self.embedding_model:
            return False, "Embedding model cannot be empty"
        if not self.embedding_device:
            return False, "Embedding device cannot be empty"
        if self.embedding_devices is None:
            self.embedding_devices = []
        if not isinstance(self.embedding_devices, list):
            return False, "Embedding devices must be a list"
        if any(not str(device).strip() for device in self.embedding_devices):
            return False, "Embedding devices cannot contain empty values"
        if self.embedding_dimensions <= 0:
            return False, "Embedding dimensions must be positive"
        if self.embedding_batch_size <= 0:
            return False, "Embedding batch size must be positive"
        if self.embedding_multi_gpu_min_chunks <= 0:
            return False, "Embedding multi-GPU minimum chunks must be positive"
        if self.max_retrieval_docs <= 0:
            return False, "Max retrieval docs must be positive"
        if not (0.0 <= self.similarity_threshold <= 1.0):
            return False, "Similarity threshold must be between 0.0 and 1.0"
        if not (0.0 <= self.evidence_similarity_threshold <= 1.0):
            return False, "Evidence similarity threshold must be between 0.0 and 1.0"
        if self.evidence_similarity_threshold < self.similarity_threshold:
            return False, (
                "Evidence similarity threshold must be at least the candidate "
                "similarity threshold"
            )
        if self.retrieval_candidate_multiplier <= 0:
            return False, "Retrieval candidate multiplier must be positive"
        if self.max_lexical_terms <= 0:
            return False, "Max lexical terms must be positive"
        if self.max_exact_match_rows <= 0:
            return False, "Max exact match rows must be positive"
        if str(self.vector_index_type).lower() not in ("ivfflat", "hnsw", "none"):
            return False, "Vector index type must be one of: ivfflat, hnsw, none"
        if self.vector_index_min_rows < 0:
            return False, "Vector index minimum rows cannot be negative"
        if self.ivfflat_lists < 0:
            return False, "IVFFlat lists cannot be negative"
        if self.ivfflat_probes < 0:
            return False, "IVFFlat probes cannot be negative"
        if self.hnsw_m <= 0:
            return False, "HNSW m must be positive"
        if self.hnsw_ef_construction <= 0:
            return False, "HNSW ef_construction must be positive"
        if self.hnsw_ef_search < 0:
            return False, "HNSW ef_search cannot be negative"
        if self.vector_index_rebuild_ratio < 1.0:
            return False, "Vector index rebuild ratio must be at least 1.0"
        return True, "RAG config is valid"


class ConfigManager:
    """Main configuration manager"""
    
    def __init__(self, config_file: str = None):
        self.config_file = Path(config_file) if config_file else None
        self.dotenv_files_loaded: List[str] = []
        self._explicit_path_fields: set[str] = set()
        
        # Initialize with defaults
        self.ssh = SSHConfig()
        self.wazuh = WazuhConfig()
        self.llm = LLMConfig()
        self.web = WebConfig()
        self.paths = PathConfig()
        self.rag = RAGConfig()
        self.database = DatabaseConfig()
        self.asset_inventory = AssetInventoryConfig()
        self.runtime = RuntimeConfig()
        
        # Load from file if provided
        if self.config_file:
            if not self.config_file.is_file():
                raise FileNotFoundError(f"Configuration file not found: {self.config_file}")
            self.load_from_file()
        
        # Load local .env files before applying environment mappings. Actual
        # process environment variables still take precedence over .env values.
        self.load_dotenv_files()
        self._apply_environment_state_root_defaults()

        # Load from environment variables
        self.load_from_env()

    def _apply_environment_state_root_defaults(self) -> None:
        """Apply XDG_STATE_HOME loaded from ENV_FILE without replacing explicit paths."""
        state_root = _state_root_from_environment()
        if "reports_dir" not in self._explicit_path_fields:
            self.paths.reports_dir = str(state_root / "reports")
        if "uploads_dir" not in self._explicit_path_fields:
            self.paths.uploads_dir = str(state_root / "uploads")

    @staticmethod
    def _parse_dotenv_line(line: str) -> Optional[Tuple[str, str]]:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            return None
        if stripped.startswith("export "):
            stripped = stripped[7:].strip()
        if "=" not in stripped:
            return None

        key, value = stripped.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not key:
            return None

        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        else:
            value = value.split(" #", 1)[0].strip()

        return key, value

    def _dotenv_candidates(self) -> List[Path]:
        config_dir = Path(__file__).resolve().parent
        candidates = [
            config_dir.parents[1] / ".env",  # repository/project root
            config_dir.parent / ".env",      # Linux_LLM/.env
            config_dir / ".env",             # Linux_LLM/config/.env
            Path.cwd() / ".env",
        ]

        if self.config_file:
            candidates.append(self.config_file.resolve().parent / ".env")

        env_file = os.getenv("ENV_FILE")
        if env_file:
            candidates.append(Path(env_file).expanduser())

        unique_candidates = []
        seen = set()
        for candidate in candidates:
            resolved_key = str(candidate.expanduser().resolve()) if candidate.expanduser().exists() else str(candidate.expanduser())
            if resolved_key not in seen:
                seen.add(resolved_key)
                unique_candidates.append(candidate)
        return unique_candidates

    def load_dotenv_files(self) -> List[str]:
        """Load .env values into os.environ without overriding real env vars."""
        dotenv_values: Dict[str, str] = {}
        loaded_files: List[str] = []

        for candidate in self._dotenv_candidates():
            path = candidate.expanduser()
            if not path.exists() or not path.is_file():
                continue

            try:
                with open(path, "r", encoding="utf-8") as f:
                    for line in f:
                        parsed = self._parse_dotenv_line(line)
                        if parsed:
                            key, value = parsed
                            dotenv_values[key] = value
                loaded_files.append(str(path))
            except Exception as e:
                print(f"WARNING: Failed to load a .env file ({type(e).__name__})")

        for key, value in dotenv_values.items():
            os.environ.setdefault(key, value)

        self.dotenv_files_loaded = loaded_files
        if loaded_files:
            print(f"Loaded configuration from {len(loaded_files)} .env file(s)")
        return loaded_files
    
    def load_from_file(self, config_file: str = None) -> bool:
        """Load configuration from JSON file"""
        file_path = Path(config_file) if config_file else self.config_file
        
        if not file_path or not file_path.is_file():
            raise FileNotFoundError(f"Configuration file not found: {file_path}")
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                config_data = json.load(f)
            if not isinstance(config_data, dict):
                raise ValueError("Configuration root must be a JSON object")

            sections = {
                'ssh': SSHConfig,
                'wazuh': WazuhConfig,
                'llm': LLMConfig,
                'web': WebConfig,
                'paths': PathConfig,
                'rag': RAGConfig,
                'database': DatabaseConfig,
                'asset_inventory': AssetInventoryConfig,
                'runtime': RuntimeConfig,
            }
            loaded = {}
            for name, section_type in sections.items():
                value = config_data.get(name)
                if value is None:
                    loaded[name] = getattr(self, name)
                    continue
                if not isinstance(value, dict):
                    raise ValueError(f"Configuration section '{name}' must be an object")
                if name == "paths":
                    self._explicit_path_fields.update(value)
                loaded[name] = section_type(**value)

            for name, value in loaded.items():
                setattr(self, name, value)
            
            print("Configuration file loaded")
            return True
            
        except (OSError, json.JSONDecodeError, TypeError, ValueError) as error:
            raise ValueError(f"Invalid configuration file ({type(error).__name__})") from error
    
    def load_from_env(self):
        """Load configuration from environment variables"""
        env_mappings = {
            # SSH config
            'SSH_HOST': ('ssh', 'host'),
            'SSH_USERNAME': ('ssh', 'username'),
            'SSH_PASSWORD': ('ssh', 'password'),
            'SSH_PORT': ('ssh', 'port', int),
            'SSH_TIMEOUT': ('ssh', 'timeout', int),
            'SSH_ALLOW_UNKNOWN_HOST': ('ssh', 'allow_unknown_host', _parse_bool),
            'SSH_KNOWN_HOSTS_PATH': ('ssh', 'known_hosts_path'),
            
            # Wazuh config
            'WAZUH_ALERTS_PATH': ('wazuh', 'alerts_file_path'),
            'WAZUH_ARCHIVES_PATH': ('wazuh', 'archives_base_path'),
            
            # LLM config
            'LLM_MODEL_PATH': ('llm', 'model_path'),
            'LLM_BINARY_PATH': ('llm', 'llama_cpp_path'),
            'LLM_TEMPERATURE': ('llm', 'temperature', float),
            'LLM_TOP_P': ('llm', 'top_p', float),
            'LLM_TOP_K': ('llm', 'top_k', int),
            'LLM_CONTEXT_SIZE': ('llm', 'context_size', int),
            'LLM_MAX_TOKENS': ('llm', 'max_tokens', int),
            'LLM_TIMEOUT': ('llm', 'timeout', int),
            'LLM_PROMPT_SAFETY_MARGIN_TOKENS': ('llm', 'prompt_safety_margin_tokens', int),
            'LLM_PROMPT_CHARS_PER_TOKEN': ('llm', 'prompt_chars_per_token', float),
            'LLM_PROMPT_UNBOUNDED_OUTPUT_RESERVE_TOKENS': ('llm', 'prompt_unbounded_output_reserve_tokens', int),
            'LLM_GPU_LAYERS': ('llm', 'gpu_layers', int),
            'LLM_MAIN_GPU': ('llm', 'main_gpu', int),
            'LLM_TENSOR_SPLIT': ('llm', 'tensor_split'),
            'LLM_INFERENCE_BACKEND': ('llm', 'inference_backend'),
            'LLM_SERVER_URL': ('llm', 'llama_server_url'),
            'LLM_SERVER_HOST': ('llm', 'llama_server_host'),
            'LLM_SERVER_PORT': ('llm', 'llama_server_port', int),
            'LLM_SERVER_AUTOSTART': ('llm', 'llama_server_autostart', _parse_bool),
            'LLM_SERVER_PATH': ('llm', 'llama_server_path'),
            'LLM_FLASH_ATTENTION': ('llm', 'flash_attention', _parse_bool),
            'LLM_DISABLE_THINKING': ('llm', 'disable_thinking', _parse_bool),
            'LLM_DEBUG_COMMANDS': ('llm', 'debug_commands', _parse_bool),
            
            # Web config
            'WEB_USERNAME': ('web', 'username'),
            'WEB_PASSWORD': ('web', 'password'),
            'WEB_HOST': ('web', 'host'),
            'WEB_PORT': ('web', 'port', int),
            
            # Path config
            'REPORTS_DIR': ('paths', 'reports_dir'),
            'TEMPLATES_DIR': ('paths', 'templates_dir'),
            'UPLOADS_DIR': ('paths', 'uploads_dir'),
            'GEOIP_DB_PATH': ('paths', 'geoip_db_path'),
            
            # RAG config
            'RAG_DOCUMENT_CHUNK_SIZE': ('rag', 'document_chunk_size', int),
            'RAG_DOCUMENT_CHUNK_OVERLAP': ('rag', 'document_chunk_overlap', int),
            'RAG_EMBEDDING_MODEL': ('rag', 'embedding_model'),
            'RAG_EMBEDDING_DEVICE': ('rag', 'embedding_device'),
            'RAG_EMBEDDING_DEVICES': ('rag', 'embedding_devices', lambda v: [item.strip() for item in v.split(',') if item.strip()]),
            'RAG_EMBEDDING_DIMENSIONS': ('rag', 'embedding_dimensions', int),
            'RAG_EMBEDDING_BATCH_SIZE': ('rag', 'embedding_batch_size', int),
            'RAG_EMBEDDING_MULTI_GPU_MIN_CHUNKS': ('rag', 'embedding_multi_gpu_min_chunks', int),
            'RAG_MAX_DOCS': ('rag', 'max_retrieval_docs', int),
            'RAG_SIMILARITY_THRESHOLD': ('rag', 'similarity_threshold', float),
            'RAG_EVIDENCE_SIMILARITY_THRESHOLD': ('rag', 'evidence_similarity_threshold', float),
            'RAG_SIMILARITY_INSTRUMENTATION': ('rag', 'similarity_instrumentation', _parse_bool),
            'RAG_MAX_LEXICAL_TERMS': ('rag', 'max_lexical_terms', int),
            'RAG_MAX_EXACT_MATCH_ROWS': ('rag', 'max_exact_match_rows', int),
            'RAG_VECTOR_INDEX_TYPE': ('rag', 'vector_index_type'),
            'RAG_VECTOR_INDEX_MIN_ROWS': ('rag', 'vector_index_min_rows', int),
            'RAG_IVFFLAT_LISTS': ('rag', 'ivfflat_lists', int),
            'RAG_IVFFLAT_PROBES': ('rag', 'ivfflat_probes', int),
            'RAG_HNSW_M': ('rag', 'hnsw_m', int),
            'RAG_HNSW_EF_CONSTRUCTION': ('rag', 'hnsw_ef_construction', int),
            'RAG_HNSW_EF_SEARCH': ('rag', 'hnsw_ef_search', int),
            'RAG_VECTOR_INDEX_REBUILD_RATIO': ('rag', 'vector_index_rebuild_ratio', float),
            'RAG_NORMALIZE_EMBEDDINGS': ('rag', 'normalize_embeddings', _parse_bool),
            'RAG_RETRIEVAL_CANDIDATE_MULTIPLIER': ('rag', 'retrieval_candidate_multiplier', int),
            'RAG_EMBEDDING_QUERY_INSTRUCTION': ('rag', 'embedding_query_instruction'),
            'RAG_EMBEDDING_DOCUMENT_INSTRUCTION': ('rag', 'embedding_document_instruction'),

            # Database config
            'DB_HOST': ('database', 'host'),
            'DB_PORT': ('database', 'port', int),
            'DB_NAME': ('database', 'database'),
            'DB_DATABASE': ('database', 'database'),
            'DB_USER': ('database', 'user'),
            'DB_PASSWORD': ('database', 'password'),
            'DB_CONNECT_TIMEOUT': ('database', 'connect_timeout', int),
            'DB_AUTO_CREATE': ('database', 'auto_create_database', _parse_bool),

            # Asset inventory config
            'ASSET_OWNED_CIDRS': ('asset_inventory', 'owned_cidrs', lambda v: [item.strip() for item in v.split(',') if item.strip()]),
            'ASSET_INFRASTRUCTURE_IPS': ('asset_inventory', 'infrastructure_ips', lambda v: [item.strip() for item in v.split(',') if item.strip()]),
            'ASSET_INTERNAL_CIDRS': ('asset_inventory', 'internal_cidrs', lambda v: [item.strip() for item in v.split(',') if item.strip()]),

            # Runtime safety limits
            'MAX_ALERT_UPLOAD_BYTES': ('runtime', 'max_alert_upload_bytes', int),
            'MAX_ALERT_RECORDS': ('runtime', 'max_alert_records', int),
            'MAX_DOCUMENT_FILES': ('runtime', 'max_document_files', int),
            'MAX_DOCUMENT_BATCH_BYTES': ('runtime', 'max_document_batch_bytes', int),
            'MAX_DRAFTS': ('runtime', 'max_drafts', int),
            'MAX_SESSION_RESULTS': ('runtime', 'max_session_results', int),
            'MAX_BACKGROUND_TASKS': ('runtime', 'max_background_tasks', int),
            'MAX_CURRENT_ALERT_LINES': ('runtime', 'max_current_alert_lines', int),
            'MAX_CURRENT_ALERT_BYTES': ('runtime', 'max_current_alert_bytes', int),
            'MAX_ALERT_LINE_BYTES': ('runtime', 'max_alert_line_bytes', int),
            'MAX_ARCHIVE_DAYS': ('runtime', 'max_archive_days', int),
            'MAX_ARCHIVE_RECORDS': ('runtime', 'max_archive_records', int),
            'MAX_ARCHIVE_BYTES': ('runtime', 'max_archive_bytes', int),
            'MAX_ARCHIVE_LINE_BYTES': ('runtime', 'max_archive_line_bytes', int),
            'MAX_WORKER_THREADS': ('runtime', 'max_worker_threads', int),
        }
        
        for env_var, mapping in env_mappings.items():
            if env_var == 'DB_DATABASE' and os.getenv('DB_NAME') is not None:
                continue
            env_value = os.getenv(env_var)
            if env_value is not None:
                section, attr = mapping[0], mapping[1]
                converter = mapping[2] if len(mapping) > 2 else str
                
                try:
                    converted_value = converter(env_value)
                    setattr(getattr(self, section), attr, converted_value)
                    print(f"Loaded from env: {env_var} -> {section}.{attr}")
                except (ValueError, TypeError) as error:
                    raise ValueError(f"Invalid value for environment variable {env_var}") from error
    
    def validate_all(self) -> Tuple[bool, list[str]]:
        """Validate all configuration sections"""
        errors = []
        
        configs = [
            ('SSH', self.ssh),
            ('Wazuh', self.wazuh),
            ('LLM', self.llm),
            ('Web', self.web),
            ('Paths', self.paths),
            ('RAG', self.rag),
            ('Database', self.database),
            ('AssetInventory', self.asset_inventory),
            ('Runtime', self.runtime),
        ]
        
        for name, config in configs:
            is_valid, message = config.validate()
            if not is_valid:
                errors.append(f"{name}: {message}")

        templates_dir = Path(self.paths.templates_dir)
        prompt_path = templates_dir / self.llm.system_prompt_file
        template_path = templates_dir / self.llm.chat_template_file
        if not prompt_path.is_file():
            errors.append("Paths: Configured system prompt was not found")
        if self.llm.use_custom_template and not template_path.is_file():
            errors.append("Paths: Configured chat template was not found")
        
        return len(errors) == 0, errors

    def get_production_warnings(self) -> List[str]:
        """Return non-blocking warnings for settings that are unsafe in production."""
        warnings = []

        if self.web.host in ("0.0.0.0", "::"):
            warnings.append(
                "Web server is bound to all interfaces. Put it behind TLS/reverse proxy controls before exposing it."
            )
        if self.ssh.allow_unknown_host:
            warnings.append(
                "SSH unknown host keys are allowed. Set SSH_KNOWN_HOSTS_PATH or install host keys before production use."
            )

        if not Path(self.llm.model_path).exists():
            warnings.append("Configured LLM model path does not exist.")
        if not Path(self.llm.llama_cpp_path).exists():
            warnings.append("Configured llama.cpp binary path does not exist.")
        if self.paths.geoip_db_path and not Path(self.paths.geoip_db_path).exists():
            warnings.append("Configured optional GeoIP database path does not exist.")
        if not self.asset_inventory.owned_cidrs:
            warnings.append(
                "No owned asset CIDRs are configured; traffic direction and remediation remain conservative."
            )
        if not self.asset_inventory.infrastructure_ips:
            warnings.append(
                "No monitoring infrastructure IPs are configured; sensor-noise suppression may be incomplete."
            )

        return warnings
    
    def get_summary(self) -> Dict[str, Any]:
        """Get configuration summary"""
        return {
            'ssh': {
                'configured': bool(self.ssh.host and self.ssh.username),
                'port': self.ssh.port,
                'timeout': self.ssh.timeout,
                'allow_unknown_host': self.ssh.allow_unknown_host,
                'known_hosts_configured': bool(self.ssh.known_hosts_path),
            },
            'wazuh': {
                'alerts_path_configured': bool(self.wazuh.alerts_file_path),
                'archives_path_configured': bool(self.wazuh.archives_base_path),
            },
            'llm': {
                'model_configured': bool(getattr(self.llm, 'model_path', None)),
                'binary_configured': bool(getattr(self.llm, 'llama_cpp_path', None)),
                'inference_backend': getattr(self.llm, 'inference_backend', 'auto'),
                'server_configured': bool(
                    getattr(self.llm, 'llama_server_url', None)
                    or (
                        callable(getattr(self.llm, 'resolved_llama_server_path', None))
                        and self.llm.resolved_llama_server_path()
                    )
                ),
                'gpu_layers': getattr(self.llm, 'gpu_layers', 0),
                'context_size': getattr(self.llm, 'context_size', None),
                'max_tokens': getattr(self.llm, 'max_tokens', None),
                'temperature': getattr(self.llm, 'temperature', None),
                'disable_thinking': getattr(self.llm, 'disable_thinking', None)
            },
            'web': {
                'binding_scope': (
                    'loopback'
                    if self.web.host in ('127.0.0.1', '::1', 'localhost')
                    else 'all_interfaces'
                    if self.web.host in ('0.0.0.0', '::')
                    else 'custom_interface'
                ),
                'port': self.web.port,
                'authentication_configured': bool(self.web.username and self.web.password),
            },
            'paths': {
                'reports_configured': bool(self.paths.reports_dir),
                'templates_configured': bool(self.paths.templates_dir),
                'uploads_configured': bool(self.paths.uploads_dir),
                'geoip_configured': bool(self.paths.geoip_db_path),
            },
            'rag': {
                'document_chunk_size': self.rag.document_chunk_size,
                'embedding_model_configured': bool(self.rag.embedding_model),
                'embedding_device': self.rag.embedding_device,
                'bulk_embedding_device_count': len(self.rag.embedding_devices or []),
                'embedding_dimensions': self.rag.embedding_dimensions,
                'embedding_batch_size': self.rag.embedding_batch_size,
                'embedding_multi_gpu_min_chunks': self.rag.embedding_multi_gpu_min_chunks,
                'normalize_embeddings': self.rag.normalize_embeddings,
                'max_docs': self.rag.max_retrieval_docs,
                'similarity_threshold': self.rag.similarity_threshold,
                'retrieval_candidate_multiplier': self.rag.retrieval_candidate_multiplier,
                'query_instruction_enabled': bool(self.rag.embedding_query_instruction)
            },
            'database': {
                'port': self.database.port,
                'configured': bool(
                    self.database.host and self.database.database
                    and self.database.user and self.database.password
                ),
                'connect_timeout': self.database.connect_timeout,
                'auto_create_database': self.database.auto_create_database,
            },
            'asset_inventory': {
                'owned_cidr_count': len(self.asset_inventory.owned_cidrs),
                'infrastructure_ip_count': len(self.asset_inventory.infrastructure_ips),
                'internal_cidr_count': len(self.asset_inventory.internal_cidrs),
            },
            'runtime_limits': {
                'max_alert_upload_bytes': self.runtime.max_alert_upload_bytes,
                'max_alert_records': self.runtime.max_alert_records,
                'max_document_files': self.runtime.max_document_files,
                'max_document_batch_bytes': self.runtime.max_document_batch_bytes,
                'max_drafts': self.runtime.max_drafts,
                'max_session_results': self.runtime.max_session_results,
                'max_background_tasks': self.runtime.max_background_tasks,
                'max_current_alert_lines': self.runtime.max_current_alert_lines,
                'max_current_alert_bytes': self.runtime.max_current_alert_bytes,
                'max_alert_line_bytes': self.runtime.max_alert_line_bytes,
                'max_archive_days': self.runtime.max_archive_days,
                'max_archive_records': self.runtime.max_archive_records,
                'max_archive_bytes': self.runtime.max_archive_bytes,
                'max_archive_line_bytes': self.runtime.max_archive_line_bytes,
                'max_worker_threads': self.runtime.max_worker_threads,
            },
            'production_warnings': self.get_production_warnings(),
            'dotenv_file_count': len(self.dotenv_files_loaded),
        }


# Configuration validation utility
def validate_environment() -> Tuple[bool, list[str]]:
    """Validate that the environment meets requirements"""
    issues = []
    
    # Check the modules imported by the cleaned application runtime.
    required_packages = [
        "fastapi",
        "uvicorn",
        "websockets",
        "paramiko",
        "pymupdf",
        "jinja2",
        "geoip2",
        "psycopg2",
        "sentence_transformers",
        "matplotlib",
        "pandas",
    ]

    for package in required_packages:
        try:
            __import__(package)
        except Exception as e:
            issues.append(f"Missing or unusable required package: {package} ({type(e).__name__})")

    optional_packages = [
        "weasyprint",
        "markdown",
        "pypdf",
        "yaml",
    ]

    for package in optional_packages:
        try:
            __import__(package)
        except Exception as e:
            print(f"Optional package unavailable: {package} ({type(e).__name__})")
    
    return len(issues) == 0, issues
