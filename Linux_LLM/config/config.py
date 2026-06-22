import os
import json
from pathlib import Path
from typing import Dict, Any, Optional, Tuple, List
from dataclasses import dataclass, asdict
from datetime import datetime

@dataclass
class DatabaseConfig:
    host: str = "localhost"
    port: int = 5432
    database: str = "soc_rag"
    user: str = "soc_user"
    password: str = "StudentPass4721"
    
    def validate(self) -> Tuple[bool, str]:
        if not self.host:
            return False, "Database host cannot be empty"
        if not self.database:
            return False, "Database name cannot be empty"
        if not (1 <= self.port <= 65535):
            return False, "Database port must be between 1 and 65535"
        return True, "Database config is valid"
    
    def get_dict(self) -> dict:
        return {
            "host": self.host,
            "port": self.port,
            "database": self.database,
            "user": self.user,
            "password": self.password
        }
@dataclass
class SSHConfig:
    """SSH connection configuration"""
    host: str = "100.78.175.127"
    username: str = "wazuh-user"
    password: str = "wazuh"
    port: int = 22
    timeout: int = 30
    
    def validate(self) -> Tuple[bool, str]:
        """Validate SSH configuration"""
        if not self.host:
            return False, "SSH host cannot be empty"
        if not self.username:
            return False, "SSH username cannot be empty"
        if not self.password:
            return False, "SSH password cannot be empty"
        if not (1 <= self.port <= 65535):
            return False, "SSH port must be between 1 and 65535"
        if self.timeout <= 0:
            return False, "SSH timeout must be positive"
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
    owned_cidrs: List[str] = None
    infrastructure_ips: List[str] = None
    internal_cidrs: List[str] = None

    def __post_init__(self):
        if self.owned_cidrs is None:
            self.owned_cidrs = [
                "66.96.0.0/16",
                "129.126.144.226/32",
            ]
        if self.infrastructure_ips is None:
            self.infrastructure_ips = [
                "192.168.56.104",  # Suricata NIDS sensor
                "192.168.56.1",    # Lab gateway
            ]
        if self.internal_cidrs is None:
            self.internal_cidrs = [
                "10.0.0.0/8",
                "172.16.0.0/12",
                "192.168.0.0/16",
                "127.0.0.0/8",
            ]

    def validate(self) -> Tuple[bool, str]:
        import ipaddress

        try:
            for cidr in self.owned_cidrs + self.internal_cidrs:
                ipaddress.ip_network(cidr, strict=False)
            for ip_value in self.infrastructure_ips:
                ipaddress.ip_address(ip_value)
        except ValueError as e:
            return False, f"Invalid asset inventory entry: {e}"
        return True, "Asset inventory config is valid"


@dataclass
class LLMConfig:
    model_path: str = "/home/student/Desktop/Qwen3-30B-A3B-Instruct-2507-Q8_0.gguf"
    llama_cpp_path: str = "/home/student/Desktop/llama.cpp/build/bin/llama-cli"
    temperature: float = 0.7
    top_p: float = 0.8
    top_k: int = 20
    context_size: int = 8192
    max_tokens: int = -2
    timeout: int = 1200
    
    model_type: str = "qwen"  
    
    use_custom_template: bool = True  
    chat_template_file: str = "qwen_chat.j2"  
    system_prompt_file: str = "cti.txt"
    
    no_display_prompt: bool = True  
    single_turn: bool = True     
    use_jinja: bool = True         
    conversation_mode: bool = False 
    
    gpu_layers: int = 99
    main_gpu: int = 0
    tensor_split: Optional[str] = "0.7,1.1,1.1,1.1"
    
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
    
    def validate(self) -> Tuple[bool, str]:
        """Validate LLM configuration"""
        if not self.model_path or not Path(self.model_path).exists():
            return False, f"Model file not found: {self.model_path}"
        if not self.llama_cpp_path or not Path(self.llama_cpp_path).exists():
            return False, f"Llama.cpp binary not found: {self.llama_cpp_path}"
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
        if self.gpu_layers < 0:
            return False, "GPU layers must be non-negative"
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
    
    def get_llama_args(self, templates_dir: str = None, custom_template_path: str = None) -> list[str]:
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
            "--gpu-layers", str(self.gpu_layers),  # Fixed typo from gpu_layers
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
        if self.tensor_split:
            args.extend(["--tensor-split", self.tensor_split])
        
        return args
    
    def get_model_specific_settings(self) -> Dict[str, Any]:
        """Get model-specific optimization settings"""
        model_settings = {
            "gemma": {
                "recommended_context": 8192,
                "recommended_temp": 0.7,
                "recommended_top_p": 0.95,
                "chat_template": "gemma_chat.j2",
                "system_handling": "user_message_wrap"  # Gemma doesn't have explicit system role
            },
            "qwen": {
                "recommended_context": 8192,
                "recommended_temp": 0.7,
                "recommended_top_p": 0.9,
                "chat_template": "qwen_chat.j2",
                "system_handling": "dedicated_system_role"
            }
        }
        
        return model_settings.get(self.model_type.lower(), model_settings["gemma"])
    
    def optimize_for_model(self):
        """Apply model-specific optimizations"""
        settings = self.get_model_specific_settings()
        
        # Apply recommended settings
        if self.context_size == 8192:  # Only if using default
            self.context_size = settings["recommended_context"]
        if self.temperature == 0.7:  # Only if using default
            self.temperature = settings["recommended_temp"]
        if self.top_p == 0.95:  # Only if using default
            self.top_p = settings["recommended_top_p"]
        
        # Update chat template
        self.chat_template_file = settings["chat_template"]
        
        print(f"✅ Optimized config for {self.model_type} model")


@dataclass
class WebConfig:
    """Web server configuration"""
    username: str = "admin"
    password: str = "admin"
    host: str = "0.0.0.0"
    port: int = 8000
    
    def validate(self) -> Tuple[bool, str]:
        """Validate web configuration"""
        if not self.username:
            return False, "Web username cannot be empty"
        if not self.password:
            return False, "Web password cannot be empty"
        if not (1 <= self.port <= 65535):
            return False, "Web port must be between 1 and 65535"
        return True, "Web config is valid"


@dataclass
class PathConfig:
    """File paths configuration"""
    reports_dir: str = "/home/student/Desktop/ICT2114_Team5/Linux_LLM/reports"
    templates_dir: str = "/home/student/Desktop/ICT2114_Team5/Linux_LLM/config/templates"
    uploads_dir: str = "/home/student/Desktop/ICT2114_Team5/Linux_LLM/uploads"
    geoip_db_path: str = "/home/student/Desktop/GeoLite2-City.mmdb"

    def validate(self) -> Tuple[bool, str]:
        """Validate path configuration and create directories if needed"""
        paths = {
            "reports": self.reports_dir,
            "templates": self.templates_dir,
            "uploads": self.uploads_dir
        }
        
        for name, path in paths.items():
            if not path:
                return False, f"{name.capitalize()} directory path cannot be empty"
            
            path_obj = Path(path)
            try:
                path_obj.mkdir(parents=True, exist_ok=True)
            except Exception as e:
                return False, f"Cannot create {name} directory {path}: {e}"
        
        return True, "Path config is valid"


@dataclass
class RAGConfig:
    """RAG configuration"""
    chunk_size: int = 500
    chunk_overlap: int = 50
    document_chunk_size: int = 1200
    document_chunk_overlap: int = 120
    embedding_model: str = "Qwen/Qwen3-Embedding-0.6B"
    embedding_device: str = "cuda"
    embedding_devices: List[str] = None
    embedding_dimensions: int = 1024
    embedding_batch_size: int = 16
    embedding_multi_gpu_min_chunks: int = 64
    max_retrieval_docs: int = 10
    normalize_embeddings: bool = False
    similarity_threshold: float = 0.2
    retrieval_candidate_multiplier: int = 4
    embedding_query_instruction: str = (
        "Retrieve cybersecurity incidents, IoCs, TTPs, and CTI passages relevant "
        "to this SOC alert."
    )
    embedding_document_instruction: str = ""

    def __post_init__(self):
        if self.embedding_devices is None:
            self.embedding_devices = ["cuda:0", "cuda:1", "cuda:2", "cuda:3"]
    
    def validate(self) -> Tuple[bool, str]:
        """Validate RAG configuration"""
        if self.chunk_size <= 0:
            return False, "Chunk size must be positive"
        if self.chunk_overlap < 0:
            return False, "Chunk overlap cannot be negative"
        if self.chunk_overlap >= self.chunk_size:
            return False, "Chunk overlap must be less than chunk size"
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
        if self.retrieval_candidate_multiplier <= 0:
            return False, "Retrieval candidate multiplier must be positive"
        return True, "RAG config is valid"


class ConfigManager:
    """Main configuration manager"""
    
    def __init__(self, config_file: str = None):
        self.config_file = Path(config_file) if config_file else None
        
        # Initialize with defaults
        self.ssh = SSHConfig()
        self.wazuh = WazuhConfig()
        self.llm = LLMConfig()
        self.web = WebConfig()
        self.paths = PathConfig()
        self.rag = RAGConfig()
        self.database = DatabaseConfig()
        self.asset_inventory = AssetInventoryConfig()
        
        # Load from file if provided
        if self.config_file and self.config_file.exists():
            self.load_from_file()
        
        # Load from environment variables
        self.load_from_env()
    
    def load_from_file(self, config_file: str = None) -> bool:
        """Load configuration from JSON file"""
        file_path = Path(config_file) if config_file else self.config_file
        
        if not file_path or not file_path.exists():
            print(f"⚠️ Config file not found: {file_path}")
            return False
        
        try:
            with open(file_path, 'r') as f:
                config_data = json.load(f)
            
            # Update configurations
            if 'ssh' in config_data:
                self.ssh = SSHConfig(**config_data['ssh'])
            if 'wazuh' in config_data:
                self.wazuh = WazuhConfig(**config_data['wazuh'])
            if 'llm' in config_data:
                self.llm = LLMConfig(**config_data['llm'])
            if 'web' in config_data:
                self.web = WebConfig(**config_data['web'])
            if 'paths' in config_data:
                self.paths = PathConfig(**config_data['paths'])
            if 'rag' in config_data:
                self.rag = RAGConfig(**config_data['rag'])
            if 'database' in config_data:
                self.database = DatabaseConfig(**config_data['database'])
            if 'asset_inventory' in config_data:
                self.asset_inventory = AssetInventoryConfig(**config_data['asset_inventory'])
            
            print(f"✅ Configuration loaded from: {file_path}")
            return True
            
        except Exception as e:
            print(f"❌ Error loading config file: {e}")
            return False
    
    def load_from_env(self):
        """Load configuration from environment variables"""
        env_mappings = {
            # SSH config
            'SSH_HOST': ('ssh', 'host'),
            'SSH_USERNAME': ('ssh', 'username'),
            'SSH_PASSWORD': ('ssh', 'password'),
            'SSH_PORT': ('ssh', 'port', int),
            'SSH_TIMEOUT': ('ssh', 'timeout', int),
            
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
            'RAG_CHUNK_SIZE': ('rag', 'chunk_size', int),
            'RAG_CHUNK_OVERLAP': ('rag', 'chunk_overlap', int),
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
            'RAG_NORMALIZE_EMBEDDINGS': ('rag', 'normalize_embeddings', lambda v: v.strip().lower() in ('1', 'true', 'yes', 'on')),
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

            # Asset inventory config
            'ASSET_OWNED_CIDRS': ('asset_inventory', 'owned_cidrs', lambda v: [item.strip() for item in v.split(',') if item.strip()]),
            'ASSET_INFRASTRUCTURE_IPS': ('asset_inventory', 'infrastructure_ips', lambda v: [item.strip() for item in v.split(',') if item.strip()]),
            'ASSET_INTERNAL_CIDRS': ('asset_inventory', 'internal_cidrs', lambda v: [item.strip() for item in v.split(',') if item.strip()]),
        }
        
        for env_var, mapping in env_mappings.items():
            env_value = os.getenv(env_var)
            if env_value is not None:
                section, attr = mapping[0], mapping[1]
                converter = mapping[2] if len(mapping) > 2 else str
                
                try:
                    converted_value = converter(env_value)
                    setattr(getattr(self, section), attr, converted_value)
                    print(f"📝 Loaded from env: {env_var} -> {section}.{attr}")
                except (ValueError, TypeError) as e:
                    print(f"⚠️ Invalid env value for {env_var}: {e}")
    
    def save_to_file(self, config_file: str = None) -> bool:
        """Save configuration to JSON file"""
        file_path = Path(config_file) if config_file else self.config_file
        
        if not file_path:
            print("❌ No config file path specified")
            return False
        
        try:
            config_data = {
                'ssh': asdict(self.ssh),
                'wazuh': asdict(self.wazuh),
                'llm': asdict(self.llm),
                'web': asdict(self.web),
                'paths': asdict(self.paths),
                'rag': asdict(self.rag),
                'database': asdict(self.database),
                'asset_inventory': asdict(self.asset_inventory),
                'saved_at': datetime.now().isoformat()
            }
            
            # Ensure parent directory exists
            file_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(file_path, 'w') as f:
                json.dump(config_data, f, indent=2)
            
            print(f"✅ Configuration saved to: {file_path}")
            return True
            
        except Exception as e:
            print(f"❌ Error saving config file: {e}")
            return False
    
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
            ('AssetInventory', self.asset_inventory)
        ]
        
        for name, config in configs:
            is_valid, message = config.validate()
            if not is_valid:
                errors.append(f"{name}: {message}")
        
        return len(errors) == 0, errors
    
    def get_summary(self) -> Dict[str, Any]:
        """Get configuration summary"""
        return {
            'ssh': {
                'host': self.ssh.host,
                'port': self.ssh.port,
                'username': self.ssh.username,
                'timeout': self.ssh.timeout
            },
            'wazuh': {
                'alerts_path': self.wazuh.alerts_file_path,
                'archives_path': self.wazuh.archives_base_path
            },
            'llm': {
                'model': Path(self.llm.model_path).name,
                'binary': Path(self.llm.llama_cpp_path).name,
                'context_size': self.llm.context_size,
                'max_tokens': self.llm.max_tokens
            },
            'web': {
                'host': self.web.host,
                'port': self.web.port,
                'username': self.web.username
            },
            'paths': {
                'reports': self.paths.reports_dir,
                'templates': self.paths.templates_dir,
                'uploads': self.paths.uploads_dir,
                'geoip_db': self.paths.geoip_db_path
            },
            'rag': {
                'chunk_size': self.rag.chunk_size,
                'document_chunk_size': self.rag.document_chunk_size,
                'embedding_model': self.rag.embedding_model,
                'embedding_device': self.rag.embedding_device,
                'embedding_devices': self.rag.embedding_devices,
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
                'host': self.database.host,
                'port': self.database.port,
                'database': self.database.database,
                'user': self.database.user
            },
            'asset_inventory': {
                'owned_cidrs': self.asset_inventory.owned_cidrs,
                'infrastructure_ips': self.asset_inventory.infrastructure_ips,
                'internal_cidrs': self.asset_inventory.internal_cidrs
            }
        }
    
    def update_config(self, section: str, updates: Dict[str, Any]) -> bool:
        """Update a specific configuration section"""
        try:
            if not hasattr(self, section):
                print(f"❌ Unknown config section: {section}")
                return False
            
            config_obj = getattr(self, section)
            for key, value in updates.items():
                if hasattr(config_obj, key):
                    setattr(config_obj, key, value)
                else:
                    print(f"⚠️ Unknown config key: {section}.{key}")
            
            # Validate after update
            is_valid, message = config_obj.validate()
            if not is_valid:
                print(f"❌ Invalid config after update: {message}")
                return False
            
            print(f"✅ Updated {section} configuration")
            return True
            
        except Exception as e:
            print(f"❌ Error updating config: {e}")
            return False

def create_default_config(config_file: str = "config.json") -> ConfigManager:
    """Create a default configuration and save to file"""
    config = ConfigManager()
    config.save_to_file(config_file)
    return config


def load_config(config_file: str = None) -> ConfigManager:
    """Load configuration from file or environment"""
    return ConfigManager(config_file)


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
            issues.append(f"Missing or unusable required package: {package} ({e})")

    optional_packages = [
        "weasyprint",
        "markdown",
    ]

    for package in optional_packages:
        try:
            __import__(package)
        except Exception as e:
            print(f"Optional package unavailable: {package} ({e})")
    
    return len(issues) == 0, issues
