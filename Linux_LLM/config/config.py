import os
import json
from pathlib import Path
from typing import Dict, Any, Optional, Tuple, Union
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
class LLMConfig:
    model_path: str = "/home/student/Desktop/Qwen3-30B-A3B-Instruct-2507-Q8_0.gguf"  # Updated for Gemma
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
            args.extend(["--system-prompt-file", str(Path(templates_dir) / "cti.txt")])
        # NEW: Add the three requested flags
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
    reports_dir: str = "/home/student/Desktop/ICT2114_Team15/Linux_LLM/reports"
    templates_dir: str = "/home/student/Desktop/ICT2114_Team15/Linux_LLM/config/templates"
    uploads_dir: str = "/home/student/Desktop/ICT2114_Team15/Linux_LLM/uploads"

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
    embedding_model: str = "Qwen/Qwen3-Embedding-0.6B"
    embedding_device: str = "cpu"
    max_retrieval_docs: int = 10
    normalize_embeddings: bool = False
    
    def validate(self) -> Tuple[bool, str]:
        """Validate RAG configuration"""
        if self.chunk_size <= 0:
            return False, "Chunk size must be positive"
        if self.chunk_overlap < 0:
            return False, "Chunk overlap cannot be negative"
        if self.chunk_overlap >= self.chunk_size:
            return False, "Chunk overlap must be less than chunk size"
        if not self.embedding_model:
            return False, "Embedding model cannot be empty"
        if self.max_retrieval_docs <= 0:
            return False, "Max retrieval docs must be positive"
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
            
            # RAG config
            'RAG_CHUNK_SIZE': ('rag', 'chunk_size', int),
            'RAG_CHUNK_OVERLAP': ('rag', 'chunk_overlap', int),
            'RAG_EMBEDDING_MODEL': ('rag', 'embedding_model'),
            'RAG_MAX_DOCS': ('rag', 'max_retrieval_docs', int),
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
            ('RAG', self.rag)
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
                'uploads': self.paths.uploads_dir
            },
            'rag': {
                'chunk_size': self.rag.chunk_size,
                'embedding_model': self.rag.embedding_model,
                'max_docs': self.rag.max_retrieval_docs
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


# Legacy compatibility class
class Config:
    """Legacy configuration class for backward compatibility"""
    
    def __init__(self, config_file: str = None):
        self._manager = ConfigManager(config_file)
    
    # SSH properties
    @property
    def ssh_host(self) -> str:
        return self._manager.ssh.host
    
    @property
    def ssh_username(self) -> str:
        return self._manager.ssh.username
    
    @property
    def ssh_password(self) -> str:
        return self._manager.ssh.password
    
    @property
    def ssh_port(self) -> int:
        return self._manager.ssh.port
    
    # Wazuh properties
    @property
    def alerts_file_path(self) -> str:
        return self._manager.wazuh.alerts_file_path
    
    @property
    def archives_base_path(self) -> str:
        return self._manager.wazuh.archives_base_path
    
    # LLM properties
    @property
    def model_path(self) -> str:
        return self._manager.llm.model_path
    
    @property
    def llama_cpp_path(self) -> str:
        return self._manager.llm.llama_cpp_path
    
    # Web properties
    @property
    def username(self) -> str:
        return self._manager.web.username
    
    @property
    def password(self) -> str:
        return self._manager.web.password
    
    # Path properties
    @property
    def reports_dir(self) -> str:
        return self._manager.paths.reports_dir
    
    @property
    def templates_dir(self) -> str:
        return self._manager.paths.templates_dir
    
    @property
    def uploads_dir(self) -> str:
        return self._manager.paths.uploads_dir


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
    
    # Check required Python packages
    required_packages = [
        'fastapi', 'uvicorn', 'paramiko', 'pypdf', 
        'langchain', 'langchain_community', 'langchain_huggingface',
        'jinja2'
    ]
    
    for package in required_packages:
        try:
            __import__(package.replace('-', '_'))
        except ImportError:
            issues.append(f"Missing required package: {package}")
    
    return len(issues) == 0, issues
