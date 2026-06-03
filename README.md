# Enhanced AI-Driven SOC Framework Configuration Guide

## Table of Contents
- [Overview](#overview)
- [System Architecture](#system-architecture)
- [Configuration Files](#configuration-files)
- [Core Components](#core-components)
- [Installation & Setup](#installation--setup)
- [Usage Guide](#usage-guide)
- [API Endpoints](#api-endpoints)
- [Troubleshooting](#troubleshooting)

## Overview

This configuration directory contains the core components of the Enhanced AI-Driven SOC Framework, developed for ICT3217 Integrative Team Project 2 (AY 2025/2026, Trimester 1). The system provides automated cybersecurity threat analysis using locally-hosted large language models, processing Wazuh/Suricata security alerts to generate comprehensive Cyber Threat Intelligence (CTI) reports.

### Key Features
- Local LLM deployment (Qwen3-30B) for data sovereignty
- Multi-GPU support (4x GTX 1080 Ti with 44GB total VRAM)
- Persistent vector database (PostgreSQL with pgvector)
- Real-time alert monitoring and analysis
- Human-in-the-loop validation workflow
- Advanced chart generation and visual analytics
- PDF report conversion capabilities
- RAG (Retrieval-Augmented Generation) system for enhanced accuracy

### Project Timeline
- Duration: September 2025 to November 2025
- Time Allocation: 5 hours per week
- Target Metrics: >85% MITRE ATT&CK mapping accuracy, 30% reduction in false positives

## System Architecture
![Main](images/main.png)

## Configuration Files

### 1. config.py
**Main configuration manager handling all system settings**

#### Configuration Sections

##### SSHConfig
```python
host: str = "100.78.175.127"
username: str = "wazuh-user"
password: str = "wazuh"
port: int = 22
timeout: int = 30
```
Manages SSH connection to Wazuh server for alert retrieval.

##### WazuhConfig
```python
alerts_file_path: str = "/var/ossec/logs/alerts/alerts.json"
archives_base_path: str = "/var/ossec/logs/archives"
```
Defines paths to Wazuh alert files and archive directories.

##### LLMConfig
```python
model_path: str = "/home/student/Desktop/Qwen3-30B-A3B-Instruct-2507-Q8_0.gguf"
llama_cpp_path: str = "/home/student/Desktop/llama.cpp/build/bin/llama-cli"
model_type: str = "qwen"
temperature: float = 0.7
top_p: float = 0.8
top_k: int = 20
context_size: int = 8192
max_tokens: int = -2
gpu_layers: int = 99
tensor_split: str = "0.7,1.1,1.1,1.1"
```

**Key Parameters:**
- `context_size: 8192` - Maximum context window for LLM processing
- `max_tokens: -2` - Generate until context is filled
- `gpu_layers: 99` - Offload all layers to GPU for maximum performance
- `tensor_split: "0.7,1.1,1.1,1.1"` - Distribute model across 4 GPUs
- `use_jinja: True` - Enable Jinja2 templating for chat
- `flash_attention: False` - Standard attention mechanism
- `batch_size: 512` - Logical batch size
- `ubatch_size: 256` - Physical batch size

##### DatabaseConfig
```python
host: str = "localhost"
port: int = 5432
database: str = "soc_rag"
user: str = "soc_user"
password: str = "StudentPass4721"
```
PostgreSQL database with pgvector extension for persistent embeddings.

##### RAGConfig
```python
chunk_size: int = 500
chunk_overlap: int = 50
embedding_model: str = "Qwen/Qwen3-Embedding-0.6B"
embedding_device: str = "cpu"
max_retrieval_docs: int = 10
normalize_embeddings: bool = False
```

##### WebConfig
```python
username: str = "admin"
password: str = "admin"
host: str = "0.0.0.0"
port: int = 8000
```

##### PathConfig
```python
reports_dir: str = "/home/student/Desktop/ICT2114_Team15/Linux_LLM/reports"
templates_dir: str = "/home/student/Desktop/ICT2114_Team15/Linux_LLM/config/templates"
uploads_dir: str = "/home/student/Desktop/ICT2114_Team15/Linux_LLM/uploads"
```

#### Environment Variable Support
All configurations can be overridden via environment variables:

```bash
# SSH Configuration
export SSH_HOST="100.78.175.127"
export SSH_USERNAME="wazuh-user"
export SSH_PASSWORD="wazuh"

# LLM Configuration
export LLM_MODEL_PATH="/path/to/model.gguf"
export LLM_TEMPERATURE="0.7"
export LLM_CONTEXT_SIZE="8192"

# Database Configuration
export DB_HOST="localhost"
export DB_PORT="5432"
```

#### Usage Examples

```python
# Load default configuration
config = ConfigManager()

# Load from file
config = ConfigManager("custom_config.json")

# Validate configuration
is_valid, errors = config.validate_all()

# Update specific section
config.update_config('llm', {'temperature': 0.8, 'top_p': 0.9})

# Save configuration
config.save_to_file("my_config.json")

# Get configuration summary
summary = config.get_summary()
```

### 2. main.py
**FastAPI application entry point and route definitions**

#### Core Features
- WebSocket-based progress tracking
- Real-time alert monitoring
- Human-in-the-loop report validation
- Automatic PDF conversion
- Chart generation integration
- Session management
- Authentication system

#### Key Components

##### SOCApplication Class
Main application container managing:
- FastAPI app instance
- Configuration management
- Component initialization
- Route registration
- Lifespan management

##### Component Initialization
```python
def _init_components(self):
    - ProgressTracker: Session and progress management
    - DocumentProcessor: File upload handling
    - ReportGenerator: LLM-based report creation
    - LiveMonitoring: Real-time alert detection
    - PDFConverter: Report format conversion
```

##### Route Categories

**Dashboard & Authentication**
- `GET /` - Main dashboard with report listing
- Basic HTTP authentication required for all endpoints

**RAG Management**
- `POST /build-rag` - Build/refresh RAG context from archives or uploads
- `GET /rag-status` - Current RAG system status

**Alert Analysis**
- `POST /analyze-alerts` - Analyze current alerts with RAG
- `POST /analyze-selected-alerts` - Process specific alerts
- `GET /api/live-alerts` - Fetch real-time alerts
- `GET /alerts/viewer` - Live alert viewer interface

**Report Management**
- `GET /reports` - List all reports with pagination
- `GET /reports/{filename}` - Download specific report
- `GET /reports/{filename}/edit` - Open report in editor
- `GET /review-report/{report_id}` - Human review interface
- `POST /api/save-draft/{report_id}` - Save draft changes
- `POST /api/approve-report/{report_id}` - Finalize report

**PDF Conversion**
- `POST /convert-to-pdf` - Convert single report to PDF
- `POST /batch-convert-pdf` - Convert all reports to PDF
- `GET /pdf-status` - PDF conversion capabilities

**System Status**
- `GET /system-status` - Comprehensive system information
- `GET /test-connection` - Test SSH connectivity
- `GET /api/report-metrics` - Generation timing statistics
- `GET /chart-capabilities` - Available chart types

**WebSocket Endpoints**
- `WS /ws/progress/{session_id}` - Real-time progress updates

### 3. requirements.txt
**Python dependencies with exact versions**

#### Key Dependencies
```
fastapi==0.118.2 - Web framework
uvicorn==0.37.0 - ASGI server
websockets==15.0.1 - WebSocket protocol support for progress updates
paramiko==4.0.0 - SSH client
Jinja2==3.1.6 - HTML templates and chat template support
sentence-transformers==5.1.1 - Embedding models
psycopg2-binary==2.9.11 - PostgreSQL driver
PyMuPDF==1.26.5 - Structured PDF extraction
geoip2==5.1.0 - IP geolocation lookup
weasyprint>=60.0 - Markdown to PDF conversion
matplotlib==3.10.7 - Chart generation
```

### 4. ssh.py
**SSH connection and alert reading functionality**

#### SmartSSHLogReader Class
Manages persistent SSH connections to Wazuh server:

**Key Features:**
- Automatic reconnection on connection loss
- Archive reading with date filtering
- Efficient alert deduplication
- JSON parsing with error handling
- Support for both alerts and archives

**Methods:**
```python
connect() -> bool
disconnect()
read_alerts(max_alerts: int = 1000) -> List[Dict]
read_archives_smart(days: int) -> List[Dict]
```

### 5. report.py
**Report generation with LLM integration**

#### ReportGenerator Class
Orchestrates threat analysis report creation:

**Features:**
- RAG-enhanced context retrieval
- MITRE ATT&CK technique mapping
- Chart generation integration
- Geolocation analysis
- Template-based formatting
- Performance metrics tracking

**Key Methods:**
```python
generate_report_with_rag(alerts, hostname, is_automatic=False)
build_rag_context(archive_logs, custom_docs)
get_rag_status() -> Dict
get_chart_capabilities() -> Dict
mark_report_approved()
```

### 6. rag.py
**Retrieval-Augmented Generation system**

#### Features
- PostgreSQL pgvector integration
- Persistent embeddings storage
- Semantic document chunking
- Duplicate detection via hashing
- Efficient similarity search

**DocumentProcessor Class:**
```python
process_upload(content, filename, save_to_disk=True)
check_duplicate(content, filename) -> Tuple[bool, str]
```

**RAG System:**
```python
build_context(archive_logs, custom_docs)
search_similar(query, k=10) -> List[Document]
get_status() -> Dict
```

### 7. charts.py
**Visual analytics generation**

#### ChartGenerator Class
Creates various chart types for threat visualization:

**Chart Types:**
- Severity distribution (bar charts)
- Geographic heat maps
- Timeline analysis
- Top sources/targets
- Technique frequency
- Agent activity

**Integration:**
- Matplotlib backend
- Embedded in markdown reports
- Automatic file management
- Chart directory organization

### 8. pdf_converter.py
**Enhanced PDF conversion system**

#### PDFConverter Class
Converts markdown reports to PDF format:

**Methods:**
- WeasyPrint-based conversion
- Chart embedding support
- CSS styling
- Fallback mechanisms
- Batch processing

### 9. progress.py
**Progress tracking and WebSocket management**

#### ProgressTracker Class
Real-time progress updates for long-running operations:

**Features:**
- WebSocket connection management
- Session timeout handling
- Progress percentage tracking
- Status message broadcasting
- Automatic cleanup

### 10. live_monitoring.py
**Continuous alert monitoring system**

#### EnhancedLiveMonitoringService
Monitors for high-severity alerts and triggers automatic analysis:

**Configuration:**
```python
high_severity_threshold: int = 10
processing_interval: int = 30  # seconds
```

**Features:**
- Alert deduplication via UUID hashing
- Automatic report generation for high-severity alerts
- Persistent SSH connection management
- Background monitoring task
- WebSocket notifications

### 11. report_parser.py
**Report parsing and serialization**

#### ReportParser Class
Handles conversion between markdown and structured data:

**Methods:**
```python
parse_report(markdown: str) -> Dict
serialize_to_markdown(data: Dict) -> str
validate_report(data: Dict) -> Tuple[bool, List[str]]
```

**Use Cases:**
- Loading existing reports for editing
- Validating report structure
- Converting between formats

### 12. mitre_techniques.json
**MITRE ATT&CK technique database**

Contains structured information about MITRE ATT&CK techniques for accurate threat classification:

**Structure:**
```json
[
  {
    "id": "T1566",
    "name": "Phishing",
    "tactic": "Initial Access",
    "deprecated": false
  }
]
```

## Core Components

### Alert Processing Pipeline


**Pipeline Steps:**
![Pipeline](images/pipeline.png)

1. **Alert Collection**: SSH connection to Wazuh server retrieves JSON alerts
2. **Deduplication**: Hash-based UUID generation prevents duplicate processing
3. **Enrichment**: IP geolocation, threat classification, severity assessment
4. **RAG Context**: Retrieve similar historical alerts and CTI documents
5. **LLM Analysis**: Generate comprehensive threat analysis report
6. **Human Validation**: Review and edit report before approval
7. **PDF Conversion**: Optional automatic conversion to PDF format

### RAG System Architecture
![Architecture](images/rag.png)


### Multi-GPU Setup
![Setup](images/setup.png)

The system distributes the 30B parameter model across 4 GPUs:

```
GPU 0: 0.7 fraction (Main processing + KV cache)
GPU 1: 1.1 fraction
GPU 2: 1.1 fraction
GPU 3: 1.1 fraction
```

**Memory Usage:**
- Total VRAM: 44GB across 4x GTX 1080 Ti
- Model size: ~30GB (Q8_0 quantization)
- KV cache: ~8GB
- Embeddings: ~4GB

## Installation & Setup

### Prerequisites

1. **Hardware Requirements:**
   - 4x GTX 1080 Ti GPUs (or equivalent)
   - 32GB+ System RAM
   - 100GB+ Storage

2. **Software Requirements:**
   - Ubuntu 24.04 LTS
   - Python 3.10+
   - PostgreSQL 14+ with pgvector extension
   - CUDA 11.8+
   - llama.cpp compiled with GPU support

### Installation Steps

#### 1. Clone Repository
```bash
cd /home/student/Desktop
git clone <repository_url> ICT2114_Team15
cd ICT2114_Team15/Linux_LLM/config
```

#### 2. Install Python Dependencies
```bash
pip install -r requirements.txt --break-system-packages
```

#### 3. Setup PostgreSQL with pgvector
```bash
# Install PostgreSQL
sudo apt install postgresql postgresql-contrib

# Install pgvector extension
sudo apt install postgresql-14-pgvector

# Create database and user
sudo -u postgres psql
CREATE DATABASE soc_rag;
CREATE USER soc_user WITH PASSWORD 'StudentPass4721';
GRANT ALL PRIVILEGES ON DATABASE soc_rag TO soc_user;

# Enable pgvector extension
\c soc_rag
CREATE EXTENSION vector;
```

#### 4. Download Model
```bash
# Download Qwen3-30B model (example URL)
wget https://huggingface.co/<model-path>/Qwen3-30B-A3B-Instruct-2507-Q8_0.gguf \
     -O /home/student/Desktop/Qwen3-30B-A3B-Instruct-2507-Q8_0.gguf
```

#### 5. Compile llama.cpp with GPU Support
```bash
cd /home/student/Desktop
git clone https://github.com/ggml-org/llama.cpp
cd llama.cpp

# Build with CUDA support
mkdir build && cd build
cmake .. -DGGML_CUDA=ON
cmake --build . --config Release

# Verify binary
./bin/llama-cli --version
```

#### 6. Configure System
```bash
# Copy example config
cp config.example.json config.json

# Edit configuration
nano config.json
```

#### 7. Verify Setup
```bash
# Test SSH connection
python3 -c "
from ssh import SmartSSHLogReader
reader = SmartSSHLogReader('100.78.175.127', 'wazuh-user', 'wazuh')
print('Connected!' if reader.connect() else 'Failed')
reader.disconnect()
"

# Test database connection
python3 -c "
import psycopg2
conn = psycopg2.connect(
    host='localhost', port=5432,
    database='soc_rag', user='soc_user',
    password='StudentPass4721'
)
print('Database OK!')
conn.close()
"

# Test LLM
/home/student/Desktop/llama.cpp/build/bin/llama-cli \
  --model /home/student/Desktop/Qwen3-30B-A3B-Instruct-2507-Q8_0.gguf \
  --prompt "Hello world" \
  --predict 10
```

## Usage Guide

### Starting the System

```bash
cd /home/student/Desktop/ICT2114_Team15/Linux_LLM/config
python3 main.py
```

The system will:
1. Load configuration
2. Initialize components
3. Validate environment
4. Start web server on port 8000
5. Display dashboard URL

### Initial RAG Build

1. Navigate to http://localhost:8000
2. Login with credentials (admin/admin)
3. Click "Build RAG Context"
4. Select data sources:
   - Archive logs (specify days)
   - Upload custom CTI documents
5. Monitor progress via WebSocket
6. Wait for completion (RAG Ready indicator)

### Manual Alert Analysis

1. Ensure RAG is ready (green indicator)
2. Click "Analyze Current Alerts"
3. Monitor progress via real-time updates
4. Review generated report in editor
5. Make any necessary edits
6. Approve report for finalization
7. Download PDF if needed

### Automatic Alert Monitoring

The system automatically:
1. Monitors for high-severity alerts (level ≥10)
2. Generates reports for qualifying alerts
3. Sends notifications via WebSocket
4. Requires human validation before finalization

### Working with Reports

#### Viewing Reports
```bash
# List all reports
curl -u admin:admin http://localhost:8000/reports

# Download specific report
curl -u admin:admin http://localhost:8000/reports/APPROVED_Threat_analysis_20251115_143022.md \
     -o report.md
```

#### Converting to PDF
```bash
# Convert single report
curl -u admin:admin -X POST http://localhost:8000/convert-to-pdf \
     -F "filename=APPROVED_Threat_analysis_20251115_143022.md"

# Batch convert all reports
curl -u admin:admin -X POST http://localhost:8000/batch-convert-pdf
```

### Chart Generation

Charts are automatically generated when analyzing alerts. Supported chart types:

1. **Severity Distribution**: Bar chart showing alert levels
2. **Geographic Heat Map**: World map of attack sources
3. **Timeline Analysis**: Alert frequency over time
4. **Top Techniques**: Most common MITRE ATT&CK techniques
5. **Agent Activity**: Alerts by monitoring agent

Charts are embedded in markdown reports and included in PDF exports.

## API Endpoints

### Authentication
All endpoints require HTTP Basic Authentication:
```bash
Authorization: Basic YWRtaW46YWRtaW4=  # admin:admin
```

### Dashboard & Status

#### GET /
Main dashboard interface with report listing and RAG status.

**Query Parameters:**
- `existing_page` (int): Page number for existing reports
- `existing_page_size` (int): Reports per page (1-50)

#### GET /system-status
Comprehensive system information including component status and metrics.

**Response:**
```json
{
  "config": { /* configuration summary */ },
  "environment": {
    "valid": true,
    "issues": []
  },
  "components": {
    "rag_ready": true,
    "auto_monitoring_enabled": true,
    "pdf_available": true,
    "charts_available": true
  },
  "stats": { /* performance metrics */ }
}
```

### RAG Management

#### POST /build-rag
Build or refresh RAG context from various sources.

**Form Parameters:**
- `use_archives` (bool): Include OSSEC archives
- `use_uploads` (bool): Include uploaded documents
- `ragDays` (int): Days of archives to process
- `customFiles` (List[File]): CTI documents to upload

**Response:**
```json
{
  "session_id": "abc123",
  "message": "RAG context refresh started"
}
```

#### GET /rag-status
Current RAG system status and statistics.

**Response:**
```json
{
  "rag_ready": true,
  "alerts_with_embeddings": 1523,
  "docs_with_embeddings": 45,
  "embedding_model": "Qwen/Qwen3-Embedding-0.6B",
  "database_status": "connected"
}
```

### Alert Analysis

#### POST /analyze-alerts
Analyze current alerts using RAG-enhanced LLM.

**Form Parameters:**
- `include_charts` (bool): Generate visual analytics

**Response:**
```json
{
  "session_id": "xyz789",
  "message": "Alert analysis started"
}
```

#### POST /analyze-selected-alerts
Analyze specific alerts by UUID or ID.

**Request Body:**
```json
{
  "selected_uuids": ["abc123", "def456"],
  "selected_ids": [0, 5, 12]
}
```

#### GET /api/live-alerts
Fetch current alerts with pagination and filtering.

**Query Parameters:**
- `page` (int): Page number
- `page_size` (int): Alerts per page (1-50)
- `min_severity` (int): Minimum severity level (0-15)

**Response:**
```json
{
  "success": true,
  "total_alerts": 150,
  "page": 1,
  "page_size": 50,
  "total_pages": 3,
  "alerts": [
    {
      "alert_id": 0,
      "alert_uuid": "abc123...",
      "timestamp": "2025-11-15T14:30:22Z",
      "rule_level": 12,
      "rule_description": "Multiple authentication failures",
      "src_ip": "192.168.1.100",
      "dest_ip": "10.0.0.5"
    }
  ]
}
```

### Report Management

#### GET /reports
List generated reports with pagination.

**Query Parameters:**
- `page` (int): Page number
- `page_size` (int): Reports per page (1-100)
- `include_all_markdown` (bool): Include markdown filenames in response

**Response:**
```json
{
  "items": [
    {
      "filename": "APPROVED_Threat_analysis_20251115_143022.md",
      "created": "2025-11-15 14:30:22",
      "size": "45.2 KB",
      "type": "markdown"
    }
  ],
  "page": 1,
  "page_size": 10,
  "total_items": 25,
  "total_pages": 3
}
```

#### GET /reports/{filename}
Download or view specific report.

**Response:** File download (markdown, PDF, or HTML)

#### GET /reports/{filename}/edit
Open existing report in editor for modifications.

**Response:** Redirect to report editor interface

#### POST /api/approve-report/{report_id}
Finalize and save approved report.

**Request Body:**
```json
{
  "title": "Threat Analysis Report",
  "timestamp": "2025-11-15T14:30:22Z",
  "executive_summary": { /* ... */ },
  "alert_details": [ /* ... */ ],
  "mitre_techniques": [ /* ... */ ]
}
```

#### POST /api/save-draft/{report_id}
Save draft changes without finalizing.

### PDF Conversion

#### POST /convert-to-pdf
Convert single markdown report to PDF.

**Form Parameters:**
- `filename` (str): Report filename (e.g., "report.md")

**Response:**
```json
{
  "pdf_filename": "report.pdf",
  "message": "Converted successfully",
  "method": "weasyprint"
}
```

#### POST /batch-convert-pdf
Convert all markdown reports to PDF.

**Response:**
```json
{
  "successful": 15,
  "failed": 0,
  "results": [
    {
      "filename": "report1.md",
      "pdf_filename": "report1.pdf",
      "status": "success"
    }
  ]
}
```

#### GET /pdf-status
PDF conversion capabilities and status.

**Response:**
```json
{
  "pdf_available": true,
  "conversion_method": "weasyprint",
  "supported_formats": ["markdown", "html"]
}
```

### WebSocket Endpoints

#### WS /ws/progress/{session_id}
Real-time progress updates for long-running operations.

**Messages Received:**
```json
{
  "message": "Processing alerts...",
  "progress": 45,
  "status": "info",
  "timestamp": "14:30:22",
  "extra_data": { /* optional */ }
}
```

**Connection Flow:**
1. Client connects with session_id
2. Server acknowledges connection
3. Progress updates sent automatically
4. Client can send "ping" for keep-alive
5. Connection closes on completion or timeout

## Troubleshooting

### Common Issues

#### 1. SSH Connection Failures

**Symptom:** Unable to connect to Wazuh server

**Solutions:**
```bash
# Verify network connectivity
ping 100.78.175.127

# Test SSH manually
ssh wazuh-user@100.78.175.127

# Check firewall rules
sudo ufw status

# Verify credentials in config.py
nano config.py  # Check SSH_HOST, SSH_USERNAME, SSH_PASSWORD
```

#### 2. CUDA Out of Memory

**Symptom:** RuntimeError: CUDA out of memory

**Solutions:**
```python
# Reduce context size
config.llm.context_size = 4096  # Instead of 8192

# Reduce batch size
config.llm.batch_size = 256
config.llm.ubatch_size = 128

# Adjust tensor split
config.llm.tensor_split = "0.5,1.0,1.0,1.0"

# Offload fewer layers
config.llm.gpu_layers = 50  # Instead of 99
```

#### 3. PostgreSQL Connection Errors

**Symptom:** psycopg2.OperationalError: could not connect to server

**Solutions:**
```bash
# Check PostgreSQL status
sudo systemctl status postgresql

# Restart PostgreSQL
sudo systemctl restart postgresql

# Verify database exists
sudo -u postgres psql -l | grep soc_rag

# Reset user permissions
sudo -u postgres psql
ALTER USER soc_user WITH PASSWORD 'StudentPass4721';
GRANT ALL PRIVILEGES ON DATABASE soc_rag TO soc_user;
```

#### 4. llama.cpp Not Found

**Symptom:** FileNotFoundError: llama-cli binary not found

**Solutions:**
```bash
# Verify binary exists
ls -l /home/student/Desktop/llama.cpp/build/bin/llama-cli

# Recompile if needed
cd /home/student/Desktop/llama.cpp
mkdir build && cd build
cmake .. -DGGML_CUDA=ON
cmake --build . --config Release

# Test execution
./bin/llama-cli --version

# Update config path
nano /home/student/Desktop/ICT2114_Team15/Linux_LLM/config/config.py
```

#### 5. Port 8000 Already in Use

**Symptom:** OSError: [Errno 98] Address already in use

**Solutions:**
```bash
# Find process using port 8000
sudo lsof -i :8000

# Kill existing process
sudo kill -9 <PID>

# Or use different port
python3 main.py --port 8001
```

#### 6. Model Loading Too Slow

**Symptom:** Model takes >5 minutes to load

**Solutions:**
```python
# Enable mmap (faster loading)
config.llm.use_mmap = True

# Disable mlock (uses less RAM but may be slower)
config.llm.use_mlock = False

# Pre-load model at startup
# Model stays in memory between requests
```

#### 7. RAG Not Finding Relevant Documents

**Symptom:** Retrieved documents not relevant to query

**Solutions:**
```python
# Adjust chunk size
config.rag.chunk_size = 1000  # Larger chunks
config.rag.chunk_overlap = 100

# Increase retrieval count
config.rag.max_retrieval_docs = 15

# Enable embedding normalization
config.rag.normalize_embeddings = True

# Rebuild RAG with clean data
# Remove duplicates and low-quality documents
```

#### 8. High False Positive Rate

**Symptom:** LLM classifying benign alerts as threats

**Solutions:**
```python
# Adjust temperature (more conservative)
config.llm.temperature = 0.5

# Increase top-k (more diverse sampling)
config.llm.top_k = 40

# Fine-tune prompt engineering in templates/cti.txt
# Add more examples of false positives to avoid

# Expand RAG context with more training data
# Include benign alert examples
```

#### 9. Chart Generation Failures

**Symptom:** Charts not appearing in reports

**Solutions:**
```bash
# Verify matplotlib backend
python3 -c "import matplotlib; print(matplotlib.get_backend())"

# Install missing dependencies
pip install matplotlib --break-system-packages

# Check charts directory exists
mkdir -p /home/student/Desktop/ICT2114_Team15/Linux_LLM/reports/charts

# Verify write permissions
chmod 755 /home/student/Desktop/ICT2114_Team15/Linux_LLM/reports/charts
```

#### 10. PDF Conversion Issues

**Symptom:** WeasyPrint conversion failing

**Solutions:**
```bash
# Install system dependencies
sudo apt install libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf2.0-0

# Install Python packages
pip install weasyprint markdown --break-system-packages

# Test conversion manually
python3 -c "
from pdf_converter import EnhancedPDFConverter
converter = EnhancedPDFConverter()
print('Available:', converter.conversion_available)
"
```

### Performance Optimization

#### Inference Speed
```python
# Enable flash attention (if supported)
config.llm.flash_attention = True

# Optimize batch sizes
config.llm.batch_size = 512
config.llm.ubatch_size = 256

# Use CPU for smaller tasks
config.rag.embedding_device = "cpu"  # Frees GPU for inference
```

#### Memory Usage
```python
# Reduce context window
config.llm.context_size = 4096

# Use quantized KV cache
config.llm.cache_type_k = "q8_0"
config.llm.cache_type_v = "q8_0"

# Limit concurrent processing
# Only 1 alert analysis at a time
```

#### Database Performance
```sql
-- Create indexes for faster retrieval
CREATE INDEX idx_embeddings ON alerts USING ivfflat (embedding vector_cosine_ops);

-- Vacuum database regularly
VACUUM ANALYZE alerts;
VACUUM ANALYZE documents;

-- Monitor query performance
EXPLAIN ANALYZE SELECT * FROM alerts ORDER BY embedding <=> '[...]';
```

### Debugging Tips

#### Enable Verbose Logging
```python
import logging
logging.basicConfig(level=logging.DEBUG)

# In main.py
uvicorn.run(app, log_level="debug")
```

#### Test Components Individually
```python
# Test SSH connection
from ssh import SmartSSHLogReader
reader = SmartSSHLogReader(...)
alerts = reader.read_alerts(10)
print(f"Retrieved {len(alerts)} alerts")

# Test LLM inference
from report import ReportGenerator
generator = ReportGenerator(...)
response = generator._call_llm("Test prompt")
print(response)

# Test RAG retrieval
docs = generator.rag_retriever.search_similar("brute force attack", k=5)
for doc in docs:
    print(doc.page_content[:200])
```

#### Monitor System Resources
```bash
# GPU usage
watch -n 1 nvidia-smi

# RAM usage
htop

# Disk I/O
iotop

# Network activity
nethogs
```

### Getting Help

#### Log Files
```bash
# Application logs
tail -f /home/student/Desktop/ICT2114_Team15/Linux_LLM/logs/app.log

# PostgreSQL logs
sudo tail -f /var/log/postgresql/postgresql-14-main.log

# System logs
journalctl -u soc-framework -f
```

#### Debug Information to Collect
1. System status output: `GET /system-status`
2. Configuration summary: `config.get_summary()`
3. GPU status: `nvidia-smi`
4. Database status: `psql -U soc_user -d soc_rag -c "\dt"`
5. Recent errors from logs
6. Steps to reproduce issue

#### Contact Information
- Team Lead: Glenn (Tan Wei Ming) - 2301777
- Project: ICT3217 Integrative Team Project 2
- Supervisors: Prof Aris Cahyadi Risdianto, Prof Johnathan Lim

## Appendix

### Project Structure
```
Linux_LLM/config/
├── main.py                 # FastAPI application
├── config.py               # Configuration management
├── ssh.py                  # SSH connectivity
├── report.py               # Report generation
├── rag.py                  # RAG system
├── charts.py               # Chart generation
├── pdf_converter.py        # PDF conversion
├── progress.py             # Progress tracking
├── live_monitoring.py      # Alert monitoring
├── report_parser.py        # Report parsing
├── requirements.txt        # Python dependencies
├── mitre_techniques.json   # MITRE ATT&CK data
├── README.md               # This file
├── templates/              # Jinja2 templates
│   ├── dashboard.html
│   ├── alert_viewer.html
│   ├── report_editor.html
│   ├── cti.txt            # System prompt
│   └── qwen_chat.j2       # Chat template
└── static/                 # Static assets
    ├── css/
    ├── js/
    └── img/
```

### Key Metrics & Performance Targets

#### Success Criteria (from Project Plan)
- MITRE ATT&CK mapping accuracy: >85%
- False positive reduction: 30% from baseline
- Response time: <90 seconds for comprehensive analysis
- System uptime: >99% during monitoring periods

#### Current Performance Benchmarks
- Alert processing: ~5-10 seconds per alert
- Report generation: 30-60 seconds (depending on alert count)
- RAG context build: 2-5 minutes (depends on data volume)
- PDF conversion: 3-5 seconds per report

### Future Enhancements

1. **Model Fine-tuning**: Train on collected SOC data for improved accuracy
2. **Advanced Analytics**: Implement predictive threat modeling
3. **Multi-tenancy**: Support multiple organizations
4. **API Gateway**: RESTful API for third-party integrations
5. **Mobile Dashboard**: Responsive mobile interface for SOC analysts

### References

1. Project Proposal: IS_12 Threat Detection and Analysis Using a Cost-Effective SOC Framework
2. ITP2 Proposal: Enhanced AI-Driven SOC Framework with Improved Accuracy and Trustworthiness
3. llama.cpp Documentation: https://github.com/ggml-org/llama.cpp
4. MITRE ATT&CK Framework: https://attack.mitre.org/
5. Wazuh Documentation: https://documentation.wazuh.com/
6. pgvector Documentation: https://github.com/pgvector/pgvector

---

**Last Updated:** November 2025  
