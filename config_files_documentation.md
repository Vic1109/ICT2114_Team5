# Config Files - Function Reference

## charts.py

### Class: `SOCChartGenerator`

**Purpose**: Generate visual charts for SOC threat analysis reports

#### Methods:

- **`__init__(charts_dir)`** - Initialize chart generator with output directory
- **`generate_ip_analysis_charts(alerts, chart_prefix)`** - Generate all IP analysis charts (returns list of chart paths)
- **`_extract_ip_data(alerts)`** - Extract and categorize IP data from alerts
- **`_create_external_sources_pie(external_sources, prefix)`** - Create pie chart for top 10 external source IPs
- **`_create_geolocation_pie(geolocation, prefix)`** - Create pie chart for geographic distribution by country
- **`_create_threat_direction_pie(threat_directions, prefix)`** - Create pie chart for threat directions (inbound/outbound/lateral)
- **`_create_protocol_pie(protocols, prefix)`** - Create pie chart for protocol distribution (TCP/UDP/HTTP)
- **`generate_severity_timeline(alerts, chart_prefix)`** - Generate timeline scatter plot showing alert severity over time
- **`cleanup_old_charts(max_age_hours)`** - Delete chart files older than specified hours

---

## config.py

### Class: `DatabaseConfig`

**Purpose**: PostgreSQL database configuration

#### Methods:

- **`validate()`** - Validate database configuration (returns tuple: bool, message)
- **`get_dict()`** - Return config as dictionary

### Class: `SSHConfig`

**Purpose**: SSH connection configuration for Wazuh server

#### Methods:

- **`validate()`** - Validate SSH configuration

### Class: `WazuhConfig`

**Purpose**: Wazuh server paths configuration

#### Methods:

- **`validate()`** - Validate Wazuh paths

### Class: `LLMConfig`

**Purpose**: LLM (Qwen model) configuration

#### Methods:

- **`validate()`** - Validate LLM configuration
- **`get_llama_args(templates_dir, custom_template_path)`** - Generate llama.cpp command line arguments
- **`get_model_specific_settings()`** - Get model-specific optimization settings (Gemma/Qwen)
- **`optimize_for_model()`** - Apply model-specific optimizations

### Class: `WebConfig`

**Purpose**: Web server configuration

#### Methods:

- **`validate()`** - Validate web configuration

### Class: `PathConfig`

**Purpose**: File paths configuration

#### Methods:

- **`validate()`** - Validate paths and create directories if needed

### Class: `RAGConfig`

**Purpose**: RAG (Retrieval-Augmented Generation) configuration

#### Methods:

- **`validate()`** - Validate RAG configuration

### Class: `ConfigManager`

**Purpose**: Main configuration manager

#### Methods:

- **`__init__(config_file)`** - Initialize config manager, load from file and environment
- **`load_from_file(config_file)`** - Load configuration from JSON file
- **`load_from_env()`** - Load configuration from environment variables
- **`save_to_file(config_file)`** - Save configuration to JSON file
- **`validate_all()`** - Validate all configuration sections (returns tuple: bool, errors list)
- **`get_production_warnings()`** - Return non-blocking warnings for unsafe production defaults and missing runtime paths
- **`get_summary()`** - Get configuration summary dictionary
- **`update_config(section, updates)`** - Update a specific configuration section

### Functions:

- **`create_default_config(config_file)`** - Create default configuration and save to file
- **`load_config(config_file)`** - Load configuration from file or environment
- **`validate_environment()`** - Validate that environment meets requirements (check Python packages)

---

## live_monitoring.py

### Class: `AlertSnapshot`

**Purpose**: Represents a snapshot of current alerts for comparison

#### Methods:

- **`to_dict()`** - Convert snapshot to dictionary

### Class: `AlertHasher`

**Purpose**: Creates unique hashes for alerts to detect duplicates

#### Static Methods:

- **`hash_alert(alert)`** - Create unique MD5 hash for an alert based on key fields

### Class: `PersistentSSHConnection`

**Purpose**: Manages a persistent SSH connection for continuous monitoring

#### Methods:

- **`__init__(ssh_reader_factory)`** - Initialize with SSH reader factory function
- **`ensure_connection()`** - Ensure SSH connection is active, reconnect if needed (async)
- **`read_alerts()`** - Read alerts using persistent connection (async)
- **`disconnect()`** - Disconnect SSH connection

### Class: `EnhancedLiveMonitoringService`

**Purpose**: Enhanced live monitoring with persistent connections and proper filtering

#### Methods:

- **`__init__(config_manager, report_generator, ssh_reader_factory)`** - Initialize monitoring service
- **`start_monitoring(continuous)`** - Start live monitoring (continuous or interval mode)
- **`stop_monitoring()`** - Stop live monitoring
- **`update_config(polling_interval, high_severity_threshold, continuous)`** - Update monitoring configuration
- **`get_config()`** - Get current monitoring configuration
- **`get_statistics()`** - Get monitoring statistics (JSON-serializable)
- **`_enhanced_monitoring_loop()`** - Main monitoring loop (async)
- **`_poll_alerts_enhanced()`** - Poll alerts with proper severity filtering (async)
- **`_create_enhanced_snapshot(cleaned_alerts)`** - Create snapshot with proper severity counting
- **`_detect_high_severity_alerts_enhanced(cleaned_alerts, current_snapshot)`** - Detect new high-severity alerts
- **`_generate_automatic_report_enhanced(all_alerts, triggered_alerts)`** - Generate automatic threat report (async)
- **`_auto_convert_to_pdf_enhanced(report_path)`** - Auto-convert report to PDF (async)
- **`_update_alert_history(snapshot)`** - Update alert history for trend analysis
- **`get_alert_trends(hours)`** - Get alert trends over specified time period
- **`cleanup_old_hashes(max_age_hours)`** - Clean up old alert hashes to prevent memory growth

### Functions:

- **`create_enhanced_live_monitoring_service(config_manager, report_generator, ssh_reader_factory)`** - Factory function to create monitoring service

---

## main.py

### Class: `FixedSOCApplication`

**Purpose**: Main FastAPI application orchestrating all SOC components

#### Methods:

- **`lifespan(app)`** - Async context manager for application startup/shutdown
- **`__init__(config_file)`** - Initialize application with all components
- **`_init_components()`** - Initialize all application components (RAG, SSH, monitoring, PDF)
- **`_create_ssh_reader()`** - Factory method to create SSH reader instances
- **`_setup_routes()`** - Setup all FastAPI routes
- **`_build_rag_with_progress(session_id, use_archives, use_uploads, archive_days, custom_docs)`** - Build RAG context with progress tracking (async)
- **`_generate_visual_report_with_progress(session_id)`** - Generate visual report with charts (async)
- **`_analyze_alerts_with_progress(session_id, include_charts)`** - Analyze alerts with optional charts (async)
- **`_auto_convert_report(report_path)`** - Auto-convert report to PDF if enabled (async)
- **`_restore_monitoring_state()`** - Restore monitoring state on startup (async)
- **`run(host, port)`** - Run the application with uvicorn

### FastAPI Routes (defined in `_setup_routes`):

- **`GET /`** - Dashboard HTML page
- **`WebSocket /ws/progress/{session_id}`** - Progress tracking WebSocket
- **`POST /build-rag`** - Build/update RAG context from sources
- **`POST /generate-visual-report`** - Generate visual report with charts only
- **`GET /chart-capabilities`** - Get chart generation capabilities
- **`POST /analyze-alerts`** - Analyze current alerts with RAG
- **`POST /convert-to-pdf`** - Convert single markdown report to PDF
- **`POST /batch-convert-pdf`** - Convert all markdown reports to PDF
- **`GET /pdf-status`** - Get PDF conversion capabilities
- **`POST /set-auto-convert`** - Set auto-convert to PDF setting
- **`GET /auto-convert-status`** - Get current auto-convert setting
- **`GET /rag-status`** - Get current RAG status
- **`GET /reports`** - List generated reports (MD, PDF, HTML)
- **`GET /reports/{filename}`** - Download or view specific report
- **`GET /test-connection`** - Test SSH connection to Wazuh server
- **`GET /system-status`** - Get system status including chart capabilities
- **`POST /check-duplicates`** - Check if uploaded files are duplicates

### Functions:

- **`update_config_for_charts(config_manager)`** - Update config to create charts directory
- **`main()`** - Main entry point, validate environment and start application

---

## pdf_converter.py

### Class: `EnhancedPDFConverter`

**Purpose**: Convert markdown reports to PDF using multiple backends

#### Methods:

- **`__init__()`** - Initialize PDF converter and detect available methods
- **`_detect_conversion_methods()`** - Detect available PDF conversion methods (weasyprint/reportlab/pandoc)
- **`get_conversion_status()`** - Get status of PDF conversion capabilities
- **`convert_markdown_to_pdf(md_path, output_dir)`** - Convert markdown to PDF using best available method (async)
- **`_convert_with_weasyprint(md_path, pdf_path)`** - Convert using weasyprint library
- **`_convert_with_reportlab(md_path, pdf_path)`** - Convert using reportlab library (basic)
- **`_convert_with_pandoc(md_path, pdf_path)`** - Convert using pandoc system command
- **`batch_convert(reports_dir)`** - Convert all markdown files in directory (async)

### Class: `EnhancedPDFAPIHandlers`

**Purpose**: FastAPI endpoint handlers for PDF conversion

#### Methods:

- **`__init__(reports_dir)`** - Initialize with reports directory
- **`handle_single_conversion(filename)`** - Handle single file conversion request (async)
- **`handle_batch_conversion()`** - Handle batch conversion request (async)
- **`get_status()`** - Get PDF conversion status for API

### Functions:

- **`create_enhanced_pdf_converter()`** - Factory function to create PDF converter
- **`create_enhanced_pdf_api_handlers(reports_dir)`** - Factory function to create API handlers

---

## progress.py

### Class: `ProgressTracker`

**Purpose**: Track and broadcast progress for long-running operations via WebSocket

#### Methods:

- **`__init__(max_sessions, session_timeout)`** - Initialize progress tracker
- **`connect(session_id, websocket, operation_type)`** - Connect WebSocket client for session (async)
- **`disconnect(session_id)`** - Disconnect WebSocket client
- **`send_progress(session_id, message, progress, status)`** - Send progress update to client (async)
- **`cleanup_old_sessions()`** - Remove expired sessions
- **`start_cleanup_task()`** - Start background cleanup task (async)
- **`stop_cleanup_task()`** - Stop background cleanup task
- **`_cleanup_loop()`** - Background loop to cleanup old sessions (async)
- **`get_session_info(session_id)`** - Get information about specific session
- **`get_all_stats()`** - Get statistics for all sessions

### Functions:

- **`generate_session_id()`** - Generate unique session ID (UUID)

---

## rag.py

### Class: `DocumentProcessor`

**Purpose**: Process documents for RAG with duplicate detection

#### Methods:

- **`__init__(uploads_dir)`** - Initialize document processor
- **`check_duplicate(content, filename)`** - Check if content is duplicate via SHA-256 hash
- **`process_upload(content, filename, save_to_disk)`** - Process uploaded file (PDF/TXT/MD), extract text
- **`get_duplicate_stats()`** - Get statistics on duplicate documents

---

## report.py

### Class: `AlertAnalyzer`

**Purpose**: Analyze and classify security alerts

#### Methods:

- **`__init__()`** - Initialize alert analyzer
- **`_is_internal_ip(ip)`** - Check if IP is internal (RFC1918)
- **`_is_infrastructure_ip(ip)`** - Check if IP belongs to the local monitoring infrastructure
- **`_classify_ip_context(ip)`** - Classify IP as infrastructure/internal/external
- **`_extract_geolocation_with_geoip(data, ip_field, geoip_manager)`** - Extract GeoIP context for external IPs
- **`_classify_threat(alert)`** - Determine threat direction and internal/external classification
- **`analyze_current_alerts(alerts)`** - Summarize severity, protocols, sources, and threat direction
- **`clean_log_data(logs)`** - Process raw alerts, add classification and context

### Class: `ReportGenerator`

**Purpose**: Generate AI-powered threat analysis reports with RAG

#### Methods:

- **`__init__(llm_config, templates_dir, reports_dir, db_config)`** - Initialize report generator
- **`get_rag_status()`** - Get current RAG status from database
- **`clean_log_data(raw_logs)`** - Clean and classify raw log data using AlertAnalyzer
- **`build_rag_context(archive_logs, custom_docs)`** - Build RAG vector database from alerts and documents
- **`add_custom_documents(docs)`** - Add uploaded CTI documents to the RAG database
- **`get_generation_metrics()`** - Return report timing and approval metrics
- **`mark_report_approved()`** - Track human approval of an edited report
- **`generate_report_with_rag(current_alerts, server_ip, is_automatic, trigger_info)`** - Generate complete RAG-enhanced report
- **`get_chart_capabilities()`** - Get chart generation capabilities
- **`generate_visual_report(alerts, output_path)`** - Generate report with only charts (no LLM analysis)

---

## ssh.py

### Class: `SmartSSHLogReader`

**Purpose**: Read security logs from remote Wazuh server via SSH

#### Methods:

- **`__init__(host, username, password, port, alerts_path, archives_base_path)`** - Initialize SSH reader
- **`connect()`** - Establish SSH connection using Paramiko
- **`disconnect()`** - Close SSH connection
- **`read_alerts(max_lines)`** - Read current alerts from alerts.json file
- **`read_archives_smart(days)`** - Read archive logs from the last N days, including `.json` and `.json.gz` files

---

## Templates

### cti.txt

**Purpose**: System prompt for Qwen LLM (Cyber Threat Intelligence analyst persona)

**Instructions include**:
- Core responsibilities (alert analysis, threat intelligence, report generation)
- Infrastructure awareness (filter out monitoring systems)
- IP classification logic (infrastructure/internal/external)
- Threat direction analysis (inbound/outbound/lateral)
- Alert processing with context awareness
- Infrastructure filtering rules
- Geolocation analysis guidelines
- HTTP context analysis
- Report structure requirements (max word counts, table limits)
- Severity classification (CRITICAL/HIGH/MEDIUM/LOW)
- Response format requirements (start/end markers, no conversational language)
- Strict formatting rules (no duplicate headers, proper markdown)

### qwen_chat.j2

**Purpose**: Jinja2 chat template for Qwen3 model message formatting

**Template structure**:
- Formats system/user/assistant/tool messages
- Uses Qwen-specific tokens (`<|im_start|>`, `<|im_end|>`)
- Supports tool calling with XML format
- Handles multi-turn conversations

### dashboard.html

**Purpose**: Interactive web UI for SOC analysts

**JavaScript Functions**:

- **`toggleOptions()`** - Show/hide RAG source options
- **`updateBuildButtonState()`** - Enable/disable build RAG button based on selections
- **`validateFiles()`** - Validate uploaded files and check for duplicates (async)
- **`updateRAGStatus(ready, message)`** - Update RAG status indicator
- **`showProgress(sessionId, operation, onComplete)`** - Display WebSocket progress tracking
- **`buildRAG()`** - Initiate RAG build process (async)
- **`analyzeAlerts()`** - Analyze current alerts (async)
- **`convertSingleReport()`** - Convert single report to PDF (async)
- **`batchConvertReports()`** - Batch convert all reports to PDF (async)
- **`loadReports()`** - Load and display reports list (async)
- **`convertReport(filename)`** - Convert specific report to PDF (async)
- **`downloadReport(filename)`** - Download report file
- **`checkRAGStatus()`** - Check and update RAG status (async)
- **`checkPDFStatus()`** - Check PDF conversion capabilities (async)
- **`checkAutoConvertStatus()`** - Check auto-convert setting (async)
- **Event listeners**: Auto-convert checkbox, upload checkbox

**Page Sections**:
- Server info display
- RAG configuration form
- Manual analysis button
- PDF conversion section
- Reports list with actions
