# Installation and operations

Use this guide to deploy the analyser on Linux, configure its integrations, and maintain its data. Run the commands from the repository root unless a step specifies another directory. [README](../README.md)

## Installation

### PostgreSQL and Python

On Ubuntu, install the base system packages.

```bash
sudo apt update
sudo apt install git python3-venv postgresql postgresql-contrib
```

Install pgvector for the **server's** PostgreSQL major version. If your distribution repository lacks a matching package, follow the PostgreSQL APT Repository or source-build instructions in the [pgvector installation guide](https://github.com/pgvector/pgvector#installation).

Open `sudo -u postgres psql`, then create the role and database. The `\password` command prompts for the password. Use the same password in the application configuration.

```sql
CREATE ROLE soc_user LOGIN;
\password soc_user
CREATE DATABASE soc_rag OWNER soc_user;
\connect soc_rag
CREATE EXTENSION IF NOT EXISTS vector;
CREATE EXTENSION IF NOT EXISTS pg_trgm;
\quit
```

The app requires `vector`. The optional `pg_trgm` extension can accelerate the text fallback used in exact matching. Startup initialises the application schema. Pre-creating the database lets the application role operate without `CREATEDB`.

Create the virtual environment and install packages using the [README installation steps](../README.md#installation). For PDF export with Python wheels on Ubuntu, install the Pango and HarfBuzz libraries below. [WeasyPrint installation guide](https://doc.courtbouillon.org/weasyprint/stable/first_steps.html#ubuntu-20-04)

```bash
sudo apt install libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz0b libharfbuzz-subset0
```

### Local model files

Build or install a llama.cpp release that can serve your chosen Qwen GGUF. For NVIDIA GPU offload, use a CUDA build compatible with the installed driver and GPU architecture. Record the tested llama.cpp revision and model quantisation for repeatable deployments. `llama-cli --list-devices` checks the devices the binary can see. [llama.cpp build instructions](https://github.com/ggml-org/llama.cpp/blob/master/docs/build.md)

Place the GGUF and executable outside the repository, with read and execute permissions as appropriate for the service account. For persistent inference, install the matching `llama-server` alongside `llama-cli` or configure its path or URL. [Local backend selection](llm-providers.md#local-llm)

### Starter configuration

Create a private repository-root `.env`. Use an editor to enter the values and keep the file out of Git.

```bash
(umask 077 && touch .env)
chmod 600 .env
python -c 'import secrets; print(secrets.token_urlsafe(48))'
```

Use the generated value for `WEB_SESSION_SECRET`. Replace each placeholder in this example.

```dotenv
WEB_USERNAME=soc_admin
WEB_PASSWORD=replace-with-a-strong-bootstrap-password
WEB_SESSION_SECRET=replace-with-generated-value
WEB_ALLOW_REGISTRATION=false
DB_HOST=localhost
DB_PORT=5432
DB_NAME=soc_rag
DB_USER=soc_user
DB_PASSWORD=replace-with-database-password
LLM_MODEL_PATH=/absolute/path/to/qwen.gguf
LLM_BINARY_PATH=/absolute/path/to/llama-cli
LLM_PROVIDER=local
```

Leave the SSH credential fields unset for upload-only operation. For Public LLM, add the appropriate [Anthropic settings](llm-providers.md#public-llm).

### Preflight and startup

Run preflight with the same environment as the service. It checks configuration, dependency discoverability, model and template paths, and PostgreSQL/pgvector access. Use `--json` for structured output or `--skip-db` for a check without a database connection. Use `--config /path/to/config.json` to check the same JSON overlay you will pass positionally to `main.py`. Preflight validates and can create or change the permissions of the configured report and upload directories.

```bash
source .venv/bin/activate
python Linux_LLM/config/runtime_preflight.py --json
python Linux_LLM/config/main.py
```

Preflight confirms prerequisites. Verify model generation, CTI extraction, and report export separately with an isolated corpus. [Testing and acceptance](#testing-and-acceptance)

### Running as a service

Use one application process. Corpus locks, model-job reservations, drafts and progress are process-local. For remote browser access, terminate TLS at a trusted reverse proxy, preserve the public Host and HTTPS scheme, and forward WebSocket upgrades. Set a total request-body limit at ingress because multipart parsing can spool data before the application applies its own limits.

Example `/etc/systemd/system/soc-rag.service`, assuming a deployment under `/opt/soc-rag` and an existing service account named `soc-rag`. Set `ENV_FILE` to the protected configuration readable by this account. Verify the model, state and virtual-environment paths before starting.

```ini
[Unit]
Description=Wazuh Telemetry Analyser
Wants=network-online.target
After=network-online.target postgresql.service

[Service]
User=soc-rag
Group=soc-rag
WorkingDirectory=/opt/soc-rag
Environment=ENV_FILE=/etc/soc-rag/soc-rag.env
ExecStart=/opt/soc-rag/.venv/bin/python /opt/soc-rag/Linux_LLM/config/main.py
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now soc-rag
journalctl -u soc-rag -f
```

Stop the service normally so it can shut down monitoring and inference, drain admitted work, and close database resources. An admitted corpus build may finish and activate during the drain. Set the service stop timeout to accommodate the work your configuration permits. Back up state before deploying an update, install dependencies from the revision you are deploying, then run preflight and check readiness after restart.

## Configuration

The loader applies built-in defaults, the optional JSON overlay, then dotenv and exported environment values. Dotenv candidates are read in order from the repository root, `Linux_LLM/`, `Linux_LLM/config/`, the current working directory, the JSON file's directory when supplied, and the path in `ENV_FILE`. Later dotenv values override earlier ones. Exported process values take precedence over all files.

To locate additional settings, use the dataclasses and environment mapping in [config.py](../Linux_LLM/config/config.py). Provider settings live in the [LLM guide](llm-providers.md).

### Accounts and state

| Setting | Default or requirement |
| --- | --- |
| `WEB_HOST`, `WEB_PORT` | `127.0.0.1`, `8000` |
| `WEB_USERNAME`, `WEB_PASSWORD` | Required at startup. The password must contain at least 12 characters. The app seeds the first admin when the account database is empty. |
| `WEB_SESSION_SECRET` | Required, at least 32 characters. Keep it with the protected auth backup. |
| `WEB_ALLOW_REGISTRATION` | `true`. Self-registration creates analyst accounts. Set `false` for admin-created accounts only. |
| `AUTH_DB_PATH` | `~/.local/state/soc-rag/users.sqlite3`, independent of `XDG_STATE_HOME` |
| `REPORTS_DIR`, `UPLOADS_DIR` | `reports` and `uploads` under `${XDG_STATE_HOME:-$HOME/.local/state}/soc-rag` |
| `TEMPLATES_DIR` | `Linux_LLM/config/templates` in the checkout. This setting supplies the model prompt and chat template path. The web UI templates load from the checkout. |

Accounts and audit events are stored in SQLite. The account store uses password hashes and encrypts TOTP secrets with a key derived from `WEB_SESSION_SECRET`. Changing the secret invalidates signed sessions and makes existing MFA secrets unreadable. Administrators can manage accounts and reset another user's MFA from **Accounts**, and inspect recorded actions in **Audit log**. The authenticated session expires after eight hours.

### Database and retrieval

| Setting | Default or requirement |
| --- | --- |
| `DB_HOST`, `DB_PORT` | `localhost`, `5432` |
| `DB_NAME`, `DB_USER` | `soc_rag`, `soc_user`. `DB_NAME` takes precedence over legacy `DB_DATABASE`. |
| `DB_PASSWORD` | Required |
| `DB_CONNECT_TIMEOUT` | 10 seconds for runtime database connections |
| `DB_AUTO_CREATE` | `false`. When enabled, the role needs permission to create a missing database. |
| `RAG_EMBEDDING_MODEL`, `RAG_EMBEDDING_DIMENSIONS` | `Qwen/Qwen3-Embedding-0.6B`, 1024 dimensions. Match pgvector column width to the embedding output. |
| `RAG_EMBEDDING_DEVICE`, `RAG_EMBEDDING_DEVICES` | Resident model defaults to `cpu`. An empty bulk list discovers compatible CUDA devices. Set the bulk list to `cpu` to use CPU for bulk builds. |
| `RAG_EMBEDDING_BATCH_SIZE`, `RAG_EMBEDDING_MULTI_GPU_MIN_CHUNKS` | 32 for the configured short-input batch cap and 64 pending chunks for the multi-process threshold |
| `RAG_DOCUMENT_CHUNK_SIZE`, `RAG_DOCUMENT_CHUNK_OVERLAP` | 1,200 and 120 characters |
| `RAG_MAX_DOCS` | 10 retrieved sources |
| `RAG_SIMILARITY_THRESHOLD`, `RAG_EVIDENCE_SIMILARITY_THRESHOLD` | 0.20 candidate floor and 0.35 semantic evidence floor. These are similarity thresholds, not measured accuracy. |
| `RAG_VECTOR_INDEX_TYPE`, `RAG_VECTOR_INDEX_MIN_ROWS` | `ivfflat` and 1,000 embedded rows per table. Choose `hnsw` or `none` to change index maintenance. |

A change to embedding model, dimensions, document instructions, normalisation, or chunking can invalidate the active corpus manifest. Rebuild from the required source set when the running configuration is incompatible. A dimension change also requires a schema with the new vector width. [Corpus lifecycle](rag-architecture.md#corpus-activation)

### Wazuh SSH

Configure `SSH_HOST`, `SSH_USERNAME` and `SSH_PASSWORD` together. Use a read-only account with access to the relevant Wazuh files. Port and timeout default to `22` and `30` seconds. Host-key checking is enabled by default. Supply a trusted known-hosts file with `SSH_KNOWN_HOSTS_PATH` if needed. `SSH_ALLOW_UNKNOWN_HOST` defaults to `false`.

`WAZUH_ALERTS_PATH` defaults to `/var/ossec/logs/alerts/alerts.json`. `WAZUH_ARCHIVES_PATH` defaults to `/var/ossec/logs/archives`. The archive reader looks for daily `ossec-archive-<day>.json` or `.json.gz` files in year and month subdirectories. Wazuh must be configured to produce JSON archives. [Wazuh event logging](https://documentation.wazuh.com/current/user-manual/manager/event-logging.html)

`LIVE_MONITORING_ENABLED=false` disables the automatic monitoring loop. Remove the SSH credential group to disable Wazuh SSH reads entirely. The automatic analysis threshold of 8 is an application setting in code. Wazuh defines rule levels from 0 to 16. [Wazuh rules classification](https://documentation.wazuh.com/current/user-manual/ruleset/rules/rules-classification.html)

### GeoIP and asset inventory

Set `GEOIP_DB_PATH` to the absolute path of a readable MaxMind City `.mmdb` file, such as GeoLite2 City. The `geoip2` package is required by the application, while the database is optional. The alert cleaner attempts local city lookups for eligible external source and destination addresses. Local and infrastructure addresses are excluded. An unset path, unavailable database, or missing match leaves the corresponding location fields absent. Preflight checks whether the configured file exists. Use an alert with an eligible address in an isolated environment to verify lookup results. [GeoIP implementation](../Linux_LLM/config/report.py)

Use `ASSET_OWNED_CIDRS` for ranges you own, `ASSET_INFRASTRUCTURE_IPS` for known monitoring or gateway addresses, and `ASSET_INTERNAL_CIDRS` for internal scopes. All accept comma-separated values. Owned and infrastructure scopes default to empty. Internal scopes default to the IPv4 private ranges and loopback listed in `AssetInventoryConfig`. These settings inform alert direction and response targets.

### Input and resource limits

| Area | Defaults |
| --- | --- |
| Manual alert uploads | `MAX_ALERT_UPLOAD_BYTES` 5 MiB, `MAX_ALERT_RECORDS` 1,000 |
| CTI uploads | `MAX_DOCUMENT_FILES` 50, `MAX_DOCUMENT_BATCH_BYTES` 100 MiB. Format-specific caps also apply. |
| Current SSH read | `MAX_CURRENT_ALERT_LINES` 1,000, `MAX_CURRENT_ALERT_BYTES` 20 MiB, `MAX_ALERT_LINE_BYTES` 1 MiB |
| Archive read | `MAX_ARCHIVE_DAYS` 31, `MAX_ARCHIVE_RECORDS` 100,000, `MAX_ARCHIVE_BYTES` 100 MiB expanded, `MAX_ARCHIVE_LINE_BYTES` 1 MiB |
| Process-local resource limits | `MAX_DRAFTS` 100, `MAX_SESSION_RESULTS` 200, `MAX_BACKGROUND_TASKS` 8, `MAX_WORKER_THREADS` 4 |

## Health and troubleshooting

| Symptom or check | What to inspect |
| --- | --- |
| Service fails at startup | Run preflight and check the startup logs. Check the session secret and bootstrap password lengths, since `main.py` enforces them at startup. |
| `GET /health` | Unauthenticated liveness. A running endpoint returns `{"status":"ok"}`. |
| `GET /ready` | Unauthenticated configuration and dependency preflight, including PostgreSQL. Success returns `{"status":"ready"}`. A failed check returns HTTP 503. Check corpus readiness separately. |
| `GET /system-status`, `GET /test-connection` | Signed-in diagnostics. Check the Wazuh host key, file permissions and configured paths when SSH reads fail. |
| `GET /rag-status` | Check `ready`, `active_corpus_id`, version compatibility and source/chunk counts after a build or rollback. A compatible corpus can still lack the expected source documents. |
| CTI or archive build fails | Check the reported source and limits. Review PDF text extraction, Wazuh JSON archive output, and embedding device compatibility. The prior ready corpus remains selected on a failed build. |
| Provider unavailable or busy | Check the selected provider, local runtime or Anthropic access, and the analysis queue. [Provider guide](llm-providers.md) |
| Progress stale or draft missing | A browser refresh can reattach to an active manual job. Drafts and queued alert payloads live in process memory, so a restart can require resubmission. |
| PDF export fails | Check signed-in `GET /pdf-status` and WeasyPrint's system libraries. The renderer restricts resource loading to permitted local report assets. |

Use the service journal for errors and normal timings. `LLM_DEBUG_COMMANDS=true` enables local command logging. `REPORT_DIAGNOSTIC_TRACE=true` can write prompt and report evidence, including telemetry and retrieved text, to disk. Set `REPORT_DIAGNOSTIC_TRACE_DIR` to a protected directory if diagnosing report quality.

## Backup and recovery

Back up PostgreSQL, the report directory, the SQLite auth database and the corresponding `WEB_SESSION_SECRET`. Take the SQLite backup with the service stopped or via SQLite's backup interface. Preserve the permissions on all state and configuration. Record the deployed revision, active corpus ID, and the configured embedding model and vector width.

For PostgreSQL, use an interactive password prompt or protected PostgreSQL credentials. This example assumes PostgreSQL runs on the Ubuntu deployment host, with local access for the system account `postgres`.

```bash
pg_dump -h localhost -U soc_user -Fc -f soc-rag.dump soc_rag
sudo -u postgres createdb -O soc_user soc_rag_restore
sudo -u postgres pg_restore -d soc_rag_restore --exit-on-error < soc-rag.dump
```

Keep the dump outside the deployed checkout. Ensure the target server has the required extensions and roles before restoring. Run the app against the restored database and isolated report/upload state before redirecting an existing service to it.

To roll back a corpus, quiesce the app and use `RAGContextManager.activate_corpus(corpus_id)` in a maintenance process with the deployed configuration. It validates the target before moving the pointer. Check the active ID and source counts afterward. This is a host-side API. Direct SQL updates to the active pointer bypass those checks. [Corpus activation](rag-architecture.md#corpus-activation)

## Testing and acceptance

Run the regression suite in an isolated environment with the project dependencies. Install `httpx` for the HTTP tests that use FastAPI's `TestClient`. The editor regression uses Node's built-in test runner.

```bash
cd Linux_LLM
python -m unittest discover -s tests -p 'test_*.py'
node --test tests/test_report_editor_fidelity.js
cd ..
python Linux_LLM/tools/check_repository.py
```

Use a disposable PostgreSQL database, auth database, report directory and upload directory for integration checks. Clear live SSH credentials and disable automatic monitoring. Exercise these workflows with representative data.

1. Build a small corpus, extend it with a new source, repeat an identical upload, and confirm the expected source counts and active corpus ID.
2. Submit an alert with a known exact indicator, an alternative input schema, and an alert with no reliable match. Compare retrieval sources, network direction, ATT&CK evidence class, attribution and recommended actions with the input evidence.
3. Check GeoIP with a readable City database and with the setting unset. For GPU validation, verify device placement and record memory at the model, context size, and workload you intend to use.
4. Generate a report with each configured provider, check the analysis queue, then review, approve, and download Markdown and PDF. Live Public LLM testing sends evidence to the configured API and uses account quota. Mocked provider tests cover failure handling independently.

For focused extraction and retrieval checks, see [validate_rag_flow.py](../Linux_LLM/tools/validate_rag_flow.py). Its `--skip-generation` option skips the report model call. The tool builds a corpus, so point it at the disposable database.
