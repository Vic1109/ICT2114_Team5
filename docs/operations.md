# Operations

This runbook covers configuration, preflight, startup, corpus lifecycle, backup, recovery, troubleshooting, deployment, and rollback for the AI-driven SOC/RAG application.

Commands use placeholders and repository-relative paths. Substitute values through the environment or a protected configuration file; never paste credentials, private hosts, alert contents, or model prompts into source control.

## Safety boundary

- At this cleanup handoff, the reviewed source changes remain undeployed; no production service, database, or corpus was restarted or changed.
- Source changes do not deploy themselves.
- Do not restart the installed service, rebuild its corpus, activate a namespace, or restore its database until the change has been reviewed and a maintenance window is authorized.
- Run tests and miniature-corpus validation against an isolated database.
- Take a database backup and record `active_corpus_id` before every production corpus mutation.
- Keep the dashboard and PostgreSQL on trusted interfaces. Put remote dashboard access behind a TLS reverse proxy and network policy.
- Use a dedicated unprivileged service account, least-privilege database role, and read-only Wazuh SSH account.

## Expected directories and permissions

Use deployment-owned paths rather than personal home or desktop paths. A typical layout is:

```text
/opt/soc-rag/                  read-only deployed application
/opt/soc-rag/.venv/           Python environment
/srv/soc-rag/models/          read-only GGUF model for service account
/var/lib/soc-rag/reports/     writable approved/generated reports and charts
/var/lib/soc-rag/uploads/     writable runtime upload area, if enabled
/var/lib/soc-rag/geoip/       optional read-only GeoIP database
/var/backups/soc-rag/         protected database/report backups
```

Recommended ownership and access:

- source, templates, llama.cpp, model, and GeoIP files: readable but not writable by the service;
- reports/uploads: owned by the service account, mode `0750` directories and `0640` files or stricter;
- `.env`, JSON configuration, `.pgpass`, and SSH keys/known-hosts: readable only by the service account;
- backups: separate restricted location with retention and restore tests.

By default, `REPORTS_DIR` and `UPLOADS_DIR` resolve below `${XDG_STATE_HOME:-$HOME/.local/state}/soc-rag`; if `XDG_STATE_HOME` is unset this is `$HOME/.local/state/soc-rag`. `TEMPLATES_DIR` defaults to the checked-out `Linux_LLM/config/templates` directory. A managed service may override the state paths with the `/var/lib` layout above. The application does not require write access to the Git checkout.

## Install dependencies

Create an isolated Python environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r Linux_LLM/config/requirements.txt
```

The pinned set includes PyMuPDF plus the pypdf fallback, PyYAML for structured YAML CTI, and the Markdown/WeasyPrint Python packages. WeasyPrint also needs distribution-level native libraries; see [Optional PDF rendering](#optional-pdf-rendering).

Install PostgreSQL and the pgvector package appropriate for the host PostgreSQL version. Create the database and role through the normal administration process, then install the extension:

```sql
CREATE EXTENSION IF NOT EXISTS vector;
```

The application can create a missing configured database when the role has `CREATEDB`, but pre-creating the database and granting only required schema privileges is preferable in production.

Build or install a llama.cpp `llama-cli` compatible with the selected GGUF and host GPU/CPU backend. Keep the binary and model outside the repository.

## Configuration loading

`ConfigManager` applies configuration in this order:

1. portable defaults in `Linux_LLM/config/config.py`;
2. an optional JSON file passed as the first argument to `main.py`;
3. `.env` discovered at the repository root, `Linux_LLM/`, `Linux_LLM/config/`, the current directory, the JSON-file directory, or `ENV_FILE`;
4. already exported process environment variables.

Exported environment variables are not overwritten by `.env` values. Use one deployment-owned `ENV_FILE` for a managed service to avoid ambiguous discovery.

Boolean aliases accept only `true/false`, `yes/no`, `on/off`, or `1/0` (case-insensitive); typos fail configuration instead of silently becoming false. `DB_NAME` takes precedence when both it and legacy `DB_DATABASE` are present. An `XDG_STATE_HOME` value loaded from `ENV_FILE` participates in default report/upload path construction unless those paths were explicitly set in JSON or environment variables.

Start from the sanitized template:

```bash
cp .env.example .env
chmod 600 .env
```

Do not use checked-in defaults as production secrets. `ConfigManager.validate_all()` rejects missing web, database, model, binary, and required-path settings before the application starts. SSH host/user/password may all be empty for offline upload workflows, but a partial SSH credential group is invalid.

## Configuration reference

### Web and authentication

| Variable | Meaning | Operational guidance |
| --- | --- | --- |
| `WEB_USERNAME` | HTTP Basic Auth user | Required; do not use a common default. |
| `WEB_PASSWORD` | HTTP Basic Auth password | Required and sensitive; use a long random value. |
| `WEB_HOST` | Uvicorn bind address | Keep `127.0.0.1` unless a controlled network design requires otherwise. |
| `WEB_PORT` | Uvicorn port | Must be an unused valid TCP port. |

HTTP Basic credentials are only confidential when carried over TLS. Progress WebSockets validate the same Basic Authorization header and browser Origin/Host boundary. State-changing HTTP methods reject cross-origin browser requests while non-browser clients without Origin/Referer remain supported. Responses set no-store, anti-framing, nosniff, referrer, permissions, and content-security headers. The remaining Marked JavaScript and Bootstrap CSS CDN assets are version-pinned with Subresource Integrity and no-referrer requests; a no-egress deployment should vendor those exact reviewed files. If the application is behind a reverse proxy, preserve the public Host, terminate TLS there, use WSS, and forward authenticated WebSocket upgrades without stripping Authorization.

The live-alert list returns only the fields rendered by the page plus the stable full-record selection hash; it does not send complete Wazuh objects to the browser. Report preview escapes raw HTML, parses Markdown inside an inert template, retains a small element/attribute allowlist, rejects unsafe link schemes, and rewrites only local generated-chart images to the authenticated chart route.

### PostgreSQL and pgvector

| Variable | Meaning | Operational guidance |
| --- | --- | --- |
| `DB_HOST` | PostgreSQL host | Prefer loopback or a private database network. |
| `DB_PORT` | PostgreSQL port | Match the installed instance. |
| `DB_NAME` | RAG database | Canonical name; it wins when the `DB_DATABASE` compatibility alias is also set. |
| `DB_USER` | Application role | Needs schema/table/vector access; `CREATEDB` is optional. |
| `DB_PASSWORD` | Application-role password | Required and sensitive. |
| `DB_CONNECT_TIMEOUT` | PostgreSQL connect timeout in seconds | Positive and bounded; applies to runtime/bootstrap connections. |
| `DB_AUTO_CREATE` | Permit missing-database creation | Off by default. Enable only for an explicitly authorized bootstrap role/workflow. |

`RAGContextManager` uses one long-lived connection protected by its database/corpus locks; rollback uses the same lock and cannot cross another transaction owner. Application shutdown closes the connection through the report-pipeline lifecycle. PostgreSQL connection failures stop startup or return concise route errors; keep database diagnostics restricted to operators. A missing database is a startup failure unless `DB_AUTO_CREATE=true`; production roles should normally use a pre-created database and leave this option false. Preflight applies both a short connect timeout and PostgreSQL statement timeout. Normal runtime statements rely on server/role policy for statement timeout, so set that policy on the production role.

Startup schema initialization uses idempotent `CREATE ... IF NOT EXISTS` DDL and does not drop/rebuild full-text indexes. It removes legacy single-column uniqueness constraints only when catalog inspection proves they still exist. Treat any first upgrade from a pre-corpus schema as migration DDL: back up first and run it during an authorized window.

### Wazuh SSH input

| Variable | Meaning | Operational guidance |
| --- | --- | --- |
| `SSH_HOST` | Wazuh host | Set together with username/password to enable live/archive collection. |
| `SSH_PORT` | SSH port | Default SSH port unless deployment differs. |
| `SSH_USERNAME` | Read-only Wazuh account | Limit access to required alert/archive files. |
| `SSH_PASSWORD` | SSH password | Sensitive; use protected service configuration. |
| `SSH_TIMEOUT` | Connect/banner/auth timeout in seconds | Positive bounded value. |
| `SSH_KNOWN_HOSTS_PATH` | Trusted known-hosts file | Preferred explicit trust source. |
| `SSH_ALLOW_UNKNOWN_HOST` | Permit unknown host keys | Leave false; temporary lab use only. |
| `WAZUH_ALERTS_PATH` | Remote current alert JSON path | Must be readable by the SSH account. |
| `WAZUH_ARCHIVES_PATH` | Remote archive root | Daily year/month files are discovered below it. |
| `MAX_CURRENT_ALERT_LINES` | Maximum live/current alert lines per read | Positive cap; default is 1,000. |
| `MAX_CURRENT_ALERT_BYTES` | Maximum total bytes in one current-alert read | Positive request cap; default is 20 MiB. |
| `MAX_ALERT_LINE_BYTES` | Maximum bytes in one current-alert line | Positive cap; default is 1 MiB. An overlong line aborts that read. |
| `MAX_ARCHIVE_DAYS` | Maximum archive lookback per request | Positive cap; default is 31 days. |
| `MAX_ARCHIVE_RECORDS` | Maximum archive objects per read | Positive cap; default is 100,000. |
| `MAX_ARCHIVE_BYTES` | Maximum expanded archive bytes per request | Shared across selected JSON and decompressed JSON.GZ files; default is 100 MiB. |
| `MAX_ARCHIVE_LINE_BYTES` | Maximum bytes in one archive JSON record | Positive cap; default is 1 MiB. |

Leave host, username, and password all empty to disable Wazuh integration for uploaded-alert/document-only workflows. A partially configured group fails validation. `SmartSSHLogReader` disables agent/key discovery for password-based configuration and uses verified host keys by default. Its readers close SFTP/SSH resources after each bounded operation or on application shutdown.

When SSH is disabled, live alerts, archive ingestion, connection testing, and automatic Wazuh monitoring are unavailable; uploaded CTI and Manual Alert Analysis remain available when the database, corpus, and model are ready.

The seven SSH-read bounds cap current lines, total bytes, and line size plus archive days, records, expanded bytes, and individual archive lines. `MAX_ARCHIVE_BYTES` is a request-wide expanded-data budget, so compressed files cannot bypass it. Archive inputs must be UTF-8 JSON objects; a malformed/non-object record aborts the complete requested source set instead of being skipped. Remote paths and connection details are not added to evidence, corpus hashes, or normal logs.

FastAPI routes run one-shot SSH connect/read/disconnect calls on the application-owned worker executor rather than on the event loop. Continuous monitoring and alert normalization use the same executor and hold one I/O lock across the persistent SSH lifecycle. A shared semaphore rejects submissions when the bounded active-plus-queued allowance is full; the thread pool's internal queue is therefore not an unbounded admission path. The single final persistent-SSH disconnect is teardown work: it runs off-loop without normal request admission so a saturated pool cannot prevent resource closure.

### Model and generation

| Variable | Meaning | Operational guidance |
| --- | --- | --- |
| `LLM_MODEL_PATH` | Local Qwen3-30B-family GGUF | Required, readable, configurable, and not stored in Git. |
| `LLM_BINARY_PATH` | Local `llama-cli` | Required and executable. |
| `LLM_TEMPERATURE` | Sampling temperature | Preserve validated production value unless behavior is intentionally re-evaluated. |
| `LLM_TOP_P` | Nucleus sampling | Preserve validated production value. |
| `LLM_TOP_K` | Top-k sampling | Preserve validated production value. |
| `LLM_CONTEXT_SIZE` | llama.cpp context window | Must fit system prompt, current evidence, CTI context, and output. |
| `LLM_MAX_TOKENS` | Maximum generated tokens | Large enough for required report sections. |
| `LLM_TIMEOUT` | Per-generation subprocess timeout | Also bounds Manual Alert Analysis wait time. |
| `LLM_DISABLE_THINKING` | Disable Qwen reasoning output | Keep enabled for report generation unless the model contract changes. |
| `LLM_DEBUG_COMMANDS` | Log complete llama.cpp argument lists | Off by default; enable only for short, access-controlled diagnostics. |

Additional `LLMConfig` fields—including model type, chat/system template files, GPU layers, main GPU, tensor split, mmap/mlock, batch sizes, flash attention, KV-cache types, threads, and penalties—can be supplied through the optional JSON configuration. They do not all have environment aliases. Record JSON overrides in deployment configuration management.

The current report model family is Qwen3-30B, but both the compatible GGUF and `llama-cli` paths remain deployment settings. `LlamaModelClient` invokes the binary without a shell, uses a temporary prompt file, starts the child in its own session, kills and reaps it on timeout/error, and removes the file. Normal logs show lifecycle state, not arguments, prompt content, model output, or stderr. Debug command logging is opt-in.

### Upload and in-memory bounds

| Variable | Meaning | Operational guidance |
| --- | --- | --- |
| `MAX_ALERT_UPLOAD_BYTES` | Maximum manual-alert upload size in bytes | Enforced while streaming, before full parsing; use a positive deployment-appropriate limit. |
| `MAX_ALERT_RECORDS` | Maximum alert objects in one manual upload | Bounds normalization, prompt work, and memory. |
| `MAX_DOCUMENT_FILES` | Maximum CTI files in one corpus-build request | Applied before background extraction begins. |
| `MAX_DOCUMENT_BATCH_BYTES` | Maximum combined uploaded CTI bytes per build request | Complements the per-format limits in `DocumentValidator`. |
| `MAX_DRAFTS` | Maximum in-memory report drafts | Oldest bounded state is evicted rather than growing without limit. |
| `MAX_SESSION_RESULTS` | Maximum in-memory analysis redirect results | Oldest bounded state is evicted rather than growing without limit. |
| `MAX_WORKER_THREADS` | Application-owned blocking worker threads | Bounds active SSH, extraction, RAG build, enrichment, preflight, and generation executor work; default is 4. |
| `MAX_BACKGROUND_TASKS` | Tracked application background jobs | Admission cap for build, analysis, and visual-report tasks; default is 8. |

These caps are production safeguards, not tuning knobs for retrieval behavior. Worker submission admission is derived from the worker/background caps and returns a busy error instead of accumulating work without limit. Draft and result state remains process-local and disappears on restart. Manual-analysis and document limits are enforced while endpoint code consumes each `UploadFile`; a multipart parser may have spooled request parts before that point. Configure a trusted reverse proxy or ASGI ingress to reject an excessive total request body before multipart parsing.

### Filesystem paths

| Variable | Meaning | Operational guidance |
| --- | --- | --- |
| `REPORTS_DIR` | Markdown, charts, and PDFs | Defaults to the state root's `reports`; writable only by the service account. |
| `TEMPLATES_DIR` | system/chat templates | Read-only deployed source path. |
| `UPLOADS_DIR` | upload-processing runtime area | Defaults to the state root's `uploads`; writable and quota-controlled. |
| `GEOIP_DB_PATH` | optional GeoLite-compatible database | Missing file is a warning; geolocation is skipped. |

The state root is `${XDG_STATE_HOME:-$HOME/.local/state}/soc-rag`. `XDG_STATE_HOME` loaded through `ENV_FILE` is applied before the default report/upload paths are finalized. Path environment variables or JSON path fields override these defaults when a deployment uses dedicated `/var/lib` or mounted storage. Existing report, upload, and chart directories are normalized to mode `0750`; atomic text reports and chart files use `0640`.

### RAG and embeddings

| Variable | Meaning | Operational guidance |
| --- | --- | --- |
| `RAG_DOCUMENT_CHUNK_SIZE` | Uploaded-document chunk size | Corpus identity input. |
| `RAG_DOCUMENT_CHUNK_OVERLAP` | Uploaded-document overlap | Must be less than document chunk size. |
| `RAG_EMBEDDING_MODEL` | SentenceTransformers model identifier/path | Corpus identity input. Pin/cache it operationally. |
| `RAG_EMBEDDING_DEVICE` | Single-query/small-batch device | Defaults to `cpu`; explicitly set `cuda` or `cuda:0` only on a validated backend. |
| `RAG_EMBEDDING_DEVICES` | Comma-separated bulk devices | Defaults empty; explicitly configure devices for sufficiently large non-query batches. |
| `RAG_EMBEDDING_DIMENSIONS` | pgvector width | Must match the embedding model and existing schema. |
| `RAG_EMBEDDING_BATCH_SIZE` | Encode batch size | Reduce on device-memory pressure. |
| `RAG_EMBEDDING_MULTI_GPU_MIN_CHUNKS` | Bulk multi-process threshold | Avoids process overhead for small jobs. |
| `RAG_MAX_DOCS` | Maximum retrieval documents | Preserve validated production behavior. |
| `RAG_SIMILARITY_THRESHOLD` | Minimum semantic similarity | Preserve validated production behavior. |
| `RAG_NORMALIZE_EMBEDDINGS` | Normalize vectors | Corpus identity input. |
| `RAG_RETRIEVAL_CANDIDATE_MULTIPLIER` | Candidate pool multiplier | Preserve validated production behavior. |
| `RAG_EMBEDDING_QUERY_INSTRUCTION` | Query instruction prefix | Corpus/retrieval contract input. |
| `RAG_EMBEDDING_DOCUMENT_INSTRUCTION` | Document instruction prefix | Corpus identity input. |

Do not alter chunking, exact-term weights, similarity threshold, attribution rules, or prompt policy as a quick production troubleshooting step. Diagnose extraction quality, active namespace, stale versions, database state, and model health first; behavioral changes require focused regression validation.

### Asset inventory

| Variable | Meaning |
| --- | --- |
| `ASSET_OWNED_CIDRS` | Comma-separated protected public/private ranges. |
| `ASSET_INFRASTRUCTURE_IPS` | Monitoring/gateway/noise sources that should not become attackers. |
| `ASSET_INTERNAL_CIDRS` | Internal/private ranges used for direction classification. |

Owned and infrastructure scopes default to empty rather than embedding one deployment's network inventory. Startup/status emits a warning until they are deliberately configured. `ASSET_INTERNAL_CIDRS` may retain portable private/loopback defaults. Inventory directly affects inbound/outbound/lateral classification and remediation; treat changes as production policy changes and test representative alerts.

### Diagnostic logging

Verbose evidence and retrieval traces are disabled by default. `LLM_DEBUG_COMMANDS=true` logs full llama.cpp argument lists, not prompt content, and should be enabled only for a short diagnostic session. Collect the minimum necessary information, then disable it. Never enable evaluation-only debug variables in a production service.

Production exception paths use `log_sanitized_exception()`: logs retain the exception class and a bounded chain of repository-relative or basename-only frame locations, but omit exception text and absolute host paths. Normal logs must not include database/SSH/web passwords, complete current alerts, complete prompts, private model input, or credentials. Restrict journal/file access to operators.

## Startup and preflight

### Preflight

From the deployed repository and environment:

```bash
source .venv/bin/activate
python3 Linux_LLM/config/runtime_preflight.py
```

Machine-readable form:

```bash
python3 Linux_LLM/config/runtime_preflight.py --json
```

Preflight checks:

- all configuration sections and cross-section startup requirements;
- required Python module discovery;
- model, llama.cpp, template, and optional GeoIP paths;
- PostgreSQL connectivity with short connect and statement timeouts;
- pgvector availability/installation;
- stale uploaded-document extraction versions when runtime status is supplied; and
- unsafe production settings such as all-interface binding or unknown SSH host keys.

A failed check is a stop condition. A warning needs explicit operator review. `--json` also converts configuration-construction failures into sanitized JSON containing only the exception class; it does not emit raw invalid values, private paths, or a traceback.

Run the tracked-source and repository-hygiene guard separately from the repository root:

```bash
python3 Linux_LLM/tools/check_repository.py
python3 Linux_LLM/tools/check_repository.py --json
```

The checker scans production source scopes for forbidden evaluation dependencies, unsafe hard-coded paths or credentials, and tracked generated artifacts. Use `--repo-root` and repeated `--production-root` only when checking an intentionally different checkout layout.

### Isolated flow validation

Inspect the focused validator before using it:

```bash
python3 Linux_LLM/tools/validate_rag_flow.py --help
```

Then point it only at a disposable or isolated validation database, because it adds the supplied CTI through the production additive corpus lifecycle:

```bash
ENV_FILE=/etc/soc-rag/validation.env \
python3 Linux_LLM/tools/validate_rag_flow.py \
  --document /path/to/sample-cti.pdf \
  --alert /path/to/sample-alert.json \
  --custom-only \
  --skip-generation \
  --json
```

Remove `--skip-generation` only when the isolated environment is ready to invoke llama.cpp. The tool enforces the configured alert byte/record and document count/batch/per-format bounds. It uses production document extraction, corpus addition, alert cleaning, retrieval, and report generation components, closes the report pipeline on exit, and emits sanitized failure JSON. It has no database-clear option. It is a focused diagnostic, not a replacement for the multipart route integration tests or an accuracy certification.

### Start

Interactive start:

```bash
source .venv/bin/activate
python3 Linux_LLM/config/main.py
```

This command starts one application worker, which is the supported topology. Corpus locks, build/analysis admission, drafts, progress sessions, and the local-model generation gate are process-local; do not wrap it in a multi-worker Uvicorn/Gunicorn configuration.

Optional JSON configuration:

```bash
ENV_FILE=/etc/soc-rag/service.env \
python3 Linux_LLM/config/main.py /etc/soc-rag/config.json
```

For a service manager, configure:

- dedicated user/group;
- exactly one application worker/process;
- deployed repository as working directory;
- `.venv/bin/python` as interpreter;
- `ENV_FILE` pointing to a protected file;
- restart policy with a delay and bounded retries;
- `TimeoutStopSec` long enough for monitoring, model subprocess, database, and temporary-file cleanup;
- read/write path restrictions matching the directory layout; and
- journal retention suitable for sensitive operational metadata.

Do not place passwords directly in a world-readable unit file.

### Shutdown

Use the service manager’s normal stop operation. Executor callables are not safely preemptible once running: the FastAPI lifespan gates new background work and monitoring starts, stops monitoring, cancels active llama.cpp process groups, and lets already admitted build/analysis/visual workflows reach their defined commit or cleanup boundary. It performs a final idempotent monitoring stop after that drain, then drains the executor and closes GeoIP/PostgreSQL. Every cleanup boundary is attempted even if an earlier one fails. An authorized corpus build already in its worker may therefore finish activation during a normal stop; quiesce mutation before stopping when activation must not occur. `MAX_WORKER_THREADS` bounds executor threads, shared admission bounds queued submissions, and `MAX_BACKGROUND_TASKS` bounds tracked jobs. Set `TimeoutStopSec` beyond the longest permitted external timeout and cleanup margin. Do not use `kill -9` except when normal termination cannot complete.

## Health checks

All HTTP checks require Basic Auth. Run them over loopback or the TLS endpoint.

| Check | Expected evidence |
| --- | --- |
| `GET /system-status` | Valid environment, safe preflight result, component status, and production warnings. |
| `GET /rag-status` | `ready=true`, expected `active_corpus_id`, embedded counts, stored/configured version compatibility, bounded corpus summaries/counts, no stale warning. |
| `GET /test-connection` | SSH and remote alert-file access when Wazuh is enabled. |
| `GET /chart-capabilities` | Availability, supported chart types/formats, and cleanup policy; no filesystem path is exposed. |
| `GET /pdf-status` | Available local PDF renderer and dependency state. |
| `GET /api/report-metrics` | Process-local generation timings and success history. |

Example local request that prompts for the password instead of putting it in shell history:

```bash
curl --user "$WEB_USERNAME" http://127.0.0.1:${WEB_PORT:-8000}/rag-status
```

`ready=true` proves that the active namespace contains embeddings and its stored model/index/extraction/chunking manifest matches the running configuration. It does not prove that a particular CTI collection was intended; compare the source-count change record and inspect the full manifest only from a protected database session.

## Corpus lifecycle

### Before a build

1. Confirm an authorized maintenance window.
2. Record the deployed Git commit and configuration checksum.
3. Run preflight.
4. Save `GET /rag-status`, especially `active_corpus_id`, versions, counts, and available corpora.
5. Back up PostgreSQL and the report directory.
6. Verify CTI source count, type, hashes, and expected extraction characteristics offline.
7. Ensure no other build or corpus activation is running.

### Extend the active corpus

The dashboard accepts Wazuh archive history, uploaded CTI documents, or both. **Extend active context** is the default. Select only the new sources: the application creates a new immutable namespace containing the union of the active custom documents, active archive records, and the submitted additions. Duplicate inputs are idempotent.

Use **Replace/rebuild active context** only for intentional source removal, a complete rebuild, or an incompatible index-version migration. Replacement requires explicit confirmation and contains only the submitted source set, so select every source that must remain available.

If active status is unavailable, or the active namespace fails exact manifest/chunk validation, no mutation starts. An incompatible or invalid active namespace cannot be silently treated as an initial build; recovery requires the explicitly confirmed replacement mode.

The first extension from an older untyped manifest is allowed only when its combined source-hash inventory and lifecycle counts exactly match the stored rows. If historical deduplication makes that union unprovable, extension is refused; rebuild through confirmed replacement from authoritative sources instead.

The application enforces request file-count/byte limits and one active background builder. Documents are extracted concurrently through the bounded application executor, while the corpus mutation/activation section remains serialized.

Selected sources are fail-closed. Every uploaded document must yield an indexable representation, so an empty or low-quality source cannot hide behind another document/archive. Every archive line must be a UTF-8 JSON object and every expanded record must yield indexable text. A malformed record, connection/I/O/timeout, record, expanded-byte, or line-size failure stops the complete request. Missing daily archive files are ordinary absent days. In every abort case the previous ready corpus and its counts remain active.

Monitor progress for:

- SSH/archive read result;
- accepted, duplicate, corrupt, unsupported, or extraction-poor documents;
- chunk and embedding counts;
- namespace ID and state;
- validation result; and
- activation result.

The database state sequence is `building -> ready -> active`. A failed build becomes `failed`; it does not replace the active pointer. Do not manually change a failed namespace to ready.

### Validate after activation

1. Confirm `/rag-status` has the new expected `active_corpus_id` and `active_corpus_version_compatible=true` for the stored/configured versions.
2. Confirm `active_source_documents`, `active_archive_records`, `active_document_chunks`, and `active_total_chunks` equal the expected post-union inventory.
3. Confirm no stale extraction warning.
4. Run one strong exact-evidence alert, one alternate schema, and one no-reliable-match alert.
5. Compare normalized evidence, canonical sources, ATT&CK categories, attribution decision, and remediation targets with the approved pre-change smoke record.
6. Do not use the corpus operationally if evidence crosses namespaces or the no-match case gains unsupported claims.

### Inspect corpora

`GET /rag-status` includes at most 20 recent manifest-free `available_corpora` summaries (always including the active row) and `available_corpora_total`, `returned`, and `truncated` fields. From PostgreSQL, a protected read-only inspection is:

```sql
SELECT corpus_id, status, document_count, chunk_count,
       created_at, validated_at, activated_at, error
FROM rag_corpora
ORDER BY created_at DESC;

SELECT value->>'corpus_id' AS active_corpus_id, updated_at
FROM rag_runtime_state
WHERE key = 'active_corpus_id';
```

Inspect manifests without exposing source contents:

```sql
SELECT corpus_id, manifest->'versions' AS versions,
       jsonb_array_length(COALESCE(manifest->'document_content_hashes', '[]'::jsonb)) AS source_hash_count
FROM rag_corpora
WHERE status = 'ready'
ORDER BY created_at DESC;
```

### Activate or roll back a corpus

`RAGContextManager.activate_corpus(corpus_id)` is the supported validation/activation API. It rejects malformed IDs, non-ready/empty namespaces, and any stored manifest incompatible with the running model, normalization, instructions, extraction, index, or chunking configuration. Legacy unscoped rows remain untouched and disabled because their vector provenance cannot be proven; build a replacement rather than relabelling them.

There is no public switch endpoint. Activation is a privileged maintenance operation:

1. stop or quiesce report generation and corpus mutation;
2. take a fresh database backup;
3. identify the exact previously ready corpus ID;
4. invoke `activate_corpus()` from a protected host maintenance session using the deployed configuration;
5. close the manager cleanly;
6. start/resume the service; and
7. verify `/rag-status` plus the representative smoke set.

Do not update `rag_runtime_state` directly unless application code cannot start and database recovery is being performed by the database owner. Direct SQL bypasses readiness validation and process locking.

### Approved-report indexing

Approval saves the report first. `ReportGenerator.index_approved_report()` removes generated QA, evidence-source, finalization, and chart appendices from the indexed copy, marks it human-validated historical context, and calls `add_custom_documents()`.

The additive path derives a new content ID, copies the current namespace, inserts/embeds the cleaned report, validates, then activates. If indexing fails, the approved Markdown remains on disk; investigate before retrying rather than approving duplicate copies.

## Database backup and recovery

Use `.pgpass`, a protected service credential, or an interactive password prompt. Avoid passwords on the command line.

### Backup

Custom-format database backup:

```bash
mkdir -p /var/backups/soc-rag
chmod 700 /var/backups/soc-rag

pg_dump \
  --host <db-host> \
  --port <db-port> \
  --username <backup-role> \
  --format=custom \
  --file /var/backups/soc-rag/soc-rag-<timestamp>.dump \
  <db-name>
```

Record alongside it:

- deployed commit;
- sanitized configuration checksum;
- active corpus ID and `rag_corpora` listing;
- extraction/index version manifest;
- report-directory backup checksum; and
- PostgreSQL/pgvector versions.

Back up reports without following external symlinks and preserve permissions:

```bash
tar --create --gzip --file /var/backups/soc-rag/reports-<timestamp>.tar.gz \
  --directory /var/lib/soc-rag reports
```

### Restore

Restore into a new database first:

```bash
createdb --host <db-host> --port <db-port> --username <admin-role> <restore-db-name>
pg_restore \
  --host <db-host> \
  --port <db-port> \
  --username <admin-role> \
  --dbname <restore-db-name> \
  --clean --if-exists \
  /var/backups/soc-rag/soc-rag-<timestamp>.dump
```

Run read-only integrity queries and a disposable application/preflight against the restored database before changing service configuration. Confirm pgvector dimensions match the deployed embedding configuration.

Never overwrite the only production database as the first restore test.

## Model and embedding backends

### llama.cpp/Qwen3-30B

Verify:

- `LLM_BINARY_PATH` exists and is executable;
- `LLM_MODEL_PATH` is a readable compatible GGUF;
- selected GPU layers/tensor split match available devices and VRAM;
- context, batch, and KV-cache settings fit memory;
- installed llama.cpp accepts the configured chat-template options; and
- `templates/cti.txt` and `templates/qwen_chat.j2` are deployed from the same reviewed commit.

The client retries without optional Qwen template arguments only when stderr identifies an unsupported argument. Other nonzero exits fail generation and are handled by report fallback/audit policy.

`ReportGenerator` owns one non-blocking generation gate shared by manual, selected-alert, and automatic-monitoring paths. Only one Qwen3-30B/llama.cpp workload runs per application process; a concurrent attempt fails explicitly instead of competing for GPU/RAM or waiting invisibly. Generation runs on the owned worker executor, and timeout/shutdown cancellation terminates tracked child process groups before executor drain.

### Embeddings

`RAG_EMBEDDING_DEVICE=cpu` with an empty `RAG_EMBEDDING_DEVICES` list is the safe default and compatibility fallback. CUDA/multi-device use is opt-in. For CUDA:

1. confirm `nvidia-smi` and the kernel driver are healthy;
2. confirm installed PyTorch detects the intended devices;
3. confirm the SentenceTransformers model produces the configured dimension;
4. use a miniature isolated corpus before a large build; and
5. adjust batch size before changing retrieval semantics.

Changing model, dimension, normalization, instruction, extraction/index version, or chunking changes corpus identity and requires a new namespace. Startup and explicit activation fail closed even when an old and new embedding model have the same dimension.

## Optional PDF rendering

PDF conversion uses `EnhancedPDFConverter` and a shared `EnhancedPDFAPIHandlers` instance. WeasyPrint work runs outside the event loop in a worker. `convert_markdown_to_pdf()` confines input and output to the resolved report directory.

`_resolve_local_resource()` and `_local_only_url_fetcher()` permit only report-local image files under the reports root. HTTP, HTTPS, data URLs, non-local hosts, non-image files, symlink escapes, and `..` traversal outside the root are rejected. Markdown input is capped at 5 MiB, each local image at 20 MiB, and batch conversion at 100 reports. A report can reference its generated local charts, but rendering never fetches remote content.

If WeasyPrint or the Markdown dependency is unavailable, `/pdf-status` reports PDF conversion as unavailable with dependency guidance. Install system libraries appropriate for the distribution, then rerun preflight/status; do not enable remote URL fetching as a workaround.

## Logs and diagnostics

The application primarily writes structured lifecycle messages to stdout/stderr for collection by the service manager. Restrict access because filenames, corpus IDs, and bounded evidence metadata may still be sensitive.

Useful diagnostic evidence:

- deployed commit and sanitized configuration summary;
- preflight JSON;
- `/system-status` and `/rag-status` with credentials and private host details removed;
- `rag_corpora` state/count query;
- last build progress messages;
- PostgreSQL error class and server-side log correlation ID;
- llama.cpp failure category plus the recorded stderr length/SHA-256 prefix;
- GPU/CPU/memory health; and
- input type/size/hash, not the sensitive body.

Sanitized exception records include the exception class and bounded frame locations, with repository-relative paths where possible and basenames otherwise. They deliberately omit exception messages and absolute host paths. Do not collect full prompts or raw model input by default. If a controlled debug trace is essential, use a synthetic alert or redact it at source, limit retention, and remove the trace after diagnosis.

## Troubleshooting

### Startup validation fails

Run `runtime_preflight.py --json`. Correct the first failed dependency/path/config/database check. `ConfigManager.validate_all()` may create configured runtime directories, so confirm parent permissions before running as the service account.

### PostgreSQL is unreachable

Check service health, address/port, network policy, role, password source, database existence, and TLS policy. Preflight uses a short connection timeout. The runtime does not retry indefinitely.

If pgvector is available but not installed, install it in the configured database with an authorized database owner. Do not grant broad superuser rights to the application role merely to hide a deployment problem.

### Corpus build is rejected as busy

Another build or activation owns the mutation guard. Inspect progress and logs. Wait for it to finish or perform normal service recovery if the owning process died; do not start a competing builder or edit state rows manually.

### Corpus build fails during extraction

Check the failing document’s extension, uploaded byte size, magic/header, DOCX container limits, and extraction-quality warnings. DOCX input is capped at 500 archive entries and 25 MiB expanded data; PDF extraction is capped at 1,000 pages and 5,000,000 characters. YAML parsing bounds aliases, composed/expanded nodes, scalar expansion, and depth; cycles or amplification are rejected before construction. Reproduce with the same content hash in an isolated environment. OCR scanned PDFs before upload.

One rejected or failed selected document aborts the requested addition or replacement; it is not silently omitted from an activated partial corpus. Correct or remove that document deliberately, then submit the intended source set again.

### Archive ingestion exceeds a bound or fails

Check `MAX_ARCHIVE_DAYS`, `MAX_ARCHIVE_RECORDS`, `MAX_ARCHIVE_BYTES`, `MAX_ARCHIVE_LINE_BYTES`, and the SSH timeout. The byte budget counts expanded JSON across all requested dates and files, including decompressed `.json.gz` content. Confirm each nonblank line is a UTF-8 JSON object; a corrupt, truncated, or non-object line is an input failure, not a record to skip. A format, connection, I/O, timeout, or safety-limit failure aborts the requested addition or replacement and retains the prior corpus. Do not raise limits until the input and host capacity have been reviewed.

### Corpus build fails during embedding

Check model availability, device selection, driver/PyTorch compatibility, vector dimensions, batch size, and memory. The multi-GPU path falls back to the configured single device once; repeated failure should leave the new namespace failed and the old namespace active.

### Corpus build fails during activation

Inspect `rag_corpora.error`, embedded row counts, transaction/database logs, and active state. Do not mark it ready manually. Repair the cause and create a new build or reactivate the previously ready corpus.

### Retrieval appears stale or crosses corpora

Compare the status active ID with every selected row’s `corpus_id`; all production queries must use one stable snapshot. Compare `active_corpus_versions` with `configured_corpus_versions` and require `active_corpus_version_compatible=true`. A mismatch disables readiness and requires a replacement build; do not reactivate or relabel legacy vectors. There is no result cache to clear; do not look for a hidden cache directory.

### Manual alert upload is rejected

Confirm:

- extension is `.json`, `.jsonl`, or `.ndjson`;
- uploaded file and batch sizes are within configured bounds;
- UTF-8/UTF-8-BOM content;
- every entry is an object;
- supported single/list/wrapper shape;
- no more than the configured record count; and
- nested optional fields that should be objects are not invalid scalars.

Malformed input returns a concise 4xx error. Server logs retain sanitized frame-level diagnostic locations without returning a traceback to the browser.

The endpoint enforces its byte limit while consuming `UploadFile`; it cannot retroactively prevent multipart spooling by the ASGI parser. Confirm the trusted ingress also has an appropriate total request-body limit.

### Wazuh SSH fails

Check host-key trust, least-privilege credentials, timeout, remote paths, and file permissions. Unknown keys are rejected unless explicitly allowed. Offline Manual Alert Analysis remains available through an uploaded alert file when a ready CTI corpus exists.

### llama.cpp times out or exits

Run the binary’s version/help command outside the service, verify model compatibility, correlate the logged failure category and stderr length/hash, and check memory pressure. Normal logs deliberately omit stderr content. `LLM_TIMEOUT` bounds the child process; the asynchronous report wait adds a 30-second cleanup margin. Analysis responses return `poll_timeout_ms` with a larger margin, and the browser uses that value as its redirect-polling deadline. A timed-out child process group is killed and reaped, and its prompt file is removed.

### Generated report is replaced or requires review

This is expected fail-closed behavior. Inspect the `Report Finalization` and `RAG Sources Used` appendices. Common causes are unsupported actor language, current/historical ATT&CK confusion, historical-only IOC leakage, or unobserved remediation targets. Correct the evidence or analyst draft; do not weaken the audit to make the warning disappear.

### Report draft disappeared

Drafts and analysis redirects are process-local and bounded. A restart removes them. Recover from an already saved Markdown report if available; otherwise rerun the analysis.

### PDF conversion rejects an image/resource

Move the approved chart into the report-local charts directory and reference it with a safe relative path. Remote URLs, data URLs, external absolute paths, and symlink escapes are intentionally blocked.

## Safe cleanup

The repository ignore policy excludes runtime uploads, reports, logs, caches, database dump files, model files, temporary extraction output, and evaluation results.

Safe cleanup candidates, after confirming no process owns them:

- expired progress sessions and old chart files through application lifecycle methods;
- abandoned temporary prompt files owned by the service account after a crashed process;
- Python bytecode/test caches in the source checkout;
- failed, non-active corpus namespaces only after backup and retention approval; and
- old external evaluation artifacts according to the project retention policy.

Do not delete:

- the active or rollback-ready corpus;
- private backups or checksum evidence;
- reports under retention/legal hold;
- model files used by the installed service; or
- any runtime directory merely to make Git status look clean.

## Deployment checklist

1. Confirm the reviewed commit and clean tracked worktree.
2. Review the file inventory and deleted/moved-file list.
3. Run compilation, retained tests, deterministic RAG checks, static dependency/leakage checks, and `git diff --check`.
4. Review the representative before/after smoke comparison; this is not a full accuracy certification.
5. Review `.env.example` changes and deployment-local configuration separately; confirm no secrets in Git.
6. Back up the database and reports; record the active corpus and deployed commit.
7. Run preflight as the service account.
8. Deploy source into a versioned release directory without changing the active service.
9. Verify file ownership/modes, state paths, templates, model/binary paths, DB role/statement-timeout policy, SSH known-hosts, local PDF policy, one-worker topology, executor/admission/task caps, ingress total-body limit, preserved public Host, same-origin protection, security headers, and pinned-SRI asset policy.
10. During the authorized window, stop the old process normally and start the reviewed release.
11. Verify startup, `/system-status`, `/rag-status`, SSH if used, and progress transport.
12. Run the representative smoke set without rebuilding the production corpus unless the release requires and authorizes it.
13. Monitor bounded logs and resource use.
14. Keep the prior release and database/report backups until the acceptance window closes.

## Rollback checklist

### Code-only rollback

1. Stop the new process normally.
2. Restore the prior versioned release or revert the reviewed cleanup commit.
3. Restore its deployment-local configuration if the schema changed.
4. Start the prior release.
5. Verify preflight, health, active corpus, and representative smoke behavior.

### Corpus rollback

1. Quiesce report generation and corpus mutation.
2. Confirm the exact prior ready corpus ID from the change record and database.
3. Call `RAGContextManager.activate_corpus()` from the protected maintenance context.
4. Close the manager and restart/resume the service normally.
5. Verify status and representative exact/no-match cases.

### Database restore

Use only when namespace activation cannot recover the required state. Restore into a separate database, validate it, then point a controlled release at it during a maintenance window. Preserve the failed database for diagnosis until recovery is accepted.

### Report rollback

Reports are files outside Git. Restore the report backup separately. Reverting code does not remove or recreate approved reports, and restoring reports does not automatically index them into RAG.

## Remaining operational risks

- Drafts, redirect results, generation metrics, admission locks, corpus locks, and the model gate are process-local; one application worker is required.
- The local Qwen3-30B model starts for every report, can have high latency/resource cost, and is intentionally limited to one concurrent generation.
- The application bounds bytes during `UploadFile` consumption, but pre-endpoint multipart spooling remains an ingress/ASGI deployment responsibility.
- Scanned/image-only PDFs need external OCR.
- Corpus builds can be long-running and resource intensive even though concurrency is bounded.
- PostgreSQL runtime statement-timeout policy, backup, retention, monitoring, TLS, and high availability are deployment responsibilities; only preflight sets an application-side statement timeout.
- Basic Auth requires TLS for remote use and has no built-in role model or multi-user audit trail.
- The authenticated editor uses pinned-SRI Marked JavaScript and the alert viewer uses pinned-SRI Bootstrap CSS from jsDelivr; deployments that prohibit third-party requests must vendor the exact reviewed assets and tighten CSP accordingly.
- Report-directory inventory and long-term report/corpus retention are operational policies; use filesystem/database quotas and an approved retention job rather than deleting active or rollback-ready data in request paths.
- Guardrails and analyst approval reduce unsupported claims but do not guarantee factual accuracy.
- A future result cache must use the complete corpus/evidence/context/model/prompt/version key; no such cache exists today.
