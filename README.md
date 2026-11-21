# Wazuh Telemetry Analyser

A FastAPI application for investigating Wazuh alerts. It retrieves related cyber threat intelligence (CTI) from PostgreSQL with pgvector and uses local Qwen inference through llama.cpp or the Anthropic Messages API to draft a report for analyst review. Reports cover key findings, technical evidence, MITRE ATT&CK mappings, possible attribution when supported, and recommended response actions.

## Installation

1. On the Linux host, install PostgreSQL and pgvector, then create the application role, database and extensions. Follow the [deployment guide](docs/operations.md#installation).
2. From the repository root, create a Python environment and install the pinned packages.

   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   python -m pip install -r Linux_LLM/config/requirements.txt
   ```
3. Prepare a compatible `llama-cli` executable and Qwen GGUF, then create a private `.env` using the [starter configuration](docs/operations.md#starter-configuration).
4. Check the configuration and start the application.

   ```bash
   python Linux_LLM/config/runtime_preflight.py
   python Linux_LLM/config/main.py
   ```

Open `http://127.0.0.1:8000` on the application host with the default bind settings. For remote access or startup at boot, see [running as a service](docs/operations.md#running-as-a-service).

## Requirements

- Python 3.10 or later and the packages in [requirements.txt](Linux_LLM/config/requirements.txt).
- PostgreSQL with the `vector` extension, plus access to the embedding model `Qwen/Qwen3-Embedding-0.6B` by default. The model can be downloaded on first use or supplied from a local path.
- An executable `llama-cli` and a readable GGUF file. Startup validates both paths even when Anthropic is the initial report provider.
- For Local LLM, enough host memory and, if offloading, compatible GPUs and a llama.cpp build with the matching backend. CPU inference depends on available RAM and model size.
- Optional capabilities use additional resources. Public LLM requires Anthropic API access, Wazuh integration requires read access over SSH, GeoIP uses a local City database, and PDF export requires working WeasyPrint system libraries.

## Configuration

The application reads `.env` and can also load a JSON configuration passed as the first argument to `main.py`. Exported environment variables override file settings. Use the [configuration reference](docs/operations.md#configuration) for precedence and defaults.

| Area | Settings |
| --- | --- |
| Accounts | Set `WEB_USERNAME`, `WEB_PASSWORD` (at least 12 characters) and a persistent `WEB_SESSION_SECRET` (at least 32 characters). |
| Database | Set `DB_PASSWORD` and match `DB_HOST`, `DB_PORT`, `DB_NAME` and `DB_USER` to PostgreSQL. |
| Report model | Set `LLM_BINARY_PATH` and `LLM_MODEL_PATH`. The initial provider defaults to `local`. Configure `ANTHROPIC_API_KEY` if using Public LLM. [Provider settings](docs/llm-providers.md) |
| Wazuh input | Set `SSH_HOST`, `SSH_USERNAME` and `SSH_PASSWORD` together, or leave them empty for uploads. [Wazuh SSH settings](docs/operations.md#wazuh-ssh) |
| Optional GeoIP | Set `GEOIP_DB_PATH` to a readable MaxMind City `.mmdb`, such as GeoLite2 City. The default is empty. [GeoIP setup](docs/operations.md#geoip-and-asset-inventory) |

## Usage

1. Sign in with the bootstrap admin account and enrol a TOTP app such as Microsoft Authenticator using the displayed QR code. Administrators manage accounts from **Accounts**.
2. In **Knowledge base**, an administrator builds the first corpus from CTI uploads, Wazuh archives when enabled, or both. Use **Extend active context** to add sources. Use **Replace/rebuild active context** to rebuild from the selected sources. Check that **Overview** shows the corpus as ready.
3. In **Analysis**, upload a `.json`, `.jsonl` or `.ndjson` alert file. With Wazuh connected, you can analyse current alerts or select rows in **Alert viewer**. Automatic monitoring processes eligible alerts at rule level 8 or higher once the corpus is ready.
4. An administrator can select **Local LLM** or **Public LLM** from **Analysis** or **Alert viewer**. Public LLM sends the report prompt, including alert evidence and retrieved context, to the configured Anthropic endpoint.
5. Follow the analysis queue until the report is ready. Review the draft and its evidence, edit it as needed, then approve it. Use **Reports** to download Markdown or render and download a PDF when the renderer is available.

## Project Structure

| Location | Purpose |
| --- | --- |
| [Linux_LLM/config/main.py](Linux_LLM/config/main.py) | FastAPI entry point, dashboard, routes, and job orchestration |
| [Linux_LLM/config/config.py](Linux_LLM/config/config.py) | Configuration defaults, environment mapping, and validation |
| [Linux_LLM/config/ssh.py](Linux_LLM/config/ssh.py), [live_monitoring.py](Linux_LLM/config/live_monitoring.py), [analysis_queue.py](Linux_LLM/config/analysis_queue.py) | Wazuh reads, monitoring, and job status |
| [Linux_LLM/config/rag.py](Linux_LLM/config/rag.py), [cti_artifacts.py](Linux_LLM/config/cti_artifacts.py), [embedding_runtime.py](Linux_LLM/config/embedding_runtime.py) | Document processing, indicator extraction, and embedding workers |
| [Linux_LLM/config/report.py](Linux_LLM/config/report.py) | Corpus storage, hybrid retrieval, prompt assembly, and report checks |
| [Linux_LLM/config/llm_client.py](Linux_LLM/config/llm_client.py), [anthropic_llm.py](Linux_LLM/config/anthropic_llm.py), [llm_provider.py](Linux_LLM/config/llm_provider.py) | Local and public generation, provider selection, and context budgets |
| [Linux_LLM/config/auth.py](Linux_LLM/config/auth.py), [report_parser.py](Linux_LLM/config/report_parser.py), [pdf_converter.py](Linux_LLM/config/pdf_converter.py) | Accounts and sessions, report editing, and PDF rendering |
| [Linux_LLM/config/templates/](Linux_LLM/config/templates/), [Linux_LLM/config/static/](Linux_LLM/config/static/) | Dashboard templates, prompts, scripts, and styles |
| [Linux_LLM/tests/](Linux_LLM/tests/), [Linux_LLM/tools/](Linux_LLM/tools/) | Regression tests, preflight-related tooling, and evaluation harnesses |

## How analysis works

Live or uploaded alerts are normalised into a common schema. The analyser extracts observed indicators and searches the active CTI and archive corpus using exact indicator matching, PostgreSQL full-text search, and embedding similarity. It ranks the results and builds a prompt that distinguishes current observations from historical context. The selected model drafts the report, which passes structure and evidence checks before analyst review. [RAG architecture and alert analysis](docs/rag-architecture.md)

## GPU Memory Distribution

`LLM_TENSOR_SPLIT` is unset by default. When no split is supplied in layer mode, llama.cpp chooses a split proportional to device memory. An explicit comma-separated split specifies relative placement weights. [llama.cpp multi-GPU options](https://github.com/ggml-org/llama.cpp/blob/master/docs/multi-gpu.md)

On 21 November 2026, the lab server reported four GTX 1080 Ti cards at 11 GiB each. Its running Qwen3-30B-A3B Instruct Q8_0 `llama-server` used `--split-mode layer` and `--gpu-layers 99`, with both `--tensor-split` and `LLAMA_ARG_TENSOR_SPLIT` unset. Actual VRAM usage depends on the model, context settings and backend.

## Further Documentation

- [Installation and operations](docs/operations.md) covers fresh deployment, configuration, health checks, backups, recovery, and testing.
- [RAG architecture and alert analysis](docs/rag-architecture.md) traces ingestion, evidence retrieval, prompt assembly, and report review.
- [LLM providers](docs/llm-providers.md) covers llama.cpp backends, Anthropic configuration, and provider-specific context handling.
