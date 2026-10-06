# LLM providers

Alert ingestion, normalisation, IOC extraction, and RAG retrieval are the same for both providers. The provider changes only how the shared report prompt is completed.

```text
Wazuh or manual alert
        |
Alert normalisation and RAG retrieval
        |
Shared prompt (system prompt + report instructions + fenced evidence)
        |
Local LLM  or  Public LLM
        |
Shared validation, report editor, approval, and PDF
```

## Local LLM

`LlamaModelClient` in `Linux_LLM/config/llm_client.py` runs llama.cpp. Inference stays in the configured application environment. The historical prompt caps remain in force for this provider: retrieved excerpts are pre-limited, exact-term hints are compacted, and the client compacts again when the prompt would exceed `LLM_CONTEXT_SIZE`. Compaction is counts-only in the logs. `/no_think` is added only for the local Qwen path.

Data stays within the application's configured environment.

## Public LLM

`OpenAIProvider` in `Linux_LLM/config/openai_llm.py` is the only module that calls the OpenAI Chat Completions API. It uses the Python standard-library HTTPS client. The official `openai` package is not a dependency.

The browser talks to this application. The application calls OpenAI. The API key is read from the server environment and is not placed in HTML, JavaScript, API responses, reports, or logs.

Both providers receive the same flow ledger, the same activity-cluster summary, and the same post-generation evidence stamp. The stamp replaces invented indicator counts and Suricata `to_server` direction with values counted from the alerts. Public mode does not drop repeated events or distinct indicators to fit the local excerpt caps. After either provider returns, the same audit repairs direction inversions, non-public addresses labelled external, contradictory execution claims, unsupported exfiltration, and hunt actions aimed at reference portals that the asset did not contact.

Relevant alert and retrieved CTI context is sent to the configured OpenAI API, together with the same system prompt and the same report instructions used locally. Public mode does not inherit the local excerpt caps. When the assembled prompt fits the selected model's context window, it is sent intact. When it does not fit, low-priority sections are reduced, exact IOC lines and the output contract are kept, and the reduction is recorded on the inference telemetry. The request is refused if it still cannot fit. There is no silent switch back to the local model.

A missing or rejected key, unknown model, timeout, rate limit, network failure, malformed response, or context overflow becomes a short GUI error. Transient HTTP failures retry at most `OPENAI_MAX_RETRIES` times. Authentication and invalid-model errors are not retried. One extra request is allowed when the API reports that the context is still too large. The existing structural repair can call the selected provider a second time if the draft fails validation; that is not a provider fallback.

## Selection

The allowlist is `local` and `openai` (`public` is accepted as an alias of `openai`). The active value is stored on `ReportGenerator` for the process. Analysis requests may send `llm_provider`, and the server validates it before generation. Alert bodies and CTI text cannot select a provider. The report header records `LLM Provider: Local` or `LLM Provider: OpenAI` and does not record credentials.

The analysis and alert-viewer pages show a Local LLM / Public LLM control, the data-handling sentence for the selected mode, and whether the OpenAI API key is configured. The control is disabled while a report is being generated. The analyse action is ignored if one is already in flight, and the backend returns HTTP 409 if a generation lock is held.

## Context accounting

| Provider | Window | Output reserve | Pre-assembly |
| --- | --- | --- | --- |
| Local | `LLM_CONTEXT_SIZE` | `LLM_MAX_TOKENS` | Historical caps, then local compaction |
| Public | Catalog entry or `OPENAI_CONTEXT_WINDOW` | `OPENAI_MAX_OUTPUT_TOKENS` | Full retrieved context when it fits |

Both budgets keep a safety margin so `input + reserved output + margin` stays within the window. Token figures in logs and `/api/report-metrics` are counts only.

## Configuration

The expected file is the repository-root template [`.env.example`](../.env.example). Copy it to `.env` and keep that copy out of Git:

```bash
cp .env.example .env
chmod 600 .env
```

`ConfigManager` discovers `.env` at the repository root, `Linux_LLM/`, `Linux_LLM/config/`, the current directory, the JSON-config directory, or the path in `ENV_FILE`. Exported process variables override `.env`.

Public LLM settings in that template:

```text
LLM_PROVIDER=local
OPENAI_API_KEY=
OPENAI_MODEL=gpt-4o-mini
OPENAI_TIMEOUT=120
OPENAI_MAX_OUTPUT_TOKENS=4096
# OPENAI_CONTEXT_WINDOW=128000
OPENAI_SAFETY_MARGIN_TOKENS=1024
OPENAI_CHARS_PER_TOKEN=3.5
OPENAI_MAX_RETRIES=2
OPENAI_TEMPERATURE=0.2
OPENAI_BASE_URL=https://api.openai.com/v1
```

`LLM_PROVIDER=local` is the default. Leave `OPENAI_API_KEY` empty unless Public LLM will be used; a non-empty value is treated as configured. Do not set `OPENAI_CONTEXT_WINDOW` to an empty string. Omit it to use the built-in model catalog, or set a positive token count for an unknown model. The GUI reports `OpenAI API: Configured` or `OpenAI API: Not configured` and can show the model name. It cannot show or edit the key.

The application still starts when the OpenAI key is absent. Selecting Public LLM then fails with an actionable message and does not call the local model.

## Tests and measurement

`Linux_LLM/tests/test_llm_providers.py` covers selection, mocked API failures, prompt equivalence, full-context delivery, evidence-preserving reduction, and the absence of the key from browser sources. It does not call the paid API.

`Linux_LLM/tools/benchmark_llm_providers.py` records provider, token estimates, and durations for a representative prompt using an in-memory transport. It does not call OpenAI and does not load the local GGUF. A live latency comparison requires a configured key and the local model, and this repository does not treat either provider as faster without that measurement.
