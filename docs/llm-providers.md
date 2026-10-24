# LLM providers

Alert ingestion, normalisation, IOC extraction, RAG retrieval, and report evidence rules are shared by both providers. The provider controls model invocation and the amount of context delivered within its window.

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

`AnthropicProvider` in `Linux_LLM/config/anthropic_llm.py` is the only module that calls the Anthropic Messages API. It uses the Python standard-library HTTPS client. The official `anthropic` package is not a dependency.

The browser talks to this application. The application calls Anthropic. The API key is read from the server environment and is not placed in HTML, JavaScript, API responses, reports, or logs.

Both providers receive the same flow ledger, the same activity-cluster summary, and the same post-generation evidence stamp. The stamp replaces invented indicator counts and Suricata `to_server` direction with values counted from the alerts. Public mode does not drop repeated events or distinct indicators to fit the local excerpt caps. After either provider returns, the same audit repairs direction inversions, non-public addresses labelled external, contradictory execution claims, unsupported exfiltration, and hunt actions aimed at reference portals that the asset did not contact.

Relevant alert and retrieved CTI context is sent to the configured Anthropic API, together with the same system prompt and the same report instructions used locally. Public mode does not inherit the local excerpt caps. When the assembled prompt fits the selected model's context window, it is sent intact. When it does not fit, low-priority sections are reduced, exact IOC lines and the output contract are kept, and the reduction is recorded on the inference telemetry. The request is refused if it still cannot fit. There is no silent switch back to the local model.

A missing or rejected key, workspace selection, billing limit, invalid request settings, unknown model, timeout, rate limit, overload, network failure, malformed response, or context overflow becomes a short GUI error. Logs retain bounded HTTP status, API error type, fixed category, and request ID, without the raw API error body. Transient HTTP failures retry at most `ANTHROPIC_MAX_RETRIES` times. Authentication and invalid-model errors are not retried. One extra request is allowed for context overflow; it reduces the actual prompt's character budget by at least 25%, rather than resending it unchanged when the token estimator was optimistic. Protected IOC/output sections still pass through the evidence-preserving reducer, which refuses impossible budgets. The existing structural repair can call the selected provider a second time if the draft fails validation; that is not a provider fallback. Text blocks are kept; thinking blocks are not written into the report.

Requests omit sampling parameters for modern and unknown model families. This fixes the default Sonnet 5.5 request, which rejects `temperature`, `top_p`, and `top_k`. Older explicitly supported families retain `ANTHROPIC_TEMPERATURE`. Sonnet 5.5 enables adaptive thinking by default, and its output-token limit covers thinking plus report text. If responses contain no report text or are consistently incomplete, review `ANTHROPIC_MAX_OUTPUT_TOKENS` against the report length and account budget. See the [official migration guide](https://platform.claude.com/docs/en/models/sonnet-5-5/migration-guide).

A public response is accepted only when Anthropic reports `stop_reason=end_turn` and supplies non-empty report text. Output/context limits, refusals, tool requests, paused turns, custom stops, and missing/unknown stop states fail visibly before structural repair or deterministic fallback can label partial text complete. Usage is recorded even for rejected completions. This adds no automatic continuation, output-budget increase, or paid retry. See [Anthropic stop reasons](https://platform.claude.com/docs/en/build-with-claude/handling-stop-reasons).

## Selection

The allowlist is `local` and `anthropic` (`public` is accepted as an alias of `anthropic`). The active value is stored on `ReportGenerator` for the process. Analysis requests may send `llm_provider`; only an admin may change the active choice, including through the analysis form. Analysts may submit the already active provider. Alert bodies and CTI text cannot select a provider. The report header records `LLM Provider: Local` or `LLM Provider: Anthropic` and does not record credentials.

The analysis and alert-viewer pages show a Local LLM / Public LLM control, the data-handling sentence for the selected mode, and whether the Anthropic API key is configured. Manual, selected-alert, and automatic work reserve one provider before background/executor queueing and deadline calculation. That reservation holds the selection/generation gate through context policy, both model passes, header/telemetry collection, and worker cleanup. Another tab's change receives HTTP 409 while work is pending or running. Cancelling a pending admission invalidates it so a late executor callable cannot start a model request; stale timeout tokens cannot cancel a later report. The browser's busy controls complement these server-side checks.

## Context accounting

| Provider | Window | Output reserve | Pre-assembly |
| --- | --- | --- | --- |
| Local | `LLM_CONTEXT_SIZE` | `LLM_MAX_TOKENS` | Historical caps, then local compaction |
| Public | Catalog entry or `ANTHROPIC_CONTEXT_WINDOW` | `ANTHROPIC_MAX_OUTPUT_TOKENS` | Full retrieved context when it fits |

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
ANTHROPIC_API_KEY=
# ANTHROPIC_WORKSPACE_ID=wrkspc_replace_me
ANTHROPIC_MODEL=claude-sonnet-5-5
ANTHROPIC_TIMEOUT=120
ANTHROPIC_MAX_OUTPUT_TOKENS=4096
# ANTHROPIC_CONTEXT_WINDOW=1000000
ANTHROPIC_SAFETY_MARGIN_TOKENS=1024
ANTHROPIC_CHARS_PER_TOKEN=3.5
ANTHROPIC_MAX_RETRIES=2
ANTHROPIC_TEMPERATURE=0.2
ANTHROPIC_BASE_URL=https://api.anthropic.com
```

`LLM_PROVIDER=local` is the default. Leave `ANTHROPIC_API_KEY` empty unless Public LLM will be used; a non-empty value is treated as configured, not verified. Set `ANTHROPIC_WORKSPACE_ID` only when the key is not scoped to one workspace; the server sends it as `anthropic-workspace-id` and does not expose it in the dashboard configuration. See [Anthropic authentication](https://platform.claude.com/docs/en/manage-claude/authentication). Do not set `ANTHROPIC_CONTEXT_WINDOW` to an empty string. Omit it to use the built-in model catalog, or set a positive token count for an unknown model. `ANTHROPIC_BASE_URL` is the HTTPS origin; requests go to `{origin}/v1/messages`. The configured legacy-model temperature must be between 0.0 and 1.0. The GUI reports `Anthropic API: Configured` or `Anthropic API: Not configured` and can show the model name. It cannot show or edit the key.

Manual and automatic analysis deadlines allow both permitted structural generation passes. Each public pass includes the bounded transient retries, backoff, and one context-correction attempt. Each local pass has its own `LLM_TIMEOUT`, with a separate allowance for server preparation. The browser uses the server-supplied deadline; successful responses return immediately.

The application still starts when the Anthropic key is absent. Selecting Public LLM then fails with an actionable message and does not call the local model.

## Tests and measurement

`Linux_LLM/tests/test_llm_providers.py` covers selection, mocked API failures, prompt equivalence, full-context delivery, evidence-preserving reduction, and the absence of the key from browser sources. It does not call the paid API.

New provider/workspace/deadline, reservation/cancellation, and completion-state regression sources were added during the October 2026 static review; they have not been executed in this checkout. Live credentials, account/model access, generation quality, and latency require isolated Linux verification.

`Linux_LLM/tools/benchmark_llm_providers.py` records provider, token estimates, and durations for a representative prompt using an in-memory transport. It does not call Anthropic and does not load the local GGUF. A live latency comparison requires a configured key and the local model, and this repository does not treat either provider as faster without that measurement.
