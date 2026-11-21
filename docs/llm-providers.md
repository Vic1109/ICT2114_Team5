# LLM providers

The analyser uses one evidence and report workflow with two generation providers. Use **Local LLM** to generate through a configured llama.cpp runtime or **Public LLM** to send the report request to Anthropic. The initial choice is `LLM_PROVIDER=local`. Set `LLM_PROVIDER=anthropic` to start in Public mode. `public` is an accepted alias in configuration and requests. [Provider selection code](../Linux_LLM/config/llm_provider.py)

## Provider selection

The **Analysis** and **Alert viewer** pages show the process-wide provider and the data-handling implications of the choice. The dashboard enables the selector for admins. The dedicated provider-change endpoint also checks the caller's role. Restarting the process restores the configured initial provider.

The current server code applies the administrator check inconsistently for provider changes associated with queued analysis. This matters when deciding whether a deployment can send alert and CTI data to the public endpoint.

Once generation is reserved, the model gate holds the selected provider through model calls, report validation and cleanup. A provider change through the selector receives HTTP 409 while that gate is held. Queued jobs can wait for the gate before starting. The report records the provider that generated it.

## Local LLM

Local mode runs the configured Qwen GGUF through llama.cpp. Report inference uses the local CLI or the configured llama-server endpoint. Both startup and preflight require the CLI and GGUF paths, including deployments initially using Public LLM.

| Setting | Default or requirement |
| --- | --- |
| `LLM_MODEL_PATH` | Required path to a readable Qwen GGUF |
| `LLM_BINARY_PATH` | Required path to an executable `llama-cli` |
| `LLM_INFERENCE_BACKEND` | `auto`. Use `cli` or `server` to select a backend explicitly. |
| `LLM_SERVER_URL` | Empty. Supply the base URL of an existing `llama-server` when attaching to a managed instance. |
| `LLM_SERVER_PATH` | Empty. The app looks for a sibling `llama-server` next to `llama-cli` when no explicit path is supplied. |
| `LLM_SERVER_HOST`, `LLM_SERVER_PORT` | `127.0.0.1`, `8090` for the local endpoint |
| `LLM_SERVER_AUTOSTART` | `true`. Set `false` when another service manages `llama-server`. |
| `LLM_GPU_LAYERS`, `LLM_TENSOR_SPLIT` | `99` layers requested when explicit GPU offload is used, and no split override. [GPU memory distribution](../README.md#gpu-memory-distribution) |
| `LLM_CONTEXT_SIZE`, `LLM_MAX_TOKENS` | 16,384 context tokens and a 2,048-token output cap |
| `LLM_TEMPERATURE`, `LLM_TOP_P`, `LLM_TOP_K` | `0.2`, `0.8`, `20` |
| `LLM_TIMEOUT` | 1,200 seconds per generation pass, with server preparation budgeted separately |
| `LLM_DISABLE_THINKING`, `LLM_FLASH_ATTENTION` | `true`, `false` |

In `auto` mode an explicit server URL selects the server backend. Otherwise the app selects `llama-server` when the GPU layer count is positive and a server binary is found. The CLI handles other cases. The app closes a server it launches itself. A separately managed server controls its own GPU placement and context settings, so keep its context window consistent with `LLM_CONTEXT_SIZE`. [Local inference client](../Linux_LLM/config/llm_client.py)

## Public LLM

The application server calls the configured HTTPS origin at `/v1/messages` using Python's standard library. The server keeps the API key and any workspace ID. The browser shows whether a key was supplied and can display the configured model. A configured key still needs access to the requested model.

The report request includes the system instructions, current alert evidence and selected historical context. Confirm that the evidence may be sent to the configured endpoint before using this mode.

| Setting | Default or requirement |
| --- | --- |
| `ANTHROPIC_API_KEY` | Empty. Required to generate a public report. |
| `ANTHROPIC_WORKSPACE_ID` | Empty. Set it for a key that requires workspace selection. The app sends it in the `anthropic-workspace-id` header. [Authentication reference](https://platform.claude.com/docs/en/manage-claude/authentication) |
| `ANTHROPIC_MODEL` | `claude-sonnet-5-5` |
| `ANTHROPIC_BASE_URL` | `https://api.anthropic.com` |
| `ANTHROPIC_TIMEOUT` | 120 seconds per request |
| `ANTHROPIC_MAX_OUTPUT_TOKENS` | 4,096 |
| `ANTHROPIC_CONTEXT_WINDOW` | `0` uses the built-in model-family catalogue. Supply a positive override for a model outside that catalogue. |
| `ANTHROPIC_SAFETY_MARGIN_TOKENS`, `ANTHROPIC_CHARS_PER_TOKEN` | 1,024 and 3.5 |
| `ANTHROPIC_MAX_RETRIES` | 2 for retryable HTTP failures, configurable from 0 to 4 |
| `ANTHROPIC_TEMPERATURE` | 0.2 for supported legacy model families, configurable from 0.0 to 1.0 |

The transport omits sampling parameters for modern and unknown model families. Sonnet 5.5 uses adaptive thinking by default. Its output budget covers thinking and report text. [Sonnet 5.5 migration guide](https://platform.claude.com/docs/en/models/sonnet-5-5/migration-guide)

## Context and completion

The application fits each prompt to a budget that reserves output tokens and a safety margin. Local mode applies shorter excerpts during assembly and compacts further if needed. Public mode can send the assembled context intact when it fits. An API context overflow can trigger one additional reduced request. If the protected exact matches and output instructions cannot fit the reduced budget, the attempt ends with a context-budget error. [Public transport and context handling](../Linux_LLM/config/anthropic_llm.py)

The public transport accepts non-empty text from a response with `stop_reason=end_turn`. Token limits, refusals and other stop reasons surface as provider errors. Thinking blocks are excluded from the report. Structural repair runs only after the provider returns a usable completion. A provider failure leaves the selected backend in place. [Anthropic stop reasons](https://platform.claude.com/docs/en/build-with-claude/handling-stop-reasons)

Use the configured model name, credential scope, timeout and context settings to diagnose generation failures. The Anthropic client reports bounded error categories for authentication, workspace, billing, invalid settings, rate limits and other transport or API failures. Tests use mocked API responses. The repository benchmark uses an in-memory transport and measures overhead rather than real model latency. [Provider tests](../Linux_LLM/tests/test_llm_providers.py) · [Benchmark harness](../Linux_LLM/tools/benchmark_llm_providers.py)
