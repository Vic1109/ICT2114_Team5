# Wazuh Telemetry Analyser

Local FastAPI SOC application that turns **uploaded CTI** and **Wazuh alerts** into an evidence-audited Markdown/PDF report. Retrieval is hybrid: deterministic exact IOC lookup, PostgreSQL full-text lexical search, and pgvector semantic search. Generation uses a local GGUF through llama.cpp. Untrusted telemetry and CTI are fenced as data, not instructions.

Production source lives under `Linux_LLM/config`. Do not treat this README as a second copy of every setting; the files below are authoritative:

| Document | Role |
| --- | --- |
| [docs/operations.md](docs/operations.md) | Install, configuration, corpus lifecycle, SSH, LLM, security, troubleshooting |
| [docs/rag-architecture.md](docs/rag-architecture.md) | CTI extraction, Wazuh normalisation, hybrid RAG, token budgets, report audit |
| [docs/engineering-handover.md](docs/engineering-handover.md) | Measured results, known limitations, readiness |
| [.env.example](.env.example) | Environment variable template (copy to `.env`, never commit secrets) |

## What it does

```text
CTI document
    → parse / extract entities and IOCs
    → section-aware chunks + embeddings
    → PostgreSQL / pgvector

Wazuh alert (SSH live/archive or JSON upload)
    → AlertNormalizer (alert-schema-v4)
    → IOC extraction
    → exact / lexical / semantic retrieval + ranking
    → token-budgeted local LLM
    → claim validation
    → analyst review
    → Markdown / optional PDF
```

The dashboard UI is a dark SOC shell (`Linux_LLM/config/static/css/soc.css`) with knowledge-base, analysis, alert-viewer, report, and PDF controls. HTTP Basic Auth is required.

## Requirements

- Python 3.10+
- PostgreSQL with the `vector` extension (pgvector)
- llama.cpp `llama-cli` (optional sibling `llama-server`) and a local GGUF
- Native libraries for WeasyPrint if PDF export is required (see operations.md)

GPU acceleration is optional. The application runs on CPU; large GGUF generation is slow without a suitable llama.cpp build.

## Install and run

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r Linux_LLM/config/requirements.txt

cp .env.example .env
chmod 600 .env
# Set WEB_USERNAME, WEB_PASSWORD, DB_*, LLM_MODEL_PATH, LLM_BINARY_PATH, and other required values.

python Linux_LLM/config/main.py
```

Optional JSON overlay: `python Linux_LLM/config/main.py /path/to/config.json`.

The dashboard binds to `WEB_HOST`/`WEB_PORT` (default `127.0.0.1:8000`). Authenticate with the configured web user. There is no committed default password.

Preflight without starting the server:

```bash
python Linux_LLM/config/runtime_preflight.py
```

Repository hygiene (tracked production files, generated artefacts, accidental secrets):

```bash
python Linux_LLM/tools/check_repository.py
```

Full operator install, pgvector, SSH, backups, and PDF native packages: [docs/operations.md](docs/operations.md).

## Supported workflows

1. **CTI / RAG** — Upload CTI (PDF, DOCX, TXT, Markdown, HTML, CSV/TSV, JSON/STIX, YAML, XML) and/or Wazuh archive history. Default build mode is lossless extend. Replace requires explicit confirmation.
2. **Alerts** — Analyse current Wazuh alerts over SSH, or upload JSON/JSONL/NDJSON. The live viewer supports severity filters and selected-alert analysis.
3. **Retrieval** — Exact IOC rows in `document_iocs` do not depend on embeddings. Lexical search uses PostgreSQL `tsvector`. Semantic search uses pgvector cosine similarity and is ranked below exact/lexical matches.
4. **Reports** — Draft review in the editor (MITRE picker, preview, validate, approve). Approval writes Markdown and can convert to PDF and index the approved report back into RAG.

Extraction is generic (contextual cues, IOC normalisers, sentence-local relationships). It does not hard-code a particular CTI corpus. Unknown Wazuh fields are preserved, not treated as fully understood.

## Tests

```bash
source .venv/bin/activate
cd Linux_LLM
python -m unittest discover -s tests -p 'test_*.py'
```

These cover CTI/IOC extraction, exact and lexical matching, RAG union behaviour, Wazuh normalisation, token budgets, prompt-injection fences, report/PDF hardening, and UI surface inventory. Isolated evaluation tools under `Linux_LLM/tools/` must use a disposable database (`soc_rag_eval` / `soc_rag_unseen`), never production `soc_rag`.

## Security

- HTTP Basic Auth, CSRF origin checks on mutating browser requests, upload size limits, path sanitisation
- Prompt fences for untrusted alert and CTI text
- Attribution and MITRE claims require overlap with retrieved evidence
- Secrets belong in `.env` / `ENV_FILE` (mode `600`). `.env` is gitignored

## Honest limitations

- Not a substitute for a human analyst. Validation reduces unsupported claims; it does not make every sentence factual.
- LLM sampling is configured (temperature 0.2 in the example env) but is not a determinism guarantee.
- End-to-end Qwen3-30B generation on the measured lab host is minutes, not 15 seconds. Measure `/api/report-metrics` on your hardware.
- Live Wazuh SSH is optional; upload-only mode is supported when SSH is unset.
- PDF conversion needs WeasyPrint and its native libraries.

## Project layout

```text
.env.example
README.md
docs/operations.md
docs/rag-architecture.md
docs/engineering-handover.md
Linux_LLM/config/          production application
Linux_LLM/tests/           automated regression tests
Linux_LLM/tools/           operator/eval tools (not imported by production)
```

Runtime reports, uploads, logs, GGUF models, and database dumps are not part of the source tree.
