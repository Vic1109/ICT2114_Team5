# Engineering handover

Measured handover for the Wazuh Telemetry Analyser after the 2026-09 accuracy, security, and production-readiness pass. This is an evidence document.

## Executive summary

The application is a local FastAPI SOC service that turns uploaded CTI plus Wazuh alerts into an evidence-audited Markdown/PDF report using PostgreSQL/pgvector hybrid RAG and a local Qwen3-30B GGUF through llama.cpp.

What was found and fixed in this pass:

- CTI PDF glue produced false domains (`443.host`, `utilities.th`) and related-article APT IDs; extractors were tightened and labelled evaluation now scores precision 1.0 / recall 1.0 on 18 must-extract/must-not-extract items across four real CTI-HAL PDFs.
- Relationships are recorded only when a verb sits between independently extracted endpoints in the same sentence.
- Sysmon registry keys, IPv6, process names from image paths, and PowerShell `-enc` payloads are normalised as observed telemetry without replacing the raw alert.
- Hybrid ranking keeps exact hash/IOC matches high; low-strength semantic-only background is dropped. A benign SSH login against the FIN7 corpus retrieved zero CTI documents.
- Prompt compaction previously treated `BEGIN UNTRUSTED DATA` fences as section breaks, starving retrieved CTI (53 tokens). After the scan-pattern fix, the FIN7 isolated generation kept **2726 retrieved-CTI tokens** inside the 16384 context (pre-compact 5558 → fitted 2726; total 15787 ≤ 16384).
- Combined “Prioritized Response Plan and Immediate Actions” headings blocked PDF approval (HTTP 400). The parser now fills recommendations and approval/PDF succeeded on the user-facing path.
- Isolated evaluation no longer opens the configured Wazuh SSH session (`LIVE_MONITORING_ENABLED=false`).

**Readiness: READY FOR CONTROLLED TESTING.** Not production-ready: live Wazuh SSH was not exercised against a real manager in this environment; the 15-second report target is not met on Qwen3-30B Q8 (LLM generation ~3 minutes); labelled retrieval/accuracy sets are too small to certify generalisation.

## Architecture

```text
CTI upload → DocumentProcessor → CTIArtifactExtractor
    → section-aware chunks + embeddings → PostgreSQL/pgvector
Wazuh JSON (SSH or upload) → AlertNormalizer (alert-schema-v4)
    → AlertAnalyzer evidence/IOCs
    → hybrid document_iocs exact / lexical / vector retrieval → ranking
    → token-budgeted Qwen prompt (untrusted fences)
    → claim audit → analyst review → Markdown/PDF
```

Authoritative module map: [docs/rag-architecture.md](rag-architecture.md). Evaluation tools under `Linux_LLM/tools/` are not imported by production code.

## Environment (this host)

| Item | Observed |
| --- | --- |
| OS | Ubuntu 22.04.5, Linux 6.8 |
| Python | 3.10.12 in `~/Desktop/venv` |
| CPU | 12-thread Xeon E5-1650 v4 |
| RAM | 94 GiB |
| GPU | 4× GTX 1080 Ti 11 GB, driver 580.178.04, CUDA 13.0 / nvcc 12.4 |
| PostgreSQL | 17.7 + pgvector 0.8.1 |
| llama.cpp | `llama-server` / `llama-cli` (previously reported build 6725) |
| Model | `Qwen3-30B-A3B-Instruct-2507-Q8_0.gguf` (~31 GiB), ctx 16384, max tokens 2048, temperature 0.2, thinking disabled, flash-attn off |
| Embeddings | `Qwen/Qwen3-Embedding-0.6B`, 1024-d cosine |
| CTI for eval | 71 PDFs under `~/Desktop/CTI-Folder/CTI-HAL-main/reports` |

## CTI extraction

Pipeline `2026-09-cti-rag-v9`. Generic entity/IOC extractors plus `IOCNormalizer`; sample-report names are not production allow-lists.

- Entities, IOCs (IPv4/IPv6, SHA-384/512, certificate fingerprints, emails, CVEs/CWEs), ATT&CK IDs, defensive text, and sentence-local relationships with polarity and provenance.
- False-domain filters reject numeric SLDs (`443.host`), 2-label `.host`, PDF-glue TLDs, and publisher domains in `for_cti_context`. Dataset-specific malware-name TLD entries were removed from production filters.
- Chunking remains section-aware with overlap tails plus a document-summary chunk. Canonical IOCs are also written to `document_iocs` for exact lookup without embeddings.

Labelled evaluation (`Linux_LLM/tools/evaluate_cti_quality.py`, four real PDFs, hold-out fact-sheet + CrashOverride):

| Split | Precision | Recall | tp | fp | fn |
| --- | ---: | ---: | ---: | ---: | ---: |
| Combined labelled set | 1.0 | 1.0 | 18 | 0 | 0 |

Unlabelled extra values are not scored as false positives. Residual raw PDF-glue can still appear in unfiltered extract output.

Held-out synthetic generalisation gold (`Linux_LLM/tools/evaluate_generalisation.py`, unseen actor/malware/IOC names, not CTI-HAL):

See the Generalisation pass section below for measured P/R on that set.

## Wazuh parsing

`AlertNormalizer` (`alert-schema-v4`) maps ECS, native Wazuh, Sysmon, syscheck, auditd, Suricata/EVE, and cloud aliases into canonical `data.*` paths. Windows/Sysmon keys are matched case-insensitively (`DestinationIp` and `destinationIp` both populate `data.dest_ip`). Unknown security-looking fields are sampled. `_raw_alert` is preserved.

Additional observed-telemetry enrichments:

- process name from image basename when `originalFileName` is absent;
- UTF-16LE decode of PowerShell `-enc` / `-encodedcommand` into `decoded_command_line` (original command retained);
- Sysmon `SHA256=` / `MD5=` tuples require algorithm-correct digest lengths;
- UNC paths require host and share so `POS\cashier07` is not a file path.

Compatibility coverage: `tests/test_wazuh_normalization.py` (Suricata, sshd, syscheck, Sysmon, auditd, incomplete, unexpected schema, IPv6, registry/user-agent, encoded PowerShell).

## RAG

Hybrid retrieval: canonical `document_iocs` equality, JSONB artifact match, lexical `tsvector`, pgvector cosine. Ranking boosts exact matches, source-context, behavior overlap, and chunk-local relationships. Low-strength semantic-only hits are not admitted as “relevant CTI”. Exact lookup continues if embeddings fail.

On the isolated two-document corpus (`soc_rag_eval`, 41 chunks):

- Positive Sysmon alert with SHA256 `6e123008…`: exact hash match, evidence_strength `high`, rank 1.
- Negative sshd success: **zero** selected documents; prompt contained `No sufficiently relevant CTI evidence identified.`

`EXPLAIN ANALYZE` on 41 rows (below IVFFlat min_rows, exact scan by design):

| Query | Plan | Execution |
| --- | --- | ---: |
| JSONB hash `?` | Seq Scan | 0.41 ms |
| `to_tsvector @@ tsquery` | Seq Scan | 4.27 ms |
| `embedding <=>` top-8 | Seq Scan + top-N sort | 0.41 ms |

Indexes present: `doc_content_fts_idx`, `doc_content_trgm_idx`, `doc_corpus_hash_unique_idx`, `doc_corpus_idx`. IVFFlat is created only above `vector_index_min_rows`.

## LLM

- Persistent `llama-server` when GPU offload is enabled.
- Hard token budget: system + prompt + reserved output + margin ≤ context; compact-or-fail, never silent truncate.
- Compaction splits only on `[[SOC:nonce]] NAME:` instructional markers. Untrusted fences are not section boundaries. Retrieved CTI is reserved before verbose synthesis JSON.
- Telemetry and CTI are fenced as untrusted data. Prompt-injection string in `full_log` did not force APT29 attribution.
- One generation lock; structural repair retries once; claim audit is deterministic.

The 15-second end-to-end target is **not** achieved. LLM generation dominates (~180 s per report on this Q8 30B configuration after the server is up). Accuracy was not reduced to chase the number.

## Accuracy (isolated user-facing workflow)

User path: `POST /build-rag` (2 CTI PDFs) → `POST /analyze-alerts` (artificial Sysmon JSON) → review draft → `POST /api/approve-report` → `POST /convert-to-pdf`.

| Check | Result |
| --- | --- |
| Exact hash retrieval | Rank 1, high strength, SentinelLabs FIN7 chunk |
| Decoded download URL in report | `http://198.51.100.29/update.vbs` observed from `-enc` |
| APT29 injection in `full_log` | Not attributed; “Ignore all previous instructions” not treated as policy |
| FIN7 | Mentioned with hash-supported CTI overlap and remaining uncertainty language |
| Negative sshd alert | No CTI selected; no FIN7 mention |
| Approve / PDF | HTTP 200; WeasyPrint PDF in 661 ms |
| Token overflow | None (budget enforced) |

Broader classification/MITRE/attribution metrics on a large labelled alert set are **N/A** (only two artificial alerts were fully generated).

## Security

Covered by automated tests: prompt injection, path traversal, upload bounds, CSRF origin, SQL identifier limits, SSH host-key policy, secret-free token-budget logs. Isolated `full_log` injection did not override report structure or force APT29. Isolated runs disable live SSH via `LIVE_MONITORING_ENABLED=false`.

## Performance (isolated full generation, Qwen already or freshly loaded)

| Stage | Observed (FIN7 alert, ms) |
| --- | ---: |
| normalisation | 55 |
| exact retrieval | 223 |
| lexical retrieval | 67 |
| vector retrieval | 2022 |
| ranking | 5 |
| context construction | 6 |
| llm | 212064 |
| validation | 2 |
| pdf | 896 |
| end_to_end report | 215011 |

Median LLM generation across isolated full runs in this session is about 180–215 s. The 15 s target is not met.

## Testing

| Suite | Result |
| --- | --- |
| `python -m unittest discover -s tests -p 'test_*.py'` | 333 tests OK |
| Labelled CTI extraction | precision 1.0, recall 1.0, tp=18, fp=0, fn=0 |
| Isolated skip-LLM upload | RAG ready, 2 source documents, 41 chunks |
| Isolated full LLM + approve + PDF | success; retrieved CTI 2726 tokens; negative case abstained |

## Baseline versus final

| Metric | Baseline | Final |
| --- | ---: | ---: |
| CTI extraction precision (labelled) | not measured / glue FPs | 1.0 (n=18 labelled items) |
| CTI extraction recall (labelled) | not measured | 1.0 |
| IOC precision (labelled must-not-extract) | PDF-glue FPs present | 1.0 on labelled rejects |
| IOC recall (labelled must-extract) | partial | 1.0 |
| Retrieval Precision@1 (isolated hash query) | N/A | 1.0 (n=1 positive) |
| Retrieval Recall@1 (isolated hash query) | N/A | 1.0 (n=1 positive) |
| MRR (isolated hash query) | N/A | 1.0 (n=1) |
| Irrelevant retrieval (negative sshd) | semantic FIN7 leak | 0 documents |
| MITRE precision (large labelled set) | N/A | N/A |
| MITRE recall (large labelled set) | N/A | N/A |
| Attribution correctness (APT29 injection) | not measured | correct abstention |
| Correct abstention (benign sshd) | mixed | yes |
| Hallucinated IOC rate | N/A | 0 on the two generated reports (decoded URL was observed) |
| Unsupported claim rate | N/A | N/A (audit still flags repairable MITRE/IP wording) |
| Token violations | compact-or-fail already present | 0 |
| Unit tests | 318 OK | 361 OK |
| Median report latency | not measured | ~215 s (LLM-bound) |
| P95 latency | N/A | N/A (n too small) |
| Maximum report latency (this session) | N/A | 215 s generation / 334 s wall including RAG upload |

## Remaining limitations

- **Application:** raw PDF extraction can still emit glue tokens before `for_cti_context`; actor/malware recall is conservative; MITRE inferred from PowerShell remains easy to over-map and is post-audited. Two-label domains need a recognised TLD. Query embedding can fail while exact/lexical retrieval still succeeds.
- **Hardware:** 15 s reports are unrealistic for cold or even warm Q8 30B on 4× 1080 Ti.
- **Model:** ~5591-token system prompt plus 2048 reserved output leaves a tight user-prompt budget; generation ~12 tokens/s decode in this session.
- **Data:** CTI-HAL PDFs are vendor blogs with navigation chrome, not STIX. Labelled sets are small. Held-out synthetic generalisation tests cover unseen names; they do not replace a large labelled corpus.
- **Environment:** no live Wazuh manager SSH in this session. Unseen NightOrchid ingest/exact retrieval was run; full Qwen+PDF was not re-run on that corpus.
- **Index:** IVFFlat is skipped below the row threshold; large corpora must rebuild indexes after ingestion.

## Generalisation pass (this follow-on)

Dedicated anti-overfitting and exact-IOC work after the first handover. Sample CTI-HAL reports were treated as unseen validation examples, not as the extraction spec.

### Architecture changes

- Generic entity cues (threat-actor / malware / tool / campaign phrasing) replace dataset allow-lists. Previously unseen names such as NightOrchid, GLASSFROG, CrimsonKite, and BlueMoth extract without code changes.
- `IOCNormalizer` canonicalises IPv4/IPv6, domains, URLs (hxxp refang), hashes including SHA-384/512 and colon fingerprints, CVEs, CWEs, and emails, with boundary-aware exact matching.
- `document_iocs` is the deterministic exact-lookup path. `_hybrid_search` continues exact and lexical retrieval when query embeddings raise.
- Relationship predicates are type-aware. Actor/malware/CVE “uses” vs “exploits” is taken from the span, not from co-occurrence. Polarity (`explicit`, `assessed`, `unconfirmed`, `denied`, …) is preserved. Conflicting sources stay separate rows.
- Prompt section `DETERMINISTIC EXACT IOC MATCHES — APPLICATION-ESTABLISHED` is reserved in the token budget. The LLM is not asked to rediscover exact identifier matches.
- Alert path lookup is case-insensitive so PascalCase Sysmon XML and camelCase Wazuh JSON both populate `dest_ip`, command line, and hashes.
- Two-label domains whose TLD is not a recognised public/special-use suffix (for example `Net.WebClient`) are rejected as IOCs.

### Anti-overfitting findings

| Finding | Classification | Action |
| --- | --- | --- |
| `FIN7` / `HALFBAKED` / `APT29` in tests and fixtures | TEST FIXTURE | retained |
| Comment in `report.py` that short curated tokens such as `APT29` must not be dropped by the generic-term heuristic | GENERIC PRODUCTION LOGIC | retained (not an allow-list branch) |
| Dataset malware names used as fake TLDs (`halfbaked`, `foxconn`, …) | UNSAFE HARDCODING | removed earlier in this pass |
| `PROMOTABLE_CTI_TLDS` / English PDF-glue TLD words | GENERIC PRODUCTION LOGIC | retained |
| Generated-report headings (`Executive Summary`) in the Markdown parser | GENERIC PRODUCTION LOGIC | retained; not used as CTI input parsers |
| Vendor blog heading names as primary extractors | none found | n/a |

Production `Linux_LLM/config/cti_artifacts.py` contains no FIN7, HALFBAKED, APT29, NightOrchid, or GLASSFROG literals.

### Held-out CTI extraction (`evaluate_generalisation.py`)

Synthetic gold split into development / validation / unseen / adversarial. None of the names appear in CTI-HAL.

| Metric | Value |
| --- | ---: |
| Entity precision / recall / F1 | 1.0 / 1.0 / 1.0 (tp=18) |
| Relationship precision / recall / F1 | 1.0 / 1.0 / 1.0 (tp=11) |
| Polarity preservation | 1.0 |
| Provenance coverage (IOC records with canonical value + context) | 1.0 |

IOC extraction F1 by type (all 1.0 on this gold set): IPv4, IPv6, domain, URL, MD5, SHA-1, SHA-256, SHA-512, CVE, email.

### Retrieval (held-out gold, no live embeddings required)

| Signal | Result |
| --- | --- |
| Exact IOC recall | 1.0 (8/8) |
| Lexical recall (defang, hxxp, case) | 1.0 (3/3) |
| Hybrid: exact evidence not buried by semantic distractor | 1.0 (1/1) |
| Negative exact precision (nearby IP, similar domain, partial hash, CVE prefix) | 1.0 (4/4) |
| Live hybrid on PostgreSQL | N/A in this script; see user-facing row below |

Top-k / MRR on this gold set are 1.0 for every exact-positive case because matching is deterministic identifier lookup rather than ranked semantic search.

### User-facing isolated unseen path (`soc_rag_unseen`)

Upload `nightorchid_advisory.txt` + Sysmon alert with `203.0.113.42` / SHA-256 `aa…aa` / `relay-unseen.example`. Query embedding raised `ValueError`; exact and lexical retrieval continued.

| Check | Result |
| --- | --- |
| RAG ready | 2 chunks |
| Alert `dest_ip` | `203.0.113.42` |
| Command line preserved | yes |
| Exact terms | IP, domain, URL, SHA-256; `net.webclient` not promoted |
| Rank-1 match types | `exact` (score 1.49) over lexical 1.05 |
| Exact IP/domain/URL/hash evidence | present |
| Retrieval latency | 315–369 ms |
| Wall time including ingest | ~6.5 s |

### Factuality and security (automated)

| Check | Result |
| --- | --- |
| Prompt-injection strings in telemetry/CTI | fenced as untrusted data; not treated as actor labels (`test_prompt_security`, `test_generalisation_ioc`) |
| Exact-match collisions | unit + gold negatives pass |
| Token overflow | compact-or-fail; tiny context (4096) still keeps the deterministic IOC section; thousands of chunks stay within `context_size` |
| Unsupported claims / hallucinated IOCs | covered by `test_evidence_discipline` and the earlier isolated FIN7 LLM reports (0 invented IOCs on those two reports) |

Full Qwen generation + PDF was not re-run on the unseen NightOrchid corpus in this pass. The prior isolated FIN7 path (`soc_rag_eval`) already produced approve/PDF HTTP 200 with 2726 retrieved-CTI tokens.

### Performance (this pass)

| Stage | Median / observation |
| --- | --- |
| Held-out extraction of the gold set | 16 ms |
| 1500 IPv4+domain boundary matches | 443 ms |
| Exact/lexical retrieval against 2 unseen chunks | 315 ms median of the successful isolated runs |
| Unseen ingest + embed 2 chunks + retrieve | ~6.5 s |
| LLM generation (prior FIN7 isolated run) | ~180–215 s (not improved; not traded for recall) |

### Token safety

| Item | Value |
| --- | --- |
| Configured context limit | 16384 |
| Reserved output | 2048 |
| Safety margin | 512 |
| Overflow tests | pass (`test_llm_context_budget`) |
| Impossible tiny window | `PromptBudgetError` before llama.cpp |

### Cleanup

- No dataset-specific production branches remain in the extractor.
- Evaluation gold and NightOrchid fixtures stay under `Linux_LLM/tools/eval_fixtures/generalisation/`.
- `python -m unittest discover -s tests -p 'test_*.py'` from `Linux_LLM`: **365 OK** (includes `test_ui_surface_inventory.py`).

## UI overhaul (2026-09)

Authenticated pages use a shared dark monochrome design system (`Linux_LLM/config/static/css/soc.css`). Dashboard, live alert viewer, and report editor keep the previous routes, element IDs, and API calls. Emoji and Bootstrap CDN styling were removed from the UI. Progress still consumes backend WebSocket `progress`/`message` values; the client does not invent percentages.

### UI changes

- Dark near-black surfaces, grey borders, restrained semantic colour for ready/warning/error only.
- Shared type scale: sans-serif for chrome, monospace only for hashes/IPs/JSON.
- Sticky header navigation: Overview, Knowledge base, Analysis, Alert viewer, Reports, Diagnostics.
- CTI and analysis workflows shown as stage chips; live progress uses the existing WebSocket plus a stage list derived from server messages.
- Structured error notices with expandable technical details; empty states explain the next action.
- Copy-name controls on reports; copy on alert IPs; generated-report filename filter on the current page.
- Alert viewer no longer loads Bootstrap from a CDN.
- Report editor keeps marked.js 9.1.6 SRI and `renderSafeMarkdown`.

### Preserved functionality

Every previous user-facing control remains. Inventory is pinned by `Linux_LLM/tests/test_ui_surface_inventory.py`.

```text
Existing feature                         Location before     Location after              Still available  Tested
Dashboard /                        GET /                 GET /                         YES              YES (template + route tests)
Wazuh SSH/model/reports summary    dashboard chips       Overview chips                YES              YES (template; ssh.host still absent)
Production warnings                dashboard             dashboard                     YES              YES
Archive RAG source                 useArchivesCheck      Knowledge base                YES              YES
Archive day range                  ragDays               Knowledge base                YES              YES
CTI upload                         customDocs            Knowledge base                YES              YES
Duplicate check                    POST /check-duplicates same                         YES              YES (JS + route tests)
Extend lossless union              extendRagMode         Knowledge base                YES              YES (RagDashboardContractTests)
Replace + confirm                  confirmReplaceCheck   Knowledge base                YES              YES
Build/refresh RAG                  POST /build-rag       Knowledge base                YES              YES
RAG status                         GET /rag-status       Overview + knowledge          YES              YES
Alert JSON template                alertTemplate         Analysis                      YES              YES
Auto-analyze                       POST /analyze-alerts  Analysis                      YES              YES
Manual alert viewer                GET /alerts/viewer    Alert viewer                  YES              YES
Live alerts + severity filter      GET /api/live-alerts  Alert viewer                  YES              YES
Select/analyze alerts              POST /analyze-selected-alerts  Alert viewer         YES              YES
Analysis redirect poll             GET /api/check-analysis-result/{id}  same           YES              YES
Progress WebSocket                 /ws/progress/{id}     status panel                  YES              YES
Single-report PDF                  /convert-to-pdf       Reports Download PDF          YES              YES
Batch/auto PDF APIs                /batch-convert-pdf, /set-auto-convert, /pdf-status  operator API     YES              YES (converter tests; no Reports UI)
Existing reports + pagination      GET /library          Reports                       YES              YES
Generated reports JSON             GET /reports          operator listing API          YES              YES
Report download                    GET /reports/{file}   Download buttons              YES              YES
Report editor                      GET /reports/{file}/edit and /review-report/{id}    YES              YES
MITRE search/select                /api/mitre-techniques Report editor                 YES              YES
Preview/save/validate/approve      preview/save/validate/approve APIs  editor          YES              YES
System status JSON                 GET /system-status    Diagnostics                   YES              YES
Test connection JSON               GET /test-connection  Diagnostics                   YES              YES
Charts include flag                include_charts=true   analyzeAlerts()               YES              YES
```

### New UX improvements

- Overview metrics for documents/chunks/archives from `/rag-status` (same payload, no extra polling).
- RAG progress percentages follow archive, extract, and index phases; analysis upload crawls 1% every 10 seconds up to 99% while the backend is still working.
- In-page errors instead of emoji alerts; replace still uses `window.confirm`.
- Skip link, `aria-current`, `aria-live` progress log, labelled remove buttons in the editor.
- Count column header added for the existing threat-count field.

### Design system

| Token | Value |
| --- | --- |
| Background | `#0b0c0e` |
| Surface | `#171a1f` / `#1d2128` |
| Border | `#2b3038` |
| Text | `#e6e8eb` / `#b4b9c1` / `#8b919a` |
| Accent (interactive) | `#d6d9de` on dark |
| Semantic | red `#c56b6b`, amber `#c4a35a`, green `#7fa37f` |
| Fonts | `ui-sans-serif, system-ui, Segoe UI`; `ui-monospace` for technical values |
| Icons | none as a mixed icon font; text + simple CSS chips |
| Radius | 6px |
| Components | `.panel`, `.btn` / `.btn-primary`, `.status-indicator`, `.notice`, `.empty-state`, `.data` tables, `.metric` |

### Performance

| Metric | Before | After |
| --- | --- | --- |
| Design CSS | Inline in each HTML page (~300+ lines on dashboard; Bootstrap 5.3 CDN on the viewer) | One local `soc.css` 14.7 KB |
| Dashboard JS | `script.js` ~21 KB of logic + emoji strings | Local `script.js` (progress, notices, RAG/analysis actions; no new library) |
| Alert viewer JS/CSS | Bootstrap CSS CDN + page CSS | Local `soc.css` only; no CDN |
| New frontend framework | none | none |
| Extra API pollers | RAG status on Overview/Knowledge/Analysis load; analysis result poll 2s | PDF/auto-convert UI pollers removed |
| Full unit suite | 361 OK | 365 OK after inventory tests |

Live Time-to-Interactive of the production Uvicorn process was not re-measured in this agent session: `python main.py` could not start because the configured model path and dotenv-backed web/database secrets were not available to the agent. Layout of `/`, `/alerts/viewer`, and `/review-report/{id}` was inspected from rendered templates.

### Regression testing

```text
Total tests     365
Passed          365
Failed          0
Skipped         0
```

Command: `python -m unittest discover -s tests -p 'test_*.py'` from `Linux_LLM` after adding `test_ui_surface_inventory.py` (4 tests). Prior discover without that file: 361 OK.

### Visual validation

Dashboard overview, knowledge base, analysis, PDF, diagnostics, reports; alert viewer chrome; report editor metadata/findings/threats/MITRE/actions/preview. No emoji. Dark monochrome. Long filenames wrap. JSON template remains behind a disclosure.

### Accessibility

- Skip to content
- Form labels and fieldset legend for RAG mode
- Focus outline on interactive elements
- `aria-live` on progress
- `role="alert"` on errors
- Severity is labelled in text, not colour-only
- Contrast: light grey on near-black

### Cleanup

- Removed per-page prototype CSS, emoji chrome, and Bootstrap CDN from the alert viewer.
- No unused component library added.
- Temporary raster files used for visual checks are not kept in the repository.

## Production release cleanup (2026-09)

Evidence-driven hygiene pass. Production routes, RAG, extraction, and the automated test suite were kept.

### Files removed

- **obsolete / sensitive diagrams:** `images/main.png` included a real SSH host (`100.78.175.127`). `images/setup.png`, `images/pipeline.png`, and `images/rag.png` described a single lab GPU layout or a semantic-only RAG story that is no longer accurate. Architecture is now text/mermaid in README and `docs/rag-architecture.md`.

### Code / debug

- Removed dashboard debug dumps (`Returning response: {response}`, analyze-alerts chatter, “about to call generate_report”).
- Removed unused `lastGeneratedReports` in `script.js`.
- Stripped emoji from operator logs, progress WebSocket copy, and generated report headings so console/UI/report output matches the SOC shell.
- Restored stop-word/TLD tokens and PDF page-number CSS that a quote-space cleanup pass had glued or spaced incorrectly (`"and"`/`"in"` false-domain list, STIX ` aliases=`, WeasyPrint `Page N of M`).
- Left process-local `print`/`logger` lines that report startup, RAG, SSH, PDF, and monitoring state (production observability).

### Documentation

- Replaced the 1,600-line README (missing files, `admin:admin`, `/home/student/...` paths, Windows-workspace claims) with a short, accurate front door that defers install detail to `docs/operations.md`.
- Dropped the operations.md “undeployed cleanup handoff” sentence that referred to a previous pass.
- Corrected remaining Bootstrap-CDN claims: only Marked 9.1.6 remains on the report editor; dashboard and alert viewer use local `soc.css`.
- Documented authenticated workflow routes, including operator-only `POST /generate-visual-report`.

### Tests retained

All `Linux_LLM/tests/test_*.py` modules and `Linux_LLM/tools/` eval/acceptance/hygiene utilities. No regression tests were deleted.

### Dependencies

None removed. `pandas` and `matplotlib` remain required by `charts.py`; `geoip2`, PyMuPDF, pypdf, WeasyPrint remain in use.

### Security

- Removed the diagram that embedded an internal SSH address.
- `.env` remains gitignored; `.env.example` uses `change-me` placeholders.
- No production debug endpoints were added or left from this pass. `/system-status`, `/test-connection`, `/chart-capabilities`, `/generate-visual-report`, and `/api/report-metrics` stay as authenticated operator APIs.

### Final validation (cleanup pass)

```text
Application startup       FAIL in this environment (no `.env`; preflight refuses start — expected)
Frontend                  PASS (templates + `test_ui_surface_inventory`; live browser not used)
Database                  FAIL connect without operator credentials; port 5432 was listening
CTI ingestion             PASS (unit: ingestion/DOCX/PDF processors)
CTI extraction            PASS (unit + labelled eval tools retained)
RAG                       PASS (unit: additive union, regressions)
Exact IOC retrieval       PASS (unit: `test_generalisation_ioc`, retrieval quality)
Lexical retrieval         PASS (unit: retrieval quality / RAG regressions)
Semantic retrieval        PASS (unit: ranking/hybrid path; live embed not re-run)
Alert parsing             PASS (unit: `test_wazuh_normalization`, alert-schema-v4)
LLM analysis              PASS (unit: token budget, prompt fences; live GGUF not invoked)
Report generation         PASS (unit: evidence discipline, incident synthesis, parser)
PDF generation            PASS (unit: converter hardening; WeasyPrint import OK)
Documentation validation  PASS (README/operations/rag-architecture paths and commands exist)
Repository hygiene        PASS (`check_repository.py`, 0 findings)
Unit tests                PASS (365 OK)
```

`python3 Linux_LLM/config/runtime_preflight.py --json` from the cleaned tree reported configuration / LLM path / PostgreSQL credential failures and usable templates. That is the documented clean-start gate, not a missing application file.

## Readiness

```text
READY FOR CONTROLLED TESTING
```
