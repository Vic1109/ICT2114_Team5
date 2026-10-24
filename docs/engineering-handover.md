# Engineering handover

Updated 2026-10-25 for the Anthropic, additive RAG memory, responsive UI, and five report-quality follow-up fixes.

## Validation boundary

This revision was reviewed on the Windows source checkout using static analysis only, as requested. The application, unit tests, PostgreSQL, embedding model, llama.cpp, Anthropic API, browser rendering, and PDF renderer were not executed. Syntax/source checks establish parseability and source consistency; they do not establish runtime success, model accuracy, GPU memory use, or latency.

Earlier versions of this handover mixed September lab measurements, different test counts, and outdated UI/diagram descriptions. Those historical results remain in Git history and are not acceptance evidence for this revision. No production-readiness or accuracy certification is implied by removing the Overview warning.

## Architecture and maintained contracts

The FastAPI composition root is `SOCApplication` in `Linux_LLM/config/main.py`.

```text
CTI upload -> DocumentProcessor / CTIArtifactExtractor
  -> section-aware chunks + canonical IOC index + embeddings
  -> versioned PostgreSQL/pgvector corpus
Wazuh JSON (SSH or upload) -> AlertNormalizer -> AlertAnalyzer
  -> exact / lexical / semantic retrieval -> evidence ranking
  -> shared prompt -> local llama.cpp or Anthropic
  -> structural validation + claim audit -> review -> approved Markdown/PDF
```

See [RAG architecture](rag-architecture.md), [alert-to-prompt pipeline](alert-to-prompt-pipeline.md), [LLM providers](llm-providers.md), and [operations](operations.md) for the implementation and deployment contracts.

The changes preserve these accuracy controls in source:

- Raw alert/provenance preservation and common canonical normalization for uploads and SSH.
- Typed, boundary-aware exact IOC matching, lexical search, semantic retrieval, canonical source diversity, and evidence-strength gating.
- Current-alert evidence separated from historical CTI; explicit, inferred, and historical ATT&CK mappings stay distinct.
- Fenced untrusted telemetry/documents, reserved exact IOC evidence, attribution support requirements, and post-generation claim checks.
- Corpus inventory/completeness validation and atomic activation: an incomplete target cannot replace the prior ready corpus.
- Report review, rich Markdown/appendix preservation, approval validation, and local-resource-only PDF rendering.

## Changes in this revision

### Anthropic workflow

The configured default `claude-sonnet-5-5` previously received `temperature=0.2`, which that model rejects. Payloads now include sampling parameters only for explicitly supported legacy families. Modern and unknown families omit them. No switch to local inference occurs on a public-provider failure.

The stdlib transport supports `ANTHROPIC_WORKSPACE_ID` for keys that are not scoped to a workspace. It trims credential whitespace, bounds and closes HTTP error bodies, and returns fixed messages for workspace, billing, sampling, model/authentication, invalid settings, and context failures. Logs retain bounded status/type/category/request ID instead of raw API text. The API key and workspace ID remain server-side.

A server-reported context overflow now reduces the actual request budget, including when the character estimator thought the original request fit. The existing reducer protects exact IOC/output rules and refuses impossible budgets. Per-generation context-reduction telemetry resets correctly.

The report deadline now covers both permitted model passes, public transient backoff and context correction, and separate local server preparation. It previously allowed only one pass, which could cancel a legitimate structural repair.

Sonnet 5.5 uses adaptive thinking by default, and `max_tokens` covers both thinking and report text. Review the output-token cap if reports are repeatedly empty/incomplete; do not silently increase account spend or disable reasoning. Provider documentation links to the official parameter/authentication contracts.

### RAG embedding memory

`embedding_runtime.py` provides `MemorySafeSentenceTransformer`. Recovery runs inside each actual encoder, including SentenceTransformers multiprocessing workers. An uncaught CUDA OOM in a worker can otherwise terminate that worker while its parent waits for a result.

CUDA OOM retries halve the batch down to one. If one input still cannot fit, that worker moves to CPU and continues there. Non-memory errors propagate normally. Model, precision, input content/normalization, sequence limit, vector dimensions, and vector normalization are unchanged; CPU/GPU floating-point results can still differ numerically. Model placement also occurs inside the recovery boundary rather than through the deprecated `_target_device` setter.

New and resumed rows use the same bounded commit scheduler. Long inputs retain the conservative batch cap, all eligible inputs can use the bulk devices, and one pool is reused across length groups. Work items are large enough to fill the configured batch while keeping workers engaged; the previous default splitting could create seven-input work items for a 32-input batch. Existing vectors are retained; only missing vectors are computed. This revision fixes the resident-device path ignoring the caller's smaller batch. Completed commits remain resumable after failure.

The subclass preserves the dense model's saved-module loader, including Qwen's pooling configuration. Worker messages and liveness checks follow the [pinned SentenceTransformers 5.1.1 source](https://github.com/UKPLab/sentence-transformers/blob/v5.1.1/sentence_transformers/SentenceTransformer.py); review that integration before upgrading the dependency.

A worker may fall back to CPU when llama.cpp already occupies GPU memory. That preserves the data contract but can increase build time. Actual speed and peak VRAM remain unmeasured on the target server; no runtime efficiency claim is made from static inspection.

### UI

The Overview production warning and Knowledge advanced-notes disclosure were removed. Authenticated pages use the available width with responsive gutters, consistent panel/control spacing, wrapping navigation/actions, scrollable tables, and stacked mobile layouts. Login, registration, MFA setup/verification, account administration, alert viewer, reports, and report editor share the spacing rules.

Existing template IDs and handlers are retained. Provider controls preserve the non-admin lock when a busy state ends. Viewer and editor render contexts now carry the authenticated account name and role; without the viewer role, even an admin's provider control was disabled. MITRE selections are keyboard-operable buttons, preview state is exposed with `aria-expanded`, and reduced-motion preferences are respected. Runtime preflight checks remain available to operators through Diagnostics.

### URL evidence normalization

Malformed URL ports are rejected as invalid IOCs instead of raising from `urlparse().port`. This avoids an invalid IOC aborting an extraction/analysis batch. Canonical output for previously valid inputs is unchanged, so this fix does not change corpus versions or require re-embedding an existing corpus.

## Static verification

Validation remains static only. The final checks passed Python 3.10-compatible AST parsing/in-memory compilation for 64 Python files, parsing of six JSON files, Jinja/include/HTML structure and unique DOM-ID checks for 14 templates, JavaScript syntax for two inline scripts and three external/regression files, CSS delimiters, repository hygiene over all 104 current files (including new sources), documentation/local paths, and `git diff --check`. All original literal template IDs remain present. These checks import no application module and contact no runtime service. Authored regression sources are unexecuted in this checkout.

An AST comparison with `HEAD` confirms that corpus identities/activation, retrieval SQL/ranking/evidence gates, prompt construction, attribution/ATT&CK claim audit, and approved-report indexing are unchanged. Independent static reviews traced the provider admission/cancellation paths, public completion-state rejection, editor value preservation, and mapping reconciliation. Formatting edge cases found during review were corrected and represented in regression sources. This establishes the reviewed source contracts, not runtime accuracy or test success.

## Five report-quality follow-up fixes

1. **Provider changes during a report:** manual, selected-alert, and automatic work now reserve the provider before background/executor submission. The same gate excludes selection changes through both model passes, metadata, telemetry, cancellation, and worker cleanup. HTTP selection changes return 409 while work is pending/running. Analyst analysis forms cannot bypass the admin change rule. Tokens invalidate timed-out queued work and prevent stale timeouts from cancelling a later report; a separate cancellation flag survives client preparation clearing its reusable event.
2. **Direction/type coercion:** editor controls retain source/destination roles, unknown/custom values, and missing classifications. Recognized direction case is normalized without changing inbound/outbound meaning. Missing/custom severity is also preserved rather than defaulting to Critical.
3. **Confidence inflation:** confidence is a visible selector and round-trips the original value. Parser/serializer defaults for missing or blank confidence are `Not established`, not `High`.
4. **Ignored ATT&CK edits:** the serializer reconciles selections with rich mapping records. Unchanged records keep their evidence classes, rationale, and citations. Removed mapping records disappear; shared records keep retained IDs while replacing withdrawn mapping declarations. Supporting URLs/citations remain intact and do not select a mapping merely by containing its ID. Explicitly touched names/tactics can change without promoting evidence class. Additions are labelled analyst selections with evidence not established. Server review routes restore the original rich/appendix/mapping baseline from the draft for preview/save/validate/approve. Independent narrative/alert/CTI source references remain evidence; deselecting a mapping does not erase those facts or promise that every source mention disappears from historical retrieval.
5. **Incomplete public responses accepted as complete:** only `end_turn` with text reaches report structural validation. Token/context limits, refusals, tools, paused turns, custom stops, and missing/unknown states fail with actionable messages. Billed usage is retained and no continuation, higher budget, paid retry, or completed fallback is added.

Source regression coverage includes reservation ownership/cancellation and queued automatic work, HTTP provider-role/busy handling, actual editor JavaScript with a minimal form-control fixture, mapping classes and Markdown formats, reviewed preview/save/approval consistency, missing confidence, and public completion-state handling. The JavaScript regression uses Node's built-in test runner and adds no application dependency.

## Isolated Linux acceptance still required

Use a disposable database and test report/upload directories, with `LIVE_MONITORING_ENABLED=false` unless deliberately validating a test Wazuh manager. Apply the deployed environment and dependency versions. Do not run the acceptance tools against a production database.

1. Run the retained unit suite from `Linux_LLM`: `python -m unittest discover -s tests -p 'test_*.py'`. From the same directory, run `node --test tests/test_report_editor_fidelity.js` with Node's built-in test runner. Then run `python Linux_LLM/tools/check_repository.py` from the repository root.
2. Run `python Linux_LLM/config/runtime_preflight.py --json` with the isolated environment and inspect every failure/warning.
3. Build a small CTI corpus, extend it with new PDFs, repeat identical uploads, and resume a partially embedded target. Compare source inventory, canonical IOC rows, chunk counts, vector dimensions/normalization, prior-source retrieval, and atomic activation against expectations.
4. Exercise CPU, one GPU, multiple GPUs, long/short mixtures, and GPU pressure with llama.cpp resident. Confirm bounded batch backoff, no stuck workers, no skipped chunks, pool cleanup, and retry/resume after failure. Record build duration and peak VRAM; compare to a baseline without changing extraction/retrieval settings.
5. Analyse a strong exact-IOC alert, an alternate Wazuh schema, an unseen indicator, a near-match negative, benign activity, and injected CTI/log instructions. Check source ranking, preserved evidence, direction/ports/processes, ATT&CK categories, qualified attribution, and grounded remediation.
6. Repeat the alert set with both providers. Verify Anthropic credential/workspace/model access, successful report text, and safe rejection/retry messages. Attempt changes from another tab during pending/running manual and automatic jobs; confirm 409 and one provider throughout. Cancel queued/preparing work and confirm it cannot start a later model request or cancel a newer report. A paid API call is required to verify actual public-model access and output quality; use mocks to exercise incomplete/refusal/continuation stop states without an extra bill.
7. Preview, save, approve, re-open, and export reports. Verify `Destination | outbound`, Low/Medium/missing confidence, custom values, ATT&CK removals, clear-all, additions, retained historical/inferred classes, label corrections, source citations, and saved/reopened mappings. Compare approved Markdown with the reviewed preview. Confirm generated QA appendices stay out of indexed RAG and independent source evidence remains historical.
8. Check every page at narrow mobile, tablet, desktop, and wide desktop widths, with keyboard navigation, long filenames/IOCs, and error/busy states.

## Remaining limits

Static review cannot certify absence of factual errors. Extraction remains heuristic and scanned PDFs require external OCR. Raw IPv6 addresses are supported, but bracketed IPv6 URL extraction/canonicalization remains limited. Approximate vector retrieval and model output need a representative labelled acceptance set. One application worker is required because locks and transient state are process-local. CPU memory recovery can be slower than GPU encoding; non-memory worker/process failure and host-level resource exhaustion still require operational recovery.

The editor reconciles mapping sections while preserving independent source evidence; reviewers still need to inspect the final preview when changing factual claims. Markdown extraction is heuristic, and unusually structured reports belong in the isolated acceptance set before operational use.

Changes are local and uncommitted. No service, database, remote host, or deployment was modified.
