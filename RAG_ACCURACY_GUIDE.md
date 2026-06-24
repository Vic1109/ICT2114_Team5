# RAG Accuracy and Reliability Guide

This project uses RAG to support CTI reporting, but RAG output should not be treated as automatically correct. The current implementation adds deterministic guardrails so retrieved context is useful without allowing weak matches to become unsupported incident claims.

## Implemented Controls

### 1. Exact IoC Boundary Matching

Exact IoC matching is type-aware. For IP addresses, the retriever now requires full IP-token equality, so `192.168.56.10` will not match `192.168.56.101`.

Why this matters:
- Prevents false "exact" evidence from substring matches.
- Reduces incorrect attribution from unrelated CTI chunks.
- Makes the RAG source appendix more trustworthy for analyst review.

### 2. Chunk-Local CTI Artefacts

Uploaded CTI documents are now indexed with artefacts extracted from each chunk rather than prepending the entire document's artefact list to every chunk.

Why this matters:
- A chunk only receives IoC context that appears near its actual text.
- Reduces false matches caused by IoCs that appear elsewhere in the same PDF.
- Preserves document-wide artefact counts separately for diagnostics.

### 3. Public vs Non-Public IP Handling

The extractor preserves non-public IPs in metadata but does not promote them as CTI context for uploaded documents.

Examples of non-public IPs:
- RFC1918 internal ranges such as `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
- Loopback and link-local IPs
- Documentation/test ranges
- Lab or analysis-environment IPs

Why this matters:
- Private/lab IPs often describe victims, sandboxes, or examples rather than hostile infrastructure.
- Public IPs remain searchable as potential external indicators.
- Non-public IPs are still retained for audit and context.

### 4. Source/Destination Awareness

Cleaned alerts now include `directional_focus`, which explains which endpoint matters most for the alert direction.

Examples:
- Inbound: external source is likely attacker/infrastructure, destination is protected target.
- Outbound: source is potentially compromised asset, destination may be C2 or exfiltration endpoint.
- Lateral: both endpoints are internal; do not infer public threat actor attribution from private IPs alone.

Why this matters:
- Prevents the model from treating every source IP as the attacker.
- Improves TTP mapping and remediation selection.
- Makes lateral movement analysis more accurate.

### 5. RAG Evidence Audit Labels

Each retrieved source is annotated before it is passed to the LLM:

| Field | Meaning |
|-------|---------|
| `evidence_strength` | `high`, `medium`, or `low` support for the current incident |
| `source_reliability` | Local telemetry, uploaded CTI document, or analyst-approved report |
| `current_ioc_overlap` | Exact IoCs shared by the current alert and retrieved source |
| `historical_only_artifacts` | Artefacts in the source but not observed in the current alert |
| `retrieval_cautions` | Warnings such as semantic-only support or no exact overlap |

Why this matters:
- Semantic-only CTI matches are kept as background, not proof.
- Uploaded CTI can support historical context without overstating current observations.
- The report appendix exposes why each RAG source was selected.

### 6. CTI Context Labels

Uploaded CTI chunks are tagged by likely analytical role, such as `ioc_listing`, `ttp_behavior`, `attribution`, `remediation`, `victim_infrastructure`, `analysis_environment`, and `vulnerability`.

Why this matters:
- IoC tables can support indicator correlation.
- TTP sections can support MITRE mapping.
- Remediation sections can support recommended actions.
- Victim or analysis-environment sections should not be treated as attacker infrastructure.

### 7. Post-Generation Report QA Findings

After the LLM generates a report, the system runs a lightweight audit over risky claims. If the report contains attribution language, specific actor names without matching support, unsupported MITRE technique IDs, or IoCs that only appeared in low-strength historical context, a `Report QA Findings` appendix is added for analyst review.

Why this matters:
- The model can still overstate claims even when retrieval is careful.
- Naming a specific actor/family now requires that exact term in current alert context or a high/medium attribution source with current-alert overlap.
- The QA appendix warns reviewers before approval.
- Warnings are preserved by the report parser/editor flow.

### 8. Artifact Disposition Labels

Uploaded CTI chunks also classify individual indicators by nearby language:

| Disposition | Meaning |
|-------------|---------|
| `malicious` | Indicator appears near malicious/C2/actor wording |
| `benign` | Indicator appears near legitimate, allowlisted, known-good, false-positive, sinkhole, or unrelated wording |
| `victim` | Indicator appears near victim, target, affected system, or internal host wording |
| `analysis_environment` | Indicator appears near sandbox, lab, detonation, researcher, or example wording |
| `remediation_reference` | Indicator appears near block, hunt, detect, firewall, or mitigation wording |
| `unknown` | No strong local context was found |

Why this matters:
- The same IP/domain format can represent attacker infrastructure, benign infrastructure, a victim, or a sandbox.
- Exact overlap with benign, victim, or analysis-environment artifacts should not become high-confidence threat attribution.
- Analysts can inspect the artifact disposition in the RAG appendix.

### 9. Approved-Report Feedback-Loop Control

Approved reports can be indexed back into RAG as analyst-validated historical context. Before indexing, generated appendices such as `Report QA Findings`, `RAG Sources Used`, and `Visual Threat Analysis` are stripped from the indexed copy.

Why this matters:
- Prevents generated citations and QA warnings from becoming future evidence.
- Reduces self-reinforcing RAG loops where a past generated report amplifies weak sources.
- Keeps the saved approved report intact while storing a cleaner RAG version.

### 10. Low-Strength Context Filtering

After retrieved sources are reranked and audited, low-strength background sources are capped when high/medium evidence is available. If all sources are weak, the system can still pass weak context through as fallback, but it is labeled and cautioned.

Why this matters:
- Prevents semantic-only background from crowding out stronger alert-matching evidence.
- Keeps the LLM prompt focused on sources most relevant to the current incident.
- Still allows graceful fallback when no strong evidence exists.

### 11. Document Extraction Quality Signals

Uploaded documents are assessed for extraction quality before they are indexed. The metadata records quality, text density, image markers, table markers, artifact count, and warnings such as `image_heavy_pdf_no_ocr`, `low_text_density`, `few_extracted_words`, or `no_cti_artifacts_extracted`.

Why this matters:
- Scanned or image-heavy PDFs may not expose their real IoCs or TTPs to text extraction.
- The RAG appendix can warn analysts when a source may be incomplete.
- The model is instructed to lower confidence and avoid absence-based claims from low-quality extraction sources.

### 12. Alert Behavior and Response Focus Hints

Current alerts are enriched with deterministic `behavior_tags` and `response_focus` fields before retrieval and prompting.

Examples:
- `possible_c2`
- `lateral_movement_candidate`
- `malware_or_destructive_activity`
- `web_or_exploit_attempt`
- `reconnaissance_or_scanning`
- `compromised_asset_egress`

Why this matters:
- RAG queries can retrieve CTI by behavior, not only by raw IoC strings.
- MITRE mapping is grounded in observed alert behavior.
- Remediation recommendations become direction-aware, such as isolating a possible outbound C2 source versus hardening an inbound target service.

### 13. MITRE Catalog Validation

Generated ATT&CK technique IDs are checked against the local `mitre_techniques.json` catalog during post-generation QA.

Why this matters:
- Unknown technique IDs are flagged as possible hallucinations, typos, or stale mappings.
- Deprecated technique IDs are flagged so analysts can prefer current ATT&CK mappings.
- Existing evidence checks still require MITRE IDs to be grounded in current alert behavior or high/medium-strength TTP context.

### 14. CTI Behavior Alignment

Uploaded CTI chunks are tagged with coarse behavior labels such as `possible_c2`, `credential_attack`, `lateral_movement_candidate`, `malware_or_destructive_activity`, and `web_or_exploit_attempt`.

Why this matters:
- A CTI chunk about the same attack behavior is ranked higher than a semantically similar chunk about a different behavior.
- Behavior-mismatched chunks receive a retrieval caution and should remain background context.
- MITRE technique support from uploaded CTI must align with current alert behavior when behavior labels are available.

### 15. Structure-Aware CTI Chunking

Uploaded CTI documents are chunked with nearby section headings preserved as `cti_section` metadata.

Why this matters:
- Headings such as `Indicators of Compromise`, `Victim Infrastructure`, `Attribution`, and `Remediation` explain the role of nearby artifacts.
- Unknown artifact roles can be resolved from section context without overriding explicit sentence-local labels.
- RAG prompts and source manifests show the section path so analysts can review why a chunk was interpreted a certain way.

### 16. Remediation Target Grounding

Post-generation QA extracts artifacts that appear near action verbs such as `block`, `isolate`, `quarantine`, and `disable`.

Why this matters:
- Immediate actions should target artifacts observed in the current alert, not only historical CTI.
- Benign, victim-side, analysis-environment, and remediation-reference artifacts are flagged before approval if they are used as action targets.
- Historical-only malicious IoCs can still be recommended as proactive watchlist/blocklist candidates, but should not be presented as confirmed incident targets.

### 17. CTI Corpus Alert Shape Parsing

Offline alert templates and archive logs now preserve CTI-corpus fields such as `data.email`, direct DNS `rrname`/`rrtype`, `data.fileinfo`, `data.smb`, and `data.modbus`.

Why this matters:
- Phishing alerts retain sender, recipient, subject, attachment, mail-from domain, and delivery URL.
- File hashes from `fileinfo` become observed IoCs for exact matching and retrieval.
- SMB and Modbus fields become part of semantic chunks, behavior tags, and retrieval fingerprints.
- Top-level objects with an `alerts` array are accepted by the analyzer as well as the upload route.

## How to Run Accuracy Checks

Run the deterministic guardrail checks from the project root:

```bash
python Linux_LLM/config/rag_accuracy_checks.py
```

Expected output:

```json
[
  {
    "check": "ip_substring_not_exact",
    "status": "pass"
  },
  {
    "check": "private_ips_not_promoted_as_cti_context",
    "status": "pass"
  },
  {
    "check": "evidence_audit_labels",
    "status": "pass"
  },
  {
    "check": "cti_context_classification",
    "status": "pass"
  },
  {
    "check": "artifact_disposition_labels",
    "status": "pass"
  },
  {
    "check": "report_claim_audit",
    "status": "pass"
  },
  {
    "check": "actor_specific_attribution_audit",
    "status": "pass"
  },
  {
    "check": "remediation_target_grounding",
    "status": "pass"
  },
  {
    "check": "mitre_catalog_validation",
    "status": "pass"
  },
  {
    "check": "approved_report_index_sanitization",
    "status": "pass"
  },
  {
    "check": "low_strength_context_filtering",
    "status": "pass"
  },
  {
    "check": "document_extraction_quality",
    "status": "pass"
  },
  {
    "check": "alert_behavior_and_response_focus",
    "status": "pass"
  },
  {
    "check": "cti_corpus_alert_shape_parsing",
    "status": "pass"
  },
  {
    "check": "cti_behavior_alignment",
    "status": "pass"
  },
  {
    "check": "structure_aware_cti_chunking",
    "status": "pass"
  }
]
```

These checks do not require PostgreSQL, embeddings, or the LLM. They validate deterministic logic only.

## Operational Notes

After changing CTI indexing logic, clear and rebuild the RAG database so old document chunks are replaced.

Recommended workflow:
1. Clear RAG context from the dashboard.
2. Re-upload CTI documents.
3. Rebuild RAG.
4. Run a known alert template.
5. Inspect the `RAG Sources Used` appendix for evidence strength, overlaps, and cautions.
6. Inspect the `Report QA Findings` appendix before approving the report.

## Remaining Limitations

These controls improve reliability, but they do not make CTI understanding perfect.

Important remaining limitations:
- PDF extraction can miss text inside images unless OCR is added.
- Semantic retrieval may still retrieve related but non-actionable background.
- Actor attribution remains risky unless current alert evidence overlaps with strong CTI evidence.
- MITRE mapping should be grounded in observed behavior, not only CTI document mentions.
- Remediation should be tied to affected asset, service, direction, and observed behavior.

## Recommended Future Enhancements

1. Add a golden evaluation set of alert templates with expected RAG sources, MITRE mappings, and forbidden false claims.
2. Add a cross-encoder reranker after pgvector retrieval to improve semantic precision.
3. Add artifact-level confidence labels such as malicious, benign/example, victim, infrastructure, or unknown.
4. Add OCR for scanned or image-heavy CTI PDFs.
5. Store analyst feedback on false-positive RAG sources and use it to down-rank similar matches later.
