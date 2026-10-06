"""Single source of truth for report prompt section names and context policy.

`report.py` assembles a prompt out of nonce-marked sections. Two consumers then
have to reason about those same sections without re-reading the report code:

* `llm_client.py` compacts an over-long prompt for the local llama.cpp path.
* `llm_provider.py` reduces an over-long prompt for the public OpenAI path.

Both need the section order, the compaction priority, the per-section character
limits, and whether a section carries alert evidence or retrieved CTI. Those
tables used to be repeated as literal string lists in both modules, so adding a
section meant editing eight lists and silently mis-budgeting the ones that were
missed. Everything lives here instead, and `registered_section_name()` lets the
marker builder reject a name that was never registered.

Add a new section by adding its name to exactly one of the three role tuples
below, giving it a `SECTION_CHAR_LIMITS` entry, and placing it in
`COMPACTION_PRIORITY`.
"""

from __future__ import annotations

from typing import Dict, Optional, Tuple


ANALYSIS_TYPE = "ANALYSIS TYPE"
CURRENT_ALERTS_DATA = "CURRENT ALERTS DATA"
CURRENT_HIGH_SEVERITY_INCIDENT_DATA = "CURRENT HIGH-SEVERITY INCIDENT DATA"
CURRENT_ALERT_OBSERVATIONS = "CURRENT ALERT — AUTHORITATIVE OBSERVATIONS"
CURRENT_ALERT_FLOW_LEDGER = "CURRENT ALERT — FLOW AND EVIDENCE LEDGER"
CURRENT_ALERT_MITRE_EVIDENCE = "CURRENT ALERT — EXPLICIT / INFERRED MITRE EVIDENCE"
CANONICAL_INCIDENT_SYNTHESIS = (
    "CANONICAL INCIDENT SYNTHESIS — ORGANIZE THE REPORT AROUND THIS OBJECT"
)
CONFIGURED_ASSET_INVENTORY = "CONFIGURED ASSET INVENTORY"
HIGH_SEVERITY_ALERTS = "HIGH-SEVERITY ALERTS"

EXACT_IOC_MATCHES = "DETERMINISTIC EXACT IOC MATCHES — APPLICATION-ESTABLISHED"
RAG_REFERENCE_CONTEXT = "RAG REFERENCE CONTEXT"
RETRIEVED_HISTORICAL_CTI = "RETRIEVED HISTORICAL CTI — SOURCE-BOUND EXCERPTS"
COMPLEMENTARY_PASSAGES = "COMPLEMENTARY PASSAGES FROM THE ALREADY-SELECTED TOP DOCUMENT"

CONFLICTS_LIMITATIONS = "CONFLICTS / LIMITATIONS"
ATTRIBUTION_POLICY = "ATTRIBUTION POLICY"
CONTEXT = "CONTEXT"
INSTRUCTIONS = "INSTRUCTIONS"
OUTPUT_CONTRACT = "OUTPUT CONTRACT"

# Headings emitted by earlier releases of the report builder. They are retained
# because the local compaction path also accepts a prompt replayed from an
# older process, and it needs these names to find the true section boundaries in
# that prompt. Nothing in the current builder emits them.
LEGACY_REPRESENTATIVE_CURRENT_ALERTS = "REPRESENTATIVE CURRENT ALERTS"
LEGACY_HISTORICAL_AND_CUSTOM_REFERENCE_CONTEXT = "HISTORICAL AND CUSTOM REFERENCE CONTEXT"

LEGACY_SECTIONS: Tuple[str, ...] = (
    LEGACY_REPRESENTATIVE_CURRENT_ALERTS,
    LEGACY_HISTORICAL_AND_CUSTOM_REFERENCE_CONTEXT,
)

# Current-incident evidence. Counted against the alert half of the token budget.
ALERT_EVIDENCE_SECTIONS: Tuple[str, ...] = (
    ANALYSIS_TYPE,
    CURRENT_ALERTS_DATA,
    CURRENT_HIGH_SEVERITY_INCIDENT_DATA,
    CURRENT_ALERT_OBSERVATIONS,
    CURRENT_ALERT_FLOW_LEDGER,
    CURRENT_ALERT_MITRE_EVIDENCE,
    CANONICAL_INCIDENT_SYNTHESIS,
    LEGACY_REPRESENTATIVE_CURRENT_ALERTS,
    HIGH_SEVERITY_ALERTS,
    CONFIGURED_ASSET_INVENTORY,
)

# Retrieved knowledge-base evidence. Counted against the CTI half of the budget
# and reserved separately during compaction so retrieval cannot be starved.
CTI_EVIDENCE_SECTIONS: Tuple[str, ...] = (
    LEGACY_HISTORICAL_AND_CUSTOM_REFERENCE_CONTEXT,
    RAG_REFERENCE_CONTEXT,
    EXACT_IOC_MATCHES,
    RETRIEVED_HISTORICAL_CTI,
    COMPLEMENTARY_PASSAGES,
)

# Instructions and report scaffolding. Neither alert nor retrieved evidence.
FORMATTING_SECTIONS: Tuple[str, ...] = (
    CONFLICTS_LIMITATIONS,
    ATTRIBUTION_POLICY,
    CONTEXT,
    INSTRUCTIONS,
    OUTPUT_CONTRACT,
)

# Every known section, in the order they appear in an assembled prompt. Used as
# the boundary vocabulary when splitting a prompt that carries no nonce markers.
ALL_SECTIONS: Tuple[str, ...] = (
    ANALYSIS_TYPE,
    CURRENT_ALERTS_DATA,
    CURRENT_HIGH_SEVERITY_INCIDENT_DATA,
    CURRENT_ALERT_OBSERVATIONS,
    CURRENT_ALERT_FLOW_LEDGER,
    CURRENT_ALERT_MITRE_EVIDENCE,
    CANONICAL_INCIDENT_SYNTHESIS,
    EXACT_IOC_MATCHES,
    CONFIGURED_ASSET_INVENTORY,
    LEGACY_REPRESENTATIVE_CURRENT_ALERTS,
    HIGH_SEVERITY_ALERTS,
    LEGACY_HISTORICAL_AND_CUSTOM_REFERENCE_CONTEXT,
    RAG_REFERENCE_CONTEXT,
    RETRIEVED_HISTORICAL_CTI,
    COMPLEMENTARY_PASSAGES,
    CONFLICTS_LIMITATIONS,
    ATTRIBUTION_POLICY,
    CONTEXT,
    INSTRUCTIONS,
    OUTPUT_CONTRACT,
)

# Order in which sections claim the local compaction budget. Earlier entries are
# emitted first, so the incident itself outranks retrieved background, and the
# report scaffolding is last because it is also reserved out of the greedy fill.
COMPACTION_PRIORITY: Tuple[str, ...] = (
    ANALYSIS_TYPE,
    CURRENT_ALERTS_DATA,
    CURRENT_HIGH_SEVERITY_INCIDENT_DATA,
    CANONICAL_INCIDENT_SYNTHESIS,
    EXACT_IOC_MATCHES,
    CURRENT_ALERT_OBSERVATIONS,
    CURRENT_ALERT_FLOW_LEDGER,
    CURRENT_ALERT_MITRE_EVIDENCE,
    LEGACY_REPRESENTATIVE_CURRENT_ALERTS,
    HIGH_SEVERITY_ALERTS,
    LEGACY_HISTORICAL_AND_CUSTOM_REFERENCE_CONTEXT,
    RAG_REFERENCE_CONTEXT,
    RETRIEVED_HISTORICAL_CTI,
    COMPLEMENTARY_PASSAGES,
    CONFLICTS_LIMITATIONS,
    ATTRIBUTION_POLICY,
    OUTPUT_CONTRACT,
    CONFIGURED_ASSET_INVENTORY,
    INSTRUCTIONS,
    CONTEXT,
)

DEFAULT_SECTION_CHAR_LIMIT = 1200

# Per-section character ceiling applied while compacting. A section with no
# entry falls back to DEFAULT_SECTION_CHAR_LIMIT.
SECTION_CHAR_LIMITS: Dict[str, int] = {
    CURRENT_ALERTS_DATA: 1800,
    CURRENT_HIGH_SEVERITY_INCIDENT_DATA: 1800,
    CANONICAL_INCIDENT_SYNTHESIS: 3500,
    EXACT_IOC_MATCHES: 1800,
    CURRENT_ALERT_OBSERVATIONS: 3600,
    CURRENT_ALERT_FLOW_LEDGER: 6000,
    CURRENT_ALERT_MITRE_EVIDENCE: 1200,
    LEGACY_REPRESENTATIVE_CURRENT_ALERTS: 3600,
    HIGH_SEVERITY_ALERTS: 3600,
    LEGACY_HISTORICAL_AND_CUSTOM_REFERENCE_CONTEXT: 3200,
    RAG_REFERENCE_CONTEXT: 3200,
    RETRIEVED_HISTORICAL_CTI: 4500,
    COMPLEMENTARY_PASSAGES: 3600,
    CONFLICTS_LIMITATIONS: 700,
    ATTRIBUTION_POLICY: 500,
    OUTPUT_CONTRACT: 2200,
    CONFIGURED_ASSET_INVENTORY: 700,
    INSTRUCTIONS: 800,
    CONTEXT: 500,
}

# Public-provider reduction policy. Retrieved background is shortened before any
# current-incident evidence, and the exact-IOC block is shortened only once the
# rest has already been reduced.
PROVIDER_SHRINK_FIRST: Tuple[str, ...] = (
    COMPLEMENTARY_PASSAGES,
    RETRIEVED_HISTORICAL_CTI,
    RAG_REFERENCE_CONTEXT,
    LEGACY_HISTORICAL_AND_CUSTOM_REFERENCE_CONTEXT,
    CANONICAL_INCIDENT_SYNTHESIS,
    HIGH_SEVERITY_ALERTS,
    LEGACY_REPRESENTATIVE_CURRENT_ALERTS,
    CURRENT_ALERT_MITRE_EVIDENCE,
    CONFIGURED_ASSET_INVENTORY,
    CONTEXT,
)

PROVIDER_SHRINK_ALERTS_AFTER_CTI: Tuple[str, ...] = (
    CURRENT_ALERTS_DATA,
    CURRENT_HIGH_SEVERITY_INCIDENT_DATA,
    CURRENT_ALERT_OBSERVATIONS,
    CURRENT_ALERT_FLOW_LEDGER,
)

PROVIDER_IOC_SECTION = EXACT_IOC_MATCHES

# Sections the public-provider reducer never shortens: they define the report
# contract and the rules the model must follow, so a partial copy is worse than
# a smaller evidence budget.
PROVIDER_KEEP_INTACT: Tuple[str, ...] = (
    OUTPUT_CONTRACT,
    ATTRIBUTION_POLICY,
    INSTRUCTIONS,
    ANALYSIS_TYPE,
    CONFLICTS_LIMITATIONS,
)

_REGISTERED = frozenset(ALL_SECTIONS)


def registered_section_name(name: str) -> Optional[str]:
    """Return the registered section a heading belongs to, or None.

    Headings may carry a dynamic suffix, for example
    ``HIGH-SEVERITY ALERTS (Compact View - Top 6 of 20)``, so the longest
    registered prefix wins rather than requiring an exact match.
    """
    observed = str(name or "").strip().upper()
    if not observed:
        return None
    best = None
    for section in ALL_SECTIONS:
        candidate = section.upper()
        if observed.startswith(candidate) and (best is None or len(candidate) > len(best)):
            best = section
    return best


def section_char_limit(section: str) -> int:
    """Character ceiling for a section during compaction."""
    return SECTION_CHAR_LIMITS.get(section, DEFAULT_SECTION_CHAR_LIMIT)


def is_registered(name: str) -> bool:
    return name in _REGISTERED
