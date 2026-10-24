"""Report editor round-trip regressions; execution is separate from static review."""

import sys
import unittest
from pathlib import Path


CONFIG_DIR = Path(__file__).resolve().parents[1] / "config"
if str(CONFIG_DIR) not in sys.path:
    sys.path.insert(0, str(CONFIG_DIR))

from report_parser import ReportParser  # noqa: E402


RICH_REPORT = """# SOC Report

## Executive Summary

Current telemetry supports execution; the historical source remains contextual.

## Key Findings

- Preserve current telemetry [ALERT-1].

## Incident Assessment

The observed command and its timestamp remain source-bound [ALERT-1].

## MITRE ATT&CK — Explicit Current Alert Metadata

| Tactic | Technique ID | Technique Name | Evidence Classification | Rationale |
|--------|--------------|----------------|-------------------------|-----------|
| Execution | T1059.001 | Original PowerShell label [ALERT-1] | Explicit alert metadata | Encoded command recorded at 08:07 [ALERT-1]. |

## MITRE ATT&CK — Inferred from Current Behavior

| ID | Evidence class | Detailed rationale |
|----|----------------|--------------------|
| T1105 | Deterministic current-behavior inference | Transfer attempted; successful file creation is unconfirmed [ALERT-2]. |

## MITRE ATT&CK — Historical CTI Context Only (Not Observed)

| ID | Evidence class | Detailed rationale |
|----|----------------|--------------------|
| T1027 | Historical context only; not observed | Vendor report associates obfuscation with the family [RAG-7], page 9. |

## Immediate Actions Required

1. Preserve endpoint telemetry.

**Analysis Complete**
"""


class MitreMappingRoundTripTests(unittest.TestCase):
    def test_all_evidence_classes_are_selected_and_untouched_rich_text_is_preserved(self):
        parsed = ReportParser.parse_report(RICH_REPORT)
        self.assertEqual(parsed["mitre_techniques"], ["T1027", "T1059.001", "T1105"])
        self.assertEqual(parsed["mitre_original_techniques"], parsed["mitre_techniques"])
        self.assertFalse(parsed["mitre_selection_edited"])
        self.assertEqual(parsed["mitre_modified_techniques"], [])
        for technique_id, classification in (
            ("T1059.001", "explicit_current"), ("T1105", "inferred_current"), ("T1027", "historical_only")
        ):
            self.assertEqual(parsed["mitre_technique_details"][technique_id]["evidence_classes"], [classification])
        original_rich = parsed["preserved_rich_sections_markdown"]
        # Initial catalog enrichment is not an instruction to change source labels.
        parsed["mitre_techniques"] = [{"id": value, "name": "Catalog label", "tactic": "Execution"}
                                      for value in parsed["mitre_techniques"]]
        serialized = ReportParser.serialize_to_markdown(parsed)
        self.assertIn(original_rich, serialized)
        self.assertNotIn("Analyst Additions", serialized)

    def test_removal_preserves_retained_classifications_citations_and_rationale(self):
        parsed = ReportParser.parse_report(RICH_REPORT)
        parsed["mitre_techniques"] = ["T1059.001", "T1105"]
        serialized = ReportParser.serialize_to_markdown(parsed)
        self.assertNotIn("| T1027 |", serialized)
        self.assertIn("| T1105 | Deterministic current-behavior inference | Transfer attempted; successful file creation is unconfirmed [ALERT-2]. |", serialized)
        self.assertIn("| Execution | T1059.001 | Original PowerShell label [ALERT-1] | Explicit alert metadata | Encoded command recorded at 08:07 [ALERT-1]. |", serialized)
        self.assertEqual(ReportParser.parse_report(serialized)["mitre_techniques"], ["T1059.001", "T1105"])

    def test_clear_all_is_respected_even_for_legacy_payload_without_review_metadata(self):
        parsed = ReportParser.parse_report(RICH_REPORT)
        for field in ("mitre_original_techniques", "mitre_technique_details", "mitre_selection_edited", "mitre_modified_techniques"):
            parsed.pop(field)
        parsed["mitre_techniques"] = []
        serialized = ReportParser.serialize_to_markdown(parsed)
        self.assertEqual(ReportParser.parse_report(serialized)["mitre_techniques"], [])
        self.assertIn("source-bound [ALERT-1]", serialized)

    def test_addition_is_explicitly_unestablished_while_historical_evidence_stays_historical(self):
        parsed = ReportParser.parse_report(RICH_REPORT)
        parsed["mitre_techniques"].append({"id": "t1486", "name": "Data Encrypted for Impact", "tactic": "Impact"})
        serialized = ReportParser.serialize_to_markdown(parsed)
        self.assertIn("MITRE ATT&CK — Analyst Additions (Evidence Not Established)", serialized)
        self.assertIn("**T1486** — Data Encrypted for Impact: Analyst added; evidence classification not established.", serialized)
        self.assertIn("| T1027 | Historical context only; not observed | Vendor report associates obfuscation with the family [RAG-7], page 9. |", serialized)
        self.assertEqual(ReportParser.parse_report(serialized)["mitre_technique_details"]["T1027"]["evidence_classes"], ["historical_only"])

    def test_same_id_label_correction_retains_evidence_columns_and_citations(self):
        parsed = ReportParser.parse_report(RICH_REPORT)
        parsed["mitre_techniques"] = [
            {"id": "T1059.001", "name": "PowerShell", "tactic": "Execution"}, "T1105", "T1027"
        ]
        parsed["mitre_modified_techniques"] = ["T1059.001"]
        parsed["mitre_selection_edited"] = True
        serialized = ReportParser.serialize_to_markdown(parsed)
        self.assertIn("| Execution | T1059.001 | PowerShell [ALERT-1] | Explicit alert metadata | Encoded command recorded at 08:07 [ALERT-1]. |", serialized)
        self.assertNotIn("Original PowerShell label", serialized)
        self.assertIn("Vendor report associates obfuscation", serialized)

    def test_shared_record_removes_parent_without_corrupting_retained_subtechnique(self):
        rich = """## MITRE ATT&CK — Historical CTI Context Only (Not Observed)

| ID | Rationale |
|----|-----------|
| T1059, T1059.001 | Shared historical source [RAG-4]. |
"""
        data = {"mitre_techniques": ["T1059.001"], "preserved_rich_sections_markdown": rich}
        serialized = ReportParser.serialize_to_markdown(data)
        self.assertIn("| [technique removed by analyst], T1059.001 | Shared historical source [RAG-4]. |", serialized)
        self.assertNotIn("~~", serialized)
        self.assertEqual(ReportParser.parse_report(serialized)["mitre_techniques"], ["T1059.001"])
        self.assertEqual(ReportParser.parse_report(serialized)["mitre_technique_details"]["T1059.001"]["evidence_classes"], ["historical_only"])

    def test_bullet_correction_retains_trailing_and_multiline_rationale(self):
        rich = """## MITRE ATT&CK — Inferred from Current Behavior

- **T1105** - Legacy Name (Command and Control): transfer was attempted [ALERT-2].
  File creation remains unconfirmed; the HTTP response alone is insufficient.
"""
        data = {"mitre_techniques": [{"id": "T1105", "name": "Ingress Tool Transfer", "tactic": "Command and Control"}],
                "mitre_modified_techniques": ["T1105"], "preserved_rich_sections_markdown": rich}
        serialized = ReportParser.serialize_to_markdown(data)
        self.assertIn("Ingress Tool Transfer (Command and Control): transfer was attempted [ALERT-2].", serialized)
        self.assertIn("File creation remains unconfirmed; the HTTP response alone is insufficient.", serialized)
        self.assertNotIn("Legacy Name", serialized)

    def test_nested_evidence_headings_apply_to_their_own_records(self):
        rich = """## MITRE ATT&CK Mapping

### Historical CTI Context Only
| ID | Rationale |
|----|-----------|
| T1027 | Context [RAG-1]. |

### Explicit Current Alert Metadata
| ID | Rationale |
|----|-----------|
| T1059.001 | Recorded command [ALERT-1]. |
"""
        parsed = ReportParser.parse_report(rich)
        self.assertEqual(parsed["mitre_technique_details"]["T1027"]["evidence_classes"], ["historical_only"])
        self.assertEqual(parsed["mitre_technique_details"]["T1059.001"]["evidence_classes"], ["explicit_current"])

    def test_omitted_selection_field_does_not_mean_clear_all(self):
        parsed = ReportParser.parse_report(RICH_REPORT)
        original_rich = parsed["preserved_rich_sections_markdown"]
        parsed.pop("mitre_techniques")
        self.assertIn(original_rich, ReportParser.serialize_to_markdown(parsed))

    def test_bold_technique_subheadings_and_rationale_remain_in_bold_container(self):
        rich = """**MITRE ATT&CK:**

**Explicit Current Alert Metadata:**

**T1059.001 — PowerShell**

Encoded command recorded [ALERT-1].

**Historical CTI Context Only:**

**T1027 — Obfuscated Files or Information**

Historical source rationale [RAG-1].

**Immediate Actions Required:**

1. Preserve telemetry.
"""
        parsed = ReportParser.parse_report(rich)
        self.assertEqual(parsed["mitre_techniques"], ["T1027", "T1059.001"])
        self.assertEqual(parsed["mitre_technique_details"]["T1027"]["evidence_classes"], ["historical_only"])
        parsed["mitre_techniques"] = []
        serialized = ReportParser.serialize_to_markdown(parsed)
        self.assertEqual(ReportParser.parse_report(serialized)["mitre_techniques"], [])
        self.assertNotIn("Encoded command recorded", serialized)
        self.assertNotIn("Historical source rationale", serialized)

    def test_peer_unclassified_heading_resets_class_and_own_heading_can_specify_it(self):
        rich = """## MITRE ATT&CK Mapping

### Explicit Current Alert Metadata
- T1059.001 - Current metadata [ALERT-1].

### Unclassified
- T1105 - Pending classification; file creation is unconfirmed [ALERT-2].

### T1027 — Historical CTI Context Only
Detailed source rationale [RAG-1].
"""
        parsed = ReportParser.parse_report(rich)
        self.assertEqual(parsed["mitre_technique_details"]["T1059.001"]["evidence_classes"], ["explicit_current"])
        self.assertEqual(parsed["mitre_technique_details"]["T1105"]["evidence_classes"], ["unspecified"])
        self.assertEqual(parsed["mitre_technique_details"]["T1027"]["evidence_classes"], ["historical_only"])

    def test_alternative_attack_heading_preserves_original_mapping_rationale(self):
        rich = """## MITRE ATTACK — Historical CTI Context Only

| ID | Rationale |
|----|-----------|
| T1027 | Historical source [RAG-1]. |
"""
        parsed = ReportParser.parse_report(rich)
        self.assertIn(rich.strip(), parsed["preserved_rich_sections_markdown"])
        self.assertIn(rich.strip(), ReportParser.serialize_to_markdown(parsed))

    def test_citation_only_prose_and_rationale_column_are_not_selected_as_mappings(self):
        prose = "## Executive Summary\n\nThe vendor mentions T1027 in its background [RAG-1].\n"
        self.assertEqual(ReportParser.parse_report(prose)["mitre_techniques"], [])
        rich = """## MITRE ATT&CK Mapping

| Technique | Rationale |
|-----------|-----------|
| Not established | The source compares T1027, which is not a mapping for this record [RAG-1]. |
"""
        self.assertEqual(ReportParser.parse_report(rich)["mitre_techniques"], [])

    def test_multiple_explicit_classes_are_preserved_for_one_id(self):
        rich = """## MITRE ATT&CK Mapping

| ID | Evidence Classification |
|----|-------------------------|
| T1059.001 | Explicit alert metadata; deterministic current-behavior inference |
"""
        parsed = ReportParser.parse_report(rich)
        self.assertEqual(parsed["mitre_technique_details"]["T1059.001"]["evidence_classes"],
                         ["explicit_current", "inferred_current"])

    def test_nonleading_pipe_table_and_escaped_pipe_rationale_survive_label_correction(self):
        rich = """## MITRE ATT&CK — Explicit Current Alert Metadata

Technique ID | Technique Name | Tactic | Rationale
------------ | -------------- | ------ | ---------
T1059.001 | Original name [ALERT-1] | Execution | Script used a pipeline \\| and preserved output [ALERT-1].
"""
        parsed = ReportParser.parse_report(rich)
        self.assertEqual(parsed["mitre_techniques"], ["T1059.001"])
        parsed["mitre_techniques"] = [{"id": "T1059.001", "name": "PowerShell", "tactic": "Execution"}]
        parsed["mitre_modified_techniques"] = ["T1059.001"]
        serialized = ReportParser.serialize_to_markdown(parsed)
        self.assertIn("PowerShell [ALERT-1]", serialized)
        self.assertIn("Script used a pipeline \\| and preserved output [ALERT-1].", serialized)

    def test_nested_declared_mapping_survives_parent_removal_without_promoting_cross_reference(self):
        rich = """## MITRE ATT&CK — Inferred from Current Behavior

- **T1059** — Parent mapping; comparison with T1027 is historical context [RAG-1].
  - **T1105** — Independently mapped child; transfer remains unconfirmed [ALERT-2].
"""
        parsed = ReportParser.parse_report(rich)
        self.assertEqual(parsed["mitre_techniques"], ["T1059", "T1105"])
        self.assertEqual(parsed["mitre_technique_details"]["T1059"]["evidence_classes"], ["inferred_current"])
        parsed["mitre_techniques"] = ["T1105"]
        serialized = ReportParser.serialize_to_markdown(parsed)
        self.assertIn("Independently mapped child; transfer remains unconfirmed [ALERT-2].", serialized)
        self.assertNotIn("Parent mapping", serialized)
        self.assertEqual(ReportParser.parse_report(serialized)["mitre_techniques"], ["T1105"])

    def test_bold_peer_heading_does_not_inherit_removed_historical_record(self):
        rich = """**MITRE ATT&CK:**

**Historical CTI Context Only:**
**T1027 — Obfuscation**
Historical rationale [RAG-1].

**Other Techniques:**
| ID | Rationale |
|----|-----------|
| T1105 | Transfer requires classification [ALERT-2]. |
"""
        parsed = ReportParser.parse_report(rich)
        self.assertEqual(parsed["mitre_technique_details"]["T1105"]["evidence_classes"], ["unspecified"])
        parsed["mitre_techniques"] = ["T1105"]
        serialized = ReportParser.serialize_to_markdown(parsed)
        self.assertIn("**Other Techniques:**", serialized)
        self.assertEqual(ReportParser.parse_report(serialized)["mitre_technique_details"]["T1105"]["evidence_classes"], ["unspecified"])

    def test_pipeline_bullet_keeps_multiline_rationale_and_ambiguous_source_link(self):
        rich = """## MITRE ATT&CK — Explicit Current Alert Metadata

- [T1059](https://attack.mitre.org/techniques/T1059/) — Old label; command `Get-Item | Invoke-X` [ALERT-1].
  Original multiline supporting rationale [ALERT-2].
"""
        data = {"mitre_techniques": [{"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution"}],
                "mitre_modified_techniques": ["T1059"], "preserved_rich_sections_markdown": rich}
        serialized = ReportParser.serialize_to_markdown(data)
        self.assertIn("Command and Scripting Interpreter (Execution). Analyst-corrected label", serialized)
        self.assertIn("[T1059](https://attack.mitre.org/techniques/T1059/)", serialized)
        self.assertIn("Original multiline supporting rationale [ALERT-2].", serialized)
        self.assertIn("`Get-Item | Invoke-X` [ALERT-1]", serialized)

    def test_placeholder_table_row_does_not_reset_headers(self):
        rich = """## MITRE ATT&CK Mapping

| ID | Rationale |
|----|-----------|
| N/A | No technique assigned yet |
| T1105 | Transfer [ALERT-1]. |
"""
        self.assertEqual(ReportParser.parse_report(rich)["mitre_techniques"], ["T1105"])

    def test_inferred_observed_behavior_is_not_promoted_to_explicit_metadata(self):
        rich = """## MITRE ATT&CK Mapping

### Inferred from observed current behavior
- T1105 - Inferred transfer [ALERT-1].

### Unspecified
- T1027 - Pending analyst classification [RAG-1].
"""
        parsed = ReportParser.parse_report(rich)
        self.assertEqual(parsed["mitre_technique_details"]["T1105"]["evidence_classes"], ["inferred_current"])
        self.assertEqual(parsed["mitre_technique_details"]["T1027"]["evidence_classes"], ["unspecified"])

    def test_shared_bold_ids_are_both_selected_and_independently_removable(self):
        rich = """## MITRE ATT&CK — Historical CTI Context Only (Not Observed)

- **T1059**, **T1071** — Shared historical rationale compares T1059 [RAG-3].
"""
        parsed = ReportParser.parse_report(rich)
        self.assertEqual(parsed["mitre_techniques"], ["T1059", "T1071"])
        parsed["mitre_techniques"] = ["T1071"]
        serialized = ReportParser.serialize_to_markdown(parsed)
        self.assertIn("**T1071** — Shared historical rationale compares T1059 [RAG-3].", serialized)
        self.assertEqual(ReportParser.parse_report(serialized)["mitre_techniques"], ["T1071"])

    def test_shared_table_withdrawal_preserves_rationale_urls_and_source_comparisons(self):
        rich = """## MITRE ATT&CK — Historical CTI Context Only (Not Observed)

| ID | Rationale |
|----|-----------|
| T1059, T1059.001 | Comparison with T1059 remains historical context [parent source](https://attack.mitre.org/techniques/T1059/) [RAG-4]. |
"""
        parsed = ReportParser.parse_report(rich)
        parsed["mitre_techniques"] = ["T1059.001"]
        serialized = ReportParser.serialize_to_markdown(parsed)
        self.assertIn("| [technique removed by analyst], T1059.001 |", serialized)
        self.assertIn("Comparison with T1059 remains historical context [parent source](https://attack.mitre.org/techniques/T1059/) [RAG-4].", serialized)
        self.assertEqual(ReportParser.parse_report(serialized)["mitre_techniques"], ["T1059.001"])

    def test_shared_linked_bullet_withdrawal_preserves_link_destinations(self):
        rich = """## MITRE ATT&CK — Historical CTI Context Only (Not Observed)

- [T1059](https://attack.mitre.org/techniques/T1059/), **T1059.001** — Rationale compares T1059 [parent source](https://attack.mitre.org/techniques/T1059/) [RAG-4].
  A bare source URL also remains intact: https://attack.mitre.org/techniques/T1059/ .
"""
        parsed = ReportParser.parse_report(rich)
        parsed["mitre_techniques"] = ["T1059.001"]
        serialized = ReportParser.serialize_to_markdown(parsed)
        self.assertIn("[technique removed by analyst](https://attack.mitre.org/techniques/T1059/)", serialized)
        self.assertIn("Rationale compares T1059 [parent source](https://attack.mitre.org/techniques/T1059/) [RAG-4].", serialized)
        self.assertIn("A bare source URL also remains intact: https://attack.mitre.org/techniques/T1059/ .", serialized)
        self.assertEqual(ReportParser.parse_report(serialized)["mitre_techniques"], ["T1059.001"])

    def test_ambiguous_source_wrappers_keep_inline_evidence_class_after_reopen(self):
        rich = """## MITRE ATT&CK Mapping

Source maps T1059 and T1059.001; Evidence Classification: historical context only; rationale [RAG-4].
"""
        parsed = ReportParser.parse_report(rich)
        parsed["mitre_techniques"] = ["T1059.001"]
        serialized = ReportParser.serialize_to_markdown(parsed)
        reopened = ReportParser.parse_report(serialized)
        self.assertEqual(reopened["mitre_techniques"], ["T1059.001"])
        self.assertEqual(reopened["mitre_technique_details"]["T1059.001"]["evidence_classes"], ["historical_only"])
        single = rich.replace("T1059 and ", "")
        parsed = ReportParser.parse_report(single)
        parsed["mitre_techniques"] = [{"id": "T1059.001", "name": "PowerShell", "tactic": "Execution"}]
        parsed["mitre_modified_techniques"] = ["T1059.001"]
        reopened = ReportParser.parse_report(ReportParser.serialize_to_markdown(parsed))
        self.assertEqual(reopened["mitre_technique_details"]["T1059.001"]["evidence_classes"], ["historical_only"])


class ThreatConfidenceRoundTripTests(unittest.TestCase):
    def test_missing_blank_low_and_medium_confidence_do_not_become_high(self):
        for confidence in (None, "", "Low", "Medium"):
            with self.subTest(confidence=confidence):
                confidence_header = " | Confidence" if confidence is not None else ""
                confidence_divider = " | ----------" if confidence is not None else ""
                confidence_cell = f" | {confidence}" if confidence is not None else ""
                markdown = ("## Top Priority Threats\n\n"
                            f"| IP Address | Activity | Severity{confidence_header} |\n"
                            f"| ---------- | -------- | --------{confidence_divider} |\n"
                            f"| 192.0.2.7 | Suspicious process | HIGH{confidence_cell} |\n")
                parsed = ReportParser.parse_report(markdown)
                expected = confidence or "Not established"
                self.assertEqual(parsed["threats"][0]["confidence"], expected)
                serialized = ReportParser.serialize_to_markdown(parsed)
                self.assertIn(f"| HIGH | {expected} |", serialized)
        data = {"threats": [{"ip": "192.0.2.7", "severity": "HIGH", "confidence": ""}]}
        self.assertIn("| HIGH | Not established |", ReportParser.serialize_to_markdown(data))


if __name__ == "__main__":
    unittest.main()
