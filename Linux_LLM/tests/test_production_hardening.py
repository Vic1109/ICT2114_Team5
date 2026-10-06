"""Regression tests for the production-readiness hardening pass.

Each test pins a defect that was found and fixed, so the defect cannot return
silently. They are grouped by the subsystem they protect.
"""

from __future__ import annotations

import ast
import re
import sys
import unittest
import uuid
from pathlib import Path


CONFIG_DIR = Path(__file__).resolve().parents[1] / "config"
if str(CONFIG_DIR) not in sys.path:
    sys.path.insert(0, str(CONFIG_DIR))

import prompt_sections  # noqa: E402
from alert_normalizer import AlertNormalizer  # noqa: E402
from cti_artifacts import CTIArtifactExtractor  # noqa: E402
from llm_client import LlamaModelClient  # noqa: E402
from report import AlertAnalyzer, ReportFormatter  # noqa: E402


class PromptSectionRegistryTests(unittest.TestCase):
    """The section tables were duplicated across eight literal lists."""

    def test_role_groups_partition_all_sections(self):
        roles = (
            prompt_sections.ALERT_EVIDENCE_SECTIONS
            + prompt_sections.CTI_EVIDENCE_SECTIONS
            + prompt_sections.FORMATTING_SECTIONS
        )
        self.assertEqual(sorted(roles), sorted(prompt_sections.ALL_SECTIONS))
        self.assertEqual(len(roles), len(set(roles)), "a section has two roles")

    def test_compaction_priority_covers_every_section_exactly_once(self):
        priority = prompt_sections.COMPACTION_PRIORITY
        self.assertEqual(len(priority), len(set(priority)))
        self.assertEqual(set(priority), set(prompt_sections.ALL_SECTIONS))

    def test_no_duplicate_section_names(self):
        self.assertEqual(
            len(prompt_sections.ALL_SECTIONS), len(set(prompt_sections.ALL_SECTIONS))
        )

    def test_char_limits_only_describe_registered_sections(self):
        unknown = set(prompt_sections.SECTION_CHAR_LIMITS) - set(prompt_sections.ALL_SECTIONS)
        self.assertEqual(unknown, set())
        for section, limit in prompt_sections.SECTION_CHAR_LIMITS.items():
            self.assertGreater(limit, 0, section)

    def test_provider_policy_only_references_registered_sections(self):
        for group in (
            prompt_sections.PROVIDER_SHRINK_FIRST,
            prompt_sections.PROVIDER_SHRINK_ALERTS_AFTER_CTI,
            prompt_sections.PROVIDER_KEEP_INTACT,
            (prompt_sections.PROVIDER_IOC_SECTION,),
        ):
            for section in group:
                self.assertIn(section, prompt_sections.ALL_SECTIONS, section)

    def test_provider_never_shrinks_and_keeps_the_same_section(self):
        shrinkable = set(prompt_sections.PROVIDER_SHRINK_FIRST) | set(
            prompt_sections.PROVIDER_SHRINK_ALERTS_AFTER_CTI
        )
        self.assertEqual(shrinkable & set(prompt_sections.PROVIDER_KEEP_INTACT), set())

    def test_every_section_the_report_emits_is_registered(self):
        """Guards the drift that let two names outlive their emitters."""
        emitted = set()
        source = (CONFIG_DIR / "report.py").read_text(encoding="utf-8")
        for node in ast.walk(ast.parse(source)):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", None)
            if name != "section_marker" or not node.args:
                continue
            argument = node.args[0]
            if isinstance(argument, ast.Constant) and isinstance(argument.value, str):
                emitted.add(argument.value)
            elif isinstance(argument, ast.JoinedStr):
                # A heading may carry a dynamic suffix; its literal prefix is the name.
                leading = argument.values[0]
                if isinstance(leading, ast.Constant) and isinstance(leading.value, str):
                    emitted.add(leading.value.strip())

        self.assertTrue(emitted, "no section_marker calls were found to check")
        for name in emitted:
            with self.subTest(section=name):
                self.assertIsNotNone(
                    prompt_sections.registered_section_name(name),
                    f"report.py emits {name!r} but prompt_sections does not register it",
                )

    def test_llm_modules_read_the_shared_registry(self):
        """No module may keep its own copy of the section tables."""
        self.assertEqual(
            LlamaModelClient._ALERT_BUDGET_SECTIONS,
            frozenset(prompt_sections.ALERT_EVIDENCE_SECTIONS),
        )
        self.assertEqual(
            LlamaModelClient._CTI_BUDGET_SECTIONS,
            frozenset(prompt_sections.CTI_EVIDENCE_SECTIONS),
        )
        import llm_provider

        self.assertIs(llm_provider._SHRINK_LAST, prompt_sections.PROVIDER_SHRINK_FIRST)
        self.assertIs(llm_provider._KEEP_INTACT, prompt_sections.PROVIDER_KEEP_INTACT)

    def test_dynamic_heading_suffix_still_resolves(self):
        self.assertEqual(
            prompt_sections.registered_section_name(
                "HIGH-SEVERITY ALERTS (Compact View - Top 6 of 20)"
            ),
            prompt_sections.HIGH_SEVERITY_ALERTS,
        )
        self.assertIsNone(prompt_sections.registered_section_name("NOT A SECTION"))


class MalformedAlertBatchTests(unittest.TestCase):
    """One malformed record used to abort the whole batch with AttributeError.

    Records reach clean_log_data without passing AlertNormalizer in two ways:
    members of a nested ``alerts`` array, and alerts whose normalisation failed
    and were preserved verbatim.
    """

    def setUp(self):
        self.analyzer = AlertAnalyzer()

    def clean(self, alerts):
        return self.analyzer.clean_log_data(alerts)

    def test_scalar_containers_do_not_raise(self):
        shapes = [
            {"rule": "scalar rule", "data": {"src_ip": "10.0.0.5"}},
            {"rule": {"level": 7, "description": "flat data"}, "data": "flat string"},
            {"rule": {"level": 9, "description": "http"}, "data": {"http": "GET /x"}},
            {"rule": {"level": 9, "description": "dns"}, "data": {"dns": "evil.example.com"}},
            {"rule": {"level": 9, "description": "process"}, "data": {"process": ["a"]}},
            {"rule": {"level": 9, "description": "win"}, "data": {"win": 42}},
            {
                "rule": {"level": 9, "description": "agent"},
                "agent": "host-as-scalar",
                "data": {"src_ip": "10.0.0.1"},
            },
        ]
        for shape in shapes:
            with self.subTest(shape=str(shape)[:60]):
                self.assertEqual(len(self.clean([shape])), 1)

    def test_one_malformed_record_does_not_discard_the_rest(self):
        """The malformed record used to abort the batch before the good one ran."""
        good = {
            "rule": {"level": 12, "description": "well formed", "id": "9999"},
            "agent": {"name": "srv1", "ip": "10.0.0.9"},
            "data": {"src_ip": "10.0.0.9", "dest_ip": "203.0.113.7"},
        }
        # Nested `alerts` members are pulled out raw, bypassing AlertNormalizer.
        batch = [{"alerts": [{"rule": "scalar", "data": {"http": "GET /"}}, good]}]

        cleaned = self.clean(batch)

        self.assertIn("9999", [row.get("rule_id") for row in cleaned])
        self.assertEqual(self.analyzer.last_clean_stats["received"], 2)

    def test_malformed_record_carrying_signal_is_retained(self):
        good = {
            "rule": {"level": 12, "description": "well formed", "id": "9999"},
            "data": {"src_ip": "10.0.0.9"},
        }
        malformed = {"rule": "scalar", "data": {"src_ip": "10.0.0.5"}}

        cleaned = self.clean([{"alerts": [malformed, good]}])

        self.assertEqual(len(cleaned), 2)
        self.assertEqual(self.analyzer.last_clean_stats["dropped_no_signal"], 0)

    def test_scalar_signature_and_dns_survive_coercion(self):
        cleaned = self.clean(
            [
                {"rule": {"level": 9, "description": "sig"}, "data": {"alert": "ET SCAN probe"}},
                {"rule": {"level": 9, "description": "dns"}, "data": {"dns": "evil.example.com"}},
            ]
        )
        self.assertEqual(cleaned[0].get("alert_signature"), "ET SCAN probe")
        self.assertEqual(len(cleaned), 2)

    def test_mitre_read_tolerates_scalar_rule(self):
        cleaned = self.clean([{"rule": "scalar", "data": {"src_ip": "10.0.0.5"}}])
        self.assertEqual(len(cleaned), 1)


class DirectionReconciliationTests(unittest.TestCase):
    """The prompt used to carry two conflicting application-established directions."""

    def setUp(self):
        self.formatter = ReportFormatter.__new__(ReportFormatter)

    @staticmethod
    def alert(**overrides):
        base = {
            "timestamp": "2026-01-02T03:04:05Z",
            "rule_id": "86601",
            "rule_level": 10,
            "src_ip": "10.0.0.15",
            "dest_ip": "203.0.113.9",
            "src_ip_context": "internal",
            "dest_ip_context": "external",
            "threat_classification": {
                "is_infrastructure_alert": False,
                "is_internal_threat": True,
                "is_external_threat": False,
                "threat_direction": "outbound",
                "confidence": "medium",
            },
        }
        base.update(overrides)
        return base

    def test_conflicting_direction_is_reconciled_to_the_authoritative_value(self):
        alert = self.alert(direction="inbound")
        authoritative = self.formatter._classified_direction(alert)
        self.assertEqual(authoritative, "inbound")

        reconciled = self.formatter._reconciled_threat_classification(alert, authoritative)

        self.assertEqual(reconciled["threat_direction"], "inbound")
        self.assertEqual(reconciled["threat_direction_from_addresses"], "outbound")

    def test_reconciliation_does_not_mutate_the_source_alert(self):
        alert = self.alert(direction="inbound")
        self.formatter._reconciled_threat_classification(
            alert, self.formatter._classified_direction(alert)
        )
        self.assertEqual(alert["threat_classification"]["threat_direction"], "outbound")

    def test_reconciliation_preserves_the_other_classification_flags(self):
        alert = self.alert(direction="inbound")
        reconciled = self.formatter._reconciled_threat_classification(
            alert, self.formatter._classified_direction(alert)
        )
        for key in ("is_infrastructure_alert", "is_internal_threat", "is_external_threat", "confidence"):
            self.assertEqual(reconciled[key], alert["threat_classification"][key], key)

    def test_agreeing_alert_is_passed_through_untouched(self):
        alert = self.alert(direction="to_server")
        reconciled = self.formatter._reconciled_threat_classification(
            alert, self.formatter._classified_direction(alert)
        )
        self.assertIs(reconciled, alert["threat_classification"])

    def test_unknown_direction_does_not_overwrite_a_recorded_one(self):
        alert = self.alert(src_ip_context="unknown", dest_ip_context="unknown")
        alert.pop("direction", None)
        reconciled = self.formatter._reconciled_threat_classification(alert, "unknown")
        self.assertIs(reconciled, alert["threat_classification"])

    def test_missing_classification_is_returned_unchanged(self):
        self.assertIsNone(
            self.formatter._reconciled_threat_classification({"direction": "inbound"}, "inbound")
        )


class AlertViewerEscapingTests(unittest.TestCase):
    """HTML-escaping a value into an inline handler is not JS escaping.

    The browser HTML-decodes an attribute before parsing it as JavaScript, so a
    field containing `x');alert(1);//` closed the copyValue() string literal.
    """

    TEMPLATE = CONFIG_DIR / "templates" / "alert_viewer.html"

    def setUp(self):
        self.markup = self.TEMPLATE.read_text(encoding="utf-8")

    def test_no_inline_handler_interpolates_a_template_expression(self):
        offenders = re.findall(r'on[a-z]+="[^"]*\$\{[^}]*\}[^"]*"', self.markup)
        interpolations = [
            found
            for found in offenders
            # Numeric pagination targets are computed, never attacker-supplied.
            if not re.fullmatch(
                r'on[a-z]+="refreshAlerts\(\$\{[A-Za-z]+(?:\s*[-+]\s*1)?\}\)"', found
            )
        ]
        self.assertEqual(interpolations, [], f"inline handler carries untrusted data: {interpolations}")

    def test_no_handler_wraps_escapehtml_output_in_a_js_string(self):
        self.assertEqual(re.findall(r"on[a-z]+=\"[^\"]*escapeHtml", self.markup), [])

    def test_alert_values_travel_in_data_attributes(self):
        self.assertIn('data-alert-uuid="${escapeHtml(alertUuid)}"', self.markup)
        self.assertIn('data-copy-value="${escapeHtml(value)}"', self.markup)

    def test_a_delegated_listener_replaces_the_removed_handlers(self):
        self.assertIn("addEventListener('click'", self.markup)
        self.assertIn('data-action="copy"', self.markup)
        self.assertIn("row.dataset.alertUuid", self.markup)

    def test_pagination_counts_are_coerced_before_interpolation(self):
        self.assertIn("Number.isFinite(parsed)", self.markup)
        self.assertIn("Array.isArray(data.alerts)", self.markup)


class TelemetryFieldLabelTests(unittest.TestCase):
    """The field-path vocabulary is derived, not hand-kept."""

    def test_vocabulary_comes_from_the_alias_registry(self):
        labels = CTIArtifactExtractor._telemetry_field_labels()
        for registry in (AlertNormalizer.ECS_ALIASES, AlertNormalizer.NATIVE_WAZUH_ALIASES):
            for source_path, canonical_path in registry:
                for path in (source_path, canonical_path):
                    for part in path.split("."):
                        if part:
                            self.assertIn(part.lower(), labels, path)

    def test_dotted_field_paths_are_not_treated_as_domains(self):
        for path in (
            "http.url",
            "win.eventdata.image",
            "data.win.eventdata.parentImage",
            "win.eventdata.commandLine",
            "data.win.eventdata.originalFileName",
            "data.srcip",
            "agent.ip",
            "rule.description",
        ):
            with self.subTest(path=path):
                self.assertTrue(CTIArtifactExtractor._is_false_domain(path))

    def test_real_indicators_are_still_accepted(self):
        for domain in (
            "evil.com",
            "bad-actor.net",
            "c2.example.org",
            "evil.domain.ai",
            "login.microsoftonline.com",
            "deep.sub.domain.evil.com",
            "process.gg",
        ):
            with self.subTest(domain=domain):
                self.assertFalse(CTIArtifactExtractor._is_false_domain(domain))

    def test_only_the_final_label_decides(self):
        """Testing every label discarded indicators that merely contain a field name."""
        self.assertFalse(CTIArtifactExtractor._is_false_domain("process.gg"))
        self.assertTrue(CTIArtifactExtractor._is_false_domain("gg.process"))


class ReportIdValidationTests(unittest.TestCase):
    """Draft identifiers the application would never issue are refused."""

    def setUp(self):
        from main import SOCApplication

        self.validate = SOCApplication._require_valid_report_id

    def test_both_issued_identifier_forms_are_accepted(self):
        for candidate in (uuid.uuid4().hex, str(uuid.uuid4())):
            with self.subTest(candidate=candidate):
                self.assertEqual(self.validate(candidate), candidate)

    def test_arbitrary_keys_are_refused(self):
        from fastapi import HTTPException

        for candidate in ("", "../../etc/passwd", "not-a-uuid", "a" * 200, None):
            with self.subTest(candidate=candidate):
                with self.assertRaises(HTTPException) as caught:
                    self.validate(candidate)
                self.assertEqual(caught.exception.status_code, 404)


class RemovedDeadCodeTests(unittest.TestCase):
    """Symbols deleted in this pass must not be reintroduced unused."""

    def test_upload_path_uses_the_shared_normalizer(self):
        import main

        for name in (
            "_path_value",
            "_set_nested_missing",
            "_bounded_unknown_fields",
            "_parse_embedded_event",
        ):
            self.assertFalse(
                hasattr(main.SOCApplication, name),
                f"{name} duplicated AlertNormalizer and was unreachable",
            )

    def test_unused_rag_helpers_are_gone(self):
        import rag

        self.assertFalse(hasattr(rag, "MarkdownProcessor"))
        self.assertFalse(hasattr(rag.PDFProcessor, "extract_text"))

    def test_normalizer_convenience_wrapper_is_gone(self):
        import alert_normalizer

        self.assertFalse(hasattr(alert_normalizer, "normalize_alerts"))

    def test_object_container_fields_are_shared_not_inlined(self):
        self.assertIn("http", AlertNormalizer.OBJECT_CONTAINER_FIELDS)
        self.assertIn("fileinfo", AlertNormalizer.OBJECT_CONTAINER_FIELDS)


if __name__ == "__main__":
    unittest.main()
