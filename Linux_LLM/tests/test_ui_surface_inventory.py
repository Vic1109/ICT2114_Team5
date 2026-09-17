"""Pin the authenticated UI surface so a restyle cannot drop user-facing controls."""

from __future__ import annotations

import re
import unittest
from pathlib import Path


CONFIG_DIR = Path(__file__).resolve().parents[1] / "config"
EMOJI = re.compile(r"[\U0001F300-\U0001FAFF\u2600-\u27BF\uFE0F]")


class UiSurfaceInventoryTests(unittest.TestCase):
    def _read(self, relative: str) -> str:
        return (CONFIG_DIR / relative).read_text(encoding="utf-8")

    def test_shared_design_system_and_no_emoji(self):
        dashboard = self._read("templates/dashboard.html")
        viewer = self._read("templates/alert_viewer.html")
        editor = self._read("templates/report_editor.html")
        script = self._read("static/js/script.js")
        css = self._read("static/css/soc.css")

        for name, text in (
            ("dashboard.html", dashboard),
            ("alert_viewer.html", viewer),
            ("report_editor.html", editor),
            ("script.js", script),
            ("soc.css", css),
        ):
            self.assertIsNone(EMOJI.search(text), name)

        self.assertIn("soc.css", dashboard)
        self.assertIn("soc.css", viewer)
        self.assertIn("soc.css", editor)
        self.assertNotIn("cdn.jsdelivr.net/npm/bootstrap", viewer)

    def test_dashboard_keeps_rag_analysis_pdf_and_diagnostic_controls(self):
        dashboard = self._read("templates/dashboard.html")
        script = self._read("static/js/script.js")
        for element_id in (
            "useArchivesCheck",
            "archiveOptions",
            "ragDays",
            "useUploadsCheck",
            "uploadOptions",
            "customDocs",
            "fileValidation",
            "duplicateWarning",
            "extendRagMode",
            "replaceRagMode",
            "confirmReplaceCheck",
            "replaceConfirmation",
            "buildModeHint",
            "buildRagBtn",
            "ragStatus",
            "ragStatusText",
            "alertTemplate",
            "analyzeBtn",
            "reportSelect",
            "autoConvertCheck",
            "pdfStatus",
            "pdfStatusText",
            "status",
            "existingReportsList",
            "reportsList",
            "reportsPagination",
        ):
            self.assertIn(f'id="{element_id}"', dashboard, element_id)

        self.assertIn('value="extend" checked', dashboard)
        self.assertIn("lossless union", dashboard)
        self.assertIn('href="/alerts/viewer"', dashboard)
        self.assertIn('href="/system-status"', dashboard)
        self.assertIn('href="/test-connection"', dashboard)
        self.assertIn("formData.append('build_mode', buildMode)", script)
        self.assertIn("formData.append('confirm_replace', confirmReplace)", script)
        self.assertIn("fetch('/build-rag'", script)
        self.assertIn("fetch('/analyze-alerts'", script)
        self.assertIn("fetch('/convert-to-pdf'", script)
        self.assertIn("fetch('/batch-convert-pdf'", script)
        self.assertIn("fetch('/set-auto-convert'", script)
        self.assertIn("fetch('/check-duplicates'", script)
        self.assertIn("/ws/progress/", script)
        self.assertIn("/api/check-analysis-result/", script)

    def test_alert_viewer_keeps_live_selection_and_analysis_controls(self):
        viewer = self._read("templates/alert_viewer.html")
        for element_id in (
            "autoRefreshToggle",
            "refreshInterval",
            "analyzeBtn",
            "selectedCount",
            "cacheStatus",
            "alertsContainer",
        ):
            self.assertIn(f'id="{element_id}"', viewer, element_id)
        self.assertIn("/api/live-alerts", viewer)
        self.assertIn("fetch('/analyze-selected-alerts'", viewer)
        self.assertIn("/api/check-analysis-result/", viewer)

    def test_report_editor_keeps_review_controls_and_safe_markdown(self):
        editor = self._read("templates/report_editor.html")
        for element_id in (
            "threatLevel",
            "totalAlerts",
            "execSummary",
            "execSummary-count",
            "findingsList",
            "threatsTable",
            "threatsBody",
            "mitreSearch",
            "mitreSelector",
            "selectedTechniques",
            "clearMitreBtn",
            "recommendationsList",
            "previewContent",
            "validationErrors",
            "errorList",
            "autoSaveIndicator",
        ):
            self.assertIn(f'id="{element_id}"', editor, element_id)
        self.assertIn("marked@9.1.6", editor)
        self.assertIn("integrity=", editor)
        self.assertIn("renderSafeMarkdown", editor)
        self.assertIn("/api/mitre-techniques", editor)
        self.assertIn("/api/preview-report", editor)
        self.assertIn("/api/save-draft/", editor)
        self.assertIn("/api/validate-report", editor)
        self.assertIn("/api/approve-report/", editor)


if __name__ == "__main__":
    unittest.main()
