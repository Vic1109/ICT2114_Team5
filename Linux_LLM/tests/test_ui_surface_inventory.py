"""Pin the authenticated UI surface so a restyle cannot drop user-facing controls."""

from __future__ import annotations

import re
import unittest
from pathlib import Path


CONFIG_DIR = Path(__file__).resolve().parents[1] / "config"
EMOJI = re.compile(r"[\U0001F300-\U0001FAFF\u2600-\u27BF\uFE0F]")
TEMPLATES = (
    "templates/dashboard.html",
    "templates/knowledge.html",
    "templates/analysis.html",
    "templates/library.html",
    "templates/alert_viewer.html",
    "templates/report_editor.html",
    "templates/_nav.html",
    "templates/_base.html",
    "static/js/script.js",
    "static/css/soc.css",
)


class UiSurfaceInventoryTests(unittest.TestCase):
    def _read(self, relative: str) -> str:
        return (CONFIG_DIR / relative).read_text(encoding="utf-8")

    def test_shared_design_system_and_no_emoji(self):
        texts = {name: self._read(name) for name in TEMPLATES}
        for name, text in texts.items():
            self.assertIsNone(EMOJI.search(text), name)

        for page in (
            "templates/dashboard.html",
            "templates/knowledge.html",
            "templates/analysis.html",
            "templates/library.html",
        ):
            self.assertIn("_base.html", texts[page])
            self.assertIn("_nav.html", texts["templates/_base.html"])

        self.assertIn("soc.css", texts["templates/_base.html"])
        self.assertIn("soc.css", texts["templates/alert_viewer.html"])
        self.assertIn("soc.css", texts["templates/report_editor.html"])
        self.assertNotIn("cdn.jsdelivr.net/npm/bootstrap", texts["templates/alert_viewer.html"])

    def test_navbar_uses_separate_pages(self):
        nav = self._read("templates/_nav.html")
        self.assertIn('href="/" ', nav)
        self.assertIn('href="/knowledge"', nav)
        self.assertIn('href="/analysis"', nav)
        self.assertIn('href="/alerts/viewer"', nav)
        self.assertIn('href="/library"', nav)
        self.assertNotIn('href="#knowledge"', nav)
        self.assertNotIn('href="/#reports"', nav)

    def test_knowledge_page_keeps_rag_controls_and_progress_mount(self):
        knowledge = self._read("templates/knowledge.html")
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
            "jobProgress",
        ):
            self.assertIn(f'id="{element_id}"', knowledge, element_id)

        self.assertIn('value="extend" checked', knowledge)
        self.assertIn("lossless union", knowledge)
        self.assertIn("formData.append('build_mode', buildMode)", script)
        self.assertIn("formData.append('confirm_replace', confirmReplace)", script)
        self.assertIn("fetch('/build-rag'", script)
        self.assertIn("setKnowledgeBusy", script)
        self.assertIn("/ws/progress/", script)
        self.assertNotIn("knowledgeStageList", knowledge)
        self.assertNotIn("Select CTI", knowledge)
        self.assertNotIn("progress-stages", knowledge)
        self.assertIn("ANALYSIS_CRAWL_MS = 10000", script)
        self.assertIn("ANALYSIS_CRAWL_CAP = 99", script)
        self.assertNotIn("RAG_STAGES", script)
        self.assertNotIn("renderStages", script)

    def test_analysis_page_keeps_alert_controls_and_busy_state(self):
        analysis = self._read("templates/analysis.html")
        script = self._read("static/js/script.js")
        for element_id in ("alertTemplate", "analyzeBtn", "jobProgress"):
            self.assertIn(f'id="{element_id}"', analysis, element_id)
        self.assertIn('href="/alerts/viewer"', analysis)
        self.assertIn("fetch('/analyze-alerts'", script)
        self.assertIn("/api/check-analysis-result/", script)
        self.assertIn("setAnalysisBusy", script)
        self.assertNotIn("analysisStageList", analysis)
        self.assertNotIn("Extract IOCs", analysis)
        self.assertNotIn("progress-stages", analysis)

    def test_overview_keeps_diagnostics(self):
        dashboard = self._read("templates/dashboard.html")
        for element_id in ("overviewMetrics", "metricReady", "metricDocs", "settings"):
            self.assertIn(f'id="{element_id}"', dashboard, element_id)
        self.assertIn('href="/system-status"', dashboard)
        self.assertIn('href="/test-connection"', dashboard)

    def test_library_reports_md_pdf_and_no_duplicate_generated_section(self):
        library = self._read("templates/library.html")
        script = self._read("static/js/script.js")
        self.assertIn('id="existingReportsList"', library)
        self.assertIn("Download MD", library)
        self.assertIn("Download PDF", library)
        self.assertNotIn("Copy name", library)
        self.assertNotIn("Copy name", script)
        self.assertNotIn("Generated reports", library)
        self.assertNotIn('id="generatedReportFilter"', library)
        self.assertNotIn('id="reportsList"', library)
        self.assertNotIn('id="autoConvertCheck"', library)
        self.assertNotIn('id="pdfStatus"', library)
        self.assertNotIn("PDF conversion", library)
        self.assertNotIn("fetch('/batch-convert-pdf'", script)
        self.assertNotIn("fetch('/set-auto-convert'", script)
        self.assertIn("fetch('/convert-to-pdf'", script)
        self.assertIn("downloadReportPdf", script)

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
        self.assertIn('{% include "_nav.html" %}', viewer)
        nav = self._read("templates/_nav.html")
        self.assertIn('href="/knowledge"', nav)
        self.assertIn('href="/library"', nav)

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
            "approveBtn",
            "approveProgress",
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
        self.assertIn("computing embeddings", editor)
        self.assertIn("progress-bar indeterminate", editor)
        self.assertIn("table-scroll", editor)


if __name__ == "__main__":
    unittest.main()
