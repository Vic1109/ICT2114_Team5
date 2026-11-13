#!/usr/bin/env python3
"""Queue, session ledger, and report-deletion checks.

These do not call the model. They check that bursts are retained, manual jobs
can be listed after a new process opens the same ledger, cancellation does not
require stopping the process, and report deletion stays inside the reports directory.
"""

from __future__ import annotations

import logging
import sys
import tempfile
import unittest
from pathlib import Path

CONFIG_DIR = Path(__file__).resolve().parents[1] / "config"
if str(CONFIG_DIR) not in sys.path:
    sys.path.insert(0, str(CONFIG_DIR))

from analysis_queue import AnalysisQueue  # noqa: E402
from live_monitoring import EnhancedLiveMonitoringService  # noqa: E402
from main import delete_report_files  # noqa: E402


class AnalysisQueueTests(unittest.TestCase):
    def test_manual_jobs_survive_reopen_and_cancel_without_a_payload(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "analysis-queue.json"
            queue = AnalysisQueue(path)
            job = queue.add_manual(
                owner="analyst",
                source="manual_upload",
                label="uploaded-alert.json",
                session_id="11111111-1111-1111-1111-111111111111",
                alert_count=1,
                llm_provider="local",
                payload={"selected_alerts": [{"rule": {"id": "1"}}]},
            )
            reopened = AnalysisQueue(path)
            reopened.recover_interrupted()
            visible = reopened.list_jobs("analyst")
            self.assertEqual(visible[0]["id"], job["id"])
            self.assertEqual(visible[0]["status"], "failed")
            self.assertIn("restarted", visible[0]["detail"])
            self.assertEqual(reopened.cancel(job["id"], "analyst")["status"], "failed")
            self.assertIsNone(reopened.cancel(job["id"], "other-user"))

    def test_queued_manual_job_can_be_cancelled_by_its_owner(self):
        with tempfile.TemporaryDirectory() as directory:
            queue = AnalysisQueue(Path(directory) / "analysis-queue.json")
            job = queue.add_manual(
                owner="analyst",
                source="manual_upload",
                label="one.json",
                session_id="22222222-2222-2222-2222-222222222222",
                alert_count=2,
                llm_provider=None,
                payload={"selected_alerts": []},
            )
            cancelled = queue.cancel(job["id"], "analyst")
            self.assertEqual(cancelled["status"], "cancelled")
            self.assertIsNone(queue.claim_next_manual())
            self.assertIsNone(queue.cancel(job["id"], "other-user"))

    def test_live_rows_update_in_place_and_are_visible_to_the_operator(self):
        with tempfile.TemporaryDirectory() as directory:
            queue = AnalysisQueue(Path(directory) / "analysis-queue.json")
            queue.observe_live("hash-1", "sshd failed", "queued", 10)
            queue.observe_live("hash-1", "sshd failed", "processed", 10)
            jobs = queue.list_jobs("analyst")
            self.assertEqual(len(jobs), 1)
            self.assertEqual(jobs[0]["status"], "processed")
            self.assertEqual(jobs[0]["source"], "live")

    def test_dismiss_removes_a_row_and_approval_clears_the_matching_report(self):
        with tempfile.TemporaryDirectory() as directory:
            queue = AnalysisQueue(Path(directory) / "analysis-queue.json")
            waiting = queue.add_manual(
                owner="analyst",
                source="manual_upload",
                label="waiting.json",
                session_id="33333333-3333-3333-3333-333333333333",
                alert_count=1,
                llm_provider=None,
                payload={"selected_alerts": []},
            )
            reviewed = queue.add_manual(
                owner="analyst",
                source="manual_upload",
                label="reviewed.json",
                session_id="44444444-4444-4444-4444-444444444444",
                alert_count=1,
                llm_provider=None,
                payload={"selected_alerts": []},
            )
            queue.finish(reviewed["id"], "processed", "Report is ready for review.", report_id="draft-1")
            queue.observe_live("hash-live", "live alert", "processed", 12)
            queue.attach_report(["hash-live"], "AUTO_HIGH_example.md")
            self.assertIsNone(queue.dismiss(waiting["id"], "other-user"))
            self.assertEqual(queue.dismiss(waiting["id"], "analyst")["id"], waiting["id"])
            self.assertIsNone(queue.dismiss(waiting["id"], "analyst"))
            self.assertEqual(queue.clear_reviewed(report_id="draft-1"), 1)
            self.assertEqual(queue.clear_reviewed(report_filename="AUTO_HIGH_example.md"), 1)
            self.assertEqual(queue.list_jobs("analyst"), [])


class LiveBurstQueueTests(unittest.TestCase):
    def test_burst_is_compacted_instead_of_dropped(self):
        service = EnhancedLiveMonitoringService.__new__(EnhancedLiveMonitoringService)
        service.pending_reports_queue = []
        service.max_queue_size = 1
        service.statistics = {}
        service.logger = logging.getLogger("test-live-queue")
        service.activity_log = AnalysisQueue(Path(tempfile.mkdtemp()) / "analysis-queue.json")
        for index in range(3):
            service._enqueue_pending_reports(
                [{"id": index}],
                [{
                    "rule_id": str(1000 + index),
                    "timestamp": f"2026-11-13T00:0{index}:00Z",
                    "src_ip": f"203.0.113.{index + 1}",
                    "rule_description": f"alert {index}",
                    "rule_level": 10,
                }],
            )
        self.assertEqual(len(service.pending_reports_queue), 1)
        self.assertEqual(len(service.pending_reports_queue[0]["triggered_alerts"]), 3)
        statuses = {job["label"]: job["status"] for job in service.activity_log.list_jobs("analyst")}
        self.assertEqual(statuses, {"alert 0": "queued", "alert 1": "queued", "alert 2": "queued"})


class ReportDeletionTests(unittest.TestCase):
    def test_delete_removes_the_report_pdf_and_unshared_chart_only(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            charts = root / "charts"
            charts.mkdir()
            (charts / "only-this.png").write_bytes(b"png")
            (charts / "shared.png").write_bytes(b"png")
            (root / "keep.md").write_text("See charts/shared.png\n", encoding="utf-8")
            (root / "remove.md").write_text(
                "Body\n![Chart](./charts/only-this.png)\n![Chart](./charts/shared.png)\n",
                encoding="utf-8",
            )
            (root / "remove.pdf").write_bytes(b"pdf")
            result = delete_report_files(root, "remove.md")
            self.assertFalse((root / "remove.md").exists())
            self.assertFalse((root / "remove.pdf").exists())
            self.assertFalse((charts / "only-this.png").exists())
            self.assertTrue((charts / "shared.png").exists())
            self.assertTrue((root / "keep.md").exists())
            self.assertIn("only-this.png", result["removed_charts"])

    def test_delete_rejects_a_path_outside_the_reports_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(Exception) as raised:
                delete_report_files(Path(directory), "../outside.md")
            self.assertEqual(getattr(raised.exception, "status_code", None), 400)


if __name__ == "__main__":
    unittest.main()
