"""Focused bounds and expiry tests for disconnected progress sessions."""

from __future__ import annotations

import sys
import unittest
from datetime import datetime, timedelta
from pathlib import Path


CONFIG_DIR = Path(__file__).resolve().parents[1] / "config"
if str(CONFIG_DIR) not in sys.path:
    sys.path.insert(0, str(CONFIG_DIR))

from progress import ProgressTracker  # noqa: E402


class PendingProgressHardeningTests(unittest.IsolatedAsyncioTestCase):
    async def test_pending_messages_keep_only_the_newest_twenty(self):
        tracker = ProgressTracker(max_sessions=2, session_timeout=3600)

        for index in range(25):
            sent = await tracker.send_progress("disconnected", f"message-{index}")
            self.assertFalse(sent)

        messages = tracker.pending_messages["disconnected"]
        self.assertEqual(len(messages), 20)
        self.assertEqual(messages[0].message, "message-5")
        self.assertEqual(messages[-1].message, "message-24")

    async def test_pending_session_keys_evict_least_recently_active(self):
        tracker = ProgressTracker(max_sessions=2, session_timeout=3600)
        now = datetime.now()

        await tracker.send_progress("oldest", "first")
        tracker.pending_messages["oldest"][-1].timestamp = now - timedelta(minutes=2)
        await tracker.send_progress("newer", "second")
        tracker.pending_messages["newer"][-1].timestamp = now - timedelta(minutes=1)
        await tracker.send_progress("newest", "third")

        self.assertEqual(len(tracker.pending_messages), 2)
        self.assertNotIn("oldest", tracker.pending_messages)
        self.assertIn("newer", tracker.pending_messages)
        self.assertIn("newest", tracker.pending_messages)

    async def test_cleanup_expires_stale_disconnected_pending_session(self):
        tracker = ProgressTracker(max_sessions=3, session_timeout=30)
        now = datetime.now()

        await tracker.send_progress("stale", "old")
        await tracker.send_progress("fresh", "new")
        tracker.pending_messages["stale"][-1].timestamp = now - timedelta(seconds=31)
        tracker.pending_messages["fresh"][-1].timestamp = now - timedelta(seconds=5)

        await tracker._cleanup_old_sessions()

        self.assertNotIn("stale", tracker.pending_messages)
        self.assertIn("fresh", tracker.pending_messages)

    async def test_latest_progress_returns_newest_pending_snapshot(self):
        tracker = ProgressTracker(max_sessions=2, session_timeout=3600)
        session_id = "11111111-1111-1111-1111-111111111111"
        await tracker.send_progress(session_id, "first", progress=10)
        await tracker.send_progress(session_id, "second", progress=40, status="info")
        snapshot = tracker.latest_progress(session_id)
        self.assertEqual(snapshot["message"], "second")
        self.assertEqual(snapshot["progress"], 40)
        self.assertIsNone(tracker.latest_progress("not-a-uuid"))

    async def test_newer_message_refreshes_pending_session_expiry(self):
        tracker = ProgressTracker(max_sessions=2, session_timeout=30)
        now = datetime.now()

        await tracker.send_progress("session", "old")
        await tracker.send_progress("session", "new")
        tracker.pending_messages["session"][0].timestamp = now - timedelta(minutes=5)
        tracker.pending_messages["session"][1].timestamp = now

        await tracker._cleanup_old_sessions()

        self.assertIn("session", tracker.pending_messages)

    async def test_zero_session_capacity_does_not_retain_pending_keys(self):
        tracker = ProgressTracker(max_sessions=0, session_timeout=30)

        sent = await tracker.send_progress("disconnected", "message")

        self.assertFalse(sent)
        self.assertEqual(tracker.pending_messages, {})


class RecordingWebSocket:
    def __init__(self):
        self.payloads = []

    async def send_json(self, payload):
        self.payloads.append(payload)


class ProgressConnectReplayTests(unittest.IsolatedAsyncioTestCase):
    async def test_connect_replays_pending_progress_instead_of_resetting_to_zero(self):
        tracker = ProgressTracker(max_sessions=2, session_timeout=3600)
        session_id = "11111111-1111-1111-1111-111111111111"
        await tracker.send_progress(session_id, "Indexing RAG corpus", progress=70)
        websocket = RecordingWebSocket()

        connected = await tracker.connect(session_id, websocket, "rag-build")

        self.assertTrue(connected)
        self.assertEqual(websocket.payloads[0]["status"], "info")
        self.assertEqual(websocket.payloads[0]["progress"], 70)
        self.assertEqual(websocket.payloads[-1]["progress"], 70)
        self.assertEqual(websocket.payloads[-1]["message"], "Indexing RAG corpus")
        self.assertTrue(all(payload.get("progress") != 0 for payload in websocket.payloads))


class ProgressWebsocketRouteTests(unittest.TestCase):
    def test_http_route_does_not_reset_connected_progress_to_zero(self):
        source = (Path(__file__).resolve().parents[1] / "config" / "main.py").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("Connected to progress tracker for session:", source)
        self.assertNotIn('"progress": 0,\n                    "status": "success"', source)


if __name__ == "__main__":
    unittest.main()
