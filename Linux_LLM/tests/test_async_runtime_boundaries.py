"""Regressions for event-loop and shared report-resource boundaries."""

from __future__ import annotations

import asyncio
import sys
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from fastapi import HTTPException

CONFIG_DIR = Path(__file__).resolve().parents[1] / "config"
if str(CONFIG_DIR) not in sys.path:
    sys.path.insert(0, str(CONFIG_DIR))

from live_monitoring import EnhancedLiveMonitoringService, PersistentSSHConnection  # noqa: E402
from main import SOCApplication  # noqa: E402
from report import ReportGenerator  # noqa: E402


class PersistentSSHAsyncTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.executor = ThreadPoolExecutor(max_workers=2)

    async def asyncTearDown(self):
        await asyncio.to_thread(self.executor.shutdown, wait=True, cancel_futures=True)

    async def test_reads_are_off_loop_and_serialized_with_reconnect(self):
        state = {"active": 0, "max_active": 0, "factory_calls": 0}
        state_lock = threading.Lock()

        class Reader:
            def __init__(self):
                self.is_connected = False

            def connect(self):
                time.sleep(0.03)
                self.is_connected = True
                return True

            def read_alerts(self, _max_lines):
                with state_lock:
                    state["active"] += 1
                    state["max_active"] = max(state["max_active"], state["active"])
                try:
                    time.sleep(0.08)
                    return [{"rule": {"id": "1"}}]
                finally:
                    with state_lock:
                        state["active"] -= 1

            def disconnect(self):
                self.is_connected = False

        def factory():
            state["factory_calls"] += 1
            return Reader()

        connection = PersistentSSHConnection(factory, executor=self.executor)
        first = asyncio.create_task(connection.read_alerts(10))
        second = asyncio.create_task(connection.read_alerts(10))
        heartbeat = asyncio.Event()

        async def tick():
            await asyncio.sleep(0.01)
            heartbeat.set()

        await asyncio.wait_for(tick(), timeout=0.05)
        self.assertTrue(heartbeat.is_set())
        results = await asyncio.gather(first, second)
        self.assertEqual([len(result) for result in results], [1, 1])
        self.assertEqual(state["max_active"], 1)
        self.assertEqual(state["factory_calls"], 1)
        await connection.disconnect_async()

    async def test_disconnect_teardown_bypasses_saturated_worker_admission(self):
        admission = threading.BoundedSemaphore(1)
        self.assertTrue(admission.acquire(blocking=False))
        reader = SimpleNamespace(disconnect=mock.Mock())
        connection = PersistentSSHConnection(
            lambda: reader,
            executor=self.executor,
            worker_admission=admission,
        )
        connection.ssh_reader = reader
        try:
            await asyncio.wait_for(connection.disconnect_async(), timeout=1.0)
        finally:
            admission.release()

        reader.disconnect.assert_called_once()
        self.assertIsNone(connection.ssh_reader)

    async def test_application_worker_admission_stays_held_after_waiter_cancellation(self):
        app = SOCApplication.__new__(SOCApplication)
        app._executor = self.executor
        app._worker_admission = threading.BoundedSemaphore(1)
        entered = threading.Event()
        release = threading.Event()

        def blocking_work():
            entered.set()
            release.wait(2)
            return "done"

        first = asyncio.create_task(app._run_blocking(blocking_work))
        for _ in range(100):
            if entered.is_set():
                break
            await asyncio.sleep(0.005)
        self.assertTrue(entered.is_set())

        with self.assertRaises(HTTPException) as busy:
            await app._run_blocking(lambda: None)
        self.assertEqual(busy.exception.status_code, 503)

        first.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await first
        with self.assertRaises(HTTPException):
            await app._run_blocking(lambda: None)

        release.set()
        result = None
        for _ in range(100):
            await asyncio.sleep(0.005)
            try:
                result = await app._run_blocking(lambda: "available")
            except HTTPException:
                continue
            break
        self.assertEqual(result, "available")

    async def test_system_preflight_collection_runs_off_the_event_loop(self):
        app = SOCApplication.__new__(SOCApplication)
        app._executor = self.executor
        app._worker_admission = threading.BoundedSemaphore(2)
        app.config = SimpleNamespace()

        def slow_environment():
            time.sleep(0.06)
            return True, []

        with mock.patch("main.validate_environment", side_effect=slow_environment), mock.patch(
            "main.build_preflight_report", return_value={"ready": True}
        ):
            work = asyncio.create_task(app._run_blocking(app._collect_system_checks, {}))
            await asyncio.wait_for(asyncio.sleep(0.01), timeout=0.03)
            self.assertFalse(work.done())
            result = await work
        self.assertEqual(result, (True, [], {"ready": True}))

    async def test_live_alert_normalization_runs_off_the_event_loop(self):
        def clean(alerts):
            time.sleep(0.06)
            return alerts

        generator = SimpleNamespace(rag_ready=True, clean_log_data=clean)
        service = EnhancedLiveMonitoringService(
            SimpleNamespace(),
            generator,
            lambda: None,
            executor=self.executor,
            worker_admission=threading.BoundedSemaphore(2),
        )
        service.persistent_ssh.read_alerts = mock.AsyncMock(
            return_value=[{"rule_level": 1, "timestamp": "2026-07-10T00:00:00Z"}]
        )
        service._detect_high_severity_alerts_enhanced = lambda *_args: []

        work = asyncio.create_task(service._poll_alerts_enhanced())
        await asyncio.wait_for(asyncio.sleep(0.01), timeout=0.03)
        self.assertFalse(work.done())
        await work
        self.assertIsNotNone(service.last_snapshot)

    async def test_shutdown_drain_awaits_admitted_workflow_commit_boundary(self):
        app = SOCApplication.__new__(SOCApplication)
        completed = asyncio.Event()

        async def workflow():
            await asyncio.sleep(0.02)
            completed.set()

        task = asyncio.create_task(workflow())
        app._background_tasks = {task}
        await app._drain_background_tasks()
        self.assertTrue(completed.is_set())
        self.assertFalse(task.cancelled())

    async def test_runtime_shutdown_runs_all_cleanup_steps_after_failures(self):
        app = SOCApplication.__new__(SOCApplication)
        app._shutting_down = False
        app.progress_tracker = SimpleNamespace(
            stop_cleanup_task=mock.AsyncMock(side_effect=RuntimeError("cleanup failed"))
        )
        app.report_generator = SimpleNamespace(
            cancel_active_generations=mock.Mock(),
            close=mock.Mock(),
        )
        app.live_monitoring = SimpleNamespace(
            shutdown=mock.AsyncMock(
                side_effect=[RuntimeError("monitoring stop failed"), None]
            )
        )
        app._drain_background_tasks = mock.AsyncMock()
        app._executor = SimpleNamespace(shutdown=mock.Mock())

        with mock.patch("main.log_sanitized_exception"), self.assertRaisesRegex(
            RuntimeError, "cleanup failed"
        ):
            await app._shutdown_runtime()

        self.assertTrue(app._shutting_down)
        self.assertEqual(app.live_monitoring.shutdown.await_count, 2)
        app._drain_background_tasks.assert_awaited_once()
        app._executor.shutdown.assert_called_once_with(
            wait=True,
            cancel_futures=True,
        )
        app.report_generator.close.assert_called_once()

    async def test_monitoring_cannot_restart_after_shutdown_begins(self):
        service = EnhancedLiveMonitoringService(
            SimpleNamespace(),
            SimpleNamespace(rag_ready=True),
            lambda: None,
            executor=self.executor,
            worker_admission=threading.BoundedSemaphore(2),
        )
        service.persistent_ssh.disconnect_async = mock.AsyncMock()

        await service.shutdown()

        self.assertFalse(service.start_monitoring())
        self.assertIsNone(service.monitoring_task)


class SharedGenerationGateTests(unittest.TestCase):
    def test_report_generator_rejects_concurrent_llama_work(self):
        entered = threading.Event()
        release = threading.Event()
        generator = ReportGenerator.__new__(ReportGenerator)
        generator._generation_lock = threading.Lock()
        generator.llm_client = SimpleNamespace(prepare_generation=lambda: True)
        generator.report_formatter = SimpleNamespace(
            generate_report_with_rag=lambda *_args, **_kwargs: (
                entered.set(), release.wait(2), "report"
            )[-1]
        )
        generator._update_report_metrics = mock.Mock()

        first_result = []

        def run_first():
            first_result.append(generator.generate_report_with_rag([]))

        thread = threading.Thread(target=run_first)
        thread.start()
        self.assertTrue(entered.wait(1))
        with self.assertRaises(RuntimeError):
            generator.generate_report_with_rag([])
        release.set()
        thread.join(2)
        self.assertEqual(first_result, ["report"])
        self.assertFalse(generator.generation_active)


if __name__ == "__main__":
    unittest.main()
