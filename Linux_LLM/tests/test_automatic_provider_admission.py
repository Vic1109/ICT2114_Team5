"""Offline automatic-report provider reservation and cancellation regressions."""

from __future__ import annotations

import asyncio
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


CONFIG_DIR = Path(__file__).resolve().parents[1] / "config"
if str(CONFIG_DIR) not in sys.path:
    sys.path.insert(0, str(CONFIG_DIR))

from live_monitoring import EnhancedLiveMonitoringService  # noqa: E402


class AutomaticProviderAdmissionTests(unittest.IsolatedAsyncioTestCase):
    def _service(self):
        token = object()
        generator = SimpleNamespace(
            reserve_generation=mock.Mock(return_value=token),
            release_generation_reservation=mock.Mock(),
            active_generation_timeout_seconds=mock.Mock(return_value=10),
            cancel_active_generations=mock.Mock(),
            clean_log_data=mock.Mock(side_effect=lambda alerts: alerts),
            generate_report_with_rag=mock.Mock(return_value="offline report"),
        )
        config = SimpleNamespace(
            llm=SimpleNamespace(timeout=10),
            paths=SimpleNamespace(reports_dir="unused-offline-reports"),
        )
        service = EnhancedLiveMonitoringService(config, generator, lambda: None)
        return service, generator, token

    async def test_reservation_precedes_deadline_and_worker_and_reaches_generation(self):
        service, generator, token = self._service()
        events = []

        def reserve():
            events.append("reserve")
            return token

        def deadline():
            events.append("deadline")
            generator.reserve_generation.assert_called_once()
            return 10

        async def run(function):
            events.append("worker")
            return function()

        generator.reserve_generation.side_effect = reserve
        generator.active_generation_timeout_seconds.side_effect = deadline
        service._run_blocking = mock.AsyncMock(side_effect=run)
        alerts = [{"rule_level": 12, "full_log": "offline evidence"}]
        with mock.patch("live_monitoring.atomic_write_text") as save:
            self.assertTrue(await service._execute_report_generation(alerts, alerts))
        self.assertEqual(events, ["reserve", "deadline", "worker"])
        generator.clean_log_data.assert_called_once_with(alerts)
        call = generator.generate_report_with_rag.call_args
        self.assertEqual(call.args, (alerts, "Monitored Wazuh source"))
        self.assertIs(call.kwargs["generation_reservation"], token)
        self.assertTrue(call.kwargs["is_automatic"])
        self.assertEqual(call.kwargs["trigger_info"]["triggered_alerts"], alerts)
        self.assertEqual(call.kwargs["trigger_info"]["critical_severity_count"], 1)
        generator.cancel_active_generations.assert_not_called()
        generator.release_generation_reservation.assert_called_once_with(token)
        save.assert_called_once()
        self.assertEqual(service.statistics["reports_generated"], 1)

    async def test_timeout_before_worker_start_cancels_only_its_reservation(self):
        service, generator, token = self._service()
        service._run_blocking = mock.AsyncMock(side_effect=asyncio.TimeoutError)
        with mock.patch("live_monitoring.atomic_write_text") as save:
            self.assertFalse(await service._execute_report_generation([], []))
        generator.generate_report_with_rag.assert_not_called()
        generator.cancel_active_generations.assert_called_once_with(
            permanent=False, generation_reservation=token,
        )
        generator.release_generation_reservation.assert_called_once_with(token)
        save.assert_not_called()
        self.assertEqual(service.statistics["errors"], 1)

    async def test_cancelled_waiter_cancels_only_its_reservation_and_propagates(self):
        service, generator, token = self._service()
        service._run_blocking = mock.AsyncMock(side_effect=asyncio.CancelledError)
        with mock.patch("live_monitoring.atomic_write_text") as save:
            with self.assertRaises(asyncio.CancelledError):
                await service._execute_report_generation([], [])
        generator.generate_report_with_rag.assert_not_called()
        generator.cancel_active_generations.assert_called_once_with(
            permanent=False, generation_reservation=token,
        )
        generator.release_generation_reservation.assert_called_once_with(token)
        save.assert_not_called()

    async def test_deadline_failure_releases_pending_admission(self):
        service, generator, token = self._service()
        generator.active_generation_timeout_seconds.side_effect = ValueError("invalid deadline")
        service._run_blocking = mock.AsyncMock()
        with mock.patch("live_monitoring.atomic_write_text") as save:
            self.assertFalse(await service._execute_report_generation([], []))
        service._run_blocking.assert_not_awaited()
        generator.release_generation_reservation.assert_called_once_with(token)
        generator.cancel_active_generations.assert_not_called()
        save.assert_not_called()

    async def test_cleaning_failure_releases_reservation_before_model_invocation(self):
        service, generator, token = self._service()
        generator.clean_log_data.side_effect = RuntimeError("offline cleaning failed")

        async def run(function):
            return function()

        service._run_blocking = mock.AsyncMock(side_effect=run)
        with mock.patch("live_monitoring.atomic_write_text") as save:
            self.assertFalse(await service._execute_report_generation([], []))
        generator.generate_report_with_rag.assert_not_called()
        generator.release_generation_reservation.assert_called_once_with(token)
        generator.cancel_active_generations.assert_not_called()
        save.assert_not_called()

    async def test_busy_admission_does_not_cancel_another_report(self):
        service, generator, _token = self._service()
        generator.reserve_generation.side_effect = RuntimeError("another report owns the provider")
        service._run_blocking = mock.AsyncMock()
        self.assertFalse(await service._execute_report_generation([], []))
        generator.active_generation_timeout_seconds.assert_not_called()
        service._run_blocking.assert_not_awaited()
        generator.cancel_active_generations.assert_not_called()
        generator.release_generation_reservation.assert_not_called()


if __name__ == "__main__":
    unittest.main()
