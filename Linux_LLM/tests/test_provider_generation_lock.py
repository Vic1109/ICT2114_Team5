"""Provider admission regressions with fake clients; no inference or database."""

import sys
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

CONFIG_DIR = Path(__file__).resolve().parents[1] / "config"
if str(CONFIG_DIR) not in sys.path:
    sys.path.insert(0, str(CONFIG_DIR))

from llm_provider import LLMProviderController, ProviderBusyError, ProviderRequestError
from report import ReportGenerator


def _generator():
    local = SimpleNamespace(
        provider_id="local", prepare_generation=mock.Mock(return_value=True),
        availability_error=lambda: None, cancel_active_generations=mock.Mock(return_value=1),
        generate_response=mock.Mock(return_value="local report"),
    )
    public = SimpleNamespace(
        provider_id="anthropic", prepare_generation=mock.Mock(return_value=True),
        availability_error=lambda: None, cancel_active_generations=mock.Mock(return_value=0),
        generate_response=mock.Mock(return_value="public report"),
    )
    generator = ReportGenerator.__new__(ReportGenerator)
    generator._generation_lock = threading.Lock()
    generator._generation_state_lock = threading.RLock()
    generator._generation_reservation = None
    generator._generation_started = False
    generator._generation_client = None
    generator._generation_cancelled = False
    generator._providers = LLMProviderController(local, lambda: public)
    generator.llm_client = local
    generator.report_formatter = SimpleNamespace(llm_client=local)
    generator.report_formatter.generate_report_with_rag = mock.Mock(return_value="report")
    generator._update_report_metrics = mock.Mock()
    return generator, local, public


class ProviderGenerationLockTests(unittest.TestCase):
    def test_pending_work_pins_provider_before_executor_start(self):
        generator, local, public = _generator()
        token = generator.reserve_generation()
        self.assertTrue(generator.generation_active)
        with self.assertRaises(ProviderBusyError):
            generator.set_llm_provider("anthropic")
        self.assertIs(generator.llm_client, local)
        self.assertIs(generator.report_formatter.llm_client, local)
        generator.release_generation_reservation(token)
        self.assertEqual(generator.set_llm_provider("anthropic"), "anthropic")
        self.assertIs(generator.report_formatter.llm_client, public)

    def test_pending_timeout_prevents_later_billed_work(self):
        generator, local, _public = _generator()
        token = generator.reserve_generation()
        generator.cancel_active_generations(generation_reservation=token)
        with self.assertRaises(ProviderBusyError):
            generator.generate_report_with_rag([], generation_reservation=token)
        local.prepare_generation.assert_not_called()
        generator.report_formatter.generate_report_with_rag.assert_not_called()
        self.assertFalse(generator.generation_active)

    def test_stale_timeout_does_not_cancel_a_later_admission(self):
        generator, local, public = _generator()
        old = generator.reserve_generation()
        generator.release_generation_reservation(old)
        generator.set_llm_provider("anthropic")
        current = generator.reserve_generation()
        self.assertEqual(generator.cancel_active_generations(generation_reservation=old), 0)
        public.cancel_active_generations.assert_not_called()
        local.cancel_active_generations.assert_not_called()
        self.assertTrue(generator.generation_active)
        generator.release_generation_reservation(current)

    def test_both_model_passes_metadata_and_cancellation_use_one_client(self):
        generator, local, public = _generator()
        token = generator.reserve_generation()

        def format_report(*_args):
            self.assertFalse(generator.release_generation_reservation(token))
            first = generator.report_formatter.llm_client.generate_response("first pass")
            with self.assertRaises(ProviderBusyError):
                generator.set_llm_provider("anthropic")
            second = generator.report_formatter.llm_client.generate_response("repair pass")
            self.assertEqual(generator.provider_report_label(), "Local")
            return first + second

        generator.report_formatter.generate_report_with_rag.side_effect = format_report
        generator.generate_report_with_rag([], generation_reservation=token)
        self.assertEqual(local.generate_response.call_count, 2)
        public.generate_response.assert_not_called()
        self.assertFalse(generator.generation_active)

    def test_cancellation_during_prepare_cannot_be_cleared_by_client(self):
        generator, local, _public = _generator()
        token = generator.reserve_generation()

        def prepare():
            generator.cancel_active_generations(generation_reservation=token)
            # Mimic a client that clears its reusable cancellation event.
            return True

        local.prepare_generation.side_effect = prepare
        with self.assertRaisesRegex(ProviderRequestError, "cancelled"):
            generator.generate_report_with_rag([], generation_reservation=token)
        generator.report_formatter.generate_report_with_rag.assert_not_called()
        self.assertFalse(generator.generation_active)

    def test_prepare_failure_releases_gate(self):
        generator, local, _public = _generator()
        local.prepare_generation.side_effect = RuntimeError("prepare failed")
        with self.assertRaisesRegex(RuntimeError, "prepare failed"):
            generator.generate_report_with_rag([])
        self.assertFalse(generator.generation_active)
        self.assertEqual(generator.set_llm_provider("anthropic"), "anthropic")

    def test_cancelled_late_result_is_not_published(self):
        generator, _local, _public = _generator()
        token = generator.reserve_generation()

        def format_report(*_args):
            generator.cancel_active_generations(generation_reservation=token)
            return "report returned after cancellation"

        generator.report_formatter.generate_report_with_rag.side_effect = format_report
        with self.assertRaisesRegex(ProviderRequestError, "cancelled"):
            generator.generate_report_with_rag([], generation_reservation=token)
        self.assertFalse(generator.generation_active)
        self.assertFalse(generator._update_report_metrics.call_args.kwargs["success"])


if __name__ == "__main__":
    unittest.main()
