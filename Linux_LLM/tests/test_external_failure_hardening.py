"""Failure-path regressions for local model and SSH boundaries."""

from __future__ import annotations

import subprocess
import sys
import time
import unittest
from types import SimpleNamespace
from unittest import mock

from pathlib import Path


CONFIG_DIR = Path(__file__).resolve().parents[1] / "config"
if str(CONFIG_DIR) not in sys.path:
    sys.path.insert(0, str(CONFIG_DIR))

from llm_client import LlamaModelClient  # noqa: E402
from ssh import ArchiveReadLimitError, AlertsReader, ArchiveReader, SSHConnectionManager  # noqa: E402


class ModelProcessTests(unittest.TestCase):
    def test_timeout_kills_and_reaps_local_process(self):
        client = LlamaModelClient(
            SimpleNamespace(),
            SimpleNamespace(),
        )
        started = time.monotonic()
        with self.assertRaises(subprocess.TimeoutExpired):
            client._run_process(
                [sys.executable, "-c", "import time; time.sleep(30)"],
                timeout=0.05,
            )
        self.assertLess(time.monotonic() - started, 2.0)

    def test_cancel_active_generations_kills_registered_processes(self):
        client = LlamaModelClient(SimpleNamespace(), SimpleNamespace())
        process = mock.Mock()
        client._active_processes.add(process)
        with mock.patch.object(client, "_kill_and_reap") as kill:
            self.assertEqual(client.cancel_active_generations(permanent=True), 1)
        kill.assert_called_once_with(process)
        self.assertTrue(client._shutdown_requested)

    def test_cancellation_before_process_start_is_not_cleared_by_client(self):
        config = SimpleNamespace(
            model_type="qwen", disable_thinking=False, use_custom_template=False,
            llama_cpp_path="llama-cli", timeout=1, debug_commands=False,
            get_llama_args=lambda **_kwargs: [],
        )
        templates = SimpleNamespace(
            format_user_message=lambda value: value,
            get_template_path=lambda: "",
            templates_dir=Path("."),
        )
        client = LlamaModelClient(config, templates)
        client.cancel_active_generations(permanent=False)
        with mock.patch.object(client, "_run_process") as run:
            response = client.generate_response("alert")
        run.assert_not_called()
        self.assertIn("cancelled", response)
        self.assertTrue(client.prepare_generation())

    def test_compatibility_retry_shares_one_total_timeout_budget(self):
        config = SimpleNamespace(
            model_type="qwen", disable_thinking=True, use_custom_template=False,
            llama_cpp_path="llama-cli", timeout=0.08, debug_commands=False,
            get_llama_args=lambda **_kwargs: [],
        )
        templates = SimpleNamespace(
            format_user_message=lambda value: value,
            get_template_path=lambda: "",
            templates_dir=Path("."),
        )
        client = LlamaModelClient(config, templates)
        client._fit_prompt_to_context = lambda value: value
        observed_timeouts = []

        def execute(_cmd, timeout):
            observed_timeouts.append(timeout)
            if len(observed_timeouts) == 1:
                time.sleep(0.03)
                return 2, "", "unknown argument: chat-template-kwargs"
            return 0, "report", ""

        with mock.patch.object(client, "_run_process", side_effect=execute):
            self.assertEqual(client.generate_response("alert"), "report")
        self.assertEqual(len(observed_timeouts), 2)
        self.assertLess(observed_timeouts[1], observed_timeouts[0])

    def test_model_failure_does_not_return_or_log_stderr_content(self):
        private_text = "private-host.example secret prompt fragment"
        config = SimpleNamespace(
            model_type="qwen", disable_thinking=False, use_custom_template=False,
            llama_cpp_path="llama-cli", timeout=1, debug_commands=False,
            get_llama_args=lambda **_kwargs: [],
        )
        templates = SimpleNamespace(
            format_user_message=lambda value: value,
            get_template_path=lambda: "",
            templates_dir=Path("."),
        )
        client = LlamaModelClient(config, templates)
        client._fit_prompt_to_context = lambda value: value
        with mock.patch.object(client, "_run_process", return_value=(2, "", private_text)), self.assertLogs(
            "LlamaModelClient", level="ERROR"
        ) as captured:
            response = client.generate_response("current private alert")
        combined = "\n".join(captured.output) + response
        self.assertNotIn(private_text, combined)
        self.assertNotIn("current private alert", combined)
        self.assertEqual(response, "Error: Local model command failed.")


class SSHLifecycleTests(unittest.TestCase):
    def test_partial_connection_failure_closes_ssh_client(self):
        class FakeClient:
            def __init__(self):
                self.closed = False

            def load_system_host_keys(self):
                pass

            def set_missing_host_key_policy(self, _policy):
                pass

            def connect(self, *_args, **_kwargs):
                pass

            def open_sftp(self):
                raise RuntimeError("sftp unavailable")

            def close(self):
                self.closed = True

        client = FakeClient()
        manager = SSHConnectionManager("host", "user", "password")
        with mock.patch("ssh.paramiko.SSHClient", return_value=client):
            self.assertFalse(manager.connect())
        self.assertTrue(client.closed)
        self.assertFalse(manager.is_connected)

    def test_alert_reader_clamps_caller_to_configured_maximum(self):
        commands = []

        class Stream(list):
            def __init__(self, values=()):
                super().__init__(values)
                self.channel = SimpleNamespace(settimeout=lambda _timeout: None)

            def close(self):
                pass

        connection = SimpleNamespace(
            is_connected=True,
            timeout=3,
            sftp=SimpleNamespace(stat=lambda _path: SimpleNamespace(st_size=1)),
            ssh=SimpleNamespace(
                exec_command=lambda command, **_kwargs: (
                    commands.append(command) or Stream(),
                    Stream(['{"rule": {"id": "1"}}\n']),
                    Stream(),
                )
            ),
        )
        reader = AlertsReader(connection, "/remote/alerts.json", default_max_lines=5)
        self.assertEqual(len(reader.read_alerts(1000)), 1)
        self.assertIn("tail -n 5", commands[0])

    def test_alert_reader_uses_bounded_readline(self):
        requested_sizes = []

        class Stream:
            def __init__(self, oversized=False):
                self.channel = SimpleNamespace(settimeout=lambda _timeout: None)
                self.oversized = oversized
                self.sent = False

            def readline(self, size=-1):
                requested_sizes.append(size)
                if self.sent or not self.oversized:
                    return ""
                self.sent = True
                return "x" * size

            def close(self):
                pass

        connection = SimpleNamespace(
            is_connected=True,
            timeout=3,
            sftp=SimpleNamespace(stat=lambda _path: SimpleNamespace(st_size=1)),
            ssh=SimpleNamespace(
                exec_command=lambda *_args, **_kwargs: (
                    Stream(),
                    Stream(oversized=True),
                    Stream(),
                )
            ),
        )
        reader = AlertsReader(
            connection,
            "/remote/alerts.json",
            default_max_lines=5,
            max_line_bytes=8,
        )
        with self.assertRaises(ArchiveReadLimitError):
            reader.read_alerts()
        self.assertEqual(requested_sizes[0], 9)

    def test_alert_reader_enforces_a_total_byte_budget(self):
        class Stream:
            def __init__(self, lines=()):
                self.channel = SimpleNamespace(settimeout=lambda _timeout: None)
                self.lines = iter(lines)

            def readline(self, _size=-1):
                return next(self.lines, "")

            def close(self):
                pass

        connection = SimpleNamespace(
            is_connected=True,
            timeout=3,
            sftp=SimpleNamespace(stat=lambda _path: SimpleNamespace(st_size=16)),
            ssh=SimpleNamespace(
                exec_command=lambda *_args, **_kwargs: (
                    Stream(),
                    Stream(['{"a":1}\n', '{"b":2}\n']),
                    Stream(),
                )
            ),
        )
        reader = AlertsReader(
            connection,
            "/remote/alerts.json",
            default_max_lines=5,
            max_total_bytes=10,
            max_line_bytes=32,
        )

        with self.assertRaisesRegex(ArchiveReadLimitError, "byte limit"):
            reader.read_alerts()

    def test_archive_day_limit_fails_before_remote_io(self):
        reader = ArchiveReader(SimpleNamespace(is_connected=False), "/remote", max_archive_days=7)
        with self.assertRaises(ValueError):
            reader.get_smart_archive_dates(8)


if __name__ == "__main__":
    unittest.main()
