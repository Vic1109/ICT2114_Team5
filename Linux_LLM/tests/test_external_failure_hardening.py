"""Failure-path regressions for local model and SSH boundaries."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
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


class OptionalQwenArgProbeTests(unittest.TestCase):
    def _client(self, llama_cpp_path: str) -> LlamaModelClient:
        config = SimpleNamespace(
            model_type="qwen", disable_thinking=True, use_custom_template=False,
            llama_cpp_path=llama_cpp_path, timeout=1, debug_commands=False,
            get_llama_args=lambda **_kwargs: [],
        )
        templates = SimpleNamespace(
            format_user_message=lambda value: value,
            get_template_path=lambda: "",
            templates_dir=Path("."),
        )
        return LlamaModelClient(config, templates)

    def test_help_probe_disables_optional_args_when_flag_is_absent(self):
        with tempfile.NamedTemporaryFile(delete=False) as handle:
            binary = handle.name
        try:
            client = self._client(binary)
            with mock.patch("llm_client.subprocess.run") as run:
                run.return_value = SimpleNamespace(stdout="usage: llama-cli\n", stderr="")
                client._detect_optional_qwen_args_support()
            self.assertIs(client._optional_qwen_args_supported, False)
            self.assertEqual(run.call_args.args[0][:2], [binary, "--help"])
        finally:
            os.unlink(binary)

    def test_help_probe_keeps_optional_args_when_flag_is_present(self):
        with tempfile.NamedTemporaryFile(delete=False) as handle:
            binary = handle.name
        try:
            client = self._client(binary)
            with mock.patch("llm_client.subprocess.run") as run:
                run.return_value = SimpleNamespace(
                    stdout="--chat-template-kwargs JSON\n", stderr=""
                )
                client._detect_optional_qwen_args_support()
            self.assertIs(client._optional_qwen_args_supported, True)
        finally:
            os.unlink(binary)

    def test_known_unsupported_optional_args_do_not_spawn_twice(self):
        config = SimpleNamespace(
            model_type="qwen", disable_thinking=True, use_custom_template=False,
            llama_cpp_path="llama-cli", timeout=1, debug_commands=False,
            get_llama_args=lambda **_kwargs: [],
        )
        templates = SimpleNamespace(
            format_user_message=lambda value: value,
            get_template_path=lambda: "",
            templates_dir=Path("."),
        )
        client = LlamaModelClient(config, templates)
        client._optional_qwen_args_supported = False
        client._fit_prompt_to_context = lambda value: value
        with mock.patch.object(client, "_run_process", return_value=(0, "report", "")) as run:
            self.assertEqual(client.generate_response("alert"), "report")
        self.assertEqual(run.call_count, 1)


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


class ServerInferenceTests(unittest.TestCase):
    def _client(self, **overrides) -> LlamaModelClient:
        values = dict(
            model_type="qwen",
            disable_thinking=True,
            use_custom_template=False,
            llama_cpp_path="llama-cli",
            timeout=5,
            debug_commands=False,
            temperature=0.2,
            top_p=0.8,
            top_k=20,
            max_tokens=64,
            context_size=16384,
            prompt_safety_margin_tokens=512,
            prompt_chars_per_token=3.0,
            inference_backend="server",
            llama_server_url="http://127.0.0.1:8090",
            llama_server_autostart=False,
            gpu_layers=99,
            get_llama_args=lambda **_kwargs: [],
        )
        values.update(overrides)
        config = SimpleNamespace(**values)
        templates = SimpleNamespace(
            format_user_message=lambda value: value,
            get_template_path=lambda: "",
            templates_dir=Path("."),
        )
        client = LlamaModelClient(config, templates)
        client._fit_prompt_to_context = lambda value: value
        client._read_system_prompt = lambda: "SYS"
        return client

    def test_server_backend_does_not_spawn_llama_cli(self):
        client = self._client()
        payload = {
            "choices": [{"message": {"content": "# Executive Summary\nOK"}}],
            "timings": {
                "prompt_n": 10,
                "prompt_per_second": 400.0,
                "predicted_n": 4,
                "predicted_per_second": 40.0,
            },
        }
        with mock.patch.object(client, "_ensure_server", return_value=True), mock.patch.object(
            client, "_http_json", return_value=payload
        ) as http, mock.patch.object(client, "_run_process") as run:
            response = client.generate_response("alert body")
        run.assert_not_called()
        http.assert_called_once()
        self.assertIn("Executive Summary", response)
        method, path, body = http.call_args.args[:3]
        self.assertEqual(method, "POST")
        self.assertEqual(path, "/v1/chat/completions")
        self.assertEqual(body["messages"][0]["role"], "system")
        self.assertTrue(body["cache_prompt"])

    def test_cli_backend_ignores_server_url(self):
        client = self._client(inference_backend="cli")
        with mock.patch.object(client, "_run_process", return_value=(0, "report", "")) as run, mock.patch.object(
            client, "_http_json"
        ) as http:
            self.assertEqual(client.generate_response("alert"), "report")
        run.assert_called_once()
        http.assert_not_called()

    def test_budget_log_omits_prompt_text(self):
        client = self._client()
        secret = "SECRET-ALERT-xyz"
        payload = {"choices": [{"message": {"content": "ok"}}]}
        with mock.patch.object(client, "_ensure_server", return_value=True), mock.patch.object(
            client, "_http_json", return_value=payload
        ), self.assertLogs("LlamaModelClient", level="INFO") as captured:
            client.generate_response(secret)
        combined = "\n".join(captured.output)
        self.assertNotIn(secret, combined)
        self.assertIn("Model context limit", combined)
        self.assertIn("Reserved output budget", combined)

    def test_http_error_does_not_log_response_body(self):
        client = self._client()
        secret = "private-server-body"
        with mock.patch.object(client, "_ensure_server", return_value=True), mock.patch.object(
            client, "_http_json", side_effect=RuntimeError(secret)
        ), self.assertLogs("LlamaModelClient", level="ERROR") as captured:
            response = client.generate_response("current private alert")
        combined = "\n".join(captured.output) + response
        self.assertNotIn(secret, combined)
        self.assertNotIn("current private alert", combined)
        self.assertEqual(response, "Error: Local model command failed.")


if __name__ == "__main__":
    unittest.main()
