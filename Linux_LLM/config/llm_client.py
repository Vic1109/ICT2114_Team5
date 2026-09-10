import json
import os
import re
import hashlib
import logging
import signal
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

from jinja2 import Template

import prompt_safety
from runtime_utils import log_sanitized_exception


LOGGER = logging.getLogger(__name__)


class PromptBudgetError(RuntimeError):
    """The prompt cannot be made to fit the configured llama.cpp context window.

    Instances only ever carry token counts, never prompt or alert content, so
    the message is safe to surface in an API response or a log line.
    """


class ChatTemplateManager:
    """Load and apply the chat template used by llama.cpp."""

    def __init__(self, templates_dir: str, llm_config):
        self.templates_dir = Path(templates_dir)
        self.config = llm_config
        self.chat_template = self._load_chat_template()

    def _load_chat_template(self) -> str:
        template_path = self.templates_dir / self.config.chat_template_file

        if template_path.exists():
            try:
                with open(template_path, "r", encoding="utf-8") as f:
                    template_content = f.read()
                LOGGER.info("Loaded configured chat template")
                return template_content
            except Exception as e:
                LOGGER.warning(
                    "Unable to load configured chat template (%s)",
                    type(e).__name__,
                )
                if getattr(self.config, "debug_commands", False):
                    LOGGER.debug("Chat template loading detail", exc_info=True)
        else:
            LOGGER.warning("Configured chat template was not found")
        return ""

    def format_user_message(self, user_message: str) -> str:
        """Format a user message when llama.cpp is not applying Jinja itself."""
        if self.config.use_jinja:
            return user_message

        if self.chat_template and self.config.use_custom_template:
            try:
                template = Template(self.chat_template)
                messages = [{"role": "user", "content": user_message}]
                return template.render(messages=messages, add_generation_prompt=True)
            except Exception as e:
                LOGGER.warning(
                    "Chat template formatting failed (%s)",
                    type(e).__name__,
                )
                if getattr(self.config, "debug_commands", False):
                    LOGGER.debug("Chat template formatting detail", exc_info=True)

        return user_message

    def get_template_path(self) -> str:
        return str(self.templates_dir / self.config.chat_template_file)


class LlamaModelClient:
    """Run local LLM inference through llama.cpp."""

    def __init__(self, llm_config, template_manager: ChatTemplateManager):
        self.config = llm_config
        self.template_manager = template_manager
        self._optional_qwen_args_supported = None
        self.logger = logging.getLogger("LlamaModelClient")
        self._process_lock = threading.RLock()
        self._active_processes = set()
        self._active_http = []
        self._cancel_generation = threading.Event()
        self._shutdown_requested = False
        self._server_process = None
        self._server_owned = False
        self._server_ready = False

    def _read_system_prompt(self) -> str:
        filename = str(getattr(self.config, "system_prompt_file", "cti.txt") or "cti.txt")
        templates_dir = getattr(self.template_manager, "templates_dir", None)
        if templates_dir is None:
            return ""
        system_prompt_path = Path(templates_dir) / filename
        try:
            if system_prompt_path.exists():
                return system_prompt_path.read_text(encoding="utf-8")
        except Exception as e:
            self.logger.warning(
                "Unable to read the system prompt for prompt budgeting (%s)",
                type(e).__name__,
            )
            if getattr(self.config, "debug_commands", False):
                self.logger.debug("System prompt read detail", exc_info=True)
        return ""

    # A prompt smaller than this cannot carry the alert evidence plus the output
    # contract, so producing one is a configuration error rather than a fallback.
    MIN_VIABLE_PROMPT_TOKENS = 512

    @staticmethod
    def _estimate_tokens(text: str, chars_per_token: float = 3.0) -> int:
        """Conservative character-based token estimate for preflight budgeting.

        llama.cpp gives us no way to count tokens without loading the model, so
        the budget is enforced against a deliberately pessimistic estimate and
        the configured safety margin absorbs the residual error.
        """
        text = str(text or "")
        if not text:
            return 0
        try:
            divisor = float(chars_per_token)
        except (TypeError, ValueError):
            divisor = 3.0
        if divisor <= 0:
            divisor = 3.0
        return max(1, int(len(text) / divisor))

    def _chars_per_token(self) -> float:
        try:
            value = float(getattr(self.config, "prompt_chars_per_token", 3.0))
        except (TypeError, ValueError):
            return 3.0
        return value if value > 0 else 3.0

    def _reserved_output_tokens(self) -> int:
        """Tokens that must stay free for generation.

        Prefers ``LLMConfig.reserved_output_tokens`` but stays usable with the
        lightweight config stubs the tests build.
        """
        reserved = getattr(self.config, "reserved_output_tokens", None)
        if isinstance(reserved, int) and reserved > 0:
            return reserved

        try:
            max_tokens = int(getattr(self.config, "max_tokens", 0) or 0)
        except (TypeError, ValueError):
            max_tokens = 0
        if max_tokens > 0:
            return max_tokens

        # -1 (infinity) and -2 (fill the context) have no explicit budget.
        try:
            fallback = int(getattr(self.config, "prompt_unbounded_output_reserve_tokens", 2048) or 2048)
        except (TypeError, ValueError):
            fallback = 2048
        return max(1, fallback)

    def _compute_prompt_budget(self, prompt: str = "", system_prompt: str = None) -> dict:
        """Resolve the context budget for a prompt.

        Enforces
        ``context_size >= system_tokens + prompt_tokens + reserved_output + margin``
        by deriving how many prompt tokens the remaining three terms leave free.
        """
        chars_per_token = self._chars_per_token()
        try:
            context_size = int(getattr(self.config, "context_size", 16384) or 16384)
        except (TypeError, ValueError):
            context_size = 16384
        context_size = max(1024, context_size)

        try:
            safety_margin_tokens = int(getattr(self.config, "prompt_safety_margin_tokens", 512) or 0)
        except (TypeError, ValueError):
            safety_margin_tokens = 512
        safety_margin_tokens = max(0, safety_margin_tokens)

        if system_prompt is None:
            system_prompt = self._read_system_prompt()
        system_tokens = self._estimate_tokens(system_prompt, chars_per_token)
        reserved_output_tokens = self._reserved_output_tokens()
        prompt_tokens = self._estimate_tokens(prompt, chars_per_token)

        available_prompt_tokens = (
            context_size - system_tokens - reserved_output_tokens - safety_margin_tokens
        )

        roles = self._prompt_token_roles(prompt, chars_per_token)
        return {
            "context_size": context_size,
            "system_tokens": system_tokens,
            "prompt_tokens": prompt_tokens,
            "alert_evidence_tokens": roles["alert_evidence_tokens"],
            "retrieved_cti_tokens": roles["retrieved_cti_tokens"],
            "formatting_tokens": roles["formatting_tokens"],
            "reserved_output_tokens": reserved_output_tokens,
            "safety_margin_tokens": safety_margin_tokens,
            "available_prompt_tokens": available_prompt_tokens,
            "available_prompt_chars": max(0, int(available_prompt_tokens * chars_per_token)),
            "chars_per_token": chars_per_token,
        }

    _ALERT_BUDGET_SECTIONS = {
        "ANALYSIS TYPE",
        "CURRENT ALERTS DATA",
        "CURRENT HIGH-SEVERITY INCIDENT DATA",
        "CURRENT ALERT — AUTHORITATIVE OBSERVATIONS",
        "CURRENT ALERT — EXPLICIT / INFERRED MITRE EVIDENCE",
        "CANONICAL INCIDENT SYNTHESIS — ORGANIZE THE REPORT AROUND THIS OBJECT",
        "REPRESENTATIVE CURRENT ALERTS",
        "HIGH-SEVERITY ALERTS",
        "CONFIGURED ASSET INVENTORY",
    }
    _CTI_BUDGET_SECTIONS = {
        "HISTORICAL AND CUSTOM REFERENCE CONTEXT",
        "RAG REFERENCE CONTEXT",
        "RETRIEVED HISTORICAL CTI — SOURCE-BOUND EXCERPTS",
        "COMPLEMENTARY PASSAGES FROM THE ALREADY-SELECTED TOP DOCUMENT",
    }

    def _prompt_token_roles(self, prompt: str, chars_per_token: float) -> dict:
        """Split a fitted prompt into alert vs retrieved-CTI vs formatting counts."""
        sections = self._split_marked_sections(prompt)
        if not sections:
            prompt_tokens = self._estimate_tokens(prompt, chars_per_token)
            return {
                "alert_evidence_tokens": prompt_tokens,
                "retrieved_cti_tokens": 0,
                "formatting_tokens": 0,
            }
        alert = 0
        retrieved = 0
        formatting = 0
        for name, body in sections:
            tokens = self._estimate_tokens(body, chars_per_token)
            canonical = self._canonical_section_name(
                name,
                list(self._ALERT_BUDGET_SECTIONS | self._CTI_BUDGET_SECTIONS)
                + ["ATTRIBUTION POLICY", "OUTPUT CONTRACT", "INSTRUCTIONS", "CONTEXT", "CONFLICTS / LIMITATIONS"],
            )
            if canonical in self._ALERT_BUDGET_SECTIONS:
                alert += tokens
            elif canonical in self._CTI_BUDGET_SECTIONS:
                retrieved += tokens
            else:
                formatting += tokens
        return {
            "alert_evidence_tokens": alert,
            "retrieved_cti_tokens": retrieved,
            "formatting_tokens": formatting,
        }

    @staticmethod
    def _describe_budget(budget: dict) -> str:
        """Render a budget as counts only, so no prompt content can leak."""
        total = (
            int(budget.get("system_tokens") or 0)
            + int(budget.get("prompt_tokens") or 0)
            + int(budget.get("reserved_output_tokens") or 0)
            + int(budget.get("safety_margin_tokens") or 0)
        )
        return (
            "Model context limit: {context_size} tokens; "
            "Reserved output budget: {reserved_output_tokens} tokens; "
            "System/prompt overhead: {system_tokens} tokens; "
            "Alert/evidence tokens: {alert_evidence_tokens} tokens; "
            "Retrieved CTI tokens: {retrieved_cti_tokens} tokens; "
            "Formatting tokens: {formatting_tokens} tokens; "
            "Safety margin: {safety_margin_tokens} tokens; "
            "Total input + output + margin: {total} tokens "
            "(context_size={context_size}, system={system_tokens}, "
            "prompt={prompt_tokens}, reserved_output={reserved_output_tokens}, "
            "margin={safety_margin_tokens}, available_prompt={available_prompt_tokens})"
        ).format(total=total, **{**{
            "alert_evidence_tokens": 0,
            "retrieved_cti_tokens": 0,
            "formatting_tokens": 0,
        }, **budget})

    def _log_token_budget(self, budget: dict) -> None:
        """Log the preflight budget. Counts only; never prompt or telemetry text."""
        self.logger.info("Token budget: %s", self._describe_budget(budget))
        print(f"token_budget {self._describe_budget(budget)}", flush=True)

    def _assert_prompt_fits(self, prompt: str, system_prompt: str = None) -> dict:
        """Fail loudly before llama.cpp silently drops the head of the prompt."""
        budget = self._compute_prompt_budget(prompt, system_prompt=system_prompt)
        total = (
            budget["system_tokens"]
            + budget["prompt_tokens"]
            + budget["reserved_output_tokens"]
            + budget["safety_margin_tokens"]
        )
        if total > budget["context_size"] or budget["prompt_tokens"] > budget["available_prompt_tokens"]:
            raise PromptBudgetError(
                "Prompt exceeds the llama.cpp context budget after compaction "
                f"({self._describe_budget(budget)}, total={total})"
            )
        return budget

    def _fit_prompt_to_context(self, prompt: str) -> str:
        prompt = str(prompt or "")
        system_prompt = self._read_system_prompt()
        budget = self._compute_prompt_budget(prompt, system_prompt=system_prompt)
        available_prompt_tokens = budget["available_prompt_tokens"]

        if available_prompt_tokens < self.MIN_VIABLE_PROMPT_TOKENS:
            raise PromptBudgetError(
                "Configured context window is too small for a usable prompt: it "
                f"leaves {available_prompt_tokens} prompt tokens, below the "
                f"{self.MIN_VIABLE_PROMPT_TOKENS} token minimum "
                f"({self._describe_budget(budget)}). Increase context_size or "
                "reduce max_tokens/prompt_safety_margin_tokens."
            )

        if budget["prompt_tokens"] <= available_prompt_tokens:
            return prompt

        max_prompt_chars = budget["available_prompt_chars"]
        compacted = self._section_aware_compact(prompt, max_prompt_chars)

        # _section_aware_compact is best effort: a single oversized section or a
        # prompt with no recognised sections can still exceed the budget, so the
        # cap is enforced here unconditionally.
        if len(compacted) > max_prompt_chars:
            compacted = compacted[:max_prompt_chars].rstrip()

        self.logger.warning(
            "Prompt compacted before llama.cpp execution (estimated tokens: %s)",
            self._describe_budget(budget),
        )
        self._assert_prompt_fits(compacted, system_prompt=system_prompt)
        return compacted

    def _configured_backend(self) -> str:
        value = str(getattr(self.config, "inference_backend", "auto") or "auto").strip().lower()
        if value in {"auto", "cli", "server"}:
            return value
        return "auto"

    def _llama_server_binary(self) -> str:
        resolver = getattr(self.config, "resolved_llama_server_path", None)
        if callable(resolver):
            path = resolver()
            if path:
                return str(path)
        explicit = str(getattr(self.config, "llama_server_path", "") or "").strip()
        if explicit:
            return explicit
        cli_path = Path(str(getattr(self.config, "llama_cpp_path", "") or ""))
        if not cli_path.name:
            return ""
        sibling = cli_path.with_name("llama-server")
        return str(sibling) if sibling.is_file() else ""

    def _uses_server(self) -> bool:
        backend = self._configured_backend()
        if backend == "cli":
            return False
        if backend == "server":
            return True
        if str(getattr(self.config, "llama_server_url", "") or "").strip():
            return True
        if int(getattr(self.config, "gpu_layers", 0) or 0) == 0:
            return False
        return bool(self._llama_server_binary())

    def _server_base_url(self) -> str:
        explicit = str(getattr(self.config, "llama_server_url", "") or "").strip().rstrip("/")
        if explicit:
            return explicit
        host = str(getattr(self.config, "llama_server_host", "127.0.0.1") or "127.0.0.1").strip()
        try:
            port = int(getattr(self.config, "llama_server_port", 8090) or 8090)
        except (TypeError, ValueError):
            port = 8090
        return f"http://{host}:{port}"

    def generate_response(self, user_message: str) -> str:
        temp_file_path = None
        try:
            with self._process_lock:
                if self._shutdown_requested:
                    return "Error: Local model generation is shutting down."
                if self._cancel_generation.is_set():
                    return "Error: Local model generation was cancelled."
            generation_deadline = time.monotonic() + max(
                0.001,
                float(self.config.timeout),
            )
            controlled_user_message = self._apply_model_control_tokens(user_message)
            formatted_prompt = self.template_manager.format_user_message(controlled_user_message)
            try:
                formatted_prompt = self._fit_prompt_to_context(formatted_prompt)
            except PromptBudgetError as budget_error:
                # The message is built from token counts only, so it is safe to
                # log and to return to the caller.
                self.logger.error("Prompt budget violation: %s", budget_error)
                return f"Error: {budget_error}"

            self._log_token_budget(self._compute_prompt_budget(formatted_prompt))

            if self._uses_server():
                return self._generate_via_server(formatted_prompt, generation_deadline)

            return self._generate_via_cli(formatted_prompt, generation_deadline)
        except Exception as e:
            log_sanitized_exception("Local model generation failed", e, logger=self.logger)
            if getattr(self.config, "debug_commands", False):
                self.logger.debug("Local model failure detail", exc_info=True)
            return "Error: Local model generation failed."
        finally:
            if temp_file_path:
                self._remove_temp_file(temp_file_path)

    def _generate_via_cli(self, formatted_prompt: str, generation_deadline: float) -> str:
        temp_file_path = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                suffix=".txt",
                delete=False,
                encoding="utf-8"
            ) as temp_file:
                temp_file.write(formatted_prompt)
                temp_file_path = temp_file.name

            template_path = (
                self.template_manager.get_template_path()
                if self.config.use_custom_template
                else None
            )

            self._detect_optional_qwen_args_support()
            optional_attempts = [self._optional_qwen_args_supported is not False]
            if optional_attempts[0] and self.config.model_type.lower() == "qwen" and getattr(self.config, "disable_thinking", False):
                optional_attempts.append(False)

            last_error = ""
            for include_optional_qwen_args in optional_attempts:
                cmd = [self.config.llama_cpp_path]
                cmd.extend(self.config.get_llama_args(
                    templates_dir=str(self.template_manager.templates_dir),
                    custom_template_path=template_path,
                    include_optional_qwen_args=include_optional_qwen_args
                ))
                cmd.extend(["--file", temp_file_path])

                self.logger.info(
                    "Executing local %s model via llama-cli",
                    self.config.model_type,
                )
                if getattr(self.config, "debug_commands", False):
                    self.logger.info(
                        "llama.cpp command arguments:\n%s",
                        "\n".join(
                            f"  [{index:2d}] {argument}"
                            for index, argument in enumerate(cmd)
                        ),
                    )

                try:
                    remaining_timeout = generation_deadline - time.monotonic()
                    if remaining_timeout <= 0:
                        raise subprocess.TimeoutExpired(cmd, self.config.timeout)
                    return_code, stdout, stderr = self._run_process(
                        cmd,
                        timeout=remaining_timeout,
                    )
                except subprocess.TimeoutExpired:
                    self.logger.error(
                        "Local model generation timed out after %s seconds",
                        self.config.timeout,
                    )
                    return "Error: Local model generation timed out."

                if self._cancel_generation.is_set():
                    return "Error: Local model generation cancelled."

                if return_code != 0:
                    last_error = f"return code {return_code}"
                    diagnostic = self._stderr_diagnostic(stderr)
                    self.logger.error(
                        "llama.cpp failed with return code %s (%s)",
                        return_code,
                        diagnostic,
                    )
                    if include_optional_qwen_args and self._looks_like_optional_arg_error(stderr):
                        self._optional_qwen_args_supported = False
                        self.logger.warning(
                            "llama.cpp rejected optional Qwen template controls; "
                            "retrying without them"
                        )
                        continue
                    return "Error: Local model command failed."

                response = stdout.strip()
                if include_optional_qwen_args:
                    self._optional_qwen_args_supported = True

                if formatted_prompt in response:
                    response = response.replace(formatted_prompt, "").strip()

                return self._clean_model_output(response)

            self.logger.error("llama.cpp command failed after compatibility retry (%s)", last_error)
            return "Error: Local model command failed."
        finally:
            if temp_file_path:
                self._remove_temp_file(temp_file_path)

    def _generate_via_server(self, formatted_prompt: str, generation_deadline: float) -> str:
        if not self._ensure_server(generation_deadline):
            return "Error: Local model server is not available."
        remaining_timeout = generation_deadline - time.monotonic()
        if remaining_timeout <= 0:
            self.logger.error(
                "Local model generation timed out after %s seconds",
                self.config.timeout,
            )
            return "Error: Local model generation timed out."

        system_prompt = self._read_system_prompt()
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": formatted_prompt})

        try:
            max_tokens = int(getattr(self.config, "max_tokens", 2048) or 2048)
        except (TypeError, ValueError):
            max_tokens = 2048
        if max_tokens <= 0:
            max_tokens = int(getattr(self.config, "prompt_unbounded_output_reserve_tokens", 2048) or 2048)

        payload = {
            "messages": messages,
            "temperature": float(getattr(self.config, "temperature", 0.2) or 0.2),
            "top_p": float(getattr(self.config, "top_p", 0.8) or 0.8),
            "top_k": int(getattr(self.config, "top_k", 20) or 20),
            "max_tokens": max_tokens,
            "cache_prompt": True,
        }
        if (
            str(getattr(self.config, "model_type", "") or "").lower() == "qwen"
            and getattr(self.config, "disable_thinking", False)
        ):
            payload["chat_template_kwargs"] = {"enable_thinking": False}

        self.logger.info(
            "Executing local %s model via llama-server",
            getattr(self.config, "model_type", "qwen"),
        )
        try:
            data = self._http_json(
                "POST",
                "/v1/chat/completions",
                payload,
                timeout=remaining_timeout,
            )
        except TimeoutError:
            self.logger.error(
                "Local model generation timed out after %s seconds",
                self.config.timeout,
            )
            return "Error: Local model generation timed out."
        except RuntimeError as error:
            if self._cancel_generation.is_set():
                return "Error: Local model generation cancelled."
            self.logger.error("llama-server request failed (%s)", type(error).__name__)
            return "Error: Local model command failed."

        if self._cancel_generation.is_set():
            return "Error: Local model generation cancelled."

        content = self._extract_chat_content(data)
        timings = data.get("timings") if isinstance(data, dict) else None
        if isinstance(timings, dict):
            self.logger.info(
                "llama-server timings: prompt_n=%s prompt_tok_s=%s predicted_n=%s predicted_tok_s=%s",
                timings.get("prompt_n"),
                round(float(timings.get("prompt_per_second") or 0), 2),
                timings.get("predicted_n"),
                round(float(timings.get("predicted_per_second") or 0), 2),
            )
            print(
                "llama_timings "
                f"prompt_n={timings.get('prompt_n')} "
                f"prompt_tok_s={round(float(timings.get('prompt_per_second') or 0), 2)} "
                f"predicted_n={timings.get('predicted_n')} "
                f"predicted_tok_s={round(float(timings.get('predicted_per_second') or 0), 2)}",
                flush=True,
            )
        return self._clean_model_output(content)

    @staticmethod
    def _extract_chat_content(data) -> str:
        if not isinstance(data, dict):
            return ""
        choices = data.get("choices")
        if isinstance(choices, list) and choices:
            choice = choices[0] if isinstance(choices[0], dict) else {}
            message = choice.get("message") if isinstance(choice.get("message"), dict) else {}
            content = message.get("content")
            if content:
                return str(content)
            text = choice.get("text")
            if text:
                return str(text)
        return str(data.get("content") or "")

    def _server_health_ok(self, timeout: float = 2.0) -> bool:
        try:
            data = self._http_json("GET", "/health", None, timeout=timeout)
        except Exception:
            return False
        if not isinstance(data, dict):
            return False
        status = str(data.get("status") or "").strip().lower()
        return status in {"ok", "healthy", ""} or data.get("status") is None

    def _ensure_server(self, generation_deadline: float) -> bool:
        if self._server_health_ok():
            self._server_ready = True
            return True
        autostart = bool(getattr(self.config, "llama_server_autostart", True))
        if not autostart:
            self.logger.error("llama-server is not reachable and autostart is disabled")
            return False
        return self._start_owned_server(generation_deadline)

    def _start_owned_server(self, generation_deadline: float) -> bool:
        with self._process_lock:
            if self._shutdown_requested or self._cancel_generation.is_set():
                return False
            if self._server_process is not None and self._server_process.poll() is None:
                process = self._server_process
            else:
                binary = self._llama_server_binary()
                if not binary or not Path(binary).is_file():
                    self.logger.error("llama-server binary was not found beside llama-cli")
                    return False
                get_args = getattr(self.config, "get_llama_server_args", None)
                server_args = get_args() if callable(get_args) else []
                cmd = [binary, *server_args]
                self.logger.info("Starting persistent llama-server")
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    start_new_session=True,
                )
                self._server_process = process
                self._server_owned = True

        while time.monotonic() < generation_deadline:
            if self._cancel_generation.is_set() or self._shutdown_requested:
                return False
            if process.poll() is not None:
                self.logger.error("llama-server exited before becoming ready")
                return False
            if self._server_health_ok():
                self._server_ready = True
                self.logger.info("Persistent llama-server is ready")
                return True
            time.sleep(0.4)
        self.logger.error("llama-server did not become ready before the generation deadline")
        return False

    def _http_json(self, method: str, path: str, payload, timeout: float):
        url = f"{self._server_base_url()}{path}"
        data = None if payload is None else json.dumps(payload).encode("utf-8")
        headers = {"Accept": "application/json"}
        if data is not None:
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(url, data=data, headers=headers, method=method)
        response = None
        try:
            response = urllib.request.urlopen(request, timeout=max(0.05, float(timeout)))
            with self._process_lock:
                if not hasattr(self, "_active_http"):
                    self._active_http = []
                self._active_http.append(response)
            raw = response.read()
        except TimeoutError as error:
            raise TimeoutError("llama-server request timed out") from error
        except urllib.error.HTTPError as error:
            status = getattr(error, "code", 0)
            try:
                error.close()
            except Exception:
                pass
            raise RuntimeError(f"llama-server HTTP {status}") from error
        except urllib.error.URLError as error:
            reason = getattr(error, "reason", error)
            if isinstance(reason, TimeoutError) or "timed out" in str(error).lower():
                raise TimeoutError("llama-server request timed out") from error
            raise RuntimeError("llama-server transport failed") from error
        finally:
            if response is not None:
                with self._process_lock:
                    try:
                        self._active_http.remove(response)
                    except ValueError:
                        pass
                try:
                    response.close()
                except Exception:
                    pass
        try:
            return json.loads(raw.decode("utf-8")) if raw else {}
        except json.JSONDecodeError as error:
            raise RuntimeError("llama-server returned invalid JSON") from error

    def close(self) -> None:
        """Cancel in-flight work and stop an autostarted llama-server."""
        self.cancel_active_generations(permanent=True)
        with self._process_lock:
            process = self._server_process if self._server_owned else None
            self._server_process = None
            self._server_owned = False
            self._server_ready = False
        if process is not None:
            self._kill_and_reap(process)


    @staticmethod
    def _extract_prompt_section(prompt: str, marker: str, next_markers: list[str]) -> str:
        marker_pattern = re.compile(rf"(?im)^\s*{re.escape(marker)}\s*:?.*$")
        match = marker_pattern.search(prompt)
        if not match:
            return ""

        next_positions = []
        for next_marker in next_markers:
            if next_marker == marker:
                continue
            next_pattern = re.compile(rf"(?im)^\s*{re.escape(next_marker)}\s*:?.*$")
            next_match = next_pattern.search(prompt, match.end())
            if next_match:
                next_positions.append(next_match.start())
        end = min(next_positions) if next_positions else len(prompt)
        return prompt[match.start():end].strip()

    @staticmethod
    def _split_marked_sections(prompt: str) -> list[tuple[str, str]]:
        """Split a prompt on nonce-bearing section markers.

        Returns ``[(section_name, section_text), ...]`` in document order, or an
        empty list when the prompt carries no genuine markers. Because the nonce
        is generated per process and stripped from untrusted content, a document
        or telemetry value cannot introduce a boundary here.
        """
        text = str(prompt or "")
        matches = list(prompt_safety.section_marker_scan_pattern().finditer(text))
        if not matches:
            return []
        sections = []
        for index, match in enumerate(matches):
            end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
            name = (match.group("name") or "").strip()
            sections.append((name, text[match.start():end].strip()))
        return sections

    @staticmethod
    def _canonical_section_name(name: str, known_markers: list[str]) -> str:
        """Map an observed section name onto a known marker, longest match first.

        Some headings carry a dynamic suffix (for example
        ``HIGH-SEVERITY ALERTS (Compact View - Top 6 of 20)``), so an exact
        comparison would miss them.
        """
        observed = str(name or "").strip().upper()
        if not observed:
            return None
        best = None
        for marker in known_markers:
            candidate = marker.upper()
            if observed.startswith(candidate) and (best is None or len(candidate) > len(best)):
                best = candidate
        if best is None:
            return None
        for marker in known_markers:
            if marker.upper() == best:
                return marker
        return None

    @classmethod
    def _section_aware_compact(cls, prompt: str, max_chars: int) -> str:
        """Compact report prompts while preserving current evidence and output contract."""
        prompt = str(prompt or "")
        if len(prompt) <= max_chars:
            return prompt

        markers = [
            "ANALYSIS TYPE",
            "CURRENT ALERTS DATA",
            "CURRENT HIGH-SEVERITY INCIDENT DATA",
            "CURRENT ALERT — AUTHORITATIVE OBSERVATIONS",
            "CURRENT ALERT — EXPLICIT / INFERRED MITRE EVIDENCE",
            "CANONICAL INCIDENT SYNTHESIS — ORGANIZE THE REPORT AROUND THIS OBJECT",
            "CONFIGURED ASSET INVENTORY",
            "REPRESENTATIVE CURRENT ALERTS",
            "HIGH-SEVERITY ALERTS",
            "HISTORICAL AND CUSTOM REFERENCE CONTEXT",
            "RAG REFERENCE CONTEXT",
            "RETRIEVED HISTORICAL CTI — SOURCE-BOUND EXCERPTS",
            "COMPLEMENTARY PASSAGES FROM THE ALREADY-SELECTED TOP DOCUMENT",
            "CONFLICTS / LIMITATIONS",
            "ATTRIBUTION POLICY",
            "CONTEXT",
            "INSTRUCTIONS",
            "OUTPUT CONTRACT",
        ]
        priority_markers = [
            "ANALYSIS TYPE",
            "CURRENT ALERTS DATA",
            "CURRENT HIGH-SEVERITY INCIDENT DATA",
            "CANONICAL INCIDENT SYNTHESIS — ORGANIZE THE REPORT AROUND THIS OBJECT",
            "CURRENT ALERT — AUTHORITATIVE OBSERVATIONS",
            "CURRENT ALERT — EXPLICIT / INFERRED MITRE EVIDENCE",
            "REPRESENTATIVE CURRENT ALERTS",
            "HIGH-SEVERITY ALERTS",
            "HISTORICAL AND CUSTOM REFERENCE CONTEXT",
            "RAG REFERENCE CONTEXT",
            "RETRIEVED HISTORICAL CTI — SOURCE-BOUND EXCERPTS",
            "COMPLEMENTARY PASSAGES FROM THE ALREADY-SELECTED TOP DOCUMENT",
            "CONFLICTS / LIMITATIONS",
            "ATTRIBUTION POLICY",
            "OUTPUT CONTRACT",
            "CONFIGURED ASSET INVENTORY",
            "INSTRUCTIONS",
            "CONTEXT",
        ]
        section_limits = {
            "CURRENT ALERTS DATA": 1800,
            "CURRENT HIGH-SEVERITY INCIDENT DATA": 1800,
            "CANONICAL INCIDENT SYNTHESIS — ORGANIZE THE REPORT AROUND THIS OBJECT": 7000,
            "CURRENT ALERT — AUTHORITATIVE OBSERVATIONS": 4200,
            "CURRENT ALERT — EXPLICIT / INFERRED MITRE EVIDENCE": 1200,
            "REPRESENTATIVE CURRENT ALERTS": 4200,
            "HIGH-SEVERITY ALERTS": 4200,
            "HISTORICAL AND CUSTOM REFERENCE CONTEXT": 2600,
            "RAG REFERENCE CONTEXT": 2600,
            "RETRIEVED HISTORICAL CTI — SOURCE-BOUND EXCERPTS": 3200,
            "COMPLEMENTARY PASSAGES FROM THE ALREADY-SELECTED TOP DOCUMENT": 3600,
            "CONFLICTS / LIMITATIONS": 900,
            "ATTRIBUTION POLICY": 700,
            "OUTPUT CONTRACT": 3200,
            "CONFIGURED ASSET INVENTORY": 900,
            "INSTRUCTIONS": 1200,
            "CONTEXT": 900,
        }
        selected = []
        seen = set()

        def add(label: str, text: str, char_limit: int = None):
            text = re.sub(r"\n{3,}", "\n\n", str(text or "").strip())
            if not text:
                return
            if char_limit and len(text) > char_limit:
                text = text[:char_limit].rstrip() + "\n[Section truncated for context budget.]"
            key = hashlib.sha256(text.encode("utf-8")).hexdigest()
            if key in seen:
                return
            seen.add(key)
            selected.append((label, text))

        marked_sections = cls._split_marked_sections(prompt)
        if marked_sections:
            # Boundaries carry a per-process nonce, so untrusted telemetry or CTI
            # text cannot create or terminate a section by writing a heading.
            for marker in priority_markers:
                for name, body in marked_sections:
                    if cls._canonical_section_name(name, priority_markers) != marker:
                        continue
                    add(marker, body, char_limit=section_limits.get(marker, 1200))
            for name, body in marked_sections:
                if cls._canonical_section_name(name, priority_markers) is None:
                    add(name, body, char_limit=1200)
        else:
            # Prompts built outside the marker-aware assembly path (or replayed
            # from an earlier process) still compact using the legacy headings.
            for marker in priority_markers:
                section = cls._extract_prompt_section(prompt, marker, markers)
                limit = section_limits.get(marker, 1200)
                add(marker, section, char_limit=limit)
        add("closing", prompt[-1800:])

        # The output contract governs the shape of the whole report, so it is
        # held back from the greedy fill and appended last. Without this a large
        # earlier section consumes the budget and the contract is dropped --
        # which, with untrusted text able to contain the words "OUTPUT
        # CONTRACT", would leave an injected contract as the only one present.
        reserved = [item for item in selected if item[0] == "OUTPUT CONTRACT"]
        if reserved:
            selected = [item for item in selected if item[0] != "OUTPUT CONTRACT"]
            reserved_cap = max(400, (max_chars - 600) // 2)
            reserved = [
                (
                    label,
                    text if len(text) <= reserved_cap
                    else text[:reserved_cap].rstrip() + "\n[Section truncated for context budget.]",
                )
                for label, text in reserved
            ]
        reserved_len = sum(len(text) + 2 for _, text in reserved)

        budget_for_sections = max(1200, max_chars - 600)
        if reserved:
            budget_for_sections = max(0, min(budget_for_sections, max_chars - 600 - reserved_len))
        output_parts = []
        used = 0
        for label, text in selected:
            if used + len(text) + 4 > budget_for_sections:
                remaining = budget_for_sections - used - 80
                if remaining > 400:
                    output_parts.append(text[:remaining].rstrip() + "\n[Section truncated for context budget.]")
                    used = budget_for_sections
                    break
                continue
            output_parts.append(text)
            used += len(text) + 2

        output_parts.extend(text for _, text in reserved)

        compacted = "\n\n".join(output_parts).strip()
        notice = (
            "\n\n[Prompt compacted before llama.cpp execution. Preserved sections: "
            "current alerts, asset inventory, selected RAG evidence, and output contract.]\n"
        )
        if len(compacted) + len(notice) <= max_chars:
            compacted += notice
        return compacted[:max_chars].rstrip()

    def _apply_model_control_tokens(self, prompt: str) -> str:
        """Add model-specific controls that must be visible in the prompt text."""
        text = str(prompt or "")
        if (
            self.config.model_type.lower() == "qwen"
            and getattr(self.config, "disable_thinking", False)
            and "/no_think" not in text.lower()
        ):
            return text.rstrip() + "\n\n/no_think\n"
        return text

    @staticmethod
    def _clean_model_output(response: str) -> str:
        """Return only assistant report text from llama.cpp stdout."""
        text = str(response or "").strip()
        if not text:
            return ""

        # llama.cpp can echo chat control tokens even when --no-display-prompt is
        # set, especially across versions and custom templates.
        for token in (
            "<|im_start|>assistant",
            "<|im_start|>",
            "<|im_end|>",
            "<end_of_turn>",
            "<start_of_turn>",
        ):
            text = text.replace(token, "")

        # Qwen reasoning-capable builds may emit <think> blocks. A closed block is
        # stripped; an unterminated block is treated as unusable unless a report
        # heading clearly appears after it.
        text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL | re.IGNORECASE).strip()
        if re.match(r"^\s*<think\b", text, flags=re.IGNORECASE):
            heading = re.search(
                r"(?im)^(?:#{1,6}\s*)?(?:\*\*)?(?:executive summary|key findings|top .*threat|mitre|immediate actions?)",
                text,
            )
            if not heading:
                return ""
            text = text[heading.start():]
            text = re.sub(r"^\s*<think\b[^>]*>?", "", text, flags=re.IGNORECASE).strip()

        text = re.sub(r"</?think>", "", text, flags=re.IGNORECASE).strip()
        return text

    def _run_process(self, cmd: list[str], timeout: float) -> tuple[int, str, str]:
        """Run llama.cpp and guarantee termination/reaping on every failure path."""
        process = None
        try:
            with self._process_lock:
                if self._shutdown_requested or self._cancel_generation.is_set():
                    raise RuntimeError("Local model generation was cancelled")
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    bufsize=1,
                    universal_newlines=True,
                    start_new_session=True,
                )
                self._active_processes.add(process)
            stdout, stderr = process.communicate(timeout=timeout)
            return process.returncode, stdout or "", stderr or ""
        except subprocess.TimeoutExpired:
            if process is not None:
                self._kill_and_reap(process)
            raise
        except BaseException:
            if process is not None:
                self._kill_and_reap(process)
            raise
        finally:
            if process is not None:
                with self._process_lock:
                    self._active_processes.discard(process)

    def cancel_active_generations(self, *, permanent: bool = False) -> int:
        """Prevent retries and kill in-flight llama-cli children / HTTP calls.

        An autostarted llama-server is kept loaded across cancellations so the
        next report does not pay model-load again. ``close()`` stops it.
        """
        with self._process_lock:
            if permanent:
                self._shutdown_requested = True
            self._cancel_generation.set()
            server_process = getattr(self, "_server_process", None)
            processes = [
                process
                for process in list(self._active_processes)
                if process is not server_process
            ]
            http_calls = list(getattr(self, "_active_http", []) or [])
        for response in http_calls:
            try:
                response.close()
            except Exception:
                pass
        for process in processes:
            self._kill_and_reap(process)
        return len(processes)

    def prepare_generation(self) -> bool:
        """Clear a prior request cancellation before a newly admitted report."""
        with self._process_lock:
            if self._shutdown_requested:
                return False
            self._cancel_generation.clear()
        if self._uses_server():
            deadline = time.monotonic() + max(
                30.0,
                float(getattr(self.config, "timeout", 1200) or 1200),
            )
            if not self._ensure_server(deadline):
                return False
        return True

    @property
    def active_process_count(self) -> int:
        with self._process_lock:
            return len(self._active_processes)

    @staticmethod
    def _kill_and_reap(process, reap_timeout: float = 10.0) -> None:
        """Kill a llama.cpp process group and wait so no zombie/child is left."""
        try:
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except (AttributeError, OSError, ProcessLookupError):
                    process.kill()
        except (OSError, ProcessLookupError):
            pass

        try:
            process.communicate(timeout=reap_timeout)
        except subprocess.TimeoutExpired:
            try:
                process.kill()
            except (OSError, ProcessLookupError):
                pass
            try:
                process.wait(timeout=reap_timeout)
            except (OSError, subprocess.TimeoutExpired):
                pass
        except Exception:
            try:
                process.wait(timeout=reap_timeout)
            except (OSError, subprocess.TimeoutExpired):
                LOGGER.error("Unable to confirm local model process termination")

    @staticmethod
    def _stderr_diagnostic(stderr: str) -> str:
        """Return useful non-content diagnostics without logging model input/output."""
        text = str(stderr or "")
        normalized = text.lower()
        if "chat-template-kwargs" in normalized:
            category = "optional-template-argument-rejected"
        elif any(token in normalized for token in ("unknown argument", "invalid argument", "unrecognized option")):
            category = "command-argument-rejected"
        else:
            category = "runtime-error"
        digest = hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()[:12]
        return f"category={category}, stderr_chars={len(text)}, stderr_sha256={digest}"

    @staticmethod
    def _remove_temp_file(temp_file_path: str):
        try:
            os.unlink(temp_file_path)
        except OSError:
            pass

    def _detect_optional_qwen_args_support(self) -> None:
        """Probe llama-cli --help so the first real generation does not double-spawn.

        Optional Qwen template kwargs are retried at runtime if this probe cannot
        run (relative binary path, missing file, or help timeout). A help probe
        does not load the GGUF.
        """
        if self._optional_qwen_args_supported is not None:
            return
        if self.config.model_type.lower() != "qwen" or not getattr(
            self.config, "disable_thinking", False
        ):
            self._optional_qwen_args_supported = False
            return
        binary = Path(str(self.config.llama_cpp_path or ""))
        if not binary.is_file():
            return
        try:
            completed = subprocess.run(
                [str(binary), "--help"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            help_text = f"{completed.stdout or ''}{completed.stderr or ''}".lower()
            self._optional_qwen_args_supported = "chat-template-kwargs" in help_text
        except Exception:
            return

    @staticmethod
    def _looks_like_optional_arg_error(stderr: str) -> bool:
        text = str(stderr or "").lower()
        return (
            "chat-template-kwargs" in text
            or "unknown argument" in text
            or "invalid argument" in text
            or "unrecognized option" in text
        )
