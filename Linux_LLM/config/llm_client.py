import os
import re
import hashlib
import logging
import signal
import subprocess
import tempfile
import threading
import time
from pathlib import Path

from jinja2 import Template

from runtime_utils import log_sanitized_exception


LOGGER = logging.getLogger(__name__)


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
        self._cancel_generation = threading.Event()
        self._shutdown_requested = False

    def _read_system_prompt(self) -> str:
        system_prompt_path = self.template_manager.templates_dir / self.config.system_prompt_file
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

    @staticmethod
    def _estimate_tokens(text: str) -> int:
        # Conservative approximation for llama.cpp preflight budgeting.
        return max(1, len(str(text or "")) // 3)

    def _fit_prompt_to_context(self, prompt: str) -> str:
        system_prompt = self._read_system_prompt()
        context_size = max(1024, int(getattr(self.config, "context_size", 16384)))
        system_tokens = self._estimate_tokens(system_prompt)
        prompt_tokens = self._estimate_tokens(prompt)
        safety_margin_tokens = 512
        available_prompt_tokens = max(768, context_size - system_tokens - safety_margin_tokens)

        if prompt_tokens <= available_prompt_tokens:
            return prompt

        max_prompt_chars = available_prompt_tokens * 3
        if len(prompt) <= max_prompt_chars:
            return prompt

        compacted = self._section_aware_compact(prompt, max_prompt_chars)
        self.logger.warning(
            "WARNING: Prompt compacted before llama.cpp execution "
            f"(estimated tokens: system={system_tokens}, prompt={prompt_tokens}, "
            f"available_prompt={available_prompt_tokens})."
        )
        return compacted

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
            "CONFIGURED ASSET INVENTORY",
            "REPRESENTATIVE CURRENT ALERTS",
            "HIGH-SEVERITY ALERTS",
            "HISTORICAL AND CUSTOM REFERENCE CONTEXT",
            "RAG REFERENCE CONTEXT",
            "CONTEXT",
            "INSTRUCTIONS",
            "OUTPUT CONTRACT",
        ]
        priority_markers = [
            "ANALYSIS TYPE",
            "CURRENT ALERTS DATA",
            "CURRENT HIGH-SEVERITY INCIDENT DATA",
            "REPRESENTATIVE CURRENT ALERTS",
            "HIGH-SEVERITY ALERTS",
            "HISTORICAL AND CUSTOM REFERENCE CONTEXT",
            "RAG REFERENCE CONTEXT",
            "OUTPUT CONTRACT",
            "CONFIGURED ASSET INVENTORY",
            "INSTRUCTIONS",
            "CONTEXT",
        ]
        section_limits = {
            "CURRENT ALERTS DATA": 1800,
            "CURRENT HIGH-SEVERITY INCIDENT DATA": 1800,
            "REPRESENTATIVE CURRENT ALERTS": 4200,
            "HIGH-SEVERITY ALERTS": 4200,
            "HISTORICAL AND CUSTOM REFERENCE CONTEXT": 2600,
            "RAG REFERENCE CONTEXT": 2600,
            "OUTPUT CONTRACT": 1600,
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

        for marker in priority_markers:
            section = cls._extract_prompt_section(prompt, marker, markers)
            limit = section_limits.get(marker, 1200)
            add(marker, section, char_limit=limit)
        add("closing", prompt[-1800:])

        budget_for_sections = max(1200, max_chars - 600)
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
            formatted_prompt = self._fit_prompt_to_context(formatted_prompt)

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
                    "Executing local %s model",
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

        except Exception as e:
            log_sanitized_exception("Local model generation failed", e, logger=self.logger)
            if getattr(self.config, "debug_commands", False):
                self.logger.debug("Local model failure detail", exc_info=True)
            return "Error: Local model generation failed."
        finally:
            if temp_file_path:
                self._remove_temp_file(temp_file_path)

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
        """Prevent retries and kill/reap every active llama.cpp process group."""
        with self._process_lock:
            if permanent:
                self._shutdown_requested = True
            self._cancel_generation.set()
            processes = list(self._active_processes)
        for process in processes:
            self._kill_and_reap(process)
        return len(processes)

    def prepare_generation(self) -> bool:
        """Clear a prior request cancellation before a newly admitted report."""
        with self._process_lock:
            if self._shutdown_requested:
                return False
            self._cancel_generation.clear()
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

    @staticmethod
    def _looks_like_optional_arg_error(stderr: str) -> bool:
        text = str(stderr or "").lower()
        return (
            "chat-template-kwargs" in text
            or "unknown argument" in text
            or "invalid argument" in text
            or "unrecognized option" in text
        )
