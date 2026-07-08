import os
import re
import hashlib
import subprocess
import tempfile
from pathlib import Path

from jinja2 import Template


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
                print(f"Loaded chat template: {template_path}")
                return template_content
            except Exception as e:
                print(f"WARNING: Error loading chat template: {e}")
        else:
            print(f"WARNING: Chat template not found: {template_path}")
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
                print(f"Template formatting error: {e}")

        return user_message

    def get_template_path(self) -> str:
        return str(self.templates_dir / self.config.chat_template_file)


class LlamaModelClient:
    """Run local LLM inference through llama.cpp."""

    def __init__(self, llm_config, template_manager: ChatTemplateManager):
        self.config = llm_config
        self.template_manager = template_manager

    def _read_system_prompt(self) -> str:
        system_prompt_path = self.template_manager.templates_dir / self.config.system_prompt_file
        try:
            if system_prompt_path.exists():
                return system_prompt_path.read_text(encoding="utf-8")
        except Exception as e:
            print(f"WARNING: Unable to read system prompt for prompt budgeting: {e}")
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
        omitted_chars = max(0, len(prompt) - len(compacted))
        print(
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

            optional_attempts = [True]
            if self.config.model_type.lower() == "qwen" and getattr(self.config, "disable_thinking", False):
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

                print(f"Executing {self.config.model_type} model with system prompt from file")
                print("=" * 100)
                for i, arg in enumerate(cmd):
                    print(f"  [{i:2d}] {arg}")
                print("=" * 100)

                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    bufsize=1,
                    universal_newlines=True
                )

                try:
                    stdout, stderr = process.communicate(timeout=self.config.timeout)
                except subprocess.TimeoutExpired:
                    print(f"LLM generation timed out after {self.config.timeout} seconds")
                    process.kill()
                    self._remove_temp_file(temp_file_path)
                    temp_file_path = None
                    return f"Error: LLM generation timed out after {self.config.timeout} seconds."

                if process.returncode != 0:
                    last_error = stderr or f"return code {process.returncode}"
                    print(f"Llama.cpp error (return code {process.returncode})")
                    if stderr:
                        print(f"Stderr: {stderr}")
                    if include_optional_qwen_args and self._looks_like_optional_arg_error(stderr):
                        print("WARNING: llama.cpp rejected optional Qwen chat-template args; retrying without them.")
                        continue
                    self._remove_temp_file(temp_file_path)
                    temp_file_path = None
                    return f"Error: Command failed with return code {process.returncode}"

                self._remove_temp_file(temp_file_path)
                temp_file_path = None

                response = stdout.strip()

                if formatted_prompt in response:
                    response = response.replace(formatted_prompt, "").strip()

                return self._clean_model_output(response)

            self._remove_temp_file(temp_file_path)
            temp_file_path = None
            return f"Error: llama.cpp command failed: {last_error}"

        except Exception as e:
            print(f"LLM generation error: {e}")
            return f"Error: {str(e)}"
        finally:
            if temp_file_path:
                self._remove_temp_file(temp_file_path)

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
