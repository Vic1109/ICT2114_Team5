import os
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

    CUDA_OOM_MARKERS = (
        "cudamalloc failed: out of memory",
        "failed to allocate cuda",
        "unable to allocate cuda",
        "out of memory",
        "try reducing --n-gpu-layers",
        "try reducing --gpu-layers",
    )

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
        max_tokens = int(getattr(self.config, "max_tokens", 1024) or 1024)
        reserved_output_tokens = min(max(max_tokens, 256), max(256, context_size // 3))
        safety_margin_tokens = 256
        available_prompt_tokens = context_size - system_tokens - reserved_output_tokens - safety_margin_tokens

        if available_prompt_tokens < 512:
            print(
                "WARNING: Very little prompt room remains after system prompt and output reserve "
                f"(context={context_size}, system_est={system_tokens}, output_reserve={reserved_output_tokens}). "
                "Use the compact system prompt or increase LLM_CONTEXT_SIZE."
            )
            available_prompt_tokens = max(256, context_size - system_tokens - safety_margin_tokens)

        if prompt_tokens <= available_prompt_tokens:
            return prompt

        max_prompt_chars = available_prompt_tokens * 3
        if len(prompt) <= max_prompt_chars:
            return prompt

        head_chars = int(max_prompt_chars * 0.72)
        tail_chars = max(800, max_prompt_chars - head_chars - 500)
        omitted_chars = max(0, len(prompt) - head_chars - tail_chars)
        compacted = (
            prompt[:head_chars].rstrip()
            + "\n\n[Prompt compacted before llama.cpp execution: "
            + f"omitted approximately {omitted_chars} characters to fit the configured context window. "
            + "Current alert summary, strongest retrieval evidence, and final instructions are preserved.]\n\n"
            + prompt[-tail_chars:].lstrip()
        )
        print(
            "WARNING: Prompt compacted before llama.cpp execution "
            f"(estimated tokens: system={system_tokens}, prompt={prompt_tokens}, "
            f"output_reserve={reserved_output_tokens}, available_prompt={available_prompt_tokens})."
        )
        return compacted

    @classmethod
    def _is_cuda_oom(cls, stderr: str) -> bool:
        normalized = (stderr or "").lower()
        return any(marker in normalized for marker in cls.CUDA_OOM_MARKERS)

    @staticmethod
    def _fallback_gpu_layers(initial_layers: int) -> list[int]:
        if initial_layers <= 0:
            return [0]

        candidates = [initial_layers, initial_layers // 2, initial_layers // 4, 0]
        fallback_layers = []
        for layers in candidates:
            layers = max(0, int(layers))
            if layers not in fallback_layers:
                fallback_layers.append(layers)
        return fallback_layers

    def _build_llama_command(self, temp_file_path: str) -> list[str]:
        template_path = (
            self.template_manager.get_template_path()
            if self.config.use_custom_template
            else None
        )

        cmd = [self.config.llama_cpp_path]
        cmd.extend(self.config.get_llama_args(
            templates_dir=str(self.template_manager.templates_dir),
            custom_template_path=template_path
        ))
        cmd.extend(["--file", temp_file_path])
        return cmd

    def _run_llama_command(self, temp_file_path: str) -> tuple[int, str, str]:
        cmd = self._build_llama_command(temp_file_path)

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
            process.kill()
            process.communicate()
            raise
        return process.returncode, stdout, stderr

    @staticmethod
    def _clean_response(stdout: str, formatted_prompt: str) -> str:
        response = stdout.strip()

        if formatted_prompt in response:
            response = response.replace(formatted_prompt, "").strip()

        response = response.replace("<end_of_turn>", "").strip()
        if response.endswith("<start_of_turn>"):
            response = response[:-len("<start_of_turn>")].strip()

        return response

    def generate_response(self, user_message: str) -> str:
        temp_file_path = None
        try:
            formatted_prompt = self.template_manager.format_user_message(user_message)
            formatted_prompt = self._fit_prompt_to_context(formatted_prompt)

            with tempfile.NamedTemporaryFile(
                mode="w",
                suffix=".txt",
                delete=False,
                encoding="utf-8"
            ) as temp_file:
                temp_file.write(formatted_prompt)
                temp_file_path = temp_file.name

            original_gpu_layers = int(getattr(self.config, "gpu_layers", 0) or 0)
            gpu_layer_attempts = self._fallback_gpu_layers(original_gpu_layers)
            last_returncode = None
            last_stderr = ""

            for attempt_index, gpu_layers in enumerate(gpu_layer_attempts):
                if attempt_index > 0:
                    print(
                        "WARNING: llama.cpp hit CUDA out-of-memory while loading the model. "
                        f"Retrying with --gpu-layers {gpu_layers}."
                    )
                    self.config.gpu_layers = gpu_layers

                try:
                    returncode, stdout, stderr = self._run_llama_command(temp_file_path)
                except subprocess.TimeoutExpired:
                    print(f"LLM generation timed out after {self.config.timeout} seconds")
                    return f"Error: LLM generation timed out after {self.config.timeout} seconds."

                last_returncode = returncode
                last_stderr = stderr

                if returncode != 0 and self._is_cuda_oom(stderr) and attempt_index < len(gpu_layer_attempts) - 1:
                    if stderr:
                        print(f"Stderr: {stderr}")
                    continue

                self._remove_temp_file(temp_file_path)
                temp_file_path = None
                if returncode != 0:
                    print(f"Llama.cpp error (return code {returncode})")
                    if stderr:
                        print(f"Stderr: {stderr}")
                    if self._is_cuda_oom(stderr):
                        return (
                            "Error: llama.cpp ran out of GPU memory while loading the model. "
                            f"The app retried down to --gpu-layers {gpu_layers}. "
                            "Set LLM_GPU_LAYERS=0 for CPU-only loading or use a smaller/lower-quantized GGUF."
                        )
                    return f"Error: Command failed with return code {returncode}"

                return self._clean_response(stdout, formatted_prompt)

            return f"Error: Command failed with return code {last_returncode}: {last_stderr}"

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
