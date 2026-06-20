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

    def __init__(self, llm_config, template_manager: ChatTemplateManager):
        self.config = llm_config
        self.template_manager = template_manager

    def generate_response(self, user_message: str) -> str:
        temp_file_path = None
        try:
            formatted_prompt = self.template_manager.format_user_message(user_message)

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

            cmd = [self.config.llama_cpp_path]
            cmd.extend(self.config.get_llama_args(
                templates_dir=str(self.template_manager.templates_dir),
                custom_template_path=template_path
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
                self._remove_temp_file(temp_file_path)
                temp_file_path = None

                if process.returncode != 0:
                    print(f"Llama.cpp error (return code {process.returncode})")
                    if stderr:
                        print(f"Stderr: {stderr}")
                    return f"Error: Command failed with return code {process.returncode}"

                response = stdout.strip()

                if formatted_prompt in response:
                    response = response.replace(formatted_prompt, "").strip()

                response = response.replace("<end_of_turn>", "").strip()
                if response.endswith("<start_of_turn>"):
                    response = response[:-len("<start_of_turn>")].strip()

                return response

            except subprocess.TimeoutExpired:
                print(f"LLM generation timed out after {self.config.timeout} seconds")
                process.kill()
                self._remove_temp_file(temp_file_path)
                temp_file_path = None
                return f"Error: LLM generation timed out after {self.config.timeout} seconds."

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
