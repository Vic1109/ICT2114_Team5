#!/usr/bin/env python3
"""Measure provider telemetry on a representative prompt.

This tool does not call the OpenAI API and does not load a GGUF. It records
how long the public provider spends around an in-memory transport, and how
long local prompt budgeting takes, so the two paths can be compared later
with real backends without changing the measurement fields.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

CONFIG_DIR = Path(__file__).resolve().parents[1] / "config"
if str(CONFIG_DIR) not in sys.path:
    sys.path.insert(0, str(CONFIG_DIR))

import prompt_safety  # noqa: E402
from llm_client import LlamaModelClient  # noqa: E402
from llm_provider import ContextPolicy  # noqa: E402
from openai_llm import OpenAIProvider  # noqa: E402
from report import SHARED_ACTOR_RULE, SHARED_EVIDENCE_INSTRUCTION, SHARED_MITRE_RULE  # noqa: E402


IOC = "203.0.113.45"
HASH = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"


class TimedTransport:
    def __init__(self, delay_s: float):
        self.delay_s = delay_s

    def post_chat(self, payload, timeout):
        time.sleep(self.delay_s)
        text = payload["messages"][-1]["content"]
        return {
            "choices": [{"message": {"content": "**Executive Summary:**\nMeasured.\n**Analysis Complete**"}}],
            "usage": {
                "prompt_tokens": max(1, len(text) // 4),
                "completion_tokens": 12,
            },
        }


def representative_prompt() -> str:
    cti = "\n".join(
        f"CTI document {index}: technique T1071, provenance unit-test, indicator overlap none."
        for index in range(1, 5)
    )
    return "\n\n".join([
        prompt_safety.section_marker("INSTRUCTIONS") + " " + SHARED_EVIDENCE_INSTRUCTION,
        prompt_safety.section_marker("ATTRIBUTION POLICY") + " " + SHARED_ACTOR_RULE,
        prompt_safety.section_marker("DETERMINISTIC EXACT IOC MATCHES — APPLICATION-ESTABLISHED")
        + f"\n- ipv4 {IOC}\n- sha256 {HASH}",
        prompt_safety.section_marker("RETRIEVED HISTORICAL CTI — SOURCE-BOUND EXCERPTS") + "\n" + cti,
        prompt_safety.section_marker("OUTPUT CONTRACT") + "\n" + SHARED_MITRE_RULE,
    ])


def main() -> int:
    prompt = representative_prompt()
    public_config = type("Cfg", (), {})()
    public_config.api_key = "replace-me"
    public_config.model = "gpt-4o-mini"
    public_config.timeout = 5
    public_config.max_output_tokens = 1024
    public_config.context_window = 128000
    public_config.safety_margin_tokens = 1024
    public_config.chars_per_token = 3.5
    public_config.max_retries = 0
    public_config.temperature = 0.2
    public_config.base_url = "https://api.openai.com/v1"
    started = time.perf_counter()
    provider = OpenAIProvider(
        public_config,
        system_prompt_reader=lambda: "Benchmark system prompt.",
        transport=TimedTransport(0.02),
    )
    provider.generate_response(prompt)
    public_total = time.perf_counter() - started
    public = dict(provider.last_inference_telemetry)
    public["total_report_latency_s"] = round(public_total, 3)
    public["context_reduced"] = provider.last_inference_telemetry["context_reduced"]
    public["note"] = "In-memory transport with a 20 ms delay. Not a live OpenAI measurement."

    local_config = type("Local", (), {})()
    local_config.context_size = 16384
    local_config.max_tokens = 2048
    local_config.prompt_safety_margin_tokens = 512
    local_config.prompt_chars_per_token = 3.0
    local_config.prompt_unbounded_output_reserve_tokens = 2048
    local_config.model_path = "local-benchmark.gguf"
    client = LlamaModelClient.__new__(LlamaModelClient)
    client.config = local_config
    client.template_manager = type("Templates", (), {"templates_dir": None})()
    client.logger = __import__("logging").getLogger("benchmark-local")
    client._last_budget = {}
    client._context_reduced = False
    budget_started = time.perf_counter()
    fitted = client._fit_prompt_to_context(prompt)
    budget_s = time.perf_counter() - budget_started
    budget = client._compute_prompt_budget(fitted, system_prompt="")
    local = {
        "provider": "local",
        "model": "local-benchmark.gguf",
        "input_tokens": budget["system_tokens"] + budget["prompt_tokens"],
        "output_tokens": None,
        "llm_request_duration_s": None,
        "context_budget_latency_s": round(budget_s, 3),
        "context_reduced": len(fitted) != len(prompt),
        "success": None,
        "retry_count": 0,
        "total_report_latency_s": None,
        "note": "Local GGUF was not loaded. Only prompt budgeting was measured.",
    }
    policy = ContextPolicy.for_openai(public_config, 128000)
    print(json.dumps({
        "prompt_characters": len(prompt),
        "public_window": policy.context_limit,
        "public_fits_without_reduction": policy.prompt_fits(prompt, "Benchmark system prompt."),
        "local": local,
        "public": public,
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
