#!/usr/bin/env python3
"""Preflight context-budget checks for llama.cpp prompt assembly.

These checks are fully deterministic: no model is loaded and no subprocess is
started. They assert the invariant

    context_size >= system_tokens + prompt_tokens + reserved_output + margin

holds for every prompt the client is willing to hand to llama.cpp.
"""

from __future__ import annotations

import sys
import types
import unittest
from pathlib import Path

CONFIG_DIR = Path(__file__).resolve().parents[1] / "config"
if str(CONFIG_DIR) not in sys.path:
    sys.path.insert(0, str(CONFIG_DIR))

from llm_client import LlamaModelClient, PromptBudgetError  # noqa: E402


def _client(
    *,
    context_size: int = 16384,
    max_tokens: int = 2048,
    safety_margin: int = 512,
    chars_per_token: float = 3.0,
    system_prompt: str = "SYSTEM " * 100,
    unbounded_reserve: int = 2048,
) -> LlamaModelClient:
    client = LlamaModelClient.__new__(LlamaModelClient)
    client.config = types.SimpleNamespace(
        context_size=context_size,
        max_tokens=max_tokens,
        prompt_safety_margin_tokens=safety_margin,
        prompt_chars_per_token=chars_per_token,
        prompt_unbounded_output_reserve_tokens=unbounded_reserve,
        debug_commands=False,
        model_type="qwen",
        disable_thinking=True,
        timeout=1200,
    )
    client.logger = __import__("logging").getLogger("test-llm-budget")
    client._read_system_prompt = lambda: system_prompt
    return client


def _assert_invariant(client: LlamaModelClient, prompt: str) -> dict:
    """The whole point of Phase 1: every accepted prompt must satisfy this."""
    budget = client._compute_prompt_budget(prompt)
    total = (
        budget["system_tokens"]
        + budget["prompt_tokens"]
        + budget["reserved_output_tokens"]
        + budget["safety_margin_tokens"]
    )
    if total > budget["context_size"]:
        raise AssertionError(
            f"Context budget violated: total={total} > context={budget['context_size']}"
        )
    return budget


class ContextBudgetTests(unittest.TestCase):
    def test_small_prompt_is_returned_unchanged(self):
        client = _client()
        prompt = "ANALYSIS TYPE: manual\n\nCURRENT ALERTS DATA:\n{}\n"
        self.assertEqual(client._fit_prompt_to_context(prompt), prompt)
        _assert_invariant(client, prompt)

    def test_output_tokens_are_reserved(self):
        """Regression: the budget used to ignore max_tokens entirely."""
        client = _client(context_size=16384, max_tokens=2048, safety_margin=512)
        budget = client._compute_prompt_budget("")
        self.assertEqual(budget["reserved_output_tokens"], 2048)
        self.assertEqual(
            budget["available_prompt_tokens"],
            16384 - budget["system_tokens"] - 2048 - 512,
        )

    def test_describe_budget_uses_required_labels_and_omits_prompt_text(self):
        client = _client()
        secret = "SECRET-ALERT-full_log-value-8f3a"
        budget = client._compute_prompt_budget(secret)
        text = client._describe_budget(budget)
        self.assertIn("Model context limit", text)
        self.assertIn("Reserved output budget", text)
        self.assertIn("System/prompt overhead", text)
        self.assertIn("Alert/evidence tokens", text)
        self.assertIn("Retrieved CTI tokens", text)
        self.assertIn("Safety margin", text)
        self.assertNotIn(secret, text)

    def test_prompt_exactly_at_budget_boundary_is_not_compacted(self):
        client = _client()
        budget = client._compute_prompt_budget("")
        prompt = "x" * budget["available_prompt_chars"]
        fitted = client._fit_prompt_to_context(prompt)
        self.assertEqual(fitted, prompt)
        _assert_invariant(client, fitted)

    def test_prompt_one_token_over_budget_is_compacted_within_budget(self):
        client = _client()
        budget = client._compute_prompt_budget("")
        prompt = "x" * (budget["available_prompt_chars"] + 4096)
        fitted = client._fit_prompt_to_context(prompt)
        self.assertLess(len(fitted), len(prompt))
        _assert_invariant(client, fitted)

    def test_large_rag_context_is_compacted_and_keeps_current_evidence(self):
        client = _client()
        prompt = "\n\n".join([
            "ANALYSIS TYPE: automated live alert",
            "CURRENT ALERTS DATA:\n" + ("{\"rule_id\": \"900001\"}\n" * 40),
            "RAG REFERENCE CONTEXT:\n" + ("filler cti passage. " * 40000),
            "OUTPUT CONTRACT:\nProduce the sections in order.",
        ])
        fitted = client._fit_prompt_to_context(prompt)
        budget = _assert_invariant(client, fitted)
        self.assertLessEqual(len(fitted), budget["available_prompt_chars"])
        self.assertIn("CURRENT ALERTS DATA", fitted)
        self.assertIn("OUTPUT CONTRACT", fitted)

    def test_larger_max_tokens_shrinks_the_prompt_budget(self):
        small = _client(max_tokens=512)._compute_prompt_budget("")
        large = _client(max_tokens=8192)._compute_prompt_budget("")
        self.assertEqual(
            small["available_prompt_tokens"] - large["available_prompt_tokens"],
            8192 - 512,
        )

    def test_unbounded_max_tokens_still_reserves_output_space(self):
        for unbounded in (-1, -2):
            with self.subTest(max_tokens=unbounded):
                client = _client(max_tokens=unbounded, unbounded_reserve=3000)
                budget = client._compute_prompt_budget("")
                self.assertEqual(budget["reserved_output_tokens"], 3000)

    def test_impossible_budget_raises_without_leaking_prompt_content(self):
        secret = "SECRET-ALERT-full_log-value-8f3a"
        client = _client(context_size=2048, max_tokens=1600, safety_margin=512)
        with self.assertRaises(PromptBudgetError) as raised:
            client._fit_prompt_to_context(secret * 100)
        message = str(raised.exception)
        self.assertNotIn(secret, message)
        self.assertIn("context_size", message)

    def test_generate_response_surfaces_budget_error_without_running_llama(self):
        client = _client(context_size=2048, max_tokens=1600, safety_margin=512)
        client._process_lock = __import__("threading").RLock()
        client._shutdown_requested = False
        client._cancel_generation = __import__("threading").Event()
        client.template_manager = types.SimpleNamespace(
            format_user_message=lambda value: value,
            templates_dir=Path("."),
            get_template_path=lambda: "",
        )

        def _fail(*_args, **_kwargs):  # pragma: no cover - must never run
            raise AssertionError("llama.cpp was invoked despite a budget violation")

        client._run_process = _fail
        response = client.generate_response("SECRET-PROMPT" * 200)
        self.assertTrue(response.startswith("Error: "))
        self.assertIn("context window is too small", response)
        self.assertNotIn("SECRET-PROMPT", response)

    def test_compaction_never_exceeds_budget_for_unstructured_prompts(self):
        """A prompt with no recognised section markers must still be capped."""
        client = _client()
        budget = client._compute_prompt_budget("")
        prompt = "lorem ipsum dolor sit amet " * 20000
        fitted = client._fit_prompt_to_context(prompt)
        self.assertLessEqual(len(fitted), budget["available_prompt_chars"])
        _assert_invariant(client, fitted)

    def test_pessimistic_chars_per_token_tightens_the_budget(self):
        loose = _client(chars_per_token=4.0)._compute_prompt_budget("")
        tight = _client(chars_per_token=2.5)._compute_prompt_budget("")
        self.assertLess(tight["available_prompt_chars"], loose["available_prompt_chars"])


if __name__ == "__main__":
    unittest.main()
