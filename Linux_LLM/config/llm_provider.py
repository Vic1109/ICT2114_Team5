"""Shared LLM provider selection and context policy.

Report generation stays in one pipeline. This module only decides which
backend receives the shared prompt and how much evidence that backend may
see before its own transport limits apply.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Callable, Optional

import prompt_safety
import prompt_sections


ALLOWED_PROVIDERS = frozenset({"local", "openai"})
_PROVIDER_ALIASES = {
    "local": "local",
    "local_llm": "local",
    "public": "openai",
    "public_llm": "openai",
    "openai": "openai",
}

LOCAL_REPORT_LABEL = "Local"
OPENAI_REPORT_LABEL = "OpenAI"
LOCAL_PROGRESS_LABEL = "Local LLM"
OPENAI_PROGRESS_LABEL = "Public LLM"

# Pre-assembly caps used by the local model path. These match the historical
# report-construction limits so Local mode does not change prompt shape.
LOCAL_RETRIEVED_DOC_CHARS = 2800
LOCAL_EXPANDED_DOC_CHARS = 3200
LOCAL_SYNTHESIS_CHARS = 3500
LOCAL_MAX_PROMPT_ALERTS = 6
LOCAL_EXACT_TERM_ITEMS = 8
LOCAL_MAX_EXACT_IOC_LINES = 12

_SHRINK_LAST = prompt_sections.PROVIDER_SHRINK_FIRST
_SHRINK_ALERTS_AFTER_CTI = prompt_sections.PROVIDER_SHRINK_ALERTS_AFTER_CTI
_IOC_SECTION = prompt_sections.PROVIDER_IOC_SECTION
_KEEP_INTACT = prompt_sections.PROVIDER_KEEP_INTACT


class ProviderSelectionError(ValueError):
    """The caller asked for a provider outside the allowlist."""


class ProviderRequestError(RuntimeError):
    """A provider failed in a way that is safe to show in the GUI.

    The message must not contain credentials, stack traces, or filesystem paths.
    """


class ContextBudgetError(ProviderRequestError):
    """The prompt cannot fit the selected model's context window."""


def normalize_provider(value: Any) -> str:
    """Map a user-facing provider token onto the allowlist.

    Anything that is not an exact alias is rejected. Module paths, class
    names, and dotted identifiers cannot select an implementation.
    """
    if value is None:
        raise ProviderSelectionError("LLM provider is required")
    token = str(value).strip().lower()
    if not token or token not in _PROVIDER_ALIASES:
        raise ProviderSelectionError("Unsupported LLM provider")
    provider_id = _PROVIDER_ALIASES[token]
    if provider_id not in ALLOWED_PROVIDERS:
        raise ProviderSelectionError("Unsupported LLM provider")
    return provider_id


def report_label(provider_id: str) -> str:
    if provider_id == "openai":
        return OPENAI_REPORT_LABEL
    return LOCAL_REPORT_LABEL


def progress_label(provider_id: str) -> str:
    if provider_id == "openai":
        return OPENAI_PROGRESS_LABEL
    return LOCAL_PROGRESS_LABEL


def estimate_tokens(text: str, chars_per_token: float) -> int:
    """Character-based token estimate. Counts only; the text is not retained."""
    text = str(text or "")
    if not text:
        return 0
    try:
        divisor = float(chars_per_token)
    except (TypeError, ValueError):
        divisor = 3.5
    if divisor <= 0:
        divisor = 3.5
    return max(1, int(len(text) / divisor))


def redact_secret(text: Any, secret: str) -> str:
    value = str(text or "")
    token = str(secret or "")
    if token and token in value:
        value = value.replace(token, "[redacted]")
    value = re.sub(r"sk-[A-Za-z0-9_-]{8,}", "[redacted]", value)
    value = re.sub(r"(?i)(bearer\s+)[A-Za-z0-9._\-]+", r"\1[redacted]", value)
    return value


@dataclass(frozen=True)
class ContextPolicy:
    """Provider-specific limits for prompt assembly and inference."""

    provider_id: str
    context_limit: int
    max_output_tokens: int
    safety_margin_tokens: int
    chars_per_token: float
    prefer_full_context: bool
    compact_before_inference: bool
    retrieved_doc_chars: int
    expanded_doc_chars: int
    synthesis_chars: int
    max_prompt_alerts: int
    exact_term_items: int
    max_exact_ioc_lines: int

    def estimate_tokens(self, text: str) -> int:
        return estimate_tokens(text, self.chars_per_token)

    def input_token_budget(self, system_prompt: str = "") -> int:
        system_tokens = self.estimate_tokens(system_prompt)
        available = (
            int(self.context_limit)
            - int(self.max_output_tokens)
            - int(self.safety_margin_tokens)
            - system_tokens
        )
        return available

    def prompt_fits(self, prompt: str, system_prompt: str = "") -> bool:
        return self.input_token_budget(system_prompt) >= self.estimate_tokens(prompt)

    def max_prompt_chars(self, system_prompt: str = "") -> int:
        tokens = self.input_token_budget(system_prompt)
        if tokens <= 0:
            return 0
        return max(0, int(tokens * float(self.chars_per_token)))

    @staticmethod
    def for_local(config: Any = None) -> "ContextPolicy":
        try:
            context_limit = int(getattr(config, "context_size", 16384) or 16384)
        except (TypeError, ValueError):
            context_limit = 16384
        context_limit = max(1024, context_limit)
        reserved = getattr(config, "reserved_output_tokens", None)
        if not isinstance(reserved, int) or reserved <= 0:
            try:
                max_tokens = int(getattr(config, "max_tokens", 2048) or 2048)
            except (TypeError, ValueError):
                max_tokens = 2048
            if max_tokens <= 0:
                try:
                    max_tokens = int(
                        getattr(config, "prompt_unbounded_output_reserve_tokens", 2048) or 2048
                    )
                except (TypeError, ValueError):
                    max_tokens = 2048
            reserved = max(1, max_tokens)
        try:
            margin = int(getattr(config, "prompt_safety_margin_tokens", 512) or 0)
        except (TypeError, ValueError):
            margin = 512
        try:
            chars = float(getattr(config, "prompt_chars_per_token", 3.0) or 3.0)
        except (TypeError, ValueError):
            chars = 3.0
        if chars <= 0:
            chars = 3.0
        return ContextPolicy(
            provider_id="local",
            context_limit=context_limit,
            max_output_tokens=int(reserved),
            safety_margin_tokens=max(0, margin),
            chars_per_token=chars,
            prefer_full_context=False,
            compact_before_inference=True,
            retrieved_doc_chars=LOCAL_RETRIEVED_DOC_CHARS,
            expanded_doc_chars=LOCAL_EXPANDED_DOC_CHARS,
            synthesis_chars=LOCAL_SYNTHESIS_CHARS,
            max_prompt_alerts=LOCAL_MAX_PROMPT_ALERTS,
            exact_term_items=LOCAL_EXACT_TERM_ITEMS,
            max_exact_ioc_lines=LOCAL_MAX_EXACT_IOC_LINES,
        )

    @staticmethod
    def for_openai(config: Any, context_limit: int) -> "ContextPolicy":
        try:
            output_tokens = int(getattr(config, "max_output_tokens", 4096) or 4096)
        except (TypeError, ValueError):
            output_tokens = 4096
        try:
            margin = int(getattr(config, "safety_margin_tokens", 1024) or 0)
        except (TypeError, ValueError):
            margin = 1024
        try:
            chars = float(getattr(config, "chars_per_token", 3.5) or 3.5)
        except (TypeError, ValueError):
            chars = 3.5
        if chars <= 0:
            chars = 3.5
        output_tokens = max(1, output_tokens)
        margin = max(0, margin)
        context_limit = int(context_limit)
        available_tokens = context_limit - output_tokens - margin
        available_chars = max(1, int(max(0, available_tokens) * chars))
        return ContextPolicy(
            provider_id="openai",
            context_limit=context_limit,
            max_output_tokens=output_tokens,
            safety_margin_tokens=margin,
            chars_per_token=chars,
            prefer_full_context=True,
            compact_before_inference=False,
            retrieved_doc_chars=available_chars,
            expanded_doc_chars=available_chars,
            synthesis_chars=available_chars,
            max_prompt_alerts=10000,
            exact_term_items=10000,
            max_exact_ioc_lines=10000,
        )


def split_marked_sections(prompt: str) -> list[tuple[str, str]]:
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


def _canonical_name(name: str, known: tuple[str, ...]) -> Optional[str]:
    observed = str(name or "").strip().upper()
    best = None
    for marker in known:
        candidate = marker.upper()
        if observed.startswith(candidate) and (best is None or len(candidate) > len(best)):
            best = marker
    return best


def _render_sections(sections: list[tuple[str, str]]) -> str:
    return "\n\n".join(body for _, body in sections if body).strip()


def _shrink_tail(body: str, target_chars: int) -> str:
    """Keep the section head, including its marker and leading evidence lines."""
    body = str(body or "")
    if len(body) <= target_chars:
        return body
    floor = min(len(body), max(0, target_chars))
    kept = body[:floor].rstrip()
    if kept and not kept.endswith("."):
        kept += "\n[Section reduced to fit the model context window.]"
    return kept


def reduce_prompt_to_budget(prompt: str, max_chars: int) -> tuple[str, bool]:
    """Shrink a shared report prompt without dropping exact IOC evidence first.

    Returns the prompt and whether any reduction was required. Raises
    ContextBudgetError when the prompt has no trustworthy section boundaries
    or when preserving the IOC section and the output contract still does not
    fit. The error text contains lengths only.
    """
    prompt = str(prompt or "")
    max_chars = int(max_chars)
    if max_chars < 0:
        max_chars = 0
    if len(prompt) <= max_chars:
        return prompt, False

    sections = split_marked_sections(prompt)
    if not sections:
        raise ContextBudgetError(
            "Public LLM is unavailable. The report context exceeds the configured "
            f"model window ({len(prompt)} characters; limit {max_chars}) and has no "
            "section boundaries that can be reduced safely."
        )

    known = _SHRINK_LAST + _SHRINK_ALERTS_AFTER_CTI + (_IOC_SECTION,) + _KEEP_INTACT
    mutable = [(name, body) for name, body in sections]
    reduced = False

    def length() -> int:
        return len(_render_sections(mutable))

    def find(target: str) -> Optional[int]:
        for index, (name, _body) in enumerate(mutable):
            if _canonical_name(name, known) == target:
                return index
        return None

    def shrink_named(target: str, floor_chars: int) -> bool:
        nonlocal reduced
        index = find(target)
        if index is None:
            return False
        name, body = mutable[index]
        if len(body) <= floor_chars:
            return False
        updated = _shrink_tail(body, max(floor_chars, int(len(body) * 0.75)))
        if updated == body:
            updated = _shrink_tail(body, floor_chars)
        if updated == body:
            return False
        mutable[index] = (name, updated)
        reduced = True
        return True

    for target in _SHRINK_LAST + _SHRINK_ALERTS_AFTER_CTI:
        while length() > max_chars and shrink_named(target, 240):
            continue

    if length() > max_chars:
        index = find(_IOC_SECTION)
        if index is not None:
            name, body = mutable[index]
            lines = body.splitlines()
            evidence = [line for line in lines if line.strip().startswith("- ") or "exact" in line.lower()]
            header = lines[:2]
            preserved = "\n".join(header + evidence).strip()
            if preserved and len(preserved) < len(body):
                mutable[index] = (name, preserved)
                reduced = True

    text = _render_sections(mutable)
    notice = (
        "\n\n[Context reduced to fit the configured public model window. "
        "Exact IOC evidence was preserved.]\n"
    )
    if len(text) + len(notice) <= max_chars:
        text = text + notice
    if len(text) > max_chars:
        raise ContextBudgetError(
            "Public LLM is unavailable. The report context exceeds the configured "
            f"model window after evidence-preserving reduction "
            f"({len(text)} characters; limit {max_chars})."
        )
    return text, True


@dataclass
class InferenceTelemetry:
    provider: str
    model: str
    input_tokens: int
    output_tokens: int
    llm_request_duration_s: float
    success: bool
    retry_count: int
    context_reduced: bool

    def as_dict(self) -> dict:
        return {
            "provider": self.provider,
            "model": self.model,
            "input_tokens": int(self.input_tokens),
            "output_tokens": int(self.output_tokens),
            "llm_request_duration_s": round(float(self.llm_request_duration_s), 3),
            "success": bool(self.success),
            "retry_count": int(self.retry_count),
            "context_reduced": bool(self.context_reduced),
        }


class LLMProviderController:
    """Backend-owned provider selection. The browser never names a class."""

    def __init__(
        self,
        local_client: Any,
        openai_factory: Callable[[], Any],
        initial: str = "local",
    ):
        self.local_client = local_client
        self._openai_factory = openai_factory
        self._openai_client = None
        self.provider_id = "local"
        self.active = local_client
        if initial and str(initial).strip() and str(initial).strip().lower() not in {"local", "local_llm"}:
            self.select(initial)

    def select(self, value: Any, formatter: Any = None) -> Any:
        provider_id = normalize_provider(value)
        if provider_id == "openai":
            if self._openai_client is None:
                self._openai_client = self._openai_factory()
            client = self._openai_client
        else:
            client = self.local_client
        self.provider_id = provider_id
        self.active = client
        if formatter is not None:
            formatter.llm_client = client
        return client

    def status(self, openai_public: Optional[dict] = None) -> dict:
        openai_public = dict(openai_public or {})
        selected = self.provider_id
        configured = bool(openai_public.get("configured"))
        return {
            "provider": selected,
            "label": report_label(selected),
            "progress_label": progress_label(selected),
            "options": [
                {
                    "id": "local",
                    "label": "Local LLM",
                    "description": (
                        "Runs inference locally. Data remains within the application environment."
                    ),
                    "selected": selected == "local",
                    "external_processing": False,
                },
                {
                    "id": "openai",
                    "label": "Public LLM",
                    "description": (
                        "Uses the configured OpenAI API. Alert and retrieved CTI context "
                        "will be sent to the public LLM provider."
                    ),
                    "selected": selected == "openai",
                    "external_processing": True,
                },
            ],
            "openai": {
                "configured": configured,
                "model": openai_public.get("model") or "",
                "status": "OpenAI API: Configured" if configured else "OpenAI API: Not configured",
                "context_window": openai_public.get("context_window"),
                "max_output_tokens": openai_public.get("max_output_tokens"),
            },
            "external_processing": selected == "openai",
            "notice": (
                "Public LLM. External API processing enabled. Alert and retrieved CTI "
                "context is sent to the configured OpenAI API."
                if selected == "openai"
                else "Local LLM. Inference stays inside the application environment."
            ),
        }
