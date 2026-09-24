"""OpenAI chat-completions provider.

All HTTP calls to the public API live in this module. The rest of the
application talks to the provider through ``generate_response`` and never
sees the API key.
"""

from __future__ import annotations

import json
import logging
import threading
import time
import urllib.error
import urllib.request
from typing import Any, Callable, Optional
from urllib.parse import urlparse

from llm_provider import (
    ContextBudgetError,
    ContextPolicy,
    InferenceTelemetry,
    ProviderRequestError,
    estimate_tokens,
    redact_secret,
    reduce_prompt_to_budget,
)


LOGGER = logging.getLogger("OpenAIProvider")

# Documented context windows for models this deployment knows how to budget.
# Longer prefixes are matched first. Unknown models require OPENAI_CONTEXT_WINDOW
# rather than an invented limit. Operators can override any entry.
_CONTEXT_WINDOWS = (
    ("gpt-4.1-nano", 1_047_576),
    ("gpt-4.1-mini", 1_047_576),
    ("gpt-4.1", 1_047_576),
    ("gpt-4o-mini", 128_000),
    ("gpt-4o", 128_000),
    ("gpt-4-turbo", 128_000),
    ("gpt-3.5-turbo", 16_385),
    ("o4-mini", 200_000),
    ("o3-mini", 200_000),
    ("o3", 200_000),
    ("o1-mini", 128_000),
    ("o1", 200_000),
)

_RETRYABLE_STATUS = {429, 500, 502, 503, 504}
_AUTH_STATUS = {401, 403}
_MODEL_STATUS = {404}


def resolve_context_window(model: str, configured_window: int = 0) -> Optional[int]:
    """Return the context window for a model, or None when it is unknown."""
    try:
        override = int(configured_window or 0)
    except (TypeError, ValueError):
        override = 0
    if override > 0:
        return override
    name = str(model or "").strip().lower()
    if not name:
        return None
    matches = [limit for prefix, limit in _CONTEXT_WINDOWS if name == prefix or name.startswith(prefix + "-")]
    if not matches:
        for prefix, limit in _CONTEXT_WINDOWS:
            if name.startswith(prefix):
                matches.append(limit)
    if not matches:
        return None
    return matches[0]


def _safe_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _safe_float(value: Any, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


class OpenAITransportError(Exception):
    def __init__(self, message: str, *, status: Optional[int] = None, retryable: bool = False, code: str = ""):
        super().__init__(message)
        self.status = status
        self.retryable = retryable
        self.code = code


class UrllibOpenAITransport:
    """HTTPS client for the Chat Completions API. Uses the stdlib HTTP stack."""

    def __init__(self, api_key: str, base_url: str):
        self._api_key = str(api_key or "")
        self._base_url = str(base_url or "").rstrip("/")

    def post_chat(self, payload: dict, timeout: float) -> dict:
        url = f"{self._base_url}/chat/completions"
        data = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            url,
            data=data,
            headers={
                "Authorization": f"Bearer {self._api_key}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=max(0.1, float(timeout))) as response:
                raw = response.read()
        except TimeoutError as error:
            raise OpenAITransportError("timeout", retryable=True, code="timeout") from error
        except urllib.error.HTTPError as error:
            status = int(getattr(error, "code", 0) or 0)
            code = ""
            try:
                body = error.read().decode("utf-8", errors="replace")
                parsed = json.loads(body) if body else {}
                if isinstance(parsed, dict):
                    err = parsed.get("error") or {}
                    if isinstance(err, dict):
                        code = str(err.get("code") or err.get("type") or "")
            except Exception:
                code = ""
            retryable = status in _RETRYABLE_STATUS
            raise OpenAITransportError(
                f"http_{status}",
                status=status,
                retryable=retryable,
                code=code,
            ) from None
        except urllib.error.URLError as error:
            reason = getattr(error, "reason", error)
            retryable = isinstance(reason, TimeoutError) or "timed out" in str(error).lower()
            raise OpenAITransportError(
                "timeout" if retryable else "network",
                retryable=True,
                code="timeout" if retryable else "network",
            ) from None
        try:
            parsed = json.loads(raw.decode("utf-8")) if raw else {}
        except json.JSONDecodeError as error:
            raise OpenAITransportError("malformed", retryable=False, code="malformed") from error
        if not isinstance(parsed, dict):
            raise OpenAITransportError("malformed", retryable=False, code="malformed")
        return parsed


class OpenAIProvider:
    """Public LLM provider. Prompt text is supplied by the shared report pipeline."""

    provider_id = "openai"
    provider_label = "OpenAI"

    def __init__(
        self,
        config: Any,
        system_prompt_reader: Optional[Callable[[], str]] = None,
        transport: Any = None,
    ):
        self.config = config
        self._system_prompt_reader = system_prompt_reader or (lambda: "")
        self._transport = transport
        self._lock = threading.RLock()
        self._cancel = threading.Event()
        self._shutdown = False
        self.last_inference_telemetry: dict = {}
        self.last_context_reduced = False

    def context_policy(self) -> ContextPolicy:
        window = self._context_window()
        if window is None:
            window = 0
        return ContextPolicy.for_openai(self.config, window)

    def availability_error(self) -> Optional[str]:
        if self._shutdown:
            return "Public LLM is unavailable. Report generation is shutting down."
        if not str(getattr(self.config, "api_key", "") or "").strip():
            return (
                "Public LLM is unavailable. The OpenAI API key has not been configured. "
                "Configure the server environment and try again."
            )
        if not str(getattr(self.config, "model", "") or "").strip():
            return (
                "Public LLM is unavailable. OPENAI_MODEL has not been configured."
            )
        if self._context_window() is None:
            return (
                "Public LLM is unavailable. The configured model has no known context "
                "window. Set OPENAI_CONTEXT_WINDOW and try again."
            )
        policy = self.context_policy()
        if policy.input_token_budget("") <= 0:
            return (
                "Public LLM is unavailable. The configured output budget and safety "
                "margin leave no room for a prompt. Reduce OPENAI_MAX_OUTPUT_TOKENS "
                "or increase OPENAI_CONTEXT_WINDOW."
            )
        base_url = str(getattr(self.config, "base_url", "") or "")
        if not _https_base_url(base_url):
            return "Public LLM is unavailable. OPENAI_BASE_URL must be an https URL."
        return None

    def prepare_generation(self) -> bool:
        with self._lock:
            if self._shutdown:
                return False
            self._cancel.clear()
        return True

    def cancel_active_generations(self, *, permanent: bool = False) -> int:
        with self._lock:
            if permanent:
                self._shutdown = True
            self._cancel.set()
        return 0

    def close(self) -> None:
        self.cancel_active_generations(permanent=True)

    def generate_response(self, user_message: str) -> str:
        started = time.monotonic()
        retries = 0
        reduced = False
        success = False
        input_tokens = 0
        output_tokens = 0
        try:
            message = self.availability_error()
            if message:
                raise ProviderRequestError(message)
            if self._cancel.is_set():
                raise ProviderRequestError("Public LLM is unavailable. Report generation was cancelled.")

            system_prompt = str(self._system_prompt_reader() or "")
            policy = self.context_policy()
            prompt = str(user_message or "")
            max_chars = policy.max_prompt_chars(system_prompt)
            if max_chars <= 0:
                raise ProviderRequestError(
                    "Public LLM is unavailable. The configured context window cannot hold a prompt."
                )
            if not policy.prompt_fits(prompt, system_prompt):
                prompt, reduced = reduce_prompt_to_budget(prompt, max_chars)
                if not policy.prompt_fits(prompt, system_prompt):
                    raise ContextBudgetError(
                        "Public LLM is unavailable. The report context exceeds the configured "
                        "model window after evidence-preserving reduction."
                    )
                LOGGER.warning(
                    "Public LLM context reduced to fit model window "
                    "(context_limit=%s reserved_output=%s margin=%s)",
                    policy.context_limit,
                    policy.max_output_tokens,
                    policy.safety_margin_tokens,
                )
            self.last_context_reduced = reduced
            input_tokens = policy.estimate_tokens(system_prompt) + policy.estimate_tokens(prompt)
            payload = self._build_payload(system_prompt, prompt, policy)
            parsed, retries = self._post_with_retries(payload)
            content, usage = _extract_completion(parsed)
            if usage.get("prompt_tokens"):
                input_tokens = int(usage["prompt_tokens"])
            output_tokens = int(usage.get("completion_tokens") or estimate_tokens(content, policy.chars_per_token))
            if not str(content or "").strip():
                raise ProviderRequestError(
                    "Public LLM is unavailable. The OpenAI response did not contain report text."
                )
            success = True
            return str(content)
        except ProviderRequestError:
            raise
        except Exception as error:
            LOGGER.error(
                "Public LLM request failed (%s)",
                type(error).__name__,
            )
            raise ProviderRequestError(
                "Public LLM is unavailable. The OpenAI request failed. Check server logs and try again."
            ) from None
        finally:
            self.last_inference_telemetry = InferenceTelemetry(
                provider="openai",
                model=str(getattr(self.config, "model", "") or ""),
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                llm_request_duration_s=time.monotonic() - started,
                success=success,
                retry_count=retries,
                context_reduced=bool(reduced or self.last_context_reduced),
            ).as_dict()

    def _build_payload(self, system_prompt: str, prompt: str, policy: ContextPolicy) -> dict:
        messages = []
        if system_prompt.strip():
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})
        temperature = _safe_float(getattr(self.config, "temperature", 0.2), 0.2)
        temperature = min(2.0, max(0.0, temperature))
        return {
            "model": str(self.config.model),
            "messages": messages,
            "max_tokens": int(policy.max_output_tokens),
            "temperature": temperature,
        }

    def _post_with_retries(self, payload: dict) -> tuple[dict, int]:
        max_transient = max(0, min(4, _safe_int(getattr(self.config, "max_retries", 2), 2)))
        timeout = max(1, _safe_int(getattr(self.config, "timeout", 120), 120))
        transport = self._transport or UrllibOpenAITransport(
            str(self.config.api_key),
            str(self.config.base_url),
        )
        corrective_reduction_used = False
        transient_retries = 0
        retries = 0
        while True:
            if self._cancel.is_set() or self._shutdown:
                raise ProviderRequestError("Public LLM is unavailable. Report generation was cancelled.")
            try:
                return transport.post_chat(payload, timeout), retries
            except OpenAITransportError as error:
                message = _public_error_message(error)
                context_exceeded = _is_context_error(error)
                if context_exceeded and not corrective_reduction_used:
                    corrective_reduction_used = True
                    payload = self._shrink_payload(payload)
                    retries += 1
                    LOGGER.warning("Public LLM rejected the context size; retrying once after reduction")
                    continue
                if error.retryable and not context_exceeded and transient_retries < max_transient:
                    transient_retries += 1
                    retries += 1
                    delay = min(2.0, 0.4 * (2 ** (transient_retries - 1)))
                    LOGGER.warning(
                        "Public LLM transient failure status=%s retry=%s",
                        error.status,
                        retries,
                    )
                    if self._cancel.wait(delay):
                        raise ProviderRequestError(
                            "Public LLM is unavailable. Report generation was cancelled."
                        )
                    continue
                raise ProviderRequestError(message) from None

    def _shrink_payload(self, payload: dict) -> dict:
        messages = list(payload.get("messages") or [])
        system = ""
        user_index = None
        for index, message in enumerate(messages):
            if not isinstance(message, dict):
                continue
            if message.get("role") == "system" and not system:
                system = str(message.get("content") or "")
            if message.get("role") == "user":
                user_index = index
        if user_index is None:
            raise ContextBudgetError(
                "Public LLM is unavailable. The report context exceeds the configured model window."
            )
        policy = self.context_policy()
        tighter = max(256, int(policy.max_prompt_chars(system) * 0.75))
        reduced, _changed = reduce_prompt_to_budget(str(messages[user_index].get("content") or ""), tighter)
        messages[user_index] = {"role": "user", "content": reduced}
        updated = dict(payload)
        updated["messages"] = messages
        self.last_context_reduced = True
        return updated

    def _context_window(self) -> Optional[int]:
        return resolve_context_window(
            str(getattr(self.config, "model", "") or ""),
            _safe_int(getattr(self.config, "context_window", 0), 0),
        )


def _https_base_url(value: str) -> bool:
    parsed = urlparse(str(value or "").strip())
    return parsed.scheme == "https" and bool(parsed.netloc)


def _is_context_error(error: OpenAITransportError) -> bool:
    code = str(error.code or "").lower()
    return "context" in code or "length" in code or "token" in code


def _public_error_message(error: OpenAITransportError) -> str:
    status = error.status
    code = str(error.code or "").lower()
    if status in _AUTH_STATUS or code in {"invalid_api_key", "authentication_error"}:
        return (
            "Public LLM is unavailable. The OpenAI API rejected the configured credentials. "
            "Check the server environment and try again."
        )
    if status in _MODEL_STATUS or code in {"model_not_found", "invalid_model"}:
        return (
            "Public LLM is unavailable. The configured OpenAI model was rejected. "
            "Check OPENAI_MODEL and try again."
        )
    if _is_context_error(error):
        return (
            "Public LLM is unavailable. The report context exceeds the configured model window."
        )
    if status == 429 or code == "rate_limit_exceeded":
        return (
            "Public LLM is unavailable. The OpenAI API rate limit was reached. Wait and try again."
        )
    if code == "timeout" or error.status is None and "timeout" in str(error):
        return (
            "Public LLM is unavailable. The OpenAI request timed out. "
            "Try again or increase OPENAI_TIMEOUT."
        )
    if code == "network":
        return "Public LLM is unavailable. The OpenAI API could not be reached."
    if code == "malformed":
        return "Public LLM is unavailable. The OpenAI response was not usable."
    return "Public LLM is unavailable. The OpenAI API returned an error. Check server logs and try again."


def _extract_completion(payload: dict) -> tuple[str, dict]:
    choices = payload.get("choices")
    if not isinstance(choices, list) or not choices:
        raise ProviderRequestError(
            "Public LLM is unavailable. The OpenAI response was not usable."
        )
    first = choices[0] if isinstance(choices[0], dict) else {}
    message = first.get("message") if isinstance(first.get("message"), dict) else {}
    content = message.get("content")
    if isinstance(content, list):
        parts = []
        for item in content:
            if isinstance(item, dict) and item.get("text"):
                parts.append(str(item.get("text")))
            elif isinstance(item, str):
                parts.append(item)
        content = "\n".join(parts)
    if content is None:
        content = first.get("text")
    usage = payload.get("usage") if isinstance(payload.get("usage"), dict) else {}
    return str(content or ""), {
        "prompt_tokens": _safe_int(usage.get("prompt_tokens"), 0),
        "completion_tokens": _safe_int(usage.get("completion_tokens"), 0),
    }


def log_transport_failure(error: BaseException, secret: str = "") -> None:
    """Diagnostic log helper that cannot retain an API key."""
    LOGGER.error(
        "OpenAI transport failure (%s) %s",
        type(error).__name__,
        redact_secret(str(error), secret)[:240],
    )
