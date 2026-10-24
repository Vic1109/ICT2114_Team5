"""Anthropic Messages API provider.

All HTTP calls to the public API live in this module. The rest of the
application talks to the provider through ``generate_response`` and never
sees the API key.
"""

from __future__ import annotations

import json
import logging
import re
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


LOGGER = logging.getLogger("AnthropicProvider")

ANTHROPIC_VERSION = "2023-06-01"

# Context windows for recognized model families. Legacy snapshot dates and
# aliases inherit the family's limit; this does not validate model availability.
# Unknown versions require ANTHROPIC_CONTEXT_WINDOW rather than inheriting a
# shorter prefix such as claude-opus-4.
_CONTEXT_WINDOWS = (
    ("claude-fable-5-1", 1_000_000),
    ("claude-mythos-5-1", 1_000_000),
    ("claude-mythos-preview", 1_000_000),
    ("claude-opus-5-5", 1_000_000),
    ("claude-opus-4-8", 1_000_000),
    ("claude-opus-4-7", 1_000_000),
    ("claude-opus-4-6", 1_000_000),
    ("claude-sonnet-5-5", 1_000_000),
    ("claude-sonnet-4-6", 1_000_000),
    ("claude-haiku-5-5", 1_000_000),
    ("claude-fable-5", 1_000_000),
    ("claude-mythos-5", 1_000_000),
    ("claude-opus-5", 1_000_000),
    ("claude-sonnet-5", 1_000_000),
    ("claude-sonnet-4-5", 200_000),
    ("claude-haiku-4-5", 200_000),
    ("claude-opus-4-5", 200_000),
    ("claude-opus-4-1", 200_000),
    ("claude-3-7-sonnet", 200_000),
    ("claude-3-5-sonnet", 200_000),
    ("claude-3-5-haiku", 200_000),
    ("claude-3-opus", 200_000),
    ("claude-3-haiku", 200_000),
    ("claude-opus-4", 200_000),
    ("claude-sonnet-4", 200_000),
)

_RETRYABLE_STATUS = {429, 500, 502, 503, 504, 529}
_AUTH_STATUS = {401, 403}
_MODEL_STATUS = {404}
# With the pinned 2023-06-01 API version, only these older model families
# accept a non-default temperature. Claude 4.7+ and Mythos reject it; omit
# optional sampling fields for unknown models as well. See Anthropic's model
# deprecations and Sonnet 5.5 migration guide.
_SAMPLING_MODELS = frozenset({
    "claude-3-7-sonnet", "claude-3-5-sonnet", "claude-3-5-haiku",
    "claude-3-opus", "claude-3-haiku", "claude-opus-4", "claude-opus-4-1",
    "claude-opus-4-5", "claude-opus-4-6", "claude-sonnet-4",
    "claude-sonnet-4-5", "claude-sonnet-4-6", "claude-haiku-4-5",
})
_CONTEXT_MARKERS = (
    "prompt_too_long",
    "prompt is too long",
    "input is too long",
    "context limit",
    "context window",
    "context_length",
    "exceed context",
    "exceeds the context",
    "exceeds context",
)


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
    family = re.sub(r"-(?:\d{8}|latest)$", "", name)
    for prefix, limit in _CONTEXT_WINDOWS:
        if family == prefix:
            return limit
    return None


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


class AnthropicTransportError(Exception):
    def __init__(self, message: str, *, status: Optional[int] = None, retryable: bool = False,
                 code: str = "", category: str = "", request_id: str = ""):
        super().__init__(message)
        self.status = status
        self.retryable = retryable
        self.code = code
        self.category = category
        self.request_id = request_id


class UrllibAnthropicTransport:
    """HTTPS client for the Messages API. Uses the stdlib HTTP stack."""

    def __init__(self, api_key: str, base_url: str, workspace_id: str = ""):
        self._api_key = str(api_key or "").strip()
        self._base_url = str(base_url or "").strip().rstrip("/")
        self._workspace_id = str(workspace_id or "").strip()

    def post_message(self, payload: dict, timeout: float) -> dict:
        url = f"{self._base_url}/v1/messages"
        data = json.dumps(payload).encode("utf-8")
        headers = {
            "x-api-key": self._api_key,
            "anthropic-version": ANTHROPIC_VERSION,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        # Keys already scoped to a workspace do not need this header. A key
        # without a workspace scope must name the target workspace explicitly.
        if self._workspace_id:
            headers["anthropic-workspace-id"] = self._workspace_id
        request = urllib.request.Request(
            url,
            data=data,
            headers=headers,
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=max(0.1, float(timeout))) as response:
                raw = response.read()
        except TimeoutError as error:
            raise AnthropicTransportError("timeout", retryable=True, code="timeout") from error
        except urllib.error.HTTPError as error:
            status = int(getattr(error, "code", 0) or 0)
            code = ""
            api_message = ""
            request_id = str(error.headers.get("request-id", "") if error.headers else "")
            try:
                body = error.read(65536).decode("utf-8", errors="replace")
                parsed = json.loads(body) if body else {}
                if isinstance(parsed, dict):
                    request_id = request_id or str(parsed.get("request_id") or "")
                    err = parsed.get("error") or {}
                    if isinstance(err, dict):
                        code = str(err.get("type") or err.get("code") or "")
                        api_message = str(err.get("message") or "")
            except Exception:
                code = ""
            finally:
                error.close()
            # Retain only a fixed category, never the API's raw error message:
            # it may echo user content or configuration values.
            category = _classify_api_error(code, api_message)
            retryable = status in _RETRYABLE_STATUS
            raise AnthropicTransportError(
                f"http_{status}",
                status=status,
                retryable=retryable,
                code=code,
                category=category,
                request_id=request_id,
            ) from None
        except urllib.error.URLError as error:
            reason = getattr(error, "reason", error)
            retryable = isinstance(reason, TimeoutError) or "timed out" in str(error).lower()
            raise AnthropicTransportError(
                "timeout" if retryable else "network",
                retryable=True,
                code="timeout" if retryable else "network",
            ) from None
        try:
            parsed = json.loads(raw.decode("utf-8")) if raw else {}
        except (json.JSONDecodeError, UnicodeDecodeError) as error:
            raise AnthropicTransportError("malformed", retryable=False, code="malformed") from error
        if not isinstance(parsed, dict):
            raise AnthropicTransportError("malformed", retryable=False, code="malformed")
        return parsed


class AnthropicProvider:
    """Public LLM provider. Prompt text is supplied by the shared report pipeline."""

    provider_id = "anthropic"
    provider_label = "Anthropic"

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
        return ContextPolicy.for_public(self.config, window)

    def availability_error(self) -> Optional[str]:
        if self._shutdown:
            return "Public LLM is unavailable. Report generation is shutting down."
        if not str(getattr(self.config, "api_key", "") or "").strip():
            return (
                "Public LLM is unavailable. The Anthropic API key has not been configured. "
                "Configure the server environment and try again."
            )
        if not str(getattr(self.config, "model", "") or "").strip():
            return (
                "Public LLM is unavailable. ANTHROPIC_MODEL has not been configured."
            )
        if self._context_window() is None:
            return (
                "Public LLM is unavailable. The configured model has no known context "
                "window. Set ANTHROPIC_CONTEXT_WINDOW and try again."
            )
        policy = self.context_policy()
        if policy.input_token_budget("") <= 0:
            return (
                "Public LLM is unavailable. The configured output budget and safety "
                "margin leave no room for a prompt. Reduce ANTHROPIC_MAX_OUTPUT_TOKENS "
                "or increase ANTHROPIC_CONTEXT_WINDOW."
            )
        base_url = str(getattr(self.config, "base_url", "") or "")
        if not _https_base_url(base_url):
            return "Public LLM is unavailable. ANTHROPIC_BASE_URL must be an https URL."
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
        self.last_context_reduced = False
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
            # A successful HTTP response can still contain a truncated draft,
            # refusal, or pending tool turn. Record billed usage before rejecting
            # it, and never pass partial text to the report formatter's repair
            # or deterministic-fallback paths.
            usage = _extract_usage(parsed)
            if usage.get("input_tokens"):
                input_tokens = int(usage["input_tokens"])
            output_tokens = int(usage.get("output_tokens") or 0)
            if self._cancel.is_set() or self._shutdown:
                raise ProviderRequestError("Public LLM is unavailable. Report generation was cancelled.")
            _require_completed_turn(parsed)
            content = _extract_completion(parsed)
            if not output_tokens:
                output_tokens = estimate_tokens(content, policy.chars_per_token)
            if not str(content or "").strip():
                raise ProviderRequestError(
                    "Public LLM is unavailable. The Anthropic response did not contain report text."
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
                "Public LLM is unavailable. The Anthropic request failed. Check server logs and try again."
            ) from None
        finally:
            self.last_inference_telemetry = InferenceTelemetry(
                provider="anthropic",
                model=str(getattr(self.config, "model", "") or ""),
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                llm_request_duration_s=time.monotonic() - started,
                success=success,
                retry_count=retries,
                context_reduced=bool(reduced or self.last_context_reduced),
            ).as_dict()

    def _build_payload(self, system_prompt: str, prompt: str, policy: ContextPolicy) -> dict:
        model = str(self.config.model).strip()
        payload = {
            "model": model,
            "max_tokens": int(policy.max_output_tokens),
            "messages": [{"role": "user", "content": prompt}],
        }
        # Match the complete legacy family, optionally followed by an eight
        # digit snapshot date. A prefix such as claude-opus-4 must not also
        # match claude-opus-4-7, which rejects temperature=0.2.
        family = re.sub(r"-(?:\d{8}|latest)$", "", model.lower())
        if family in _SAMPLING_MODELS:
            temperature = _safe_float(getattr(self.config, "temperature", 0.2), 0.2)
            payload["temperature"] = min(1.0, max(0.0, temperature))
        if system_prompt.strip():
            payload["system"] = system_prompt
        return payload

    def _post_with_retries(self, payload: dict) -> tuple[dict, int]:
        max_transient = max(0, min(4, _safe_int(getattr(self.config, "max_retries", 2), 2)))
        timeout = max(1, _safe_int(getattr(self.config, "timeout", 120), 120))
        transport = self._transport or UrllibAnthropicTransport(
            str(self.config.api_key),
            str(self.config.base_url),
            str(getattr(self.config, "workspace_id", "") or ""),
        )
        corrective_reduction_used = False
        transient_retries = 0
        retries = 0
        while True:
            if self._cancel.is_set() or self._shutdown:
                raise ProviderRequestError("Public LLM is unavailable. Report generation was cancelled.")
            try:
                return transport.post_message(payload, timeout), retries
            except AnthropicTransportError as error:
                # Log only bounded metadata. API error bodies can contain
                # telemetry or credentials and must not enter server logs.
                code = str(error.code or "")
                safe_code = code if code in {
                    "authentication_error", "permission_error", "not_found_error",
                    "invalid_request_error", "rate_limit_error", "api_error",
                    "overloaded_error", "billing_error", "request_too_large",
                    "prompt_too_long", "context_length_exceeded", "invalid_api_key",
                    "model_not_found", "invalid_model", "rate_limit_exceeded",
                    "timeout", "network", "malformed",
                } else "unknown"
                request_id = str(error.request_id or "")
                safe_request_id = request_id if re.fullmatch(r"req_[A-Za-z0-9_-]{1,120}", request_id) else "unavailable"
                safe_request_id = redact_secret(safe_request_id, str(self.config.api_key).strip())
                category = error.category if error.category in {
                    "prompt_too_long", "workspace", "billing", "sampling_parameters",
                } else "unspecified"
                LOGGER.warning(
                    "Anthropic request rejected status=%s type=%s category=%s request_id=%s",
                    error.status, safe_code, category, safe_request_id,
                )
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
        system = str(payload.get("system") or "")
        user_index = None
        for index, message in enumerate(messages):
            if isinstance(message, dict) and message.get("role") == "user":
                user_index = index
                break
        if user_index is None:
            raise ContextBudgetError(
                "Public LLM is unavailable. The report context exceeds the configured model window."
            )
        policy = self.context_policy()
        original = str(messages[user_index].get("content") or "")
        # The server can reject a prompt below our character-based estimate.
        # Reduce the actual request as well as the estimated window so the
        # corrective retry cannot resend the identical oversized prompt.
        tighter = max(0, int(min(len(original), policy.max_prompt_chars(system)) * 0.75))
        reduced, _changed = reduce_prompt_to_budget(original, tighter)
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


def _message_is_context_overflow(code: str, message: str) -> bool:
    blob = f"{code} {message}".lower()
    return any(marker in blob for marker in _CONTEXT_MARKERS)


def _classify_api_error(code: str, message: str) -> str:
    """Classify common 400 failures without retaining the raw API response."""
    text = str(message or "").lower()
    if _message_is_context_overflow(code, message):
        return "prompt_too_long"
    if "workspace" in text:
        return "workspace"
    if any(token in text for token in ("credit balance", "billing", "spend limit", "spending limit")):
        return "billing"
    if any(token in text for token in ("temperature", "top_p", "top_k")):
        return "sampling_parameters"
    return ""


def _is_context_error(error: AnthropicTransportError) -> bool:
    return error.category == "prompt_too_long" or _message_is_context_overflow(str(error.code or ""), str(error))


def _public_error_message(error: AnthropicTransportError) -> str:
    status = error.status
    code = str(error.code or "").lower()
    if error.category == "workspace":
        return (
            "Public LLM is unavailable. The Anthropic API rejected the workspace selection. "
            "Check ANTHROPIC_WORKSPACE_ID and the API key's workspace access."
        )
    if status == 402 or code == "billing_error" or error.category == "billing":
        return (
            "Public LLM is unavailable. The Anthropic account has a billing or spending-limit issue. "
            "Check the account's API credits and limits."
        )
    if error.category == "sampling_parameters":
        return (
            "Public LLM is unavailable. The Anthropic model rejected sampling settings. "
            "Use a request without temperature, top_p, or top_k for this model."
        )
    if status in _AUTH_STATUS or code in {"invalid_api_key", "authentication_error", "permission_error"}:
        return (
            "Public LLM is unavailable. The Anthropic API rejected the configured credentials. "
            "Check the server environment and try again."
        )
    if status in _MODEL_STATUS or code in {"model_not_found", "invalid_model", "not_found_error"}:
        return (
            "Public LLM is unavailable. The configured Anthropic model was rejected. "
            "Check ANTHROPIC_MODEL and try again."
        )
    if _is_context_error(error):
        return (
            "Public LLM is unavailable. The report context exceeds the configured model window."
        )
    if status == 429 or code in {"rate_limit_exceeded", "rate_limit_error"}:
        return (
            "Public LLM is unavailable. The Anthropic API rate limit was reached. Wait and try again."
        )
    if status == 529 or code == "overloaded_error":
        return (
            "Public LLM is unavailable. The Anthropic API is overloaded. Wait and try again."
        )
    if code == "timeout" or error.status is None and "timeout" in str(error):
        return (
            "Public LLM is unavailable. The Anthropic request timed out. "
            "Try again or increase ANTHROPIC_TIMEOUT."
        )
    if code == "network":
        return "Public LLM is unavailable. The Anthropic API could not be reached."
    if code == "malformed":
        return "Public LLM is unavailable. The Anthropic response was not usable."
    if status == 400 or code == "invalid_request_error":
        return (
            "Public LLM is unavailable. The Anthropic API rejected the request settings. "
            "Check the configured model, output token limit, and server log request ID."
        )
    return "Public LLM is unavailable. The Anthropic API returned an error. Check server logs and try again."


def _extract_usage(payload: dict) -> dict:
    usage = payload.get("usage") if isinstance(payload.get("usage"), dict) else {}
    return {
        "input_tokens": _safe_int(usage.get("input_tokens"), 0),
        "output_tokens": _safe_int(usage.get("output_tokens"), 0),
    }


def _require_completed_turn(payload: dict) -> None:
    """Accept only a naturally completed Messages API response.

    This provider sends neither tools nor stop sequences and does not implement
    conversation continuation. Even a draft containing every report heading is
    incomplete when the API reports a limit or a pending turn. Do not retry here:
    another successful API request can be billed and needs an explicit decision.
    See https://platform.claude.com/docs/en/build-with-claude/handling-stop-reasons.
    """
    stop_reason = payload.get("stop_reason")
    if stop_reason == "end_turn":
        return
    if stop_reason == "max_tokens":
        message = (
            "Public LLM report is incomplete. Anthropic reached the output token limit. "
            "Increase ANTHROPIC_MAX_OUTPUT_TOKENS within the model's limits or reduce "
            "the report scope, then generate the report again."
        )
    elif stop_reason == "model_context_window_exceeded":
        message = (
            "Public LLM report is incomplete. Anthropic reached the model's context window. "
            "Reduce the report scope or configure a model with a larger context window, "
            "then generate the report again."
        )
    elif stop_reason == "refusal":
        message = (
            "Public LLM report was not generated. Anthropic declined the request. "
            "Review the request and source material before trying again."
        )
    elif stop_reason == "tool_use":
        message = (
            "Public LLM report is incomplete. Anthropic requested tool execution, which "
            "this report provider does not support. Review the configured model and "
            "API endpoint before trying again."
        )
    elif stop_reason == "pause_turn":
        message = (
            "Public LLM report is incomplete. Anthropic paused the response and requires "
            "continuation, which this report provider does not support. Review the "
            "configured model and API endpoint before trying again."
        )
    elif stop_reason == "stop_sequence":
        message = (
            "Public LLM report is incomplete. Anthropic stopped at a custom stop sequence "
            "that this report provider did not request. Review the API endpoint before "
            "trying again."
        )
    else:
        # Missing, null, malformed, and future values must not imply success.
        # Never echo an untrusted stop reason or any partial response text.
        message = (
            "Public LLM response was not usable. Anthropic did not confirm a completed "
            "response. Check the configured API endpoint and server configuration "
            "before trying again."
        )
    raise ProviderRequestError(message)


def _extract_completion(payload: dict) -> str:
    content = payload.get("content")
    if isinstance(content, list):
        parts = []
        for item in content:
            if isinstance(item, dict) and item.get("type") == "text" and item.get("text"):
                parts.append(str(item.get("text")))
            elif isinstance(item, str):
                parts.append(item)
        content = "\n".join(parts)
    elif not isinstance(content, str):
        content = None
    if content is None:
        raise ProviderRequestError(
            "Public LLM is unavailable. The Anthropic response was not usable."
        )
    return str(content or "")


def log_transport_failure(error: BaseException, secret: str = "") -> None:
    """Diagnostic log helper that cannot retain an API key."""
    LOGGER.error(
        "Anthropic transport failure (%s) %s",
        type(error).__name__,
        redact_secret(str(error), secret)[:240],
    )
