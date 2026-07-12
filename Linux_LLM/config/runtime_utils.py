"""Shared runtime helpers for CLI and web entry points.

This module intentionally stays small. It centralizes cross-platform console
encoding setup so main, RAG, reporting, and validation paths do not each carry
their own slightly different stdout/stderr handling.
"""

import logging
import os
import re
import sys
import tempfile
import traceback
from pathlib import Path
from typing import TextIO


LOGGER = logging.getLogger("soc.runtime")
PROJECT_ROOT = Path(__file__).resolve().parents[2]


def atomic_write_text(path: Path | str, content: str) -> None:
    """Publish a UTF-8 text file atomically with private report permissions."""
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
    temporary_name = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=destination.parent,
            prefix=f".{destination.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary_name = handle.name
            handle.write(str(content))
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary_name, 0o640)
        os.replace(temporary_name, destination)
    finally:
        if temporary_name and os.path.exists(temporary_name):
            os.unlink(temporary_name)


def configure_console_encoding(
    encoding: str = "utf-8",
    errors: str = "replace",
    streams: tuple[TextIO | None, ...] | None = None,
) -> None:
    """Best-effort UTF-8 console setup for cross-platform logs."""
    target_streams = streams or (getattr(sys, "stdout", None), getattr(sys, "stderr", None))
    for stream in target_streams:
        if stream is None or not hasattr(stream, "reconfigure"):
            continue
        try:
            stream.reconfigure(encoding=encoding, errors=errors)
        except Exception:
            continue


def _safe_frame_path(filename: str) -> str:
    """Return a repository-relative path or a basename, never a host path."""
    path = Path(str(filename or "unknown"))
    try:
        return path.resolve().relative_to(PROJECT_ROOT).as_posix()
    except (OSError, ValueError):
        return path.name or "unknown"


def sanitized_traceback(error: BaseException, max_frames: int = 12) -> str:
    """Format bounded stack locations without exception text or absolute paths."""
    limit = max(1, min(int(max_frames), 32))
    frames = traceback.extract_tb(error.__traceback__)
    rendered = []
    for frame in frames[-limit:]:
        function_name = re.sub(r"[^A-Za-z0-9_.<>-]", "?", frame.name)[:80]
        rendered.append(
            f"{_safe_frame_path(frame.filename)}:{int(frame.lineno)}:{function_name}"
        )
    return " <- ".join(rendered) if rendered else "no-python-frame"


def log_sanitized_exception(
    event: str,
    error: BaseException,
    *,
    logger: logging.Logger | None = None,
    level: int = logging.ERROR,
) -> None:
    """Log failure location/type while withholding exception messages and secrets."""
    safe_event = re.sub(r"[^A-Za-z0-9 _.,:/()-]", "?", str(event or "Runtime failure"))[:160]
    (logger or LOGGER).log(
        level,
        "%s (%s); stack=%s",
        safe_event,
        type(error).__name__,
        sanitized_traceback(error),
    )
