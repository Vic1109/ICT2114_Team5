"""Shared runtime helpers for CLI and web entry points.

This module intentionally stays small. It centralizes cross-platform console
encoding setup so main, RAG, reporting, and validation paths do not each carry
their own slightly different stdout/stderr handling.
"""

import sys
from typing import TextIO


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
