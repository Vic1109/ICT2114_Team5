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
_THREAD_ENV_KEYS = (
    "OMP_NUM_THREADS",
    "MKL_NUM_THREADS",
    "OPENBLAS_NUM_THREADS",
    "NUMEXPR_NUM_THREADS",
)


def physical_cpu_count() -> int:
    """Count physical cores available to this process, ignoring SMT siblings."""
    if hasattr(os, "sched_getaffinity"):
        allowed = set(os.sched_getaffinity(0))
    else:
        allowed = set(range(os.cpu_count() or 1))
    core_ids = set()
    for cpu in allowed:
        core_path = Path(f"/sys/devices/system/cpu/cpu{cpu}/topology/core_id")
        try:
            core_ids.add(core_path.read_text(encoding="utf-8").strip() or str(cpu))
        except OSError:
            core_ids.add(str(cpu))
    return max(1, len(core_ids) or len(allowed) or 1)


def configure_physical_core_threads() -> int:
    """Bind OpenMP/BLAS and PyTorch intra-op work to one thread per physical core.

    Inter-op threads stay at 1 so six intra-op threads do not fan out into a
    36-thread oversubscription on a 6-core CPU. GPU worker processes set their
    own smaller values before they are spawned.
    """
    count = physical_cpu_count()
    for key in _THREAD_ENV_KEYS:
        os.environ[key] = str(count)
    os.environ["OMP_PLACES"] = "cores"
    os.environ["OMP_PROC_BIND"] = "close"
    os.environ.setdefault("PYTORCH_CUDA_ALLOC_CONF", "expandable_segments:True")
    try:
        import torch
    except Exception:
        return count
    try:
        torch.set_num_threads(count)
    except Exception:
        pass
    try:
        torch.set_num_interop_threads(1)
    except Exception:
        pass
    return count


def limit_blas_threads_for_workers() -> dict[str, str | None]:
    """Return the previous BLAS thread env and pin spawned workers to one thread."""
    saved = {key: os.environ.get(key) for key in _THREAD_ENV_KEYS}
    for key in _THREAD_ENV_KEYS:
        os.environ[key] = "1"
    return saved


def restore_blas_thread_env(saved: dict[str, str | None]) -> None:
    for key, value in saved.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value


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
