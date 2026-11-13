"""Visible, durable ledger for analysis jobs.

The ledger records manual uploads, selected-alert jobs, and live high-severity
alerts that have not been approved. It does not store alert bodies or report
text. Payloads for manual and selected jobs stay in memory for the life of the
process; the JSON file only keeps status so a refreshed browser can reattach.
One worker still runs one model job at a time. Approving a report, or removing
a row, deletes that entry.
"""

from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from uuid import uuid4


TERMINAL_STATUSES = {"processed", "failed", "cancelled"}
ACTIVE_STATUSES = {"queued", "running"}
MAX_JOBS = 200


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class AnalysisQueue:
    """Serial job ledger shared by the analysis page and live monitoring."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self._lock = threading.Lock()
        self.jobs: List[Dict[str, Any]] = []
        self.payloads: Dict[str, Dict[str, Any]] = {}
        self._load()

    def recover_interrupted(self) -> None:
        """Mark in-flight work that cannot be resumed after a process restart."""
        with self._lock:
            changed = False
            for job in self.jobs:
                if job.get("status") not in ACTIVE_STATUSES:
                    continue
                if job.get("source") == "live" or job.get("id") not in self.payloads:
                    job["status"] = "failed"
                    job["detail"] = (
                        "The application restarted before this alert was processed. "
                        "A live alert still in the Wazuh file will be queued again; "
                        "a manual upload needs to be submitted again."
                    )
                    job["updated_at"] = _now()
                    changed = True
            if changed:
                self._save_locked()

    def add_manual(
        self,
        *,
        owner: str,
        source: str,
        label: str,
        session_id: str,
        alert_count: int,
        llm_provider: Optional[str],
        payload: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Queue one manual or selected-alert job. The payload stays in memory."""
        job = {
            "id": str(uuid4()),
            "session_id": session_id,
            "owner": owner,
            "source": source,
            "label": label,
            "status": "queued",
            "alert_count": int(alert_count or 0),
            "level": None,
            "created_at": _now(),
            "updated_at": _now(),
            "detail": "Waiting for the single analysis worker.",
            "report_id": None,
            "llm_provider": llm_provider,
        }
        with self._lock:
            self.jobs.append(job)
            self.payloads[job["id"]] = payload
            self._trim_locked()
            self._save_locked()
            return self._public_copy(job)

    def observe_live(self, alert_id: str, label: str, status: str, level: Optional[int] = None) -> None:
        """Insert or update one live alert row. The same hash keeps one row."""
        if not alert_id:
            return
        now = _now()
        with self._lock:
            existing = next((job for job in self.jobs if job.get("id") == alert_id), None)
            if existing is None:
                self.jobs.append({
                    "id": alert_id,
                    "session_id": None,
                    "owner": "monitoring",
                    "source": "live",
                    "label": label or "High-severity alert",
                    "status": status,
                    "alert_count": 1,
                    "level": level,
                    "created_at": now,
                    "updated_at": now,
                    "detail": "",
                    "report_id": None,
                    "llm_provider": None,
                })
            else:
                existing["status"] = status
                existing["label"] = label or existing.get("label")
                existing["level"] = level if level is not None else existing.get("level")
                existing["updated_at"] = now
            self._trim_locked()
            self._save_locked()

    def claim_next_manual(self) -> Optional[Dict[str, Any]]:
        """Mark the oldest queued manual job running and return it."""
        with self._lock:
            for job in self.jobs:
                if job.get("source") == "live" or job.get("status") != "queued":
                    continue
                if job["id"] not in self.payloads:
                    job["status"] = "failed"
                    job["detail"] = "The uploaded alert is no longer available."
                    job["updated_at"] = _now()
                    continue
                job["status"] = "running"
                job["detail"] = "Analysis is running."
                job["updated_at"] = _now()
                self._save_locked()
                return dict(job)
            self._save_locked()
            return None

    def take_payload(self, job_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            return self.payloads.get(job_id)

    def drop_payload(self, job_id: str) -> None:
        with self._lock:
            self.payloads.pop(job_id, None)

    def finish(
        self,
        job_id: str,
        status: str,
        detail: str = "",
        report_id: Optional[str] = None,
    ) -> None:
        with self._lock:
            job = next((item for item in self.jobs if item.get("id") == job_id), None)
            if job is None:
                return
            if job.get("status") == "cancelled" and status != "cancelled":
                self.payloads.pop(job_id, None)
                return
            job["status"] = status
            job["detail"] = detail
            job["updated_at"] = _now()
            if report_id:
                job["report_id"] = report_id
            if status in TERMINAL_STATUSES:
                self.payloads.pop(job_id, None)
            self._save_locked()

    def attach_report(self, job_ids: List[str], report_filename: str) -> None:
        """Remember which saved report a live alert batch produced."""
        if not job_ids or not report_filename:
            return
        wanted = set(job_ids)
        with self._lock:
            changed = False
            for job in self.jobs:
                if job.get("id") in wanted:
                    job["report_filename"] = report_filename
                    job["updated_at"] = _now()
                    changed = True
            if changed:
                self._save_locked()

    def clear_reviewed(self, report_id: Optional[str] = None, report_filename: Optional[str] = None) -> int:
        """Drop queue rows whose report the operator just approved."""
        if not report_id and not report_filename:
            return 0
        with self._lock:
            kept = []
            removed = 0
            for job in self.jobs:
                matches_draft = bool(report_id) and job.get("report_id") == report_id
                matches_file = bool(report_filename) and job.get("report_filename") == report_filename
                if matches_draft or matches_file:
                    self.payloads.pop(job.get("id"), None)
                    removed += 1
                    continue
                kept.append(job)
            if removed:
                self.jobs = kept
                self._save_locked()
            return removed

    def dismiss(self, job_id: str, owner: str) -> Optional[Dict[str, Any]]:
        """Remove one visible row. Live rows are shared; manual rows belong to the owner."""
        with self._lock:
            job = next((item for item in self.jobs if item.get("id") == job_id), None)
            if job is None:
                return None
            if job.get("source") != "live" and job.get("owner") != owner:
                return None
            copy = self._public_copy(job)
            self.jobs = [item for item in self.jobs if item.get("id") != job_id]
            self.payloads.pop(job_id, None)
            self._save_locked()
            return copy

    def cancel(self, job_id: str, owner: str) -> Optional[Dict[str, Any]]:
        """Cancel a manual job owned by this user. Live rows are not cancelled here."""
        with self._lock:
            job = next((item for item in self.jobs if item.get("id") == job_id), None)
            if job is None or job.get("owner") != owner or job.get("source") == "live":
                return None
            if job.get("status") in TERMINAL_STATUSES:
                return self._public_copy(job)
            job["status"] = "cancelled"
            job["detail"] = "Cancelled by the operator."
            job["updated_at"] = _now()
            self.payloads.pop(job_id, None)
            self._save_locked()
            return self._public_copy(job)

    def list_jobs(self, owner: str) -> List[Dict[str, Any]]:
        """Return this user's jobs and the shared live-alert rows, newest first."""
        with self._lock:
            visible = [
                job for job in self.jobs
                if job.get("source") == "live" or job.get("owner") == owner
            ]
            ordered = sorted(visible, key=lambda job: job.get("created_at") or "", reverse=True)
            public = [self._public_copy(job) for job in ordered[:100]]
        queued_ids = [job["id"] for job in reversed(public) if job["status"] == "queued"]
        for job in public:
            if job["status"] == "queued" and job["source"] != "live":
                job["queue_position"] = queued_ids.index(job["id"]) + 1
            elif job["status"] == "running":
                job["queue_position"] = 0
            else:
                job["queue_position"] = None
        return public

    def _public_copy(self, job: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "id": job.get("id"),
            "session_id": job.get("session_id"),
            "owner": job.get("owner"),
            "source": job.get("source"),
            "label": job.get("label"),
            "status": job.get("status"),
            "alert_count": job.get("alert_count"),
            "level": job.get("level"),
            "created_at": job.get("created_at"),
            "updated_at": job.get("updated_at"),
            "detail": job.get("detail") or "",
            "report_id": job.get("report_id"),
            "report_filename": job.get("report_filename"),
            "queue_position": None,
        }

    def _trim_locked(self) -> None:
        if len(self.jobs) <= MAX_JOBS:
            return
        terminal = [job for job in self.jobs if job.get("status") in TERMINAL_STATUSES]
        overflow = len(self.jobs) - MAX_JOBS
        remove_ids = {job["id"] for job in terminal[:overflow]}
        if not remove_ids:
            return
        self.jobs = [job for job in self.jobs if job.get("id") not in remove_ids]

    def _load(self) -> None:
        if not self.path.is_file():
            return
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        jobs = payload.get("jobs") if isinstance(payload, dict) else None
        if isinstance(jobs, list):
            self.jobs = [job for job in jobs if isinstance(job, dict) and job.get("id")]

    def _save_locked(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(".json.tmp")
        temporary.write_text(
            json.dumps({"jobs": self.jobs}, indent=2),
            encoding="utf-8",
        )
        temporary.replace(self.path)
