"""Append-only, privacy-minimized JSONL audit events."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class AuditLogError(OSError):
    """Raised when a workflow event cannot be durably recorded."""


class AuditLogger:
    """Persist privacy-minimized workflow events with a tamper-evident daily chain."""

    def __init__(self, directory: str | Path = "audit_logs") -> None:
        self.directory = Path(directory)
        self._lock = threading.Lock()

    def record(self, event_type: str, session_id: str, **fields: Any) -> None:
        reserved_fields = {
            "timestamp",
            "event_type",
            "session_ref",
            "previous_event_hash",
            "event_hash",
        }
        if reserved_fields.intersection(fields):
            raise AuditLogError("Audit event contains a reserved field.")
        created_at = datetime.now(timezone.utc)
        safe_event = {
            "timestamp": created_at.isoformat(),
            "event_type": event_type,
            "session_ref": hashlib.sha256(session_id.encode("utf-8")).hexdigest()[:16],
            **fields,
        }
        try:
            self.directory.mkdir(parents=True, exist_ok=True)
            path = self.directory / f"{created_at:%Y-%m-%d}.jsonl"
            with self._lock:
                previous_hash = self._last_event_hash(path)
                safe_event["previous_event_hash"] = previous_hash
                safe_event["event_hash"] = self._event_hash(safe_event)
                serialized = json.dumps(
                    safe_event,
                    ensure_ascii=True,
                    allow_nan=False,
                )
                with path.open("a", encoding="utf-8") as audit_file:
                    audit_file.write(serialized + "\n")
                    audit_file.flush()
                    os.fsync(audit_file.fileno())
        except AuditLogError:
            raise
        except (OSError, TypeError, ValueError) as error:
            raise AuditLogError("Audit event could not be durably recorded.") from error

    @classmethod
    def _last_event_hash(cls, path: Path) -> str | None:
        if not path.exists():
            return None

        previous_hash = None
        chain_started = False
        try:
            contents = path.read_bytes()
            if contents and not contents.endswith(b"\n"):
                raise AuditLogError("Audit log integrity check failed.")
            lines = contents.splitlines()
            for line in lines:
                if not line.strip():
                    continue
                event = json.loads(line)
                if not isinstance(event, dict):
                    raise AuditLogError("Audit log integrity check failed.")
                if "event_hash" not in event:
                    if chain_started:
                        raise AuditLogError("Audit log integrity check failed.")
                    previous_hash = hashlib.sha256(line).hexdigest()
                    continue
                event_hash = event["event_hash"]
                if not isinstance(event_hash, str):
                    raise AuditLogError("Audit log integrity check failed.")
                expected_previous = event.get("previous_event_hash")
                if expected_previous != previous_hash:
                    raise AuditLogError("Audit log integrity check failed.")
                unsigned_event = dict(event)
                unsigned_event.pop("event_hash")
                calculated_hash = cls._event_hash(unsigned_event)
                if not hmac.compare_digest(event_hash, calculated_hash):
                    raise AuditLogError("Audit log integrity check failed.")
                previous_hash = event_hash
                chain_started = True
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
            raise AuditLogError("Audit log integrity check failed.") from error
        return previous_hash

    @staticmethod
    def _event_hash(event: dict[str, Any]) -> str:
        canonical = json.dumps(
            event,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
