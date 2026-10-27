"""Run a read-only sample of Windows evidence collectors and print a safe summary."""

from __future__ import annotations

import ctypes
import json
import platform
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from diagnostic_intelligence.collectors.windows import WindowsEvidenceCollector
from diagnostic_intelligence.models.classification import Category
from diagnostic_intelligence.models.diagnostic_plan import (
    DiagnosticPlan,
    EvidenceRequest,
    Priority,
)
from diagnostic_intelligence.models.evidence import EvidenceType


_SMOKE_EVIDENCE = (
    EvidenceType.CPU_METRICS,
    EvidenceType.MEMORY_METRICS,
    EvidenceType.STORAGE_CAPACITY,
    EvidenceType.DISK_ACTIVITY,
    EvidenceType.PROCESS_SUMMARY,
    EvidenceType.STORAGE_ERRORS,
    EvidenceType.ADAPTER_STATUS,
    EvidenceType.SYSTEM_EVENTS,
    EvidenceType.RELIABILITY_SUMMARY,
    EvidenceType.APPLICATION_LOGS,
    EvidenceType.RUNTIME_VERSIONS,
    EvidenceType.APPLICATION_STARTUP,
    EvidenceType.DEVICE_STATUS,
    EvidenceType.DRIVER_DETAILS,
    EvidenceType.DRIVER_EVENTS,
    EvidenceType.UPDATE_HISTORY,
)


def _is_elevated() -> bool | None:
    if platform.system() != "Windows":
        return None
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return None


def _summary(record) -> dict[str, object]:
    data = record.data
    counts = {
        EvidenceType.APPLICATION_LOGS: len(data.get("errors", [])),
        EvidenceType.RUNTIME_VERSIONS: len(data.get("runtimes", [])),
        EvidenceType.DEVICE_STATUS: len(data.get("devices", [])),
        EvidenceType.DRIVER_DETAILS: len(data.get("drivers", [])),
        EvidenceType.DRIVER_EVENTS: len(data.get("events", [])),
        EvidenceType.UPDATE_HISTORY: len(data.get("updates", [])),
        EvidenceType.SYSTEM_EVENTS: len(data.get("events", [])),
        EvidenceType.STORAGE_ERRORS: len(data.get("events", [])),
        EvidenceType.RELIABILITY_SUMMARY: len(data.get("incidents", [])),
        EvidenceType.ADAPTER_STATUS: len(data.get("adapters", [])),
        EvidenceType.PROCESS_SUMMARY: len(data.get("processes", [])),
        EvidenceType.STORAGE_CAPACITY: len(data.get("volumes", [])),
    }
    summary: dict[str, object] = {
        "evidence_type": record.evidence_type.value,
        "status": record.status.value,
    }
    if record.error:
        summary["error"] = record.error
    elif isinstance(data.get("reason"), str):
        summary["reason"] = data["reason"]
    elif record.evidence_type in counts:
        summary["record_count"] = counts[record.evidence_type]
    elif record.evidence_type == EvidenceType.CPU_METRICS:
        summary["sample_count"] = len(data.get("samples", []))
    else:
        summary["collected"] = True
    if record.evidence_type == EvidenceType.DEVICE_STATUS:
        summary["checked_device_count"] = data.get("checked_device_count", 0)
    return summary


def main() -> int:
    requests = [
        EvidenceRequest(
            evidence_id=f"smoke.{evidence_type.value.replace('.', '_')}",
            evidence_type=evidence_type,
            purpose="Read-only Windows smoke check.",
            priority=Priority.LOW,
            required=False,
            privacy_notes="Do not output raw records, paths, messages, or identifiers.",
        )
        for evidence_type in _SMOKE_EVIDENCE
    ]
    plan = DiagnosticPlan(
        session_id="read-only-windows-smoke",
        category=Category.UNKNOWN,
        evidence_requests=requests,
        reasoning_summary="Read-only local collector validation; no remediation.",
    )
    records = WindowsEvidenceCollector().collect_for_plan(plan)
    payload = {
        "platform": platform.platform(),
        "windows_host": platform.system() == "Windows",
        "elevated": _is_elevated(),
        "system_changes_performed": False,
        "network_probes_performed": False,
        "evidence": [_summary(record) for record in records],
    }
    print(json.dumps(payload, indent=2))
    return 1 if any(record.status.value == "error" for record in records) else 0


if __name__ == "__main__":
    raise SystemExit(main())
