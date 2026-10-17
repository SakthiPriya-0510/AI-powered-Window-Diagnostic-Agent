"""Rule-based, targeted planning for approved collector evidence types."""

from diagnostic_intelligence.models.classification import Category, ProblemUnderstanding
from diagnostic_intelligence.models.diagnostic_plan import DiagnosticPlan, EvidenceRequest, Priority
from diagnostic_intelligence.models.evidence import (
    EVIDENCE_BY_CATEGORY,
    EvidenceRecord,
    EvidenceStatus,
    EvidenceType,
)


_PURPOSES: dict[EvidenceType, tuple[str, list[str], str]] = {
    EvidenceType.STORAGE_CAPACITY: (
        "Check total, used, and available capacity on relevant volumes.",
        ["volumes[].total_bytes", "volumes[].free_bytes", "volumes[].free_percent"],
        "Volume names and capacity values are system metadata; omit file names and paths.",
    ),
    EvidenceType.DISK_ACTIVITY: (
        "Check disk utilization and latency during the reported issue.",
        ["utilization_percent", "average_latency_ms", "observation_window_seconds"],
        "Collect aggregate metrics only; do not collect file contents.",
    ),
    EvidenceType.STORAGE_ERRORS: (
        "Check recent relevant filesystem or disk error summaries.",
        ["events[].timestamp", "events[].provider", "events[].event_id", "events[].level"],
        "Limit to relevant event summaries; exclude message fields containing personal data.",
    ),
    EvidenceType.NETWORK_CONFIGURATION: (
        "Review address configuration and default route state.",
        ["adapters[].status", "adapters[].addresses", "default_gateway"],
        "Network addresses can be sensitive; restrict access and avoid public sharing.",
    ),
    EvidenceType.DNS_RESOLUTION: (
        "Check DNS resolution for a permitted test hostname.",
        ["hostname", "success", "resolved_addresses", "error_category"],
        "Use a configured permitted hostname; do not collect browsing history.",
    ),
    EvidenceType.GATEWAY_REACHABILITY: (
        "Check reachability of the configured default gateway.",
        ["gateway", "reachable", "latency_ms"],
        "Collect only the gateway and test result.",
    ),
    EvidenceType.NETWORK_CONNECTIVITY: (
        "Check connectivity to an explicitly permitted test endpoint.",
        ["endpoint_id", "reachable", "latency_ms", "error_category"],
        "Use configured endpoint identifiers; do not contact arbitrary hosts.",
    ),
    EvidenceType.ADAPTER_STATUS: (
        "Check relevant network adapter operational status.",
        ["adapters[].name", "adapters[].status", "adapters[].problem_code"],
        "Adapter names may identify hardware; collect only relevant adapters.",
    ),
    EvidenceType.CPU_METRICS: (
        "Measure CPU utilization over a short bounded observation window.",
        ["samples[].timestamp", "samples[].utilization_percent", "utilization_percent"],
        "Collect aggregate utilization only.",
    ),
    EvidenceType.MEMORY_METRICS: (
        "Measure memory pressure and available memory.",
        ["total_bytes", "available_bytes", "used_percent"],
        "Collect aggregate memory metrics only.",
    ),
    EvidenceType.PROCESS_SUMMARY: (
        "Summarize the largest resource consumers, if needed to explain a measured bottleneck.",
        ["processes[].name", "processes[].cpu_percent", "processes[].memory_bytes"],
        "Names can reveal software use; omit command lines, usernames, and file paths.",
    ),
    EvidenceType.SYSTEM_EVENTS: (
        "Summarize recent Windows errors relevant to the reported instability.",
        ["recurring_error_count", "events[].timestamp", "events[].provider", "events[].event_id", "events[].level"],
        "Return bounded event summaries; redact account names and free-text details.",
    ),
    EvidenceType.RELIABILITY_SUMMARY: (
        "Check reliability indicators around the reported hang or failure.",
        ["incidents[].timestamp", "incidents[].type", "incidents[].application"],
        "Limit to relevant incident metadata; avoid unrelated personal activity.",
    ),
    EvidenceType.APPLICATION_LOGS: (
        "Inspect relevant application error summaries for startup or runtime failures.",
        ["application_id", "errors[].timestamp", "errors[].error_category", "errors[].message"],
        "Redact paths, usernames, tokens, and unrelated log content.",
    ),
    EvidenceType.RUNTIME_VERSIONS: (
        "Check runtime and dependency versions relevant to the affected application.",
        ["runtimes[].name", "runtimes[].version", "runtimes[].source"],
        "Collect only versions relevant to the named application.",
    ),
    EvidenceType.APPLICATION_STARTUP: (
        "Capture the affected application's startup result and documented error category.",
        ["application_id", "started", "exit_code", "error_category"],
        "Do not collect document contents or credentials.",
    ),
    EvidenceType.DEVICE_STATUS: (
        "Check the affected device's availability and reported status.",
        ["devices[].device_id", "devices[].status", "devices[].problem_code"],
        "Use stable device identifiers; avoid collecting unrelated device data.",
    ),
    EvidenceType.DRIVER_DETAILS: (
        "Collect provider and version for the relevant device driver.",
        ["device_id", "provider", "version", "date"],
        "Collect only driver metadata for the affected device.",
    ),
    EvidenceType.DRIVER_EVENTS: (
        "Summarize relevant driver or device errors.",
        ["recurring_error_count", "events[].timestamp", "events[].device_id", "events[].event_id", "events[].level"],
        "Return relevant event metadata and redact free-text personal data.",
    ),
    EvidenceType.UPDATE_HISTORY: (
        "Check recent system or driver updates that may relate to the reported change.",
        ["updates[].date", "updates[].identifier", "updates[].category"],
        "Collect update metadata only; do not collect unrelated history.",
    ),
}


class DiagnosticDecisionEngine:
    """Build evidence requests without accessing Windows or producing commands."""

    def __init__(self, ai_agent: object | None = None) -> None:
        self.ai_agent = ai_agent

    def create_plan(
        self,
        understanding: ProblemUnderstanding,
        evidence: list[EvidenceRecord] | None = None,
        session_id: str | None = None,
    ) -> DiagnosticPlan:
        if self.ai_agent is not None and hasattr(self.ai_agent, "generate_diagnostic_plan"):
            try:
                payload = self.ai_agent.generate_diagnostic_plan(
                    understanding.model_dump(mode="json"),
                    [item.model_dump(mode="json") for item in evidence or []],
                    session_id,
                )
            except Exception:
                payload = None
            if isinstance(payload, dict):
                try:
                    return DiagnosticPlan.model_validate(payload)
                except Exception:
                    pass

        categories = [understanding.primary_category, *understanding.secondary_categories]
        collected = {
            item.evidence_type
            for item in evidence or []
            if item.status in (EvidenceStatus.AVAILABLE, EvidenceStatus.PARTIAL)
            and (session_id is None or item.session_id == session_id)
        }
        requested_types: list[EvidenceType] = []
        for category in categories:
            for evidence_type in EVIDENCE_BY_CATEGORY.get(category, ()):
                if evidence_type not in collected and evidence_type not in requested_types:
                    requested_types.append(evidence_type)

        requests = []
        for index, evidence_type in enumerate(requested_types):
            purpose, fields, privacy = _PURPOSES[evidence_type]
            requests.append(
                EvidenceRequest(
                    evidence_id=f"evidence.{evidence_type.value.replace('.', '_')}",
                    evidence_type=evidence_type,
                    purpose=purpose,
                    priority=Priority.HIGH if index < 2 else Priority.MEDIUM,
                    required=index < 2,
                    parameters={},
                    time_window="last_24_hours" if evidence_type in {
                        EvidenceType.SYSTEM_EVENTS,
                        EvidenceType.STORAGE_ERRORS,
                        EvidenceType.DRIVER_EVENTS,
                        EvidenceType.UPDATE_HISTORY,
                        EvidenceType.RELIABILITY_SUMMARY,
                    } else None,
                    expected_output_fields=fields,
                    privacy_notes=privacy,
                )
            )
        return DiagnosticPlan(
            session_id=session_id,
            category=understanding.primary_category,
            evidence_requests=requests,
            reasoning_summary=(
                f"Selected {len(requests)} predefined evidence request(s) for "
                f"{understanding.primary_category.value}; already available evidence was excluded."
            ),
        )
