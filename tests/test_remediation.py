import hashlib
import json
import os
import subprocess
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

import pytest

from diagnostic_intelligence.engines.diagnostic_orchestrator import DiagnosticOrchestrator
from diagnostic_intelligence.models.evidence import EvidenceRecord, EvidenceStatus, EvidenceType
from diagnostic_intelligence.models.recommendations import (
    ActionType,
    ApprovalRequest,
    ExecutionStatus,
    RemediationMode,
    VerificationStatus,
)
from diagnostic_intelligence.services.audit import AuditLogger
from diagnostic_intelligence.services.remediation import (
    ACTION_REGISTRY,
    ExecutionNotFound,
    RemediationNotAllowed,
    RemediationService,
)


class StatefulCollector:
    def __init__(self, outcomes=None, statuses=None):
        self.outcomes = list(outcomes or [False, True])
        self.statuses = list(statuses or ["available", "available"])
        self.calls = 0

    def collect_for_plan(self, plan):
        records = []
        current = self.calls
        self.calls += 1
        for request in plan.evidence_requests:
            if request.evidence_type == EvidenceType.DNS_RESOLUTION:
                result_index = min(current, len(self.outcomes) - 1)
                success = self.outcomes[result_index]
                status = self.statuses[min(current, len(self.statuses) - 1)]
                data = {
                    "hostname": "diagnostic.example",
                    "success": success,
                    "error_category": None if success else "name_resolution_failed",
                }
                record_status = EvidenceStatus(status)
            else:
                data = {"reason": "not configured in test"}
                record_status = EvidenceStatus.UNAVAILABLE
            records.append(
                EvidenceRecord(
                    session_id=plan.session_id,
                    evidence_id=request.evidence_id,
                    evidence_type=request.evidence_type,
                    collected_at=datetime.now(timezone.utc),
                    status=record_status,
                    data=data,
                    source="windows_resource_collector",
                )
            )
        return records


class StaleVerificationCollector(StatefulCollector):
    def collect_for_plan(self, plan):
        records = super().collect_for_plan(plan)
        if self.calls > 1:
            for record in records:
                if record.evidence_type == EvidenceType.DNS_RESOLUTION:
                    record.collected_at = datetime(2020, 1, 1, tzinfo=timezone.utc)
        return records


class CachedVerificationCollector(StatefulCollector):
    def __init__(self):
        super().__init__([False, True])
        self.initial_dns_record = None

    def collect_for_plan(self, plan):
        records = super().collect_for_plan(plan)
        if self.calls == 1:
            self.initial_dns_record = next(
                record
                for record in records
                if record.evidence_type == EvidenceType.DNS_RESOLUTION
            )
        elif self.calls == 2:
            return [self.initial_dns_record]
        return records


def diagnosis(collector, evidence=()):
    return DiagnosticOrchestrator(evidence_collector=collector).run(
        {
            "session_id": "remediation-test-session",
            "complaint": "DNS resolution for the diagnostic hostname is failing.",
        },
        evidence,
    )


def service(tmp_path, runner=None, platform_name="Windows"):
    return RemediationService(
        AuditLogger(tmp_path / "audit"),
        command_runner=runner or (
            lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 0)
        ),
        platform_name=platform_name,
    )


def run_auto(tmp_path, collector, runner=None):
    result = diagnosis(collector)
    assert result.remediation_candidate is not None
    return service(tmp_path, runner).propose(
        result,
        collector,
        ActionType.FLUSH_DNS_CACHE,
        RemediationMode.AUTOMATIC,
    )


def test_registry_contains_only_fixed_allowlisted_low_risk_action() -> None:
    assert list(ACTION_REGISTRY) == [ActionType.FLUSH_DNS_CACHE]
    assert ACTION_REGISTRY[ActionType.FLUSH_DNS_CACHE].timeout_seconds <= 10


def test_automatic_mode_executes_fixed_command_and_verifies_success(tmp_path) -> None:
    calls = []
    collector = StatefulCollector([False, True])

    def runner(args, **kwargs):
        calls.append((args, kwargs))
        return subprocess.CompletedProcess(args, 0)

    execution = run_auto(tmp_path, collector, runner)

    assert execution.execution_status == ExecutionStatus.SUCCEEDED
    assert execution.verification.status == VerificationStatus.VERIFIED_SUCCESS
    assert len(calls) == 1
    assert calls[0][0][0].endswith(os.path.join("System32", "ipconfig.exe"))
    assert calls[0][0][1] == "/flushdns"
    assert calls[0][1]["shell"] is False
    assert calls[0][1]["timeout"] == 10
    assert collector.calls == 2
    assert "does not establish general internet access" in execution.verification.message


@pytest.mark.parametrize("system_root", [r"D:\Windows-Test", None])
def test_windows_executor_uses_system_root_and_fixed_safe_arguments(
    tmp_path, monkeypatch, system_root
) -> None:
    if system_root is None:
        monkeypatch.delenv("SystemRoot", raising=False)
        expected_root = r"C:\Windows"
    else:
        monkeypatch.setenv("SystemRoot", system_root)
        expected_root = system_root
    calls = []

    def runner(args, **kwargs):
        calls.append((args, kwargs))
        return subprocess.CompletedProcess(args, 0)

    execution = run_auto(tmp_path, StatefulCollector([False, True]), runner)

    assert execution.execution_status == ExecutionStatus.SUCCEEDED
    assert len(calls) == 1
    args, kwargs = calls[0]
    assert args == [
        str(Path(expected_root) / "System32" / "ipconfig.exe"),
        "/flushdns",
    ]
    assert kwargs == {
        "capture_output": True,
        "text": True,
        "timeout": 10,
        "check": False,
        "shell": False,
    }


def test_approval_mode_does_not_execute_until_explicit_approval(tmp_path) -> None:
    calls = []
    collector = StatefulCollector([False, True])
    remediation = service(tmp_path, lambda *args, **kwargs: calls.append(args))
    result = diagnosis(collector)

    execution = remediation.propose(
        result,
        collector,
        ActionType.FLUSH_DNS_CACHE,
        RemediationMode.APPROVAL_REQUIRED,
    )

    assert execution.execution_status == ExecutionStatus.AWAITING_APPROVAL
    assert calls == []
    assert remediation.decide(
        execution.execution_id, ApprovalRequest(approved=False)
    ).execution_status == ExecutionStatus.DENIED
    assert calls == []


def test_approval_required_action_runs_only_after_approval(tmp_path) -> None:
    calls = []
    collector = StatefulCollector([False, True])

    def runner(args, **kwargs):
        calls.append(args)
        return subprocess.CompletedProcess(args, 0)

    remediation = service(tmp_path, runner)
    result = diagnosis(collector)
    pending = remediation.propose(
        result,
        collector,
        ActionType.FLUSH_DNS_CACHE,
        RemediationMode.APPROVAL_REQUIRED,
    )

    completed = remediation.decide(
        pending.execution_id, ApprovalRequest(approved=True)
    )

    assert len(calls) == 1
    assert calls[0][0].endswith(os.path.join("System32", "ipconfig.exe"))
    assert calls[0][1] == "/flushdns"
    assert completed.execution_status == ExecutionStatus.SUCCEEDED
    assert completed.approval_decision is True
    assert completed.verification.status == VerificationStatus.VERIFIED_SUCCESS


def test_approval_decision_is_single_use_and_bound_to_execution(tmp_path) -> None:
    calls = []
    collector = StatefulCollector([False, True])
    remediation = service(
        tmp_path,
        lambda args, **kwargs: (
            calls.append(args) or subprocess.CompletedProcess(args, 0)
        ),
    )
    result = diagnosis(collector)
    pending = remediation.propose(
        result,
        collector,
        ActionType.FLUSH_DNS_CACHE,
        RemediationMode.APPROVAL_REQUIRED,
    )

    completed = remediation.decide(
        pending.execution_id,
        ApprovalRequest(approved=True),
    )

    assert completed.execution_status == ExecutionStatus.SUCCEEDED
    with pytest.raises(ExecutionNotFound, match="No pending remediation approval"):
        remediation.decide(
            pending.execution_id,
            ApprovalRequest(approved=True),
        )
    with pytest.raises(ExecutionNotFound, match="No pending remediation approval"):
        remediation.decide(
            "another-execution-id",
            ApprovalRequest(approved=True),
        )
    assert len(calls) == 1


@pytest.mark.parametrize("change", ["stale", "contradictory"])
def test_approval_rechecks_dns_preconditions_before_execution(tmp_path, change) -> None:
    calls = []
    collector = StatefulCollector([False, True])
    remediation = service(
        tmp_path,
        lambda args, **kwargs: (
            calls.append(args) or subprocess.CompletedProcess(args, 0)
        ),
    )
    result = diagnosis(collector)
    pending = remediation.propose(
        result,
        collector,
        ActionType.FLUSH_DNS_CACHE,
        RemediationMode.APPROVAL_REQUIRED,
    )
    dns_evidence = next(
        item
        for item in result.collected_evidence
        if item.evidence_type == EvidenceType.DNS_RESOLUTION
    )
    if change == "stale":
        dns_evidence.collected_at = datetime(2020, 1, 1, tzinfo=timezone.utc)
    else:
        result.collected_evidence.append(
            EvidenceRecord(
                session_id=result.session_id,
                evidence_id="dns.success",
                evidence_type=EvidenceType.DNS_RESOLUTION,
                collected_at=datetime.now(timezone.utc),
                status=EvidenceStatus.AVAILABLE,
                data={"hostname": "diagnostic.example", "success": True},
                source="windows_resource_collector",
            )
        )

    completed = remediation.decide(
        pending.execution_id,
        ApprovalRequest(approved=True),
    )

    assert completed.execution_status == ExecutionStatus.BLOCKED
    assert calls == []


def test_unallowlisted_actions_are_rejected(tmp_path) -> None:
    collector = StatefulCollector()
    result = diagnosis(collector)

    with pytest.raises(RemediationNotAllowed, match="not allowlisted"):
        service(tmp_path).propose(
            result, collector, "delete_files", RemediationMode.AUTOMATIC
        )


def test_missing_or_stale_evidence_blocks_execution(tmp_path) -> None:
    collector = StatefulCollector()
    result = diagnosis(collector)
    result.collected_evidence = []

    with pytest.raises(RemediationNotAllowed, match="Fresh available DNS"):
        service(tmp_path).propose(
            result,
            collector,
            ActionType.FLUSH_DNS_CACHE,
            RemediationMode.AUTOMATIC,
        )

    stale_collector = StatefulCollector()
    stale_result = diagnosis(stale_collector)
    dns_record = next(
        item for item in stale_result.collected_evidence
        if item.evidence_type == EvidenceType.DNS_RESOLUTION
    )
    dns_record.collected_at = datetime(2020, 1, 1, tzinfo=timezone.utc)
    with pytest.raises(RemediationNotAllowed, match="Fresh available DNS"):
        service(tmp_path).propose(
            stale_result,
            stale_collector,
            ActionType.FLUSH_DNS_CACHE,
            RemediationMode.AUTOMATIC,
        )


def test_dns_evidence_from_untrusted_source_blocks_action(tmp_path) -> None:
    collector = StatefulCollector()
    result = diagnosis(collector)
    dns_record = next(
        item for item in result.collected_evidence
        if item.evidence_type == EvidenceType.DNS_RESOLUTION
    )
    dns_record.source = "untrusted_test_source"
    calls = []
    remediation = service(tmp_path, lambda *args, **kwargs: calls.append(args))

    with pytest.raises(RemediationNotAllowed, match="Fresh available DNS"):
        remediation.propose(
            result,
            collector,
            ActionType.FLUSH_DNS_CACHE,
            RemediationMode.AUTOMATIC,
        )

    assert calls == []


def test_successful_dns_or_missing_candidate_blocks_remediation(tmp_path) -> None:
    collector = StatefulCollector([True, True])
    result = diagnosis(collector)
    assert result.remediation_candidate is None

    with pytest.raises(RemediationNotAllowed, match="No supported remediation candidate"):
        service(tmp_path).propose(
            result,
            collector,
            ActionType.FLUSH_DNS_CACHE,
            RemediationMode.AUTOMATIC,
        )


def test_contradictory_dns_evidence_blocks_remediation(tmp_path) -> None:
    collector = StatefulCollector()
    result = diagnosis(
        collector,
        [
            {
                "session_id": "remediation-test-session",
                "evidence_id": "dns.failed",
                "evidence_type": "network.dns_resolution",
                "collected_at": datetime.now(timezone.utc).isoformat(),
                "status": "available",
                "data": {
                    "hostname": "diagnostic.example",
                    "success": False,
                    "error_category": "name_resolution_failed",
                },
            },
            {
                "session_id": "remediation-test-session",
                "evidence_id": "dns.success",
                "evidence_type": "network.dns_resolution",
                "collected_at": datetime.now(timezone.utc).isoformat(),
                "status": "available",
                "data": {"hostname": "diagnostic.example", "success": True},
            }
        ],
    )

    assert result.status.value == "inconclusive"
    with pytest.raises(RemediationNotAllowed, match="Contradictory evidence"):
        service(tmp_path).propose(
            result,
            collector,
            ActionType.FLUSH_DNS_CACHE,
            RemediationMode.AUTOMATIC,
        )


@pytest.mark.parametrize(
    ("runner", "status"),
    [
        (
            lambda args, **kwargs: subprocess.CompletedProcess(args, 1),
            ExecutionStatus.FAILED,
        ),
        (
            lambda args, **kwargs: (_ for _ in ()).throw(
                subprocess.TimeoutExpired(args, kwargs["timeout"])
            ),
            ExecutionStatus.TIMED_OUT,
        ),
        (
            lambda args, **kwargs: (_ for _ in ()).throw(OSError("private detail")),
            ExecutionStatus.FAILED,
        ),
    ],
)
def test_execution_failures_are_reported_and_verified(
    tmp_path, runner, status
) -> None:
    collector = StatefulCollector([False, False])

    execution = run_auto(tmp_path, collector, runner)

    assert execution.execution_status == status
    assert execution.verification.status == VerificationStatus.FAILED


@pytest.mark.parametrize(
    ("outcomes", "statuses", "expected"),
    [
        ([False, True], ["available", "partial"], VerificationStatus.PARTIAL),
        ([False, None], ["available", "unavailable"], VerificationStatus.INCONCLUSIVE),
    ],
)
def test_verification_distinguishes_partial_and_unavailable_evidence(
    tmp_path, outcomes, statuses, expected
) -> None:
    collector = StatefulCollector(outcomes, statuses)
    execution = run_auto(tmp_path, collector)

    assert execution.verification.status == expected


def test_stale_post_action_dns_evidence_is_not_reported_as_verified(tmp_path) -> None:
    collector = StaleVerificationCollector([False, True])

    execution = run_auto(tmp_path, collector)

    assert execution.execution_status == ExecutionStatus.SUCCEEDED
    assert execution.verification.status == VerificationStatus.INCONCLUSIVE
    assert "not collected after verification began" in execution.verification.message


def test_cached_pre_action_dns_record_cannot_verify_post_action_recovery(tmp_path) -> None:
    collector = CachedVerificationCollector()

    execution = run_auto(tmp_path, collector)

    assert execution.execution_status == ExecutionStatus.SUCCEEDED
    assert execution.verification.status == VerificationStatus.INCONCLUSIVE
    assert "not collected after verification began" in execution.verification.message


def test_duplicate_action_is_prevented_for_session(tmp_path) -> None:
    collector = StatefulCollector([False, True])
    remediation = service(tmp_path)
    result = diagnosis(collector)
    remediation.propose(
        result, collector, ActionType.FLUSH_DNS_CACHE, RemediationMode.AUTOMATIC
    )

    with pytest.raises(RemediationNotAllowed, match="already been requested"):
        remediation.propose(
            result, collector, ActionType.FLUSH_DNS_CACHE, RemediationMode.AUTOMATIC
        )


def test_concurrent_duplicate_requests_execute_only_once(tmp_path) -> None:
    collector = StatefulCollector([False, True])
    result = diagnosis(collector)
    calls = []

    def runner(args, **kwargs):
        calls.append(args)
        return subprocess.CompletedProcess(args, 0)

    remediation = service(tmp_path, runner)

    def request():
        try:
            remediation.propose(
                result,
                collector,
                ActionType.FLUSH_DNS_CACHE,
                RemediationMode.AUTOMATIC,
            )
            return "executed"
        except RemediationNotAllowed:
            return "blocked"

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(lambda _: request(), range(2)))

    assert sorted(outcomes) == ["blocked", "executed"]
    assert len(calls) == 1


def test_concurrent_approval_decisions_execute_only_once(tmp_path) -> None:
    collector = StatefulCollector([False, True])
    calls = []
    remediation = service(
        tmp_path,
        lambda args, **kwargs: (
            calls.append(args) or subprocess.CompletedProcess(args, 0)
        ),
    )
    result = diagnosis(collector)
    pending = remediation.propose(
        result,
        collector,
        ActionType.FLUSH_DNS_CACHE,
        RemediationMode.APPROVAL_REQUIRED,
    )

    def decide():
        try:
            return remediation.decide(
                pending.execution_id,
                ApprovalRequest(approved=True),
            ).execution_status.value
        except ExecutionNotFound:
            return "consumed"

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(lambda _: decide(), range(2)))

    assert sorted(outcomes) == ["consumed", "succeeded"]
    assert len(calls) == 1


def test_non_windows_execution_is_blocked(tmp_path) -> None:
    collector = StatefulCollector()
    result = diagnosis(collector)

    with pytest.raises(RemediationNotAllowed, match="only on Windows"):
        service(tmp_path, platform_name="Linux").propose(
            result,
            collector,
            ActionType.FLUSH_DNS_CACHE,
            RemediationMode.AUTOMATIC,
        )


def test_audit_log_records_workflow_without_complaint_or_command(tmp_path) -> None:
    collector = StatefulCollector([False, True])
    result = diagnosis(collector)
    secret_complaint = result.problem_summary
    remediation = service(tmp_path)
    execution = remediation.propose(
        result,
        collector,
        ActionType.FLUSH_DNS_CACHE,
        RemediationMode.APPROVAL_REQUIRED,
    )
    remediation.decide(execution.execution_id, ApprovalRequest(approved=True))
    audit_files = list((tmp_path / "audit").glob("*.jsonl"))
    events = [json.loads(line) for line in audit_files[0].read_text().splitlines()]

    assert [event["event_type"] for event in events] == [
        "remediation_proposed",
        "remediation_approval_decision",
        "remediation_execution_started",
        "remediation_outcome",
    ]
    serialized = json.dumps(events)
    assert secret_complaint not in serialized
    assert "ipconfig.exe" not in serialized
    assert "name_resolution_failed" not in serialized


def test_audit_failure_prevents_command_execution(tmp_path) -> None:
    audit_path = tmp_path / "not-a-directory"
    audit_path.write_text("file")
    calls = []
    collector = StatefulCollector()
    result = diagnosis(collector)
    remediation = RemediationService(
        AuditLogger(audit_path),
        command_runner=lambda *args, **kwargs: calls.append(args),
        platform_name="Windows",
    )

    with pytest.raises(OSError, match="Audit event"):
        remediation.propose(
            result, collector, ActionType.FLUSH_DNS_CACHE, RemediationMode.AUTOMATIC
        )
    assert calls == []


def test_tampered_audit_chain_blocks_new_actions(tmp_path) -> None:
    audit = AuditLogger(tmp_path / "audit")
    audit.record("first_event", "session-one", status="ok")
    audit_file = next((tmp_path / "audit").glob("*.jsonl"))
    event = json.loads(audit_file.read_text(encoding="utf-8").splitlines()[0])
    event["status"] = "altered"
    audit_file.write_text(json.dumps(event) + "\n", encoding="utf-8")

    with pytest.raises(OSError, match="Audit"):
        audit.record("second_event", "session-two", status="ok")


def test_legacy_audit_records_seed_chain_but_cannot_resume_after_chain_starts(
    tmp_path,
) -> None:
    directory = tmp_path / "audit"
    directory.mkdir()
    audit_file = directory / f"{datetime.now(timezone.utc):%Y-%m-%d}.jsonl"
    legacy_event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": "legacy_event",
        "session_ref": "legacy",
    }
    legacy_line = json.dumps(legacy_event)
    audit_file.write_text(legacy_line + "\n", encoding="utf-8")
    audit = AuditLogger(directory)

    audit.record("chained_event", "session-one", status="ok")
    chained_event = json.loads(audit_file.read_text(encoding="utf-8").splitlines()[1])
    assert chained_event["previous_event_hash"] == hashlib.sha256(
        legacy_line.encode("utf-8")
    ).hexdigest()

    with audit_file.open("a", encoding="utf-8") as audit_file_handle:
        audit_file_handle.write(json.dumps(legacy_event) + "\n")
    with pytest.raises(OSError, match="integrity"):
        audit.record("after_downgrade", "session-two", status="ok")


def test_audit_logger_rejects_reserved_hash_fields(tmp_path) -> None:
    audit = AuditLogger(tmp_path / "audit")

    with pytest.raises(OSError, match="reserved field"):
        audit.record("event", "session", event_hash="forged")

    assert not list((tmp_path / "audit").glob("*.jsonl"))


def test_audit_logger_refuses_to_append_after_unterminated_record(tmp_path) -> None:
    directory = tmp_path / "audit"
    directory.mkdir()
    audit_file = directory / f"{datetime.now(timezone.utc):%Y-%m-%d}.jsonl"
    audit_file.write_text('{"event_type":"partial"}', encoding="utf-8")

    with pytest.raises(OSError, match="integrity"):
        AuditLogger(directory).record("new_event", "session")

    assert audit_file.read_text(encoding="utf-8") == '{"event_type":"partial"}'
