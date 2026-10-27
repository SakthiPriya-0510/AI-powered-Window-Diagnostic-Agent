"""Allowlisted remediation planning, execution, verification, and approval."""

from __future__ import annotations

import os
import platform
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from threading import RLock
from types import MappingProxyType
from typing import Mapping
from uuid import uuid4

from diagnostic_intelligence.models.diagnostic_plan import (
    DiagnosticPlan,
    EvidenceRequest,
    Priority,
)
from diagnostic_intelligence.models.evidence import EvidenceRecord, EvidenceStatus, EvidenceType
from diagnostic_intelligence.models.recommendations import (
    ActionType,
    ApprovalRequest,
    DiagnosticResult,
    ExecutionStatus,
    RemediationExecution,
    RemediationMode,
    VerificationResult,
    VerificationStatus,
)
from diagnostic_intelligence.services.audit import AuditLogger


@dataclass(frozen=True)
class ActionDefinition:
    action_type: ActionType
    related_cause_id: str
    purpose: str
    expected_effect: str
    risk_hint: str
    automatic_allowed: bool
    timeout_seconds: int
    preconditions: tuple[str, ...]
    verification_criteria: tuple[str, ...]


ACTION_REGISTRY: Mapping[ActionType, ActionDefinition] = MappingProxyType({
    ActionType.FLUSH_DNS_CACHE: ActionDefinition(
        action_type=ActionType.FLUSH_DNS_CACHE,
        related_cause_id="network.dns_failure",
        purpose="Clear the local DNS resolver cache using the fixed Windows utility.",
        expected_effect="The configured diagnostic hostname resolves successfully.",
        risk_hint=(
            "Low risk and non-destructive; this clears only cached DNS entries and "
            "does not alter DNS server settings."
        ),
        automatic_allowed=True,
        timeout_seconds=10,
        preconditions=(
            "Fresh available DNS evidence for the configured hostname explicitly reports resolution failure.",
            "No fresh DNS evidence contradicts the failure.",
            "The action runs on Windows with the fixed allowlisted command.",
        ),
        verification_criteria=(
            "Re-query only the configured diagnostic hostname and confirm resolution succeeds.",
            "A successful probe verifies that hostname only, not general internet access or issue resolution.",
        ),
    )
})


class RemediationError(Exception):
    """Base error for rejected remediation requests."""


class RemediationNotAllowed(RemediationError):
    """Raised when a candidate or precondition is not safe for execution."""


class ExecutionNotFound(RemediationError):
    """Raised when an approval references no pending execution."""


class RemediationService:
    def __init__(
        self,
        audit_logger: AuditLogger,
        *,
        command_runner=subprocess.run,
        platform_name: str | None = None,
    ) -> None:
        self.audit_logger = audit_logger
        self.command_runner = command_runner
        self.platform_name = platform_name
        self.executions: dict[str, RemediationExecution] = {}
        self._session_actions: dict[tuple[str, ActionType], str] = {}
        self._pending: dict[str, tuple[DiagnosticResult, object]] = {}
        self._lock = RLock()

    def available_actions(self) -> list[dict[str, object]]:
        return [
            {
                "action_type": action.action_type.value,
                "related_cause_id": action.related_cause_id,
                "purpose": action.purpose,
                "expected_effect": action.expected_effect,
                "risk_hint": action.risk_hint,
                "automatic_allowed": action.automatic_allowed,
                "supported_modes": [
                    RemediationMode.AUTOMATIC.value,
                    RemediationMode.APPROVAL_REQUIRED.value,
                ] if action.automatic_allowed else [RemediationMode.APPROVAL_REQUIRED.value],
                "timeout_seconds": action.timeout_seconds,
                "preconditions": list(action.preconditions),
                "verification_criteria": list(action.verification_criteria),
            }
            for action in ACTION_REGISTRY.values()
        ]

    def propose(
        self,
        result: DiagnosticResult,
        collector: object,
        action_type: ActionType,
        mode: RemediationMode,
    ) -> RemediationExecution:
        with self._lock:
            return self._propose(result, collector, action_type, mode)

    def _propose(
        self,
        result: DiagnosticResult,
        collector: object,
        action_type: ActionType,
        mode: RemediationMode,
    ) -> RemediationExecution:
        definition = ACTION_REGISTRY.get(action_type)
        if definition is None:
            raise RemediationNotAllowed("The requested action is not allowlisted.")
        if mode == RemediationMode.AUTOMATIC and not definition.automatic_allowed:
            raise RemediationNotAllowed(
                "This action requires explicit approval and cannot run automatically."
            )
        self._validate_platform()
        self._validate_candidate(result, definition)
        eligible_evidence_ids = self._validate_preconditions(
            result.collected_evidence, result.session_id
        )
        self._validate_supporting_evidence(result, definition, eligible_evidence_ids)

        session_id = result.session_id
        if session_id is None:
            raise RemediationNotAllowed("A session ID is required for remediation.")
        key = (session_id, action_type)
        if key in self._session_actions:
            raise RemediationNotAllowed("This action has already been requested for this session.")

        execution = RemediationExecution(
            execution_id=str(uuid4()),
            session_id=session_id,
            action_type=action_type,
            related_cause_id=definition.related_cause_id,
            purpose=definition.purpose,
            risk_hint=definition.risk_hint,
            mode=mode,
            approval_required=mode == RemediationMode.APPROVAL_REQUIRED,
            execution_status=(
                ExecutionStatus.AWAITING_APPROVAL
                if mode == RemediationMode.APPROVAL_REQUIRED
                else ExecutionStatus.BLOCKED
            ),
            message=(
                "Explicit approval is required before this action can run."
                if mode == RemediationMode.APPROVAL_REQUIRED
                else "The allowlisted action is being checked before execution."
            ),
        )
        self.audit_logger.record(
            "remediation_proposed",
            session_id,
            execution_id=execution.execution_id,
            action_type=action_type.value,
            cause_id=definition.related_cause_id,
            mode=mode.value,
            supporting_evidence_ids=self._supporting_ids(result, definition),
        )
        self._session_actions[key] = execution.execution_id
        self.executions[execution.execution_id] = execution
        if mode == RemediationMode.APPROVAL_REQUIRED:
            self._pending[execution.execution_id] = (result, collector)
            return execution
        return self._execute(execution, result, collector, approval_decision=None)

    def decide(
        self,
        execution_id: str,
        approval: ApprovalRequest,
    ) -> RemediationExecution:
        with self._lock:
            return self._decide(execution_id, approval)

    def _decide(
        self,
        execution_id: str,
        approval: ApprovalRequest,
    ) -> RemediationExecution:
        execution = self.executions.get(execution_id)
        pending = self._pending.get(execution_id)
        if execution is None or pending is None:
            raise ExecutionNotFound("No pending remediation approval exists for this execution ID.")

        result, collector = pending
        self.audit_logger.record(
            "remediation_approval_decision",
            execution.session_id,
            execution_id=execution_id,
            action_type=execution.action_type.value,
            approved=approval.approved,
        )
        execution.approval_decision = approval.approved
        self._pending.pop(execution_id, None)
        if not approval.approved:
            execution.execution_status = ExecutionStatus.DENIED
            execution.message = "Approval was denied; no action was executed."
            self._record_outcome(execution)
            return execution

        definition = ACTION_REGISTRY[execution.action_type]
        try:
            self._validate_candidate(result, definition)
            eligible_evidence_ids = self._validate_preconditions(
                result.collected_evidence, result.session_id
            )
            self._validate_supporting_evidence(
                result, definition, eligible_evidence_ids
            )
        except RemediationNotAllowed as error:
            execution.execution_status = ExecutionStatus.BLOCKED
            execution.message = str(error)
            self._record_outcome(execution)
            return execution
        return self._execute(execution, result, collector, approval_decision=True)

    @staticmethod
    def _supporting_ids(
        result: DiagnosticResult,
        definition: ActionDefinition,
    ) -> list[str]:
        candidate = next(
            (
                item.remediation_candidate
                for item in result.ranked_root_causes
                if item.cause_id == definition.related_cause_id
                and item.remediation_candidate is not None
            ),
            None,
        )
        return candidate.supporting_evidence_ids if candidate else []

    @staticmethod
    def _validate_candidate(result: DiagnosticResult, definition: ActionDefinition) -> None:
        if result.session_id is None:
            raise RemediationNotAllowed("A session ID is required for remediation.")
        candidate = next(
            (
                item for item in result.ranked_root_causes
                if item.cause_id == definition.related_cause_id
            ),
            None,
        )
        if candidate is not None and candidate.contradicting_evidence_ids:
            raise RemediationNotAllowed(
                "Contradictory evidence blocks remediation; collect fresh targeted evidence first."
            )
        public_candidate = result.remediation_candidate
        if (
            public_candidate is None
            or public_candidate.action_type != definition.action_type.value
            or public_candidate.related_cause_id != definition.related_cause_id
        ):
            raise RemediationNotAllowed(
                "No supported remediation candidate exists for this diagnosis."
            )
        if candidate is None or candidate.remediation_candidate is None:
            raise RemediationNotAllowed("No supported remediation candidate exists for this diagnosis.")
        if candidate.remediation_candidate.action_type != definition.action_type.value:
            raise RemediationNotAllowed("The candidate does not match the allowlisted action.")

    @staticmethod
    def _validate_preconditions(
        evidence: list[EvidenceRecord],
        session_id: str | None,
    ) -> set[str]:
        if not session_id:
            raise RemediationNotAllowed("A session ID is required for remediation.")
        dns_records = [
            record
            for record in evidence
            if record.session_id == session_id
            and record.evidence_type == EvidenceType.DNS_RESOLUTION
        ]
        usable = [
            record for record in dns_records
            if record.source == "windows_resource_collector"
            and isinstance(record.data.get("hostname"), str)
            and bool(record.data["hostname"])
        ]
        usable = [
            record for record in usable
            if record.status in (EvidenceStatus.AVAILABLE, EvidenceStatus.PARTIAL)
            and 0
            <= (datetime.now(timezone.utc) - record.collected_at).total_seconds()
            <= 900
        ]
        if not usable:
            raise RemediationNotAllowed(
                "Fresh available DNS failure evidence is required before this action."
            )
        failures = {
            record.evidence_id
            for record in usable
            if record.data.get("success") is False
            and record.data.get("error_category") == "name_resolution_failed"
        }
        if not failures:
            raise RemediationNotAllowed(
                "DNS evidence does not show a confirmed hostname resolution failure."
            )
        failed_hosts = {
            record.data.get("hostname")
            for record in usable
            if record.evidence_id in failures
        }
        if any(
            record.data.get("success") is True
            and record.data.get("hostname") in failed_hosts
            for record in usable
        ):
            raise RemediationNotAllowed(
                "Fresh DNS evidence is contradictory or already successful; no action was taken."
            )
        return failures

    @staticmethod
    def _validate_supporting_evidence(
        result: DiagnosticResult,
        definition: ActionDefinition,
        eligible_evidence_ids: set[str],
    ) -> None:
        candidate = next(
            item for item in result.ranked_root_causes
            if item.cause_id == definition.related_cause_id
        )
        action_candidate = candidate.remediation_candidate
        if action_candidate is None or not (
            set(action_candidate.supporting_evidence_ids)
            and set(action_candidate.supporting_evidence_ids).issubset(eligible_evidence_ids)
        ):
            raise RemediationNotAllowed(
                "The remediation candidate is not supported by the fresh allowlisted evidence."
            )

    def _execute(
        self,
        execution: RemediationExecution,
        result: DiagnosticResult,
        collector: object,
        approval_decision: bool | None,
    ) -> RemediationExecution:
        definition = ACTION_REGISTRY[execution.action_type]
        self._validate_platform()
        execution.approval_decision = approval_decision
        try:
            self.audit_logger.record(
                "remediation_execution_started",
                execution.session_id,
                execution_id=execution.execution_id,
                action_type=execution.action_type.value,
                mode=execution.mode.value,
                approval_decision=approval_decision,
            )
        except OSError:
            execution.execution_status = ExecutionStatus.BLOCKED
            execution.message = (
                "Execution was not started because its audit event could not be recorded."
            )
            raise
        try:
            completed = self.command_runner(
                [
                    str(Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "ipconfig.exe"),
                    "/flushdns",
                ],
                capture_output=True,
                text=True,
                timeout=definition.timeout_seconds,
                check=False,
                shell=False,
            )
            if completed.returncode == 0:
                execution.execution_status = ExecutionStatus.SUCCEEDED
                execution.message = "The Windows DNS cache flush command completed successfully."
            else:
                execution.execution_status = ExecutionStatus.FAILED
                execution.message = "The Windows DNS cache flush command returned a failure."
        except subprocess.TimeoutExpired:
            execution.execution_status = ExecutionStatus.TIMED_OUT
            execution.message = "The Windows DNS cache flush command timed out."
        except OSError:
            execution.execution_status = ExecutionStatus.FAILED
            execution.message = "The Windows DNS cache flush command could not be started."

        execution.verification = self._verify(collector, result, definition)
        self._record_outcome(execution)
        return execution

    def _validate_platform(self) -> None:
        if (self.platform_name or platform.system()) != "Windows":
            raise RemediationNotAllowed(
                "This action is available only on Windows; no system changes were made."
            )

    @staticmethod
    def _verify(
        collector: object,
        result: DiagnosticResult,
        definition: ActionDefinition,
    ) -> VerificationResult:
        request = next(
            (
                item for item in result.evidence_requests
                if item.evidence_type == EvidenceType.DNS_RESOLUTION
            ),
            None,
        )
        if result.session_id is None:
            return VerificationResult(
                status=VerificationStatus.INCONCLUSIVE,
                message="No DNS evidence request is available for post-action verification.",
            )
        if request is None:
            request = EvidenceRequest(
                evidence_id="evidence.network_dns_resolution",
                evidence_type=EvidenceType.DNS_RESOLUTION,
                purpose="Verify only the configured diagnostic hostname after the action.",
                priority=Priority.HIGH,
                required=True,
                privacy_notes="Resolve only the preconfigured permitted hostname.",
            )
        cause = next(
            (
                item for item in result.ranked_root_causes
                if item.cause_id == definition.related_cause_id
            ),
            None,
        )
        expected_host = None
        if cause is not None and cause.remediation_candidate is not None:
            support_ids = set(cause.remediation_candidate.supporting_evidence_ids)
            expected_host = next(
                (
                    record.data.get("hostname")
                    for record in result.collected_evidence
                    if record.evidence_id in support_ids
                    and record.evidence_type == EvidenceType.DNS_RESOLUTION
                    and isinstance(record.data.get("hostname"), str)
                ),
                None,
            )
        if expected_host is None:
            return VerificationResult(
                status=VerificationStatus.INCONCLUSIVE,
                message="The original permitted DNS hostname is unavailable for verification.",
            )
        plan = DiagnosticPlan(
            session_id=result.session_id,
            category=result.primary_category,
            evidence_requests=[request],
            reasoning_summary="Targeted post-action DNS verification.",
        )
        verification_started_at = datetime.now(timezone.utc)
        try:
            records = collector.collect_for_plan(plan)
        except Exception:
            return VerificationResult(
                status=VerificationStatus.INCONCLUSIVE,
                message="Post-action DNS evidence could not be collected.",
            )
        if not isinstance(records, (list, tuple)):
            return VerificationResult(
                status=VerificationStatus.INCONCLUSIVE,
                message="Post-action DNS evidence was malformed; the result is inconclusive.",
            )
        valid_records: list[EvidenceRecord] = []
        for item in records:
            try:
                record = (
                    item
                    if isinstance(item, EvidenceRecord)
                    else EvidenceRecord.model_validate(item)
                )
            except (TypeError, ValueError):
                continue
            if (
                record.session_id == result.session_id
                and record.evidence_type == EvidenceType.DNS_RESOLUTION
                and record.source == "windows_resource_collector"
            ):
                valid_records.append(record)
        if not valid_records:
            return VerificationResult(
                status=VerificationStatus.INCONCLUSIVE,
                message="Post-action DNS evidence was unavailable.",
            )
        record = valid_records[-1]
        if record.status in (EvidenceStatus.UNAVAILABLE, EvidenceStatus.ERROR):
            return VerificationResult(
                status=VerificationStatus.INCONCLUSIVE,
                evidence_id=record.evidence_id,
                message="Post-action DNS evidence is unavailable; the result is inconclusive.",
            )
        evidence_age_seconds = (
            datetime.now(timezone.utc) - record.collected_at
        ).total_seconds()
        if (
            record.collected_at < verification_started_at
            or not 0 <= evidence_age_seconds <= 900
        ):
            return VerificationResult(
                status=VerificationStatus.INCONCLUSIVE,
                evidence_id=record.evidence_id,
                message=(
                    "Post-action DNS evidence was not collected after verification began "
                    "or is stale/future-dated; verification is inconclusive."
                ),
            )
        if record.data.get("hostname") != expected_host:
            return VerificationResult(
                status=VerificationStatus.INCONCLUSIVE,
                evidence_id=record.evidence_id,
                message=(
                    "The configured DNS verification hostname changed after diagnosis; "
                    "the result is inconclusive."
                ),
            )
        if record.data.get("success") is True:
            status = (
                VerificationStatus.PARTIAL
                if record.status == EvidenceStatus.PARTIAL
                else VerificationStatus.VERIFIED_SUCCESS
            )
            return VerificationResult(
                status=status,
                evidence_id=record.evidence_id,
                message=(
                    "The configured diagnostic hostname resolves after the action. "
                    "This does not establish general internet access or resolution of the original complaint."
                ),
            )
        if record.data.get("success") is False:
            return VerificationResult(
                status=VerificationStatus.FAILED,
                evidence_id=record.evidence_id,
                message="The configured diagnostic hostname still fails to resolve.",
            )
        return VerificationResult(
            status=VerificationStatus.INCONCLUSIVE,
            evidence_id=record.evidence_id,
            message="Post-action DNS evidence did not contain a valid resolution result.",
        )

    def _record_outcome(self, execution: RemediationExecution) -> None:
        try:
            self.audit_logger.record(
                "remediation_outcome",
                execution.session_id,
                execution_id=execution.execution_id,
                action_type=execution.action_type.value,
                execution_status=execution.execution_status.value,
                approval_decision=execution.approval_decision,
                verification_status=(
                    execution.verification.status.value
                    if execution.verification
                    else None
                ),
                verification_evidence_id=(
                    execution.verification.evidence_id
                    if execution.verification
                    else None
                ),
            )
        except OSError:
            execution.audit_warning = (
                "The action outcome could not be written to the audit log; inspect "
                "audit storage before relying on this record."
            )
