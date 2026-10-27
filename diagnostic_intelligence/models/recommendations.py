"""Structured root-cause findings and user/API recommendations."""

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from diagnostic_intelligence.models.classification import Category
from diagnostic_intelligence.models.diagnostic_plan import EvidenceRequest
from diagnostic_intelligence.models.evidence import EvidenceRecord


class DiagnosticStatus(StrEnum):
    CLASSIFIED = "classified"
    COLLECTING_EVIDENCE = "collecting_evidence"
    ANALYSIS_COMPLETE = "analysis_complete"
    NEEDS_CLARIFICATION = "needs_clarification"
    INCONCLUSIVE = "inconclusive"
    ERROR = "error"


class ActionType(StrEnum):
    FLUSH_DNS_CACHE = "flush_dns_cache"


class RemediationCandidate(BaseModel):
    """A policy-engine input; never an instruction to execute an operation."""

    model_config = ConfigDict(extra="forbid")

    action_candidate_id: str
    related_cause_id: str
    action_type: str
    purpose: str
    expected_effect: str
    risk_hint: str
    supporting_evidence_ids: list[str]
    preconditions: list[str]
    verification_criteria: list[str]


class RootCauseCandidate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    cause_id: str
    title: str
    explanation: str
    supporting_evidence_ids: list[str]
    contradicting_evidence_ids: list[str]
    confidence_score: float = Field(ge=0, le=1)
    confidence_rationale: str
    missing_evidence: list[str]
    suggested_next_step: str
    remediation_candidate: RemediationCandidate | None = None


class DiagnosticResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    session_id: str | None
    primary_category: Category
    secondary_categories: list[Category]
    problem_summary: str
    status: DiagnosticStatus
    evidence_summary: list[str]
    collected_evidence: list[EvidenceRecord] = Field(default_factory=list, exclude=True)
    evidence_requests: list[EvidenceRequest]
    ranked_root_causes: list[RootCauseCandidate]
    overall_uncertainty: str
    recommended_next_step: str
    remediation_candidate: RemediationCandidate | None = None
    user_facing_explanation: str
    warnings: list[str]
    ai_summary: str | None = None
    ai_model: str | None = None


class RemediationMode(StrEnum):
    AUTOMATIC = "automatic"
    APPROVAL_REQUIRED = "approval_required"


class ExecutionStatus(StrEnum):
    AWAITING_APPROVAL = "awaiting_approval"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    DENIED = "denied"
    BLOCKED = "blocked"


class VerificationStatus(StrEnum):
    VERIFIED_SUCCESS = "verified_success"
    FAILED = "failed"
    PARTIAL = "partial"
    INCONCLUSIVE = "inconclusive"


class VerificationResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: VerificationStatus
    evidence_id: str | None = None
    message: str


class RemediationExecution(BaseModel):
    model_config = ConfigDict(extra="forbid")

    execution_id: str
    session_id: str
    action_type: ActionType
    related_cause_id: str
    purpose: str
    risk_hint: str
    mode: RemediationMode
    approval_required: bool
    approval_decision: bool | None = None
    execution_status: ExecutionStatus
    message: str
    verification: VerificationResult | None = None
    audit_warning: str | None = None


class RemediationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action_type: ActionType
    mode: RemediationMode


class ApprovalRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    approved: bool
