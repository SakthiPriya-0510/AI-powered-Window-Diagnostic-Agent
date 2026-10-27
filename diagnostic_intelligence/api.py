"""Local HTTP API for the diagnostic intelligence package."""

from __future__ import annotations

from collections.abc import Callable
import hmac
import os
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException
from pydantic import ConfigDict

from diagnostic_intelligence.ai.ollama_agent import OllamaAgent
from diagnostic_intelligence.collectors.windows import WindowsEvidenceCollector
from diagnostic_intelligence.engines.diagnostic_orchestrator import DiagnosticOrchestrator
from diagnostic_intelligence.models.recommendations import (
    ApprovalRequest,
    DiagnosticResult,
    RemediationExecution,
    RemediationRequest,
)
from diagnostic_intelligence.models.requests import DiagnosticRequest
from diagnostic_intelligence.services.audit import AuditLogError, AuditLogger
from diagnostic_intelligence.services.remediation import (
    ExecutionNotFound,
    RemediationError,
    RemediationService,
)


class DiagnosticRunRequest(DiagnosticRequest):
    """Frontend request with optional local Ollama summary generation."""

    model_config = ConfigDict(extra="forbid")

    use_ai: bool = False


def create_app(
    collector_factory: Callable[[], object] = WindowsEvidenceCollector,
    *,
    audit_directory: str | Path = "audit_logs",
    remediation_service: RemediationService | None = None,
    remediation_token: str | None = None,
) -> FastAPI:
    app = FastAPI(
        title="Windows Diagnostic Intelligence API",
        version="0.1.0",
        description="Local-only API for collecting approved evidence and running diagnostics.",
    )
    app.state.sessions = {}
    app.state.session_collectors = {}
    app.state.audit_logger = (
        remediation_service.audit_logger
        if remediation_service is not None
        else AuditLogger(audit_directory)
    )
    app.state.remediation_service = remediation_service or RemediationService(
        app.state.audit_logger
    )
    app.state.remediation_token = (
        remediation_token
        if remediation_token is not None
        else os.environ.get("WINDOWS_DIAGNOSTIC_API_TOKEN")
    )

    def require_remediation_auth(authorization: str | None) -> None:
        expected = app.state.remediation_token
        if not isinstance(expected, str) or len(expected.encode("utf-8")) < 32:
            raise HTTPException(
                status_code=503,
                detail=(
                    "Remediation is disabled until WINDOWS_DIAGNOSTIC_API_TOKEN "
                    "is configured with at least 32 bytes."
                ),
            )
        scheme, separator, supplied = (authorization or "").partition(" ")
        if (
            not separator
            or scheme.casefold() != "bearer"
            or not supplied
            or " " in supplied
            or not hmac.compare_digest(supplied.encode("utf-8"), expected.encode("utf-8"))
        ):
            raise HTTPException(
                status_code=401,
                detail="A valid local remediation bearer token is required.",
                headers={"WWW-Authenticate": "Bearer"},
            )

    @app.get("/api/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "service": "windows-diagnostic-intelligence"}

    @app.post("/api/diagnostics", response_model=DiagnosticResult)
    def run_diagnostic(payload: DiagnosticRunRequest) -> DiagnosticResult:
        summary_agent = OllamaAgent(timeout=90) if payload.use_ai else None
        collector = collector_factory()
        orchestrator = DiagnosticOrchestrator(
            ai_agent=None,
            evidence_collector=collector,
        )
        result = orchestrator.run(
            payload,
            use_ai=payload.use_ai,
            ai_agent=summary_agent,
        )
        if result.session_id is None:
            raise HTTPException(status_code=500, detail="Diagnostic session could not be created.")
        try:
            app.state.audit_logger.record(
                "diagnosis_completed",
                result.session_id,
                category=result.primary_category.value,
                status=result.status.value,
                cause_ids=[cause.cause_id for cause in result.ranked_root_causes],
                evidence_ids=[item.evidence_id for item in result.collected_evidence],
            )
        except AuditLogError as error:
            raise HTTPException(
                status_code=503,
                detail="Diagnosis completed but could not be durably audited.",
            ) from error
        app.state.sessions[result.session_id] = result
        app.state.session_collectors[result.session_id] = collector
        return result

    @app.get("/api/diagnostics/{session_id}", response_model=DiagnosticResult)
    def get_diagnostic(session_id: str) -> DiagnosticResult:
        result = app.state.sessions.get(session_id)
        if result is None:
            raise HTTPException(status_code=404, detail="Diagnostic session was not found.")
        return result

    @app.get("/api/remediations/actions")
    def list_remediation_actions() -> dict[str, list[dict[str, object]]]:
        return {"actions": app.state.remediation_service.available_actions()}

    @app.post(
        "/api/diagnostics/{session_id}/remediations",
        response_model=RemediationExecution,
    )
    def request_remediation(
        session_id: str,
        payload: RemediationRequest,
        authorization: str | None = Header(default=None),
    ) -> RemediationExecution:
        require_remediation_auth(authorization)
        result = app.state.sessions.get(session_id)
        collector = app.state.session_collectors.get(session_id)
        if result is None or collector is None:
            raise HTTPException(status_code=404, detail="Diagnostic session was not found.")
        try:
            return app.state.remediation_service.propose(
                result,
                collector,
                payload.action_type,
                payload.mode,
            )
        except RemediationError as error:
            raise HTTPException(status_code=409, detail=str(error)) from error
        except AuditLogError as error:
            raise HTTPException(
                status_code=503,
                detail="Remediation was not started because its audit event could not be recorded.",
            ) from error

    @app.post(
        "/api/remediations/{execution_id}/approval",
        response_model=RemediationExecution,
    )
    def decide_remediation(
        execution_id: str,
        payload: ApprovalRequest,
        authorization: str | None = Header(default=None),
    ) -> RemediationExecution:
        require_remediation_auth(authorization)
        try:
            return app.state.remediation_service.decide(execution_id, payload)
        except ExecutionNotFound as error:
            raise HTTPException(status_code=404, detail=str(error)) from error
        except AuditLogError as error:
            raise HTTPException(
                status_code=503,
                detail="Approval was not processed because its audit event could not be recorded.",
            ) from error

    return app


app = create_app()