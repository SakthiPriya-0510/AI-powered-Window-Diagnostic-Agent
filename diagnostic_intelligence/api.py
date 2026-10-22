"""Local HTTP API for the diagnostic intelligence package."""

from __future__ import annotations

from collections.abc import Callable

from fastapi import FastAPI, HTTPException
from pydantic import ConfigDict

from diagnostic_intelligence.ai.ollama_agent import OllamaAgent
from diagnostic_intelligence.collectors.windows import WindowsEvidenceCollector
from diagnostic_intelligence.engines.diagnostic_orchestrator import DiagnosticOrchestrator
from diagnostic_intelligence.models.recommendations import DiagnosticResult
from diagnostic_intelligence.models.requests import DiagnosticRequest


class DiagnosticRunRequest(DiagnosticRequest):
    """Frontend request with optional local Ollama summary generation."""

    model_config = ConfigDict(extra="forbid")

    use_ai: bool = False


def create_app(
    collector_factory: Callable[[], object] = WindowsEvidenceCollector,
) -> FastAPI:
    app = FastAPI(
        title="Windows Diagnostic Intelligence API",
        version="0.1.0",
        description="Local-only API for collecting approved evidence and running diagnostics.",
    )
    app.state.sessions = {}

    @app.get("/api/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "service": "windows-diagnostic-intelligence"}

    @app.post("/api/diagnostics", response_model=DiagnosticResult)
    def run_diagnostic(payload: DiagnosticRunRequest) -> DiagnosticResult:
        summary_agent = OllamaAgent(timeout=90) if payload.use_ai else None
        orchestrator = DiagnosticOrchestrator(
            ai_agent=object(),
            evidence_collector=collector_factory(),
        )
        result = orchestrator.run(
            payload,
            use_ai=payload.use_ai,
            ai_agent=summary_agent,
        )
        if result.session_id is None:
            raise HTTPException(status_code=500, detail="Diagnostic session could not be created.")
        app.state.sessions[result.session_id] = result
        return result

    @app.get("/api/diagnostics/{session_id}", response_model=DiagnosticResult)
    def get_diagnostic(session_id: str) -> DiagnosticResult:
        result = app.state.sessions.get(session_id)
        if result is None:
            raise HTTPException(status_code=404, detail="Diagnostic session was not found.")
        return result

    return app


app = create_app()