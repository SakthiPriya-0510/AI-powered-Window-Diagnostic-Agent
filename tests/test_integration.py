from datetime import datetime, timezone

from diagnostic_intelligence import DiagnosticOrchestrator


class FakeOllamaAgent:
    def __init__(self, summary: str = "AI summary") -> None:
        self.summary = summary

    def generate_diagnostic_summary(self, *, complaint: str, category: str, evidence_summary: list[str], root_causes: list[str]) -> str:
        return self.summary


def test_end_to_end_classification_planning_analysis_and_result() -> None:
    result = DiagnosticOrchestrator().run(
        {"session_id": "demo-001", "complaint": "My laptop is slow."},
        [
            {
                "session_id": "demo-001",
                "evidence_id": "cpu.sample",
                "evidence_type": "performance.cpu",
                "collected_at": datetime.now(timezone.utc).isoformat(),
                "status": "available",
                "data": {"utilization_percent": 96},
                "source": "synthetic_test_fixture",
            }
        ],
    )
    payload = result.model_dump(mode="json")
    assert payload["status"] == "analysis_complete"
    assert payload["primary_category"] == "system_performance"
    assert payload["ranked_root_causes"][0]["cause_id"] == "performance.cpu_saturation"
    assert payload["evidence_summary"] == ["performance.cpu: available (utilization_percent=96)"]
    assert "resolved" not in payload["status"]


def test_orchestrator_survives_malformed_evidence_and_reports_warning() -> None:
    result = DiagnosticOrchestrator().run(
        {"session_id": "demo-001", "complaint": "My laptop is slow."},
        [{"evidence_type": "performance.cpu", "data": {"utilization_percent": 99}}],
    )
    assert result.status.value == "collecting_evidence"
    assert any("malformed" in warning for warning in result.warnings)


def test_unknown_complaint_requires_clarification() -> None:
    result = DiagnosticOrchestrator().run({"complaint": "Help me with my computer"})
    assert result.status.value == "needs_clarification"
    assert result.primary_category.value == "unknown"


def test_foreign_session_evidence_is_reported_and_not_scored() -> None:
    result = DiagnosticOrchestrator().run(
        {"session_id": "demo-001", "complaint": "My laptop is slow."},
        [{
            "session_id": "another-session",
            "evidence_id": "cpu.sample",
            "evidence_type": "performance.cpu",
            "collected_at": datetime.now(timezone.utc).isoformat(),
            "status": "available",
            "data": {"utilization_percent": 99},
        }],
    )
    assert result.status.value == "collecting_evidence"
    assert any("different session" in warning for warning in result.warnings)


def test_orchestrator_can_enrich_result_with_ollama_summary() -> None:
    result = DiagnosticOrchestrator().run(
        {"session_id": "demo-001", "complaint": "My laptop is slow."},
        [{
            "session_id": "demo-001",
            "evidence_id": "cpu.sample",
            "evidence_type": "performance.cpu",
            "collected_at": datetime.now(timezone.utc).isoformat(),
            "status": "available",
            "data": {"utilization_percent": 96},
            "source": "synthetic_test_fixture",
        }],
        use_ai=True,
        ai_agent=FakeOllamaAgent("AI summary enabled"),
    )
    assert result.ai_summary == "AI summary enabled"
    assert result.ai_model is not None


def test_requested_summary_without_agent_reports_warning() -> None:
    result = DiagnosticOrchestrator().run(
        {"session_id": "demo-no-agent", "complaint": "My laptop is slow."},
        use_ai=True,
    )

    assert result.ai_summary is None
    assert any("no summary agent is configured" in warning for warning in result.warnings)


def test_orchestrator_disables_llm_by_default_and_keeps_engine_llm_separate() -> None:
    summary_agent = FakeOllamaAgent()
    engine_llm = object()
    orchestrator = DiagnosticOrchestrator(ai_agent=summary_agent, engine_llm=engine_llm)

    assert orchestrator.ai_agent is summary_agent
    assert orchestrator.engine_llm is engine_llm
    assert orchestrator.understanding_engine.ai_agent is engine_llm
    assert orchestrator.decision_engine.ai_agent is engine_llm
    assert orchestrator.correlation_engine.ai_agent is engine_llm

    default_orchestrator = DiagnosticOrchestrator()
    assert default_orchestrator.ai_agent is None
    assert default_orchestrator.understanding_engine.ai_agent is None
    assert default_orchestrator.decision_engine.ai_agent is None
    assert default_orchestrator.correlation_engine.ai_agent is None


def test_diagnostic_result_retains_evidence_internally_only() -> None:
    evidence = {
        "session_id": "demo-001",
        "evidence_id": "cpu.sample",
        "evidence_type": "performance.cpu",
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "status": "available",
        "data": {"utilization_percent": 96},
        "source": "synthetic_test_fixture",
    }
    result = DiagnosticOrchestrator().run(
        {"session_id": "demo-001", "complaint": "My laptop is slow."},
        [evidence],
    )

    assert len(result.collected_evidence) == 1
    assert result.collected_evidence[0].data["utilization_percent"] == 96
    assert "collected_evidence" not in result.model_dump(mode="json")


def test_diagnostic_result_defaults_to_no_collected_evidence() -> None:
    result = DiagnosticOrchestrator().run(
        {"session_id": "demo-empty", "complaint": "My laptop is slow."}
    )

    assert result.collected_evidence == []
    assert "collected_evidence" not in result.model_dump(mode="json")


def test_contradictory_evidence_keeps_diagnosis_inconclusive() -> None:
    now = datetime.now(timezone.utc)
    result = DiagnosticOrchestrator().run(
        {"session_id": "demo-conflict", "complaint": "DNS resolution is failing."},
        [
            {
                "session_id": "demo-conflict",
                "evidence_id": "dns.failed",
                "evidence_type": "network.dns_resolution",
                "collected_at": now.isoformat(),
                "status": "available",
                "data": {"hostname": "diagnostic.example", "success": False},
            },
            {
                "session_id": "demo-conflict",
                "evidence_id": "dns.success",
                "evidence_type": "network.dns_resolution",
                "collected_at": now.isoformat(),
                "status": "available",
                "data": {"hostname": "diagnostic.example", "success": True},
            },
        ],
    )

    assert result.status.value == "inconclusive"
    assert result.ranked_root_causes[0].supporting_evidence_ids == ["dns.failed"]
    assert result.ranked_root_causes[0].contradicting_evidence_ids == ["dns.success"]
    assert result.remediation_candidate is None
    assert result.ranked_root_causes[0].remediation_candidate is None
