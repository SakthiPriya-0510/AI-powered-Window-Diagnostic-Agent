from datetime import datetime, timezone
import subprocess

import pytest
from fastapi.testclient import TestClient

from diagnostic_intelligence import api
from diagnostic_intelligence.api import create_app
from diagnostic_intelligence.collectors.windows import WindowsEvidenceCollector
from diagnostic_intelligence.collectors import windows as windows_collector
from diagnostic_intelligence.models.evidence import (
    EvidenceRecord,
    EvidenceStatus,
    EvidenceType,
)
from diagnostic_intelligence.services.audit import AuditLogger
from diagnostic_intelligence.services.remediation import RemediationService


TEST_REMEDIATION_TOKEN = "test-only-remediation-token-32-bytes-minimum"
AUTH_HEADERS = {"Authorization": f"Bearer {TEST_REMEDIATION_TOKEN}"}


def authorized_test_client(app):
    return TestClient(app, headers=AUTH_HEADERS)


class StubCollector:
    def collect_for_plan(self, plan):
        return [
            EvidenceRecord(
                session_id=plan.session_id,
                evidence_id="performance.cpu",
                evidence_type="performance.cpu",
                collected_at=datetime.now(timezone.utc),
                status="available",
                data={"utilization_percent": 96},
                source="windows_resource_collector",
            )
        ]


class UnavailableCollector:
    def collect_for_plan(self, plan):
        return [
            EvidenceRecord(
                session_id=plan.session_id,
                evidence_id=request.evidence_id,
                evidence_type=request.evidence_type,
                collected_at=datetime.now(timezone.utc),
                status=EvidenceStatus.UNAVAILABLE,
                data={"reason": "not configured"},
                source="test_collector",
            )
            for request in plan.evidence_requests
        ]


class DnsStubCollector:
    def __init__(self, *, initial_success=False, include_failure_category=True):
        self.calls = 0
        self.initial_success = initial_success
        self.include_failure_category = include_failure_category

    def collect_for_plan(self, plan):
        records = []
        current = self.calls
        self.calls += 1
        for request in plan.evidence_requests:
            if request.evidence_type == EvidenceType.DNS_RESOLUTION:
                data = {
                    "hostname": "diagnostic.example",
                    "success": current > 0 or self.initial_success,
                }
                if self.include_failure_category or current > 0 or self.initial_success:
                    data["error_category"] = (
                        None
                        if current > 0 or self.initial_success
                        else "name_resolution_failed"
                    )
                status = EvidenceStatus.AVAILABLE
            else:
                data = {"reason": "not configured"}
                status = EvidenceStatus.UNAVAILABLE
            records.append(
                EvidenceRecord(
                    session_id=plan.session_id,
                    evidence_id=request.evidence_id,
                    evidence_type=request.evidence_type,
                    collected_at=datetime.now(timezone.utc),
                    status=status,
                    data=data,
                    source="windows_resource_collector",
                )
            )
        return records


def test_health_endpoint_reports_service_ready(tmp_path) -> None:
    client = TestClient(create_app(collector_factory=StubCollector, audit_directory=tmp_path))

    response = client.get("/api/health")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_diagnostic_endpoint_runs_and_retrieves_session(tmp_path) -> None:
    client = TestClient(create_app(collector_factory=StubCollector, audit_directory=tmp_path))

    response = client.post(
        "/api/diagnostics",
        json={
            "session_id": "api-test-001",
            "complaint": "My laptop is slow.",
            "use_ai": False,
        },
    )

    assert response.status_code == 200
    result = response.json()
    assert result["status"] == "analysis_complete"
    assert result["ranked_root_causes"][0]["cause_id"] == "performance.cpu_saturation"
    assert client.get("/api/diagnostics/api-test-001").json() == result


def test_api_collects_application_event_metadata_and_correlates_it(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(windows_collector.platform, "system", lambda: "Windows")

    def query_windows(query, timeout):
        if query == windows_collector._APPLICATION_LOG_QUERY:
            return [
                {
                    "timestamp": "2026-10-26T10:00:00Z",
                    "provider": "ExampleApp",
                    "event_id": 1001,
                    "level": "Error",
                }
                for _ in range(3)
            ]
        if query == windows_collector._RUNTIME_VERSIONS_QUERY:
            return {"runtimes": []}
        raise AssertionError("Unexpected PowerShell query in mocked API test")

    monkeypatch.setattr(
        WindowsEvidenceCollector,
        "_run_windows_json",
        staticmethod(query_windows),
    )
    client = TestClient(
        create_app(
            collector_factory=WindowsEvidenceCollector,
            audit_directory=tmp_path,
        )
    )

    response = client.post(
        "/api/diagnostics",
        json={
            "session_id": "api-application-events",
            "complaint": "My application keeps crashing.",
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "analysis_complete"
    assert payload["ranked_root_causes"][0]["cause_id"] == "application.recurring_errors"
    assert "collected_evidence" not in payload
    assert any("application.logs: available" in item for item in payload["evidence_summary"])
    assert any("application.startup: unavailable" in item for item in payload["evidence_summary"])


def test_diagnostic_endpoint_does_not_create_ollama_when_ai_is_disabled(monkeypatch, tmp_path) -> None:
    def unexpected_ollama(*args, **kwargs):
        raise AssertionError("Ollama must not be created when AI is disabled")

    monkeypatch.setattr(api, "OllamaAgent", unexpected_ollama)
    client = TestClient(create_app(collector_factory=StubCollector, audit_directory=tmp_path))

    response = client.post(
        "/api/diagnostics",
        json={"session_id": "api-no-ai-test", "complaint": "My laptop is slow."},
    )

    assert response.status_code == 200
    assert response.json()["ai_summary"] is None
    assert "collected_evidence" not in response.json()


def test_diagnosis_with_insufficient_evidence_is_inconclusive(tmp_path) -> None:
    client = TestClient(
        create_app(collector_factory=UnavailableCollector, audit_directory=tmp_path)
    )

    response = client.post(
        "/api/diagnostics",
        json={"session_id": "api-insufficient-evidence", "complaint": "Network is not working."},
    )

    assert response.status_code == 200
    assert response.json()["status"] == "inconclusive"
    assert response.json()["ranked_root_causes"] == []


def test_diagnostic_endpoint_rejects_blank_complaint(tmp_path) -> None:
    client = TestClient(create_app(collector_factory=StubCollector, audit_directory=tmp_path))

    response = client.post("/api/diagnostics", json={"complaint": "  "})

    assert response.status_code == 422


def test_get_diagnostic_returns_not_found_for_unknown_session(tmp_path) -> None:
    client = TestClient(create_app(collector_factory=StubCollector, audit_directory=tmp_path))

    response = client.get("/api/diagnostics/no-such-session")

    assert response.status_code == 404


def test_api_uses_long_timeout_for_optional_summary_only(monkeypatch, tmp_path) -> None:
    class FakeSummaryAgent:
        model = "test-model"
        timeouts = []

        def __init__(self, timeout):
            self.timeouts.append(timeout)

        def generate_diagnostic_summary(self, **kwargs):
            return "Summary based on supplied evidence."

    monkeypatch.setattr(api, "OllamaAgent", FakeSummaryAgent)
    client = TestClient(create_app(collector_factory=StubCollector, audit_directory=tmp_path))

    response = client.post(
        "/api/diagnostics",
        json={
            "session_id": "api-ai-test",
            "complaint": "My laptop is slow.",
            "use_ai": True,
        },
    )

    assert response.status_code == 200
    assert response.json()["ai_summary"] == "Summary based on supplied evidence."
    assert response.json()["ai_model"] == "test-model"
    assert FakeSummaryAgent.timeouts == [90]


def test_api_does_not_label_missing_summary_as_ollama_output(monkeypatch, tmp_path) -> None:
    class UnavailableSummaryAgent:
        model = "test-model"

        def __init__(self, timeout):
            self.timeout = timeout

        def generate_diagnostic_summary(self, **kwargs):
            return None

    monkeypatch.setattr(api, "OllamaAgent", UnavailableSummaryAgent)
    client = TestClient(create_app(collector_factory=StubCollector, audit_directory=tmp_path))

    response = client.post(
        "/api/diagnostics",
        json={
            "session_id": "api-no-summary-test",
            "complaint": "My laptop is slow.",
            "use_ai": True,
        },
    )

    assert response.status_code == 200
    assert response.json()["ai_summary"] is None
    assert response.json()["ai_model"] is None
    assert any("Optional Ollama summary could not be generated" in warning for warning in response.json()["warnings"])


def test_remediation_api_automatically_executes_and_verifies_dns_action(tmp_path) -> None:
    collector = DnsStubCollector()
    runner_calls = []
    remediation_service = RemediationService(
        AuditLogger(tmp_path / "audit"),
        command_runner=lambda args, **kwargs: (
            runner_calls.append((args, kwargs))
            or subprocess.CompletedProcess(args, 0)
        ),
        platform_name="Windows",
    )
    client = authorized_test_client(
        create_app(
            collector_factory=lambda: collector,
            remediation_service=remediation_service,
            remediation_token=TEST_REMEDIATION_TOKEN,
        )
    )
    diagnosis = client.post(
        "/api/diagnostics",
        json={
            "session_id": "api-dns-remediation",
            "complaint": "DNS resolution for the diagnostic hostname is failing.",
        },
    )

    assert diagnosis.status_code == 200
    result = diagnosis.json()
    assert result["ranked_root_causes"][0]["cause_id"] == "network.dns_failure"
    assert result["remediation_candidate"]["action_type"] == "flush_dns_cache"
    assert "collected_evidence" not in result
    audit_path = next((tmp_path / "audit").glob("*.jsonl"))
    audit_text = audit_path.read_text(encoding="utf-8")
    assert '"event_type": "diagnosis_completed"' in audit_text
    assert "DNS resolution for the diagnostic hostname is failing." not in audit_text
    assert "diagnostic.example" not in audit_text
    assert "name_resolution_failed" not in audit_text

    response = client.post(
        "/api/diagnostics/api-dns-remediation/remediations",
        json={"action_type": "flush_dns_cache", "mode": "automatic"},
    )

    assert response.status_code == 200
    assert response.json()["execution_status"] == "succeeded"
    assert response.json()["verification"]["status"] == "verified_success"
    assert runner_calls[0][0][0].endswith("System32\\ipconfig.exe")
    assert runner_calls[0][0][1] == "/flushdns"
    assert runner_calls[0][1]["shell"] is False


def test_successful_dns_evidence_does_not_create_failure_or_execute_action(tmp_path) -> None:
    collector = DnsStubCollector(initial_success=True)
    runner_calls = []
    remediation_service = RemediationService(
        AuditLogger(tmp_path / "audit"),
        command_runner=lambda *args, **kwargs: runner_calls.append(args),
        platform_name="Windows",
    )
    client = authorized_test_client(
        create_app(
            collector_factory=lambda: collector,
            remediation_service=remediation_service,
            remediation_token=TEST_REMEDIATION_TOKEN,
        )
    )

    diagnosis = client.post(
        "/api/diagnostics",
        json={
            "session_id": "api-dns-success",
            "complaint": "DNS seems broken, but the configured lookup works.",
        },
    )
    response = client.post(
        "/api/diagnostics/api-dns-success/remediations",
        json={"action_type": "flush_dns_cache", "mode": "automatic"},
    )

    assert diagnosis.status_code == 200
    assert diagnosis.json()["ranked_root_causes"] == []
    assert diagnosis.json()["remediation_candidate"] is None
    assert response.status_code == 409
    assert runner_calls == []


def test_failed_dns_without_action_preconditions_is_blocked_by_api(tmp_path) -> None:
    collector = DnsStubCollector(include_failure_category=False)
    runner_calls = []
    remediation_service = RemediationService(
        AuditLogger(tmp_path / "audit"),
        command_runner=lambda *args, **kwargs: runner_calls.append(args),
        platform_name="Windows",
    )
    client = authorized_test_client(
        create_app(
            collector_factory=lambda: collector,
            remediation_service=remediation_service,
            remediation_token=TEST_REMEDIATION_TOKEN,
        )
    )

    diagnosis = client.post(
        "/api/diagnostics",
        json={
            "session_id": "api-dns-unconfirmed-failure",
            "complaint": "DNS resolution fails for the configured test hostname.",
        },
    )
    response = client.post(
        "/api/diagnostics/api-dns-unconfirmed-failure/remediations",
        json={"action_type": "flush_dns_cache", "mode": "automatic"},
    )

    assert diagnosis.status_code == 200
    assert diagnosis.json()["ranked_root_causes"][0]["cause_id"] == "network.dns_failure"
    assert diagnosis.json()["remediation_candidate"] is None
    assert response.status_code == 409
    assert runner_calls == []


@pytest.mark.parametrize(
    ("runner", "expected_status"),
    [
        (
            lambda args, **kwargs: subprocess.CompletedProcess(
                args, 1, stdout="PRIVATE_COMMAND_OUTPUT", stderr="PRIVATE_COMMAND_ERROR"
            ),
            "failed",
        ),
        (
            lambda args, **kwargs: (_ for _ in ()).throw(
                subprocess.TimeoutExpired(args, kwargs["timeout"], output="PRIVATE_TIMEOUT_OUTPUT")
            ),
            "timed_out",
        ),
    ],
)
def test_api_reports_execution_failure_and_timeout_without_claiming_recovery(
    tmp_path, runner, expected_status
) -> None:
    collector = DnsStubCollector()
    remediation_service = RemediationService(
        AuditLogger(tmp_path / "audit"),
        command_runner=runner,
        platform_name="Windows",
    )
    client = authorized_test_client(
        create_app(
            collector_factory=lambda: collector,
            remediation_service=remediation_service,
            remediation_token=TEST_REMEDIATION_TOKEN,
        )
    )
    client.post(
        "/api/diagnostics",
        json={
            "session_id": f"api-dns-{expected_status}",
            "complaint": (
                "DNS resolution is failing for the configured hostname. "
                f"Private complaint marker {expected_status}."
            ),
        },
    )

    response = client.post(
        f"/api/diagnostics/api-dns-{expected_status}/remediations",
        json={"action_type": "flush_dns_cache", "mode": "automatic"},
    )

    assert response.status_code == 200
    assert response.json()["execution_status"] == expected_status
    assert response.json()["verification"]["status"] == "verified_success"
    audit_text = "".join(
        path.read_text(encoding="utf-8")
        for path in (tmp_path / "audit").glob("*.jsonl")
    )
    assert "PRIVATE_COMMAND_OUTPUT" not in audit_text
    assert "PRIVATE_COMMAND_ERROR" not in audit_text
    assert "PRIVATE_TIMEOUT_OUTPUT" not in audit_text
    assert f"Private complaint marker {expected_status}." not in audit_text


def test_api_prevents_duplicate_remediation_requests(tmp_path) -> None:
    collector = DnsStubCollector()
    runner_calls = []
    remediation_service = RemediationService(
        AuditLogger(tmp_path / "audit"),
        command_runner=lambda args, **kwargs: (
            runner_calls.append(args)
            or subprocess.CompletedProcess(args, 0)
        ),
        platform_name="Windows",
    )
    client = authorized_test_client(
        create_app(
            collector_factory=lambda: collector,
            remediation_service=remediation_service,
            remediation_token=TEST_REMEDIATION_TOKEN,
        )
    )
    client.post(
        "/api/diagnostics",
        json={
            "session_id": "api-dns-duplicate",
            "complaint": "DNS resolution is failing for the test hostname.",
        },
    )
    payload = {"action_type": "flush_dns_cache", "mode": "automatic"}

    first = client.post("/api/diagnostics/api-dns-duplicate/remediations", json=payload)
    second = client.post("/api/diagnostics/api-dns-duplicate/remediations", json=payload)

    assert first.status_code == 200
    assert second.status_code == 409
    assert len(runner_calls) == 1


def test_remediation_api_requires_approval_before_action(tmp_path) -> None:
    collector = DnsStubCollector()
    calls = []
    remediation_service = RemediationService(
        AuditLogger(tmp_path / "audit"),
        command_runner=lambda *args, **kwargs: calls.append(args),
        platform_name="Windows",
    )
    client = authorized_test_client(
        create_app(
            collector_factory=lambda: collector,
            remediation_service=remediation_service,
            remediation_token=TEST_REMEDIATION_TOKEN,
        )
    )
    client.post(
        "/api/diagnostics",
        json={
            "session_id": "api-dns-approval",
            "complaint": "DNS resolution for the diagnostic hostname is failing.",
        },
    )

    pending = client.post(
        "/api/diagnostics/api-dns-approval/remediations",
        json={"action_type": "flush_dns_cache", "mode": "approval_required"},
    )

    assert pending.status_code == 200
    assert pending.json()["execution_status"] == "awaiting_approval"
    assert calls == []
    denied = client.post(
        f"/api/remediations/{pending.json()['execution_id']}/approval",
        json={"approved": False},
    )
    assert denied.status_code == 200
    assert denied.json()["execution_status"] == "denied"
    assert calls == []
    replay = client.post(
        f"/api/remediations/{pending.json()['execution_id']}/approval",
        json={"approved": True},
    )
    assert replay.status_code == 404
    assert calls == []


def test_remediation_api_executes_only_after_approval(tmp_path) -> None:
    collector = DnsStubCollector()
    calls = []
    remediation_service = RemediationService(
        AuditLogger(tmp_path / "audit"),
        command_runner=lambda args, **kwargs: (
            calls.append(args)
            or subprocess.CompletedProcess(args, 0)
        ),
        platform_name="Windows",
    )
    client = authorized_test_client(
        create_app(
            collector_factory=lambda: collector,
            remediation_service=remediation_service,
            remediation_token=TEST_REMEDIATION_TOKEN,
        )
    )
    client.post(
        "/api/diagnostics",
        json={
            "session_id": "api-dns-approved",
            "complaint": "DNS resolution for the configured diagnostic hostname is failing.",
        },
    )
    pending = client.post(
        "/api/diagnostics/api-dns-approved/remediations",
        json={"action_type": "flush_dns_cache", "mode": "approval_required"},
    )

    assert pending.status_code == 200
    assert pending.json()["execution_status"] == "awaiting_approval"
    assert calls == []
    unauthenticated_approval = TestClient(client.app).post(
        f"/api/remediations/{pending.json()['execution_id']}/approval",
        json={"approved": True},
    )
    assert unauthenticated_approval.status_code == 401
    assert calls == []
    approved = client.post(
        f"/api/remediations/{pending.json()['execution_id']}/approval",
        json={"approved": True},
    )

    assert approved.status_code == 200
    assert approved.json()["approval_decision"] is True
    assert approved.json()["execution_status"] == "succeeded"
    assert len(calls) == 1
    replay = client.post(
        f"/api/remediations/{pending.json()['execution_id']}/approval",
        json={"approved": True},
    )
    assert replay.status_code == 404
    assert len(calls) == 1


def test_remediation_endpoints_require_configured_bearer_token(tmp_path) -> None:
    collector = DnsStubCollector()
    calls = []
    remediation_service = RemediationService(
        AuditLogger(tmp_path / "audit"),
        command_runner=lambda args, **kwargs: (
            calls.append(args) or subprocess.CompletedProcess(args, 0)
        ),
        platform_name="Windows",
    )
    app = create_app(
        collector_factory=lambda: collector,
        remediation_service=remediation_service,
        remediation_token=TEST_REMEDIATION_TOKEN,
    )
    client = TestClient(app)
    client.post(
        "/api/diagnostics",
        json={
            "session_id": "api-dns-auth",
            "complaint": "DNS resolution for the configured hostname is failing.",
        },
    )
    request_payload = {
        "action_type": "flush_dns_cache",
        "mode": "automatic",
    }

    missing = client.post(
        "/api/diagnostics/api-dns-auth/remediations",
        json=request_payload,
    )
    incorrect = client.post(
        "/api/diagnostics/api-dns-auth/remediations",
        json=request_payload,
        headers={"Authorization": "Bearer incorrect-token"},
    )

    assert missing.status_code == 401
    assert incorrect.status_code == 401
    assert calls == []

    authorized = client.post(
        "/api/diagnostics/api-dns-auth/remediations",
        json=request_payload,
        headers=AUTH_HEADERS,
    )
    assert authorized.status_code == 200
    assert len(calls) == 1


def test_remediation_is_disabled_when_token_is_not_configured(tmp_path) -> None:
    client = TestClient(create_app(audit_directory=tmp_path))

    response = client.post(
        "/api/diagnostics/unknown/remediations",
        json={"action_type": "flush_dns_cache", "mode": "automatic"},
    )

    assert response.status_code == 503
    assert "WINDOWS_DIAGNOSTIC_API_TOKEN" in response.json()["detail"]


def test_remediation_api_rejects_unknown_action_and_lists_allowlist(tmp_path) -> None:
    client = TestClient(create_app(audit_directory=tmp_path))

    actions = client.get("/api/remediations/actions")
    rejected = client.post(
        "/api/diagnostics/unknown/remediations",
        json={"action_type": "delete_files", "mode": "automatic"},
    )

    assert actions.status_code == 200
    registered_actions = actions.json()["actions"]
    assert [item["action_type"] for item in registered_actions] == ["flush_dns_cache"]
    assert registered_actions[0]["automatic_allowed"] is True
    assert registered_actions[0]["supported_modes"] == ["automatic", "approval_required"]
    assert registered_actions[0]["timeout_seconds"] == 10
    assert registered_actions[0]["preconditions"]
    assert registered_actions[0]["verification_criteria"]
    assert rejected.status_code == 422