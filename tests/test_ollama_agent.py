import json
from urllib import error

from diagnostic_intelligence.ai.ollama_agent import OllamaAgent


def test_parse_json_accepts_plain_and_wrapped_objects() -> None:
    assert OllamaAgent._parse_json('{"value": 3}') == {"value": 3}
    assert OllamaAgent._parse_json('Result:\n{"value": 3}\nDone') == {"value": 3}


def test_parse_json_rejects_invalid_or_non_object_output() -> None:
    assert OllamaAgent._parse_json("not JSON") is None
    assert OllamaAgent._parse_json("[1, 2]") is None
    assert OllamaAgent._parse_json('prefix {"value": } suffix') is None


def test_is_available_uses_configured_ollama_endpoint(monkeypatch) -> None:
    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    seen = {}

    def fake_urlopen(req, timeout):
        seen["url"] = req.full_url
        seen["timeout"] = timeout
        return Response()

    monkeypatch.setattr("diagnostic_intelligence.ai.ollama_agent.request.urlopen", fake_urlopen)
    agent = OllamaAgent(base_url="http://ollama.test:11434/", timeout=7)

    assert agent.is_available() is True
    assert seen == {"url": "http://ollama.test:11434/api/tags", "timeout": 7}


def test_is_available_returns_false_when_service_is_unavailable(monkeypatch) -> None:
    def unavailable(*args, **kwargs):
        raise error.URLError("offline")

    monkeypatch.setattr("diagnostic_intelligence.ai.ollama_agent.request.urlopen", unavailable)

    assert OllamaAgent().is_available() is False


def test_classification_rejects_invalid_model_output(monkeypatch) -> None:
    monkeypatch.setattr(OllamaAgent, "_call_model", lambda self, prompt: json.dumps({"primary_category": "not-real"}))

    assert OllamaAgent().classify_complaint("My laptop is slow.") is None


def test_plan_and_correlation_prompts_receive_only_evidence_summaries(monkeypatch) -> None:
    prompts = []

    def fake_call(self, prompt):
        prompts.append(prompt)
        return "not-json"

    monkeypatch.setattr(OllamaAgent, "_call_model", fake_call)
    evidence = [
        {
            "evidence_id": "performance.cpu",
            "evidence_type": "performance.cpu",
            "status": "available",
            "data": {
                "utilization_percent": 91,
                "private_raw_value": "should not be sent",
                "processes": [{"name": "private-process.exe"}],
            },
        }
    ]
    agent = OllamaAgent()

    assert agent.generate_diagnostic_plan({"primary_category": "system_performance"}, evidence) is None
    assert agent.correlate_evidence({}, {}, evidence) is None
    assert len(prompts) == 2
    assert all('"utilization_percent": 91' in prompt for prompt in prompts)
    assert all("private_raw_value" not in prompt for prompt in prompts)
    assert all("should not be sent" not in prompt for prompt in prompts)
    assert all("private-process.exe" not in prompt for prompt in prompts)
