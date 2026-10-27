"""Minimal Ollama integration for optional AI-assisted diagnostic summaries."""

from __future__ import annotations

import json
from urllib import error, request

from pydantic import ValidationError

from diagnostic_intelligence.models.classification import ProblemUnderstanding
from diagnostic_intelligence.models.diagnostic_plan import DiagnosticPlan
from diagnostic_intelligence.models.recommendations import RootCauseCandidate


_EVIDENCE_SUMMARY_FIELDS = (
    "utilization_percent",
    "used_percent",
    "available_percent",
    "free_percent",
    "free_gb",
    "success",
    "reachable",
    "started",
    "error_category",
    "recurring_error_count",
    "average_latency_ms",
    "read_bytes_per_second",
    "write_bytes_per_second",
    "observation_window_seconds",
)
_EVIDENCE_COUNT_FIELDS = (
    "volumes",
    "events",
    "incidents",
    "processes",
    "adapters",
    "errors",
    "runtimes",
    "devices",
)


class OllamaAgent:
    """Thin HTTP client for a local Ollama instance."""

    def __init__(
        self,
        base_url: str = "http://localhost:11434",
        model: str = "llama3.2",
        timeout: int = 20,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout

    def is_available(self) -> bool:
        """Return whether the configured Ollama service responds to its tags endpoint."""
        try:
            req = request.Request(f"{self.base_url}/api/tags", method="GET")
            with request.urlopen(req, timeout=self.timeout) as response:
                return 200 <= response.status < 300
        except (error.URLError, TimeoutError, OSError, ValueError):
            return False

    def _call_model(self, prompt: str) -> str | None:
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": 0.1},
        }
        endpoint = f"{self.base_url}/api/generate"
        data = json.dumps(payload).encode("utf-8")
        req = request.Request(endpoint, data=data, headers={"Content-Type": "application/json"})
        try:
            with request.urlopen(req, timeout=self.timeout) as response:
                body = response.read().decode("utf-8")
        except (error.URLError, TimeoutError, OSError, ValueError):
            return None

        try:
            result = json.loads(body)
        except (TypeError, json.JSONDecodeError):
            return None

        if not isinstance(result, dict):
            return None
        response_text = result.get("response")
        if isinstance(response_text, str):
            return response_text.strip()
        return None

    @staticmethod
    def _parse_json(response: str) -> dict | None:
        try:
            parsed = json.loads(response)
        except (TypeError, json.JSONDecodeError):
            start = response.find("{")
            end = response.rfind("}")
            if start < 0 or end <= start:
                return None
            try:
                parsed = json.loads(response[start : end + 1])
            except (TypeError, json.JSONDecodeError):
                return None
        return parsed if isinstance(parsed, dict) else None

    @staticmethod
    def _summarize_evidence(evidence: list[dict]) -> list[dict]:
        summaries = []
        for record in evidence:
            if not isinstance(record, dict):
                continue
            summary = {
                key: record[key]
                for key in ("evidence_id", "evidence_type", "status")
                if isinstance(record.get(key), str)
            }
            data = record.get("data")
            if isinstance(data, dict):
                facts = {
                    key: value[:128] if isinstance(value, str) else value
                    for key in _EVIDENCE_SUMMARY_FIELDS
                    if isinstance(
                        (value := data.get(key)),
                        (str, int, float, bool),
                    )
                }
                for key in _EVIDENCE_COUNT_FIELDS:
                    value = data.get(key)
                    if isinstance(value, list):
                        facts[f"{key}_count"] = len(value)
                if facts:
                    summary["data_summary"] = facts
            summaries.append(summary)
        return summaries

    def classify_complaint(self, complaint: str) -> dict | None:
        prompt = (
            "Return only valid JSON with this schema: "
            "{\n"
            "  \"primary_category\": \"storage|network|system_performance|windows_health|application_compatibility|driver|unknown\",\n"
            "  \"secondary_categories\": [\"...\"],\n"
            "  \"symptoms\": [\"...\"],\n"
            "  \"affected_component\": \"string or null\",\n"
            "  \"time_pattern\": \"string or null\",\n"
            "  \"recent_changes\": \"string or null\",\n"
            "  \"severity_or_impact\": \"string or null\",\n"
            "  \"missing_information\": [\"...\"],\n"
            "  \"clarification_questions\": [\"...\"],\n"
            "  \"needs_clarification\": false,\n"
            "  \"classification_confidence\": 0.0,\n"
            "  \"classification_explanation\": \"string\"\n"
            "}\n"
            "Do not output markdown. Do not invent evidence. Use only the complaint text. Complaint: "
            f"{complaint}"
        )
        response = self._call_model(prompt)
        if not response:
            return None
        parsed = self._parse_json(response)
        if parsed is None:
            return None
        try:
            understanding = ProblemUnderstanding.model_validate(
                {
                    **{
                        key: value
                        for key, value in parsed.items()
                        if key != "original_complaint"
                    },
                    "original_complaint": complaint,
                }
            )
        except (TypeError, ValueError, ValidationError):
            return None
        return understanding.model_dump(mode="json", exclude={"original_complaint"})

    def generate_diagnostic_plan(self, understanding: dict, evidence: list[dict] | None = None, session_id: str | None = None) -> dict | None:
        prompt = (
            "Return only valid JSON matching this schema: "
            "{\"session_id\": \"string or null\", \"category\": \"storage|network|system_performance|windows_health|application_compatibility|driver\", \"evidence_requests\": [{\"evidence_id\": \"string\", \"evidence_type\": \"string\", \"purpose\": \"string\", \"priority\": \"high|medium|low\", \"required\": true, \"parameters\": {}, \"time_window\": \"string or null\", \"expected_output_fields\": [\"string\"], \"privacy_notes\": \"string\"}], \"reasoning_summary\": \"string\"}. "
            "Use only predefined, non-executable evidence identifiers and do not invent commands. "
            f"Understanding: {json.dumps(understanding, ensure_ascii=True)}\n"
            f"Evidence summary: {json.dumps(self._summarize_evidence(evidence or []), ensure_ascii=True)}\n"
            f"SessionId: {session_id}"
        )
        response = self._call_model(prompt)
        if not response:
            return None
        parsed = self._parse_json(response)
        if parsed is None:
            return None
        try:
            plan = DiagnosticPlan.model_validate(parsed)
        except (TypeError, ValueError, ValidationError):
            return None
        if session_id is not None and plan.session_id != session_id:
            return None
        return plan.model_dump(mode="json")

    def correlate_evidence(self, understanding: dict, plan: dict, evidence: list[dict], now: str | None = None) -> dict | None:
        prompt = (
            "Return only valid JSON with this shape: "
            "{\"candidates\": [{\"cause_id\": \"string\", \"title\": \"string\", \"explanation\": \"string\", \"supporting_evidence_ids\": [\"string\"], \"contradicting_evidence_ids\": [\"string\"], \"confidence_score\": 0.0, \"confidence_rationale\": \"string\", \"missing_evidence\": [\"string\"], \"suggested_next_step\": \"string\", \"remediation_candidate\": null}], \"warnings\": [\"string\"], \"missing\": [\"string\"]}. "
            "Only use the provided evidence and do not invent measurements. "
            f"Understanding: {json.dumps(understanding, ensure_ascii=True)}\n"
            f"Plan: {json.dumps(plan, ensure_ascii=True)}\n"
            f"Evidence summary: {json.dumps(self._summarize_evidence(evidence), ensure_ascii=True)}\n"
            f"Now: {now}"
        )
        response = self._call_model(prompt)
        if not response:
            return None
        parsed = self._parse_json(response)
        if parsed is None:
            return None
        candidates = parsed.get("candidates")
        warnings = parsed.get("warnings")
        missing = parsed.get("missing")
        if not (
            isinstance(candidates, list)
            and isinstance(warnings, list)
            and all(isinstance(item, str) for item in warnings)
            and isinstance(missing, list)
            and all(isinstance(item, str) for item in missing)
        ):
            return None
        try:
            validated_candidates = [
                RootCauseCandidate.model_validate(candidate)
                for candidate in candidates
            ]
        except (TypeError, ValueError, ValidationError):
            return None
        evidence_ids = {
            item.get("evidence_id")
            for item in evidence
            if isinstance(item, dict) and isinstance(item.get("evidence_id"), str)
        }
        if any(
            candidate.remediation_candidate is not None
            or not set(candidate.supporting_evidence_ids).issubset(evidence_ids)
            or not set(candidate.contradicting_evidence_ids).issubset(evidence_ids)
            for candidate in validated_candidates
        ):
            return None
        return {
            "candidates": [
                candidate.model_dump(mode="json")
                for candidate in validated_candidates
            ],
            "warnings": warnings,
            "missing": missing,
        }

    def generate_diagnostic_summary(
        self,
        *,
        complaint: str,
        category: str,
        evidence_summary: list[str],
        root_causes: list[str],
    ) -> str | None:
        """Generate a concise, safety-constrained summary from a local Ollama model."""
        prompt = (
            "You are a safety-constrained diagnostic assistant. Use only the structured evidence below "
            "and do not claim a fix or resolution. Summarize the likely issue in 2 to 3 sentences. "
            "Keep it factual and explain uncertainty carefully.\n\n"
            f"Complaint: {complaint}\n"
            f"Category: {category}\n"
            f"Evidence: {json.dumps(evidence_summary, ensure_ascii=True)}\n"
            f"Root causes: {json.dumps(root_causes, ensure_ascii=True)}"
        )
        response = self._call_model(prompt)
        return response or None
