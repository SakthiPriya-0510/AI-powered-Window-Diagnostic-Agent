"""Minimal Ollama integration for optional AI-assisted diagnostic summaries."""

from __future__ import annotations

import json
from urllib import error, request


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

        response_text = result.get("response")
        if isinstance(response_text, str):
            return response_text.strip()
        return None

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
        try:
            parsed = json.loads(response)
        except json.JSONDecodeError:
            try:
                start = response.find("{")
                end = response.rfind("}")
                if start >= 0 and end > start:
                    parsed = json.loads(response[start : end + 1])
                else:
                    return None
            except json.JSONDecodeError:
                return None
        return parsed if isinstance(parsed, dict) else None

    def generate_diagnostic_plan(self, understanding: dict, evidence: list[dict] | None = None, session_id: str | None = None) -> dict | None:
        prompt = (
            "Return only valid JSON matching this schema: "
            "{\"session_id\": \"string or null\", \"category\": \"storage|network|system_performance|windows_health|application_compatibility|driver\", \"evidence_requests\": [{\"evidence_id\": \"string\", \"evidence_type\": \"string\", \"purpose\": \"string\", \"priority\": \"high|medium|low\", \"required\": true, \"parameters\": {}, \"time_window\": \"string or null\", \"expected_output_fields\": [\"string\"], \"privacy_notes\": \"string\"}], \"reasoning_summary\": \"string\"}. "
            "Use only predefined, non-executable evidence identifiers and do not invent commands. "
            f"Understanding: {json.dumps(understanding, ensure_ascii=True)}\n"
            f"Evidence: {json.dumps(evidence or [], ensure_ascii=True)}\n"
            f"SessionId: {session_id}"
        )
        response = self._call_model(prompt)
        if not response:
            return None
        try:
            parsed = json.loads(response)
        except json.JSONDecodeError:
            try:
                start = response.find("{")
                end = response.rfind("}")
                if start >= 0 and end > start:
                    parsed = json.loads(response[start : end + 1])
                else:
                    return None
            except json.JSONDecodeError:
                return None
        return parsed if isinstance(parsed, dict) else None

    def correlate_evidence(self, understanding: dict, plan: dict, evidence: list[dict], now: str | None = None) -> dict | None:
        prompt = (
            "Return only valid JSON with this shape: "
            "{\"candidates\": [{\"cause_id\": \"string\", \"title\": \"string\", \"explanation\": \"string\", \"supporting_evidence_ids\": [\"string\"], \"contradicting_evidence_ids\": [\"string\"], \"confidence_score\": 0.0, \"confidence_rationale\": \"string\", \"missing_evidence\": [\"string\"], \"suggested_next_step\": \"string\", \"remediation_candidate\": null}], \"warnings\": [\"string\"], \"missing\": [\"string\"]}. "
            "Only use the provided evidence and do not invent measurements. "
            f"Understanding: {json.dumps(understanding, ensure_ascii=True)}\n"
            f"Plan: {json.dumps(plan, ensure_ascii=True)}\n"
            f"Evidence: {json.dumps(evidence, ensure_ascii=True)}\n"
            f"Now: {now}"
        )
        response = self._call_model(prompt)
        if not response:
            return None
        try:
            parsed = json.loads(response)
        except json.JSONDecodeError:
            try:
                start = response.find("{")
                end = response.rfind("}")
                if start >= 0 and end > start:
                    parsed = json.loads(response[start : end + 1])
                else:
                    return None
            except json.JSONDecodeError:
                return None
        return parsed if isinstance(parsed, dict) else None

    def generate_diagnostic_summary(
        self,
        *,
        complaint: str,
        category: str,
        evidence_summary: list[str],
        root_causes: list[str],
    ) -> str:
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
        if not response:
            return "AI summary unavailable; deterministic evidence analysis remains the authoritative result."
        return response
