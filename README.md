# Secure AI-Powered Windows Diagnostic Agent — Intelligence Module

This repository contains a Windows diagnostic intelligence package, an opt-in local evidence collector, a FastAPI bridge, and a React/Vite diagnostic console. The console submits complaints to the local API; the API plans evidence collection, gathers supported local metrics, correlates evidence, and returns a structured result.

The collector currently reads CPU, memory, process summaries, disk I/O counters, configured-volume capacity, bounded Windows System event metadata, and network adapter/IP/default-route metadata. Its ICMP probe only targets the machine's configured default gateway. DNS checks require `WINDOWS_DIAGNOSTIC_DNS_HOSTNAME`. TCP connectivity checks require all of `WINDOWS_DIAGNOSTIC_CONNECTIVITY_ENDPOINT_ID`, `WINDOWS_DIAGNOSTIC_CONNECTIVITY_HOST`, and `WINDOWS_DIAGNOSTIC_CONNECTIVITY_PORT`; no arbitrary destination is contacted by default. It does not run user- or model-provided commands or apply fixes. API sessions are held in memory and are cleared when the API process restarts. Confidence scores are heuristic evidence-strength scores, not measured probabilities.

## Requirements and setup

- Python 3.11 or newer
- Pydantic 2
- psutil 5.9 or newer
- FastAPI and Uvicorn
- Node.js 20.19+ or 22.12+ for the frontend
- pytest 8 and HTTPX (development/test dependencies)

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
python -m pytest
```

Alternatively install the Python runtime dependencies with `python -m pip install -r requirements.txt`.

## Package layout

- `diagnostic_intelligence/models/`: Pydantic v2 request, evidence, plan, and result contracts.
- `diagnostic_intelligence/engines/problem_understanding.py`: deterministic six-category phrase classifier and clarification handling.
- `diagnostic_intelligence/engines/diagnostic_decision.py`: targeted evidence planner; references only predefined evidence types.
- `diagnostic_intelligence/engines/root_cause_correlation.py`: evidence rules, missing/stale checks, and ranked heuristic findings.
- `diagnostic_intelligence/engines/diagnostic_orchestrator.py`: end-to-end orchestration and malformed evidence handling.
- `diagnostic_intelligence/collectors/windows.py`: bounded local CPU, memory, process-summary, disk-I/O, volume-capacity, System event, reliability incident, and network metadata collection.
- `tests/`: synthetic test cases that require no Windows collectors.
- `examples/`: sample API request and collector evidence.

## Run the local application

Start the API in one PowerShell terminal from the repository root:

```powershell
.\.venv\Scripts\python.exe -m uvicorn diagnostic_intelligence.api:app --host 127.0.0.1 --port 8000
```

Start the frontend in a second terminal:

```powershell
cd frontend
npm install
npm run dev
```

Open `http://localhost:5173`. The Vite development server proxies `/api` requests to `127.0.0.1:8000`. The API listens on loopback and exposes `GET /api/health`, `POST /api/diagnostics`, and `GET /api/diagnostics/{session_id}`. Sessions are in-memory only; database persistence, approval workflows, and remediation are not implemented.

## Minimal example

```python
from datetime import datetime, timezone

from diagnostic_intelligence import DiagnosticOrchestrator

engine = DiagnosticOrchestrator()
result = engine.run(
    {
        "session_id": "demo-001",
        "complaint": "My laptop is extremely slow.",
    },
    evidence=[
        {
            "session_id": "demo-001",
            "evidence_id": "cpu.sample",
            "evidence_type": "performance.cpu",
            "collected_at": datetime.now(timezone.utc).isoformat(),
            "status": "available",
            "data": {"utilization_percent": 94},
            "source": "approved_cpu_collector",
        }
    ],
)
print(result.model_dump(mode="json"))
```

To collect those local metrics before analysis, use the optional Windows collector:

```python
from diagnostic_intelligence import DiagnosticOrchestrator, WindowsEvidenceCollector

session_id = "demo-001"
engine = DiagnosticOrchestrator(
    evidence_collector=WindowsEvidenceCollector(),
)
result = engine.run(
    {"session_id": session_id, "complaint": "My laptop is extremely slow."},
)
print(result.model_dump(mode="json"))
```

The collector currently returns aggregate CPU utilization, memory totals, a bounded process summary (name, CPU percentage, and memory bytes), disk I/O rates and average latency, configured-volume capacity, up to 100 recent warning/error/critical System events, and network adapter/IP/default-route metadata. Event records contain only timestamp, provider, event ID, and level; process IDs, command lines, usernames, paths, and raw event messages are omitted. Reliability Monitor evidence is limited to the last seven days and at most 50 incidents, with timestamp, incident type, product name, and event ID only. The gateway probe targets only the configured default gateway. DNS and TCP connectivity probes require the documented explicit environment configuration; no arbitrary destination or browsing history is collected. Disk utilization percentage is not reported because the Windows counters used here do not provide a reliable busy-time value. Collection errors are returned as evidence records rather than aborting the other metric collections.

The result is JSON-serializable. Integrators should retain the returned session ID when one was generated by the orchestrator and use it for subsequent evidence requests.

Optional local AI summary:

```python
from diagnostic_intelligence import DiagnosticOrchestrator, OllamaAgent

agent = OllamaAgent(model="llama3.2", base_url="http://localhost:11434")
result = DiagnosticOrchestrator().run(
    {"session_id": "demo-001", "complaint": "My laptop is slow."},
    evidence=[...],
    use_ai=True,
    ai_agent=agent,
)
print(result.ai_summary)
```

When `use_ai=True`, the orchestrator attempts to enrich the final result with a local Ollama summary without replacing the deterministic decision flow.

## Integration contracts

### API/frontend → intelligence module

`DiagnosticRequest` accepts:

- `session_id`: optional string (1–128 characters); generated when omitted.
- `complaint`: required nonblank string (at most 4,000 characters).
- `context`: optional JSON-like dictionary (at most 50 top-level fields). Current deterministic rules do not interpret arbitrary context as instructions.

Unknown request fields are rejected.

### Intelligence module → evidence collector

`DiagnosticPlan` contains `session_id`, primary `category`, a list of `evidence_requests`, and a `reasoning_summary`. Each `EvidenceRequest` has:

- `evidence_id`: stable identifier (for example `evidence_network_dns_resolution`).
- `evidence_type`: one of the documented `EvidenceType` identifiers below.
- `purpose`, `priority`, `required`, and non-executable `parameters`.
- Optional time window, expected output fields, and privacy notes.

The collector maps these identifiers to its own approved implementations; the plan does not contain shell commands. Categories map to:

| Category | Evidence types |
|---|---|
| `storage` | `storage.capacity`, `storage.disk_activity`, `storage.errors` |
| `network` | `network.configuration`, `network.dns_resolution`, `network.gateway_reachability`, `network.connectivity`, `network.adapter_status` |
| `system_performance` | `performance.cpu`, `performance.memory`, `storage.disk_activity`, `performance.process_summary` |
| `windows_health` | `windows.system_events`, `windows.reliability` |
| `application_compatibility` | `application.startup`, `application.logs`, `application.runtime_versions` |
| `driver` | `driver.device_status`, `driver.details`, `driver.events`, `system.update_history` |

### Evidence collector → intelligence module

Each `EvidenceRecord` contains:

- `session_id`, `evidence_id`, and `evidence_type`.
- Timezone-aware `collected_at` timestamp.
- `status`: `available`, `partial`, `unavailable`, or `error`.
- JSON-compatible `data` (maximum 100 KB and 200 top-level fields).
- Optional `source`; optional `error` is accepted only for `error` status.

Malformed evidence records are skipped with a warning; unavailable/error evidence is not scored. Evidence for a different session is ignored. Evidence older than 24 hours is considered stale by default and excluded from scoring.

### Intelligence module → remediation policy engine

Optional `RemediationCandidate` contains `action_candidate_id`, `related_cause_id`, a documented non-executable `action_type`, purpose, expected effect, risk hint, supporting evidence IDs, preconditions, and verification criteria. Initial action identifiers are `review_storage_cleanup` and `review_dns_configuration`. These are review suggestions, not permissions or executable instructions. Member 3 must independently allow, require approval for, or block any resulting action.

### Intelligence module → API/frontend

`DiagnosticResult` returns the session/category, problem summary, status, factual evidence summary, evidence requests, ranked root causes, uncertainty explanation, recommended next step, optional remediation candidate, user-facing explanation, and warnings. Status values are `classified`, `collecting_evidence`, `analysis_complete`, `needs_clarification`, `inconclusive`, and `error`. `run()` returns `collecting_evidence`, `analysis_complete`, `needs_clarification`, or `inconclusive` as applicable; it never reports a fix as resolved.

## Deterministic behavior and privacy

- Classification is keyword/rule-based and may return `unknown` or request clarification.
- Root-cause rules require structured evidence; a complaint alone does not establish a cause.
- Competing findings are ranked by documented heuristic evidence strength. Do not present their scores as probabilities.
- User text and collected free-text logs are data, not instructions. This implementation has no LLM, command execution, network calls, or Windows privileges.
- An optional local Ollama integration is available behind a separately configured provider and strict validated schemas. The default execution path remains deterministic and does not send evidence to an external model unless explicitly enabled.
- The collector should minimize and redact private content before returning evidence. API deployments should add authentication, authorization, and request rate/size controls.

## Extending rules

Add category-specific phrase rules in `problem_understanding.py`, evidence types and category mappings in `models/evidence.py`, matching request descriptions in `diagnostic_decision.py`, and testable `CauseRule` entries in `root_cause_correlation.py`. Keep evidence thresholds explicit and add synthetic positive, negative, stale, and malformed fixtures/tests with each new rule.
