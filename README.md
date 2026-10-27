# Secure AI-Powered Windows Diagnostic Agent — Intelligence Module

This repository contains a deterministic-first Windows diagnostic package, a local evidence collector, a FastAPI bridge, and a React/Vite diagnostic console. The console submits complaints to the API; the API plans evidence collection, gathers supported host metrics, correlates the evidence with explicit rules, and returns a structured result. A narrow remediation workflow is implemented for one evidence-supported action: flushing the local DNS resolver cache after a confirmed configured-host lookup failure. It supports automatic execution of this low-risk allowlisted action or an explicit approval-required mode, re-collects DNS evidence, and records privacy-minimized audit events. This is not a general remediation system; no other system-changing action is allowlisted.

The collector reads aggregate CPU, memory, disk I/O, process, and volume-capacity metrics; network adapter and route metadata; configured DNS and endpoint connectivity checks; and bounded Windows event/reliability metadata. Windows collection uses fixed, read-only PowerShell queries for event logs, reliability records, routes, and gateway reachability. No user- or model-provided commands are run, and the collector does not change settings or apply fixes. API sessions are held in memory and are cleared when the API process restarts. Confidence scores are heuristic evidence-strength scores, not measured probabilities.

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
Set-Location .\frontend
npm ci
Set-Location ..
```

Alternatively install the Python runtime dependencies with `python -m pip install -r requirements.txt`.

## Package layout

- `diagnostic_intelligence/models/`: Pydantic v2 request, evidence, plan, and result contracts.
- `diagnostic_intelligence/engines/problem_understanding.py`: deterministic six-category phrase classifier and clarification handling, with optional LLM classification only when explicitly configured.
- `diagnostic_intelligence/engines/diagnostic_decision.py`: targeted evidence planner; references only predefined evidence types.
- `diagnostic_intelligence/engines/root_cause_correlation.py`: evidence rules, missing/stale checks, and ranked heuristic findings; it does not execute actions.
- `diagnostic_intelligence/engines/diagnostic_orchestrator.py`: end-to-end orchestration, separate optional engine-LLM and summary-agent injection, and malformed evidence handling.
- `diagnostic_intelligence/collectors/windows.py`: bounded local CPU, memory, process-summary, disk-I/O, volume-capacity, System event, reliability incident, and network metadata collection.
- `diagnostic_intelligence/services/remediation.py`: strict action allowlist, evidence/precondition checks, approval gate, fixed-command execution, duplicate prevention, and post-action DNS verification.
- `diagnostic_intelligence/services/audit.py`: privacy-minimized JSONL workflow audit with hashed session references and a per-day tamper-evident hash chain.
- `tests/`: synthetic evidence tests and mocked collector tests; they do not replace validation on a real Windows host.
- `examples/`: sample API request and collector evidence.

## Run the local application

From the project root, activate the Python environment if needed, configure a fresh local remediation token, and start the backend in the first PowerShell terminal. Keep the terminal open; the token is held in that terminal's environment and printed so it can be pasted into the UI prompt or Swagger header.

```powershell
.\.venv\Scripts\Activate.ps1
$token = python -c "import secrets; print(secrets.token_urlsafe(32))"
$env:WINDOWS_DIAGNOSTIC_API_TOKEN = $token
Write-Host "Local remediation token: $token"
.\.venv\Scripts\python.exe -m uvicorn diagnostic_intelligence.api:app --host 127.0.0.1 --port 8000
```

In a second PowerShell terminal, from the project root, start the frontend:

```powershell
Set-Location .\frontend
npm ci
npm run dev -- --host 127.0.0.1
```

Open `http://127.0.0.1:5173`. The Vite development server proxies `/api` requests to `127.0.0.1:8000`. `npm ci` installs the exact dependency versions recorded in `frontend/package-lock.json`.

Uvicorn must remain bound to loopback and run as a single worker. The command above explicitly uses `--host 127.0.0.1`; do not change this to `0.0.0.0`, enable untrusted proxy forwarding, add workers, or otherwise expose the service to a LAN or the internet. This application does not enforce the bind address itself, so deployment configuration must preserve loopback-only access. Diagnostic and read-only routes do not require authentication and must only be reachable locally. Remediation requests and approval decisions require the `Authorization: Bearer <token>` header and are disabled with HTTP 503 unless `WINDOWS_DIAGNOSTIC_API_TOKEN` is configured with at least 32 bytes; generate a high-entropy token with a cryptographically secure generator. The same shared token authorizes both requesting and approving actions; it does not identify individual users or provide role separation. The frontend prompts for the token when remediation is requested and does not save it.

Approval is a one-time decision bound to a randomly generated execution ID. Only a pending execution can be approved; replayed, unknown, or already-decided approval IDs are rejected, and preconditions are checked again after approval. The service uses in-process locks; state and duplicate protection are not coordinated across multiple API processes. Run one Uvicorn worker and do not run multiple instances against the same audit directory. Sessions, collectors, pending approvals, and execution state remain in memory and are cleared when the API process restarts; no diagnostic/session database is introduced. JSONL audit files persist under `audit_logs/` relative to the API working directory. New daily records include a hash chain that detects accidental or partial edits before later appends, but it is not a digital signature or protection against a privileged attacker who can rewrite the complete file. Legacy records without hashes are retained as unverified chain anchors. Keep audit storage access restricted and do not expose this API to untrusted browser origins.

### API endpoints

| Method and path | Purpose |
|---|---|
| `GET /api/health` | Return service readiness. |
| `POST /api/diagnostics` | Classify a complaint, collect planned evidence, and return evidence-based findings. `use_ai` is optional and defaults to `false`. |
| `GET /api/diagnostics/{session_id}` | Retrieve an in-memory diagnostic result; collected evidence is excluded from the response. |
| `GET /api/remediations/actions` | List the actual fixed action allowlist and its preconditions. |
| `POST /api/diagnostics/{session_id}/remediations` | Request an allowlisted action in `automatic` or `approval_required` mode. Requires the remediation bearer token. |
| `POST /api/remediations/{execution_id}/approval` | Submit an explicit `approved` boolean for a pending approval-required action. Requires the remediation bearer token; decisions are single-use. |

Diagnostic requests require a nonblank `complaint` of at most 4,000 characters, with an optional `session_id` (up to 128 characters), optional `context` object, and optional API-only `use_ai` boolean. Remediation requests require `action_type` and `mode`; currently the only supported action is `flush_dns_cache`. Approval requests contain only `{"approved": true}` or `{"approved": false}`. Invalid request schemas return HTTP 422; missing or invalid remediation tokens return HTTP 401; remediation is disabled if the token is unset or too short (HTTP 503); unknown sessions and non-pending approval IDs return HTTP 404; blocked remediation preconditions return HTTP 409. In Swagger, provide the `Authorization` header as `Bearer <your token>` for each remediation/approval operation. See `/docs` for the live OpenAPI schema.

Run the complete backend tests, compilation check, read-only Windows smoke test, frontend build, and frontend lint from the project root. This PowerShell block stops if a check fails:

```powershell
python -m pytest
if ($LASTEXITCODE -ne 0) { throw "Python tests failed." }
python -m compileall -q diagnostic_intelligence tests scripts
if ($LASTEXITCODE -ne 0) { throw "Python compilation failed." }
python scripts\windows_smoke_test.py
if ($LASTEXITCODE -ne 0) { throw "Windows smoke test reported an error." }
Push-Location .\frontend
npm ci
if ($LASTEXITCODE -ne 0) { Pop-Location; throw "Frontend dependency installation failed." }
npm run build
if ($LASTEXITCODE -ne 0) { Pop-Location; throw "Frontend build failed." }
npm run lint
if ($LASTEXITCODE -ne 0) { Pop-Location; throw "Frontend lint failed." }
Pop-Location
```

## AI and network behavior

The default orchestrator does not create or call an LLM. Python callers may separately inject `engine_llm` for optional classification, planning, and correlation, and `ai_agent` for optional final-summary generation. The API currently exposes only the summary opt-in. `OllamaAgent` defaults to `http://localhost:11434` and model `llama3.2`; Ollama is not a required dependency and is not required for deterministic diagnostics. If the service is unavailable, optional AI output is omitted and deterministic analysis remains authoritative. An explicitly configured non-local Ollama URL will receive the prompts sent to that agent.

DNS evidence is unavailable until `WINDOWS_DIAGNOSTIC_DNS_HOSTNAME` is set to an approved hostname. Optional TCP connectivity evidence requires all three settings: `WINDOWS_DIAGNOSTIC_CONNECTIVITY_ENDPOINT_ID`, `WINDOWS_DIAGNOSTIC_CONNECTIVITY_HOST`, and `WINDOWS_DIAGNOSTIC_CONNECTIVITY_PORT`. Only those configured targets are checked; no arbitrary hosts or browsing history are collected.

For example, in PowerShell set only destinations approved for your environment before starting the API:

```powershell
$env:WINDOWS_DIAGNOSTIC_DNS_HOSTNAME = "health.example"
$env:WINDOWS_DIAGNOSTIC_CONNECTIVITY_ENDPOINT_ID = "corp-health"
$env:WINDOWS_DIAGNOSTIC_CONNECTIVITY_HOST = "health.example"
$env:WINDOWS_DIAGNOSTIC_CONNECTIVITY_PORT = "443"
```

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

### Evidence currently supported

`collect_for_plan` has bounded collectors for:

- `performance.cpu`, `performance.memory`, `performance.process_summary`
- `storage.capacity`, `storage.disk_activity`, `storage.errors`
- `network.configuration`, `network.adapter_status`, `network.dns_resolution`, `network.gateway_reachability`, `network.connectivity`
- `windows.system_events`, `windows.reliability`
- `application.logs` (recent Windows Application event metadata only; no event messages)
- `application.runtime_versions` (installed .NET and Java runtime versions)
- `driver.device_status` and `driver.details` (problem devices only; hardware identifiers are hashed)
- `driver.events` (selected System event metadata only)
- `system.update_history` (up to 100 Windows hotfix entries; this is not driver update history)

`application.startup` remains **unsupported**. Determining whether an arbitrary named app started would require an explicit application identity and a safe, non-invasive startup signal; the collector will not launch applications. Unsupported Windows-only collectors return `UNAVAILABLE`, and collection/permission/timeout failures return `ERROR` with a bounded error type. Successful empty event, runtime, device-problem, driver, or update results remain `AVAILABLE` and report an empty list rather than pretending collection failed.

Windows event, reliability, route, gateway, application-log, runtime, PnP, driver, and hotfix queries require Windows PowerShell and the corresponding local provider/class/permissions. DNS and TCP connectivity require the explicit configuration above. The read-only application/runtime/device/update queries use fixed PowerShell statements, structured JSON output, bounded record counts, and subprocess timeouts; they do not read raw event messages, enumerate user files, or execute remediation.

The collector returns aggregate CPU utilization from three short samples (the median is used for correlation), memory totals, a bounded process summary (name, CPU percentage, and memory bytes), disk I/O rates/latency, configured-volume capacity, event metadata, and network adapter/IP/default-route metadata. Disk I/O does not expose a reliable utilization percentage; high-latency findings require at least five measured I/O operations during the sampling window. Process IDs, command lines, usernames, paths, raw event messages, and raw Plug-and-Play identifiers are omitted. Device identifiers are one-way hashes. Reliability evidence is limited to the last seven days and at most 50 incidents, with timestamp, incident type, product name, and event ID only. The gateway probe targets only the configured default gateway. Collection failures are returned as evidence records rather than aborting other metric collections.

### Current root-cause coverage

Correlation currently evaluates these evidence-backed findings:

| Category | Cause IDs | Evidence condition (summary) |
|---|---|---|
| Storage | `storage.low_free_space` | A volume is at or below 10% free or 2 GB free; healthy capacity is recorded as contradicting evidence. |
| Storage | `storage.disk_saturation` | High measured average I/O latency (at least 50 ms) with at least five operations, or explicit utilization evidence at/above 90%. |
| Storage | `storage.recurring_errors` | At least three repeated storage-provider/event-ID error records. |
| Network | `network.dns_failure` | DNS evidence explicitly reports a failed lookup; remediation additionally requires `name_resolution_failed` for a configured hostname. |
| Network | `network.gateway_unreachable` | An explicit default-gateway probe reports unreachable. |
| Network | `network.permitted_endpoint_unreachable` | A configured, permitted connectivity endpoint reports unreachable; success is scoped to that endpoint only. |
| Network | `network.adapter_unavailable` | All reported network adapters are explicitly down. |
| System performance | `performance.cpu_saturation` | Median of CPU samples is at least 85%; a single transient spike is not enough when a sample series is supplied. |
| System performance | `performance.memory_pressure` | Used memory is at least 90% or available memory is at most 10%. |
| System performance | `performance.disk_bottleneck` | Same measured latency/activity guard as the storage disk finding, when performance is in scope. |
| Windows health | `windows_health.recurring_errors` | At least three repeated System provider/event-ID error records. |
| Windows health | `windows_health.reliability_failure` | Reliability metadata records an application error or hang. |
| Application compatibility | `application.runtime_incompatibility` | Evidence explicitly identifies a missing/incompatible runtime; generic Windows Application event metadata does not imply this. |
| Application compatibility | `application.recurring_errors` | At least three recent Application log errors share a provider and event ID. |
| Application compatibility | `application.startup_failure` | Only if an independently supplied trusted collector provides an explicit startup outcome; the built-in collector does not. |
| Driver | `driver.device_error` | Windows PnP evidence reports a nonzero device problem code. |
| Driver | `driver.recurring_device_errors` | At least three repeated selected driver/System provider-event-ID errors. |

These are heuristic findings, not calibrated probabilities or proof of causation. Missing, stale, unavailable, or insufficient evidence does not imply failure. Contradictory evidence is surfaced and can keep a diagnosis inconclusive. Hotfix history is contextual only: a listed Windows update alone does not establish that it caused a driver or system problem. Windows driver event metadata is not guaranteed to identify a particular device.

### Safe Windows smoke test

From the project root, run:

```powershell
python scripts\windows_smoke_test.py
```

The script performs read-only local metric, event, runtime, PnP, driver, and hotfix collection. It deliberately does not test DNS, contact a network endpoint, start an application, or request remediation. Output is limited to platform/elevation state, evidence status, record counts, and safe unavailable/error reasons; raw records, names, paths, addresses, and event messages are not printed. It exits nonzero if any attempted collector reports `ERROR`; an unsupported `UNAVAILABLE` item such as application startup is reported but is not a script failure.

Run it without elevation first. Event log, WMI/CIM, or registry policies can restrict individual sources; the script reports per-source failures rather than requiring elevation or changing permissions. Whether particular checks require elevated access depends on Windows edition and local policy. No real DNS remediation is exercised by this smoke test.

Tests use synthetic evidence and mocks for host-specific collectors. Passing them, including on Linux, does not demonstrate successful collection on a real Windows installation. Validate PowerShell availability, permissions, installed Windows features, and the configured approved endpoints on the target Windows systems before deployment.

The result is JSON-serializable. Validated evidence records are available internally as `result.collected_evidence` for future verification work; that field is excluded from public serialization. Integrators should retain the returned session ID when one was generated by the orchestrator and use it for subsequent evidence requests.

## Remediation workflow

Diagnosis (`POST /api/diagnostics`) does not change host state. The rule engine proposes `flush_dns_cache` only for fresh available DNS evidence that explicitly reports `name_resolution_failed`; a passing DNS query does not create that finding. A reachable configured endpoint is evidence only about that endpoint, not every website or service. Contradictory measurements keep the diagnosis inconclusive and block remediation.

The allowlist currently contains exactly one action, `flush_dns_cache`, which invokes only the fixed argument vector `ipconfig.exe /flushdns` (no shell and no model/user command input) with a 10-second timeout. It clears the DNS resolver cache, not DNS server settings. The action is Windows-only, limited to findings linked to fresh evidence from the Windows collector, and prevented from running twice in one session. Destructive, privileged, driver, registry, security, and file-deletion operations are not allowlisted. Both automatic execution and approval-required execution require the bearer token; the automatic mode is not token-free.

After execution, the collector checks the same configured DNS hostname. The response reports command outcome separately from verification (`verified_success`, `failed`, `partial`, or `inconclusive`). A successful command is not itself proof of improved resolution; a successful hostname lookup is not proof that the original complaint is resolved or that internet services work generally. Approval-required mode creates a pending execution and runs nothing until the approval endpoint records an explicit `approved: true`. Denials are audited and do not execute the command.

### Controlled remediation validation

**Dry run (safe and automated):** `python -m pytest tests/test_remediation.py tests/test_api.py` uses a mocked command runner. It checks preconditions, duplicate prevention, approval, failures/timeouts, audit events, and DNS verification without invoking `ipconfig.exe` or changing the host. This is the recommended validation for routine development.

**Real-host procedure (not performed by the test suite):** the DNS flush changes the local DNS resolver cache. Do not follow these steps unless the Windows operator intentionally approves that change. Never use `automatic` mode for this controlled host-validation procedure.

1. Configure the bearer token and only an explicitly approved DNS hostname as described above; start the API bound to `127.0.0.1`, and open `http://127.0.0.1:8000/docs`.
2. Before any action, check `GET /api/health` and `GET /api/remediations/actions`. Use `POST /api/diagnostics` to gather fresh evidence:

   ```json
   {
     "session_id": "dns-remediation-demo",
     "complaint": "DNS resolution for the configured diagnostic hostname is failing."
   }
   ```

   Continue only if fresh evidence supports `network.dns_failure` and the response includes the `flush_dns_cache` candidate. If DNS succeeds, no DNS-failure candidate should be returned. Do not proceed on unavailable, stale, contradictory, or unconfirmed evidence.

3. Request an approval-gated execution using `POST /api/diagnostics/dns-remediation-demo/remediations`. Include `Authorization: Bearer <token>` where `<token>` is the value generated in the backend terminal:

   ```json
   {
     "action_type": "flush_dns_cache",
     "mode": "approval_required"
   }
   ```

   A response with `execution_status: "awaiting_approval"` does not run anything. Review the action, purpose, risk, and current conditions before proceeding.

4. Only after the local operator explicitly chooses to run it, call `POST /api/remediations/{execution_id}/approval` with the same bearer token and `{"approved": true}`. Choosing `{"approved": false}` denies it without execution. Approval is single-use and bound to that pending execution ID; stale or contradictory DNS evidence is rechecked and blocks execution.

5. Inspect `execution_status` and `verification.status` separately. The application re-collects fresh evidence for the same configured hostname after the command, and rejects evidence that predates verification. Independently run `Resolve-DnsName -Name "<approved-hostname>"` in PowerShell to check that hostname from the host; this checks only that lookup, not general internet access or whether the original user issue is resolved. If either check fails or is inconclusive, report it as such. A successful command alone is not success of verification.

Never approve unrelated actions or make additional network/system changes as part of this procedure. The real-host procedure requires an explicit user/operator approval at step 4; it was not run as part of automated validation.

Example completed response (the verification status depends on fresh Windows evidence):

```json
{
  "action_type": "flush_dns_cache",
  "execution_status": "succeeded",
  "approval_required": true,
  "message": "The Windows DNS cache flush command completed successfully.",
  "verification": {
    "status": "verified_success",
    "message": "The configured diagnostic hostname resolves after the action. This does not establish general internet access or resolution of the original complaint."
  }
}
```

The API returns HTTP 409 when evidence, candidate, platform, or policy preconditions block an action; unsupported action IDs are rejected by request validation. Read-only and diagnostic routes remain unauthenticated, so the loopback-only binding is mandatory. Remediation and approval operations require the shared local bearer token; this is a single-operator gate, not individual identity or role-based authorization. Audit records in `audit_logs/YYYY-MM-DD.jsonl` contain event types, a hashed session reference, cause/action IDs, approval outcomes, execution status, and verification status/evidence IDs; they omit complaint text, raw evidence values, and command output. If an audit event cannot be written before execution, the action is not started. Hash chains detect in-file edits only when validated during a later append; they are not keyed signatures, are not checked by a separate audit-verification command, and cannot prevent a privileged user from rewriting the full log. Legacy rows seed the chain as unverified content.

### Implemented scope and limitations

The diagnostic-only mode remains the default. Automatic execution and approval-required execution are separate request modes for the single allowlisted action. The registry does not yet contain remediation for storage, gateway, endpoint-connectivity, performance, Windows-health, application, or driver findings. Pending sessions/approvals do not survive an API restart. Diagnostic routes remain unauthenticated, while the shared remediation token has no user identity or role separation. The broad three-pipeline remediation design, protected high-risk workflows, durable session/approval storage, broader policy rules, and real-Windows remediation validation remain future work. Automated executor tests mock the command runner; they do not flush a DNS cache or validate remediation on a real Windows host.

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

When `use_ai=True` and an `ai_agent` is supplied, the orchestrator attempts to enrich the final result with an Ollama summary without replacing the deterministic decision flow. `use_ai` defaults to `False`. This optional summary call sends the complaint, category, concise evidence summary, and root-cause titles to the configured Ollama service.

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

Optional `RemediationCandidate` contains `action_candidate_id`, `related_cause_id`, a documented non-executable `action_type`, purpose, expected effect, risk hint, supporting evidence IDs, preconditions, and verification criteria. The only currently actionable candidate is `flush_dns_cache`, and it is created only for qualifying evidence of DNS resolution failure. The separate remediation service validates the candidate and evidence against its fixed allowlist before any execution. A candidate is not, by itself, authorization to execute.

### Intelligence module → API/frontend

`DiagnosticResult` returns the session/category, problem summary, status, factual evidence summary, evidence requests, ranked root causes, uncertainty explanation, recommended next step, optional remediation candidate, user-facing explanation, and warnings. Status values are `classified`, `collecting_evidence`, `analysis_complete`, `needs_clarification`, `inconclusive`, and `error`. `run()` returns `collecting_evidence`, `analysis_complete`, `needs_clarification`, or `inconclusive` as applicable; it never reports a fix as resolved.

## Deterministic behavior and privacy

- Classification is keyword/rule-based and may return `unknown` or request clarification.
- Root-cause rules require structured evidence; a complaint alone does not establish a cause.
- Competing findings are ranked by documented heuristic evidence strength. Do not present their scores as probabilities.
- User text and collected free-text logs are data, not instructions. The deterministic default does not call an LLM. Optional summary generation can send the complaint and concise evidence summaries to the configured Ollama service when explicitly enabled; only explicitly configured DNS/connectivity targets are contacted for those probes.
- The collector uses fixed, read-only PowerShell queries for selected Windows telemetry. The allowlisted DNS remediation executes a fixed `ipconfig.exe /flushdns` argument vector without a shell; it does not execute user- or model-provided commands.
- Audit events omit complaint text and raw evidence values, and new records are hash chained. This is tamper-evident rather than tamper-proof: filesystem administrators can rewrite the complete log, and legacy unchained events cannot be retroactively authenticated. Read-only APIs remain unauthenticated; only remediation and approval requests use the shared bearer token. This token is not identity-bound and does not provide per-user authorization. Run on loopback only; do not expose it to remote networks.

## Extending rules

Add category-specific phrase rules in `problem_understanding.py`, evidence types and category mappings in `models/evidence.py`, matching request descriptions in `diagnostic_decision.py`, and testable `CauseRule` entries in `root_cause_correlation.py`. Keep evidence thresholds explicit and add synthetic positive, negative, stale, and malformed fixtures/tests with each new rule.
