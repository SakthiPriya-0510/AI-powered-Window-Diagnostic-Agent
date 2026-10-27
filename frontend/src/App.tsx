import { useEffect, useState, type FormEvent } from 'react'
import {
  Activity,
  AlertCircle,
  ArrowDownRight,
  ArrowRight,
  Check,
  CheckCircle2,
  ChevronRight,
  CircleHelp,
  Clock3,
  Cpu,
  Database,
  HardDrive,
  LoaderCircle,
  MemoryStick,
  Network,
  Plus,
  Search,
  ShieldCheck,
  Sparkles,
} from 'lucide-react'
import './App.css'

type RootCause = {
  cause_id: string
  title: string
  explanation: string
  confidence_score: number
  confidence_rationale: string
  supporting_evidence_ids: string[]
  contradicting_evidence_ids: string[]
  missing_evidence: string[]
  suggested_next_step: string
}

type RemediationCandidate = {
  action_type: string
  purpose: string
  expected_effect: string
  risk_hint: string
  supporting_evidence_ids: string[]
  preconditions: string[]
  verification_criteria: string[]
}

type DiagnosticResult = {
  session_id: string | null
  primary_category: string
  secondary_categories: string[]
  problem_summary: string
  status: string
  evidence_summary: string[]
  evidence_requests: { evidence_id: string; evidence_type: string; required: boolean }[]
  ranked_root_causes: RootCause[]
  overall_uncertainty: string
  recommended_next_step: string
  user_facing_explanation: string
  warnings: string[]
  ai_summary: string | null
  ai_model: string | null
  remediation_candidate: RemediationCandidate | null
}

type RemediationExecution = {
  execution_id: string
  action_type: string
  purpose: string
  risk_hint: string
  mode: string
  approval_required: boolean
  approval_decision: boolean | null
  execution_status: string
  message: string
  verification: {
    status: string
    message: string
  } | null
  audit_warning: string | null
}

type RecentSession = {
  session_id: string
  complaint: string
  status: string
  category: string
}

const prompts = [
  'My laptop becomes slow after running for a while.',
  'Wi-Fi keeps disconnecting from my laptop.',
  'My system drive is almost full.',
]

const categoryIcons: Record<string, typeof Activity> = {
  system_performance: Cpu,
  network: Network,
  storage: HardDrive,
  windows_health: ShieldCheck,
  application_compatibility: Search,
  driver: Database,
  unknown: CircleHelp,
}

function pretty(value: string) {
  return value.replaceAll('_', ' ')
}

function App() {
  const [complaint, setComplaint] = useState('')
  const [useAi, setUseAi] = useState(false)
  const [result, setResult] = useState<DiagnosticResult | null>(null)
  const [remediation, setRemediation] = useState<RemediationExecution | null>(null)
  const [remediationBusy, setRemediationBusy] = useState(false)
  const [recent, setRecent] = useState<RecentSession[]>(() => {
    const saved = window.localStorage.getItem('diagnostic-sessions')
    if (!saved) return []
    try {
      return JSON.parse(saved) as RecentSession[]
    } catch {
      window.localStorage.removeItem('diagnostic-sessions')
      return []
    }
  })
  const [apiReady, setApiReady] = useState<boolean | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => {
    fetch('/api/health')
      .then((response) => setApiReady(response.ok))
      .catch(() => setApiReady(false))
  }, [])

  async function runDiagnosis(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!complaint.trim() || loading) return

    setLoading(true)
    setError('')
    setResult(null)
    setRemediation(null)
    try {
      const response = await fetch('/api/diagnostics', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ complaint: complaint.trim(), use_ai: useAi }),
      })
      const payload = await response.json()
      if (!response.ok) {
        throw new Error(payload.detail ?? 'The diagnostic request could not be completed.')
      }

      const nextResult = payload as DiagnosticResult
      setResult(nextResult)
      if (nextResult.session_id) {
        const entry: RecentSession = {
          session_id: nextResult.session_id,
          complaint: nextResult.problem_summary,
          status: nextResult.status,
          category: nextResult.primary_category,
        }
        setRecent((previous) => {
          const updated = [entry, ...previous.filter((item) => item.session_id !== entry.session_id)].slice(0, 5)
          window.localStorage.setItem('diagnostic-sessions', JSON.stringify(updated))
          return updated
        })
      }
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : 'Could not connect to the diagnostic API.')
    } finally {
      setLoading(false)
    }
  }

  async function openSession(sessionId: string) {
    setError('')
    setRemediation(null)
    try {
      const response = await fetch(`/api/diagnostics/${encodeURIComponent(sessionId)}`)
      const payload = await response.json()
      if (!response.ok) throw new Error(payload.detail ?? 'This session is no longer available.')
      setResult(payload as DiagnosticResult)
      setComplaint((payload as DiagnosticResult).problem_summary)
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : 'Could not load this session.')
    }
  }

  async function requestRemediation(mode: 'automatic' | 'approval_required') {
    if (!result?.session_id || !result.remediation_candidate || remediationBusy) return
    const remediationToken = window.prompt('Enter the local remediation API token.')
    if (!remediationToken) {
      setError('A local remediation API token is required.')
      return
    }
    setRemediationBusy(true)
    setError('')
    setRemediation(null)
    try {
      const response = await fetch(
        `/api/diagnostics/${encodeURIComponent(result.session_id)}/remediations`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${remediationToken}`,
          },
          body: JSON.stringify({
            action_type: result.remediation_candidate.action_type,
            mode,
          }),
        },
      )
      const payload = await response.json()
      if (!response.ok) {
        throw new Error(payload.detail ?? 'The remediation request could not be completed.')
      }
      let execution = payload as RemediationExecution
      setRemediation(execution)
      if (execution.execution_status === 'awaiting_approval') {
        const approved = window.confirm(
          `${execution.purpose}\n\nRisk: ${execution.risk_hint}\n\nApprove this action?`,
        )
        const approvalResponse = await fetch(
          `/api/remediations/${encodeURIComponent(execution.execution_id)}/approval`,
          {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              Authorization: `Bearer ${remediationToken}`,
            },
            body: JSON.stringify({ approved }),
          },
        )
        const approvalPayload = await approvalResponse.json()
        if (!approvalResponse.ok) {
          throw new Error(approvalPayload.detail ?? 'The approval decision could not be recorded.')
        }
        execution = approvalPayload as RemediationExecution
        setRemediation(execution)
      }
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : 'The remediation request could not be completed.')
    } finally {
      setRemediationBusy(false)
    }
  }

  return (
    <div className="app-shell">
      <header className="topbar">
        <a className="brand" href="#home" aria-label="Fieldnote diagnostics home">
          <span className="brand-mark"><Activity size={17} strokeWidth={2.5} /></span>
          <span>fieldnote<span className="brand-period">.</span></span>
        </a>
        <div className="topbar-right">
          <span className={`connection ${apiReady === false ? 'connection-offline' : ''}`}>
            <span className="connection-dot" />
            {apiReady === null ? 'Checking local service' : apiReady ? 'Local service online' : 'Local service offline'}
          </span>
          <span className="topbar-divider" />
          <span className="local-badge"><ShieldCheck size={14} /> Runs on this device</span>
        </div>
      </header>

      <main id="home" className="workspace">
        <section className="workspace-heading">
          <div>
            <div className="eyebrow"><span>WINDOWS</span><span className="eyebrow-slash">/</span><span>DIAGNOSTICS</span></div>
            <h1>Diagnostic desk</h1>
            <p className="heading-copy">A measured look at what your PC is doing.</p>
          </div>
          <div className="date-stamp"><span className="date-indicator" /> LOCAL SESSION</div>
        </section>

        <div className="main-grid">
          <section className="primary-column">
            <section className="intake-panel" aria-labelledby="complaint-heading">
              <div className="panel-topline">
                <div className="step-index">01</div>
                <div className="panel-title-group">
                  <h2 id="complaint-heading">Describe the problem</h2>
                  <p>Include what happened and when you noticed it.</p>
                </div>
              </div>
              <form onSubmit={runDiagnosis}>
                <label className="sr-only" htmlFor="complaint">Describe the Windows problem</label>
                <textarea
                  id="complaint"
                  value={complaint}
                  onChange={(event) => setComplaint(event.target.value)}
                  maxLength={4000}
                  placeholder="For example: My laptop becomes slow after running for about an hour..."
                  rows={5}
                  disabled={loading}
                />
                <div className="form-meta">
                  <span>{complaint.length.toLocaleString()} / 4,000</span>
                  <span><ShieldCheck size={14} /> Complaint text stays local</span>
                </div>
                <div className="form-footer">
                  <label className="ai-toggle" htmlFor="ai-summary">
                    <input
                      id="ai-summary"
                      type="checkbox"
                      checked={useAi}
                      onChange={(event) => setUseAi(event.target.checked)}
                      disabled={loading}
                    />
                    <span className="toggle-track" aria-hidden="true"><span /></span>
                    <span className="toggle-label"><Sparkles size={15} /> Add Ollama summary</span>
                  </label>
                  <button className="run-button" type="submit" disabled={!complaint.trim() || loading || apiReady === false}>
                    {loading ? <LoaderCircle className="spin" size={17} /> : <ArrowRight size={17} />}
                    {loading ? 'Collecting and analyzing' : 'Run diagnosis'}
                  </button>
                </div>
              </form>
              {error && <div className="error-banner" role="alert"><AlertCircle size={17} />{error}</div>}
              {apiReady === false && (
                <div className="service-banner"><AlertCircle size={16} /> Start the local API to begin a session.</div>
              )}
              {!result && !loading && (
                <div className="prompt-row" aria-label="Example complaints">
                  <span>TRY</span>
                  {prompts.map((prompt) => (
                    <button type="button" key={prompt} onClick={() => setComplaint(prompt)}>{prompt}</button>
                  ))}
                </div>
              )}
            </section>

            {loading && (
              <section className="progress-panel" aria-live="polite">
                <div className="progress-symbol"><LoaderCircle className="spin" size={20} /></div>
                <div><strong>Reading local system metrics</strong><p>Collecting planned evidence, then comparing it with the complaint.</p></div>
                <span className="progress-timer"><Clock3 size={14} /> IN PROGRESS</span>
              </section>
            )}

            {result && (
              <Results
                result={result}
                remediation={remediation}
                remediationBusy={remediationBusy}
                onRemediate={(mode) => void requestRemediation(mode)}
              />
            )}
          </section>

          <aside className="side-column">
            <section className="session-panel">
              <div className="side-heading">
                <div><span className="side-kicker">WORKSPACE</span><h2>Sessions</h2></div>
                <button
                  type="button"
                  className="icon-button"
                  title="Start a new session"
                  aria-label="Start a new session"
                  onClick={() => { setResult(null); setRemediation(null); setComplaint(''); setError('') }}
                ><Plus size={17} /></button>
              </div>
              {recent.length ? (
                <div className="session-list">
                  {recent.map((session) => (
                    <button className="session-item" key={session.session_id} type="button" onClick={() => void openSession(session.session_id)}>
                      <span className="session-icon"><Activity size={15} /></span>
                      <span className="session-text"><strong>{session.complaint}</strong><small>{pretty(session.category)} · {pretty(session.status)}</small></span>
                      <ChevronRight size={15} className="session-chevron" />
                    </button>
                  ))}
                </div>
              ) : (
                <div className="empty-sessions"><span className="empty-icon"><Clock3 size={17} /></span><p>No sessions yet</p></div>
              )}
              <div className="session-note"><span className="note-line" />Session results live in the API process and reset when it restarts.</div>
            </section>

            <section className="scope-panel">
              <div className="scope-icon"><ShieldCheck size={18} /></div>
              <div>
                <h3>Evidence before action</h3>
                <p>Diagnosis only reads evidence. A separately requested, allowlisted DNS cache action can be run automatically or after explicit approval, then checked again.</p>
              </div>
            </section>

            <div className="side-footer"><span>LOCAL DIAGNOSTIC MODULE</span><span>v0.1</span></div>
          </aside>
        </div>
      </main>
      <footer className="app-footer"><span>FIELDNOTE / WINDOWS DIAGNOSTICS</span><span>Findings are evidence-based, not a guarantee of cause or resolution.</span></footer>
    </div>
  )
}

function Results({
  result,
  remediation,
  remediationBusy,
  onRemediate,
}: {
  result: DiagnosticResult
  remediation: RemediationExecution | null
  remediationBusy: boolean
  onRemediate: (mode: 'automatic' | 'approval_required') => void
}) {
  const CategoryIcon = categoryIcons[result.primary_category] ?? Activity
  const StatusIcon = result.status === 'analysis_complete'
    ? CheckCircle2
    : result.status === 'inconclusive'
      ? CircleHelp
      : AlertCircle

  return (
    <section className="results-panel" aria-labelledby="results-heading">
      <div className="results-header">
        <div className="panel-topline results-topline">
          <div className="step-index step-index-complete"><Check size={14} /></div>
          <div className="panel-title-group"><span className="side-kicker">SESSION {result.session_id?.slice(0, 8).toUpperCase()}</span><h2 id="results-heading">Diagnostic result</h2></div>
        </div>
        <span className={`status-pill status-${result.status}`}><StatusIcon size={14} />{pretty(result.status)}</span>
      </div>

      <div className="classification-strip">
        <div className="category-tile"><span className="category-glyph"><CategoryIcon size={18} /></span><span><small>PRIMARY CATEGORY</small><strong>{pretty(result.primary_category)}</strong></span></div>
        {result.secondary_categories.map((category) => {
          const Icon = categoryIcons[category] ?? Activity
          return <div className="category-tile category-secondary" key={category}><span className="category-glyph"><Icon size={17} /></span><span><small>ALSO DETECTED</small><strong>{pretty(category)}</strong></span></div>
        })}
      </div>

      {result.ai_summary && (
        <div className="ai-summary"><Sparkles size={16} /><div><span>OLLAMA SUMMARY{result.ai_model ? ` · ${result.ai_model}` : ''}</span><p>{result.ai_summary}</p></div></div>
      )}

      <div className="section-rule"><span>RANKED FINDINGS</span><span>{result.ranked_root_causes.length.toString().padStart(2, '0')}</span></div>
      {result.ranked_root_causes.length ? (
        <div className="findings-list">
          {result.ranked_root_causes.map((cause, index) => (
            <article className="finding-row" key={cause.cause_id}>
              <span className="finding-rank">{String(index + 1).padStart(2, '0')}</span>
              <div className="finding-content">
                <h3>{cause.title}</h3>
                <p>{cause.explanation}</p>
                <div className="finding-meta"><span><CheckCircle2 size={13} />{cause.supporting_evidence_ids.length} supporting signal{cause.supporting_evidence_ids.length === 1 ? '' : 's'}</span><span>{cause.confidence_rationale}</span></div>
                {cause.supporting_evidence_ids.length > 0 && <p className="finding-evidence">Supporting evidence: {cause.supporting_evidence_ids.join(', ')}</p>}
                {cause.contradicting_evidence_ids.length > 0 && <p className="finding-evidence finding-conflict">Contradicting evidence: {cause.contradicting_evidence_ids.join(', ')}</p>}
                {cause.missing_evidence.length > 0 && <p className="finding-evidence">Follow-up evidence: {cause.missing_evidence.join('; ')}</p>}
              </div>
              <ArrowDownRight className="finding-arrow" size={16} />
            </article>
          ))}
        </div>
      ) : (
        <div className="no-findings"><CircleHelp size={18} /><div><strong>No supported cause yet</strong><p>{result.user_facing_explanation}</p></div></div>
      )}

      <div className="evidence-section">
        <div className="section-rule"><span>COLLECTED EVIDENCE</span><span>{result.evidence_summary.length.toString().padStart(2, '0')}</span></div>
        {result.evidence_summary.length ? (
          <ul className="evidence-list">
            {result.evidence_summary.map((item) => {
              const [type, ...details] = item.split(': ')
              const detail = details.join(': ')
              const status = detail.split(' ')[0]
              const Icon = type.includes('network') ? Network : type.includes('memory') ? MemoryStick : type.includes('cpu') ? Cpu : type.includes('storage') ? HardDrive : Activity
              return <li key={item}><span className="evidence-icon"><Icon size={15} /></span><span className="evidence-type">{type.replaceAll('.', ' ')}</span><span className={`evidence-status evidence-${status}`}>{status}</span><span className="evidence-detail">{detail.replace(/^[^ ]+\s?/, '')}</span></li>
            })}
          </ul>
        ) : <p className="empty-evidence">No evidence was collected for this session.</p>}
      </div>

      <div className="next-step"><span className="next-step-icon"><ArrowRight size={16} /></span><div><small>RECOMMENDED NEXT STEP</small><p>{result.recommended_next_step}</p></div></div>

      {result.remediation_candidate && (
        <section className="remediation-card" aria-labelledby="remediation-heading">
          <div className="section-rule"><span id="remediation-heading">ALLOWLISTED REMEDIATION OPTION</span></div>
          <h3>{result.remediation_candidate.purpose}</h3>
          <p>{result.remediation_candidate.expected_effect}</p>
          <p className="remediation-risk">{result.remediation_candidate.risk_hint}</p>
          <ul>
            {result.remediation_candidate.preconditions.map((item) => <li key={item}>{item}</li>)}
            {result.remediation_candidate.verification_criteria.map((item) => <li key={item}>{item}</li>)}
          </ul>
          <p>Remediation requires the local operator token. It is not saved by this page.</p>
          <div className="remediation-actions">
            <button type="button" disabled={remediationBusy || Boolean(remediation)} onClick={() => onRemediate('automatic')}>
              {remediationBusy ? 'Working…' : 'Run low-risk action'}
            </button>
            <button type="button" disabled={remediationBusy || Boolean(remediation)} onClick={() => onRemediate('approval_required')}>
              Require approval first
            </button>
          </div>
          {remediation && (
            <div className="remediation-outcome" aria-live="polite">
              <strong>{pretty(remediation.execution_status)}</strong>
              <p>{remediation.message}</p>
              {remediation.verification && (
                <p><b>Verification: {pretty(remediation.verification.status)}.</b> {remediation.verification.message}</p>
              )}
              {remediation.audit_warning && <p className="warning-line">{remediation.audit_warning}</p>}
            </div>
          )}
        </section>
      )}

      {(result.warnings.length > 0 || result.evidence_requests.length > 0) && (
        <details className="details-disclosure">
          <summary><span>Collection details</span><ChevronRight size={15} /></summary>
          <div className="details-content">
            {result.warnings.map((warning) => <p className="warning-line" key={warning}><AlertCircle size={14} />{warning}</p>)}
            <p className="request-count">{result.evidence_requests.length} evidence request(s) remain in the plan.</p>
          </div>
        </details>
      )}

      <div className="uncertainty-note"><ShieldCheck size={14} /><span>{result.overall_uncertainty}</span></div>
    </section>
  )
}

export default App
