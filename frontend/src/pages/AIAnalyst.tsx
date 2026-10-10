import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { aiApi, findingApi, scanApi } from '../api/client'

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: '#ff1744',
  HIGH: '#ff5722',
  MEDIUM: '#ff9800',
  LOW: '#ffc107',
  INFO: '#38bdf8',
}

function formatDate(value?: string) {
  if (!value) return '—'
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? '—' : date.toLocaleString()
}

export default function AIAnalyst() {
  const navigate = useNavigate()
  const [selectedId, setSelectedId] = useState('')
  const [analysis, setAnalysis] = useState<any>(null)
  const [analyzing, setAnalyzing] = useState(false)
  const [analysisError, setAnalysisError] = useState<string | null>(null)

  const findingsQuery = useQuery({
    queryKey: ['ai-analyst-findings'],
    queryFn: () => findingApi.list({ limit: 100 }),
    retry: false,
    refetchInterval: 15000,
  })
  const scansQuery = useQuery({
    queryKey: ['ai-analyst-scans'],
    queryFn: () => scanApi.list({ limit: 10 }),
    retry: false,
    refetchInterval: 15000,
  })
  const findings: any[] = Array.isArray(findingsQuery.data) ? findingsQuery.data : []
  const scans: any[] = Array.isArray(scansQuery.data) ? scansQuery.data : []
  const selectedFinding = findings.find(f => String(f.id) === selectedId) || null

  useEffect(() => {
    if (selectedFinding || !findings.length) return
    setSelectedId(String(findings[0].id))
  }, [findings, selectedFinding])

  const activeScans = scans.filter(s => ['PENDING', 'RUNNING'].includes(String(s.status || '').toUpperCase())).length
  const criticalCount = findings.filter(f => String(f.severity).toUpperCase() === 'CRITICAL').length
  const highCount = findings.filter(f => String(f.severity).toUpperCase() === 'HIGH').length

  const runAnalysis = async () => {
    if (!selectedFinding) {
      setAnalysisError('There is no saved finding to analyze. Run an authorized scan first.')
      return
    }
    setAnalyzing(true)
    setAnalysis(null)
    setAnalysisError(null)
    try {
      const endpoint = selectedFinding.affected_url || selectedFinding.endpoint || 'Endpoint not recorded'
      const cves = Array.isArray(selectedFinding.cve_ids) ? selectedFinding.cve_ids.join(', ') : ''
      const tags = Array.isArray(selectedFinding.tags) ? selectedFinding.tags.join(', ') : ''
      const context = [
        'Analyze the following saved scanner finding. Distinguish facts present in the record from hypotheses. Do not claim a vulnerability is exploited or verified unless the stored evidence establishes that.',
        `Finding: ${selectedFinding.title || 'Untitled'}`,
        `Severity: ${selectedFinding.severity || 'INFO'}`,
        `Scanner: ${selectedFinding.plugin || selectedFinding.scanner || 'unknown'}`,
        `Template: ${selectedFinding.template_id || 'not recorded'}`,
        `Asset: ${selectedFinding.asset_value || 'not recorded'}`,
        `Endpoint: ${endpoint}`,
        `CVE identifiers: ${cves || 'none recorded'}`,
        `CVSS score: ${selectedFinding.cvss_score ?? 'not recorded'}`,
        `Tags: ${tags || 'none recorded'}`,
        `Description: ${selectedFinding.description || 'No description returned by scanner'}`,
      ].join('\n')
      const result = await aiApi.analyze({
        context,
        mode: 'blue',
        finding_ids: [String(selectedFinding.id)],
      })
      setAnalysis(result)
    } catch (err: any) {
      setAnalysisError(String(err?.response?.data?.detail || err?.message || 'AI analysis request failed.'))
    } finally {
      setAnalyzing(false)
    }
  }

  const statusColor = (status: string) => {
    const s = String(status || '').toUpperCase()
    return ['COMPLETED', 'SUCCESS'].includes(s) ? '#00ff88'
      : ['FAILED', 'FAILURE', 'CANCELLED'].includes(s) ? '#ff3b5c'
      : ['RUNNING', 'PENDING', 'STARTED'].includes(s) ? '#a855f7'
      : 'var(--color-text-muted)'
  }

  return (
    <div>
      <div className="page-header" style={{ marginBottom: 'var(--space-6)' }}>
        <div>
          <h1 className="page-title" style={{ background: 'linear-gradient(135deg, #a855f7, #00e5ff)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
            ⚡ AI HUNTER
          </h1>
          <p className="page-subtitle">Evidence-first reasoning on findings stored by connected scanners. Analysis requires a configured AI provider.</p>
          <div style={{ fontSize: '0.68rem', color: 'var(--color-text-muted)', marginTop: 5 }}>
            No scan is launched automatically from this page.
          </div>
        </div>
        <div className="flex gap-2">
          <button className="btn btn-ghost" onClick={() => navigate('/web-security')}>Web Security →</button>
          <button className="btn btn-primary" onClick={() => navigate('/findings')}>View Findings →</button>
        </div>
      </div>

      {(findingsQuery.isError || scansQuery.isError) && (
        <div role="alert" className="card" style={{ marginBottom: 'var(--space-5)', color: 'var(--color-high)' }}>
          One or more backend requests failed. Displayed counts only use API responses that were successfully received.
        </div>
      )}

      <div className="stats-grid mb-6" style={{ gridTemplateColumns: 'repeat(4, 1fr)' }}>
        {[
          { label: 'Stored Findings', value: findings.length, color: 'var(--color-cyan)', icon: '◈' },
          { label: 'Critical', value: criticalCount, color: '#ff1744', icon: '!' },
          { label: 'High', value: highCount, color: '#ff5722', icon: '⚠' },
          { label: 'Active Scan Jobs', value: activeScans, color: '#a855f7', icon: '⌁' },
        ].map(item => (
          <div key={item.label} className="stat-card" style={{ '--card-accent': item.color } as any}>
            <div className="stat-icon">{item.icon}</div>
            <div className="stat-value" style={{ color: item.color }}>{item.value}</div>
            <div className="stat-label">{item.label}</div>
          </div>
        ))}
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'minmax(280px, 0.9fr) minmax(0, 1.3fr)', gap: 'var(--space-5)', alignItems: 'start' }}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}>
          <div className="card">
            <div className="card-header">
              <span className="card-title">Select a saved finding</span>
              <span style={{ fontSize: '0.65rem', color: 'var(--color-text-muted)' }}>API DATA</span>
            </div>
            {findingsQuery.isLoading ? (
              <div style={{ color: 'var(--color-text-muted)', fontSize: '0.8rem' }}>Loading saved findings…</div>
            ) : findings.length ? (
              <>
                <label className="form-label" htmlFor="ai-finding-select">Finding to analyze</label>
                <select
                  id="ai-finding-select"
                  className="input"
                  value={selectedId}
                  onChange={e => { setSelectedId(e.target.value); setAnalysis(null); setAnalysisError(null) }}
                  style={{ width: '100%', marginBottom: 'var(--space-3)' }}
                >
                  {findings.map(f => (
                    <option key={f.id} value={String(f.id)}>
                      [{String(f.severity || 'INFO').toUpperCase()}] {f.title}
                    </option>
                  ))}
                </select>
                {selectedFinding && (
                  <div style={{ padding: 'var(--space-3)', border: '1px solid var(--color-border)', borderRadius: 'var(--radius-md)', background: 'rgba(255,255,255,0.025)' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap', marginBottom: 8 }}>
                      <span className={`badge badge-${String(selectedFinding.severity || 'info').toLowerCase()}`}>
                        {String(selectedFinding.severity || 'INFO').toUpperCase()}
                      </span>
                      <span style={{ fontSize: '0.72rem', color: 'var(--color-text-muted)' }}>
                        CVSS {selectedFinding.cvss_score ?? '—'}
                      </span>
                    </div>
                    <div style={{ fontWeight: 700, fontSize: '0.9rem', marginBottom: 8 }}>{selectedFinding.title}</div>
                    <div style={{ fontSize: '0.74rem', color: 'var(--color-text-muted)', overflowWrap: 'anywhere' }}>
                      {selectedFinding.affected_url || selectedFinding.endpoint || selectedFinding.asset_value || 'No affected endpoint recorded'}
                    </div>
                    <div style={{ fontSize: '0.73rem', color: 'var(--color-text-muted)', marginTop: 7 }}>
                      Source: {selectedFinding.plugin || selectedFinding.scanner || 'unknown'} · Recorded {formatDate(selectedFinding.created_at)}
                    </div>
                    <div style={{ fontSize: '0.78rem', marginTop: 10, lineHeight: 1.5 }}>
                      {selectedFinding.description || 'The scanner did not return a description.'}
                    </div>
                  </div>
                )}
                <button className="btn btn-primary w-full" style={{ marginTop: 'var(--space-4)' }} onClick={runAnalysis} disabled={analyzing || !selectedFinding}>
                  {analyzing ? 'Analyzing stored evidence…' : '⚡ Analyze with configured AI'}
                </button>
                <div style={{ fontSize: '0.68rem', color: 'var(--color-text-muted)', marginTop: 8 }}>
                  Only metadata from the selected database record is sent for analysis; raw requests and responses are not included by this screen.
                </div>
              </>
            ) : (
              <div style={{ textAlign: 'center', padding: 'var(--space-6)', color: 'var(--color-text-muted)' }}>
                <div style={{ fontSize: '2rem', marginBottom: 8 }}>◈</div>
                <strong>No stored findings available</strong>
                <div style={{ fontSize: '0.8rem', marginTop: 6 }}>Run a scan against an authorized target in an active scope, then return here to analyze its findings.</div>
                <button className="btn btn-primary" style={{ marginTop: 12 }} onClick={() => navigate('/web-security')}>Open Web Security</button>
              </div>
            )}
          </div>

          <div className="card">
            <div className="card-header"><span className="card-title">Recent Scan Jobs</span></div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              {scans.slice(0, 6).map(scan => (
                <div key={scan.id} style={{ border: '1px solid var(--color-border)', borderRadius: 6, padding: 9, background: 'rgba(255,255,255,0.02)' }}>
                  <div style={{ display: 'flex', gap: 8, alignItems: 'start', justifyContent: 'space-between' }}>
                    <div style={{ fontWeight: 600, fontSize: '0.78rem', lineHeight: 1.4 }}>{scan.name || scan.plugin || 'Scan job'}</div>
                    <span style={{ color: statusColor(scan.status), fontSize: '0.65rem', fontWeight: 800, whiteSpace: 'nowrap' }}>{scan.status || 'UNKNOWN'}</span>
                  </div>
                  <div style={{ fontSize: '0.68rem', color: 'var(--color-text-muted)', marginTop: 4 }}>{(scan.targets || []).join(', ') || 'No targets recorded'}</div>
                  <div style={{ fontSize: '0.65rem', color: 'var(--color-text-muted)', marginTop: 3 }}>{formatDate(scan.created_at)}</div>
                </div>
              ))}
              {!scansQuery.isLoading && !scans.length && <div style={{ color: 'var(--color-text-muted)', fontSize: '0.8rem' }}>No scan jobs recorded yet.</div>}
            </div>
          </div>
        </div>

        <div className="card" style={{ border: '1px solid rgba(168,85,247,0.3)', background: 'linear-gradient(135deg, rgba(168,85,247,0.04), rgba(0,229,255,0.025))' }}>
          <div className="card-header">
            <div>
              <span className="card-title" style={{ color: '#a855f7' }}>AI Analysis Result</span>
              <div style={{ fontSize: '0.7rem', color: 'var(--color-text-muted)', marginTop: 3 }}>Results from the configured provider; no mock output.</div>
            </div>
            {analysis && <span className={`badge badge-${String(analysis.severity || 'info').toLowerCase()}`}>{analysis.severity}</span>}
          </div>

          {analyzing && (
            <div style={{ padding: 'var(--space-6)', color: 'var(--color-text-muted)', textAlign: 'center' }}>
              Waiting for the AI provider to analyze the stored finding…
            </div>
          )}
          {analysisError && !analyzing && (
            <div role="alert" style={{ padding: 'var(--space-4)', borderRadius: 8, border: '1px solid rgba(255,59,92,0.3)', background: 'rgba(255,59,92,0.07)', color: 'var(--color-high)', fontSize: '0.82rem', whiteSpace: 'pre-wrap' }}>
              <strong>AI analysis unavailable or failed.</strong>
              <div style={{ marginTop: 7 }}>{analysisError}</div>
              <div style={{ color: 'var(--color-text-muted)', fontSize: '0.72rem', marginTop: 7 }}>Check OPENAI_API_KEY or ANTHROPIC_API_KEY and the model configuration in the backend environment.</div>
            </div>
          )}
          {!analysis && !analysisError && !analyzing && (
            <div style={{ padding: 'var(--space-8)', color: 'var(--color-text-muted)', textAlign: 'center' }}>
              <div style={{ fontSize: '2.5rem', marginBottom: 10 }}>🧠</div>
              <strong>No AI analysis run yet</strong>
              <div style={{ fontSize: '0.8rem', marginTop: 7 }}>Select a saved finding, then request analysis. Nothing will be reported as “confirmed” unless the input evidence supports it.</div>
            </div>
          )}
          {analysis && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}>
              <div style={{ padding: 'var(--space-4)', borderRadius: 8, border: '1px solid rgba(168,85,247,0.25)', background: 'rgba(168,85,247,0.06)' }}>
                <div style={{ fontSize: '0.65rem', letterSpacing: '0.08em', color: '#a855f7', fontWeight: 800, marginBottom: 6 }}>SUMMARY</div>
                <div style={{ fontSize: '0.92rem', fontWeight: 700, lineHeight: 1.5 }}>{analysis.summary}</div>
                <div style={{ marginTop: 8, fontSize: '0.75rem', color: 'var(--color-text-muted)' }}>
                  Risk score: {analysis.risk_score ?? '—'} / 10
                </div>
              </div>

              <section>
                <h3 style={{ fontSize: '0.85rem', marginBottom: 10 }}>Reasoning chain</h3>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                  {(analysis.reasoning_chain || []).map((step: any, i: number) => (
                    <div key={`${step.step || 'step'}-${i}`} style={{ display: 'flex', gap: 10, borderLeft: '2px solid rgba(168,85,247,0.45)', padding: '7px 10px', background: 'rgba(255,255,255,0.025)' }}>
                      <div style={{ minWidth: 115, fontSize: '0.73rem', fontWeight: 700, color: '#a855f7' }}>{step.step}</div>
                      <div style={{ fontSize: '0.78rem', lineHeight: 1.5, flex: 1, overflowWrap: 'anywhere' }}>{step.content}</div>
                    </div>
                  ))}
                </div>
              </section>

              <section>
                <h3 style={{ fontSize: '0.85rem', marginBottom: 8 }}>Recommended actions</h3>
                {(analysis.recommended_actions || []).length ? (
                  <ol style={{ margin: 0, paddingLeft: 20, fontSize: '0.8rem', lineHeight: 1.7 }}>
                    {analysis.recommended_actions.map((action: string, i: number) => <li key={i}>{action}</li>)}
                  </ol>
                ) : <div style={{ fontSize: '0.8rem', color: 'var(--color-text-muted)' }}>The provider returned no recommended actions.</div>}
              </section>

              <section>
                <h3 style={{ fontSize: '0.85rem', marginBottom: 8 }}>Remediation</h3>
                <div style={{ whiteSpace: 'pre-wrap', fontSize: '0.8rem', lineHeight: 1.6 }}>{analysis.remediation || 'No remediation guidance returned.'}</div>
              </section>

              <section>
                <h3 style={{ fontSize: '0.85rem', marginBottom: 8 }}>Evidence summary</h3>
                <div style={{ fontSize: '0.8rem', color: 'var(--color-text-secondary)', lineHeight: 1.6 }}>{analysis.evidence_summary || 'The provider returned no evidence summary.'}</div>
              </section>

              {!!(analysis.mitre_techniques || []).length && (
                <section>
                  <h3 style={{ fontSize: '0.85rem', marginBottom: 8 }}>MITRE ATT&CK mappings (AI-suggested)</h3>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                    {analysis.mitre_techniques.map((item: any, i: number) => (
                      <span key={`${item.id || item.name || 'technique'}-${i}`} style={{ padding: '4px 7px', border: '1px solid rgba(0,229,255,0.25)', borderRadius: 4, color: 'var(--color-cyan)', fontSize: '0.7rem' }}>
                        {item.id || 'ID not returned'} · {item.name || 'Unnamed technique'}
                      </span>
                    ))}
                  </div>
                </section>
              )}
              {!!(analysis.detection_rules || []).length && (
                <section>
                  <h3 style={{ fontSize: '0.85rem', marginBottom: 8 }}>Suggested detection rules (review before use)</h3>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                    {analysis.detection_rules.map((rule: string, i: number) => (
                      <pre key={i} style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere', fontSize: '0.7rem', background: 'rgba(0,0,0,0.3)', padding: 10, borderRadius: 6, border: '1px solid var(--color-border)' }}>{rule}</pre>
                    ))}
                  </div>
                </section>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
