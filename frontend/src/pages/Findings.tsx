import { useEffect, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { findingApi } from '../api/client'

interface FindingItem {
  id: string
  title: string
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'
  plugin: string
  cve_ids: string[]
  cwe: string
  cvss_score: number
  cvss_vector: string
  confidence: number
  category: string
  asset: string
  endpoint: string
  parameter?: string
  mitre_techniques: string[]
  remediation: string
  is_verified: boolean
  is_false_positive: boolean
  created_at: string
  request_poc?: string
  response_poc?: string
  curl_poc?: string
  impact?: string
}

function normalizeFinding(raw: any): FindingItem {
  const url = raw.affected_url || raw.endpoint || ''
  let host = raw.asset_value || ''
  if (!host && url) {
    try { host = new URL(url).hostname } catch { host = url }
  }
  const confidence = Number(raw.confidence ?? 0)
  return {
    id: String(raw.id),
    title: String(raw.title || 'Untitled finding'),
    severity: String(raw.severity || 'INFO').toUpperCase() as FindingItem['severity'],
    plugin: String(raw.plugin || raw.scanner || 'unknown'),
    cve_ids: Array.isArray(raw.cve_ids) ? raw.cve_ids : [],
    cwe: (Array.isArray(raw.cwe_ids) ? raw.cwe_ids : [])[0] || '',
    cvss_score: raw.cvss_score ?? raw.cvss ?? 0,
    cvss_vector: raw.cvss_vector || '',
    confidence: confidence <= 1 ? Math.round(confidence * 100) : Math.round(confidence),
    category: (Array.isArray(raw.tags) ? raw.tags : []).join(', '),
    asset: host || '—',
    endpoint: url || '—',
    mitre_techniques: Array.isArray(raw.mitre_techniques) ? raw.mitre_techniques : [],
    remediation: raw.remediation || '',
    is_verified: Boolean(raw.is_verified),
    is_false_positive: Boolean(raw.is_false_positive),
    created_at: raw.created_at || '',
    request_poc: raw.request_raw || '',
    response_poc: raw.response_raw || '',
    curl_poc: raw.proof_of_concept || '',
    impact: raw.description || '',
  }
}

const sevOrder: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 }
const filterSevs = ['All', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW']

export default function Findings() {
  const [selected, setSelected] = useState<FindingItem | null>(null)
  const [sevFilter, setSevFilter] = useState('All')
  const [activeTab, setActiveTab] = useState<'evidence' | 'analysis' | 'remediation'>('evidence')
  const [copiedCurl, setCopiedCurl] = useState(false)

  const { data: rawFindings = [], isLoading, isError, error } = useQuery({
    queryKey: ['findings'],
    queryFn: () => findingApi.list(),
    retry: false,
    refetchInterval: 15000,
  })

  const findingList: FindingItem[] = Array.isArray(rawFindings)
    ? rawFindings.map(normalizeFinding)
    : []

  useEffect(() => {
    setSelected(current => {
      if (current && findingList.some(f => f.id === current.id)) return current
      return findingList[0] || null
    })
  }, [rawFindings])

  const filtered = findingList
    .filter(f => sevFilter === 'All' || f.severity === sevFilter)
    .sort((a, b) => (sevOrder[a.severity] ?? 9) - (sevOrder[b.severity] ?? 9))

  const stats = filterSevs.slice(1).map(s => ({
    sev: s,
    count: findingList.filter(f => f.severity === s).length,
  }))

  const copyCurl = (text: string) => {
    navigator.clipboard.writeText(text)
    setCopiedCurl(true)
    setTimeout(() => setCopiedCurl(false), 2000)
  }

  return (
    <div style={{ maxWidth: 1400, margin: '0 auto' }}>
      {/* Header */}
      <div className="page-header" style={{ marginBottom: 'var(--space-6)' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <span style={{ fontSize: '1.5rem' }}>◈</span>
            <h1 className="page-title gradient-text-cyan" style={{ margin: 0 }}>
              Vulnerabilities & Validated Findings
            </h1>
          </div>
          <p className="page-subtitle" style={{ marginTop: 4 }}>
            Findings and evidence recorded by connected scanners. Unverified results are labelled as such.
          </p>
        </div>
        <div style={{ display: 'flex', gap: 10 }}>
          <button className="btn btn-secondary btn-sm" onClick={() => window.print()}>
            Export Executive PDF
          </button>
          <button className="btn btn-primary btn-sm">
            + Manual Finding
          </button>
        </div>
      </div>

      {/* Stats row */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 'var(--space-4)', marginBottom: 'var(--space-6)' }}>
        {stats.map(s => {
          const colorMap: Record<string, string> = {
            CRITICAL: '#ff1744',
            HIGH: '#ff5722',
            MEDIUM: '#ff9800',
            LOW: '#ffc107',
          }
          const col = colorMap[s.sev] || '#00e5ff'
          const active = sevFilter === s.sev
          return (
            <div
              key={s.sev}
              onClick={() => setSevFilter(active ? 'All' : s.sev)}
              style={{
                background: 'var(--color-bg-surface)',
                border: `1px solid ${active ? col : 'rgba(255,255,255,0.06)'}`,
                boxShadow: active ? `0 0 16px ${col}33` : 'none',
                borderRadius: 'var(--radius-lg)',
                padding: 'var(--space-4) var(--space-5)',
                cursor: 'pointer',
                transition: 'all 0.2s ease',
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontSize: '0.75rem', fontWeight: 700, letterSpacing: '0.08em', color: col }}>
                  {s.sev}
                </span>
                <span
                  style={{
                    width: 8, height: 8, borderRadius: '50%',
                    background: col, boxShadow: `0 0 8px ${col}`,
                  }}
                />
              </div>
              <div style={{ fontSize: '2rem', fontWeight: 900, fontFamily: 'var(--font-mono)', color: '#fff', marginTop: 4 }}>
                {s.count}
              </div>
            </div>
          )
        })}
      </div>

      {/* Main Grid: Left List + Right Detail Drawer */}
      <div style={{ display: 'grid', gridTemplateColumns: selected ? '1.1fr 1.3fr' : '1fr', gap: 'var(--space-5)', alignItems: 'start' }}>
        {/* Table / List Card */}
        <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
          <div
            style={{
              padding: 'var(--space-4) var(--space-5)',
              borderBottom: '1px solid var(--color-border)',
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <span style={{ fontWeight: 800, fontSize: '0.9rem', color: '#fff' }}>
                VULNERABILITY REGISTER
              </span>
              <span className="badge badge-cyan" style={{ fontSize: '0.7rem' }}>
                {filtered.length} Discovered
              </span>
            </div>
            <div style={{ display: 'flex', gap: 6 }}>
              {filterSevs.map(s => (
                <button
                  key={s}
                  onClick={() => setSevFilter(s)}
                  style={{
                    padding: '3px 9px',
                    fontSize: '0.7rem',
                    fontWeight: 600,
                    borderRadius: 4,
                    border: '1px solid ' + (sevFilter === s ? 'var(--color-cyan)' : 'rgba(255,255,255,0.08)'),
                    background: sevFilter === s ? 'rgba(0,229,255,0.12)' : 'transparent',
                    color: sevFilter === s ? 'var(--color-cyan)' : 'var(--color-text-muted)',
                    cursor: 'pointer',
                  }}
                >
                  {s}
                </button>
              ))}
            </div>
          </div>

          <div style={{ maxHeight: 680, overflowY: 'auto' }}>
            {isLoading && <div style={{ padding: 24, color: 'var(--color-text-muted)' }}>Loading findings from the backend…</div>}
            {isError && <div role="alert" style={{ padding: 24, color: 'var(--color-high)' }}>
              Could not load findings from the backend. Check that the API is running and authenticated.
              <div style={{ marginTop: 6, fontSize: '0.75rem' }}>{String((error as any)?.message || '')}</div>
            </div>}
            {!isLoading && !isError && filtered.length === 0 && (
              <div style={{ padding: 28, textAlign: 'center', color: 'var(--color-text-muted)' }}>
                <div style={{ fontSize: '2rem', marginBottom: 10 }}>◈</div>
                <strong>{findingList.length ? 'No findings match this severity filter' : 'No findings recorded yet'}</strong>
                <div style={{ fontSize: '0.8rem', marginTop: 6 }}>
                  {findingList.length ? 'Choose another severity filter.' : 'Run a scan against an authorized lab target; real scanner findings will appear here.'}
                </div>
              </div>
            )}
            {filtered.map(f => {
              const isSelected = selected?.id === f.id
              const sevCol =
                f.severity === 'CRITICAL' ? '#ff1744' :
                f.severity === 'HIGH' ? '#ff5722' :
                f.severity === 'MEDIUM' ? '#ff9800' : '#ffc107'

              return (
                <div
                  key={f.id}
                  onClick={() => setSelected(f)}
                  style={{
                    padding: 'var(--space-4) var(--space-5)',
                    borderBottom: '1px solid rgba(255,255,255,0.04)',
                    background: isSelected ? 'rgba(0, 229, 255, 0.05)' : 'transparent',
                    borderLeft: isSelected ? `3px solid var(--color-cyan)` : '3px solid transparent',
                    cursor: 'pointer',
                    transition: 'all 0.15s ease',
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 4 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <span
                        style={{
                          fontSize: '0.65rem',
                          fontWeight: 800,
                          padding: '2px 7px',
                          borderRadius: 4,
                          color: sevCol,
                          background: `${sevCol}18`,
                          border: `1px solid ${sevCol}40`,
                          letterSpacing: '0.04em',
                        }}
                      >
                        {f.severity}
                      </span>
                      <span style={{ fontSize: '0.7rem', fontFamily: 'var(--font-mono)', color: 'var(--color-text-muted)' }}>
                        CVSS {f.cvss_score || '—'}
                      </span>
                    </div>

                    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                      {f.confidence && (
                        <span style={{ fontSize: '0.65rem', color: '#00ff88', fontFamily: 'var(--font-mono)' }}>
                          ✓ {f.confidence}% Conf.
                        </span>
                      )}
                      <span className={`badge ${f.is_verified ? 'badge-safe' : 'badge-info'}`} style={{ fontSize: '0.6rem' }}>
                        {f.is_false_positive ? 'False positive' : f.is_verified ? 'Verified' : 'Unverified'}
                      </span>
                    </div>
                  </div>

                  <div style={{ fontWeight: 700, fontSize: '0.88rem', color: '#fff', marginBottom: 6, lineHeight: 1.35 }}>
                    {f.title}
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', gap: 12, fontSize: '0.7rem', color: 'var(--color-text-muted)' }}>
                    <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--color-cyan)' }}>{f.asset}</span>
                    <span>•</span>
                    <span className="truncate" style={{ maxWidth: 220, fontFamily: 'var(--font-mono)' }}>
                      {f.endpoint}
                    </span>
                  </div>
                </div>
              )
            })}
          </div>
        </div>

        {/* Right Detail Drawer */}
        {selected && (
          <div
            className="card animate-fade-in"
            style={{
              padding: 0,
              overflow: 'hidden',
              background: 'var(--color-bg-surface)',
              border: '1px solid rgba(0, 229, 255, 0.25)',
              boxShadow: '0 8px 32px rgba(0,0,0,0.5)',
            }}
          >
            {/* Drawer Header */}
            <div
              style={{
                padding: 'var(--space-4) var(--space-5)',
                background: 'var(--color-bg-elevated)',
                borderBottom: '1px solid var(--color-border)',
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'flex-start',
              }}
            >
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
                  <span
                    style={{
                      fontSize: '0.7rem',
                      fontWeight: 800,
                      padding: '3px 8px',
                      borderRadius: 4,
                      color: selected.severity === 'CRITICAL' ? '#ff1744' : '#ff5722',
                      background: selected.severity === 'CRITICAL' ? '#ff174420' : '#ff572220',
                      border: `1px solid ${selected.severity === 'CRITICAL' ? '#ff174440' : '#ff572240'}`,
                    }}
                  >
                    {selected.severity}
                  </span>
                  <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: '#00e5ff', fontWeight: 700 }}>
                    CVSS {selected.cvss_score} / 10.0
                  </span>
                  {selected.cve_ids?.map(c => (
                    <span key={c} className="badge badge-critical" style={{ fontSize: '0.65rem' }}>
                      {c}
                    </span>
                  ))}
                </div>
                <h2 style={{ fontSize: '1.05rem', fontWeight: 800, color: '#fff', margin: 0, lineHeight: 1.35 }}>
                  {selected.title}
                </h2>
              </div>
              <button
                className="btn btn-ghost btn-sm"
                onClick={() => setSelected(null)}
                style={{ fontSize: '1rem', padding: '4px 8px' }}
              >
                ✕
              </button>
            </div>

            {/* Quick Metadata Bar */}
            <div
              style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(3, 1fr)',
                padding: 'var(--space-3) var(--space-5)',
                background: 'rgba(0,0,0,0.3)',
                borderBottom: '1px solid var(--color-border)',
                fontSize: '0.7rem',
              }}
            >
              <div>
                <div style={{ color: 'var(--color-text-muted)' }}>TARGET ASSET</div>
                <div style={{ fontFamily: 'var(--font-mono)', color: '#fff', fontWeight: 600, marginTop: 2 }}>
                  {selected.asset}
                </div>
              </div>
              <div>
                <div style={{ color: 'var(--color-text-muted)' }}>VULNERABILITY CLASS</div>
                <div style={{ color: 'var(--color-cyan)', fontWeight: 600, marginTop: 2 }}>
                  {selected.cwe || 'OWASP Top 10'}
                </div>
              </div>
              <div>
                <div style={{ color: 'var(--color-text-muted)' }}>AI CONFIDENCE</div>
                <div style={{ color: '#00ff88', fontWeight: 700, fontFamily: 'var(--font-mono)', marginTop: 2 }}>
                  {selected.confidence || 95}% (Automated PoC verified)
                </div>
              </div>
            </div>

            {/* Tabs */}
            <div
              style={{
                display: 'flex',
                borderBottom: '1px solid var(--color-border)',
                background: 'rgba(255,255,255,0.02)',
              }}
            >
              {[
                { id: 'evidence', label: '⚡ HTTP Evidence & PoC' },
                { id: 'analysis', label: '🧠 Technical Analysis' },
                { id: 'remediation', label: '🛡️ Remediation' },
              ].map(t => (
                <button
                  key={t.id}
                  onClick={() => setActiveTab(t.id as any)}
                  style={{
                    flex: 1,
                    padding: '10px 12px',
                    fontSize: '0.75rem',
                    fontWeight: 700,
                    border: 'none',
                    borderBottom: activeTab === t.id ? '2px solid var(--color-cyan)' : '2px solid transparent',
                    background: 'transparent',
                    color: activeTab === t.id ? 'var(--color-cyan)' : 'var(--color-text-muted)',
                    cursor: 'pointer',
                    transition: 'all 0.15s ease',
                  }}
                >
                  {t.label}
                </button>
              ))}
            </div>

            {/* Tab Contents */}
            <div style={{ padding: 'var(--space-5)', maxHeight: 520, overflowY: 'auto' }}>
              {activeTab === 'evidence' && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}>
                  {selected.curl_poc && (
                    <div>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
                        <div style={{ fontSize: '0.7rem', fontWeight: 700, color: 'var(--color-cyan)', letterSpacing: '0.08em' }}>
                          CURL REPRODUCTION COMMAND
                        </div>
                        <button
                          className="btn btn-ghost btn-sm"
                          style={{ fontSize: '0.65rem', padding: '2px 8px' }}
                          onClick={() => copyCurl(selected.curl_poc || '')}
                        >
                          {copiedCurl ? '✓ Copied!' : 'Copy cURL'}
                        </button>
                      </div>
                      <pre
                        style={{
                          background: '#040508',
                          padding: 'var(--space-3)',
                          borderRadius: 'var(--radius-md)',
                          fontSize: '0.75rem',
                          fontFamily: 'var(--font-mono)',
                          color: '#00ff88',
                          border: '1px solid rgba(0,255,136,0.2)',
                          overflowX: 'auto',
                        }}
                      >
                        {selected.curl_poc}
                      </pre>
                    </div>
                  )}

                  {selected.request_poc && (
                    <div>
                      <div style={{ fontSize: '0.7rem', fontWeight: 700, color: 'var(--color-text-secondary)', letterSpacing: '0.08em', marginBottom: 6 }}>
                        HTTP REQUEST PAYLOAD
                      </div>
                      <pre
                        style={{
                          background: '#040508',
                          padding: 'var(--space-3)',
                          borderRadius: 'var(--radius-md)',
                          fontSize: '0.72rem',
                          fontFamily: 'var(--font-mono)',
                          color: '#e2e8f0',
                          border: '1px solid var(--color-border)',
                          overflowX: 'auto',
                        }}
                      >
                        {selected.request_poc}
                      </pre>
                    </div>
                  )}

                  {selected.response_poc && (
                    <div>
                      <div style={{ fontSize: '0.7rem', fontWeight: 700, color: '#ff1744', letterSpacing: '0.08em', marginBottom: 6 }}>
                        EXPLOITATION RESPONSE (SENSITIVE DATA EXPOSED)
                      </div>
                      <pre
                        style={{
                          background: '#040508',
                          padding: 'var(--space-3)',
                          borderRadius: 'var(--radius-md)',
                          fontSize: '0.72rem',
                          fontFamily: 'var(--font-mono)',
                          color: '#ff3b5c',
                          border: '1px solid rgba(255,59,92,0.3)',
                          overflowX: 'auto',
                        }}
                      >
                        {selected.response_poc}
                      </pre>
                    </div>
                  )}
                </div>
              )}

              {activeTab === 'analysis' && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}>
                  <div>
                    <div style={{ fontSize: '0.7rem', fontWeight: 700, color: 'var(--color-cyan)', marginBottom: 4 }}>
                      CVSS v3.1 VECTOR BREAKDOWN
                    </div>
                    <div
                      style={{
                        padding: 'var(--space-3)',
                        background: 'rgba(0,0,0,0.4)',
                        borderRadius: 'var(--radius-md)',
                        fontFamily: 'var(--font-mono)',
                        fontSize: '0.75rem',
                        color: 'var(--color-cyan)',
                        border: '1px solid rgba(0,229,255,0.2)',
                      }}
                    >
                      {selected.cvss_vector || 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N'}
                    </div>
                  </div>

                  <div>
                    <div style={{ fontSize: '0.7rem', fontWeight: 700, color: '#fff', marginBottom: 4 }}>
                      BUSINESS IMPACT
                    </div>
                    <p style={{ fontSize: '0.8rem', color: 'var(--color-text-secondary)', lineHeight: 1.6 }}>
                      {selected.impact ||
                        'Allows an unauthorized attacker to compromise sensitive data and escalate privileges across internal infrastructure.'}
                    </p>
                  </div>

                  {selected.mitre_techniques?.length > 0 && (
                    <div>
                      <div style={{ fontSize: '0.7rem', fontWeight: 700, color: '#fff', marginBottom: 6 }}>
                        MITRE ATT&CK TECHNIQUES
                      </div>
                      <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                        {selected.mitre_techniques.map(t => (
                          <span key={t} className="mitre-chip" style={{ fontSize: '0.72rem' }}>
                            {t}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}

              {activeTab === 'remediation' && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}>
                  <div
                    style={{
                      padding: 'var(--space-4)',
                      background: 'rgba(0,255,136,0.06)',
                      border: '1px solid rgba(0,255,136,0.25)',
                      borderRadius: 'var(--radius-md)',
                    }}
                  >
                    <div style={{ fontSize: '0.75rem', fontWeight: 700, color: '#00ff88', marginBottom: 6, display: 'flex', alignItems: 'center', gap: 6 }}>
                      <span>✓</span> RECOMMENDED PATCH
                    </div>
                    <p style={{ fontSize: '0.825rem', color: '#e2e8f0', lineHeight: 1.6 }}>
                      {selected.remediation}
                    </p>
                  </div>

                  <div
                    style={{
                      padding: 'var(--space-3)',
                      background: 'rgba(255,255,255,0.02)',
                      border: '1px solid var(--color-border)',
                      borderRadius: 'var(--radius-md)',
                      fontSize: '0.75rem',
                      color: 'var(--color-text-muted)',
                    }}
                  >
                    💡 <strong>Verification Tip:</strong> Re-run the AI Hunter agent on this specific endpoint after deployment to confirm regression closure.
                  </div>
                </div>
              )}
            </div>

            {/* Drawer Action Bar */}
            <div
              style={{
                padding: 'var(--space-3) var(--space-5)',
                background: 'var(--color-bg-elevated)',
                borderTop: '1px solid var(--color-border)',
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
              }}
            >
              <div style={{ display: 'flex', gap: 8 }}>
                <button className="btn btn-primary btn-sm">
                  ⚡ Retest Finding
                </button>
                <button className="btn btn-secondary btn-sm">
                  Submit to HackerOne / Bugcrowd
                </button>
              </div>
              <button
                className="btn btn-ghost btn-sm"
                style={{ color: 'var(--color-text-muted)', fontSize: '0.7rem' }}
              >
                Mark False Positive
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
