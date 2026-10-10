import { useEffect, useState } from 'react'
import { webApi } from '../api/client'
import toast from 'react-hot-toast'

// ── Vulnerability Categories ──────────────────────────────
const VULN_CATEGORIES = [
  { id: 'cves',          icon: '💀', label: 'Known CVEs',              desc: 'CVE-identified vulnerabilities in web frameworks, CMS, libraries', severity: 'CRITICAL', mitre: 'T1190' },
  { id: 'injection',     icon: '💉', label: 'Injection (XSS / SQLi)',  desc: 'SQL Injection, Cross-Site Scripting, Command Injection, SSTI',    severity: 'CRITICAL', mitre: 'T1190' },
  { id: 'ssrf',          icon: '🔄', label: 'SSRF',                    desc: 'Server-Side Request Forgery — internal service enumeration',      severity: 'HIGH',     mitre: 'T1190' },
  { id: 'path_traversal',icon: '📂', label: 'Path Traversal / LFI',   desc: 'Directory traversal, Local File Inclusion, file read',            severity: 'HIGH',     mitre: 'T1083' },
  { id: 'auth',          icon: '🔑', label: 'Authentication Bypass',   desc: 'Default creds, broken auth, session fixation',                    severity: 'HIGH',     mitre: 'T1078' },
  { id: 'jwt',           icon: '🎫', label: 'JWT / OAuth Issues',      desc: 'alg:none, weak signing, token leakage, OIDC misconfig',           severity: 'HIGH',     mitre: 'T1078.001' },
  { id: 'cors',          icon: '🌐', label: 'CORS Misconfiguration',   desc: 'Wildcard origin, credential exposure, cross-origin bypass',        severity: 'MEDIUM',   mitre: 'T1185' },
  { id: 'api',           icon: '⚙️', label: 'API Security / BOLA',     desc: 'IDOR, BOLA, mass assignment, GraphQL introspection, API keys',    severity: 'HIGH',     mitre: 'T1190' },
  { id: 'misconfig',     icon: '⚠️', label: 'Security Misconfiguration',desc: 'Debug endpoints, open redirects, directory listing, backup files', severity: 'MEDIUM',  mitre: 'T1190' },
  { id: 'exposures',     icon: '🔓', label: 'Sensitive Exposures',     desc: '.env files, git repos, AWS keys, private keys, stack traces',     severity: 'HIGH',     mitre: 'T1552' },
  { id: 'upload',        icon: '📤', label: 'File Upload',             desc: 'Unrestricted upload, webshell, MIME bypass, path traversal upload',severity: 'CRITICAL', mitre: 'T1190' },
  { id: 'takeovers',     icon: '🏴', label: 'Subdomain Takeover',      desc: 'Dangling DNS, unclaimed cloud/SaaS services',                     severity: 'HIGH',     mitre: 'T1584' },
]

const SEV_COLOR: Record<string, string> = {
  CRITICAL: 'var(--color-critical)',
  HIGH:     'var(--color-high)',
  MEDIUM:   'var(--color-medium)',
  LOW:      'var(--color-low)',
  INFO:     'var(--color-info)',
}

const SEV_BG: Record<string, string> = {
  CRITICAL: 'rgba(255,23,68,0.1)',
  HIGH:     'rgba(255,87,34,0.1)',
  MEDIUM:   'rgba(255,152,0,0.1)',
  LOW:      'rgba(255,193,7,0.1)',
  INFO:     'rgba(33,150,243,0.1)',
}

export default function WebSecurity() {
  const [targets, setTargets] = useState('')
  const [selected, setSelected] = useState<string[]>(VULN_CATEGORIES.map(c => c.id))
  const [findings, setFindings] = useState<any[]>([])
  const [scanning, setScanning] = useState(false)
  const [detailFinding, setDetailFinding] = useState<any>(null)
  const [proxyMode, setProxyMode] = useState(false)
  const [proxyUrl, setProxyUrl] = useState('http://127.0.0.1:8080')
  const [taskId, setTaskId] = useState<string | null>(null)
  const [scanStatus, setScanStatus] = useState('IDLE')
  const [scanError, setScanError] = useState<string | null>(null)
  const [scanMeta, setScanMeta] = useState<any>(null)

  // Poll the API for real scanner state. No simulated progress or sample results.
  useEffect(() => {
    if (!taskId) return
    let stopped = false
    let timer: ReturnType<typeof setTimeout> | undefined

    const poll = async () => {
      try {
        const status = await webApi.scanStatus(taskId)
        if (stopped) return
        const state = String(status.status || 'PENDING').toUpperCase()
        const result = status.result
        setScanStatus(state)

        const terminal = ['SUCCESS', 'COMPLETED', 'FAILURE', 'FAILED', 'REVOKED', 'CANCELLED'].includes(state)
        if (result?.error || terminal) {
          const failure = result?.error || (['FAILURE', 'FAILED', 'REVOKED', 'CANCELLED'].includes(state)
            ? 'The scanner job did not complete successfully.'
            : null)
          setScanning(false)
          setTaskId(null)
          setScanMeta(result || null)
          setFindings(Array.isArray(result?.findings) ? result.findings : [])
          if (failure) {
            setScanError(String(failure))
            toast.error(String(failure))
          } else {
            setScanError(null)
            toast.success(`Real scan complete — ${Array.isArray(result?.findings) ? result.findings.length : 0} finding(s)`)
          }
          return
        }
      } catch (err: any) {
        if (stopped) return
        const message = err?.response?.data?.detail || err?.message || 'Unable to read scan status from the API.'
        setScanning(false)
        setTaskId(null)
        setScanStatus('ERROR')
        setScanError(String(message))
        toast.error(String(message))
        return
      }

      if (!stopped) timer = setTimeout(poll, 2000)
    }

    void poll()
    return () => {
      stopped = true
      if (timer) clearTimeout(timer)
    }
  }, [taskId])

  // Toggle category selection
  const toggleCat = (id: string) =>
    setSelected(p => p.includes(id) ? p.filter(c => c !== id) : [...p, id])

  const selectAll   = () => setSelected(VULN_CATEGORIES.map(c => c.id))
  const selectNone  = () => setSelected([])

  // Start an authorized scan. The API rejects targets outside active scope.
  const handleScan = async () => {
    const urls = targets.split('\n').map(t => t.trim()).filter(Boolean)
    if (!urls.length) { toast.error('Add at least one target URL'); return }
    if (!selected.length) { toast.error('Select at least one vulnerability category'); return }

    setScanning(true)
    setFindings([])
    setDetailFinding(null)
    setScanError(null)
    setScanMeta(null)
    setScanStatus('SUBMITTING')

    try {
      const response = await webApi.scan({
        targets: urls,
        categories: selected,
        rate_limit: 10,
        timeout: 10,
        proxy: proxyMode && proxyUrl.trim() ? proxyUrl.trim() : undefined,
      })
      if (!response?.task_id) throw new Error('The API did not return a scan task ID.')
      setScanStatus(String(response.status || 'QUEUED').toUpperCase())
      setTaskId(String(response.task_id))
      toast.success('Authorized scan queued. Waiting for actual scanner results.')
    } catch (err: any) {
      const message = err?.response?.data?.detail || err?.message || 'Could not queue scan.'
      setScanning(false)
      setTaskId(null)
      setScanStatus('REJECTED')
      setScanError(String(message))
      toast.error(String(message))
    }
  }

  const exportFindings = () => {
    const blob = new Blob([JSON.stringify({
      product: 'SPAiDER',
      exported_at: new Date().toISOString(),
      scan_status: scanStatus,
      scan: scanMeta,
      findings,
    }, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const anchor = document.createElement('a')
    anchor.href = url
    anchor.download = `spaider-web-findings-${new Date().toISOString().replace(/[:.]/g, '-')}.json`
    anchor.click()
    URL.revokeObjectURL(url)
  }

  const sevCount = (sev: string) => findings.filter(f => f.severity === sev).length

  return (
    <div>
      {/* Header */}
      <div className="page-header">
        <div>
          <h1 className="page-title gradient-text-red">🕷️ Web Security Testing</h1>
          <p className="page-subtitle">Nuclei template scanning · evidence-backed findings · optional Burp/Caido proxy and finding import</p>
        </div>
        <div className="flex gap-2">
          <button
            className={`btn ${proxyMode ? 'btn-primary' : 'btn-ghost'}`}
            onClick={() => setProxyMode(p => !p)}
          >
            🔥 Burp / Caido Proxy
          </button>
        </div>
      </div>

      {/* Proxy mode banner */}
      {proxyMode && (
        <div className="animate-fade-in" style={{
          background: 'rgba(255,87,34,0.08)', border: '1px solid rgba(255,87,34,0.3)',
          borderRadius: 'var(--radius-lg)', padding: 'var(--space-5)', marginBottom: 'var(--space-5)',
        }}>
          <div style={{ fontWeight: 700, marginBottom: 8 }}>🔥 Burp / Caido Proxy Integration</div>
          <div className="form-group" style={{ marginBottom: 'var(--space-4)' }}>
            <label className="form-label">Proxy URL (reachable from the backend host/container)</label>
            <input
              className="input input-mono"
              value={proxyUrl}
              onChange={e => setProxyUrl(e.target.value)}
              placeholder="http://127.0.0.1:8080"
            />
            <div style={{ fontSize: '0.72rem', color: 'var(--color-text-muted)', marginTop: 5 }}>
              The URL is passed to Nuclei only when proxy mode is enabled. If the backend runs in Docker, use a proxy address reachable from that container.
            </div>
          </div>
          <div className="grid-3" style={{ gap: 'var(--space-4)', fontSize: '0.875rem' }}>
            {[
              ['1. Start Burp Suite', 'Proxy → Options → HTTP Proxy → 127.0.0.1:8080'],
              ['2. Configure Browser', 'Set proxy to 127.0.0.1:8080 and install Burp CA cert'],
              ['3. Browse Target',    'Capture traffic in the configured proxy'],
              ['4. Run Active Scan',  'Burp Dashboard → New Scan → configure scope → launch'],
              ['5. Purple Validate',  'SPAIDER auto-correlates with Wazuh/Zeek detections'],
              ['6. View in SPAIDER',  'Imported findings are saved through the SPAIDER API'],
            ].map(([title, desc]) => (
              <div key={title} style={{ padding: 'var(--space-3)', background: 'rgba(255,255,255,0.03)', borderRadius: 'var(--radius-md)', border: '1px solid var(--color-border)' }}>
                <div style={{ fontWeight: 700, color: 'var(--color-high)', marginBottom: 4 }}>{title}</div>
                <div style={{ color: 'var(--color-text-muted)', lineHeight: 1.5 }}>{desc}</div>
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="grid-2" style={{ alignItems: 'start', gap: 'var(--space-5)' }}>

        {/* ── LEFT: Configuration ── */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}>

          {/* Targets */}
          <div className="card">
            <div className="card-header">
              <span className="card-title">🎯 Target URLs</span>
            </div>
            <div className="form-group">
              <label className="form-label">One URL per line</label>
              <textarea
                className="input input-mono"
                rows={4}
                placeholder={'http://localhost:3001\nhttps://your-authorized-host.example'}
                value={targets}
                onChange={e => setTargets(e.target.value)}
              />
            </div>
            <div style={{ marginTop: 'var(--space-3)', padding: 'var(--space-3)', background: 'rgba(255,59,92,0.06)', border: '1px solid rgba(255,59,92,0.2)', borderRadius: 'var(--radius-md)', fontSize: '0.75rem', color: 'var(--color-red)' }}>
              ⚠️ Only scan systems you are authorised to test. Ensure a valid scope and authorization document exists.
            </div>
          </div>

          {/* Vulnerability Categories */}
          <div className="card">
            <div className="card-header">
              <span className="card-title">🔍 Vulnerability Categories</span>
              <div className="flex gap-2">
                <button className="btn btn-sm btn-ghost" onClick={selectAll}>All</button>
                <button className="btn btn-sm btn-ghost" onClick={selectNone}>None</button>
              </div>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              {VULN_CATEGORIES.map(cat => (
                <label
                  key={cat.id}
                  style={{
                    display: 'flex', alignItems: 'flex-start', gap: 'var(--space-3)',
                    padding: 'var(--space-3)', borderRadius: 'var(--radius-md)',
                    border: `1px solid ${selected.includes(cat.id) ? SEV_COLOR[cat.severity] + '55' : 'var(--color-border)'}`,
                    background: selected.includes(cat.id) ? SEV_BG[cat.severity] : 'transparent',
                    cursor: 'pointer', transition: 'all 0.15s',
                  }}
                >
                  <input
                    type="checkbox"
                    checked={selected.includes(cat.id)}
                    onChange={() => toggleCat(cat.id)}
                    style={{ marginTop: 2, flexShrink: 0, accentColor: SEV_COLOR[cat.severity] }}
                  />
                  <span style={{ fontSize: '1.1rem', flexShrink: 0 }}>{cat.icon}</span>
                  <div style={{ flex: 1 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 2 }}>
                      <span style={{ fontWeight: 600, fontSize: '0.875rem' }}>{cat.label}</span>
                      <span className={`badge badge-${cat.severity.toLowerCase()}`}>{cat.severity}</span>
                      <span className="mitre-chip" style={{ marginLeft: 'auto' }}>{cat.mitre}</span>
                    </div>
                    <div style={{ fontSize: '0.75rem', color: 'var(--color-text-muted)', lineHeight: 1.4 }}>{cat.desc}</div>
                  </div>
                </label>
              ))}
            </div>

            <div style={{
              marginTop: 'var(--space-3)',
              marginBottom: 'var(--space-3)',
              padding: 'var(--space-2) var(--space-3)',
              background: 'rgba(255,59,92,0.06)',
              border: '1px solid rgba(255,59,92,0.2)',
              borderRadius: 'var(--radius-md)',
              fontSize: '0.73rem',
              color: 'var(--color-red)',
              display: 'flex',
              alignItems: 'center',
              gap: 6,
            }}>
              <span>⚠️</span>
              <span>Only scan systems you are authorised to test. Ensure a valid scope and authorization document exists.</span>
            </div>

            <div style={{ marginTop: 'var(--space-2)' }}>
              <button
                className="btn btn-primary w-full"
                onClick={handleScan}
                disabled={scanning}
                style={{ position: 'relative', overflow: 'hidden' }}
              >
                {scanning ? (
                  <span className="flex items-center gap-2">
                    <span style={{ animation: 'blink 1s infinite' }}>⚡</span>
                    Scanning... ({selected.length} categories)
                  </span>
                ) : (
                  `🚀 Launch Web Scan (${selected.length} categories selected)`
                )}
              </button>
              {scanning && (
                <div className="progress-bar" style={{ marginTop: 'var(--space-2)' }}>
                  <div className="progress-fill" style={{ width: '60%', animation: 'shimmer 1.5s linear infinite' }} />
                </div>
              )}
            </div>
          </div>
        </div>

        {/* ── RIGHT: Results ── */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}>

          {/* Stats */}
          {findings.length > 0 && (
            <div className="flex gap-3 animate-fade-in">
              {['CRITICAL','HIGH','MEDIUM','LOW'].map(sev => (
                <div key={sev} className="stat-card" style={{ flex: 1, '--card-accent': SEV_COLOR[sev] } as any}>
                  <div className="stat-value" style={{ fontSize: '1.5rem', color: SEV_COLOR[sev] }}>{sevCount(sev)}</div>
                  <div className="stat-label">{sev}</div>
                </div>
              ))}
            </div>
          )}

          {/* Findings list */}
          <div className="card">
            <div className="card-header">
              <span className="card-title">
                {findings.length > 0 ? `🔎 ${findings.length} Findings` : '🔎 Findings'}
              </span>
              {findings.length > 0 && (
                <button className="btn btn-sm btn-ghost" onClick={exportFindings}>Export JSON</button>
              )}
            </div>

            {/* Authorization Notice for Scan Answers */}
            <div style={{
              margin: 'var(--space-2) var(--space-4)',
              padding: 'var(--space-2) var(--space-3)',
              background: 'rgba(255,59,92,0.06)',
              border: '1px solid rgba(255,59,92,0.2)',
              borderRadius: 'var(--radius-sm)',
              fontSize: '0.73rem',
              color: 'var(--color-red)',
              display: 'flex',
              alignItems: 'center',
              gap: 6,
            }}>
              <span>⚠️</span>
              <span>Only scan systems you are authorised to test. Ensure a valid scope and authorization document exists.</span>
            </div>


            {scanning && (
              <div style={{ padding: 'var(--space-4)' }}>
                <div className="terminal">
                  <div className="terminal-line info">[*] Scan task: {taskId || 'submitting'}</div>
                  <div className="terminal-line info">[*] Status: {scanStatus}</div>
                  <div className="terminal-line info">[*] Waiting for the backend scanner; results are not simulated.</div>
                </div>
              </div>
            )}

            {scanError && !scanning && (
              <div role="alert" style={{
                margin: 'var(--space-3) var(--space-4)',
                padding: 'var(--space-3)',
                border: '1px solid rgba(255,59,92,0.35)',
                borderRadius: 'var(--radius-md)',
                background: 'rgba(255,59,92,0.07)',
                color: 'var(--color-red)',
                fontSize: '0.8rem',
                whiteSpace: 'pre-wrap',
              }}>
                <strong>Scan failed — no demo findings shown.</strong>
                <div style={{ marginTop: 6 }}>{scanError}</div>
              </div>
            )}

            {scanMeta && !scanError && (
              <div style={{ padding: '0 var(--space-4) var(--space-2)', color: 'var(--color-text-muted)', fontSize: '0.72rem' }}>
                Scanner result: {scanMeta.demo === false ? 'real tool output' : 'status unknown'}
                {scanMeta.persisted_findings !== undefined ? ` · ${scanMeta.persisted_findings} newly persisted` : ''}
              </div>
            )}

            {findings.length === 0 && !scanning && !scanError && (
              <div style={{ textAlign: 'center', padding: 'var(--space-10)', color: 'var(--color-text-muted)' }}>
                <div style={{ fontSize: '3rem', marginBottom: 'var(--space-4)' }}>🕷️</div>
                <div style={{ fontWeight: 600, marginBottom: 8 }}>
                  {scanStatus === 'SUCCESS' || scanStatus === 'COMPLETED'
                    ? 'Scan completed — no matching findings were returned'
                    : 'Configure a target and launch a scan'}
                </div>
                <div style={{ fontSize: '0.875rem' }}>Only findings returned by the real scanner appear here.</div>
              </div>
            )}

            <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
              {findings.map(f => (
                <div
                  key={f.id || `${f.template_id || f.title}-${f.url}`}
                  onClick={() => setDetailFinding(detailFinding?.id === f.id ? null : f)}
                  style={{
                    padding: 'var(--space-3) var(--space-4)',
                    borderRadius: 'var(--radius-md)',
                    border: `1px solid ${detailFinding?.id === f.id ? SEV_COLOR[f.severity] : 'var(--color-border)'}`,
                    background: detailFinding?.id === f.id ? SEV_BG[f.severity] : 'var(--color-bg-elevated)',
                    cursor: 'pointer', transition: 'all 0.15s',
                  }}
                >
                  <div className="flex items-center gap-2">
                    <span className={`badge badge-${f.severity.toLowerCase()}`}>{f.severity}</span>
                    {f.cve_ids?.map((c: string) => (
                      <span key={c} style={{ fontFamily: 'var(--font-mono)', fontSize: '0.7rem', color: 'var(--color-red)' }}>{c}</span>
                    ))}
                    {f.cvss_score && (
                      <span style={{ marginLeft: 'auto', fontWeight: 700, fontSize: '0.75rem', color: f.cvss_score >= 9 ? 'var(--color-critical)' : f.cvss_score >= 7 ? 'var(--color-high)' : 'var(--color-medium)' }}>
                        CVSS {f.cvss_score}
                      </span>
                    )}
                  </div>
                  <div style={{ fontWeight: 600, fontSize: '0.875rem', marginTop: 4 }}>{f.title}</div>
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.7rem', color: 'var(--color-cyan)', marginTop: 2 }}>{f.url}</div>
                  <div className="flex gap-1" style={{ marginTop: 6, flexWrap: 'wrap' }}>
                    {f.tags?.map((t: string) => (
                      <span key={t} style={{ fontSize: '0.65rem', padding: '1px 6px', background: 'rgba(255,255,255,0.06)', borderRadius: 3, color: 'var(--color-text-muted)' }}>{t}</span>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* ── Finding Detail Panel ── */}
      {detailFinding && (
        <div className="card animate-fade-in" style={{ marginTop: 'var(--space-5)', border: `1px solid ${SEV_COLOR[detailFinding.severity]}55` }}>
          <div className="card-header">
            <span className="card-title">🔬 Finding Detail</span>
            <button className="btn btn-sm btn-ghost" onClick={() => setDetailFinding(null)}>✕</button>
          </div>

          <div className="grid-3" style={{ gap: 'var(--space-5)' }}>
            {/* Description */}
            <div style={{ gridColumn: '1 / 3' }}>
              <div className="flex items-center gap-3" style={{ marginBottom: 'var(--space-3)' }}>
                <span className={`badge badge-${detailFinding.severity.toLowerCase()}`}>{detailFinding.severity}</span>
                {detailFinding.cvss_score && (
                  <span style={{ fontWeight: 700, fontSize: '0.875rem', color: SEV_COLOR[detailFinding.severity] }}>
                    CVSS {detailFinding.cvss_score}
                  </span>
                )}
                {detailFinding.cve_ids?.map((c: string) => (
                  <span key={c} className="badge badge-critical">{c}</span>
                ))}
              </div>

              <h3 style={{ fontSize: '1.1rem', fontWeight: 700, marginBottom: 'var(--space-3)' }}>{detailFinding.title}</h3>
              <p style={{ fontSize: '0.875rem', color: 'var(--color-text-secondary)', lineHeight: 1.7, marginBottom: 'var(--space-4)' }}>
                {detailFinding.description}
              </p>

              <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: 'var(--color-cyan)', padding: 'var(--space-2) var(--space-3)', background: 'rgba(0,229,255,0.06)', borderRadius: 'var(--radius-sm)', marginBottom: 'var(--space-4)' }}>
                URL: {detailFinding.url}
              </div>

              {/* PoC curl command */}
              {detailFinding.curl_command && (
                <div style={{ marginBottom: 'var(--space-4)' }}>
                  <div className="form-label" style={{ marginBottom: 8 }}>🧪 Proof of Concept</div>
                  <div className="terminal" style={{ minHeight: 'auto', padding: 'var(--space-3)' }}>
                    <div className="terminal-line">{detailFinding.curl_command}</div>
                  </div>
                </div>
              )}

              {/* References */}
              {detailFinding.references?.length > 0 && (
                <div>
                  <div className="form-label" style={{ marginBottom: 8 }}>📚 References</div>
                  {detailFinding.references.map((r: string) => (
                    <div key={r} style={{ fontSize: '0.8rem', color: 'var(--color-blue)', marginBottom: 4 }}>
                      <a href={r} target="_blank" rel="noreferrer" style={{ color: 'inherit' }}>↗ {r}</a>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Actions */}
            <div>
              <div className="form-label" style={{ marginBottom: 12 }}>Actions</div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-2)' }}>
                <button className="btn btn-primary btn-sm">🧠 AI Deep Analysis</button>
                <button className="btn btn-ghost btn-sm">🟣 Purple Validate</button>
                <button className="btn btn-ghost btn-sm">📋 Add to Report</button>
                <button className="btn btn-ghost btn-sm">🎯 Open in Burp</button>
                <button className="btn btn-danger btn-sm">⚠ Mark Critical</button>
              </div>

              {/* OWASP Top 10 mapping */}
              <div style={{ marginTop: 'var(--space-5)' }}>
                <div className="form-label" style={{ marginBottom: 8 }}>OWASP Top 10</div>
                <div style={{
                  padding: 'var(--space-3)', background: 'rgba(168,85,247,0.08)',
                  border: '1px solid rgba(168,85,247,0.25)', borderRadius: 'var(--radius-md)',
                  fontSize: '0.8rem',
                }}>
                  <div style={{ fontWeight: 700, color: 'var(--color-purple)', marginBottom: 4 }}>
                    {detailFinding.tags?.includes('injection') || detailFinding.tags?.includes('sqli') || detailFinding.tags?.includes('xss')
                      ? 'A03:2021 – Injection'
                      : detailFinding.tags?.includes('auth') || detailFinding.tags?.includes('jwt')
                      ? 'A07:2021 – Identification & Auth Failures'
                      : detailFinding.tags?.includes('misconfig') || detailFinding.tags?.includes('headers')
                      ? 'A05:2021 – Security Misconfiguration'
                      : detailFinding.tags?.includes('exposure') || detailFinding.tags?.includes('secrets')
                      ? 'A02:2021 – Cryptographic Failures'
                      : detailFinding.tags?.includes('cors') || detailFinding.tags?.includes('graphql')
                      ? 'A04:2021 – Insecure Design'
                      : 'A06:2021 – Vulnerable Components'}
                  </div>
                  <div style={{ color: 'var(--color-text-muted)', fontSize: '0.75rem' }}>
                    See owasp.org/Top10 for details
                  </div>
                </div>
              </div>

              {/* Tags */}
              <div style={{ marginTop: 'var(--space-4)' }}>
                <div className="form-label" style={{ marginBottom: 8 }}>Tags</div>
                <div className="flex gap-1" style={{ flexWrap: 'wrap' }}>
                  {detailFinding.tags?.map((t: string) => (
                    <span key={t} className="target-tag" style={{ fontSize: '0.7rem' }}>{t}</span>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
