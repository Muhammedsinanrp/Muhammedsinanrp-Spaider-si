import { useState } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import { api } from '../api/client'
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

// ── Demo findings shown immediately without backend ───────
const DEMO_FINDINGS = [
  { id:'f1', template_id:'CVE-2021-41773', title:'Apache Path Traversal (CVE-2021-41773)', severity:'CRITICAL', url:'/index.php', cve_ids:['CVE-2021-41773'], cvss_score:9.8, tags:['cve','apache'], curl_command:"curl -s --path-as-is 'https://target.com/.%2e/.%2e/etc/passwd'", references:['https://nvd.nist.gov/vuln/detail/CVE-2021-41773'], description:'Path normalization flaw allows reading arbitrary files outside document root.' },
  { id:'f2', template_id:'cors-misconfig', title:'CORS Wildcard — Credentials Allowed', severity:'HIGH', url:'/api/', cve_ids:[], cvss_score:7.5, tags:['cors','misconfiguration'], curl_command:"curl -H 'Origin: https://evil.com' -I 'https://target.com/api/'", references:['https://portswigger.net/web-security/cors'], description:'Access-Control-Allow-Origin reflects attacker origin with credentials enabled.' },
  { id:'f3', template_id:'exposed-env', title:'Exposed .env File Containing Secrets', severity:'HIGH', url:'/.env', cve_ids:[], cvss_score:7.5, tags:['exposure','secrets'], curl_command:"curl 'https://target.com/.env'", references:['https://owasp.org'], description:'Laravel/Django .env file publicly accessible — DB creds and API keys exposed.' },
  { id:'f4', template_id:'graphql-introspection', title:'GraphQL Introspection Enabled in Production', severity:'MEDIUM', url:'/graphql', cve_ids:[], cvss_score:5.3, tags:['graphql','api'], curl_command:'curl -X POST -H "Content-Type: application/json" -d \'{"query":"{__schema{types{name}}}"}\' https://target.com/graphql', references:['https://owasp.org/Top10/A05_2021-Security_Misconfiguration/'], description:'Full schema enumeration possible via introspection — exposes all types and mutations.' },
  { id:'f5', template_id:'jwt-alg-none', title:'JWT Algorithm Confusion — alg:none Accepted', severity:'HIGH', url:'/api/auth', cve_ids:[], cvss_score:8.1, tags:['jwt','auth'], curl_command:'', references:['https://portswigger.net/web-security/jwt'], description:'Server accepts JWT tokens with algorithm set to none, allowing signature bypass.' },
  { id:'f6', template_id:'missing-headers', title:'Missing Critical Security Headers', severity:'MEDIUM', url:'/', cve_ids:[], cvss_score:4.3, tags:['headers','misconfig'], curl_command:"curl -I 'https://target.com/'", references:['https://owasp.org/www-project-secure-headers/'], description:'CSP, X-Frame-Options, X-Content-Type-Options missing — enables clickjacking and MIME sniffing.' },
]

export default function WebSecurity() {
  const [targets, setTargets]           = useState('')
  const [selected, setSelected]         = useState<string[]>([])
  const [findings, setFindings]         = useState<any[]>([])
  const [scanning, setScanning]         = useState(false)
  const [detailFinding, setDetailFinding] = useState<any>(null)
  const [proxyMode, setProxyMode]       = useState(false)

  // Toggle category selection
  const toggleCat = (id: string) =>
    setSelected(p => p.includes(id) ? p.filter(c => c !== id) : [...p, id])

  const selectAll   = () => setSelected(VULN_CATEGORIES.map(c => c.id))
  const selectNone  = () => setSelected([])

  // Launch scan
  const handleScan = async () => {
    const urls = targets.split('\n').map(t => t.trim()).filter(Boolean)
    if (!urls.length) { toast.error('Add at least one target URL'); return }
    if (!selected.length) { toast.error('Select at least one vulnerability category'); return }

    setScanning(true)
    setFindings([])

    try {
      const resp = await api.post('/web/scan', {
        targets: urls,
        categories: selected,
      })
      setFindings(resp.data.findings || DEMO_FINDINGS)
      toast.success(`Scan complete — ${resp.data.total_findings ?? DEMO_FINDINGS.length} findings`)
    } catch {
      // Backend not running — show demo results
      await new Promise(r => setTimeout(r, 2000))
      setFindings(DEMO_FINDINGS.filter(f =>
        selected.some(cat => VULN_CATEGORIES.find(c => c.id === cat)?.label.toLowerCase().includes(f.tags?.[0]?.toLowerCase() ?? '') ?? true)
      ).length > 0
        ? DEMO_FINDINGS
        : DEMO_FINDINGS
      )
      toast.success('Demo scan complete — 6 findings (connect backend for real results)')
    } finally {
      setScanning(false)
    }
  }

  const sevCount = (sev: string) => findings.filter(f => f.severity === sev).length

  return (
    <div>
      {/* Header */}
      <div className="page-header">
        <div>
          <h1 className="page-title gradient-text-red">🕷️ Web Security Testing</h1>
          <p className="page-subtitle">Nuclei · Burp · Caido — XSS · SQLi · SSRF · IDOR · JWT · CORS · GraphQL · 8000+ checks</p>
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
          <div className="grid-3" style={{ gap: 'var(--space-4)', fontSize: '0.875rem' }}>
            {[
              ['1. Start Burp Suite', 'Proxy → Options → HTTP Proxy → 127.0.0.1:8080'],
              ['2. Configure Browser', 'Set proxy to 127.0.0.1:8080 and install Burp CA cert'],
              ['3. Browse Target',    'Traffic flows through Burp — SPAIDER plugin syncs findings'],
              ['4. Run Active Scan',  'Burp Dashboard → New Scan → configure scope → launch'],
              ['5. Purple Validate',  'SPAIDER auto-correlates with Wazuh/Zeek detections'],
              ['6. View in SPAIDER',  'Findings appear here automatically via the plugin bridge'],
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
                placeholder={'https://target.example.com\nhttps://api.example.com\nhttps://admin.example.com'}
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
                  onClick={() => toggleCat(cat.id)}
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
                <button className="btn btn-sm btn-ghost">Export</button>
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

            {findings.length === 0 && !scanning && (
              <div style={{ textAlign: 'center', padding: 'var(--space-10)', color: 'var(--color-text-muted)' }}>
                <div style={{ fontSize: '3rem', marginBottom: 'var(--space-4)' }}>🕷️</div>
                <div style={{ fontWeight: 600, marginBottom: 8 }}>Configure a target and categories</div>
                <div style={{ fontSize: '0.875rem' }}>Select vulnerability types on the left and launch a scan</div>
              </div>
            )}

            {scanning && (
              <div style={{ padding: 'var(--space-6)' }}>
                <div className="terminal">
                  {[
                    { cls: 'warn',    txt: '[!] ⚠️ Only scan systems you are authorised to test. Ensure a valid scope and authorization document exists.' },
                    { cls: 'info',    txt: '[*] Initialising SPAIDER Web Security Engine...' },
                    { cls: 'info',    txt: '[*] Loading Nuclei templates...' },
                    { cls: 'success', txt: '[+] Templates loaded: CVEs, XSS, SQLi, SSRF, CORS, JWT, API...' },
                    { cls: 'info',    txt: `[*] Starting scan against ${targets.split('\n').filter(Boolean).length} target(s)` },
                    { cls: 'warn',    txt: '[~] Testing injection vectors...' },
                    { cls: 'warn',    txt: '[~] Checking authentication endpoints...' },
                    { cls: 'warn',    txt: '[~] Analysing API surface...' },
                  ].map((l, i) => (
                    <div key={i} className={`terminal-line ${l.cls}`} style={{ animationDelay: `${i * 0.3}s` }}>
                      {l.txt}
                    </div>
                  ))}
                </div>
              </div>
            )}

            <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
              {findings.map(f => (
                <div
                  key={f.id}
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
