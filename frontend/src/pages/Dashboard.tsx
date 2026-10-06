import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import SpiderWebCanvas from '../components/SpiderWebCanvas'

const MOCK_STATS = {
  assets: 127,
  apis: 43,
  services: 18,
  subdomains: 62,
  critical: 3,
  high: 11,
  medium: 28,
  low: 42,
  scanProgress: 73,
}

const RECON_STEPS = [
  { label: 'Asset discovery',          done: true  },
  { label: 'Subdomain enumeration',    done: true  },
  { label: 'Technology fingerprinting',done: true  },
  { label: 'HTTP probing',             done: true  },
  { label: 'Endpoint discovery',       done: true  },
  { label: 'Parameter discovery',      done: true  },
  { label: 'Vulnerability validation', active: true },
  { label: 'Evidence collection',      done: false },
  { label: 'Report generation',        done: false },
]

const MOCK_VULNS = [
  { id: '1', title: 'Apache 2.4.49 Path Traversal', cve: 'CVE-2021-41773', severity: 'CRITICAL', asset: 'example.com', cvss: 9.8, conf: 96 },
  { id: '2', title: 'Potential SSRF via url= parameter', cve: null, severity: 'HIGH', asset: 'api.example.com', cvss: 8.6, conf: 87 },
  { id: '3', title: 'IDOR on /api/v1/users/{id}', cve: null, severity: 'HIGH', asset: 'api.example.com', cvss: 7.9, conf: 81 },
  { id: '4', title: 'Reflected XSS in search param', cve: null, severity: 'MEDIUM', asset: 'example.com', cvss: 6.1, conf: 94 },
  { id: '5', title: 'Default admin credentials exposed', cve: null, severity: 'CRITICAL', asset: 'admin.example.com', cvss: 9.1, conf: 99 },
]

const AI_LOG = [
  { time: '18:54', msg: 'SSRF confirmed on /api/fetch endpoint. Callback intercepted at burp collab.', type: 'vuln' },
  { time: '18:51', msg: 'Enumerating parameters on /api/v1/users — IDOR pattern detected.', type: 'info' },
  { time: '18:47', msg: 'Fingerprinting complete: Apache 2.4.49 on port 80. Nuclei template match.', type: 'warn' },
  { time: '18:39', msg: 'Discovered 14 new endpoints via JS analysis. Adding to attack surface.', type: 'info' },
  { time: '18:30', msg: 'Subfinder: 62 subdomains found. HTTPX probing in progress.', type: 'info' },
]

function SeverityBadge({ severity }: { severity: string }) {
  return <span className={`badge badge-${severity.toLowerCase()}`}>{severity}</span>
}

function StatCard({ value, label, color, icon }: any) {
  return (
    <div className="stat-card" style={{ '--card-accent': color } as any}>
      <div className="stat-icon">{icon}</div>
      <div className="stat-value" style={{ color }}>{value}</div>
      <div className="stat-label">{label}</div>
    </div>
  )
}

function SeverityBar({ label, count, color, max }: { label: string; count: number; color: string; max: number }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
      <span style={{ fontSize: '0.7rem', color, fontWeight: 700, width: 60, fontFamily: 'var(--font-mono)' }}>{label}</span>
      <div style={{ flex: 1, height: 6, background: 'rgba(255,255,255,0.06)', borderRadius: 3, overflow: 'hidden' }}>
        <div style={{
          width: `${(count / max) * 100}%`, height: '100%',
          background: `linear-gradient(90deg, ${color}, ${color}88)`,
          borderRadius: 3, transition: 'width 1s ease',
          boxShadow: `0 0 8px ${color}66`,
        }} />
      </div>
      <span style={{ fontSize: '0.8rem', fontWeight: 800, color, width: 28, textAlign: 'right', fontFamily: 'var(--font-mono)' }}>{count}</span>
    </div>
  )
}

export default function Dashboard() {
  const navigate = useNavigate()
  const [tick, setTick] = useState(0)
  const [nodeCount, setNodeCount] = useState(89)

  useEffect(() => {
    const id = setInterval(() => {
      setTick(t => t + 1)
      if (Math.random() > 0.7) setNodeCount(n => n + 1)
    }, 3000)
    return () => clearInterval(id)
  }, [])

  const maxSev = Math.max(MOCK_STATS.critical, MOCK_STATS.high, MOCK_STATS.medium, MOCK_STATS.low)

  return (
    <div>
      {/* Hero header */}
      <div className="page-header" style={{ marginBottom: 'var(--space-6)' }}>
        <div>
          <h1 className="page-title gradient-text-cyan" style={{ fontSize: '1.6rem', letterSpacing: '0.1em' }}>
            🕷️ SPAiDER COMMAND CENTER
          </h1>
          <p className="page-subtitle">AI-Powered Bug Bounty Automation · Hunt deeper. Find what others miss.</p>
        </div>
        <div className="flex gap-2" style={{ alignItems: 'center' }}>
          <div className="scanner-pulse" style={{ display: 'flex', alignItems: 'center', gap: 8,
            padding: '6px 14px', background: 'rgba(0,255,136,0.08)', border: '1px solid rgba(0,255,136,0.3)',
            borderRadius: 'var(--radius-md)', fontSize: '0.75rem', color: '#00ff88', fontWeight: 700 }}>
            <span className="status-dot running" />
            AI HUNTING ACTIVE
          </div>
          <button className="btn btn-primary" onClick={() => navigate('/ai-analyst')}>
            ⚡ AI Hunter →
          </button>
        </div>
      </div>

      {/* Stats row */}
      <div className="stats-grid mb-6" style={{ gridTemplateColumns: 'repeat(4, 1fr)' }}>
        <StatCard icon="📡" value={MOCK_STATS.assets} label="Assets Discovered" color="var(--color-cyan)" />
        <StatCard icon="🔗" value={MOCK_STATS.apis}  label="APIs Mapped"        color="var(--color-purple)" />
        <StatCard icon="🌐" value={MOCK_STATS.subdomains} label="Subdomains"    color="#00ff88" />
        <StatCard icon="⚙" value={MOCK_STATS.services}   label="Services"       color="#38bdf8" />
      </div>

      {/* Main grid */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 'var(--space-5)', marginBottom: 'var(--space-5)' }}>

        {/* Attack Surface 3D Preview */}
        <div className="card" style={{
          background: 'linear-gradient(135deg, rgba(0,229,255,0.04), rgba(168,85,247,0.04))',
          border: '1px solid var(--color-border-accent)',
          position: 'relative', overflow: 'hidden',
        }}>
          <div className="card-header">
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <span style={{ fontSize: '1.4rem' }}>🕸️</span>
              <div>
                <span className="card-title">Attack Surface Map</span>
                <div style={{ fontSize: '0.7rem', color: 'var(--color-text-muted)' }}>
                  Live 3D relationship graph — {nodeCount} nodes
                </div>
              </div>
            </div>
            <button className="btn btn-sm btn-primary" onClick={() => navigate('/network-map')}
              style={{ background: 'linear-gradient(135deg, var(--color-cyan), var(--color-purple))', color: '#000', fontWeight: 700 }}>
              Full Map →
            </button>
          </div>
          <div style={{ height: 220, background: 'rgba(0,0,0,0.5)', borderRadius: 'var(--radius-md)',
            border: '1px solid var(--color-border)', position: 'relative', overflow: 'hidden' }}>
            <SpiderWebCanvas interactive={true} opacity={0.9} />
            <div style={{ position: 'absolute', top: 10, left: 12, display: 'flex', gap: 6, pointerEvents: 'none' }}>
              {['DOMAIN', 'SUBDOMAIN', 'API', 'ENDPOINT', 'VULN'].map((t, i) => {
                const colors = ['#00e5ff', '#00ff88', '#a855f7', '#38bdf8', '#ff3b5c']
                return (
                  <span key={t} style={{ fontSize: '0.6rem', padding: '2px 6px',
                    background: `${colors[i]}15`, border: `1px solid ${colors[i]}40`,
                    borderRadius: 3, color: colors[i], fontFamily: 'var(--font-mono)', fontWeight: 700 }}>
                    {t}
                  </span>
                )
              })}
            </div>
            <div style={{ position: 'absolute', bottom: 8, right: 12, fontSize: '0.6rem',
              color: 'var(--color-text-muted)', pointerEvents: 'none' }}>
              Mouse to interact · Auto-rotating
            </div>
          </div>

          {/* Node type legend */}
          <div style={{ display: 'flex', gap: 16, marginTop: 12, flexWrap: 'wrap' }}>
            {[
              { label: 'Domains', count: 1, color: '#00e5ff' },
              { label: 'Subdomains', count: MOCK_STATS.subdomains, color: '#00ff88' },
              { label: 'APIs', count: MOCK_STATS.apis, color: '#a855f7' },
              { label: 'Endpoints', count: 84, color: '#38bdf8' },
              { label: 'Vulns', count: MOCK_STATS.critical + MOCK_STATS.high, color: '#ff3b5c' },
            ].map(item => (
              <div key={item.label} style={{ textAlign: 'center' }}>
                <div style={{ fontSize: '1rem', fontWeight: 800, color: item.color, fontFamily: 'var(--font-mono)' }}>{item.count}</div>
                <div style={{ fontSize: '0.62rem', color: 'var(--color-text-muted)' }}>{item.label}</div>
              </div>
            ))}
          </div>
        </div>

        {/* AI Hunter Status */}
        <div className="card" style={{ background: 'linear-gradient(135deg, rgba(168,85,247,0.05), rgba(0,0,0,0))', border: '1px solid rgba(168,85,247,0.25)' }}>
          <div className="card-header">
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span style={{ fontSize: '1.3rem' }}>⚡</span>
              <div>
                <span className="card-title" style={{ color: '#a855f7' }}>AI HUNTER</span>
                <div style={{ fontSize: '0.7rem', color: '#00ff88' }}>● Target: example.com · Authorized ✓</div>
              </div>
            </div>
            <button className="btn btn-sm" onClick={() => navigate('/ai-analyst')}
              style={{ background: 'rgba(168,85,247,0.15)', color: '#a855f7', border: '1px solid rgba(168,85,247,0.4)', fontSize: '0.72rem' }}>
              View →
            </button>
          </div>

          {/* Scan progress */}
          <div style={{ marginBottom: 16 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
              <span style={{ fontSize: '0.72rem', color: 'var(--color-text-muted)' }}>Hunt Progress</span>
              <span style={{ fontSize: '0.8rem', fontWeight: 800, color: '#a855f7', fontFamily: 'var(--font-mono)' }}>{MOCK_STATS.scanProgress}%</span>
            </div>
            <div style={{ height: 8, background: 'rgba(255,255,255,0.06)', borderRadius: 4, overflow: 'hidden' }}>
              <div style={{
                width: `${MOCK_STATS.scanProgress}%`, height: '100%',
                background: 'linear-gradient(90deg, #a855f7, #00e5ff)',
                borderRadius: 4, transition: 'width 1.5s ease',
                boxShadow: '0 0 12px rgba(168,85,247,0.5)',
              }} />
            </div>
          </div>

          {/* Step checklist */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
            {RECON_STEPS.map((step, i) => (
              <div key={i} style={{
                display: 'flex', alignItems: 'center', gap: 8,
                fontSize: '0.78rem', opacity: step.done ? 0.9 : step.active ? 1 : 0.4,
              }}>
                <span style={{
                  width: 16, height: 16, borderRadius: '50%', flexShrink: 0,
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  fontSize: '0.6rem', fontWeight: 800,
                  background: step.done ? 'rgba(0,255,136,0.2)' : step.active ? 'rgba(168,85,247,0.3)' : 'rgba(255,255,255,0.05)',
                  border: `1px solid ${step.done ? '#00ff88' : step.active ? '#a855f7' : 'rgba(255,255,255,0.1)'}`,
                  color: step.done ? '#00ff88' : step.active ? '#a855f7' : 'var(--color-text-muted)',
                }}>
                  {step.done ? '✓' : step.active ? '●' : '○'}
                </span>
                <span style={{ color: step.active ? '#a855f7' : step.done ? 'var(--color-text-primary)' : 'var(--color-text-muted)' }}>
                  {step.label}
                </span>
                {step.active && (
                  <span style={{ marginLeft: 'auto', fontSize: '0.65rem', color: '#a855f7',
                    animation: 'pulse-brand 1.5s ease-in-out infinite' }}>
                    ● RUNNING
                  </span>
                )}
              </div>
            ))}
          </div>

          {/* Latest AI reasoning */}
          <div style={{ marginTop: 14, padding: 10, background: 'rgba(168,85,247,0.06)',
            border: '1px solid rgba(168,85,247,0.2)', borderRadius: 'var(--radius-md)' }}>
            <div style={{ fontSize: '0.65rem', fontWeight: 800, color: '#a855f7', marginBottom: 4, letterSpacing: '0.08em' }}>
              🧠 AI REASONING
            </div>
            <div style={{ fontSize: '0.75rem', color: 'var(--color-text-primary)', lineHeight: 1.5, fontFamily: 'var(--font-mono)' }}>
              Potential SSRF detected.<br />
              Endpoint: /api/fetch · Param: url=<br />
              Confidence: <span style={{ color: '#a855f7' }}>87%</span><br />
              Next: Controlled callback verification
            </div>
          </div>
        </div>
      </div>

      {/* Severity breakdown + AI Log */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1.6fr', gap: 'var(--space-5)', marginBottom: 'var(--space-5)' }}>

        {/* Severity breakdown */}
        <div className="card">
          <div className="card-header">
            <span className="card-title">⚠ Vulnerability Summary</span>
          </div>
          <div style={{ marginBottom: 20 }}>
            <SeverityBar label="CRITICAL" count={MOCK_STATS.critical} color="#ff1744" max={maxSev} />
            <SeverityBar label="HIGH"     count={MOCK_STATS.high}     color="#ff5722" max={maxSev} />
            <SeverityBar label="MEDIUM"   count={MOCK_STATS.medium}   color="#ff9800" max={maxSev} />
            <SeverityBar label="LOW"      count={MOCK_STATS.low}      color="#ffc107" max={maxSev} />
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
            <div style={{ padding: 10, background: 'rgba(255,23,68,0.08)', border: '1px solid rgba(255,23,68,0.3)', borderRadius: 8, textAlign: 'center' }}>
              <div style={{ fontSize: '1.8rem', fontWeight: 900, color: '#ff1744', fontFamily: 'var(--font-mono)' }}>{MOCK_STATS.critical}</div>
              <div style={{ fontSize: '0.65rem', color: 'var(--color-text-muted)' }}>CRITICAL</div>
            </div>
            <div style={{ padding: 10, background: 'rgba(255,87,34,0.08)', border: '1px solid rgba(255,87,34,0.3)', borderRadius: 8, textAlign: 'center' }}>
              <div style={{ fontSize: '1.8rem', fontWeight: 900, color: '#ff5722', fontFamily: 'var(--font-mono)' }}>{MOCK_STATS.high}</div>
              <div style={{ fontSize: '0.65rem', color: 'var(--color-text-muted)' }}>HIGH</div>
            </div>
          </div>
          <button className="btn btn-sm btn-primary" style={{ width: '100%', marginTop: 12 }} onClick={() => navigate('/findings')}>
            View All Vulnerabilities →
          </button>
        </div>

        {/* AI Activity log */}
        <div className="card">
          <div className="card-header">
            <span className="card-title">🧠 AI Activity Log</span>
            <span style={{ fontSize: '0.68rem', color: '#00ff88', fontFamily: 'var(--font-mono)' }}>● LIVE</span>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {AI_LOG.map((entry, i) => (
              <div key={i} style={{
                display: 'flex', gap: 10, padding: '8px 10px',
                background: entry.type === 'vuln' ? 'rgba(255,59,92,0.06)' : entry.type === 'warn' ? 'rgba(255,152,0,0.06)' : 'rgba(255,255,255,0.03)',
                border: `1px solid ${entry.type === 'vuln' ? 'rgba(255,59,92,0.2)' : entry.type === 'warn' ? 'rgba(255,152,0,0.2)' : 'rgba(255,255,255,0.05)'}`,
                borderRadius: 6,
              }}>
                <span style={{ fontSize: '0.65rem', color: 'var(--color-text-muted)', fontFamily: 'var(--font-mono)', whiteSpace: 'nowrap', marginTop: 1 }}>
                  {entry.time}
                </span>
                <span style={{
                  fontSize: '0.75rem',
                  color: entry.type === 'vuln' ? '#ff3b5c' : entry.type === 'warn' ? '#ff9800' : 'var(--color-text-secondary)',
                  lineHeight: 1.5,
                }}>
                  {entry.msg}
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Vulnerabilities table */}
      <div className="card">
        <div className="card-header">
          <span className="card-title">🔎 Validated Vulnerabilities</span>
          <div style={{ display: 'flex', gap: 8 }}>
            <button className="btn btn-sm btn-ghost" onClick={() => navigate('/reports')}>Generate Report</button>
            <button className="btn btn-sm btn-primary" onClick={() => navigate('/ai-analyst')}>⚡ Start Hunt</button>
          </div>
        </div>
        <table className="data-table">
          <thead>
            <tr>
              <th>Vulnerability</th>
              <th>CVE</th>
              <th>Severity</th>
              <th>CVSS</th>
              <th>Confidence</th>
              <th>Asset</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {MOCK_VULNS.map(v => (
              <tr key={v.id}>
                <td style={{ fontWeight: 600 }}>{v.title}</td>
                <td className="mono" style={{ fontSize: '0.72rem', color: 'var(--color-text-muted)' }}>
                  {v.cve || '—'}
                </td>
                <td><SeverityBadge severity={v.severity} /></td>
                <td className="mono" style={{
                  color: v.cvss >= 9 ? '#ff1744' : v.cvss >= 7 ? '#ff5722' : '#ff9800',
                  fontWeight: 800,
                }}>
                  {v.cvss}
                </td>
                <td>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                    <div style={{ flex: 1, height: 4, background: 'rgba(255,255,255,0.06)', borderRadius: 2, overflow: 'hidden', minWidth: 40 }}>
                      <div style={{ width: `${v.conf}%`, height: '100%',
                        background: v.conf > 90 ? '#00ff88' : '#ff9800', borderRadius: 2 }} />
                    </div>
                    <span className="mono" style={{ fontSize: '0.72rem', color: 'var(--color-text-muted)' }}>{v.conf}%</span>
                  </div>
                </td>
                <td className="mono" style={{ fontSize: '0.72rem', color: 'var(--color-cyan)' }}>{v.asset}</td>
                <td>
                  <div style={{ display: 'flex', gap: 4 }}>
                    <button className="btn btn-sm btn-ghost" style={{ fontSize: '0.68rem' }}>Evidence</button>
                    <button className="btn btn-sm btn-primary" style={{ fontSize: '0.68rem' }}>Report</button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
