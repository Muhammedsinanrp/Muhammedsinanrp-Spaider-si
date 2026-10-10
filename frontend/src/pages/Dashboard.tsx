import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import SpiderWebCanvas from '../components/SpiderWebCanvas'
import { experimentApi, findingApi, scanApi } from '../api/client'

type Metrics = {
  targets_scanned: number
  scans_executed: number
  assets_discovered: number
  endpoints_discovered: number
  ports_discovered: number
  findings: { total: number; critical: number; high: number; medium: number; low: number; info: number }
}

const EMPTY_METRICS: Metrics = {
  targets_scanned: 0,
  scans_executed: 0,
  assets_discovered: 0,
  endpoints_discovered: 0,
  ports_discovered: 0,
  findings: { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 },
}

const SEVERITIES = [
  { key: 'critical', label: 'CRITICAL', color: '#ff1744' },
  { key: 'high', label: 'HIGH', color: '#ff5722' },
  { key: 'medium', label: 'MEDIUM', color: '#ff9800' },
  { key: 'low', label: 'LOW', color: '#ffc107' },
] as const

function SeverityBadge({ severity }: { severity: string }) {
  const normalized = String(severity || 'INFO').toLowerCase()
  return <span className={`badge badge-${normalized}`}>{String(severity || 'INFO').toUpperCase()}</span>
}

function StatCard({ value, label, color, icon }: { value: number | string; label: string; color: string; icon: string }) {
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
          width: `${max ? (count / max) * 100 : 0}%`, height: '100%',
          background: `linear-gradient(90deg, ${color}, ${color}88)`,
          borderRadius: 3, transition: 'width 1s ease',
        }} />
      </div>
      <span style={{ fontSize: '0.8rem', fontWeight: 800, color, width: 28, textAlign: 'right', fontFamily: 'var(--font-mono)' }}>{count}</span>
    </div>
  )
}

export default function Dashboard() {
  const navigate = useNavigate()
  const [metrics, setMetrics] = useState<Metrics>(EMPTY_METRICS)
  const [findings, setFindings] = useState<any[]>([])
  const [scans, setScans] = useState<any[]>([])
  const [events, setEvents] = useState<any[]>([])
  const [apiConnected, setApiConnected] = useState(false)
  const [lastUpdated, setLastUpdated] = useState<string | null>(null)
  const [loadError, setLoadError] = useState<string | null>(null)

  useEffect(() => {
    let mounted = true

    const load = async () => {
      const [metricResult, findingResult, scanResult] = await Promise.allSettled([
        experimentApi.metrics(),
        findingApi.list({ limit: 10 }),
        scanApi.list({ limit: 10 }),
      ])
      if (!mounted) return

      if (metricResult.status === 'fulfilled') {
        const m = metricResult.value || {}
        setMetrics({
          targets_scanned: Number(m.targets_scanned || 0),
          scans_executed: Number(m.scans_executed || 0),
          assets_discovered: Number(m.assets_discovered || 0),
          endpoints_discovered: Number(m.endpoints_discovered || 0),
          ports_discovered: Number(m.ports_discovered || 0),
          findings: {
            total: Number(m.findings?.total || 0),
            critical: Number(m.findings?.critical || 0),
            high: Number(m.findings?.high || 0),
            medium: Number(m.findings?.medium || 0),
            low: Number(m.findings?.low || 0),
            info: Number(m.findings?.info || 0),
          },
        })
      }
      if (findingResult.status === 'fulfilled') {
        setFindings(Array.isArray(findingResult.value) ? findingResult.value : [])
      }
      if (scanResult.status === 'fulfilled') {
        setScans(Array.isArray(scanResult.value) ? scanResult.value : [])
      }

      const connected = metricResult.status === 'fulfilled' ||
        findingResult.status === 'fulfilled' || scanResult.status === 'fulfilled'
      setApiConnected(connected)
      const failures = [metricResult, findingResult, scanResult].filter(r => r.status === 'rejected')
      setLoadError(connected ? null : 'Backend API is not reachable. Start the SPAiDER backend and refresh.')
      if (failures.length === 3) return

      const latest = scanResult.status === 'fulfilled' && Array.isArray(scanResult.value)
        ? scanResult.value[0] : null
      if (latest?.id) {
        try {
          const fetchedEvents = await experimentApi.scanEvents(String(latest.id))
          if (mounted) setEvents(Array.isArray(fetchedEvents) ? fetchedEvents.slice(-8).reverse() : [])
        } catch {
          if (mounted) setEvents([])
        }
      } else {
        setEvents([])
      }

      if (mounted) setLastUpdated(new Date().toLocaleTimeString())
    }

    void load()
    const timer = window.setInterval(() => { void load() }, 15000)
    return () => { mounted = false; window.clearInterval(timer) }
  }, [])

  const latestScan = scans[0]
  const hasRunningScan = scans.some(s => ['PENDING', 'RUNNING', 'STARTED'].includes(String(s.status || '').toUpperCase()))
  const nodeCount = metrics.assets_discovered + metrics.endpoints_discovered + metrics.ports_discovered
  const maxSev = Math.max(1, ...SEVERITIES.map(s => metrics.findings[s.key]))
  const topFindings = findings.slice(0, 5)

  return (
    <div>
      <div className="page-header" style={{ marginBottom: 'var(--space-6)' }}>
        <div>
          <h1 className="page-title gradient-text-cyan" style={{ fontSize: '1.6rem', letterSpacing: '0.1em' }}>
            🕷️ SPAiDER COMMAND CENTER
          </h1>
          <p className="page-subtitle">AI-Powered Security Testing · Metrics and findings from your connected backend.</p>
          <div style={{ fontSize: '0.68rem', color: 'var(--color-text-muted)', marginTop: 5 }}>
            {lastUpdated ? `Last API refresh: ${lastUpdated}` : 'Loading live API data…'}
          </div>
        </div>
        <div className="flex gap-2" style={{ alignItems: 'center' }}>
          <div style={{
            display: 'flex', alignItems: 'center', gap: 8, padding: '6px 14px',
            background: apiConnected ? 'rgba(0,255,136,0.08)' : 'rgba(255,152,0,0.08)',
            border: `1px solid ${apiConnected ? 'rgba(0,255,136,0.3)' : 'rgba(255,152,0,0.3)'}`,
            borderRadius: 'var(--radius-md)', fontSize: '0.75rem',
            color: apiConnected ? '#00ff88' : '#ff9800', fontWeight: 700,
          }}>
            <span className={`status-dot ${apiConnected ? 'running' : ''}`} />
            {apiConnected ? 'API CONNECTED' : 'API DISCONNECTED'}
          </div>
          <button className="btn btn-primary" onClick={() => navigate('/web-security')}>⚡ Web Scan →</button>
        </div>
      </div>

      {loadError && (
        <div role="alert" className="card" style={{ marginBottom: 'var(--space-4)', color: 'var(--color-high)' }}>
          {loadError}
        </div>
      )}

      <div className="stats-grid mb-6" style={{ gridTemplateColumns: 'repeat(4, 1fr)' }}>
        <StatCard icon="📡" value={metrics.assets_discovered} label="Assets Discovered" color="var(--color-cyan)" />
        <StatCard icon="🔗" value={metrics.endpoints_discovered} label="Endpoints Mapped" color="var(--color-purple)" />
        <StatCard icon="⚙️" value={metrics.ports_discovered} label="Services Discovered" color="#38bdf8" />
        <StatCard icon="🧪" value={metrics.scans_executed} label="Scan Jobs Recorded" color="#00ff88" />
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 'var(--space-5)', marginBottom: 'var(--space-5)' }}>
        <div className="card" style={{
          background: 'linear-gradient(135deg, rgba(0,229,255,0.04), rgba(168,85,247,0.04))',
          border: '1px solid var(--color-border-accent)', position: 'relative', overflow: 'hidden',
        }}>
          <div className="card-header">
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <span style={{ fontSize: '1.4rem' }}>🕸️</span>
              <div>
                <span className="card-title">Attack Surface Map</span>
                <div style={{ fontSize: '0.7rem', color: 'var(--color-text-muted)' }}>
                  {nodeCount} database-recorded asset, endpoint, and service records
                </div>
              </div>
            </div>
            <button className="btn btn-sm btn-primary" onClick={() => navigate('/network-map')}
              style={{ background: 'linear-gradient(135deg, var(--color-cyan), var(--color-purple))', color: '#000', fontWeight: 700 }}>
              Full Map →
            </button>
          </div>
          <div style={{ height: 220, background: 'rgba(0,0,0,0.5)', borderRadius: 'var(--radius-md)', border: '1px solid var(--color-border)', position: 'relative', overflow: 'hidden' }}>
            <SpiderWebCanvas interactive={true} opacity={0.9} />
            <div style={{ position: 'absolute', top: 10, left: 12, display: 'flex', gap: 6, pointerEvents: 'none' }}>
              {['ASSETS', 'ENDPOINTS', 'SERVICES', 'FINDINGS'].map((label, i) => {
                const counts = [metrics.assets_discovered, metrics.endpoints_discovered, metrics.ports_discovered, metrics.findings.total]
                const colors = ['#00e5ff', '#00ff88', '#a855f7', '#ff3b5c']
                return (
                  <span key={label} style={{ fontSize: '0.6rem', padding: '2px 6px', background: `${colors[i]}15`, border: `1px solid ${colors[i]}40`, borderRadius: 3, color: colors[i], fontFamily: 'var(--font-mono)', fontWeight: 700 }}>
                    {label} {counts[i]}
                  </span>
                )
              })}
            </div>
            <div style={{ position: 'absolute', bottom: 8, right: 12, fontSize: '0.6rem', color: 'var(--color-text-muted)', pointerEvents: 'none' }}>
              Visualization · counts come from API data
            </div>
          </div>
          <div style={{ display: 'flex', gap: 16, marginTop: 12, flexWrap: 'wrap' }}>
            {[
              { label: 'Targets scanned', count: metrics.targets_scanned, color: '#00e5ff' },
              { label: 'Endpoints', count: metrics.endpoints_discovered, color: '#a855f7' },
              { label: 'Findings', count: metrics.findings.total, color: '#ff3b5c' },
            ].map(item => (
              <div key={item.label} style={{ textAlign: 'center' }}>
                <div style={{ fontSize: '1rem', fontWeight: 800, color: item.color, fontFamily: 'var(--font-mono)' }}>{item.count}</div>
                <div style={{ fontSize: '0.62rem', color: 'var(--color-text-muted)' }}>{item.label}</div>
              </div>
            ))}
          </div>
        </div>

        <div className="card" style={{ background: 'linear-gradient(135deg, rgba(168,85,247,0.05), rgba(0,0,0,0))', border: '1px solid rgba(168,85,247,0.25)' }}>
          <div className="card-header">
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span style={{ fontSize: '1.3rem' }}>⚡</span>
              <div>
                <span className="card-title" style={{ color: '#a855f7' }}>SCAN ENGINE</span>
                <div style={{ fontSize: '0.7rem', color: hasRunningScan ? '#00ff88' : 'var(--color-text-muted)' }}>
                  {hasRunningScan ? '● A scan job is active' : 'No scan currently active'}
                </div>
              </div>
            </div>
            <button className="btn btn-sm" onClick={() => navigate('/scans')}
              style={{ background: 'rgba(168,85,247,0.15)', color: '#a855f7', border: '1px solid rgba(168,85,247,0.4)', fontSize: '0.72rem' }}>
              View Jobs →
            </button>
          </div>
          <div style={{ marginBottom: 16 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
              <span style={{ fontSize: '0.72rem', color: 'var(--color-text-muted)' }}>Latest scan progress</span>
              <span style={{ fontSize: '0.8rem', fontWeight: 800, color: '#a855f7', fontFamily: 'var(--font-mono)' }}>
                {latestScan ? `${Number(latestScan.progress || 0)}%` : '—'}
              </span>
            </div>
            <div style={{ height: 8, background: 'rgba(255,255,255,0.06)', borderRadius: 4, overflow: 'hidden' }}>
              <div style={{ width: `${latestScan ? Math.max(0, Math.min(100, Number(latestScan.progress || 0))) : 0}%`, height: '100%', background: 'linear-gradient(90deg, #a855f7, #00e5ff)', borderRadius: 4, transition: 'width 0.5s ease' }} />
            </div>
          </div>
          <div style={{ fontSize: '0.75rem', marginBottom: 12, lineHeight: 1.6 }}>
            <div style={{ color: 'var(--color-text-muted)' }}>Most recent job</div>
            <div style={{ fontWeight: 700 }}>{latestScan?.name || 'No scan jobs recorded yet'}</div>
            {latestScan && <div style={{ color: 'var(--color-text-muted)' }}>
              Status: {String(latestScan.status || 'UNKNOWN')} · Targets: {(latestScan.targets || []).join(', ') || '—'}
            </div>}
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
            {events.length ? events.slice(0, 5).map((event, i) => (
              <div key={event.id || i} style={{ display: 'flex', alignItems: 'start', gap: 8, fontSize: '0.76rem' }}>
                <span style={{ color: '#a855f7' }}>•</span>
                <span style={{ color: 'var(--color-text-secondary)', lineHeight: 1.5 }}>{event.message || event.stage}</span>
                <span style={{ marginLeft: 'auto', color: 'var(--color-text-muted)', whiteSpace: 'nowrap', fontSize: '0.65rem' }}>{event.progress ?? 0}%</span>
              </div>
            )) : (
              <div style={{ color: 'var(--color-text-muted)', fontSize: '0.75rem' }}>
                No scan events yet. Run a scan against an authorized lab target to populate activity.
              </div>
            )}
          </div>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1.6fr', gap: 'var(--space-5)', marginBottom: 'var(--space-5)' }}>
        <div className="card">
          <div className="card-header"><span className="card-title">⚠ Vulnerability Summary</span></div>
          <div style={{ marginBottom: 20 }}>
            {SEVERITIES.map(sev => (
              <SeverityBar key={sev.key} label={sev.label} count={metrics.findings[sev.key]} color={sev.color} max={maxSev} />
            ))}
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
            <div style={{ padding: 10, background: 'rgba(255,23,68,0.08)', border: '1px solid rgba(255,23,68,0.3)', borderRadius: 8, textAlign: 'center' }}>
              <div style={{ fontSize: '1.8rem', fontWeight: 900, color: '#ff1744', fontFamily: 'var(--font-mono)' }}>{metrics.findings.critical}</div>
              <div style={{ fontSize: '0.65rem', color: 'var(--color-text-muted)' }}>CRITICAL</div>
            </div>
            <div style={{ padding: 10, background: 'rgba(255,87,34,0.08)', border: '1px solid rgba(255,87,34,0.3)', borderRadius: 8, textAlign: 'center' }}>
              <div style={{ fontSize: '1.8rem', fontWeight: 900, color: '#ff5722', fontFamily: 'var(--font-mono)' }}>{metrics.findings.high}</div>
              <div style={{ fontSize: '0.65rem', color: 'var(--color-text-muted)' }}>HIGH</div>
            </div>
          </div>
          <button className="btn btn-sm btn-primary" style={{ width: '100%', marginTop: 12 }} onClick={() => navigate('/findings')}>
            View Findings →
          </button>
        </div>

        <div className="card">
          <div className="card-header">
            <span className="card-title">🧠 Recent Scan Activity</span>
            <span style={{ fontSize: '0.68rem', color: apiConnected ? '#00ff88' : '#ff9800', fontFamily: 'var(--font-mono)' }}>
              {apiConnected ? '● API DATA' : '○ OFFLINE'}
            </span>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {scans.slice(0, 5).length ? scans.slice(0, 5).map((scan, i) => (
              <div key={scan.id || i} style={{
                display: 'flex', gap: 10, padding: '8px 10px',
                background: 'rgba(255,255,255,0.03)', border: '1px solid var(--color-border)', borderRadius: 6,
              }}>
                <span style={{ fontSize: '0.65rem', color: 'var(--color-text-muted)', fontFamily: 'var(--font-mono)', whiteSpace: 'nowrap', marginTop: 1 }}>
                  {scan.created_at ? new Date(scan.created_at).toLocaleTimeString() : '—'}
                </span>
                <span style={{ flex: 1, fontSize: '0.75rem', color: 'var(--color-text-secondary)', lineHeight: 1.5 }}>
                  {scan.name || scan.plugin || 'Scan'} · {(scan.targets || []).join(', ')}
                </span>
                <SeverityBadge severity={String(scan.status || 'PENDING')} />
              </div>
            )) : (
              <div style={{ color: 'var(--color-text-muted)', fontSize: '0.8rem', padding: 12 }}>
                No scan history yet. Start a scan to see real events here.
              </div>
            )}
          </div>
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <span className="card-title">🔎 Recent Findings</span>
          <div className="flex gap-2">
            <button className="btn btn-sm btn-ghost" onClick={() => navigate('/reports')}>Reports</button>
            <button className="btn btn-sm btn-primary" onClick={() => navigate('/web-security')}>Start Web Scan</button>
          </div>
        </div>
        {topFindings.length ? (
          <div style={{ overflowX: 'auto' }}>
            <table className="data-table">
              <thead><tr><th>Finding</th><th>CVE</th><th>Severity</th><th>CVSS</th><th>Source</th><th>Created</th></tr></thead>
              <tbody>
                {topFindings.map((finding, i) => (
                  <tr key={finding.id || i}>
                    <td style={{ fontWeight: 600 }}>{finding.title || 'Untitled finding'}</td>
                    <td className="mono" style={{ fontSize: '0.72rem', color: 'var(--color-text-muted)' }}>
                      {(finding.cve_ids || []).join(', ') || '—'}
                    </td>
                    <td><SeverityBadge severity={finding.severity} /></td>
                    <td className="mono" style={{ fontWeight: 800 }}>{finding.cvss_score ?? '—'}</td>
                    <td className="mono" style={{ fontSize: '0.72rem', color: 'var(--color-cyan)' }}>{finding.plugin || '—'}</td>
                    <td className="mono" style={{ fontSize: '0.72rem', color: 'var(--color-text-muted)' }}>
                      {finding.created_at ? new Date(finding.created_at).toLocaleString() : '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div style={{ textAlign: 'center', padding: 'var(--space-8)', color: 'var(--color-text-muted)' }}>
            No findings are stored yet. The dashboard will populate after a real scan returns and saves results.
          </div>
        )}
      </div>
    </div>
  )
}
