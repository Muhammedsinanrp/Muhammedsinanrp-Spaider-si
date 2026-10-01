import { useQuery } from '@tanstack/react-query'
import { findingApi, alertApi, aiApi, scanApi } from '../api/client'

const MOCK_STATS = {
  criticalFindings: 3,
  highFindings: 12,
  openAlerts: 8,
  assetsMonitored: 47,
  scansToday: 6,
  detectionRate: 72,
}

const MOCK_RECENT_ALERTS = [
  { id: '1', time: '06:12', title: 'Suspicious lateral movement detected', source: 'Zeek', severity: 'HIGH' },
  { id: '2', time: '05:44', title: 'Multiple failed SSH authentications', source: 'Wazuh', severity: 'MEDIUM' },
  { id: '3', time: '04:30', title: 'Outbound connection to known C2', source: 'Suricata', severity: 'CRITICAL' },
  { id: '4', time: '03:15', title: 'Unusual DNS query pattern', source: 'Zeek', severity: 'MEDIUM' },
  { id: '5', time: '02:00', title: 'Port scan from external IP', source: 'Suricata', severity: 'HIGH' },
]

const MOCK_FINDINGS = [
  { id: '1', title: 'Apache 2.4.49 Path Traversal (CVE-2021-41773)', severity: 'CRITICAL', asset: '192.168.1.10' },
  { id: '2', title: 'Default credentials on admin panel', severity: 'HIGH', asset: '192.168.1.20' },
  { id: '3', title: 'TLS 1.0 enabled on HTTPS service', severity: 'MEDIUM', asset: '192.168.1.10' },
  { id: '4', title: 'Missing HTTP security headers', severity: 'LOW', asset: '192.168.1.10' },
]

function SeverityBadge({ severity }: { severity: string }) {
  return <span className={`badge badge-${severity.toLowerCase()}`}>{severity}</span>
}

function StatCard({ icon, value, label, trend, color }: any) {
  return (
    <div className="stat-card" style={{ '--card-accent': color } as any}>
      <div className="stat-icon">{icon}</div>
      <div className="stat-value">{value}</div>
      <div className="stat-label">{label}</div>
      {trend && <div className={`stat-trend ${trend.dir}`}>{trend.text}</div>}
    </div>
  )
}

export default function Dashboard() {
  const { data: aiSummary } = useQuery({ queryKey: ['ai-summary'], queryFn: aiApi.dashboardSummary, retry: false })

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title gradient-text-cyan">Security Command Center</h1>
          <p className="page-subtitle">Real-time threat intelligence & security posture overview</p>
        </div>
        <div className="flex gap-2">
          <span className="badge badge-critical">⚡ {MOCK_STATS.criticalFindings} Critical</span>
          <span className="badge badge-high">⚠ {MOCK_STATS.highFindings} High</span>
        </div>
      </div>

      {/* Stats */}
      <div className="stats-grid mb-6">
        <StatCard icon="🚨" value={MOCK_STATS.criticalFindings} label="Critical Findings" color="var(--color-critical)" trend={{ dir: 'down', text: '↑ 2 new today' }} />
        <StatCard icon="🛡️" value={MOCK_STATS.openAlerts} label="Open Alerts" color="var(--color-high)" />
        <StatCard icon="📡" value={MOCK_STATS.assetsMonitored} label="Assets Monitored" color="var(--color-cyan)" trend={{ dir: 'up', text: '↑ 3 new hosts' }} />
        <StatCard icon="🔍" value={MOCK_STATS.scansToday} label="Scans Today" color="var(--color-blue)" />
        <StatCard icon="🎯" value={`${MOCK_STATS.detectionRate}%`} label="Detection Coverage" color="var(--color-purple)" trend={{ dir: 'up', text: '↑ improving' }} />
        <StatCard icon="✅" value="ACTIVE" label="Threat Intel Feed" color="var(--color-safe)" />
      </div>

      {/* AI Summary + Recent Alerts */}
      <div className="grid-2 mb-6">
        {/* AI Posture Panel */}
        <div className="card">
          <div className="card-header">
            <span className="card-title">🧠 AI Security Posture</span>
            <span className="badge badge-medium">Powered by GPT-4o</span>
          </div>
          {aiSummary ? (
            <div>
              <div style={{ fontSize: '2.5rem', fontWeight: 800, color: 'var(--color-cyan)', marginBottom: 4 }}>
                {aiSummary.posture_score}<span style={{ fontSize: '1rem', color: 'var(--color-text-muted)'}}>/100</span>
              </div>
              <div style={{ fontSize: '0.875rem', color: 'var(--color-text-muted)', marginBottom: 'var(--space-4)' }}>
                Security posture score · Trend: <span style={{ color: 'var(--color-safe)' }}>{aiSummary.trend}</span>
              </div>
              <div style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--color-text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 'var(--space-2)' }}>TOP RISKS</div>
              {aiSummary.top_risks?.map((risk: string, i: number) => (
                <div key={i} style={{ display: 'flex', gap: 'var(--space-2)', marginBottom: 'var(--space-2)', fontSize: '0.875rem' }}>
                  <span style={{ color: 'var(--color-red)' }}>▸</span>
                  <span>{risk}</span>
                </div>
              ))}
            </div>
          ) : (
            <div>
              <div style={{ fontSize: '2.5rem', fontWeight: 800, color: 'var(--color-cyan)', marginBottom: 4 }}>
                72<span style={{ fontSize: '1rem', color: 'var(--color-text-muted)' }}>/100</span>
              </div>
              <div style={{ fontSize: '0.875rem', color: 'var(--color-text-muted)', marginBottom: 'var(--space-4)' }}>
                Security posture · <span style={{ color: 'var(--color-safe)' }}>Improving ↑</span>
              </div>
              <div style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--color-text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 'var(--space-2)' }}>TOP RISKS</div>
              {['Unpatched services on perimeter', 'Lateral movement detection gaps', 'Weak authentication on VPN'].map((r, i) => (
                <div key={i} style={{ display: 'flex', gap: 'var(--space-2)', marginBottom: 'var(--space-2)', fontSize: '0.875rem' }}>
                  <span style={{ color: 'var(--color-red)' }}>▸</span>
                  <span>{r}</span>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Recent Alerts */}
        <div className="card">
          <div className="card-header">
            <span className="card-title">🔔 Recent Alerts</span>
            <button className="btn btn-sm btn-ghost">View All</button>
          </div>
          <div>
            {MOCK_RECENT_ALERTS.map(alert => (
              <div key={alert.id} className="timeline-item">
                <div className="timeline-time">{alert.time}</div>
                <div className="timeline-content">
                  <div className="flex items-center gap-2">
                    <SeverityBadge severity={alert.severity} />
                  </div>
                  <div className="timeline-title" style={{ marginTop: 4 }}>{alert.title}</div>
                  <div className="timeline-source">Source: {alert.source}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Recent Findings */}
      <div className="card">
        <div className="card-header">
          <span className="card-title">🔎 Critical Findings</span>
          <button className="btn btn-sm btn-primary">New Scan</button>
        </div>
        <table className="data-table">
          <thead>
            <tr>
              <th>Finding</th>
              <th>Severity</th>
              <th>Asset</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {MOCK_FINDINGS.map(f => (
              <tr key={f.id}>
                <td>{f.title}</td>
                <td><SeverityBadge severity={f.severity} /></td>
                <td className="mono">{f.asset}</td>
                <td>
                  <button className="btn btn-sm btn-ghost">Investigate</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
