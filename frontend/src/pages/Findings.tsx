import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { findingApi } from '../api/client'

const MOCK_FINDINGS = [
  { id:'1', title:'Apache 2.4.49 Path Traversal (CVE-2021-41773)', severity:'CRITICAL', plugin:'nuclei', cve_ids:['CVE-2021-41773'], cvss_score:9.8, mitre_techniques:['T1190'], remediation:'Update Apache to 2.4.51+', is_verified:true, is_false_positive:false, created_at:'2026-09-30T22:10:00Z', asset:'192.168.1.10' },
  { id:'2', title:'Default admin credentials on management panel', severity:'HIGH', plugin:'nuclei', cve_ids:[], cvss_score:8.1, mitre_techniques:['T1078'], remediation:'Change default credentials immediately', is_verified:true, is_false_positive:false, created_at:'2026-09-30T21:00:00Z', asset:'192.168.1.20' },
  { id:'3', title:'TLS 1.0 and 1.1 supported (SWEET32)', severity:'MEDIUM', plugin:'nmap', cve_ids:['CVE-2016-2183'], cvss_score:5.9, mitre_techniques:['T1557'], remediation:'Disable TLS 1.0 and 1.1', is_verified:false, is_false_positive:false, created_at:'2026-09-30T19:30:00Z', asset:'192.168.1.10' },
  { id:'4', title:'Missing X-Frame-Options security header', severity:'LOW', plugin:'nuclei', cve_ids:[], cvss_score:3.1, mitre_techniques:[], remediation:'Add X-Frame-Options: DENY header', is_verified:false, is_false_positive:false, created_at:'2026-09-30T18:00:00Z', asset:'192.168.1.10' },
  { id:'5', title:'SMBv1 enabled – EternalBlue exposure risk', severity:'CRITICAL', plugin:'nmap', cve_ids:['CVE-2017-0144'], cvss_score:9.3, mitre_techniques:['T1210'], remediation:'Disable SMBv1 via PowerShell', is_verified:true, is_false_positive:false, created_at:'2026-09-29T14:00:00Z', asset:'192.168.1.30' },
  { id:'6', title:'PostgreSQL exposed without authentication', severity:'HIGH', plugin:'nuclei', cve_ids:[], cvss_score:7.5, mitre_techniques:['T1190'], remediation:'Restrict PostgreSQL to localhost or VPN', is_verified:false, is_false_positive:false, created_at:'2026-09-29T10:00:00Z', asset:'192.168.1.20' },
]

const sevOrder: Record<string,number> = { CRITICAL:0, HIGH:1, MEDIUM:2, LOW:3, INFO:4 }
const filterSevs = ['All','CRITICAL','HIGH','MEDIUM','LOW','INFO']

export default function Findings() {
  const [selected, setSelected] = useState<any>(null)
  const [sevFilter, setSevFilter] = useState('All')

  const { data: findings = MOCK_FINDINGS } = useQuery({
    queryKey: ['findings'], queryFn: () => findingApi.list(), retry: false,
    placeholderData: MOCK_FINDINGS,
  })

  const filtered = (findings as any[])
    .filter(f => sevFilter === 'All' || f.severity === sevFilter)
    .sort((a,b) => (sevOrder[a.severity]??9) - (sevOrder[b.severity]??9))

  const stats = filterSevs.slice(1).map(s => ({
    sev: s,
    count: (findings as any[]).filter((f:any)=>f.severity===s).length,
  }))

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title gradient-text-red">🔎 Vulnerability Findings</h1>
          <p className="page-subtitle">AI-correlated security findings from all scan engines</p>
        </div>
        <button className="btn btn-primary">Export Report</button>
      </div>

      {/* Stats */}
      <div className="flex gap-3 mb-6">
        {stats.map(s => (
          <div key={s.sev}
            className={`stat-card`}
            style={{ flex:1, cursor:'pointer', '--card-accent': `var(--color-${s.sev.toLowerCase()})` } as any}
            onClick={() => setSevFilter(s.sev === sevFilter ? 'All' : s.sev)}>
            <div className="stat-value">{s.count}</div>
            <div className="stat-label">{s.sev}</div>
          </div>
        ))}
      </div>

      <div className={`grid-2`} style={{ alignItems: 'start' }}>
        {/* Table */}
        <div className="card" style={{ gridColumn: selected ? '1' : '1 / -1' }}>
          <div className="card-header">
            <span className="card-title">Findings ({filtered.length})</span>
            <div className="flex gap-2">
              {filterSevs.map(s => (
                <button key={s} className={`btn btn-sm ${sevFilter===s ? 'btn-primary' : 'btn-ghost'}`}
                  onClick={() => setSevFilter(s)}>{s}</button>
              ))}
            </div>
          </div>
          <table className="data-table">
            <thead>
              <tr>
                <th>Severity</th><th>Finding</th><th>Asset</th><th>CVE</th><th>CVSS</th><th>Status</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((f:any) => (
                <tr key={f.id} onClick={() => setSelected(f)} style={{ cursor:'pointer' }}>
                  <td><span className={`badge badge-${f.severity.toLowerCase()}`}>{f.severity}</span></td>
                  <td style={{ maxWidth: 300 }}>
                    <div style={{ fontWeight:600, fontSize:'0.875rem' }} className="truncate">{f.title}</div>
                    <div style={{ fontSize:'0.7rem', color:'var(--color-text-muted)' }}>via {f.plugin}</div>
                  </td>
                  <td className="mono">{f.asset}</td>
                  <td>
                    {f.cve_ids?.map((c:string) => (
                      <span key={c} style={{ fontSize:'0.7rem', color:'var(--color-red)', fontFamily:'var(--font-mono)' }}>{c}</span>
                    ))}
                  </td>
                  <td style={{ fontWeight:700, color: f.cvss_score>=9?'var(--color-critical)':f.cvss_score>=7?'var(--color-high)':'var(--color-medium)' }}>
                    {f.cvss_score}
                  </td>
                  <td>
                    {f.is_verified
                      ? <span className="badge badge-safe">Verified</span>
                      : <span className="badge badge-info">Unverified</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Detail panel */}
        {selected && (
          <div className="card animate-fade-in">
            <div className="card-header">
              <span className="card-title">Finding Detail</span>
              <button className="btn btn-sm btn-ghost" onClick={() => setSelected(null)}>✕</button>
            </div>
            <div>
              <span className={`badge badge-${selected.severity.toLowerCase()}`}>{selected.severity}</span>
              {selected.cvss_score && (
                <span style={{ marginLeft:8, fontSize:'0.75rem', color:'var(--color-text-muted)' }}>CVSS {selected.cvss_score}</span>
              )}
              <h3 style={{ marginTop:'var(--space-3)', fontSize:'1rem', fontWeight:700, lineHeight:1.4 }}>{selected.title}</h3>

              {selected.cve_ids?.length > 0 && (
                <div style={{ marginTop:'var(--space-3)' }}>
                  <div className="form-label" style={{ marginBottom:6 }}>CVEs</div>
                  {selected.cve_ids.map((c:string) => (
                    <span key={c} style={{ marginRight:6 }} className="badge badge-critical">{c}</span>
                  ))}
                </div>
              )}

              {selected.mitre_techniques?.length > 0 && (
                <div style={{ marginTop:'var(--space-3)' }}>
                  <div className="form-label" style={{ marginBottom:6 }}>MITRE ATT&CK</div>
                  {selected.mitre_techniques.map((t:string) => (
                    <span key={t} className="mitre-chip" style={{ marginRight:6 }}>{t}</span>
                  ))}
                </div>
              )}

              <div style={{ marginTop:'var(--space-4)', padding:'var(--space-4)', background:'rgba(0,230,118,0.05)', border:'1px solid rgba(0,230,118,0.15)', borderRadius:'var(--radius-md)' }}>
                <div className="form-label" style={{ marginBottom:6, color:'var(--color-safe)' }}>✅ Remediation</div>
                <p style={{ fontSize:'0.875rem', lineHeight:1.6 }}>{selected.remediation}</p>
              </div>

              <div style={{ marginTop:'var(--space-4)', display:'flex', gap:'var(--space-2)' }}>
                <button className="btn btn-primary btn-sm">🧠 AI Analysis</button>
                <button className="btn btn-ghost btn-sm">🟣 Purple Validate</button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
