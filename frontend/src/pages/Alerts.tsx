import { useState } from 'react'
import { useQuery, useMutation } from '@tanstack/react-query'
import { alertApi } from '../api/client'

const MOCK_ALERTS = [
  { id:'1', title:'Lateral movement via SMB — T1021.002', severity:'CRITICAL', status:'OPEN', source:'Zeek', source_ip:'192.168.1.30', destination_ip:'192.168.1.20', event_type:'Lateral Movement', mitre_techniques:['T1021.002'], is_purple_validated:false, detection_gap:false, created_at:'2026-10-01T05:12:00Z' },
  { id:'2', title:'Repeated SSH brute-force from 45.33.32.156', severity:'HIGH', status:'INVESTIGATING', source:'Wazuh', source_ip:'45.33.32.156', destination_ip:'192.168.1.10', event_type:'Credential Access', mitre_techniques:['T1110'], is_purple_validated:true, detection_gap:false, created_at:'2026-10-01T04:44:00Z' },
  { id:'3', title:'Outbound beacon to known C2 — 104.21.91.14', severity:'CRITICAL', status:'OPEN', source:'Suricata', source_ip:'192.168.1.30', destination_ip:'104.21.91.14', event_type:'Command & Control', mitre_techniques:['T1071.001'], is_purple_validated:false, detection_gap:true, created_at:'2026-10-01T03:30:00Z' },
  { id:'4', title:'Suspicious DNS exfiltration pattern', severity:'MEDIUM', status:'OPEN', source:'Zeek', source_ip:'192.168.1.20', destination_ip:'8.8.8.8', event_type:'Exfiltration', mitre_techniques:['T1048'], is_purple_validated:false, detection_gap:false, created_at:'2026-10-01T02:15:00Z' },
  { id:'5', title:'New admin user created outside business hours', severity:'HIGH', status:'RESOLVED', source:'Wazuh', source_ip:'192.168.1.30', destination_ip:'192.168.1.1', event_type:'Persistence', mitre_techniques:['T1136'], is_purple_validated:true, detection_gap:false, created_at:'2026-09-30T23:00:00Z' },
]

const STATUS_OPTS = ['OPEN','INVESTIGATING','RESOLVED','FALSE_POSITIVE']
const statusColors: Record<string,string> = {
  OPEN:'var(--color-red)', INVESTIGATING:'var(--color-medium)',
  RESOLVED:'var(--color-safe)', FALSE_POSITIVE:'var(--color-text-muted)',
}

export default function Alerts() {
  const [selected, setSelected] = useState<any>(null)
  const { data: alerts = MOCK_ALERTS } = useQuery({
    queryKey:['alerts'], queryFn:()=>alertApi.list(), retry:false, placeholderData:MOCK_ALERTS,
  })

  const timeAgo = (iso: string) => {
    const diff = Math.floor((Date.now()-new Date(iso).getTime())/1000)
    if (diff<60) return `${diff}s ago`
    if (diff<3600) return `${Math.floor(diff/60)}m ago`
    return `${Math.floor(diff/3600)}h ago`
  }

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title gradient-text-cyan">🛡️ Security Alerts</h1>
          <p className="page-subtitle">SIEM-correlated detections from Wazuh, Zeek & Suricata</p>
        </div>
        <div className="flex gap-2">
          <span className="badge badge-critical">● {(alerts as any[]).filter((a:any)=>a.status==='OPEN').length} Open</span>
          <span className="badge badge-medium">⚠ {(alerts as any[]).filter((a:any)=>a.detection_gap).length} Gaps</span>
        </div>
      </div>

      <div className={selected ? 'grid-2' : ''} style={{ alignItems:'start' }}>
        <div className="card">
          <div className="card-header">
            <span className="card-title">Alert Feed ({(alerts as any[]).length})</span>
          </div>
          <div style={{ display:'flex', flexDirection:'column', gap:'var(--space-2)' }}>
            {(alerts as any[]).map((a:any) => (
              <div key={a.id}
                onClick={() => setSelected(selected?.id===a.id ? null : a)}
                style={{
                  padding:'var(--space-4)', borderRadius:'var(--radius-md)',
                  border:`1px solid ${selected?.id===a.id?'var(--color-cyan)':'var(--color-border)'}`,
                  background: selected?.id===a.id ? 'var(--color-cyan-dim)' : 'var(--color-bg-elevated)',
                  cursor:'pointer', transition:'all 0.15s',
                }}>
                <div className="flex items-center justify-between" style={{ marginBottom:'var(--space-2)' }}>
                  <div className="flex items-center gap-2">
                    <span className={`badge badge-${a.severity.toLowerCase()}`}>{a.severity}</span>
                    <span style={{ fontSize:'0.7rem', color:'var(--color-text-muted)', fontFamily:'var(--font-mono)' }}>{a.source}</span>
                    {a.detection_gap && <span className="badge badge-medium">⚠ Gap</span>}
                    {a.is_purple_validated && <span className="badge badge-info">🟣 Validated</span>}
                  </div>
                  <span style={{ fontSize:'0.7rem', color:'var(--color-text-muted)' }}>{timeAgo(a.created_at)}</span>
                </div>
                <div style={{ fontWeight:600, fontSize:'0.875rem', marginBottom:'var(--space-1)' }}>{a.title}</div>
                <div className="flex items-center gap-4" style={{ fontSize:'0.75rem', color:'var(--color-text-muted)' }}>
                  {a.source_ip && <span>SRC: <span className="font-mono" style={{ color:'var(--color-text-secondary)' }}>{a.source_ip}</span></span>}
                  {a.destination_ip && <span>DST: <span className="font-mono" style={{ color:'var(--color-text-secondary)' }}>{a.destination_ip}</span></span>}
                  <span style={{ marginLeft:'auto', color: statusColors[a.status] }}>● {a.status}</span>
                </div>
                {a.mitre_techniques?.length > 0 && (
                  <div className="flex gap-1" style={{ marginTop:'var(--space-2)' }}>
                    {a.mitre_techniques.map((t:string) => <span key={t} className="mitre-chip">{t}</span>)}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>

        {/* Detail panel */}
        {selected && (
          <div className="card animate-fade-in" style={{ position:'sticky', top:'var(--topbar-height)' }}>
            <div className="card-header">
              <span className="card-title">🧠 AI SOC Analyst</span>
              <button className="btn btn-sm btn-ghost" onClick={() => setSelected(null)}>✕</button>
            </div>
            <div style={{ padding:'var(--space-4)', background:'rgba(0,229,255,0.05)', border:'1px solid var(--color-border-accent)', borderRadius:'var(--radius-md)', marginBottom:'var(--space-4)' }}>
              <div style={{ fontSize:'0.7rem', fontWeight:700, letterSpacing:'0.1em', color:'var(--color-cyan)', marginBottom:'var(--space-2)', textTransform:'uppercase' }}>Incident Summary</div>
              <div style={{ fontSize:'0.875rem', lineHeight:1.6 }}>{selected.title}</div>
            </div>
            <div style={{ marginBottom:'var(--space-4)' }}>
              <div className="form-label" style={{ marginBottom:8 }}>Evidence</div>
              {['Source IP detected scanning internal hosts','Successful lateral movement to DB server','Suspicious process spawned: cmd.exe → powershell.exe'].map((e,i) => (
                <div key={i} style={{ display:'flex', gap:'var(--space-2)', marginBottom:'var(--space-2)', fontSize:'0.875rem' }}>
                  <span style={{ color:'var(--color-cyan)' }}>•</span><span>{e}</span>
                </div>
              ))}
            </div>
            {selected.mitre_techniques?.length > 0 && (
              <div style={{ marginBottom:'var(--space-4)' }}>
                <div className="form-label" style={{ marginBottom:8 }}>MITRE ATT&CK Mapping</div>
                <div className="flex gap-2" style={{ flexWrap:'wrap' }}>
                  {selected.mitre_techniques.map((t:string) => <span key={t} className="mitre-chip">{t}</span>)}
                </div>
              </div>
            )}
            <div style={{ marginBottom:'var(--space-4)' }}>
              <div className="form-label" style={{ marginBottom:8 }}>Recommended Actions</div>
              {['Isolate source endpoint immediately','Review authentication logs for lateral movement','Check for persistence mechanisms','Run Purple team validation'].map((r,i) => (
                <div key={i} style={{ display:'flex', gap:'var(--space-2)', marginBottom:'var(--space-2)', fontSize:'0.875rem' }}>
                  <span style={{ color:'var(--color-safe)', fontWeight:700 }}>{i+1}.</span><span>{r}</span>
                </div>
              ))}
            </div>
            <div className="flex gap-2">
              <button className="btn btn-primary btn-sm">Investigate</button>
              <button className="btn btn-ghost btn-sm">🟣 Purple Validate</button>
              <button className="btn btn-ghost btn-sm">Mark Resolved</button>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
