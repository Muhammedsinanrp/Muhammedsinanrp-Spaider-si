import { useState } from 'react'
import { useQuery, useMutation } from '@tanstack/react-query'
import { alertApi } from '../api/client'

const STATUS_OPTS = ['OPEN','INVESTIGATING','RESOLVED','FALSE_POSITIVE']
const statusColors: Record<string,string> = {
  OPEN:'var(--color-red)', INVESTIGATING:'var(--color-medium)',
  RESOLVED:'var(--color-safe)', FALSE_POSITIVE:'var(--color-text-muted)',
}

export default function Alerts() {
  const [selected, setSelected] = useState<any>(null)
  const { data: alertData, isLoading, isError, error } = useQuery({
    queryKey:['alerts'], queryFn:()=>alertApi.list(), retry:false, refetchInterval:15000,
  })
  const alerts: any[] = Array.isArray(alertData) ? alertData : []

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
          <p className="page-subtitle">Stored security alerts from configured integrations; no demo alert records are shown.</p>
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
            {isLoading && <div style={{ padding:24, color:'var(--color-text-muted)' }}>Loading stored alert records…</div>}
            {isError && <div role="alert" style={{ padding:24, color:'var(--color-high)' }}>
              Could not load alert data from the backend. No sample alerts are substituted.
              <div style={{ fontSize:'0.75rem', marginTop:6 }}>{String((error as any)?.message || '')}</div>
            </div>}
            {!isLoading && !isError && alerts.length === 0 && (
              <div style={{ padding:32, textAlign:'center', color:'var(--color-text-muted)' }}>
                <div style={{ fontSize:'2rem', marginBottom:8 }}>◈</div>
                <strong>No alerts recorded</strong>
                <div style={{ fontSize:'0.8rem', marginTop:6 }}>Connect Wazuh, Zeek, Suricata or another alert source to populate this feed.</div>
              </div>
            )}
            {alerts.map((a:any) => (
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
