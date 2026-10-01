import { useQuery } from '@tanstack/react-query'
import { pluginApi } from '../api/client'

const MOCK_PLUGINS = [
  { name:'nmap', version:'7.94', category:'Network Discovery', enabled:true, icon:'📡', description:'Network scanner — port scanning, OS detection, service fingerprinting' },
  { name:'nuclei', version:'3.2.4', category:'Web/API Security', enabled:true, icon:'⚡', description:'Template-based vulnerability scanner with 8000+ community templates' },
  { name:'zeek', version:'6.0.0', category:'Network Detection', enabled:true, icon:'🕸️', description:'Network analysis framework — structured logs for DNS, HTTP, TLS, conn' },
  { name:'suricata', version:'7.0.3', category:'IDS/IPS', enabled:true, icon:'🛡️', description:'High-performance network threat detection engine with rule support' },
  { name:'wazuh', version:'4.8.0', category:'SIEM/EDR', enabled:false, icon:'🔍', description:'Open-source security platform — SIEM, XDR, compliance' },
  { name:'yara', version:'4.5.1', category:'Malware Detection', enabled:true, icon:'🦠', description:'Pattern matching for malware researchers — rules engine' },
  { name:'burp', version:'2024.5', category:'Web Proxy', enabled:false, icon:'🔥', description:'Industry-standard web security testing tool — Montoya API integration' },
  { name:'caido', version:'0.42', category:'Web Proxy', enabled:false, icon:'🌊', description:'Modern web proxy with Automate fuzzing and AI-powered analysis' },
]

const CATEGORY_COLORS: Record<string,string> = {
  'Network Discovery':'var(--color-cyan)', 'Web/API Security':'var(--color-blue)',
  'Network Detection':'var(--color-purple)', 'IDS/IPS':'var(--color-red)',
  'SIEM/EDR':'var(--color-high)', 'Malware Detection':'var(--color-medium)',
  'Web Proxy':'var(--color-safe)',
}

export default function Plugins() {
  const { data: plugins = MOCK_PLUGINS } = useQuery({
    queryKey:['plugins'], queryFn:()=>pluginApi.list(), retry:false, placeholderData:MOCK_PLUGINS,
  })

  const categories = [...new Set((plugins as any[]).map((p:any)=>p.category))]

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title gradient-text-cyan">🔌 Plugin Marketplace</h1>
          <p className="page-subtitle">Security engine integrations — each plugin exposes discover · scan · analyze · normalize · report</p>
        </div>
        <div className="flex gap-2">
          <span className="badge badge-safe">{(plugins as any[]).filter((p:any)=>p.enabled).length} active</span>
          <span className="badge badge-info">{(plugins as any[]).filter((p:any)=>!p.enabled).length} available</span>
        </div>
      </div>

      {/* Stats */}
      <div className="stats-grid mb-6">
        {[
          { label:'Active Plugins', value:(plugins as any[]).filter((p:any)=>p.enabled).length, icon:'✅', color:'var(--color-safe)' },
          { label:'Categories', value:categories.length, icon:'📁', color:'var(--color-cyan)' },
          { label:'Available', value:(plugins as any[]).filter((p:any)=>!p.enabled).length, icon:'⚙️', color:'var(--color-blue)' },
          { label:'Total', value:(plugins as any[]).length, icon:'🔌', color:'var(--color-purple)' },
        ].map(s=>(
          <div key={s.label} className="stat-card" style={{ '--card-accent':s.color } as any}>
            <div className="stat-icon">{s.icon}</div>
            <div className="stat-value">{s.value}</div>
            <div className="stat-label">{s.label}</div>
          </div>
        ))}
      </div>

      {/* Plugin SDK info */}
      <div className="card mb-6" style={{ background:'linear-gradient(135deg, rgba(0,229,255,0.05), rgba(168,85,247,0.05))', border:'1px solid var(--color-border-accent)' }}>
        <div className="card-header"><span className="card-title">Plugin SDK</span></div>
        <div className="grid-3" style={{ gap:'var(--space-4)' }}>
          {['discover()','scan()','analyze()','collect()','normalize()','report()'].map(fn=>(
            <div key={fn} style={{ padding:'var(--space-3)', background:'rgba(255,255,255,0.04)', borderRadius:'var(--radius-md)', border:'1px solid var(--color-border)' }}>
              <code style={{ fontFamily:'var(--font-mono)', color:'var(--color-cyan)', fontSize:'0.875rem' }}>{fn}</code>
            </div>
          ))}
        </div>
        <div style={{ marginTop:'var(--space-4)', fontSize:'0.875rem', color:'var(--color-text-muted)' }}>
          Every plugin implements these 6 standard methods. Add new security tools without modifying the core platform.
        </div>
      </div>

      {/* Plugin cards by category */}
      {categories.map(cat => (
        <div key={cat} style={{ marginBottom:'var(--space-6)' }}>
          <div style={{ display:'flex', alignItems:'center', gap:'var(--space-3)', marginBottom:'var(--space-3)' }}>
            <div style={{ height:2, width:24, background:CATEGORY_COLORS[cat]||'var(--color-cyan)', borderRadius:2 }} />
            <span style={{ fontSize:'0.75rem', fontWeight:700, color:CATEGORY_COLORS[cat]||'var(--color-cyan)', textTransform:'uppercase', letterSpacing:'0.1em' }}>{cat}</span>
          </div>
          <div className="grid-3">
            {(plugins as any[]).filter((p:any)=>p.category===cat).map((p:any)=>(
              <div key={p.name} className="plugin-card">
                <div className="plugin-icon" style={{ fontSize:'1.5rem' }}>{p.icon}</div>
                <div className="plugin-info">
                  <div className="plugin-name">{p.name}</div>
                  <div className="plugin-version">v{p.version}</div>
                  <div style={{ fontSize:'0.7rem', color:'var(--color-text-muted)', marginTop:4, lineHeight:1.4 }}>{p.description}</div>
                </div>
                <div style={{ display:'flex', flexDirection:'column', gap:'var(--space-2)', alignItems:'flex-end' }}>
                  <span className={`plugin-status ${p.enabled?'enabled':'disabled'}`}>
                    {p.enabled?'Enabled':'Disabled'}
                  </span>
                  <button className="btn btn-sm btn-ghost">{p.enabled?'Configure':'Enable'}</button>
                </div>
              </div>
            ))}
          </div>
        </div>
      ))}
    </div>
  )
}
