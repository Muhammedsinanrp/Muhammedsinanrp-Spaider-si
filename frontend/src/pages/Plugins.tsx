import { useQuery } from '@tanstack/react-query'
import { pluginApi } from '../api/client'

const CATEGORY_COLORS: Record<string,string> = {
  'Network Discovery':'var(--color-cyan)', 'Web/API Security':'var(--color-blue)',
  'Network Detection':'var(--color-purple)', 'IDS/IPS':'var(--color-red)',
  'SIEM/EDR':'var(--color-high)', 'Malware Detection':'var(--color-medium)',
  'Web Proxy':'var(--color-safe)', 'Endpoint Audit':'#38bdf8',
  'Governance & Compliance':'#a855f7', 'Defensive Hardening':'#10b981',
  'OSINT':'#e11d48', 'Threat Intel':'#3b82f6',
  'Wireless Security':'#f59e0b', 'Global Intel':'#06b6d4',
}

export default function Plugins() {
  const { data: pluginData, isLoading, isError, error } = useQuery({
    queryKey: ['plugins'],
    queryFn: () => pluginApi.list(),
    retry: false,
    refetchInterval: 30000,
  })
  const plugins: any[] = Array.isArray(pluginData) ? pluginData : []
  const categories = [...new Set(plugins.map((p: any) => p.category).filter(Boolean))]
  const readyCount = plugins.filter((p: any) => p.status === 'ready' || p.enabled).length
  const configCount = plugins.filter((p: any) => p.status === 'configuration_required').length
  const externalCount = plugins.filter((p: any) => p.status === 'external').length
  const unavailableCount = plugins.filter((p: any) => p.status === 'not_installed').length

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title gradient-text-cyan">🔌 Plugin Marketplace</h1>
          <p className="page-subtitle">Tool catalogue with runtime dependency checks from the backend environment.</p>
        </div>
        <div className="flex gap-2">
          <span className="badge badge-safe">{readyCount} ready</span>
          <span className="badge badge-info">{configCount + unavailableCount} need setup</span>
        </div>
      </div>

      {/* Stats */}
      <div className="stats-grid mb-6">
        {[
          { label:'Active Plugins', value:(plugins as any[]).filter((p:any)=>p.enabled).length, icon:'✅', color:'var(--color-safe)' },
          { label:'Categories', value:categories.length, icon:'📁', color:'var(--color-cyan)' },
          { label:'Available', value:(plugins as any[]).filter((p:any)=>!p.enabled).length, icon:'⚙️', color:'var(--color-blue)' },
          { label:'Total', value:plugins.length, icon:'🔌', color:'var(--color-purple)' },
        ].map(s=>(
          <div key={s.label} className="stat-card" style={{ '--card-accent':s.color } as any}>
            <div className="stat-icon">{s.icon}</div>
            <div className="stat-value">{s.value}</div>
            <div className="stat-label">{s.label}</div>
          </div>
        ))}
      </div>

      <div className="card mb-6" style={{ background:'linear-gradient(135deg, rgba(0,229,255,0.04), rgba(168,85,247,0.04))', border:'1px solid var(--color-border-accent)' }}>
        <div className="card-header"><span className="card-title">Runtime Integration Status</span></div>
        <div className="grid-3" style={{ gap:'var(--space-4)' }}>
          {[
            { label:'Ready in this environment', value:readyCount, color:'var(--color-safe)' },
            { label:'Configuration required', value:configCount, color:'var(--color-medium)' },
            { label:'External / not executed here', value:externalCount, color:'var(--color-purple)' },
          ].map(item => (
            <div key={item.label} style={{ padding:'var(--space-3)', background:'rgba(255,255,255,0.03)', borderRadius:'var(--radius-md)', border:'1px solid var(--color-border)' }}>
              <div style={{ fontSize:'1.4rem', fontWeight:800, color:item.color }}>{item.value}</div>
              <div style={{ fontSize:'0.75rem', color:'var(--color-text-muted)' }}>{item.label}</div>
            </div>
          ))}
        </div>
        <div style={{ marginTop:'var(--space-4)', fontSize:'0.8rem', color:'var(--color-text-muted)' }}>
          The API checks installed executables, Python dependencies and environment configuration. External tools and setup guidance are not reported as executed scans.
        </div>
      </div>

      {isLoading && <div className="card mb-6" style={{ color:'var(--color-text-muted)' }}>Checking installed tools and integrations…</div>}
      {isError && <div className="card mb-6" role="alert" style={{ color:'var(--color-high)' }}>
        Could not load plugin status from the backend. Start the API and refresh this page.
        <div style={{ fontSize:'0.75rem', marginTop:6 }}>{String((error as any)?.message || '')}</div>
      </div>}
      {!isLoading && !isError && plugins.length === 0 && (
        <div className="card mb-6" style={{ textAlign:'center', padding:'var(--space-8)', color:'var(--color-text-muted)' }}>
          The backend did not report any registered plugins.
        </div>
      )}

      {/* Plugin cards by category */}
      {categories.map(cat => (
        <div key={cat} style={{ marginBottom:'var(--space-6)' }}>
          <div style={{ display:'flex', alignItems:'center', gap:'var(--space-3)', marginBottom:'var(--space-3)' }}>
            <div style={{ height:2, width:24, background:CATEGORY_COLORS[cat]||'var(--color-cyan)', borderRadius:2 }} />
            <span style={{ fontSize:'0.75rem', fontWeight:700, color:CATEGORY_COLORS[cat]||'var(--color-cyan)', textTransform:'uppercase', letterSpacing:'0.1em' }}>{cat}</span>
          </div>
          <div className="grid-3">
            {plugins.filter((p:any)=>p.category===cat).map((p:any)=>(
              <div key={p.name} className="plugin-card">
                <div className="plugin-icon" style={{ fontSize:'1.5rem' }}>{p.icon}</div>
                <div className="plugin-info">
                  <div className="plugin-name">{p.name}</div>
                  <div className="plugin-version">{p.version || 'version not detected'}</div>
                  <div style={{ fontSize:'0.7rem', color:'var(--color-text-muted)', marginTop:4, lineHeight:1.4 }}>{p.description}</div>
                </div>
                <div style={{ display:'flex', flexDirection:'column', gap:'var(--space-2)', alignItems:'flex-end' }}>
                  <span className={`plugin-status ${p.enabled ? 'enabled' : 'disabled'}`}>
                    {p.status === 'external' ? 'External' :
                     p.status === 'configuration_required' ? 'Needs configuration' :
                     p.enabled ? 'Ready' : 'Unavailable'}
                  </span>
                  <span title={p.reason || ''} style={{ fontSize:'0.65rem', color:'var(--color-text-muted)', maxWidth:160, textAlign:'right' }}>
                    {p.reason || ''}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      ))}
    </div>
  )
}
