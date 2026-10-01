import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { assetApi } from '../api/client'

const MOCK_ASSETS = [
  { id: '1', name: 'web01.corp.local', value: '192.168.1.10', asset_type: 'HOST', os: 'Ubuntu 22.04', criticality: 'HIGH', tags: ['web','prod'], services: [{port:80,name:'http'},{port:443,name:'https'},{port:22,name:'ssh'}], is_active: true },
  { id: '2', name: 'db01.corp.local',  value: '192.168.1.20', asset_type: 'HOST', os: 'Debian 11', criticality: 'CRITICAL', tags: ['db','prod'], services: [{port:5432,name:'postgresql'},{port:22,name:'ssh'}], is_active: true },
  { id: '3', name: 'vpn01.corp.local', value: '192.168.1.5',  asset_type: 'HOST', os: 'CentOS 7',  criticality: 'HIGH', tags: ['vpn'], services: [{port:1194,name:'openvpn'},{port:22,name:'ssh'}], is_active: true },
  { id: '4', name: 'pc01.corp.local',  value: '192.168.1.30', asset_type: 'HOST', os: 'Windows 10', criticality: 'MEDIUM', tags: ['endpoint'], services: [{port:445,name:'smb'},{port:3389,name:'rdp'}], is_active: true },
  { id: '5', name: 'api.corp.local',   value: '192.168.1.11', asset_type: 'HOST', os: 'Alpine Linux', criticality: 'HIGH', tags: ['api','prod'], services: [{port:8080,name:'http'},{port:22,name:'ssh'}], is_active: true },
]

const critColor: Record<string, string> = {
  CRITICAL: 'var(--color-critical)', HIGH: 'var(--color-high)',
  MEDIUM: 'var(--color-medium)', LOW: 'var(--color-low)',
}

export default function Assets() {
  const [search, setSearch] = useState('')
  const { data: assets = MOCK_ASSETS } = useQuery({
    queryKey: ['assets', search], queryFn: () => assetApi.list({ search }), retry: false,
    placeholderData: MOCK_ASSETS,
  })

  const filtered = (assets as any[]).filter(a =>
    !search || a.value.includes(search) || a.name.toLowerCase().includes(search.toLowerCase())
  )

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title gradient-text-cyan">📡 Asset Inventory</h1>
          <p className="page-subtitle">Discovered hosts, services, and network topology</p>
        </div>
        <div className="flex gap-2">
          <button className="btn btn-ghost">Import Nmap XML</button>
          <button className="btn btn-primary">+ Add Asset</button>
        </div>
      </div>

      <div className="stats-grid mb-6" style={{ gridTemplateColumns: 'repeat(4, 1fr)' }}>
        {[
          { label: 'Total Assets', value: filtered.length, icon: '📡' },
          { label: 'Critical Assets', value: filtered.filter((a:any)=>a.criticality==='CRITICAL').length, icon: '🚨' },
          { label: 'Open Services', value: filtered.reduce((s:number,a:any)=>s+(a.services?.length||0),0), icon: '🔌' },
          { label: 'Active Hosts', value: filtered.filter((a:any)=>a.is_active).length, icon: '✅' },
        ].map(s => (
          <div key={s.label} className="stat-card">
            <div className="stat-icon">{s.icon}</div>
            <div className="stat-value">{s.value}</div>
            <div className="stat-label">{s.label}</div>
          </div>
        ))}
      </div>

      <div className="card">
        <div className="card-header">
          <span className="card-title">Asset Registry</span>
          <input className="input" style={{ width: 260 }} placeholder="Search by IP or hostname..." value={search} onChange={e => setSearch(e.target.value)} />
        </div>
        <table className="data-table">
          <thead>
            <tr>
              <th>Host / IP</th>
              <th>OS</th>
              <th>Services</th>
              <th>Criticality</th>
              <th>Tags</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((a: any) => (
              <tr key={a.id}>
                <td>
                  <div style={{ fontWeight: 600, fontSize: '0.875rem' }}>{a.name}</div>
                  <div className="mono" style={{ fontSize: '0.75rem' }}>{a.value}</div>
                </td>
                <td style={{ color: 'var(--color-text-secondary)', fontSize: '0.8rem' }}>{a.os}</td>
                <td>
                  <div className="flex gap-1" style={{ flexWrap: 'wrap' }}>
                    {a.services?.slice(0, 4).map((s: any) => (
                      <span key={s.port} className="target-tag" style={{ fontSize: '0.65rem' }}>{s.port}/{s.name}</span>
                    ))}
                    {a.services?.length > 4 && <span style={{ fontSize: '0.7rem', color: 'var(--color-text-muted)' }}>+{a.services.length - 4}</span>}
                  </div>
                </td>
                <td>
                  <span style={{ color: critColor[a.criticality], fontWeight: 700, fontSize: '0.75rem' }}>
                    ● {a.criticality}
                  </span>
                </td>
                <td>
                  <div className="flex gap-1">
                    {a.tags?.map((t: string) => (
                      <span key={t} style={{ background: 'rgba(255,255,255,0.06)', borderRadius: 'var(--radius-sm)', padding: '1px 6px', fontSize: '0.65rem', color: 'var(--color-text-muted)' }}>{t}</span>
                    ))}
                  </div>
                </td>
                <td>
                  <span className="flex items-center gap-2">
                    <span className="status-dot running" />
                    <span style={{ fontSize: '0.75rem', color: 'var(--color-safe)' }}>Active</span>
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
