import { useState, useEffect, useRef } from 'react'
import SpiderWebCanvas from '../components/SpiderWebCanvas'

const NODE_TYPES = [
  { type: 'DOMAIN',    color: '#00e5ff', count: 1,  desc: 'Root domain target' },
  { type: 'SUBDOMAIN', color: '#00ff88', count: 62, desc: 'Enumerated subdomains' },
  { type: 'API',       color: '#a855f7', count: 43, desc: 'API endpoints & services' },
  { type: 'ENDPOINT',  color: '#38bdf8', count: 234,desc: 'Discoverable endpoints' },
  { type: 'SERVICE',   color: '#6366f1', count: 18, desc: 'Running network services' },
  { type: 'VULN',      color: '#ff3b5c', count: 14, desc: 'Confirmed vulnerabilities' },
]

const RECENT_DISCOVERIES = [
  { time: '18:54', node: 'admin.example.com', type: 'SUBDOMAIN', relation: 'Found via subfinder' },
  { time: '18:52', node: '/api/v2/internal', type: 'ENDPOINT',  relation: 'JS bundle analysis' },
  { time: '18:49', node: 'SSH:22 (192.168.1.10)', type: 'SERVICE', relation: 'Nmap scan' },
  { time: '18:47', node: '/graphql', type: 'API', relation: 'Directory brute-force' },
  { time: '18:44', node: 'SSRF on /api/fetch', type: 'VULN', relation: 'AI Validation' },
  { time: '18:41', node: 'dev.example.com', type: 'SUBDOMAIN', relation: 'DNS brute-force' },
]

const TOPOLOGY = [
  { from: 'example.com', to: 'api.example.com', rel: 'DOMAIN → SUBDOMAIN' },
  { from: 'api.example.com', to: '/api/v1', rel: 'SUBDOMAIN → API' },
  { from: '/api/v1', to: '/api/v1/fetch', rel: 'API → ENDPOINT' },
  { from: '/api/v1/fetch', to: 'SSRF', rel: 'ENDPOINT → VULNERABILITY' },
  { from: 'example.com', to: 'HTTP:80', rel: 'DOMAIN → SERVICE' },
  { from: 'example.com', to: 'HTTPS:443', rel: 'DOMAIN → SERVICE' },
]

export default function NetworkMap() {
  const [nodeCount, setNodeCount] = useState(372)
  const [edgeCount, setEdgeCount] = useState(841)
  const [newNode, setNewNode] = useState<string | null>(null)

  useEffect(() => {
    const id = setInterval(() => {
      if (Math.random() > 0.6) {
        setNodeCount(n => n + 1)
        setEdgeCount(e => e + Math.floor(Math.random() * 3) + 1)
        const types = ['SUBDOMAIN', 'ENDPOINT', 'API', 'SERVICE']
        const labels = ['dev2.example.com', '/api/v3/admin', 'GraphQL Schema', 'Redis:6379', '/oauth/token']
        setNewNode(labels[Math.floor(Math.random() * labels.length)])
        setTimeout(() => setNewNode(null), 2500)
      }
    }, 4000)
    return () => clearInterval(id)
  }, [])

  return (
    <div>
      <div className="page-header" style={{ marginBottom: 'var(--space-6)' }}>
        <div>
          <h1 className="page-title gradient-text-cyan">🕸️ Attack Surface Map</h1>
          <p className="page-subtitle">3D relationship graph · Domain → Subdomain → IP → Port → Service → API → Endpoint → Vulnerability</p>
        </div>
        <div className="flex gap-2">
          <div style={{ padding: '6px 14px', background: 'rgba(0,255,136,0.08)', border: '1px solid rgba(0,255,136,0.3)',
            borderRadius: 'var(--radius-md)', fontSize: '0.75rem', color: '#00ff88', fontWeight: 700, display: 'flex', alignItems: 'center', gap: 6 }}>
            <span className="status-dot running" />
            LIVE DISCOVERY
          </div>
          <div style={{ padding: '6px 14px', background: 'rgba(255,255,255,0.04)', border: '1px solid var(--color-border)',
            borderRadius: 'var(--radius-md)', fontSize: '0.75rem', fontFamily: 'var(--font-mono)', color: 'var(--color-text-muted)' }}>
            {nodeCount} nodes · {edgeCount} edges
          </div>
        </div>
      </div>

      {/* Stats */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(6, 1fr)', gap: 10, marginBottom: 'var(--space-5)' }}>
        {NODE_TYPES.map(nt => (
          <div key={nt.type} style={{
            padding: 12, borderRadius: 8, textAlign: 'center',
            background: `${nt.color}08`, border: `1px solid ${nt.color}30`,
          }}>
            <div style={{ fontSize: '1.4rem', fontWeight: 900, color: nt.color, fontFamily: 'var(--font-mono)' }}>{nt.count}</div>
            <div style={{ fontSize: '0.62rem', fontWeight: 800, color: nt.color, letterSpacing: '0.08em' }}>{nt.type}</div>
            <div style={{ fontSize: '0.58rem', color: 'var(--color-text-muted)', marginTop: 2 }}>{nt.desc}</div>
            <div style={{ width: '100%', height: 3, background: `${nt.color}20`, borderRadius: 2, marginTop: 8, overflow: 'hidden' }}>
              <div style={{ width: `${Math.min(100, (nt.count / 234) * 100)}%`, height: '100%', background: nt.color }} />
            </div>
          </div>
        ))}
      </div>

      {/* New node discovered toast */}
      {newNode && (
        <div style={{
          position: 'fixed', top: 80, right: 24, zIndex: 1000,
          padding: '10px 16px', background: 'rgba(0,229,255,0.12)',
          border: '1px solid rgba(0,229,255,0.5)', borderRadius: 8,
          fontSize: '0.75rem', color: '#00e5ff', fontWeight: 700,
          boxShadow: '0 0 20px rgba(0,229,255,0.2)',
          animation: 'animate-fade-in 0.3s ease',
        }}>
          🔍 NEW NODE DISCOVERED<br />
          <span style={{ color: 'var(--color-text-primary)', fontFamily: 'var(--font-mono)' }}>{newNode}</span>
        </div>
      )}

      <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: 'var(--space-5)' }}>

        {/* Main 3D Map */}
        <div className="card" style={{
          border: '1px solid rgba(0,229,255,0.3)',
          background: 'linear-gradient(135deg, rgba(0,229,255,0.03), rgba(168,85,247,0.03))',
        }}>
          <div className="card-header">
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <span style={{ fontSize: '1.3rem' }}>🌐</span>
              <div>
                <span className="card-title">3D Attack Surface</span>
                <div style={{ fontSize: '0.7rem', color: 'var(--color-text-muted)' }}>
                  Hover nodes for details · Auto-rotating · Mouse to interact
                </div>
              </div>
            </div>
            <div style={{ display: 'flex', gap: 6 }}>
              {['DOMAIN', 'API', 'ENDPOINT', 'VULN'].map((t, i) => {
                const colors = ['#00e5ff', '#a855f7', '#38bdf8', '#ff3b5c']
                return (
                  <span key={t} style={{
                    fontSize: '0.6rem', padding: '2px 7px', borderRadius: 3,
                    background: `${colors[i]}12`, border: `1px solid ${colors[i]}35`,
                    color: colors[i], fontFamily: 'var(--font-mono)', fontWeight: 700,
                  }}>{t}</span>
                )
              })}
            </div>
          </div>

          <div style={{
            height: 480, background: 'rgba(0,0,0,0.6)', borderRadius: 'var(--radius-md)',
            border: '1px solid var(--color-border)', position: 'relative', overflow: 'hidden',
          }}>
            <SpiderWebCanvas interactive={true} opacity={0.95} />

            {/* HUD overlay */}
            <div style={{ position: 'absolute', top: 12, left: 12, pointerEvents: 'none' }}>
              <div style={{ fontSize: '0.65rem', color: '#00e5ff', fontFamily: 'var(--font-mono)', opacity: 0.8 }}>
                TARGET: example.com<br />
                NODES: {nodeCount} · EDGES: {edgeCount}
              </div>
            </div>

            {/* Legend */}
            <div style={{ position: 'absolute', bottom: 12, left: 12, pointerEvents: 'none' }}>
              <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
                {NODE_TYPES.map(nt => (
                  <div key={nt.type} style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                    <div style={{ width: 8, height: 8, borderRadius: '50%', background: nt.color, boxShadow: `0 0 6px ${nt.color}` }} />
                    <span style={{ fontSize: '0.6rem', color: nt.color, fontFamily: 'var(--font-mono)' }}>{nt.type}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* Right panel */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}>

          {/* Relationship topology */}
          <div className="card">
            <div className="card-header">
              <span className="card-title">🔗 Relationship Topology</span>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              {TOPOLOGY.map((t, i) => (
                <div key={i} style={{ fontSize: '0.72rem', display: 'flex', flexDirection: 'column', gap: 2 }}>
                  <div style={{ color: 'var(--color-text-muted)', fontFamily: 'var(--font-mono)', fontSize: '0.6rem', letterSpacing: '0.05em' }}>{t.rel}</div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '4px 8px',
                    background: 'rgba(255,255,255,0.03)', borderRadius: 4 }}>
                    <span style={{ color: 'var(--color-cyan)' }}>{t.from}</span>
                    <span style={{ color: 'var(--color-text-muted)' }}>→</span>
                    <span style={{ color: t.to.includes('VULN') || t.to.includes('SSRF') ? '#ff3b5c' : 'var(--color-text-primary)' }}>{t.to}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Recent discoveries */}
          <div className="card" style={{ flex: 1 }}>
            <div className="card-header">
              <span className="card-title">📡 Recent Discoveries</span>
              <span style={{ fontSize: '0.65rem', color: '#00ff88', fontFamily: 'var(--font-mono)' }}>● LIVE</span>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6, maxHeight: 280, overflowY: 'auto' }}>
              {RECENT_DISCOVERIES.map((d, i) => {
                const typeColors: Record<string, string> = { SUBDOMAIN: '#00ff88', ENDPOINT: '#38bdf8', SERVICE: '#6366f1', API: '#a855f7', VULN: '#ff3b5c' }
                const c = typeColors[d.type] || '#aaa'
                return (
                  <div key={i} style={{
                    display: 'flex', gap: 8, padding: '6px 8px',
                    background: d.type === 'VULN' ? 'rgba(255,59,92,0.06)' : 'rgba(255,255,255,0.02)',
                    border: `1px solid ${d.type === 'VULN' ? 'rgba(255,59,92,0.2)' : 'rgba(255,255,255,0.05)'}`,
                    borderRadius: 5,
                  }}>
                    <span style={{ fontSize: '0.6rem', color: 'var(--color-text-muted)', fontFamily: 'var(--font-mono)', whiteSpace: 'nowrap' }}>{d.time}</span>
                    <div style={{ flex: 1 }}>
                      <div style={{ fontSize: '0.72rem', color: 'var(--color-text-primary)', marginBottom: 2 }}>{d.node}</div>
                      <div style={{ display: 'flex', gap: 4, alignItems: 'center' }}>
                        <span style={{ fontSize: '0.58rem', padding: '1px 5px', background: `${c}15`, border: `1px solid ${c}35`, borderRadius: 3, color: c, fontWeight: 800 }}>{d.type}</span>
                        <span style={{ fontSize: '0.62rem', color: 'var(--color-text-muted)' }}>{d.relation}</span>
                      </div>
                    </div>
                  </div>
                )
              })}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
