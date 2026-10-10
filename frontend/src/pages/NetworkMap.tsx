import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { assetApi, findingApi, scanApi } from '../api/client'

type RawNode = {
  id: string
  label?: string
  type?: string
  ip?: string
  os?: string
  criticality?: string
  services?: Array<{ port?: number; protocol?: string; name?: string; product?: string; version?: string }>
}
type GraphNode = {
  id: string
  label: string
  type: string
  color: string
  detail: string
}
type GraphEdge = { source: string; target: string; label?: string }

const TYPE_COLORS: Record<string, string> = {
  DOMAIN: '#00e5ff',
  HOST: '#00e5ff',
  IP_RANGE: '#00e5ff',
  URL: '#00ff88',
  API_ENDPOINT: '#a855f7',
  ENDPOINT: '#38bdf8',
  SERVICE: '#6366f1',
  FINDING: '#ff3b5c',
}
const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: '#ff1744',
  HIGH: '#ff5722',
  MEDIUM: '#ff9800',
  LOW: '#ffc107',
  INFO: '#38bdf8',
}

function hostnameFromUrl(value: string): string {
  try { return new URL(value).hostname.toLowerCase() } catch { return '' }
}

function relativeTime(value?: string): string {
  if (!value) return 'Timestamp unavailable'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return 'Timestamp unavailable'
  return date.toLocaleString()
}

export default function NetworkMap() {
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const assetsQuery = useQuery({
    queryKey: ['asset-graph'],
    queryFn: () => assetApi.graph(),
    retry: false,
    refetchInterval: 15000,
  })
  const findingsQuery = useQuery({
    queryKey: ['findings-network-map'],
    queryFn: () => findingApi.list({ limit: 100 }),
    retry: false,
    refetchInterval: 15000,
  })
  const scansQuery = useQuery({
    queryKey: ['scans-network-map'],
    queryFn: () => scanApi.list({ limit: 20 }),
    retry: false,
    refetchInterval: 15000,
  })

  const graphData = assetsQuery.data || { nodes: [], edges: [] }
  const rawAssets: RawNode[] = Array.isArray(graphData.nodes) ? graphData.nodes : []
  const findings: any[] = Array.isArray(findingsQuery.data) ? findingsQuery.data : []
  const scans: any[] = Array.isArray(scansQuery.data) ? scansQuery.data : []

  const graph = useMemo(() => {
    const nodes: GraphNode[] = []
    const edges: GraphEdge[] = []
    const ids = new Set<string>()
    const addNode = (node: GraphNode) => {
      if (!ids.has(node.id)) { ids.add(node.id); nodes.push(node) }
    }
    const addEdge = (edge: GraphEdge) => {
      if (edge.source !== edge.target) edges.push(edge)
    }

    rawAssets.forEach((asset) => {
      const type = String(asset.type || 'HOST').toUpperCase()
      const label = asset.label || asset.ip || asset.id
      addNode({
        id: asset.id,
        label,
        type,
        color: TYPE_COLORS[type] || '#00e5ff',
        detail: [asset.ip, asset.os, asset.criticality ? `Criticality: ${asset.criticality}` : ''].filter(Boolean).join(' · '),
      })
      ;(asset.services || []).forEach(service => {
        if (service.port == null) return
        const serviceId = `service:${asset.id}:${service.port}:${service.name || service.protocol || 'tcp'}`
        addNode({
          id: serviceId,
          label: `${service.name || service.protocol || 'service'}:${service.port}`,
          type: 'SERVICE',
          color: TYPE_COLORS.SERVICE,
          detail: [service.product, service.version].filter(Boolean).join(' ') || 'Service record returned by the asset API',
        })
        addEdge({ source: asset.id, target: serviceId, label: 'HOST → SERVICE' })
      })
    })

    // Create endpoint/finding nodes only from evidence persisted by the scanner API.
    findings.forEach((finding) => {
      const url = String(finding.affected_url || finding.endpoint || '')
      const host = String(finding.asset_value || hostnameFromUrl(url)).toLowerCase()
      const linkedAsset = rawAssets.find(a =>
        [a.ip, a.label].some(v => String(v || '').toLowerCase() === host) ||
        (host && String(a.label || '').toLowerCase().endsWith(`.${host}`)) ||
        (host && hostnameFromUrl(String(a.ip || '')) === host)
      )
      let endpointId = ''
      if (url) {
        endpointId = `endpoint:${url}`
        addNode({
          id: endpointId,
          label: url.length > 54 ? `${url.slice(0, 51)}…` : url,
          type: 'ENDPOINT',
          color: TYPE_COLORS.ENDPOINT,
          detail: 'Endpoint stored with a scanner finding',
        })
        if (linkedAsset) addEdge({ source: linkedAsset.id, target: endpointId, label: 'ASSET → ENDPOINT' })
      }

      const findingId = `finding:${finding.id}`
      const severity = String(finding.severity || 'INFO').toUpperCase()
      addNode({
        id: findingId,
        label: String(finding.title || 'Finding').slice(0, 64),
        type: 'FINDING',
        color: SEVERITY_COLORS[severity] || SEVERITY_COLORS.INFO,
        detail: `${severity} · ${finding.plugin || finding.scanner || 'scanner'} · ${url || 'No endpoint supplied'}`,
      })
      if (endpointId) addEdge({ source: endpointId, target: findingId, label: 'ENDPOINT → FINDING' })
      else if (linkedAsset) addEdge({ source: linkedAsset.id, target: findingId, label: 'ASSET → FINDING' })
    })

    const allowed = new Set(nodes.map(n => n.id))
    const known = new Set<string>()
    const uniqueEdges = edges.filter(e => {
      if (!allowed.has(e.source) || !allowed.has(e.target)) return false
      const key = [e.source, e.target].sort().join('|') + '|' + (e.label || '')
      if (known.has(key)) return false
      known.add(key)
      return true
    })
    return { nodes, edges: uniqueEdges }
  }, [rawAssets, findings])

  const visibleNodes = graph.nodes.slice(0, 64)
  const visibleIds = new Set(visibleNodes.map(n => n.id))
  const visibleEdges = graph.edges.filter(e => visibleIds.has(e.source) && visibleIds.has(e.target))
  const width = 920
  const height = 520
  const positioned = visibleNodes.map((node, index) => {
    const angle = (Math.PI * 2 * index) / Math.max(1, visibleNodes.length)
    const ring = index % 3
    const radiusX = 120 + ring * 95
    const radiusY = 80 + ring * 54
    return { ...node, x: width / 2 + Math.cos(angle) * radiusX, y: height / 2 + Math.sin(angle) * radiusY }
  })
  const pointById = new Map(positioned.map(n => [n.id, n]))
  const selected = graph.nodes.find(n => n.id === selectedId) || null

  const counts = [
    { type: 'ASSET', label: 'Assets', color: TYPE_COLORS.HOST, count: rawAssets.length },
    { type: 'SERVICE', label: 'Services', color: TYPE_COLORS.SERVICE, count: graph.nodes.filter(n => n.type === 'SERVICE').length },
    { type: 'ENDPOINT', label: 'Finding endpoints', color: TYPE_COLORS.ENDPOINT, count: graph.nodes.filter(n => n.type === 'ENDPOINT').length },
    { type: 'FINDING', label: 'Findings', color: TYPE_COLORS.FINDING, count: graph.nodes.filter(n => n.type === 'FINDING').length },
  ]
  const recentEvents = [
    ...findings.map(f => ({
      id: `finding:${f.id}`,
      time: f.created_at,
      title: f.title || 'Finding recorded',
      detail: `${String(f.severity || 'INFO').toUpperCase()} · ${f.plugin || f.scanner || 'scanner'}`,
      color: SEVERITY_COLORS[String(f.severity || 'INFO').toUpperCase()] || SEVERITY_COLORS.INFO,
    })),
    ...scans.map(s => ({
      id: `scan:${s.id}`,
      time: s.created_at,
      title: s.name || `${s.plugin || 'Scanner'} job`,
      detail: `${s.status || 'UNKNOWN'} · ${(s.targets || []).join(', ')}`,
      color: '#a855f7',
    })),
  ].sort((a, b) => new Date(b.time || 0).getTime() - new Date(a.time || 0).getTime()).slice(0, 8)

  const hasError = assetsQuery.isError || findingsQuery.isError || scansQuery.isError

  return (
    <div>
      <div className="page-header" style={{ marginBottom: 'var(--space-6)' }}>
        <div>
          <h1 className="page-title gradient-text-cyan">🕸️ Attack Surface Map</h1>
          <p className="page-subtitle">Asset, service, endpoint and finding relationships derived from saved backend records.</p>
        </div>
        <div className="flex gap-2">
          <div style={{
            padding: '6px 14px',
            background: hasError ? 'rgba(255,152,0,0.08)' : 'rgba(0,255,136,0.08)',
            border: `1px solid ${hasError ? 'rgba(255,152,0,0.3)' : 'rgba(0,255,136,0.3)'}`,
            borderRadius: 'var(--radius-md)', fontSize: '0.75rem',
            color: hasError ? '#ff9800' : '#00ff88', fontWeight: 700,
          }}>
            {hasError ? 'API DATA INCOMPLETE' : 'API DATA'}
          </div>
          <div style={{ padding: '6px 14px', background: 'rgba(255,255,255,0.04)', border: '1px solid var(--color-border)', borderRadius: 'var(--radius-md)', fontSize: '0.75rem', fontFamily: 'var(--font-mono)', color: 'var(--color-text-muted)' }}>
            {graph.nodes.length} nodes · {graph.edges.length} edges
          </div>
        </div>
      </div>

      {hasError && (
        <div role="alert" className="card" style={{ marginBottom: 'var(--space-4)', color: 'var(--color-high)' }}>
          One or more API requests failed. Map counts include only data successfully returned by the backend.
        </div>
      )}

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 10, marginBottom: 'var(--space-5)' }}>
        {counts.map(item => (
          <div key={item.type} style={{ padding: 12, borderRadius: 8, textAlign: 'center', background: `${item.color}08`, border: `1px solid ${item.color}30` }}>
            <div style={{ fontSize: '1.4rem', fontWeight: 900, color: item.color, fontFamily: 'var(--font-mono)' }}>{item.count}</div>
            <div style={{ fontSize: '0.68rem', fontWeight: 800, color: item.color, letterSpacing: '0.08em' }}>{item.label.toUpperCase()}</div>
          </div>
        ))}
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: 'var(--space-5)', alignItems: 'start' }}>
        <div className="card" style={{ border: '1px solid rgba(0,229,255,0.3)', background: 'linear-gradient(135deg, rgba(0,229,255,0.03), rgba(168,85,247,0.03))' }}>
          <div className="card-header">
            <div>
              <span className="card-title">Attack Surface Graph</span>
              <div style={{ fontSize: '0.7rem', color: 'var(--color-text-muted)' }}>Select any node to inspect its source record</div>
            </div>
            <span style={{ fontSize: '0.65rem', color: 'var(--color-text-muted)' }}>Showing up to 64 nodes</span>
          </div>
          {(assetsQuery.isLoading || findingsQuery.isLoading) && (
            <div style={{ padding: 18, color: 'var(--color-text-muted)' }}>Loading asset and finding records…</div>
          )}
          {!assetsQuery.isLoading && visibleNodes.length === 0 && (
            <div style={{ padding: 40, textAlign: 'center', color: 'var(--color-text-muted)' }}>
              <div style={{ fontSize: '2rem', marginBottom: 8 }}>🕸️</div>
              <strong>No topology records yet</strong>
              <div style={{ marginTop: 6, fontSize: '0.8rem' }}>Run an authorized lab scan and persist assets or findings to populate this graph.</div>
            </div>
          )}
          {visibleNodes.length > 0 && (
            <div style={{ background: 'rgba(0,0,0,0.55)', borderRadius: 'var(--radius-md)', border: '1px solid var(--color-border)', overflow: 'hidden' }}>
              <svg viewBox={`0 0 ${width} ${height}`} role="img" aria-label="Attack surface graph built from backend asset and finding records" style={{ width: '100%', minHeight: 330, display: 'block' }}>
                <defs>
                  <pattern id="spaider-map-grid" width="28" height="28" patternUnits="userSpaceOnUse">
                    <path d="M 28 0 L 0 0 0 28" fill="none" stroke="rgba(0,229,255,0.08)" strokeWidth="1" />
                  </pattern>
                </defs>
                <rect width={width} height={height} fill="url(#spaider-map-grid)" />
                {visibleEdges.map((edge, i) => {
                  const from = pointById.get(edge.source)
                  const to = pointById.get(edge.target)
                  if (!from || !to) return null
                  return <line key={`${edge.source}-${edge.target}-${i}`} x1={from.x} y1={from.y} x2={to.x} y2={to.y} stroke="rgba(0,229,255,0.28)" strokeWidth="1.3" />
                })}
                {positioned.map(node => (
                  <g key={node.id} onClick={() => setSelectedId(node.id)} style={{ cursor: 'pointer' }}>
                    <title>{node.label} — {node.type}: {node.detail || 'No additional details'}</title>
                    <circle cx={node.x} cy={node.y} r={selectedId === node.id ? 9 : 6} fill={node.color} fillOpacity={0.9} stroke={selectedId === node.id ? '#ffffff' : node.color} strokeWidth={selectedId === node.id ? 2 : 1} />
                    <text x={node.x + 10} y={node.y + 3} fill={node.color} fontSize="10" fontFamily="monospace">{node.label.slice(0, 23)}</text>
                  </g>
                ))}
              </svg>
            </div>
          )}
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}>
          <div className="card">
            <div className="card-header"><span className="card-title">Selected Node</span></div>
            {selected ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                <div style={{ fontSize: '0.65rem', fontWeight: 800, color: selected.color }}>{selected.type}</div>
                <div style={{ fontWeight: 700, overflowWrap: 'anywhere' }}>{selected.label}</div>
                <div style={{ fontSize: '0.8rem', color: 'var(--color-text-muted)', overflowWrap: 'anywhere' }}>{selected.detail || 'No additional details in the saved record.'}</div>
                <button className="btn btn-sm btn-ghost" onClick={() => setSelectedId(null)}>Clear selection</button>
              </div>
            ) : (
              <div style={{ fontSize: '0.8rem', color: 'var(--color-text-muted)' }}>Select a node in the graph. No synthetic targets are added.</div>
            )}
          </div>

          <div className="card">
            <div className="card-header">
              <span className="card-title">Recent Findings & Scan Jobs</span>
              <span style={{ fontSize: '0.65rem', color: '#00ff88' }}>API</span>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8, maxHeight: 360, overflowY: 'auto' }}>
              {recentEvents.map(event => (
                <div key={event.id} style={{ display: 'flex', gap: 8, padding: '8px', borderRadius: 6, background: 'rgba(255,255,255,0.025)', border: '1px solid var(--color-border)' }}>
                  <span style={{ width: 7, height: 7, borderRadius: '50%', background: event.color, flexShrink: 0, marginTop: 4 }} />
                  <div style={{ minWidth: 0 }}>
                    <div style={{ fontSize: '0.75rem', overflowWrap: 'anywhere' }}>{event.title}</div>
                    <div style={{ fontSize: '0.63rem', color: 'var(--color-text-muted)', marginTop: 3, overflowWrap: 'anywhere' }}>{event.detail}</div>
                    <div style={{ fontSize: '0.6rem', color: 'var(--color-text-muted)', marginTop: 3 }}>{relativeTime(event.time)}</div>
                  </div>
                </div>
              ))}
              {!recentEvents.length && <div style={{ padding: 12, fontSize: '0.8rem', color: 'var(--color-text-muted)' }}>No saved scans or findings yet.</div>}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
