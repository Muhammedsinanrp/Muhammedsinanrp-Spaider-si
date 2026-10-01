import { useEffect, useRef } from 'react'
import { useQuery } from '@tanstack/react-query'
import { assetApi } from '../api/client'

/* ── Mock network graph data ───────────────────────────── */
const MOCK_NODES = [
  { id:'internet', label:'INTERNET', type:'internet', x:400, y:50, color:'#555', icon:'🌐' },
  { id:'fw',       label:'Firewall', type:'firewall', x:400, y:150, color:'#ff9800', icon:'🔥' },
  { id:'web01',    label:'web01\n192.168.1.10', type:'host', x:200, y:280, color:'#3b82f6', icon:'🖥️', findings:3, alerts:1 },
  { id:'api',      label:'api\n192.168.1.11',  type:'host', x:350, y:300, color:'#3b82f6', icon:'⚙️', findings:1, alerts:0 },
  { id:'db01',     label:'db01\n192.168.1.20',  type:'host', x:200, y:420, color:'#ff3b5c', icon:'🗄️', findings:2, alerts:0 },
  { id:'vpn',      label:'VPN\n192.168.1.5',    type:'host', x:600, y:280, color:'#a855f7', icon:'🔐', findings:0, alerts:0 },
  { id:'pc01',     label:'pc01\n192.168.1.30',  type:'host', x:520, y:420, color:'#ff9800', icon:'💻', findings:1, alerts:2 },
  { id:'pc02',     label:'pc02\n192.168.1.31',  type:'host', x:680, y:420, color:'#3b82f6', icon:'💻', findings:0, alerts:0 },
]
const MOCK_EDGES = [
  { from:'internet', to:'fw' },
  { from:'fw', to:'web01' }, { from:'fw', to:'api' }, { from:'fw', to:'vpn' },
  { from:'web01', to:'db01' }, { from:'api', to:'db01' },
  { from:'vpn', to:'pc01' }, { from:'vpn', to:'pc02' },
  { from:'pc01', to:'db01' }, // lateral movement!
]

const NODE_R = 30

export default function NetworkMap() {
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const animFrameRef = useRef<number>(0)

  const { data: graphData } = useQuery({
    queryKey:['asset-graph'], queryFn: assetApi.graph, retry:false,
  })

  /* Canvas 2D network map */
  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return
    const ctx = canvas.getContext('2d')!
    let hovered: string | null = null

    const resize = () => {
      canvas.width = canvas.offsetWidth
      canvas.height = canvas.offsetHeight
    }
    resize()
    window.addEventListener('resize', resize)

    const draw = () => {
      ctx.clearRect(0, 0, canvas.width, canvas.height)

      // Background grid
      ctx.strokeStyle = 'rgba(255,255,255,0.03)'
      ctx.lineWidth = 1
      for (let x = 0; x < canvas.width; x += 40) {
        ctx.beginPath(); ctx.moveTo(x,0); ctx.lineTo(x, canvas.height); ctx.stroke()
      }
      for (let y = 0; y < canvas.height; y += 40) {
        ctx.beginPath(); ctx.moveTo(0,y); ctx.lineTo(canvas.width,y); ctx.stroke()
      }

      // Scale nodes to canvas
      const scaleX = canvas.width / 800
      const scaleY = canvas.height / 500

      // Draw edges
      MOCK_EDGES.forEach(e => {
        const from = MOCK_NODES.find(n => n.id === e.from)!
        const to   = MOCK_NODES.find(n => n.id === e.to)!
        const isLateral = (e.from === 'pc01' && e.to === 'db01')
        ctx.beginPath()
        ctx.moveTo(from.x * scaleX, from.y * scaleY)
        ctx.lineTo(to.x * scaleX, to.y * scaleY)
        ctx.strokeStyle = isLateral ? 'rgba(255,59,92,0.7)' : 'rgba(0,229,255,0.2)'
        ctx.lineWidth = isLateral ? 2.5 : 1.5
        if (isLateral) ctx.setLineDash([6,4])
        else ctx.setLineDash([])
        ctx.stroke()
        ctx.setLineDash([])
      })

      // Animated connection pulse
      const t = Date.now() / 1000
      MOCK_EDGES.forEach((e, i) => {
        const from = MOCK_NODES.find(n => n.id === e.from)!
        const to   = MOCK_NODES.find(n => n.id === e.to)!
        const progress = ((t * 0.4 + i * 0.3) % 1)
        const px = (from.x + (to.x - from.x) * progress) * scaleX
        const py = (from.y + (to.y - from.y) * progress) * scaleY
        const isLateral = (e.from === 'pc01' && e.to === 'db01')
        ctx.beginPath()
        ctx.arc(px, py, 3, 0, Math.PI*2)
        ctx.fillStyle = isLateral ? 'rgba(255,59,92,0.9)' : 'rgba(0,229,255,0.7)'
        ctx.fill()
      })

      // Draw nodes
      MOCK_NODES.forEach(n => {
        const x = n.x * scaleX, y = n.y * scaleY
        const isHovered = hovered === n.id
        const r = isHovered ? NODE_R + 4 : NODE_R

        // Glow
        if (n.findings! > 0 || n.alerts! > 0) {
          const grad = ctx.createRadialGradient(x,y,0,x,y,r*2)
          grad.addColorStop(0, 'rgba(255,59,92,0.3)')
          grad.addColorStop(1, 'rgba(255,59,92,0)')
          ctx.beginPath(); ctx.arc(x,y,r*2,0,Math.PI*2)
          ctx.fillStyle = grad; ctx.fill()
        }

        // Node circle
        ctx.beginPath(); ctx.arc(x, y, r, 0, Math.PI*2)
        ctx.fillStyle = n.id === 'internet' ? '#1a1a2e' : '#16162a'
        ctx.fill()
        ctx.strokeStyle = n.color + (isHovered ? 'ff' : '99')
        ctx.lineWidth = isHovered ? 3 : 2
        if (n.alerts! > 0) {
          ctx.strokeStyle = '#ff3b5c'
          ctx.shadowColor = '#ff3b5c'
          ctx.shadowBlur = 15
        }
        ctx.stroke()
        ctx.shadowBlur = 0

        // Icon
        ctx.font = `${r * 0.7}px serif`
        ctx.textAlign = 'center'
        ctx.textBaseline = 'middle'
        ctx.fillText(n.icon, x, y)

        // Label
        ctx.font = '10px Inter, sans-serif'
        ctx.fillStyle = 'rgba(240,240,255,0.8)'
        ctx.textAlign = 'center'
        ctx.textBaseline = 'top'
        n.label.split('\n').forEach((line, li) => {
          ctx.fillText(line, x, y + r + 4 + li * 12)
        })

        // Badge
        if (n.findings! > 0) {
          ctx.beginPath(); ctx.arc(x + r - 4, y - r + 4, 8, 0, Math.PI*2)
          ctx.fillStyle = '#ff3b5c'; ctx.fill()
          ctx.font = 'bold 8px Inter'
          ctx.fillStyle = '#fff'
          ctx.textAlign = 'center'; ctx.textBaseline = 'middle'
          ctx.fillText(String(n.findings), x + r - 4, y - r + 4)
        }
      })

      animFrameRef.current = requestAnimationFrame(draw)
    }

    // Mouse hover
    canvas.addEventListener('mousemove', e => {
      const rect = canvas.getBoundingClientRect()
      const mx = (e.clientX - rect.left) * (canvas.width / rect.width)
      const my = (e.clientY - rect.top) * (canvas.height / rect.height)
      const scaleX = canvas.width / 800, scaleY = canvas.height / 500
      hovered = null
      MOCK_NODES.forEach(n => {
        const dx = mx - n.x * scaleX, dy = my - n.y * scaleY
        if (Math.sqrt(dx*dx+dy*dy) < NODE_R + 5) hovered = n.id
      })
      canvas.style.cursor = hovered ? 'pointer' : 'default'
    })

    draw()
    return () => {
      cancelAnimationFrame(animFrameRef.current)
      window.removeEventListener('resize', resize)
    }
  }, [])

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title gradient-text-cyan">🌍 Network Map</h1>
          <p className="page-subtitle">Live network topology with attack paths and asset relationships</p>
        </div>
        <div className="flex gap-2">
          <button className="btn btn-ghost">🔍 Run Discovery</button>
          <button className="btn btn-primary">Export Topology</button>
        </div>
      </div>

      {/* Legend */}
      <div className="flex gap-4 mb-4" style={{ fontSize:'0.75rem' }}>
        {[
          { color:'var(--color-blue)', label:'Normal host' },
          { color:'var(--color-red)', label:'Vulnerable host' },
          { color:'#ff9800', label:'Firewall' },
          { color:'var(--color-purple)', label:'VPN / edge' },
        ].map(l => (
          <span key={l.label} className="flex items-center gap-2">
            <span style={{ width:10, height:10, borderRadius:'50%', background:l.color, display:'inline-block' }} />
            {l.label}
          </span>
        ))}
        <span className="flex items-center gap-2">
          <span style={{ width:20, height:2, background:'var(--color-red)', display:'inline-block', borderTop:'2px dashed var(--color-red)' }} />
          Lateral movement
        </span>
      </div>

      {/* Canvas */}
      <div className="canvas-container" style={{ height:520 }}>
        <div className="canvas-overlay">
          <div style={{ background:'rgba(10,10,20,0.8)', border:'1px solid var(--color-border-accent)', borderRadius:'var(--radius-md)', padding:'var(--space-3)', fontSize:'0.75rem' }}>
            <div style={{ color:'var(--color-cyan)', fontWeight:700, marginBottom:4 }}>NETWORK TOPOLOGY</div>
            <div style={{ color:'var(--color-text-muted)' }}>{MOCK_NODES.length} nodes · {MOCK_EDGES.length} connections</div>
            <div style={{ color:'var(--color-red)', marginTop:4 }}>⚠ 1 lateral movement path</div>
          </div>
        </div>
        <canvas ref={canvasRef} style={{ width:'100%', height:'100%' }} />
      </div>

      {/* Node list */}
      <div className="card mt-4">
        <div className="card-header">
          <span className="card-title">Network Nodes</span>
        </div>
        <table className="data-table">
          <thead>
            <tr><th>Node</th><th>IP</th><th>Type</th><th>Findings</th><th>Alerts</th></tr>
          </thead>
          <tbody>
            {MOCK_NODES.filter(n=>n.type==='host').map(n => (
              <tr key={n.id}>
                <td><span style={{ fontSize:'1rem' }}>{n.icon}</span> {n.label.split('\n')[0]}</td>
                <td className="mono">{n.label.split('\n')[1]}</td>
                <td><span style={{ color:'var(--color-text-muted)', fontSize:'0.75rem' }}>HOST</span></td>
                <td>
                  {n.findings! > 0
                    ? <span className="badge badge-high">{n.findings} findings</span>
                    : <span className="badge badge-safe">Clean</span>}
                </td>
                <td>
                  {n.alerts! > 0
                    ? <span className="badge badge-critical">{n.alerts} alerts</span>
                    : <span style={{ color:'var(--color-text-muted)', fontSize:'0.75rem' }}>—</span>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
