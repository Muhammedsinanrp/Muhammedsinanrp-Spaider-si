import React, { useEffect, useRef } from 'react'

interface Node3D {
  id: number
  x: number; y: number; z: number
  vx: number; vy: number; vz: number
  type: 'domain' | 'subdomain' | 'api' | 'endpoint' | 'service' | 'vuln'
  label: string
  radius: number
  pulse: number
  pulseSpeed: number
  discovered: number // 0..1 grow-in progress
  connections: number[]
}

interface SpiderWebCanvasProps {
  opacity?: number
  interactive?: boolean
  className?: string
}

const NODE_TYPES = {
  domain:    { color: '#00e5ff', glow: 'rgba(0,229,255,0.7)',   size: 7,  label: 'DOMAIN'    },
  subdomain: { color: '#00ff88', glow: 'rgba(0,255,136,0.6)',   size: 5,  label: 'SUBDOMAIN'  },
  api:       { color: '#a855f7', glow: 'rgba(168,85,247,0.6)',  size: 5,  label: 'API'        },
  endpoint:  { color: '#38bdf8', glow: 'rgba(56,189,248,0.5)',  size: 4,  label: 'ENDPOINT'   },
  service:   { color: '#6366f1', glow: 'rgba(99,102,241,0.5)',  size: 4,  label: 'SERVICE'    },
  vuln:      { color: '#ff3b5c', glow: 'rgba(255,59,92,0.8)',   size: 6,  label: 'VULN'       },
}

const LABELS: Record<Node3D['type'], string[]> = {
  domain:    ['example.com', 'target.io', 'corp.net'],
  subdomain: ['api.', 'admin.', 'dev.', 'staging.', 'auth.', 'cdn.'],
  api:       ['/api/v1', '/graphql', '/rest', '/oauth'],
  endpoint:  ['/fetch', '/upload', '/search', '/user'],
  service:   ['HTTP:80', 'HTTPS:443', 'SSH:22', 'FTP:21'],
  vuln:      ['XSS', 'SSRF', 'IDOR', 'SQLi', 'RCE'],
}

function randomLabel(type: Node3D['type']): string {
  const arr = LABELS[type]
  return arr[Math.floor(Math.random() * arr.length)]
}

function buildGraph(): Node3D[] {
  const nodes: Node3D[] = []
  let id = 0
  const spread = 320

  const mkNode = (type: Node3D['type']): Node3D => {
    const t = NODE_TYPES[type]
    return {
      id: id++,
      x: (Math.random() - 0.5) * spread,
      y: (Math.random() - 0.5) * spread,
      z: (Math.random() - 0.5) * spread,
      vx: (Math.random() - 0.5) * 0.12,
      vy: (Math.random() - 0.5) * 0.12,
      vz: (Math.random() - 0.5) * 0.12,
      type,
      label: randomLabel(type),
      radius: t.size,
      pulse: Math.random() * Math.PI * 2,
      pulseSpeed: 0.6 + Math.random() * 1.2,
      discovered: Math.random(),
      connections: [],
    }
  }

  // Core topology
  const domain = mkNode('domain')
  nodes.push(domain)

  const subdomains = Array.from({ length: 5 }, () => mkNode('subdomain'))
  subdomains.forEach(s => { nodes.push(s); domain.connections.push(s.id); s.connections.push(domain.id) })

  const apis = Array.from({ length: 4 }, () => mkNode('api'))
  apis.forEach((a, i) => {
    nodes.push(a)
    const parent = subdomains[i % subdomains.length]
    parent.connections.push(a.id); a.connections.push(parent.id)
  })

  const endpoints = Array.from({ length: 8 }, () => mkNode('endpoint'))
  endpoints.forEach((e, i) => {
    nodes.push(e)
    const parent = apis[i % apis.length]
    parent.connections.push(e.id); e.connections.push(parent.id)
  })

  const services = Array.from({ length: 6 }, () => mkNode('service'))
  services.forEach((s, i) => {
    nodes.push(s)
    const parent = subdomains[i % subdomains.length]
    parent.connections.push(s.id); s.connections.push(parent.id)
  })

  const vulns = Array.from({ length: 4 }, () => mkNode('vuln'))
  vulns.forEach((v, i) => {
    nodes.push(v)
    const parent = endpoints[i % endpoints.length]
    parent.connections.push(v.id); v.connections.push(parent.id)
  })

  return nodes
}

export default function SpiderWebCanvas({ opacity = 0.85, interactive = false, className = '' }: SpiderWebCanvasProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const mouseRef = useRef({ x: 0, y: 0 })
  const cameraRef = useRef({ rx: 0.25, ry: 0.3, targetRx: 0.25, targetRy: 0.3, zoom: 1 })
  const nodesRef = useRef<Node3D[]>(buildGraph())
  const timeRef = useRef(0)

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return
    const context = canvas.getContext('2d')
    if (!context) return
    const ctx: CanvasRenderingContext2D = context

    let raf: number
    let w = canvas.width = window.innerWidth
    let h = canvas.height = window.innerHeight

    const onResize = () => {
      w = canvas.width = window.innerWidth
      h = canvas.height = window.innerHeight
    }
    window.addEventListener('resize', onResize)

    const onMouseMove = (e: MouseEvent) => {
      const nx = (e.clientX / w - 0.5) * 2
      const ny = (e.clientY / h - 0.5) * 2
      mouseRef.current = { x: nx, y: ny }
      cameraRef.current.targetRy = 0.3 + nx * 0.6
      cameraRef.current.targetRx = 0.25 - ny * 0.4
    }
    if (interactive) window.addEventListener('mousemove', onMouseMove)

    function project(x: number, y: number, z: number): { sx: number; sy: number; scale: number } {
      const cam = cameraRef.current
      const cosY = Math.cos(cam.ry), sinY = Math.sin(cam.ry)
      const x1 = x * cosY + z * sinY
      const z1 = -x * sinY + z * cosY
      const cosX = Math.cos(cam.rx), sinX = Math.sin(cam.rx)
      const y2 = y * cosX - z1 * sinX
      const z2 = y * sinX + z1 * cosX
      const fov = 700 * cam.zoom
      const d = fov / (fov + z2 + 400)
      return { sx: w / 2 + x1 * d, sy: h / 2 + y2 * d, scale: d }
    }

    function drawParticles(t: number) {
      ctx.save()
      for (let i = 0; i < 40; i++) {
        const phase = (t * 0.0003 + i * 137.5) % (2 * Math.PI * 100)
        const px = ((i * 73.1 + Math.sin(t * 0.0001 * (i + 1)) * 200) % w + w) % w
        const py = ((i * 47.3 + Math.cos(t * 0.00008 * (i + 1)) * 150) % h + h) % h
        const a2 = (Math.sin(phase) * 0.5 + 0.5) * 0.25
        const sz = 1 + Math.sin(phase * 0.7) * 0.8
        ctx.beginPath()
        ctx.arc(px, py, sz, 0, Math.PI * 2)
        ctx.fillStyle = i % 3 === 0 ? `rgba(0,229,255,${a2})` : i % 3 === 1 ? `rgba(0,255,136,${a2})` : `rgba(168,85,247,${a2})`
        ctx.fill()
      }
      ctx.restore()
    }

    function drawEdges(nodes: Node3D[], t: number) {
      const seen = new Set<string>()
      for (const node of nodes) {
        const pA = project(node.x, node.y, node.z)
        for (const cid of node.connections) {
          const key = [Math.min(node.id, cid), Math.max(node.id, cid)].join('-')
          if (seen.has(key)) continue
          seen.add(key)
          const other = nodes.find(n => n.id === cid)
          if (!other) continue
          const pB = project(other.x, other.y, other.z)
          const avgScale = (pA.scale + pB.scale) / 2
          const edgeAlpha = Math.min(0.55, avgScale * 0.7) * opacity
          const typeA = NODE_TYPES[node.type]
          const typeB = NODE_TYPES[other.type]

          const grad = ctx.createLinearGradient(pA.sx, pA.sy, pB.sx, pB.sy)
          const hexAlpha = Math.round(edgeAlpha * 255).toString(16).padStart(2, '0')
          grad.addColorStop(0, typeA.color + hexAlpha)
          grad.addColorStop(1, typeB.color + hexAlpha)

          ctx.beginPath()
          ctx.moveTo(pA.sx, pA.sy)
          ctx.lineTo(pB.sx, pB.sy)
          ctx.strokeStyle = grad
          ctx.lineWidth = Math.max(0.3, avgScale * 1.2)
          ctx.stroke()

          // Animated pulse along edge
          const edgePhase = ((t * 0.0008 + node.id * 0.3) % 1 + 1) % 1
          const px = pA.sx + (pB.sx - pA.sx) * edgePhase
          const py2 = pA.sy + (pB.sy - pA.sy) * edgePhase
          ctx.beginPath()
          ctx.arc(px, py2, 1.5, 0, Math.PI * 2)
          ctx.fillStyle = typeA.color
          ctx.globalAlpha = edgeAlpha * 2
          ctx.fill()
          ctx.globalAlpha = 1
        }
      }
    }

    function drawNodes(nodes: Node3D[], t: number) {
      const sorted = [...nodes].sort((a, b) => {
        return project(a.x, a.y, a.z).scale - project(b.x, b.y, b.z).scale
      })

      for (const node of sorted) {
        const p = project(node.x, node.y, node.z)
        const t2 = NODE_TYPES[node.type]
        const pulseFactor = Math.sin(node.pulse + t * 0.001 * node.pulseSpeed) * 0.35 + 1
        const r = node.radius * p.scale * 3.5 * pulseFactor * node.discovered
        if (r < 0.5) continue
        const alpha = Math.min(1, p.scale * 1.4) * opacity

        // Glow halo
        ctx.save()
        const glowR = r * 3.5
        const glowGrad = ctx.createRadialGradient(p.sx, p.sy, 0, p.sx, p.sy, glowR)
        const glowBase = t2.glow.replace('rgba(', '').replace(')', '').split(',')
        glowGrad.addColorStop(0, `rgba(${glowBase[0]},${glowBase[1]},${glowBase[2]},${alpha * 0.5})`)
        glowGrad.addColorStop(1, 'transparent')
        ctx.beginPath()
        ctx.arc(p.sx, p.sy, glowR, 0, Math.PI * 2)
        ctx.fillStyle = glowGrad
        ctx.fill()
        ctx.restore()

        // Node body
        ctx.save()
        ctx.shadowBlur = 15 * p.scale
        ctx.shadowColor = t2.color
        ctx.beginPath()
        ctx.arc(p.sx, p.sy, r, 0, Math.PI * 2)
        const bodyGrad = ctx.createRadialGradient(p.sx - r * 0.3, p.sy - r * 0.3, 0, p.sx, p.sy, r)
        bodyGrad.addColorStop(0, '#ffffff')
        bodyGrad.addColorStop(0.3, t2.color)
        bodyGrad.addColorStop(1, t2.color + '88')
        ctx.fillStyle = bodyGrad
        ctx.globalAlpha = alpha
        ctx.fill()
        ctx.restore()

        if (r > 5 && alpha > 0.4) {
          ctx.save()
          ctx.font = `${Math.max(8, r * 1.1)}px "JetBrains Mono", monospace`
          ctx.fillStyle = t2.color
          ctx.globalAlpha = alpha * 0.85
          ctx.textAlign = 'center'
          ctx.fillText(node.label, p.sx, p.sy + r + 10)
          ctx.restore()
        }
      }
    }

    function updateNodes(nodes: Node3D[]) {
      const bounds = 380
      for (const n of nodes) {
        n.x += n.vx; n.y += n.vy; n.z += n.vz
        if (Math.abs(n.x) > bounds) n.vx *= -0.9
        if (Math.abs(n.y) > bounds) n.vy *= -0.9
        if (Math.abs(n.z) > bounds) n.vz *= -0.9
        n.vx += -n.x * 0.00005
        n.vy += -n.y * 0.00005
        n.vz += -n.z * 0.00005
        const spd = Math.sqrt(n.vx ** 2 + n.vy ** 2 + n.vz ** 2)
        if (spd > 0.3) { n.vx *= 0.95; n.vy *= 0.95; n.vz *= 0.95 }
        n.discovered = Math.min(1, n.discovered + 0.004)
      }
    }

    function render(t: number) {
      timeRef.current = t
      ctx.clearRect(0, 0, w, h)
      const cam = cameraRef.current
      cam.rx += (cam.targetRx - cam.rx) * 0.04
      cam.ry += (cam.targetRy - cam.ry) * 0.04
      // Auto rotate
      cam.targetRy += 0.0008

      const nodes = nodesRef.current
      ctx.save()
      ctx.globalAlpha = opacity
      drawParticles(t)
      drawEdges(nodes, t)
      drawNodes(nodes, t)
      ctx.restore()

      updateNodes(nodes)
      raf = requestAnimationFrame(render)
    }

    raf = requestAnimationFrame(render)

    return () => {
      cancelAnimationFrame(raf)
      window.removeEventListener('resize', onResize)
      if (interactive) window.removeEventListener('mousemove', onMouseMove)
    }
  }, [opacity, interactive])

  return (
    <canvas
      ref={canvasRef}
      className={`spider-web-canvas ${className}`}
      style={{
        position: interactive ? 'relative' : 'fixed',
        top: 0, left: 0,
        width: '100%', height: '100%',
        pointerEvents: interactive ? 'auto' : 'none',
        zIndex: interactive ? 1 : 0,
        opacity,
      }}
    />
  )
}
