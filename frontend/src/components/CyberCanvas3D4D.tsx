import React, { useEffect, useRef, useState } from 'react'
import { useStore, CyberTheme, AnimationDimension } from '../store/useStore'

// ── 4D Tesseract Geometry Definitions ─────────────────────────────────────────
// 16 vertices in 4-dimensional space {-1, 1}^4
const VERTICES_4D: number[][] = []
for (let i = 0; i < 16; i++) {
  VERTICES_4D.push([
    (i & 1) ? 1 : -1,
    (i & 2) ? 1 : -1,
    (i & 4) ? 1 : -1,
    (i & 8) ? 1 : -1,
  ])
}

// 32 edges connecting vertices that differ by exactly 1 coordinate
const EDGES_4D: [number, number][] = []
for (let i = 0; i < 16; i++) {
  for (let j = i + 1; j < 16; j++) {
    let diff = 0
    for (let k = 0; k < 4; k++) {
      if (VERTICES_4D[i][k] !== VERTICES_4D[j][k]) diff++
    }
    if (diff === 1) {
      EDGES_4D.push([i, j])
    }
  }
}

// Color palette mapping per theme
const THEME_PALETTES: Record<CyberTheme, { primary: string; secondary: string; glow: string; bg: string }> = {
  cyberpunk: { primary: '#00e5ff', secondary: '#a855f7', glow: 'rgba(0, 229, 255, 0.4)', bg: '#060609' },
  matrix:    { primary: '#00ff66', secondary: '#10b981', glow: 'rgba(0, 255, 102, 0.4)', bg: '#040804' },
  crimson:   { primary: '#ff2a4b', secondary: '#ff9100', glow: 'rgba(255, 42, 75, 0.4)', bg: '#0a0405' },
  void:      { primary: '#e2e8f0', secondary: '#64748b', glow: 'rgba(226, 232, 240, 0.3)', bg: '#000000' },
  synthwave: { primary: '#ff2a85', secondary: '#00f0ff', glow: 'rgba(255, 42, 133, 0.4)', bg: '#0c061a' },
  quantum:   { primary: '#38bdf8', secondary: '#6366f1', glow: 'rgba(56, 189, 248, 0.4)', bg: '#030712' },
}

interface CyberCanvasProps {
  interactive?: boolean
  className?: string
  opacity?: number
}

export default function CyberCanvas3D4D({ interactive = false, className = '', opacity = 0.85 }: CyberCanvasProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const { theme, animDimension, animSpeed, animGlow } = useStore()
  
  // Mouse tracking for interactive tilt
  const mouseRef = useRef({ x: 0, y: 0, targetX: 0, targetY: 0, isDown: false, lastX: 0, lastY: 0 })
  const rotation4DRef = useRef({ angleXW: 0, angleYZ: 0, angleZW: 0, angleXY: 0 })

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return
    const ctx = canvas.getContext('2d')
    if (!ctx) return

    let animationFrameId: number
    let width = (canvas.width = window.innerWidth)
    let height = (canvas.height = window.innerHeight)

    const handleResize = () => {
      if (!canvas) return
      width = canvas.width = window.innerWidth
      height = canvas.height = window.innerHeight
    }
    window.addEventListener('resize', handleResize)

    // Mouse handlers
    const handleMouseMove = (e: MouseEvent) => {
      mouseRef.current.targetX = (e.clientX / width - 0.5) * 2
      mouseRef.current.targetY = (e.clientY / height - 0.5) * 2
      if (mouseRef.current.isDown) {
        const dx = e.clientX - mouseRef.current.lastX
        const dy = e.clientY - mouseRef.current.lastY
        rotation4DRef.current.angleXW += dx * 0.008
        rotation4DRef.current.angleZW += dy * 0.008
        mouseRef.current.lastX = e.clientX
        mouseRef.current.lastY = e.clientY
      }
    }

    const handleMouseDown = (e: MouseEvent) => {
      mouseRef.current.isDown = true
      mouseRef.current.lastX = e.clientX
      mouseRef.current.lastY = e.clientY
    }

    const handleMouseUp = () => {
      mouseRef.current.isDown = false
    }

    if (interactive) {
      window.addEventListener('mousemove', handleMouseMove)
      window.addEventListener('mousedown', handleMouseDown)
      window.addEventListener('mouseup', handleMouseUp)
    }

    // ── Matrix Rain State ──
    const fontSize = 14
    const columns = Math.floor(width / fontSize)
    const drops: number[] = Array(columns).fill(1).map(() => Math.floor(Math.random() * -100))
    const chars = '01SPAIDER_X4D_SEC_INTEL_CYBER_MATRIX_ΑΒΓΔΩ0123456789'

    // ── 3D Terrain Wave State ──
    const gridCols = 32
    const gridRows = 24
    let waveTime = 0

    // ── Render Loop ─────────────────────────────────────────────────────────
    const render = () => {
      const palette = THEME_PALETTES[theme] || THEME_PALETTES.cyberpunk

      // Clear or fade
      ctx.clearRect(0, 0, width, height)

      // Smooth mouse interpolation
      mouseRef.current.x += (mouseRef.current.targetX - mouseRef.current.x) * 0.05
      mouseRef.current.y += (mouseRef.current.targetY - mouseRef.current.y) * 0.05

      const speedFactor = animSpeed * 0.015

      // ────────────────────────────────────────────────────────────────────────
      // MODE 1: 4D TESSERACT HYPERCUBE
      // ────────────────────────────────────────────────────────────────────────
      if (animDimension === '4d') {
        rotation4DRef.current.angleXW += speedFactor * 0.8
        rotation4DRef.current.angleYZ += speedFactor * 0.6
        rotation4DRef.current.angleZW += speedFactor * 0.4 + mouseRef.current.y * 0.01
        rotation4DRef.current.angleXY += speedFactor * 0.3 + mouseRef.current.x * 0.01

        const aXW = rotation4DRef.current.angleXW
        const aYZ = rotation4DRef.current.angleYZ
        const aZW = rotation4DRef.current.angleZW
        const aXY = rotation4DRef.current.angleXY

        const cx = width / 2
        const cy = height / 2
        const baseScale = Math.min(width, height) * (interactive ? 0.32 : 0.26)

        // 4D Rotation & Stereographic Projection
        const projected3D: { x: number; y: number; z: number; w: number; sx: number; sy: number }[] = []

        for (let i = 0; i < VERTICES_4D.length; i++) {
          let [x, y, z, w] = VERTICES_4D[i]

          // 1. Rotate in X-W plane
          let x1 = x * Math.cos(aXW) - w * Math.sin(aXW)
          let w1 = x * Math.sin(aXW) + w * Math.cos(aXW)

          // 2. Rotate in Y-Z plane
          let y1 = y * Math.cos(aYZ) - z * Math.sin(aYZ)
          let z1 = y * Math.sin(aYZ) + z * Math.cos(aYZ)

          // 3. Rotate in Z-W plane
          let z2 = z1 * Math.cos(aZW) - w1 * Math.sin(aZW)
          let w2 = z1 * Math.sin(aZW) + w1 * Math.cos(aZW)

          // 4. Rotate in X-Y plane
          let x2 = x1 * Math.cos(aXY) - y1 * Math.sin(aXY)
          let y2 = x1 * Math.sin(aXY) + y1 * Math.cos(aXY)

          // 4D to 3D perspective projection (camera distance in 4th dimension = 3.0)
          const distance4D = 2.8
          const scale4D = 1 / (distance4D - w2)

          const p3X = x2 * scale4D
          const p3Y = y2 * scale4D
          const p3Z = z2 * scale4D

          // 3D to 2D screen projection
          const distance3D = 3.5
          const scale3D = 1 / (distance3D - p3Z)

          const screenX = cx + p3X * scale3D * baseScale * 3.5
          const screenY = cy + p3Y * scale3D * baseScale * 3.5

          projected3D.push({ x: p3X, y: p3Y, z: p3Z, w: w2, sx: screenX, sy: screenY })
        }

        // Draw 32 4D Hypercube Edges
        ctx.save()
        if (animGlow) {
          ctx.shadowBlur = 12
          ctx.shadowColor = palette.glow
        }

        for (let e = 0; e < EDGES_4D.length; e++) {
          const [i, j] = EDGES_4D[e]
          const pA = projected3D[i]
          const pB = projected3D[j]

          // Compute average 4D depth (w) for depth coloring & alpha
          const avgW = (pA.w + pB.w) / 2
          const alpha = Math.max(0.15, Math.min(0.9, (avgW + 1.6) / 3.2))

          const grad = ctx.createLinearGradient(pA.sx, pA.sy, pB.sx, pB.sy)
          grad.addColorStop(0, pA.w > 0 ? palette.primary : palette.secondary)
          grad.addColorStop(1, pB.w > 0 ? palette.secondary : palette.primary)

          ctx.beginPath()
          ctx.moveTo(pA.sx, pA.sy)
          ctx.lineTo(pB.sx, pB.sy)
          ctx.strokeStyle = grad
          ctx.lineWidth = Math.max(1, (avgW + 2) * 1.3)
          ctx.globalAlpha = alpha * opacity
          ctx.stroke()
        }

        // Draw 16 4D Vertices with pulsating energy halos
        for (let i = 0; i < projected3D.length; i++) {
          const p = projected3D[i]
          const pulse = Math.sin(aXW * 3 + i) * 1.5 + 3.5
          const nodeRadius = Math.max(2, (p.w + 1.8) * pulse * 0.8)

          ctx.beginPath()
          ctx.arc(p.sx, p.sy, nodeRadius, 0, Math.PI * 2)
          ctx.fillStyle = p.w > 0 ? palette.primary : palette.secondary
          ctx.globalAlpha = Math.min(1, Math.max(0.3, (p.w + 1.8) / 3)) * opacity
          ctx.fill()

          // Core bright center
          ctx.beginPath()
          ctx.arc(p.sx, p.sy, Math.max(1, nodeRadius * 0.4), 0, Math.PI * 2)
          ctx.fillStyle = '#ffffff'
          ctx.fill()
        }
        ctx.restore()

        // 4D Geometry Telemetry HUD (Interactive Mode or subtle background)
        if (interactive) {
          ctx.fillStyle = palette.primary
          ctx.font = '10px "JetBrains Mono", monospace'
          ctx.globalAlpha = 0.75
          ctx.fillText(`4D HYPERCUBE [TESSERACT]  •  DIMENSIONS: 4 (X, Y, Z, W)`, 24, 30)
          ctx.fillText(`ROTATION 4D: ∠XW=${aXW.toFixed(2)} rad  ∠YZ=${aYZ.toFixed(2)} rad  ∠ZW=${aZW.toFixed(2)} rad`, 24, 46)
          ctx.fillText(`VERTICES: 16  |  EDGES: 32  |  PROJECTION: STEREOGRAPHIC $\\mathbb{R}^4 \\to \\mathbb{R}^3 \\to \\mathbb{R}^2$`, 24, 62)
          ctx.fillText(`[Drag with mouse to rotate through the 4th spatial dimension]`, 24, 78)
        }
      }

      // ────────────────────────────────────────────────────────────────────────
      // MODE 2: 3D CYBER GRID & HORIZON WAVE
      // ────────────────────────────────────────────────────────────────────────
      else if (animDimension === '3d') {
        waveTime += speedFactor * 1.8
        const cx = width / 2
        const cy = height * 0.65
        const fov = 350

        ctx.save()
        ctx.globalAlpha = 0.65 * opacity
        if (animGlow) {
          ctx.shadowBlur = 8
          ctx.shadowColor = palette.glow
        }

        // Horizon line glow
        const horizonGrad = ctx.createLinearGradient(0, cy - 80, 0, cy + 40)
        horizonGrad.addColorStop(0, 'transparent')
        horizonGrad.addColorStop(0.5, palette.glow)
        horizonGrad.addColorStop(1, 'transparent')
        ctx.fillStyle = horizonGrad
        ctx.fillRect(0, cy - 80, width, 160)

        // Draw 3D undulating grid lines
        const points3D: { sx: number; sy: number; z: number }[][] = []

        for (let r = 0; r < gridRows; r++) {
          points3D[r] = []
          const z = (r + 1) * 22
          const scale = fov / (fov + z)

          for (let c = 0; c < gridCols; c++) {
            const x = (c - gridCols / 2) * 55
            const waveY = Math.sin(c * 0.4 + waveTime + r * 0.2) * 28 + Math.cos(r * 0.3 - waveTime) * 15
            const sx = cx + (x + mouseRef.current.x * 40) * scale
            const sy = cy + (waveY + mouseRef.current.y * 30 + r * 14) * scale

            points3D[r].push({ sx, sy, z })
          }
        }

        // Lateral lines
        ctx.strokeStyle = palette.primary
        ctx.lineWidth = 1.2
        for (let r = 0; r < gridRows; r++) {
          ctx.beginPath()
          for (let c = 0; c < gridCols; c++) {
            const p = points3D[r][c]
            if (c === 0) ctx.moveTo(p.sx, p.sy)
            else ctx.lineTo(p.sx, p.sy)
          }
          ctx.stroke()
        }

        // Longitudinal lines
        ctx.strokeStyle = palette.secondary
        ctx.lineWidth = 0.8
        for (let c = 0; c < gridCols; c += 2) {
          ctx.beginPath()
          for (let r = 0; r < gridRows; r++) {
            const p = points3D[r][c]
            if (r === 0) ctx.moveTo(p.sx, p.sy)
            else ctx.lineTo(p.sx, p.sy)
          }
          ctx.stroke()
        }
        ctx.restore()
      }

      // ────────────────────────────────────────────────────────────────────────
      // MODE 3: 3D QUANTUM THREAT CORE (ORB & GYROSCOPE)
      // ────────────────────────────────────────────────────────────────────────
      else if (animDimension === 'quantum') {
        waveTime += speedFactor * 1.5
        const cx = width / 2
        const cy = height / 2
        const coreRadius = Math.min(width, height) * 0.22

        ctx.save()
        if (animGlow) {
          ctx.shadowBlur = 18
          ctx.shadowColor = palette.glow
        }

        // Outer rotating gimbal rings in 3D
        const rings = [
          { rx: waveTime * 0.8, ry: waveTime * 0.5, color: palette.primary, r: coreRadius * 1.4 },
          { rx: -waveTime * 0.6, ry: waveTime * 0.9, color: palette.secondary, r: coreRadius * 1.2 },
          { rx: waveTime * 1.1, ry: -waveTime * 0.7, color: palette.primary, r: coreRadius * 1.0 },
        ]

        rings.forEach((ring) => {
          ctx.beginPath()
          const steps = 64
          for (let i = 0; i <= steps; i++) {
            const theta = (i / steps) * Math.PI * 2
            let x = Math.cos(theta) * ring.r
            let y = Math.sin(theta) * ring.r
            let z = 0

            // 3D rotations
            const y1 = y * Math.cos(ring.rx) - z * Math.sin(ring.rx)
            const z1 = y * Math.sin(ring.rx) + z * Math.cos(ring.rx)
            const x1 = x * Math.cos(ring.ry) + z1 * Math.sin(ring.ry)

            const dist = 600
            const s = dist / (dist + z1)
            const sx = cx + x1 * s
            const sy = cy + y1 * s

            if (i === 0) ctx.moveTo(sx, sy)
            else ctx.lineTo(sx, sy)
          }
          ctx.strokeStyle = ring.color
          ctx.lineWidth = 1.8
          ctx.globalAlpha = 0.8 * opacity
          ctx.stroke()
        })

        // Pulsing central plasma sphere
        const pulse = Math.sin(waveTime * 2.5) * 8 + coreRadius * 0.45
        const coreGrad = ctx.createRadialGradient(cx, cy, 2, cx, cy, pulse)
        coreGrad.addColorStop(0, '#ffffff')
        coreGrad.addColorStop(0.3, palette.primary)
        coreGrad.addColorStop(0.8, palette.secondary)
        coreGrad.addColorStop(1, 'transparent')

        ctx.fillStyle = coreGrad
        ctx.beginPath()
        ctx.arc(cx, cy, pulse, 0, Math.PI * 2)
        ctx.fill()

        ctx.restore()
      }

      // ────────────────────────────────────────────────────────────────────────
      // MODE 4: 3D MATRIX VOLUMETRIC CODE RAIN
      // ────────────────────────────────────────────────────────────────────────
      else if (animDimension === 'matrix') {
        ctx.fillStyle = 'rgba(0, 0, 0, 0.08)'
        ctx.fillRect(0, 0, width, height)

        ctx.font = `${fontSize}px "JetBrains Mono", monospace`

        for (let i = 0; i < drops.length; i++) {
          const char = chars[Math.floor(Math.random() * chars.length)]
          const x = i * fontSize
          const y = drops[i] * fontSize

          // Leading bright character
          ctx.fillStyle = '#ffffff'
          ctx.fillText(char, x, y)

          // Trailing phosphor character
          ctx.fillStyle = palette.primary
          ctx.fillText(char, x, y - fontSize)

          if (y > height && Math.random() > 0.975) {
            drops[i] = 0
          }
          drops[i] += animSpeed * 0.85
        }
      }

      animationFrameId = requestAnimationFrame(render)
    }

    render()

    return () => {
      cancelAnimationFrame(animationFrameId)
      window.removeEventListener('resize', handleResize)
      if (interactive) {
        window.removeEventListener('mousemove', handleMouseMove)
        window.removeEventListener('mousedown', handleMouseDown)
        window.removeEventListener('mouseup', handleMouseUp)
      }
    }
  }, [theme, animDimension, animSpeed, animGlow, interactive, opacity])

  return (
    <canvas
      ref={canvasRef}
      className={`cyber-canvas-3d4d ${className}`}
      style={{
        position: interactive ? 'relative' : 'fixed',
        top: 0,
        left: 0,
        width: '100%',
        height: '100%',
        pointerEvents: interactive ? 'auto' : 'none',
        zIndex: interactive ? 1 : 0,
        cursor: interactive ? 'grab' : 'default',
        opacity: opacity,
        display: animDimension === 'off' ? 'none' : 'block',
      }}
    />
  )
}
