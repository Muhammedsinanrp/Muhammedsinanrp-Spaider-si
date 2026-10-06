import React from 'react'
import { useStore, CyberTheme, AnimationDimension } from '../store/useStore'
import CyberCanvas3D4D from './CyberCanvas3D4D'

const THEMES: { id: CyberTheme; name: string; icon: string; color: string; desc: string }[] = [
  { id: 'cyberpunk', name: 'Cyberpunk Neon', icon: '⚡', color: '#00e5ff', desc: 'Electric cyan & ultraviolet glow' },
  { id: 'matrix',    name: 'Matrix Terminal', icon: '🟢', color: '#00ff66', desc: 'Phosphor green digital rain' },
  { id: 'crimson',   name: 'Crimson Breach',  icon: '🔴', color: '#ff2a4b', desc: 'Red team offensive posture' },
  { id: 'synthwave', name: 'Synthwave 80s',   icon: '🌴', color: '#ff2a85', desc: 'Hot fuchsia & laser cyan' },
  { id: 'quantum',   name: 'Quantum Arctic',  icon: '❄️', color: '#38bdf8', desc: 'Deep sapphire & ice blue grid' },
  { id: 'void',      name: 'Deep Void OLED',  icon: '🌑', color: '#e2e8f0', desc: 'Pure black stealth contrast' },
]

const MODES: { id: AnimationDimension; name: string; icon: string; desc: string }[] = [
  { id: '4d',      name: '4D Tesseract',    icon: '🔮', desc: '4-Dimensional hypercube rotation' },
  { id: '3d',      name: '3D Cyber Grid',   icon: '🌐', desc: 'Undulating spatial perspective waves' },
  { id: 'quantum', name: 'Quantum Core',    icon: '⚛️', desc: '3D Gyroscopic plasma orb' },
  { id: 'matrix',  name: 'Matrix Code Rain',icon: '🌧️', desc: 'Volumetric phosphor streaming text' },
  { id: 'off',     name: 'Disable FX',      icon: '⏹️', desc: 'Minimal static background' },
]

export default function HoloViewerModal() {
  const {
    holoViewerOpen,
    setHoloViewerOpen,
    theme,
    setTheme,
    animDimension,
    setAnimDimension,
    animSpeed,
    setAnimSpeed,
    animGlow,
    setAnimGlow,
  } = useStore()

  if (!holoViewerOpen) return null

  return (
    <div
      style={{
        position: 'fixed',
        inset: 0,
        zIndex: 500,
        background: 'rgba(2, 4, 10, 0.88)',
        backdropFilter: 'blur(12px)',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '24px',
      }}
      onClick={(e) => {
        if (e.target === e.currentTarget) setHoloViewerOpen(false)
      }}
    >
      <div
        style={{
          width: '100%',
          maxWidth: 1080,
          height: '88vh',
          maxHeight: 780,
          background: 'var(--color-bg-surface, #0d0d14)',
          borderRadius: 20,
          border: '1px solid var(--color-cyan, #00e5ff)',
          boxShadow: '0 0 50px rgba(0, 229, 255, 0.25), 0 20px 40px rgba(0, 0, 0, 0.7)',
          display: 'flex',
          flexDirection: 'column',
          overflow: 'hidden',
          position: 'relative',
        }}
      >
        {/* Header bar */}
        <div
          style={{
            padding: '16px 24px',
            borderBottom: '1px solid var(--color-border, rgba(255,255,255,0.08))',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            background: 'var(--color-bg-elevated, #12121c)',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <span style={{ fontSize: '1.5rem' }}>🔮</span>
            <div>
              <div style={{ fontSize: '1rem', fontWeight: 800, letterSpacing: '0.08em', color: 'var(--color-cyan, #00e5ff)' }}>
                4D TESSERACT & 3D CYBER VISUALIZER
              </div>
              <div style={{ fontSize: '0.7rem', color: 'var(--color-text-muted, #888)' }}>
                Interactive R⁴ → R³ → R² Stereographic Projection Engine
              </div>
            </div>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <button
              onClick={() => setHoloViewerOpen(false)}
              style={{
                background: 'rgba(255,255,255,0.06)',
                border: '1px solid var(--color-border, rgba(255,255,255,0.1))',
                borderRadius: 8,
                padding: '6px 14px',
                color: 'var(--color-text-primary, #fff)',
                cursor: 'pointer',
                fontWeight: 700,
                fontSize: '0.8rem',
              }}
            >
              ✕ Close
            </button>
          </div>
        </div>

        {/* Main Stage */}
        <div style={{ flex: 1, display: 'flex', position: 'relative', overflow: 'hidden' }}>
          {/* 3D/4D Canvas Viewport */}
          <div
            style={{
              flex: 1,
              position: 'relative',
              background: '#020308',
              overflow: 'hidden',
              cursor: 'grab',
            }}
          >
            <CyberCanvas3D4D interactive={true} opacity={1.0} />

            {/* Quick floating drag hint */}
            <div
              style={{
                position: 'absolute',
                bottom: 16,
                left: 20,
                padding: '6px 12px',
                borderRadius: 20,
                background: 'rgba(0,0,0,0.65)',
                border: '1px solid rgba(255,255,255,0.1)',
                fontSize: '0.7rem',
                color: 'var(--color-cyan, #00e5ff)',
                display: 'flex',
                alignItems: 'center',
                gap: 6,
                pointerEvents: 'none',
              }}
            >
              <span>🖱️</span>
              <span>Click & Drag to rotate in 4th dimension (XW & ZW planes)</span>
            </div>
          </div>

          {/* Right Control Sidebar */}
          <div
            style={{
              width: 320,
              background: 'var(--color-bg-elevated, #12121c)',
              borderLeft: '1px solid var(--color-border, rgba(255,255,255,0.08))',
              padding: '20px',
              display: 'flex',
              flexDirection: 'column',
              gap: 20,
              overflowY: 'auto',
            }}
          >
            {/* Dimension Mode Selector */}
            <div>
              <div style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--color-cyan, #00e5ff)', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 10 }}>
                1. Hologram Dimension
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                {MODES.map((m) => (
                  <button
                    key={m.id}
                    onClick={() => setAnimDimension(m.id)}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: 10,
                      padding: '8px 12px',
                      borderRadius: 8,
                      border: `1px solid ${animDimension === m.id ? 'var(--color-cyan, #00e5ff)' : 'rgba(255,255,255,0.06)'}`,
                      background: animDimension === m.id ? 'rgba(0, 229, 255, 0.12)' : 'rgba(255,255,255,0.02)',
                      color: '#fff',
                      cursor: 'pointer',
                      textAlign: 'left',
                      transition: 'all 0.15s ease',
                    }}
                  >
                    <span style={{ fontSize: '1.2rem' }}>{m.icon}</span>
                    <div style={{ flex: 1 }}>
                      <div style={{ fontSize: '0.8rem', fontWeight: 700 }}>{m.name}</div>
                      <div style={{ fontSize: '0.65rem', color: 'var(--color-text-muted, #888)' }}>{m.desc}</div>
                    </div>
                  </button>
                ))}
              </div>
            </div>

            {/* Theme Selector */}
            <div>
              <div style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--color-cyan, #00e5ff)', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 10 }}>
                2. Cyberpunk Themes
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 6 }}>
                {THEMES.map((t) => (
                  <button
                    key={t.id}
                    onClick={() => setTheme(t.id)}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: 6,
                      padding: '8px 10px',
                      borderRadius: 8,
                      border: `1px solid ${theme === t.id ? t.color : 'rgba(255,255,255,0.06)'}`,
                      background: theme === t.id ? `${t.color}20` : 'rgba(255,255,255,0.02)',
                      color: '#fff',
                      cursor: 'pointer',
                      textAlign: 'left',
                      transition: 'all 0.15s ease',
                    }}
                  >
                    <span style={{ fontSize: '1rem' }}>{t.icon}</span>
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ fontSize: '0.72rem', fontWeight: 700, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                        {t.name}
                      </div>
                      <div style={{ width: 14, height: 3, borderRadius: 2, background: t.color, marginTop: 3 }} />
                    </div>
                  </button>
                ))}
              </div>
            </div>

            {/* Animation Controls */}
            <div>
              <div style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--color-cyan, #00e5ff)', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 10 }}>
                3. Simulation Speed ({animSpeed}x)
              </div>
              <input
                type="range"
                min="0.2"
                max="3"
                step="0.2"
                value={animSpeed}
                onChange={(e) => setAnimSpeed(parseFloat(e.target.value))}
                style={{ width: '100%', accentColor: 'var(--color-cyan, #00e5ff)', cursor: 'pointer' }}
              />
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.65rem', color: '#666', marginTop: 4 }}>
                <span>0.2x Hypnotic</span>
                <span>1.0x Normal</span>
                <span>3.0x Hyperdrive</span>
              </div>
            </div>

            {/* Glow toggle */}
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '10px', background: 'rgba(255,255,255,0.02)', borderRadius: 8 }}>
              <span style={{ fontSize: '0.75rem', fontWeight: 600 }}>Quantum Laser Glow</span>
              <button
                onClick={() => setAnimGlow(!animGlow)}
                style={{
                  padding: '4px 10px',
                  borderRadius: 20,
                  border: '1px solid var(--color-cyan, #00e5ff)',
                  background: animGlow ? 'var(--color-cyan, #00e5ff)' : 'transparent',
                  color: animGlow ? '#000' : 'var(--color-cyan, #00e5ff)',
                  fontWeight: 700,
                  fontSize: '0.7rem',
                  cursor: 'pointer',
                }}
              >
                {animGlow ? 'ON' : 'OFF'}
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
