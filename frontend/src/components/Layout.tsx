import { useState, useRef, useEffect } from 'react'
import { Outlet, useNavigate, useLocation } from 'react-router-dom'
import { useStore } from '../store/useStore'
import ToolsPanel from './ToolsPanel'

const NAV_ITEMS = [
  { icon: '🏠', label: 'Dashboard', path: '/dashboard', section: 'OVERVIEW' },
  { icon: '🧠', label: 'AI Analyst', path: '/ai-analyst', section: 'AI CORE' },
  { icon: '🌐', label: 'Network Map', path: '/network-map', section: 'AI CORE' },
  { icon: '🔴', label: 'Scans', path: '/scans', section: 'RED TEAM' },
  { icon: '📡', label: 'Assets', path: '/assets', section: 'RED TEAM' },
  { icon: '🕷️', label: 'Web Security', path: '/web-security', section: 'RED TEAM' },
  { icon: '🔎', label: 'Findings', path: '/findings', section: 'RED TEAM', badge: true },
  { icon: '🛡️', label: 'Alerts', path: '/alerts', section: 'BLUE TEAM', badge: true },
  { icon: '🦠', label: 'Malware Analysis', path: '/malware', section: 'BLUE TEAM' },
  { icon: '🟣', label: 'Purple Team', path: '/purple', section: 'PURPLE TEAM' },
  { icon: '🧬', label: 'MITRE ATT&CK', path: '/mitre', section: 'PURPLE TEAM' },
  { icon: '📑', label: 'Reports', path: '/reports', section: 'REPORTING' },
  { icon: '🔌', label: 'Plugins', path: '/plugins', section: 'PLATFORM' },
]

export default function Layout() {
  const navigate = useNavigate()
  const location = useLocation()
  const { mode, setMode } = useStore()

  const [toolsOpen, setToolsOpen] = useState(false)
  const [toolsDropdown, setToolsDropdown] = useState(false)
  const dropdownRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    const handleOutsideClick = (e: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target as Node)) {
        setToolsDropdown(false)
      }
    }
    if (toolsDropdown) document.addEventListener('mousedown', handleOutsideClick)
    return () => document.removeEventListener('mousedown', handleOutsideClick)
  }, [toolsDropdown])

  const grouped = NAV_ITEMS.reduce((acc, item) => {
    if (!acc[item.section]) acc[item.section] = []
    acc[item.section].push(item)
    return acc
  }, {} as Record<string, typeof NAV_ITEMS>)

  return (
    <div className="app-layout">
      {/* Matrix background */}
      <div className="matrix-bg" />

      {/* Sidebar */}
      <aside className="sidebar animate-slide-in">
        <div className="brand">
          <div className="brand-icon">🕷️</div>
          <div>
            <div className="brand-name">SPAIDER</div>
            <div className="brand-sub">AI SECURITY COMMAND</div>
          </div>
        </div>

        {/* Mode Selector */}
        <div className="mode-selector">
          {(['RED', 'BLUE', 'PURPLE'] as const).map(m => (
            <button
              key={m}
              className={`mode-btn ${m.toLowerCase()} ${mode === m ? 'active' : ''}`}
              onClick={() => setMode(m)}
            >
              {m}
            </button>
          ))}
        </div>

        {/* Navigation */}
        <nav className="nav">
          {Object.entries(grouped).map(([section, items]) => (
            <div key={section}>
              <div className="nav-section-label">{section}</div>
              {items.map(item => (
                <button
                  key={item.path}
                  className={`nav-item ${location.pathname === item.path ? 'active' : ''}`}
                  onClick={() => navigate(item.path)}
                >
                  <span className="nav-icon">{item.icon}</span>
                  {item.label}
                  {item.badge && <span className="nav-badge">!</span>}
                </button>
              ))}
            </div>
          ))}
        </nav>

        {/* Tools launcher in sidebar */}
        <div style={{ padding: 'var(--space-3) var(--space-4)', borderTop: '1px solid var(--color-border)' }}>
          <button
            onClick={() => setToolsOpen(true)}
            style={{
              width: '100%', display: 'flex', alignItems: 'center', gap: 'var(--space-3)',
              padding: 'var(--space-3)', borderRadius: 'var(--radius-md)',
              border: '1px solid var(--color-border)',
              background: 'var(--color-bg-elevated)', cursor: 'pointer',
              color: 'var(--color-text-primary)', transition: 'all 0.2s',
            }}
            onMouseEnter={e => {
              const el = e.currentTarget as HTMLButtonElement
              el.style.borderColor = 'var(--color-cyan)'
              el.style.background = 'var(--color-cyan-dim)'
            }}
            onMouseLeave={e => {
              const el = e.currentTarget as HTMLButtonElement
              el.style.borderColor = 'var(--color-border)'
              el.style.background = 'var(--color-bg-elevated)'
            }}
          >
            <span style={{ fontSize: '1.1rem' }}>🔌</span>
            <div style={{ flex: 1, textAlign: 'left' }}>
              <div style={{ fontSize: '0.8rem', fontWeight: 700, color: 'var(--color-cyan)' }}>Tools</div>
              <div style={{ fontSize: '0.65rem', color: 'var(--color-text-muted)' }}>Nmap · Nuclei · Zeek · YARA…</div>
            </div>
            <span style={{ fontSize: '0.8rem', color: 'var(--color-text-muted)' }}>›</span>
          </button>
        </div>

        {/* System status */}
        <div style={{
          padding: 'var(--space-4)',
          borderTop: '1px solid var(--color-border)',
          fontSize: '0.7rem',
          color: 'var(--color-text-muted)',
        }}>
          <div className="flex items-center gap-2" style={{ marginBottom: 4 }}>
            <span className="status-dot running" />
            <span>API Connected</span>
          </div>
          <div style={{ fontFamily: 'var(--font-mono)', opacity: 0.5 }}>v1.0.0 · SPAIDER AI</div>
        </div>
      </aside>

      {/* Main */}
      <div className="main-content">
        {/* Topbar */}
        <header className="topbar">
          <div className="topbar-search">
            <span className="topbar-search-icon">🔍</span>
            <input className="input" placeholder="Search assets, findings, alerts..." />
          </div>

          {/* Right-side action controls */}
          <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 'var(--space-3)' }}>
            {/* PURPLE TEAM Tool Option in Right Side */}
            <div ref={dropdownRef} className="topbar-tools-wrapper">
              <button
                id="topbar-purple-tools-btn"
                className="topbar-purple-tools-btn"
                onClick={() => setToolsDropdown(prev => !prev)}
                title="PURPLE TEAM & Security Tools (Nmap, Nuclei, Zeek, YARA...)"
              >
                <span style={{ fontSize: '1rem' }}>🟣</span>
                <span>PURPLE TOOLS</span>
                <span className="topbar-purple-tools-badge">10</span>
                <span style={{ fontSize: '0.65rem', opacity: 0.8 }}>▾</span>
              </button>

              {toolsDropdown && (
                <div className="topbar-tools-dropdown align-right animate-fade-in">
                  <div className="tools-dropdown-header">
                    <div style={{ fontWeight: 700, fontSize: '0.8rem', color: 'var(--color-purple)' }}>🟣 Purple Team Security Command</div>
                    <div style={{ fontSize: '0.7rem', color: 'var(--color-text-muted)' }}>Offensive & Defensive Tool Suite</div>
                  </div>

                  <div style={{ padding: '8px' }}>
                    <button
                      className="tools-dropdown-primary-action"
                      style={{
                        borderColor: 'rgba(168, 85, 247, 0.4)',
                        background: 'linear-gradient(135deg, rgba(168, 85, 247, 0.2), rgba(0, 229, 255, 0.1))',
                        color: 'var(--color-purple)',
                      }}
                      onClick={() => {
                        setToolsDropdown(false)
                        setToolsOpen(true)
                      }}
                    >
                      <span>🚀 Launch Interactive Tool Drawer</span>
                      <span style={{ fontSize: '0.7rem', opacity: 0.75, fontWeight: 400 }}>Nmap, Nuclei, Zeek, YARA, Burp, Caido...</span>
                    </button>
                  </div>

                  <div className="tools-dropdown-divider" />

                  <div className="tools-dropdown-list">
                    <button
                      className="tools-dropdown-item"
                      onClick={() => { setToolsDropdown(false); navigate('/purple') }}
                    >
                      <span className="item-icon">🟣</span>
                      <div className="item-text">
                        <div className="item-title" style={{ color: 'var(--color-purple)' }}>Purple Team Validation</div>
                        <div className="item-desc">Validate attacks vs defense detections</div>
                      </div>
                    </button>

                    <button
                      className="tools-dropdown-item"
                      onClick={() => { setToolsDropdown(false); navigate('/mitre') }}
                    >
                      <span className="item-icon">🧬</span>
                      <div className="item-text">
                        <div className="item-title">MITRE ATT&CK Matrix</div>
                        <div className="item-desc">Full matrix coverage & mapping</div>
                      </div>
                    </button>

                    <button
                      className="tools-dropdown-item"
                      onClick={() => { setToolsDropdown(false); navigate('/scans') }}
                    >
                      <span className="item-icon">📡</span>
                      <div className="item-text">
                        <div className="item-title">Nmap Scanner</div>
                        <div className="item-desc">Network discovery & port enumeration</div>
                      </div>
                    </button>

                    <button
                      className="tools-dropdown-item"
                      onClick={() => { setToolsDropdown(false); navigate('/web-security') }}
                    >
                      <span className="item-icon">🕷️</span>
                      <div className="item-text">
                        <div className="item-title">Nuclei Web Security</div>
                        <div className="item-desc">Web & API vulnerability scanning</div>
                      </div>
                    </button>

                    <button
                      className="tools-dropdown-item"
                      onClick={() => { setToolsDropdown(false); navigate('/malware') }}
                    >
                      <span className="item-icon">🦠</span>
                      <div className="item-text">
                        <div className="item-title">YARA Malware Analysis</div>
                        <div className="item-desc">Rule matching & binary static inspection</div>
                      </div>
                    </button>

                    <button
                      className="tools-dropdown-item"
                      onClick={() => { setToolsDropdown(false); navigate('/network-map') }}
                    >
                      <span className="item-icon">🌐</span>
                      <div className="item-text">
                        <div className="item-title">Network Topology Map</div>
                        <div className="item-desc">3D asset relationship & threat visualizer</div>
                      </div>
                    </button>

                    <button
                      className="tools-dropdown-item"
                      onClick={() => { setToolsDropdown(false); navigate('/plugins') }}
                    >
                      <span className="item-icon">🔌</span>
                      <div className="item-text">
                        <div className="item-title">All Plugins & Integrations</div>
                        <div className="item-desc">Burp, Caido, Zeek, Suricata, Wazuh</div>
                      </div>
                    </button>
                  </div>
                </div>
              )}
            </div>

            {/* Quick direct runner trigger button */}
            <button
              onClick={() => setToolsOpen(true)}
              className="topbar-quick-run-btn"
              title="Launch Tool Runner Drawer"
            >
              <span>⚡ Run Tool</span>
            </button>

            <div style={{
              padding: '4px 12px',
              borderRadius: 'var(--radius-sm)',
              fontSize: '0.75rem',
              fontWeight: 700,
              letterSpacing: '0.1em',
              background: mode === 'RED' ? 'var(--color-red-dim)' : mode === 'BLUE' ? 'var(--color-blue-dim)' : 'var(--color-purple-dim)',
              color: mode === 'RED' ? 'var(--color-red)' : mode === 'BLUE' ? 'var(--color-blue)' : 'var(--color-purple)',
              border: `1px solid ${mode === 'RED' ? 'var(--color-red)' : mode === 'BLUE' ? 'var(--color-blue)' : 'var(--color-purple)'}`,
            }}>
              {mode} MODE
            </div>
            <div style={{
              width: 32, height: 32, borderRadius: '50%',
              background: 'linear-gradient(135deg, var(--color-cyan), var(--color-purple))',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              fontSize: '0.875rem', fontWeight: 700, color: '#000',
              cursor: 'pointer',
            }}>A</div>
          </div>
        </header>

        {/* Page content */}
        <div className="page-content animate-fade-in">
          <Outlet />
        </div>
      </div>

      {/* Sliding Tools Panel */}
      <ToolsPanel open={toolsOpen} onClose={() => setToolsOpen(false)} />
    </div>
  )
}
