import { useState, useRef, useEffect } from 'react'
import { Outlet, useNavigate, useLocation } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { experimentApi, targetApi } from '../api/client'
import { useStore, CyberTheme } from '../store/useStore'
import ToolsPanel from './ToolsPanel'
import HoloViewerModal from './HoloViewerModal'
import SpiderWebCanvas from './SpiderWebCanvas'

const THEMES: { id: CyberTheme; name: string; icon: string; color: string }[] = [
  { id: 'cyberpunk', name: 'Cyberpunk Neon',  icon: '⚡', color: '#00e5ff' },
  { id: 'matrix',   name: 'Matrix Terminal',  icon: '🟢', color: '#00ff66' },
  { id: 'crimson',  name: 'Crimson Breach',   icon: '🔴', color: '#ff2a4b' },
  { id: 'synthwave',name: 'Synthwave 80s',    icon: '🌴', color: '#ff2a85' },
  { id: 'quantum',  name: 'Quantum Arctic',   icon: '❄️', color: '#38bdf8' },
  { id: 'void',     name: 'Deep Void OLED',   icon: '🌑', color: '#e2e8f0' },
]

const NAV_ITEMS = [
  // Bug bounty platform navigation
  { icon: '⌂', label: 'Dashboard',      path: '/dashboard',      section: 'OVERVIEW' },
  { icon: '◎', label: 'Targets',        path: '/assets',         section: 'RECON' },
  { icon: '◉', label: 'Recon',          path: '/scans',          section: 'RECON' },
  { icon: '◇', label: 'Attack Surface', path: '/network-map',    section: 'RECON' },
  { icon: '⚡', label: 'AI Hunter',     path: '/ai-analyst',     section: 'AI ENGINE' },
  { icon: '◈', label: 'Vulnerabilities',path: '/findings',       section: 'AI ENGINE', badge: true },
  { icon: '☷', label: 'Evidence',       path: '/alerts',         section: 'AI ENGINE', badge: true },
  { icon: '▣', label: 'Reports',        path: '/reports',        section: 'REPORTING' },
  { icon: '◌', label: 'Automation',     path: '/purple',         section: 'AUTOMATION' },
  { icon: '🕷️', label: 'Web Security',  path: '/web-security',   section: 'TOOLS' },
  { icon: '🦠', label: 'Malware',       path: '/malware',        section: 'TOOLS' },
  { icon: '🧬', label: 'MITRE ATT&CK',  path: '/mitre',          section: 'TOOLS' },
  { icon: '⚙', label: 'Plugins',        path: '/plugins',        section: 'PLATFORM' },
]

export default function Layout() {
  const navigate = useNavigate()
  const location = useLocation()
  const { theme, setTheme, setHoloViewerOpen } = useStore()

  const [toolsOpen, setToolsOpen] = useState(false)
  const [themeDropdown, setThemeDropdown] = useState(false)
  const themeDropdownRef = useRef<HTMLDivElement>(null)

  const { data: targets = [] } = useQuery({
    queryKey: ['layout-targets'],
    queryFn: () => targetApi.list(),
    retry: false,
    refetchInterval: 15000,
  })
  const { data: liveMetrics } = useQuery({
    queryKey: ['layout-live-metrics'],
    queryFn: () => experimentApi.metrics(),
    retry: false,
    refetchInterval: 15000,
  })
  const latestTarget = Array.isArray(targets) && targets.length ? targets[0] : null
  const { data: targetScopes = [] } = useQuery({
    queryKey: ['layout-target-scopes', latestTarget?.id],
    queryFn: () => latestTarget ? targetApi.scopes(String(latestTarget.id)) : Promise.resolve([]),
    enabled: Boolean(latestTarget?.id),
    retry: false,
    refetchInterval: 15000,
  })
  const now = Date.now()
  const hasDocumentedScope = Array.isArray(targetScopes) && targetScopes.some((scope: any) =>
    scope.authorization_status === 'AUTHORIZED' &&
    scope.active_testing === true &&
    scope.authorization_document_present === true &&
    (!scope.valid_from || new Date(scope.valid_from).getTime() <= now) &&
    (!scope.valid_until || new Date(scope.valid_until).getTime() > now)
  )
  const storedUser = (() => {
    try { return JSON.parse(localStorage.getItem('spaider_user') || '{}') } catch { return {} }
  })()
  const handleLogout = () => {
    localStorage.removeItem('spaider_token')
    localStorage.removeItem('spaider_user')
    navigate('/login', { replace: true })
  }

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme)
  }, [theme])

  useEffect(() => {
    const handleOutsideClick = (e: MouseEvent) => {
      if (themeDropdownRef.current && !themeDropdownRef.current.contains(e.target as Node)) {
        setThemeDropdown(false)
      }
    }
    document.addEventListener('mousedown', handleOutsideClick)
    return () => document.removeEventListener('mousedown', handleOutsideClick)
  }, [])

  const currentTheme = THEMES.find(t => t.id === theme) || THEMES[0]

  const grouped = NAV_ITEMS.reduce((acc, item) => {
    if (!acc[item.section]) acc[item.section] = []
    acc[item.section].push(item)
    return acc
  }, {} as Record<string, typeof NAV_ITEMS>)

  return (
    <div className="app-layout">
      {/* 3D Spider Web Background */}
      <SpiderWebCanvas opacity={0.35} />

      {/* Sidebar */}
      <aside className="sidebar animate-slide-in">
        {/* Brand */}
        <div className="brand">
          <div className="brand-icon">🕷️</div>
          <div>
            <div className="brand-name">SPAiDER</div>
            <div className="brand-sub">AI BUG BOUNTY PLATFORM</div>
          </div>
        </div>

        {/* Live target inventory and platform metrics */}
        <div className="active-target-indicator">
          <div className="target-label">LATEST REGISTERED TARGET</div>
          <div className="target-domain" style={{ overflowWrap: 'anywhere' }}>
            {latestTarget?.hostname || latestTarget?.name || 'No target registered'}
          </div>
          <div className="target-stats">
            <span><span className="target-stat-num" style={{ color: '#00e5ff' }}>{Number(liveMetrics?.assets_discovered || 0)}</span> Assets</span>
            <span><span className="target-stat-num" style={{ color: '#a855f7' }}>{Number(liveMetrics?.endpoints_discovered || 0)}</span> Endpoints</span>
            <span><span className="target-stat-num" style={{ color: '#ff3b5c' }}>{Number(liveMetrics?.findings?.total || 0)}</span> Findings</span>
          </div>
          <div style={{ fontSize: '0.61rem', color: 'var(--color-text-muted)', marginTop: 4 }}>
            Platform totals · API-backed
          </div>
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
              <div style={{ fontSize: '0.8rem', fontWeight: 700, color: 'var(--color-cyan)' }}>Security Tools</div>
              <div style={{ fontSize: '0.65rem', color: 'var(--color-text-muted)' }}>Nmap · Nuclei · Subfinder · httpx…</div>
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
          <div style={{ fontFamily: 'var(--font-mono)', opacity: 0.5 }}>v1.0.0 · SPAiDER AI</div>
        </div>
      </aside>

      {/* Main */}
      <div className="main-content">
        {/* Topbar */}
        <header className="topbar">
          <div className="topbar-search">
            <span className="topbar-search-icon">🔍</span>
            <input className="input" placeholder="Search targets, vulns, APIs, endpoints..." />
          </div>

          <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 'var(--space-3)' }}>
            {/* Spider Web FX Button */}
            <button
              onClick={() => setHoloViewerOpen(true)}
              style={{
                display: 'flex', alignItems: 'center', gap: 6,
                padding: '6px 12px', borderRadius: 'var(--radius-md)',
                border: '1px solid var(--color-cyan)',
                background: 'linear-gradient(135deg, var(--color-cyan-dim), transparent)',
                color: 'var(--color-cyan)', fontSize: '0.75rem',
                fontWeight: 800, cursor: 'pointer',
                boxShadow: '0 0 12px var(--color-cyan-dim)',
                letterSpacing: '0.05em',
              }}
              title="Open 3D Attack Surface Visualizer"
            >
              <span>🕸️</span>
              <span>3D MAP</span>
            </button>

            {/* Theme Selector */}
            <div ref={themeDropdownRef} style={{ position: 'relative' }}>
              <button
                onClick={() => setThemeDropdown(prev => !prev)}
                style={{
                  display: 'flex', alignItems: 'center', gap: 6,
                  padding: '6px 12px', borderRadius: 'var(--radius-md)',
                  border: `1px solid ${currentTheme.color}55`,
                  background: 'var(--color-bg-elevated)',
                  color: 'var(--color-text-primary)',
                  fontSize: '0.75rem', fontWeight: 700,
                  cursor: 'pointer', transition: 'all 0.2s ease',
                }}
              >
                <span>{currentTheme.icon}</span>
                <span style={{ fontSize: '0.72rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                  {currentTheme.name.split(' ')[0]}
                </span>
                <div style={{ width: 8, height: 8, borderRadius: '50%', background: currentTheme.color, boxShadow: `0 0 6px ${currentTheme.color}` }} />
                <span style={{ fontSize: '0.65rem', opacity: 0.6 }}>▾</span>
              </button>

              {themeDropdown && (
                <div className="animate-fade-in" style={{
                  position: 'absolute', top: 'calc(100% + 8px)', right: 0,
                  width: 220, background: 'var(--color-bg-elevated)',
                  border: '1px solid var(--color-border-accent)',
                  borderRadius: 'var(--radius-lg)', padding: '8px',
                  boxShadow: '0 10px 30px rgba(0,0,0,0.6)', zIndex: 100,
                }}>
                  <div style={{ padding: '4px 8px 8px', fontSize: '0.68rem', fontWeight: 800, color: 'var(--color-cyan)', textTransform: 'uppercase', letterSpacing: '0.08em', borderBottom: '1px solid var(--color-border)' }}>
                    Platform Themes
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 4, marginTop: 6 }}>
                    {THEMES.map(t => (
                      <button key={t.id} onClick={() => { setTheme(t.id); setThemeDropdown(false) }}
                        style={{
                          display: 'flex', alignItems: 'center', gap: 8,
                          padding: '6px 10px', borderRadius: 'var(--radius-sm)',
                          border: `1px solid ${theme === t.id ? t.color : 'transparent'}`,
                          background: theme === t.id ? `${t.color}20` : 'transparent',
                          color: '#fff', cursor: 'pointer', fontSize: '0.75rem',
                          fontWeight: theme === t.id ? 700 : 500, textAlign: 'left',
                          transition: 'all 0.15s ease',
                        }}>
                        <span>{t.icon}</span>
                        <span style={{ flex: 1 }}>{t.name}</span>
                        <div style={{ width: 10, height: 10, borderRadius: '50%', background: t.color, boxShadow: theme === t.id ? `0 0 8px ${t.color}` : 'none' }} />
                      </button>
                    ))}
                  </div>
                </div>
              )}
            </div>

            {/* Run Tool button */}
            <button onClick={() => setToolsOpen(true)} className="topbar-quick-run-btn" title="Launch Tool Runner Drawer">
              <span>⚡ Run Tool</span>
            </button>

            {/* Scope status reflects a real saved scope, its validity, and its document reference */}
            <div
              title={hasDocumentedScope ? 'The latest registered target has an active scope and a document reference.' : 'No active, unexpired documented scope is recorded for the latest registered target.'}
              style={{
                padding: '4px 12px', borderRadius: 'var(--radius-sm)',
                fontSize: '0.7rem', fontWeight: 700, letterSpacing: '0.04em',
                background: hasDocumentedScope ? 'rgba(0,255,136,0.12)' : 'rgba(255,152,0,0.12)',
                color: hasDocumentedScope ? '#00ff88' : '#ffb74d',
                border: `1px solid ${hasDocumentedScope ? 'rgba(0,255,136,0.4)' : 'rgba(255,152,0,0.4)'}`,
              }}
            >
              {hasDocumentedScope ? '✓ DOCUMENTED SCOPE' : '⚠ SCOPE REQUIRED'}
            </div>

            <button
              type="button"
              onClick={handleLogout}
              title={`Sign out ${storedUser.username || 'user'}`}
              aria-label="Sign out"
              style={{
                width: 32, height: 32, borderRadius: '50%',
                background: 'linear-gradient(135deg, var(--color-cyan), var(--color-purple))',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                fontSize: '0.875rem', fontWeight: 800, color: '#000', cursor: 'pointer',
                border: 0,
              }}>{String(storedUser.username || 'U').slice(0, 1).toUpperCase()}</button>
          </div>
        </header>

        {/* Page content */}
        <div className="page-content animate-fade-in">
          <Outlet />
        </div>
      </div>

      {/* Sliding Tools Panel */}
      <ToolsPanel open={toolsOpen} onClose={() => setToolsOpen(false)} />

      {/* 3D Holographic Viewer Modal */}
      <HoloViewerModal />
    </div>
  )
}
