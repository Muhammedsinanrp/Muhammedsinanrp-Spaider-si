import { useState, useEffect, useRef } from 'react'
import { useMutation } from '@tanstack/react-query'
import { api } from '../api/client'
import toast from 'react-hot-toast'

// ── Tool Definitions ──────────────────────────────────────────────────
const TOOLS = [
  {
    id: 'nmap',
    name: 'Nmap',
    version: '7.94',
    icon: '📡',
    category: 'Network',
    color: '#00e5ff',
    desc: 'Network scanner — port scanning, OS detection, service fingerprinting',
    status: 'ready',
    fields: [
      { key: 'target',    label: 'Target(s)',   placeholder: '192.168.1.0/24  or  10.0.0.1', type: 'text' },
      { key: 'scan_type', label: 'Scan Profile', type: 'select',
        options: ['quick','full','stealth','udp','os','version','web'] },
      { key: 'ports',     label: 'Ports (optional)', placeholder: '22,80,443  or  1-1024', type: 'text' },
    ],
    task: 'run_nmap_scan',
    queue: 'RED',
  },
  {
    id: 'nuclei',
    name: 'Nuclei',
    version: '3.2.4',
    icon: '⚡',
    category: 'Web',
    color: '#ff3b5c',
    desc: 'Template-based vulnerability scanner — 8000+ checks for XSS, SQLi, CVEs, CORS, JWT…',
    status: 'ready',
    fields: [
      { key: 'target',     label: 'Target URL', placeholder: 'https://target.example.com', type: 'text' },
      { key: 'templates',  label: 'Templates',  type: 'select',
        options: ['cves','vulnerabilities','misconfiguration','exposures','takeovers','all'] },
      { key: 'severity',   label: 'Min Severity', type: 'select',
        options: ['critical','high','medium','low','info'] },
    ],
    task: 'run_nuclei_scan',
    queue: 'RED',
  },
  {
    id: 'zeek',
    name: 'Zeek',
    version: '6.0.0',
    icon: '🕸️',
    category: 'Network',
    color: '#a855f7',
    desc: 'Network analysis framework — structured logs: conn, DNS, HTTP, TLS, files, notices',
    status: 'ready',
    fields: [
      { key: 'interface', label: 'Interface', placeholder: 'eth0  or  leave blank for PCAP', type: 'text' },
      { key: 'pcap',      label: 'PCAP File', placeholder: '/app/pcap_files/capture.pcap', type: 'text' },
      { key: 'scripts',   label: 'Scripts',   type: 'select',
        options: ['default','detect-protocols','detect-malware','conn-summary'] },
    ],
    task: 'analyze_pcap',
    queue: 'BLUE',
  },
  {
    id: 'suricata',
    name: 'Suricata',
    version: '7.0.3',
    icon: '🛡️',
    category: 'IDS',
    color: '#ff9800',
    desc: 'Network threat detection — IDS/IPS with signature and anomaly-based detection',
    status: 'ready',
    fields: [
      { key: 'interface', label: 'Interface', placeholder: 'eth0', type: 'text' },
      { key: 'ruleset',   label: 'Ruleset',   type: 'select',
        options: ['et/open','emerging-threats','custom','all'] },
      { key: 'mode',      label: 'Mode',      type: 'select', options: ['ids','ips','af-packet'] },
    ],
    task: 'start_suricata',
    queue: 'BLUE',
  },
  {
    id: 'wazuh',
    name: 'Wazuh',
    version: '4.8.0',
    icon: '🔍',
    category: 'SIEM',
    color: '#3b82f6',
    desc: 'Open-source SIEM/XDR — log analysis, FIM, vulnerability detection, compliance',
    status: 'disabled',
    fields: [
      { key: 'manager',  label: 'Manager URL', placeholder: 'https://wazuh.local:55000', type: 'text' },
      { key: 'api_user', label: 'API User',    placeholder: 'wazuh-wui', type: 'text' },
      { key: 'api_pass', label: 'API Pass',    placeholder: '••••••••', type: 'password' },
    ],
    task: 'connect_wazuh',
    queue: 'BLUE',
  },
  {
    id: 'yara',
    name: 'YARA',
    version: '4.5.1',
    icon: '🦠',
    category: 'Malware',
    color: '#ff3b5c',
    desc: 'Pattern matching engine for malware identification — custom rules engine',
    status: 'ready',
    fields: [
      { key: 'file',      label: 'File / Directory', placeholder: '/app/malware_samples/sample.exe', type: 'text' },
      { key: 'rules_dir', label: 'Rules Directory',  placeholder: '/app/yara_rules/', type: 'text' },
      { key: 'recursive', label: 'Recursive Scan',   type: 'select', options: ['yes','no'] },
    ],
    task: 'analyze_malware',
    queue: 'BLUE',
  },
  {
    id: 'burp',
    name: 'Burp Suite',
    version: '2024.5',
    icon: '🔥',
    category: 'Web Proxy',
    color: '#ff6b35',
    desc: 'Industry standard web security testing — proxy, scanner, intruder, repeater',
    status: 'external',
    fields: [
      { key: 'proxy_url', label: 'Proxy URL',  placeholder: 'http://127.0.0.1:8080', type: 'text' },
      { key: 'api_key',   label: 'REST API Key', placeholder: 'burp-api-key', type: 'text' },
      { key: 'scope',     label: 'Scope URL',  placeholder: 'https://target.com', type: 'text' },
    ],
    task: 'burp_scan',
    queue: 'RED',
  },
  {
    id: 'caido',
    name: 'Caido',
    version: '0.42',
    icon: '🌊',
    category: 'Web Proxy',
    color: '#00b8d4',
    desc: 'Modern web proxy with Automate fuzzing — intercept, replay, scan API endpoints',
    status: 'external',
    fields: [
      { key: 'url',     label: 'Caido URL', placeholder: 'http://127.0.0.1:8080', type: 'text' },
      { key: 'api_key', label: 'API Key',   placeholder: 'caido-api-key', type: 'text' },
    ],
    task: 'caido_scan',
    queue: 'RED',
  },
  {
    id: 'masscan',
    name: 'Masscan',
    version: '1.3.2',
    icon: '🚀',
    category: 'Network',
    color: '#00e5ff',
    desc: 'Ultra-fast port scanner — scan the entire internet in under 6 minutes',
    status: 'ready',
    fields: [
      { key: 'target', label: 'Target Range', placeholder: '10.0.0.0/8', type: 'text' },
      { key: 'ports',  label: 'Port Range',   placeholder: '0-65535', type: 'text' },
      { key: 'rate',   label: 'Packets/sec',  placeholder: '1000', type: 'text' },
    ],
    task: 'run_masscan',
    queue: 'RED',
  },
  {
    id: 'tshark',
    name: 'tshark / Wireshark',
    version: '4.2.0',
    icon: '🦈',
    category: 'Packet',
    color: '#00e5ff',
    desc: 'Deep packet inspection — protocol dissection, stream following, statistics',
    status: 'ready',
    fields: [
      { key: 'file',      label: 'PCAP File',   placeholder: '/app/pcap_files/capture.pcap', type: 'text' },
      { key: 'filter',    label: 'Display Filter', placeholder: 'http.request or dns', type: 'text' },
      { key: 'protocol',  label: 'Protocol',    type: 'select',
        options: ['all','http','dns','tls','tcp','udp','icmp'] },
    ],
    task: 'analyze_pcap',
    queue: 'BLUE',
  },
]

const CAT_COLORS: Record<string, string> = {
  Network: 'var(--color-cyan)',
  Web: 'var(--color-red)',
  'Web Proxy': 'var(--color-high)',
  IDS: 'var(--color-medium)',
  SIEM: 'var(--color-blue)',
  Malware: 'var(--color-critical)',
  Packet: 'var(--color-cyan)',
}

const STATUS_LABELS: Record<string, { label: string; color: string }> = {
  ready:    { label: 'Ready',    color: 'var(--color-safe)' },
  disabled: { label: 'Disabled', color: 'var(--color-text-muted)' },
  external: { label: 'External', color: 'var(--color-medium)' },
  running:  { label: 'Running',  color: 'var(--color-cyan)' },
}

// ── Props ─────────────────────────────────────────────────────────────
interface ToolsPanelProps {
  open: boolean
  onClose: () => void
}

export default function ToolsPanel({ open, onClose }: ToolsPanelProps) {
  const [activeTool, setActiveTool] = useState<string | null>(null)
  const [formData, setFormData] = useState<Record<string, Record<string, string>>>({})
  const [search, setSearch] = useState('')
  const [catFilter, setCatFilter] = useState('All')
  const [runningTools, setRunningTools] = useState<Set<string>>(new Set())
  const panelRef = useRef<HTMLDivElement>(null)

  // Close on backdrop click
  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (panelRef.current && !panelRef.current.contains(e.target as Node)) {
        onClose()
      }
    }
    if (open) document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [open, onClose])

  // Close on Escape
  useEffect(() => {
    const handler = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose() }
    if (open) document.addEventListener('keydown', handler)
    return () => document.removeEventListener('keydown', handler)
  }, [open, onClose])

  const setField = (toolId: string, key: string, value: string) => {
    setFormData(prev => ({
      ...prev,
      [toolId]: { ...(prev[toolId] || {}), [key]: value },
    }))
  }

  const launchTool = async (tool: typeof TOOLS[0]) => {
    if (tool.status === 'disabled') { toast.error(`${tool.name} is not configured`); return }
    if (tool.status === 'external') { toast(`Open ${tool.name} externally and configure proxy settings`, { icon: 'ℹ️' }); return }

    setRunningTools(prev => new Set(prev).add(tool.id))
    toast.loading(`Launching ${tool.name}...`, { id: tool.id })

    try {
      const fields = formData[tool.id] || {}
      const targets = fields.target ? [fields.target] : []
      await api.post('/scans', {
        name: `${tool.name} — ${targets[0] || 'default'}`,
        mode: tool.queue,
        plugin: tool.id,
        targets,
        options: fields,
      })
      toast.success(`${tool.name} launched!`, { id: tool.id })
    } catch {
      toast.success(`${tool.name} queued (demo mode)`, { id: tool.id })
    } finally {
      setTimeout(() => {
        setRunningTools(prev => { const s = new Set(prev); s.delete(tool.id); return s })
      }, 3000)
    }
  }

  const categories = ['All', ...Array.from(new Set(TOOLS.map(t => t.category)))]
  const filtered = TOOLS.filter(t => {
    const matchCat = catFilter === 'All' || t.category === catFilter
    const matchSearch = !search || t.name.toLowerCase().includes(search.toLowerCase()) ||
      t.desc.toLowerCase().includes(search.toLowerCase())
    return matchCat && matchSearch
  })

  const activeTool_ = TOOLS.find(t => t.id === activeTool)

  return (
    <>
      {/* Backdrop */}
      <div
        style={{
          position: 'fixed', inset: 0, zIndex: 200,
          background: 'rgba(0,0,0,0.6)',
          backdropFilter: 'blur(4px)',
          opacity: open ? 1 : 0,
          pointerEvents: open ? 'all' : 'none',
          transition: 'opacity 0.3s ease',
        }}
      />

      {/* Sliding Panel */}
      <div
        ref={panelRef}
        style={{
          position: 'fixed',
          top: 0, right: 0, bottom: 0,
          width: activeTool_ ? 780 : 480,
          zIndex: 300,
          background: 'var(--color-bg-surface)',
          borderLeft: '1px solid var(--color-border-accent)',
          display: 'flex',
          flexDirection: 'column',
          transform: open ? 'translateX(0)' : 'translateX(100%)',
          transition: 'transform 0.35s cubic-bezier(0.16,1,0.3,1), width 0.3s ease',
          boxShadow: '-20px 0 60px rgba(0,0,0,0.5)',
        }}
      >
        {/* ── Header ── */}
        <div style={{
          padding: 'var(--space-4) var(--space-5)',
          borderBottom: '1px solid var(--color-border)',
          display: 'flex', alignItems: 'center', gap: 'var(--space-3)',
          background: 'var(--color-bg-elevated)',
          flexShrink: 0,
        }}>
          <div style={{
            width: 36, height: 36, borderRadius: 'var(--radius-md)',
            background: 'linear-gradient(135deg, var(--color-cyan), var(--color-purple))',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            fontSize: '1.1rem', flexShrink: 0,
          }}>🔌</div>
          <div style={{ flex: 1 }}>
            <div style={{ fontFamily: 'var(--font-display)', fontWeight: 700, fontSize: '1rem', letterSpacing: '0.1em', color: 'var(--color-cyan)' }}>
              SPAIDER TOOLS
            </div>
            <div style={{ fontSize: '0.7rem', color: 'var(--color-text-muted)' }}>
              {TOOLS.filter(t => t.status === 'ready').length} ready · {TOOLS.filter(t => t.status === 'external').length} external
            </div>
          </div>
          {activeTool_ && (
            <button className="btn btn-ghost btn-sm" onClick={() => setActiveTool(null)}>
              ← Back
            </button>
          )}
          <button
            onClick={onClose}
            style={{
              background: 'none', border: 'none', cursor: 'pointer',
              color: 'var(--color-text-muted)', fontSize: '1.2rem',
              padding: 'var(--space-1)', borderRadius: 'var(--radius-sm)',
              transition: 'color 0.15s',
            }}
            onMouseEnter={e => (e.currentTarget.style.color = 'var(--color-text-primary)')}
            onMouseLeave={e => (e.currentTarget.style.color = 'var(--color-text-muted)')}
          >✕</button>
        </div>

        <div style={{ display: 'flex', flex: 1, overflow: 'hidden' }}>

          {/* ── Tool List ── */}
          <div style={{
            width: activeTool_ ? 280 : '100%',
            flexShrink: 0,
            display: 'flex', flexDirection: 'column',
            borderRight: activeTool_ ? '1px solid var(--color-border)' : 'none',
            transition: 'width 0.3s ease',
            overflow: 'hidden',
          }}>
            {/* Search + Filter */}
            <div style={{ padding: 'var(--space-3) var(--space-4)', borderBottom: '1px solid var(--color-border)', flexShrink: 0 }}>
              <input
                className="input"
                placeholder="Search tools..."
                value={search}
                onChange={e => setSearch(e.target.value)}
                style={{ marginBottom: 'var(--space-2)' }}
              />
              <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                {categories.map(cat => (
                  <button
                    key={cat}
                    onClick={() => setCatFilter(cat)}
                    style={{
                      padding: '2px 8px', borderRadius: 'var(--radius-sm)',
                      border: `1px solid ${catFilter === cat ? 'var(--color-cyan)' : 'var(--color-border)'}`,
                      background: catFilter === cat ? 'var(--color-cyan-dim)' : 'transparent',
                      color: catFilter === cat ? 'var(--color-cyan)' : 'var(--color-text-muted)',
                      fontSize: '0.65rem', fontWeight: 700, cursor: 'pointer',
                      letterSpacing: '0.06em', textTransform: 'uppercase',
                    }}
                  >{cat}</button>
                ))}
              </div>
            </div>

            {/* Tool Cards */}
            <div style={{ flex: 1, overflowY: 'auto', padding: 'var(--space-3)' }}>
              {filtered.map(tool => {
                const isActive = activeTool === tool.id
                const isRunning = runningTools.has(tool.id)
                const st = STATUS_LABELS[isRunning ? 'running' : tool.status]
                return (
                  <div
                    key={tool.id}
                    onClick={() => setActiveTool(isActive ? null : tool.id)}
                    style={{
                      padding: 'var(--space-3)',
                      borderRadius: 'var(--radius-md)',
                      border: `1px solid ${isActive ? tool.color + '88' : 'var(--color-border)'}`,
                      background: isActive ? `${tool.color}12` : 'var(--color-bg-elevated)',
                      cursor: 'pointer',
                      marginBottom: 6,
                      transition: 'all 0.15s',
                      position: 'relative',
                      overflow: 'hidden',
                    }}
                    onMouseEnter={e => { if (!isActive) (e.currentTarget as HTMLDivElement).style.borderColor = tool.color + '55' }}
                    onMouseLeave={e => { if (!isActive) (e.currentTarget as HTMLDivElement).style.borderColor = 'var(--color-border)' }}
                  >
                    {/* Accent line */}
                    <div style={{ position: 'absolute', top: 0, left: 0, right: 0, height: 2, background: isActive ? tool.color : 'transparent', transition: 'background 0.2s' }} />

                    <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
                      <span style={{ fontSize: '1.2rem' }}>{tool.icon}</span>
                      <div style={{ flex: 1, minWidth: 0 }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                          <span style={{ fontWeight: 700, fontSize: '0.875rem' }}>{tool.name}</span>
                          <span style={{ fontSize: '0.6rem', color: 'var(--color-text-muted)', fontFamily: 'var(--font-mono)' }}>v{tool.version}</span>
                        </div>
                        <div style={{ fontSize: '0.65rem', fontWeight: 700, color: CAT_COLORS[tool.category] || 'var(--color-cyan)', letterSpacing: '0.08em', textTransform: 'uppercase' }}>
                          {tool.category}
                        </div>
                      </div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 4, flexShrink: 0 }}>
                        {isRunning && <span className="status-dot running" />}
                        <span style={{ fontSize: '0.65rem', color: st.color, fontWeight: 700 }}>{st.label}</span>
                        <span style={{ fontSize: '0.8rem', color: isActive ? 'var(--color-cyan)' : 'var(--color-text-muted)' }}>›</span>
                      </div>
                    </div>

                    {!activeTool_ && (
                      <div style={{ fontSize: '0.75rem', color: 'var(--color-text-muted)', marginTop: 4, lineHeight: 1.4 }} className="truncate">
                        {tool.desc}
                      </div>
                    )}
                  </div>
                )
              })}
            </div>

            {/* Footer */}
            <div style={{
              padding: 'var(--space-3) var(--space-4)',
              borderTop: '1px solid var(--color-border)',
              fontSize: '0.7rem', color: 'var(--color-text-muted)',
              flexShrink: 0,
            }}>
              <div className="flex items-center gap-2">
                <span className="status-dot running" />
                <span>Plugin SDK — discover · scan · analyze · normalize · report</span>
              </div>
            </div>
          </div>

          {/* ── Tool Detail / Launch Panel ── */}
          {activeTool_ && (
            <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }} className="animate-fade-in">
              {/* Tool header */}
              <div style={{
                padding: 'var(--space-5)',
                borderBottom: '1px solid var(--color-border)',
                background: `${activeTool_.color}0a`,
                flexShrink: 0,
              }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)', marginBottom: 'var(--space-3)' }}>
                  <div style={{
                    width: 48, height: 48, borderRadius: 'var(--radius-lg)',
                    background: `${activeTool_.color}22`,
                    border: `2px solid ${activeTool_.color}55`,
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                    fontSize: '1.6rem',
                    boxShadow: `0 0 20px ${activeTool_.color}33`,
                  }}>{activeTool_.icon}</div>
                  <div>
                    <div style={{ fontWeight: 800, fontSize: '1.2rem' }}>{activeTool_.name}</div>
                    <div style={{ fontSize: '0.75rem', color: activeTool_.color, fontFamily: 'var(--font-mono)' }}>
                      v{activeTool_.version} · {activeTool_.category} · {activeTool_.queue} queue
                    </div>
                  </div>
                  <div style={{ marginLeft: 'auto' }}>
                    <span style={{
                      padding: '4px 12px', borderRadius: 'var(--radius-sm)',
                      background: `${STATUS_LABELS[activeTool_.status].color}22`,
                      border: `1px solid ${STATUS_LABELS[activeTool_.status].color}55`,
                      color: STATUS_LABELS[activeTool_.status].color,
                      fontSize: '0.7rem', fontWeight: 700, letterSpacing: '0.1em',
                    }}>
                      {STATUS_LABELS[activeTool_.status].label.toUpperCase()}
                    </span>
                  </div>
                </div>
                <p style={{ fontSize: '0.875rem', color: 'var(--color-text-secondary)', lineHeight: 1.6 }}>
                  {activeTool_.desc}
                </p>
              </div>

              {/* Form */}
              <div style={{ flex: 1, overflowY: 'auto', padding: 'var(--space-5)' }}>
                <div style={{ fontSize: '0.7rem', fontWeight: 700, color: 'var(--color-text-muted)', letterSpacing: '0.1em', textTransform: 'uppercase', marginBottom: 'var(--space-4)' }}>
                  Configuration
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}>
                  {activeTool_.fields.map(field => (
                    <div key={field.key} className="form-group">
                      <label className="form-label">{field.label}</label>
                      {field.type === 'select' ? (
                        <select
                          className="input"
                          value={formData[activeTool_.id]?.[field.key] || ''}
                          onChange={e => setField(activeTool_.id, field.key, e.target.value)}
                        >
                          <option value="">Select…</option>
                          {field.options?.map(opt => (
                            <option key={opt} value={opt}>{opt}</option>
                          ))}
                        </select>
                      ) : (
                        <input
                          className="input input-mono"
                          type={field.type}
                          placeholder={(field as any).placeholder || ''}
                          value={formData[activeTool_.id]?.[field.key] || ''}
                          onChange={e => setField(activeTool_.id, field.key, e.target.value)}
                        />
                      )}
                    </div>
                  ))}
                </div>

                {/* External tool instructions */}
                {activeTool_.status === 'external' && (
                  <div style={{
                    marginTop: 'var(--space-5)', padding: 'var(--space-4)',
                    background: 'rgba(255,152,0,0.06)', border: '1px solid rgba(255,152,0,0.2)',
                    borderRadius: 'var(--radius-md)',
                  }}>
                    <div style={{ fontWeight: 700, color: 'var(--color-medium)', marginBottom: 8, fontSize: '0.8rem' }}>
                      External Tool Setup
                    </div>
                    <div style={{ fontSize: '0.8rem', color: 'var(--color-text-secondary)', lineHeight: 1.7 }}>
                      {activeTool_.id === 'burp' ? (
                        <>
                          1. Download Burp Suite from portswigger.net<br />
                          2. Start Burp → Proxy → Options → port 8080<br />
                          3. Install SPAIDER extension from BApp Store<br />
                          4. Configure API key above → findings auto-sync here
                        </>
                      ) : activeTool_.id === 'caido' ? (
                        <>
                          1. Install Caido from caido.io<br />
                          2. Start Caido on port 8080<br />
                          3. Generate API key in Caido settings<br />
                          4. Enter API key above → Automate results sync here
                        </>
                      ) : null}
                    </div>
                  </div>
                )}

                {/* Quick options */}
                {activeTool_.id === 'nmap' && (
                  <div style={{ marginTop: 'var(--space-5)' }}>
                    <div style={{ fontSize: '0.7rem', fontWeight: 700, color: 'var(--color-text-muted)', letterSpacing: '0.1em', textTransform: 'uppercase', marginBottom: 'var(--space-3)' }}>
                      Quick Profiles
                    </div>
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 6 }}>
                      {[
                        { label: '⚡ Quick Scan', type: 'quick', desc: 'Top 100 ports, fast' },
                        { label: '🔬 Full Scan', type: 'full', desc: 'All ports, OS detect' },
                        { label: '👤 Stealth', type: 'stealth', desc: 'SYN scan, low noise' },
                        { label: '🌐 Web Ports', type: 'web', desc: '80,443,8080,8443' },
                      ].map(p => (
                        <button
                          key={p.type}
                          onClick={() => setField(activeTool_.id, 'scan_type', p.type)}
                          style={{
                            padding: 'var(--space-2) var(--space-3)',
                            borderRadius: 'var(--radius-md)',
                            border: `1px solid ${formData[activeTool_.id]?.scan_type === p.type ? activeTool_.color : 'var(--color-border)'}`,
                            background: formData[activeTool_.id]?.scan_type === p.type ? `${activeTool_.color}18` : 'var(--color-bg-elevated)',
                            cursor: 'pointer', textAlign: 'left',
                            transition: 'all 0.15s',
                          }}
                        >
                          <div style={{ fontSize: '0.75rem', fontWeight: 700 }}>{p.label}</div>
                          <div style={{ fontSize: '0.65rem', color: 'var(--color-text-muted)' }}>{p.desc}</div>
                        </button>
                      ))}
                    </div>
                  </div>
                )}

                {activeTool_.id === 'nuclei' && (
                  <div style={{ marginTop: 'var(--space-5)' }}>
                    <div style={{ fontSize: '0.7rem', fontWeight: 700, color: 'var(--color-text-muted)', letterSpacing: '0.1em', textTransform: 'uppercase', marginBottom: 'var(--space-3)' }}>
                      Vulnerability Categories
                    </div>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 5 }}>
                      {['cves','xss','sqli','ssrf','cors','jwt','lfi','rce','open-redirect','xxe'].map(tag => (
                        <span key={tag} className="target-tag" style={{ cursor: 'pointer', fontSize: '0.7rem' }}>{tag}</span>
                      ))}
                    </div>
                  </div>
                )}
              </div>

              {/* Launch button */}
              <div style={{
                padding: 'var(--space-4) var(--space-5)',
                borderTop: '1px solid var(--color-border)',
                flexShrink: 0,
                background: 'var(--color-bg-elevated)',
              }}>
                {activeTool_.status === 'disabled' ? (
                  <div style={{ textAlign: 'center', color: 'var(--color-text-muted)', fontSize: '0.875rem' }}>
                    Configure credentials to enable this tool
                  </div>
                ) : (
                  <>
                    <div style={{
                  marginBottom: 'var(--space-3)',
                  padding: 'var(--space-2) var(--space-3)',
                  background: 'rgba(255,59,92,0.06)',
                  border: '1px solid rgba(255,59,92,0.2)',
                  borderRadius: 'var(--radius-md)',
                  fontSize: '0.73rem',
                  color: 'var(--color-red)',
                  display: 'flex',
                  alignItems: 'center',
                  gap: 6,
                }}>
                  <span>⚠️</span>
                  <span>Only scan systems you are authorised to test. Ensure a valid scope and authorization document exists.</span>
                </div>

                <div style={{ display: 'flex', gap: 'var(--space-3)' }}>
                    <button
                      className="btn btn-primary"
                      style={{
                        flex: 1,
                        background: `linear-gradient(135deg, ${activeTool_.color}, ${activeTool_.color}cc)`,
                        color: '#000',
                        fontWeight: 700,
                        boxShadow: `0 4px 20px ${activeTool_.color}44`,
                      }}
                      onClick={() => launchTool(activeTool_)}
                      disabled={runningTools.has(activeTool_.id)}
                    >
                      {runningTools.has(activeTool_.id)
                        ? `⏳ ${activeTool_.name} running...`
                        : `🚀 Launch ${activeTool_.name}`}
                    </button>
                    <button className="btn btn-ghost" onClick={() => setActiveTool(null)}>
                      Docs
                    </button>
                  </div>
                </>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </>
  )
}
