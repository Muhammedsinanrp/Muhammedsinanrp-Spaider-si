import { useState, useEffect, useRef } from 'react'
import { toolApi } from '../api/client'
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
  {
    id: 'shodan',
    name: 'Shodan',
    version: '1.0',
    icon: '🌐',
    category: 'OSINT',
    color: '#e11d48',
    desc: 'Internet-wide host intelligence — open ports, banners, CVEs, geolocation, and exposure analysis',
    status: 'ready',
    fields: [
      { key: 'query',      label: 'Query / IP',         placeholder: '8.8.8.8  or  apache port:8080', type: 'text' },
      { key: 'query_type', label: 'Query Type',          type: 'select', options: ['host','search','dns'] },
      { key: 'api_key',    label: 'API Key (optional)',  placeholder: 'Overrides SHODAN_API_KEY env var', type: 'password' },
    ],
    task: 'osint_shodan',
    queue: 'RED',
  },
  {
    id: 'virustotal',
    name: 'VirusTotal',
    version: '3.0',
    icon: '🦠',
    category: 'Threat Intel',
    color: '#3b82f6',
    desc: 'Multi-engine AV/reputation analysis — scan files, URLs, IPs, and domains against 70+ security engines',
    status: 'ready',
    fields: [
      { key: 'target',    label: 'Target',              placeholder: 'https://evil.com  or  d41d8cd98f  or  8.8.8.8', type: 'text' },
      { key: 'scan_type', label: 'Scan Type',           type: 'select', options: ['url','ip','domain','hash'] },
      { key: 'api_key',   label: 'API Key (optional)',  placeholder: 'Overrides VIRUSTOTAL_API_KEY env var', type: 'password' },
    ],
    task: 'osint_virustotal',
    queue: 'RED',
  },
  {
    id: 'truecaller',
    name: 'Truecaller',
    version: '1.0',
    icon: '📞',
    category: 'OSINT',
    color: '#10b981',
    desc: 'Phone number intelligence — caller identity, spam score, carrier, location, and social profile enrichment',
    status: 'ready',
    fields: [
      { key: 'phone',        label: 'Phone Number',       placeholder: '9876543210 (without country code)', type: 'text' },
      { key: 'country_code', label: 'Country Code',       placeholder: 'IN', type: 'text' },
      { key: 'auth_token',   label: 'Auth Token (optional)', placeholder: 'Overrides TRUECALLER_AUTH_TOKEN env var', type: 'password' },
    ],
    task: 'osint_truecaller',
    queue: 'RED',
  },
  {
    id: 'wifite',
    name: 'WiFite',
    version: '2.7.0',
    icon: '📶',
    category: 'Wireless',
    color: '#f59e0b',
    desc: 'Automated Wi-Fi auditing — WPS brute-force, WPA/WPA2 handshake capture, PMKID attacks, Evil Twin',
    status: 'ready',
    fields: [
      { key: 'interface', label: 'Wireless Interface', placeholder: 'wlan0  or  wlan0mon', type: 'text' },
      { key: 'attack',    label: 'Attack Mode',        type: 'select',
        options: ['wps','wpa','pmkid','all','evil-twin'] },
      { key: 'bssid',     label: 'Target BSSID (optional)', placeholder: 'AA:BB:CC:DD:EE:FF', type: 'text' },
      { key: 'channel',   label: 'Channel (optional)', placeholder: '1-14  or  leave blank for all', type: 'text' },
    ],
    task: 'run_wifite',
    queue: 'RED',
  },
  {
    id: 'maltego',
    name: 'Maltego',
    version: '4.6',
    icon: '🕵️',
    category: 'OSINT',
    color: '#8b5cf6',
    desc: 'Visual link analysis & OSINT graph intelligence — map relationships between people, domains, IPs, orgs',
    status: 'external',
    fields: [
      { key: 'target',      label: 'Seed Entity',    placeholder: 'domain.com  or  person@email.com  or  8.8.8.8', type: 'text' },
      { key: 'entity_type', label: 'Entity Type',    type: 'select',
        options: ['domain','ip','email','person','organisation','phone','hash'] },
      { key: 'transforms',  label: 'Transform Set',  type: 'select',
        options: ['all','dns','whois','social','threat_intel','shodan','haveibeenpwned'] },
    ],
    task: 'maltego_pivot',
    queue: 'RED',
  },
  {
    id: 'godseye',
    name: 'GodsEYE',
    version: '2024',
    icon: '👁️',
    category: 'Global Intel',
    color: '#06b6d4',
    desc: 'AI-Powered Global Intelligence Platform — live flight tracking, CCTV, maritime, earthquakes, news, undersea cables & more',
    status: 'external',
    fields: [
      { key: 'layers', label: 'Active Layers', placeholder: 'maritime,cctv,live_news,earthquakes', type: 'text' },
      { key: 'region', label: 'Region Focus (optional)', placeholder: 'e.g. South Asia  or  leave blank for global', type: 'text' },
    ],
    task: 'godseye_open',
    queue: 'RED',
  },
  {
    id: 'zingela',
    name: 'Zingela',
    version: '1.2.0',
    icon: '🎯',
    category: 'Network',
    color: '#00e5ff',
    desc: 'Stateless mass TCP/UDP port scanner in Zig — line-rate SYN scanning with SipHash & AF_XDP',
    status: 'ready',
    fields: [
      { key: 'target',    label: 'Target Range / CIDR', placeholder: '192.168.1.0/24  or  10.0.0.0/16', type: 'text' },
      { key: 'ports',     label: 'Ports',               placeholder: '1-1024  or  80,443,22,8080,3389', type: 'text' },
      { key: 'rate',      label: 'Packets / sec (pps)', placeholder: '10000', type: 'text' },
      { key: 'scan_mode', label: 'Scan Mode',           type: 'select', options: ['syn', 'udp', 'ack', 'fin'] },
      { key: 'interface', label: 'Interface (optional)', placeholder: 'eth0 or leave blank', type: 'text' },
    ],
    task: 'run_zingela_scan',
    queue: 'RED',
  },
  {
    id: 'lisdex',
    name: 'LISDEX',
    version: '2.1.0',
    icon: '🐧',
    category: 'Endpoint Audit',
    color: '#38bdf8',
    desc: 'Linux System & Security Indexer — privilege escalation vectors, SUID/GUID enumeration, kernel vulnerabilities, and configuration audit',
    status: 'ready',
    fields: [
      { key: 'target',      label: 'Target Host / SSH',  placeholder: 'localhost  or  192.168.1.45', type: 'text' },
      { key: 'audit_level', label: 'Audit Profile',      type: 'select', options: ['deep', 'quick', 'standard', 'privesc', 'cve'] },
      { key: 'modules',     label: 'Checks to Run',      placeholder: 'suid,capabilities,cron,kernel_cves,sudoers,containers', type: 'text' },
    ],
    task: 'run_lisdex_audit',
    queue: 'BLUE',
  },
  {
    id: 'cre',
    name: 'OpenCRE',
    version: '1.4.0',
    icon: '📚',
    category: 'Governance',
    color: '#c084fc',
    desc: 'OWASP Open Common Requirement Enumeration — cross-framework mapping for NIST 800-53, ISO 27001, ASVS, and CWE',
    status: 'ready',
    fields: [
      { key: 'query',      label: 'Search Requirement / CRE ID', placeholder: 'Authentication  or  074-651  or  CWE-79', type: 'text' },
      { key: 'framework',  label: 'Target Framework',            type: 'select', options: ['All Frameworks', 'NIST SP 800-53', 'ISO/IEC 27001', 'OWASP ASVS', 'OWASP Top 10', 'CWE'] },
    ],
    task: 'run_cre_lookup',
    queue: 'PURPLE',
  },
  {
    id: 'fwrule',
    name: 'FWRule',
    version: '1.8.0',
    icon: '🛡️',
    category: 'Hardening',
    color: '#10b981',
    desc: 'Automated Firewall Rule Synthesizer & Policy Enforcement — generate, analyze, and deploy iptables, nftables, UFW, pf, and cloud security rules',
    status: 'ready',
    fields: [
      { key: 'target',   label: 'Target IP / Subnet', placeholder: '192.168.1.100  or  10.0.0.0/24', type: 'text' },
      { key: 'engine',   label: 'Firewall Engine',    type: 'select', options: ['iptables', 'nftables', 'ufw', 'pf', 'aws_security_group', 'cisco_acl'] },
      { key: 'action',   label: 'Enforcement Action', type: 'select', options: ['block_ip', 'rate_limit_ddos', 'isolate_host', 'allow_service'] },
      { key: 'port',     label: 'Port / Service',     placeholder: 'any  or  443, 80, 22', type: 'text' },
      { key: 'protocol', label: 'Protocol',           type: 'select', options: ['tcp', 'udp', 'all'] },
    ],
    task: 'run_fwrule_enforce',
    queue: 'BLUE',
  },
  {
    id: 'httpheader',
    name: 'HTTP Header Inspector',
    version: '1.0.0',
    icon: '🔒',
    category: 'Web',
    color: '#a855f7',
    desc: 'HTTPS Security Header Inspector — checks HSTS, CSP, X-Content-Type-Options (nosniff), and framing restrictions with optional AI defensive advisory.',
    status: 'ready',
    fields: [
      { key: 'target',   label: 'Target Hostname', placeholder: 'example.com  or  target.org', type: 'text' },
      { key: 'interval', label: 'Request Interval (sec)', placeholder: '1.0', type: 'text' },
      { key: 'ai',       label: 'AI Advisory (OpenAI)', type: 'select', options: ['no', 'yes'] },
    ],
    task: 'run_httpheader_scan',
    queue: 'RED',
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
  OSINT: '#e11d48',
  'Threat Intel': 'var(--color-blue)',
  Wireless: '#f59e0b',
  'Endpoint Audit': '#38bdf8',
  Governance: '#c084fc',
  Hardening: '#10b981',
  'Global Intel': '#06b6d4',
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
  const [toolResults, setToolResults] = useState<Record<string, any>>({})
  const [resultTab, setResultTab] = useState<'result' | 'report' | 'analysis'>('result')
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

    setRunningTools(prev => new Set(prev).add(tool.id))
    // clear old results for this tool
    setToolResults(prev => { const n = { ...prev }; delete n[tool.id]; return n })
    setResultTab('result')
    toast.loading(`Running ${tool.name}...`, { id: tool.id })

    const fields = formData[tool.id] || {}

    // GodsEYE — open in browser tab
    if (tool.id === 'godseye') {
      const layers = fields.layers || 'maritime,cctv,live_news,earthquakes,global_incidents,day_night,cables'
      window.open(`https://godseye.network/dashboard?layers=${encodeURIComponent(layers)}`, '_blank', 'noopener')
      toast.success('GodsEYE opened in new tab', { id: tool.id })
      setRunningTools(prev => { const s = new Set(prev); s.delete(tool.id); return s })
      return
    }

    const targets = fields.target ? [fields.target]
      : fields.phone ? [fields.phone]
      : fields.query ? [fields.query]
      : []

    try {
      const resp = await toolApi.run(tool.id, targets, fields)
      setToolResults(prev => ({ ...prev, [tool.id]: resp }))
      if (resp.mock || resp.result?.type === 'external_tool' || resp.result?.type === 'configuration_required') {
        toast(`${tool.name}: setup guidance only; this did not execute a scan.`, { id: tool.id, icon: 'ℹ️' })
      } else if (resp.success === false || resp.result?.error) {
        toast.error(resp.result?.error || `${tool.name} failed.`, { id: tool.id })
      } else {
        toast.success(`${tool.name} completed in ${resp.elapsed_ms}ms`, { id: tool.id })
      }
    } catch (err: any) {
      const message = err?.response?.data?.detail || err?.message || `Unable to reach backend for ${tool.name}.`
      const failure = {
        plugin: tool.id, success: false, elapsed_ms: 0, mock: false,
        result: { error: String(message) },
        report: `${tool.name} was not executed. Check backend availability and authorization scope.\n${String(message)}`,
      }
      setToolResults(prev => ({ ...prev, [tool.id]: failure }))
      toast.error(String(message), { id: tool.id })
    } finally {
      setRunningTools(prev => { const s = new Set(prev); s.delete(tool.id); return s })
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

                {/* OSINT tool setup notes */}
                {['shodan', 'virustotal', 'truecaller'].includes(activeTool_.id) && (
                  <div style={{
                    marginTop: 'var(--space-5)', padding: 'var(--space-4)',
                    background: `${activeTool_.color}0a`,
                    border: `1px solid ${activeTool_.color}33`,
                    borderRadius: 'var(--radius-md)',
                  }}>
                    <div style={{ fontWeight: 700, color: activeTool_.color, marginBottom: 8, fontSize: '0.8rem' }}>
                      API Setup
                    </div>
                    <div style={{ fontSize: '0.8rem', color: 'var(--color-text-secondary)', lineHeight: 1.7 }}>
                      {activeTool_.id === 'shodan' && (
                        <>
                          1. Sign up at <strong>shodan.io</strong><br />
                          2. Copy API key from account.shodan.io<br />
                          3. Set <code>SHODAN_API_KEY</code> in your <code>.env</code><br />
                          4. Or paste the key directly in the field above
                        </>
                      )}
                      {activeTool_.id === 'virustotal' && (
                        <>
                          1. Sign up at <strong>virustotal.com</strong><br />
                          2. Go to Profile → API Key<br />
                          3. Set <code>VIRUSTOTAL_API_KEY</code> in your <code>.env</code><br />
                          4. Or paste the key directly in the field above
                        </>
                      )}
                      {activeTool_.id === 'truecaller' && (
                        <>
                          1. Install: <code>pip install truecallerpy</code><br />
                          2. Run: <code>python -m truecallerpy login</code><br />
                          3. Set <code>TRUECALLER_AUTH_TOKEN</code> in your <code>.env</code><br />
                          4. Or paste the token directly in the field above
                        </>
                      )}
                    </div>
                  </div>
                )}

                {/* GodsEYE live dashboard embed */}
                {activeTool_.id === 'godseye' && (
                  <div style={{ marginTop: 'var(--space-5)' }}>
                    <div style={{ fontSize: '0.7rem', fontWeight: 700, color: 'var(--color-text-muted)', letterSpacing: '0.1em', textTransform: 'uppercase', marginBottom: 'var(--space-3)' }}>
                      Live Dashboard Preview
                    </div>
                    <div style={{
                      borderRadius: 'var(--radius-md)', overflow: 'hidden',
                      border: `1px solid ${activeTool_.color}44`,
                      boxShadow: `0 0 24px ${activeTool_.color}22`,
                    }}>
                      <iframe
                        src="https://godseye.network/dashboard?layers=maritime,cctv,live_news,news_intel,earthquakes,global_incidents,day_night,cables,sdk_sea,sdk_air,sdk_naval"
                        style={{ width: '100%', height: 280, border: 'none', display: 'block' }}
                        title="GodsEYE Global Intelligence"
                        sandbox="allow-scripts allow-same-origin allow-popups"
                      />
                    </div>
                    <div style={{ fontSize: '0.7rem', color: 'var(--color-text-muted)', marginTop: 6 }}>
                      Click Launch to open full dashboard in a new tab with all layers active.
                    </div>
                  </div>
                )}

                {/* Maltego setup */}
                {activeTool_.id === 'maltego' && (
                  <div style={{
                    marginTop: 'var(--space-5)', padding: 'var(--space-4)',
                    background: `${activeTool_.color}0a`,
                    border: `1px solid ${activeTool_.color}33`,
                    borderRadius: 'var(--radius-md)',
                  }}>
                    <div style={{ fontWeight: 700, color: activeTool_.color, marginBottom: 8, fontSize: '0.8rem' }}>
                      Maltego Setup
                    </div>
                    <div style={{ fontSize: '0.8rem', color: 'var(--color-text-secondary)', lineHeight: 1.7 }}>
                      1. Download Maltego from <strong>maltego.com</strong><br />
                      2. Create a free Community Edition account<br />
                      3. Install transform hub packs (OSINT, Shodan, etc.)<br />
                      4. Launch → New Graph → add seed entity above<br />
                      5. Run All Transforms to map the intelligence graph
                    </div>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 5, marginTop: 10 }}>
                      {['Shodan','HaveIBeenPwned','VirusTotal','DomainTools','PassiveTotal','WhoisXML'].map(t => (
                        <span key={t} style={{
                          padding: '2px 8px', borderRadius: 'var(--radius-sm)',
                          border: `1px solid ${activeTool_.color}44`,
                          color: activeTool_.color, fontSize: '0.65rem', fontWeight: 700,
                        }}>{t}</span>
                      ))}
                    </div>
                  </div>
                )}

                {/* WiFite attack profiles */}
                {activeTool_.id === 'wifite' && (
                  <div style={{ marginTop: 'var(--space-5)' }}>
                    <div style={{ fontSize: '0.7rem', fontWeight: 700, color: 'var(--color-text-muted)', letterSpacing: '0.1em', textTransform: 'uppercase', marginBottom: 'var(--space-3)' }}>
                      Attack Profiles
                    </div>
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 6 }}>
                      {[
                        { label: '📡 WPS PIN',    type: 'wps',        desc: 'WPS brute-force' },
                        { label: '🤝 WPA Handshake', type: 'wpa',     desc: 'Capture & crack' },
                        { label: '🔑 PMKID',      type: 'pmkid',      desc: 'Clientless attack' },
                        { label: '👹 Evil Twin',   type: 'evil-twin',  desc: 'Rogue AP + deauth' },
                      ].map(p => (
                        <button
                          key={p.type}
                          onClick={() => setField(activeTool_.id, 'attack', p.type)}
                          style={{
                            padding: 'var(--space-2) var(--space-3)',
                            borderRadius: 'var(--radius-md)',
                            border: `1px solid ${formData[activeTool_.id]?.attack === p.type ? activeTool_.color : 'var(--color-border)'}`,
                            background: formData[activeTool_.id]?.attack === p.type ? `${activeTool_.color}18` : 'var(--color-bg-elevated)',
                            cursor: 'pointer', textAlign: 'left', transition: 'all 0.15s',
                          }}
                        >
                          <div style={{ fontSize: '0.75rem', fontWeight: 700 }}>{p.label}</div>
                          <div style={{ fontSize: '0.65rem', color: 'var(--color-text-muted)' }}>{p.desc}</div>
                        </button>
                      ))}
                    </div>
                  </div>
                )}

                {/* Zingela Line-rate Presets */}
                {activeTool_.id === 'zingela' && (
                  <div style={{ marginTop: 'var(--space-5)' }}>
                    <div style={{ fontSize: '0.7rem', fontWeight: 700, color: 'var(--color-text-muted)', letterSpacing: '0.1em', textTransform: 'uppercase', marginBottom: 'var(--space-3)' }}>
                      Line-Rate Probe Rates (Packets / Second)
                    </div>
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 6 }}>
                      {[
                        { label: '🚀 10,000 pps', rate: '10000', desc: 'Standard subnet scan' },
                        { label: '⚡ 50,000 pps', rate: '50000', desc: 'Campus CIDR /16' },
                        { label: '🔥 100,000 pps', rate: '100000', desc: 'Line-rate stateless' },
                        { label: '🌌 1,000,000 pps', rate: '1000000', desc: '10GbE Mass throughput' },
                      ].map(p => (
                        <button
                          key={p.rate}
                          onClick={() => setField(activeTool_.id, 'rate', p.rate)}
                          style={{
                            padding: 'var(--space-2) var(--space-3)',
                            borderRadius: 'var(--radius-md)',
                            border: `1px solid ${formData[activeTool_.id]?.rate === p.rate ? activeTool_.color : 'var(--color-border)'}`,
                            background: formData[activeTool_.id]?.rate === p.rate ? `${activeTool_.color}18` : 'var(--color-bg-elevated)',
                            cursor: 'pointer', textAlign: 'left', transition: 'all 0.15s',
                          }}
                        >
                          <div style={{ fontSize: '0.75rem', fontWeight: 700 }}>{p.label}</div>
                          <div style={{ fontSize: '0.65rem', color: 'var(--color-text-muted)' }}>{p.desc}</div>
                        </button>
                      ))}
                    </div>
                    <div style={{
                      marginTop: 'var(--space-3)', padding: 'var(--space-3)',
                      background: 'rgba(0, 229, 255, 0.05)',
                      border: '1px solid rgba(0, 229, 255, 0.2)',
                      borderRadius: 'var(--radius-md)',
                      fontSize: '0.7rem', color: 'var(--color-text-secondary)',
                    }}>
                      💡 <strong>Zig Engine:</strong> Uses stateless SYN scanning with SipHash-2-4 cookies and <code>AF_PACKET / AF_XDP</code> direct kernel bypass for high line-rate speeds.
                    </div>
                  </div>
                )}

                {/* LISDEX Linux Audit Profiles */}
                {activeTool_.id === 'lisdex' && (
                  <div style={{ marginTop: 'var(--space-5)' }}>
                    <div style={{ fontSize: '0.7rem', fontWeight: 700, color: 'var(--color-text-muted)', letterSpacing: '0.1em', textTransform: 'uppercase', marginBottom: 'var(--space-3)' }}>
                      Linux Audit Profiles
                    </div>
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 6 }}>
                      {[
                        { label: '👑 PrivEsc Vectors', level: 'privesc', desc: 'SUID, sudoers, capabilities' },
                        { label: '🐛 Kernel CVEs',     level: 'cve',     desc: 'Dirty COW, PwnKit, Looney' },
                        { label: '🔍 Deep Inspection', level: 'deep',    desc: 'All 6 security indexers' },
                        { label: '⚡ Quick Audit',     level: 'quick',   desc: 'Critical exposure sweep' },
                      ].map(p => (
                        <button
                          key={p.level}
                          onClick={() => setField(activeTool_.id, 'audit_level', p.level)}
                          style={{
                            padding: 'var(--space-2) var(--space-3)',
                            borderRadius: 'var(--radius-md)',
                            border: `1px solid ${formData[activeTool_.id]?.audit_level === p.level ? activeTool_.color : 'var(--color-border)'}`,
                            background: formData[activeTool_.id]?.audit_level === p.level ? `${activeTool_.color}18` : 'var(--color-bg-elevated)',
                            cursor: 'pointer', textAlign: 'left', transition: 'all 0.15s',
                          }}
                        >
                          <div style={{ fontSize: '0.75rem', fontWeight: 700 }}>{p.label}</div>
                          <div style={{ fontSize: '0.65rem', color: 'var(--color-text-muted)' }}>{p.desc}</div>
                        </button>
                      ))}
                    </div>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 5, marginTop: 'var(--space-3)' }}>
                      {['SUID Binaries', 'Linux Capabilities', 'Docker Escape Check', 'Cron Wildcards', 'Kernel CVE Matcher'].map(t => (
                        <span key={t} style={{
                          padding: '2px 8px', borderRadius: 'var(--radius-sm)',
                          border: `1px solid ${activeTool_.color}44`,
                          color: activeTool_.color, fontSize: '0.65rem', fontWeight: 700,
                        }}>{t}</span>
                      ))}
                    </div>
                  </div>
                )}

                {/* OpenCRE Standards Search Presets */}
                {activeTool_.id === 'cre' && (
                  <div style={{ marginTop: 'var(--space-5)' }}>
                    <div style={{ fontSize: '0.7rem', fontWeight: 700, color: 'var(--color-text-muted)', letterSpacing: '0.1em', textTransform: 'uppercase', marginBottom: 'var(--space-3)' }}>
                      Standards Quick Queries
                    </div>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                      {[
                        { label: '🔐 Authentication', q: 'Authentication' },
                        { label: '🔑 Cryptographic Keys', q: 'Cryptographic keys' },
                        { label: '🛡️ Input Validation', q: 'Input validation' },
                        { label: '⚖️ Least Privilege', q: 'Least privilege' },
                        { label: '📝 Audit & Logging', q: 'Log and monitor' },
                        { label: '📦 Supply Chain SBOM', q: 'Supply chain' },
                      ].map(pill => (
                        <button
                          key={pill.q}
                          onClick={() => setField(activeTool_.id, 'query', pill.q)}
                          style={{
                            padding: '4px 10px', borderRadius: 'var(--radius-full)',
                            border: `1px solid ${formData[activeTool_.id]?.query === pill.q ? activeTool_.color : 'var(--color-border)'}`,
                            background: formData[activeTool_.id]?.query === pill.q ? `${activeTool_.color}22` : 'var(--color-bg-elevated)',
                            color: formData[activeTool_.id]?.query === pill.q ? activeTool_.color : 'var(--color-text-primary)',
                            fontSize: '0.7rem', fontWeight: 600, cursor: 'pointer',
                          }}
                        >
                          {pill.label}
                        </button>
                      ))}
                    </div>
                    <div style={{
                      marginTop: 'var(--space-3)', padding: 'var(--space-3)',
                      background: 'rgba(192, 132, 252, 0.05)',
                      border: '1px solid rgba(192, 132, 252, 0.2)',
                      borderRadius: 'var(--radius-md)',
                      fontSize: '0.7rem', color: 'var(--color-text-secondary)',
                    }}>
                      Maps controls directly across <strong>NIST SP 800-53</strong>, <strong>ISO/IEC 27001</strong>, <strong>OWASP ASVS</strong>, <strong>OWASP Top 10</strong>, and <strong>CWE / CAPEC</strong>.
                    </div>
                  </div>
                )}

                {/* FWRule Firewall Enforcement Presets */}
                {activeTool_.id === 'fwrule' && (
                  <div style={{ marginTop: 'var(--space-5)' }}>
                    <div style={{ fontSize: '0.7rem', fontWeight: 700, color: 'var(--color-text-muted)', letterSpacing: '0.1em', textTransform: 'uppercase', marginBottom: 'var(--space-3)' }}>
                      Defensive Enforcement Actions
                    </div>
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 6 }}>
                      {[
                        { label: '🚫 Block Threat IP', action: 'block_ip', desc: 'DROP / deny all ingress traffic' },
                        { label: '⚡ Rate-Limit DDoS', action: 'rate_limit_ddos', desc: 'Mitigate volumetric floods' },
                        { label: '🔒 Isolate Host', action: 'isolate_host', desc: 'Quarantine compromised server' },
                        { label: '✅ Allow Service', action: 'allow_service', desc: 'Permit secure port' },
                      ].map(a => (
                        <button
                          key={a.action}
                          onClick={() => setField(activeTool_.id, 'action', a.action)}
                          style={{
                            padding: 'var(--space-2) var(--space-3)',
                            borderRadius: 'var(--radius-md)',
                            border: `1px solid ${formData[activeTool_.id]?.action === a.action ? activeTool_.color : 'var(--color-border)'}`,
                            background: formData[activeTool_.id]?.action === a.action ? `${activeTool_.color}18` : 'var(--color-bg-elevated)',
                            cursor: 'pointer', textAlign: 'left', transition: 'all 0.15s',
                          }}
                        >
                          <div style={{ fontSize: '0.75rem', fontWeight: 700 }}>{a.label}</div>
                          <div style={{ fontSize: '0.65rem', color: 'var(--color-text-muted)' }}>{a.desc}</div>
                        </button>
                      ))}
                    </div>
                    <div style={{ marginTop: 'var(--space-3)' }}>
                      <div style={{ fontSize: '0.68rem', color: 'var(--color-text-muted)', marginBottom: 4 }}>Target Architecture:</div>
                      <div style={{ display: 'flex', gap: 5, flexWrap: 'wrap' }}>
                        {['iptables', 'nftables', 'ufw', 'pf', 'aws_security_group'].map(eng => (
                          <button
                            key={eng}
                            onClick={() => setField(activeTool_.id, 'engine', eng)}
                            style={{
                              padding: '2px 8px', borderRadius: 'var(--radius-sm)',
                              border: `1px solid ${formData[activeTool_.id]?.engine === eng ? activeTool_.color : 'var(--color-border)'}`,
                              background: formData[activeTool_.id]?.engine === eng ? `${activeTool_.color}22` : 'transparent',
                              color: formData[activeTool_.id]?.engine === eng ? activeTool_.color : 'var(--color-text-muted)',
                              fontSize: '0.65rem', fontWeight: 700, cursor: 'pointer',
                            }}
                          >
                            {eng}
                          </button>
                        ))}
                      </div>
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

              {/* ── Results Viewer ── */}
              {toolResults[activeTool_.id] && (
                <div style={{
                  borderTop: '2px solid ' + activeTool_.color + '44',
                  flexShrink: 0, maxHeight: 360,
                  display: 'flex', flexDirection: 'column',
                  background: 'var(--color-bg)',
                }}>
                  <div style={{ display: 'flex', borderBottom: '1px solid var(--color-border)', flexShrink: 0 }}>
                    {(['result', 'report', 'analysis'] as const).map(tab => {
                      const res = toolResults[activeTool_.id]
                      if (tab === 'report' && !res?.report) return null
                      if (tab === 'analysis' && !res?.analysis) return null
                      return (
                        <button key={tab} onClick={() => setResultTab(tab)} style={{
                          padding: '8px 14px', background: resultTab === tab ? activeTool_.color + '18' : 'transparent',
                          border: 'none', borderBottom: resultTab === tab ? '2px solid ' + activeTool_.color : '2px solid transparent',
                          color: resultTab === tab ? activeTool_.color : 'var(--color-text-muted)',
                          fontSize: '0.68rem', fontWeight: 700, cursor: 'pointer', letterSpacing: '0.08em', textTransform: 'uppercase',
                        }}>{tab}</button>
                      )
                    })}
                    <div style={{ flex: 1 }} />
                    <div style={{ padding: '6px 12px', fontSize: '0.65rem', color: 'var(--color-text-muted)', display: 'flex', alignItems: 'center', gap: 6 }}>
                      {toolResults[activeTool_.id].mock && <span style={{ color: '#f59e0b', fontWeight: 700 }}>NOT EXECUTED / SETUP ONLY</span>}
                      <span style={{ fontFamily: 'var(--font-mono)' }}>{toolResults[activeTool_.id].elapsed_ms}ms</span>
                    </div>
                  </div>
                  <div style={{ flex: 1, overflowY: 'auto', padding: 'var(--space-3)' }}>
                    {resultTab === 'result' && <ResultView data={toolResults[activeTool_.id].result} color={activeTool_.color} />}
                    {resultTab === 'report' && (
                      <pre style={{ fontFamily: 'var(--font-mono)', fontSize: '0.72rem', color: activeTool_.color, lineHeight: 1.6, whiteSpace: 'pre-wrap', margin: 0 }}>
                        {toolResults[activeTool_.id].report}
                      </pre>
                    )}
                    {resultTab === 'analysis' && <ResultView data={toolResults[activeTool_.id].analysis} color={activeTool_.color} />}
                  </div>
                </div>
              )}

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
                      marginBottom: 'var(--space-3)', padding: 'var(--space-2) var(--space-3)',
                      background: 'rgba(255,59,92,0.06)', border: '1px solid rgba(255,59,92,0.2)',
                      borderRadius: 'var(--radius-md)', fontSize: '0.73rem', color: 'var(--color-red)',
                      display: 'flex', alignItems: 'center', gap: 6,
                    }}>
                      <span>⚠️</span>
                      <span>Only scan systems you are authorised to test.</span>
                    </div>
                    <div style={{ display: 'flex', gap: 'var(--space-3)' }}>
                      <button
                        className="btn btn-primary"
                        style={{
                          flex: 1,
                          background: `linear-gradient(135deg, ${activeTool_.color}, ${activeTool_.color}cc)`,
                          color: '#000', fontWeight: 700,
                          boxShadow: `0 4px 20px ${activeTool_.color}44`,
                        }}
                        onClick={() => launchTool(activeTool_)}
                        disabled={runningTools.has(activeTool_.id)}
                      >
                        {runningTools.has(activeTool_.id) ? `⏳ Running ${activeTool_.name}…` : `🚀 Run ${activeTool_.name}`}
                      </button>
                      {toolResults[activeTool_.id] && (
                        <button className="btn btn-ghost"
                          onClick={() => setToolResults(prev => { const n = { ...prev }; delete n[activeTool_.id]; return n })}>
                          ✕ Clear
                        </button>
                      )}
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

// ── ResultView ────────────────────────────────────────────────────────────────
function ResultView({ data, color }: { data: any; color: string }) {
  if (!data) return <div style={{ color: 'var(--color-text-muted)', fontSize: '0.8rem' }}>No data</div>
  if (Array.isArray(data)) {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
        {data.map((item, i) => (
          <div key={i} style={{
            padding: '6px 10px', background: color + '0a', border: '1px solid ' + color + '22',
            borderRadius: 6, fontFamily: 'var(--font-mono)', fontSize: '0.7rem', color: 'var(--color-text-primary)',
          }}>
            {typeof item === 'object' ? JSON.stringify(item, null, 2) : String(item)}
          </div>
        ))}
      </div>
    )
  }
  if (typeof data !== 'object') {
    return <pre style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: 'var(--color-text-primary)', whiteSpace: 'pre-wrap' }}>{String(data)}</pre>
  }
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
      {Object.entries(data).map(([key, val]) => {
        const isArr = Array.isArray(val)
        const isObj = val && typeof val === 'object' && !isArr
        return (
          <div key={key} style={{
            background: color + '08', border: '1px solid ' + color + '20',
            borderRadius: 6, padding: '8px 12px',
          }}>
            <div style={{ fontSize: '0.6rem', fontWeight: 700, color, letterSpacing: '0.1em', textTransform: 'uppercase', marginBottom: 4 }}>
              {key.replace(/_/g, ' ')}
            </div>
            {isArr ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
                {(val as any[]).slice(0, 6).map((item, i) => (
                  <div key={i} style={{
                    fontFamily: 'var(--font-mono)', fontSize: '0.68rem',
                    color: 'var(--color-text-primary)', background: 'rgba(0,0,0,0.2)',
                    borderRadius: 4, padding: '2px 6px', lineHeight: 1.5,
                  }}>
                    {typeof item === 'object' ? JSON.stringify(item) : String(item)}
                  </div>
                ))}
                {(val as any[]).length > 6 && (
                  <div style={{ fontSize: '0.65rem', color: 'var(--color-text-muted)' }}>+{(val as any[]).length - 6} more…</div>
                )}
              </div>
            ) : isObj ? (
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.7rem', color: 'var(--color-text-secondary)', whiteSpace: 'pre-wrap', lineHeight: 1.5 }}>
                {JSON.stringify(val, null, 2)}
              </div>
            ) : (
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: 'var(--color-text-primary)', lineHeight: 1.5 }}>
                {String(val ?? '')}
              </div>
            )}
          </div>
        )
      })}
    </div>
  )
}
