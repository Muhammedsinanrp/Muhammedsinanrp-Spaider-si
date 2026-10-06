import { useState, useEffect, useRef } from 'react'
import { useNavigate } from 'react-router-dom'

const HUNT_STEPS = [
  { id: 'recon',       label: 'Asset discovery',          agent: '🕷️ Recon Agent',     done: true,   result: '127 assets found' },
  { id: 'subdomains',  label: 'Subdomain enumeration',    agent: '🕷️ Recon Agent',     done: true,   result: '62 subdomains' },
  { id: 'fingerprint', label: 'Technology fingerprinting', agent: '👁️ Surface Agent',  done: true,   result: 'Apache 2.4.49 detected' },
  { id: 'http',        label: 'HTTP probing',              agent: '👁️ Surface Agent',  done: true,   result: '89 live hosts' },
  { id: 'endpoints',   label: 'Endpoint discovery',       agent: '🔍 Web Agent',       done: true,   result: '234 endpoints' },
  { id: 'params',      label: 'Parameter discovery',      agent: '⚡ API Agent',       done: true,   result: '512 parameters' },
  { id: 'vuln',        label: 'Vulnerability validation', agent: '🛡️ Validation Agent',active: true, result: '3 confirmed' },
  { id: 'evidence',    label: 'Evidence collection',      agent: '📊 Risk Agent',      done: false,  result: '' },
  { id: 'report',      label: 'Report generation',        agent: '📝 Report Agent',    done: false,  result: '' },
]

const AI_AGENTS = [
  { icon: '🕷️', name: 'Recon Agent',       status: 'DONE',    desc: 'Asset discovery & mapping' },
  { icon: '👁️', name: 'Surface Agent',     status: 'DONE',    desc: 'Attack-surface mapping' },
  { icon: '🔍', name: 'Web Agent',          status: 'DONE',    desc: 'Web vulnerability analysis' },
  { icon: '⚡', name: 'API Agent',          status: 'DONE',    desc: 'API security testing' },
  { icon: '🧠', name: 'Logic Agent',        status: 'IDLE',    desc: 'Business-logic hypothesis' },
  { icon: '🛡️', name: 'Validation Agent',  status: 'RUNNING', desc: 'Evidence & validation' },
  { icon: '📊', name: 'Risk Agent',         status: 'WAITING', desc: 'Severity & prioritization' },
  { icon: '📝', name: 'Report Agent',       status: 'WAITING', desc: 'Bug bounty report gen' },
]

const REASONING_LOG = [
  { time: '18:54:12', level: 'VULN',  msg: 'SSRF confirmed. /api/fetch?url= accepts external URLs. Controlled callback intercepted at oast.pro burp collab. Confidence: 87%.' },
  { time: '18:51:38', level: 'PROBE', msg: 'Testing IDOR pattern on /api/v1/users/{id}. Changing ID from 1→2 returns different user data without authorization check.' },
  { time: '18:49:05', level: 'INFO',  msg: 'Nuclei template apache-path-traversal matched on 192.168.1.10:80. CVE-2021-41773. CVSS 9.8.' },
  { time: '18:45:22', level: 'INFO',  msg: 'JS analysis complete. 14 new API endpoints extracted from bundle.js. Adding to surface.' },
  { time: '18:40:11', level: 'INFO',  msg: 'Technology stack fingerprinted: Apache 2.4.49, PHP 8.0.3, jQuery 3.2.1 (outdated).' },
  { time: '18:32:00', level: 'INFO',  msg: 'HTTPX probing complete. 89 live hosts out of 127. 38 hosts timed out or filtered.' },
]

const CURRENT_FINDING = {
  endpoint: 'https://example.com/api/fetch',
  param: 'url=',
  type: 'SSRF',
  confidence: 87,
  nextStep: 'Controlled callback verification',
  impact: 'Internal service access, metadata endpoint exposure, potential RCE via cloud SSRF',
}

export default function AIAnalyst() {
  const navigate = useNavigate()
  const [elapsed, setElapsed] = useState(0)
  const [logIdx, setLogIdx] = useState(REASONING_LOG.length)
  const logRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    const id = setInterval(() => setElapsed(e => e + 1), 1000)
    return () => clearInterval(id)
  }, [])

  const formatTime = (s: number) => `${String(Math.floor(s / 60)).padStart(2, '0')}:${String(s % 60).padStart(2, '0')}`

  const doneCount = HUNT_STEPS.filter(s => s.done).length
  const progress = Math.round((doneCount / HUNT_STEPS.length) * 100)

  return (
    <div>
      <div className="page-header" style={{ marginBottom: 'var(--space-6)' }}>
        <div>
          <h1 className="page-title" style={{ background: 'linear-gradient(135deg, #a855f7, #00e5ff)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
            ⚡ AI HUNTER
          </h1>
          <p className="page-subtitle">Autonomous bug bounty discovery · Human-approved exploitation</p>
        </div>
        <div className="flex gap-2">
          <div style={{ padding: '6px 14px', background: 'rgba(0,255,136,0.08)', border: '1px solid rgba(0,255,136,0.3)',
            borderRadius: 'var(--radius-md)', fontSize: '0.75rem', color: '#00ff88', fontWeight: 700, display: 'flex', alignItems: 'center', gap: 6 }}>
            <span className="status-dot running" />
            SCOPE: AUTHORIZED ✓
          </div>
          <div style={{ padding: '6px 14px', background: 'rgba(255,255,255,0.04)', border: '1px solid var(--color-border)',
            borderRadius: 'var(--radius-md)', fontSize: '0.75rem', color: 'var(--color-text-muted)', fontFamily: 'var(--font-mono)' }}>
            ⏱ {formatTime(elapsed + 1423)}
          </div>
          <button className="btn btn-primary" onClick={() => navigate('/findings')}>
            View Findings →
          </button>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 'var(--space-5)', marginBottom: 'var(--space-5)' }}>

        {/* Left: Hunt pipeline */}
        <div className="card" style={{ border: '1px solid rgba(168,85,247,0.3)', background: 'linear-gradient(135deg, rgba(168,85,247,0.05), rgba(0,0,0,0))' }}>
          <div className="card-header">
            <div>
              <span className="card-title" style={{ color: '#a855f7' }}>SPAiDER AI HUNTER</span>
              <div style={{ fontSize: '0.7rem', color: 'var(--color-text-muted)' }}>Target: example.com</div>
            </div>
            <div style={{ textAlign: 'right' }}>
              <div style={{ fontSize: '1.4rem', fontWeight: 900, color: '#a855f7', fontFamily: 'var(--font-mono)' }}>{progress}%</div>
              <div style={{ fontSize: '0.65rem', color: 'var(--color-text-muted)' }}>complete</div>
            </div>
          </div>

          {/* Progress bar */}
          <div style={{ marginBottom: 20 }}>
            <div style={{ height: 6, background: 'rgba(255,255,255,0.06)', borderRadius: 3, overflow: 'hidden' }}>
              <div style={{
                width: `${progress}%`, height: '100%',
                background: 'linear-gradient(90deg, #a855f7, #00e5ff)',
                borderRadius: 3, boxShadow: '0 0 10px rgba(168,85,247,0.5)',
                transition: 'width 1s ease',
              }} />
            </div>
          </div>

          {/* Steps */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            {HUNT_STEPS.map((step, i) => (
              <div key={step.id} style={{
                display: 'flex', alignItems: 'center', gap: 10,
                padding: '8px 10px',
                background: step.active ? 'rgba(168,85,247,0.08)' : step.done ? 'transparent' : 'transparent',
                border: step.active ? '1px solid rgba(168,85,247,0.3)' : '1px solid transparent',
                borderRadius: 6, opacity: !step.done && !step.active ? 0.45 : 1,
              }}>
                {/* Status icon */}
                <span style={{
                  width: 20, height: 20, borderRadius: '50%', display: 'flex',
                  alignItems: 'center', justifyContent: 'center', fontSize: '0.65rem', fontWeight: 800, flexShrink: 0,
                  background: step.done ? 'rgba(0,255,136,0.15)' : step.active ? 'rgba(168,85,247,0.2)' : 'rgba(255,255,255,0.04)',
                  border: `1px solid ${step.done ? '#00ff88' : step.active ? '#a855f7' : 'rgba(255,255,255,0.08)'}`,
                  color: step.done ? '#00ff88' : step.active ? '#a855f7' : 'var(--color-text-muted)',
                }}>
                  {step.done ? '✓' : step.active ? '●' : String(i + 1)}
                </span>

                <div style={{ flex: 1 }}>
                  <div style={{ fontSize: '0.8rem', color: step.active ? '#a855f7' : step.done ? 'var(--color-text-primary)' : 'var(--color-text-muted)', fontWeight: step.active ? 700 : 500 }}>
                    {step.label}
                  </div>
                  <div style={{ fontSize: '0.65rem', color: 'var(--color-text-muted)' }}>{step.agent}</div>
                </div>

                {step.result && (
                  <span style={{ fontSize: '0.65rem', color: step.done ? '#00ff88' : '#a855f7',
                    fontFamily: 'var(--font-mono)', background: 'rgba(0,255,136,0.06)', padding: '2px 6px', borderRadius: 4 }}>
                    {step.result}
                  </span>
                )}
                {step.active && (
                  <span style={{ fontSize: '0.65rem', color: '#a855f7', animation: 'pulse-brand 1.2s ease infinite' }}>LIVE</span>
                )}
              </div>
            ))}
          </div>

          {/* Human approval required note */}
          <div style={{ marginTop: 14, padding: 10, background: 'rgba(255,152,0,0.06)', border: '1px solid rgba(255,152,0,0.25)', borderRadius: 6, fontSize: '0.72rem', color: '#ff9800' }}>
            ⚠ Human approval required before intrusive actions or bounty submission
          </div>
        </div>

        {/* Right: AI Reasoning panel */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}>

          {/* Current finding detail */}
          <div className="card" style={{ border: '1px solid rgba(255,59,92,0.3)', background: 'linear-gradient(135deg, rgba(255,59,92,0.05), rgba(0,0,0,0))' }}>
            <div className="card-header">
              <span className="card-title" style={{ color: '#ff3b5c' }}>🔴 Active Finding</span>
              <span className="badge badge-high">SSRF · 87% confidence</span>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, marginBottom: 12 }}>
              {[
                { l: 'Type', v: CURRENT_FINDING.type, c: '#ff3b5c' },
                { l: 'Confidence', v: `${CURRENT_FINDING.confidence}%`, c: '#ff9800' },
                { l: 'Endpoint', v: '/api/fetch', c: 'var(--color-cyan)' },
                { l: 'Parameter', v: 'url=', c: '#a855f7' },
              ].map(item => (
                <div key={item.l} style={{ padding: '8px', background: 'rgba(255,255,255,0.03)', borderRadius: 6, border: '1px solid rgba(255,255,255,0.05)' }}>
                  <div style={{ fontSize: '0.62rem', color: 'var(--color-text-muted)' }}>{item.l}</div>
                  <div style={{ fontSize: '0.85rem', fontWeight: 700, color: item.c, fontFamily: 'var(--font-mono)' }}>{item.v}</div>
                </div>
              ))}
            </div>

            <div style={{ padding: 10, background: 'rgba(0,0,0,0.3)', borderRadius: 6, fontFamily: 'var(--font-mono)', fontSize: '0.72rem', color: '#ff3b5c', marginBottom: 10 }}>
              GET /api/fetch?<span style={{ color: '#ff9800' }}>url</span>=http://169.254.169.254/<br />
              → <span style={{ color: '#00ff88' }}>200 OK · AWS metadata exposed</span>
            </div>

            <div style={{ fontSize: '0.72rem', color: 'var(--color-text-muted)', marginBottom: 8 }}>
              <strong style={{ color: '#ff9800' }}>Impact:</strong> {CURRENT_FINDING.impact}
            </div>

            <div style={{ fontSize: '0.72rem', color: '#a855f7', marginBottom: 12 }}>
              <strong>Next step:</strong> {CURRENT_FINDING.nextStep}
            </div>

            <div style={{ display: 'flex', gap: 8 }}>
              <button className="btn btn-sm btn-primary" style={{ flex: 1, background: 'rgba(255,59,92,0.2)', color: '#ff3b5c', border: '1px solid rgba(255,59,92,0.4)' }}>
                ✋ Approve for Validation
              </button>
              <button className="btn btn-sm btn-ghost" style={{ flex: 1 }}>View Evidence</button>
            </div>
          </div>

          {/* AI Reasoning log */}
          <div className="card" style={{ flex: 1 }}>
            <div className="card-header">
              <span className="card-title">🧠 AI Reasoning</span>
              <span style={{ fontSize: '0.65rem', color: '#00ff88', fontFamily: 'var(--font-mono)' }}>● LIVE</span>
            </div>
            <div ref={logRef} style={{ display: 'flex', flexDirection: 'column', gap: 6, maxHeight: 260, overflowY: 'auto' }}>
              {REASONING_LOG.map((entry, i) => (
                <div key={i} style={{
                  display: 'flex', gap: 8, padding: '6px 8px',
                  background: entry.level === 'VULN' ? 'rgba(255,59,92,0.06)' : entry.level === 'PROBE' ? 'rgba(168,85,247,0.06)' : 'rgba(255,255,255,0.02)',
                  borderLeft: `2px solid ${entry.level === 'VULN' ? '#ff3b5c' : entry.level === 'PROBE' ? '#a855f7' : 'rgba(255,255,255,0.1)'}`,
                  borderRadius: '0 4px 4px 0',
                }}>
                  <div style={{ flexShrink: 0 }}>
                    <div style={{ fontSize: '0.6rem', color: 'var(--color-text-muted)', fontFamily: 'var(--font-mono)' }}>{entry.time}</div>
                    <div style={{ fontSize: '0.58rem', fontWeight: 800, letterSpacing: '0.05em',
                      color: entry.level === 'VULN' ? '#ff3b5c' : entry.level === 'PROBE' ? '#a855f7' : 'var(--color-text-muted)' }}>
                      {entry.level}
                    </div>
                  </div>
                  <div style={{ fontSize: '0.72rem', color: 'var(--color-text-secondary)', lineHeight: 1.5 }}>{entry.msg}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* AI Agents grid */}
      <div className="card">
        <div className="card-header">
          <span className="card-title">🤖 Specialized AI Agents</span>
          <span style={{ fontSize: '0.72rem', color: 'var(--color-text-muted)' }}>AI proposes → tools verify → evidence collected → human approves</span>
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12 }}>
          {AI_AGENTS.map((agent) => {
            const statusColor = agent.status === 'RUNNING' ? '#a855f7' : agent.status === 'DONE' ? '#00ff88' : agent.status === 'WAITING' ? '#ff9800' : 'rgba(255,255,255,0.3)'
            return (
              <div key={agent.name} style={{
                padding: 12, borderRadius: 8,
                background: agent.status === 'RUNNING' ? 'rgba(168,85,247,0.08)' : 'rgba(255,255,255,0.02)',
                border: `1px solid ${agent.status === 'RUNNING' ? 'rgba(168,85,247,0.35)' : 'rgba(255,255,255,0.06)'}`,
              }}>
                <div style={{ fontSize: '1.5rem', marginBottom: 6 }}>{agent.icon}</div>
                <div style={{ fontSize: '0.8rem', fontWeight: 700, color: 'var(--color-text-primary)', marginBottom: 2 }}>{agent.name}</div>
                <div style={{ fontSize: '0.65rem', color: 'var(--color-text-muted)', marginBottom: 8 }}>{agent.desc}</div>
                <div style={{
                  fontSize: '0.62rem', fontWeight: 800, letterSpacing: '0.08em',
                  color: statusColor, display: 'flex', alignItems: 'center', gap: 4,
                }}>
                  {agent.status === 'RUNNING' && <span style={{ animation: 'pulse-brand 1.2s infinite' }}>●</span>}
                  {agent.status === 'DONE' && <span>✓</span>}
                  {agent.status === 'WAITING' && <span>○</span>}
                  {agent.status === 'IDLE' && <span>—</span>}
                  {agent.status}
                </div>
              </div>
            )
          })}
        </div>
      </div>
    </div>
  )
}
