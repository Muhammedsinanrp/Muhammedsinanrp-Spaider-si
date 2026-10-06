import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { targetApi, scanApi } from '../api/client'
import toast from 'react-hot-toast'

const LAB_PRESETS = [
  {
    name: 'OWASP Juice Shop',
    hostname: 'juice-shop',
    description: 'Deliberately insecure Node.js web application. AUTHORIZED LAB TARGET.',
    defaultUrl: 'http://juice-shop:3000',
    icon: '🧃',
    tags: ['lab', 'owasp', 'nodejs'],
    badge: 'AUTHORIZED',
    badgeColor: '#00ff88',
    vulnCount: '85+ known vulnerabilities',
  },
  {
    name: 'DVWA',
    hostname: 'dvwa',
    description: 'Damn Vulnerable Web Application — PHP/MySQL security research target.',
    defaultUrl: 'http://dvwa:80',
    icon: '🎯',
    tags: ['lab', 'php', 'dvwa'],
    badge: 'AUTHORIZED',
    badgeColor: '#00ff88',
    vulnCount: 'SQLi · XSS · CSRF · Upload · Cmd Injection',
  },
  {
    name: 'WebGoat',
    hostname: 'webgoat',
    description: 'OWASP WebGoat deliberately insecure Java EE application.',
    defaultUrl: 'http://webgoat:8080',
    icon: '🐐',
    tags: ['lab', 'java', 'owasp'],
    badge: 'AUTHORIZED',
    badgeColor: '#00ff88',
    vulnCount: 'OWASP Top 10 coverage',
  },
]

function TargetCard({
  target,
  onScan,
  isScanning,
}: {
  target: any
  onScan: (target: any) => void
  isScanning: boolean
}) {
  const preset = LAB_PRESETS.find(p => p.hostname === target.hostname)

  return (
    <div
      style={{
        background: 'var(--color-bg-surface)',
        border: '1px solid rgba(255,255,255,0.07)',
        borderRadius: 12,
        padding: 'var(--space-5)',
        position: 'relative',
        overflow: 'hidden',
        transition: 'border-color 0.2s ease, box-shadow 0.2s ease',
      }}
      onMouseEnter={e => {
        ;(e.currentTarget as HTMLDivElement).style.borderColor = 'rgba(0,229,255,0.25)'
        ;(e.currentTarget as HTMLDivElement).style.boxShadow = '0 4px 24px rgba(0,229,255,0.06)'
      }}
      onMouseLeave={e => {
        ;(e.currentTarget as HTMLDivElement).style.borderColor = 'rgba(255,255,255,0.07)'
        ;(e.currentTarget as HTMLDivElement).style.boxShadow = 'none'
      }}
    >
      {/* Top accent line */}
      <div
        style={{
          position: 'absolute',
          top: 0,
          left: 0,
          right: 0,
          height: 2,
          background: 'linear-gradient(90deg, transparent, #00e5ff, transparent)',
          opacity: 0.4,
        }}
      />

      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 'var(--space-3)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <span style={{ fontSize: '1.8rem' }}>{preset?.icon || '🎯'}</span>
          <div>
            <div style={{ fontWeight: 800, fontSize: '1rem', color: '#fff' }}>{target.name}</div>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: 'var(--color-cyan)', marginTop: 2 }}>
              {target.hostname}
            </div>
          </div>
        </div>

        <span
          style={{
            fontSize: '0.65rem',
            fontWeight: 700,
            padding: '3px 8px',
            borderRadius: 4,
            background: 'rgba(0,255,136,0.12)',
            border: '1px solid rgba(0,255,136,0.35)',
            color: '#00ff88',
            letterSpacing: '0.08em',
            display: 'flex',
            alignItems: 'center',
            gap: 5,
          }}
        >
          <span style={{ width: 6, height: 6, borderRadius: '50%', background: '#00ff88', boxShadow: '0 0 6px #00ff88' }} />
          AUTHORIZED
        </span>
      </div>

      {/* Description */}
      <p style={{ fontSize: '0.8rem', color: 'var(--color-text-secondary)', lineHeight: 1.6, marginBottom: 'var(--space-3)' }}>
        {target.description}
      </p>

      {/* Vuln count label */}
      {preset?.vulnCount && (
        <div
          style={{
            fontSize: '0.7rem',
            color: '#ff9800',
            fontFamily: 'var(--font-mono)',
            background: 'rgba(255,152,0,0.08)',
            border: '1px solid rgba(255,152,0,0.2)',
            borderRadius: 4,
            padding: '4px 8px',
            display: 'inline-block',
            marginBottom: 'var(--space-4)',
          }}
        >
          ⚠ {preset.vulnCount}
        </div>
      )}

      {/* Tags */}
      <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginBottom: 'var(--space-4)' }}>
        {(target.tags || []).map((tag: string) => (
          <span
            key={tag}
            style={{
              fontSize: '0.65rem',
              padding: '2px 7px',
              borderRadius: 3,
              background: 'rgba(255,255,255,0.04)',
              border: '1px solid rgba(255,255,255,0.08)',
              color: 'var(--color-text-muted)',
            }}
          >
            {tag}
          </span>
        ))}
      </div>

      {/* Action */}
      <div style={{ display: 'flex', gap: 8 }}>
        <button
          className="btn btn-primary"
          style={{ flex: 1, fontSize: '0.8rem', padding: '8px 12px' }}
          disabled={isScanning}
          onClick={() => onScan(target)}
        >
          {isScanning ? '⏳ Scanning...' : '⚡ Launch AI Hunt'}
        </button>
        <button
          className="btn btn-secondary"
          style={{ fontSize: '0.8rem', padding: '8px 12px' }}
          onClick={() => {
            const url = preset?.defaultUrl || `http://${target.hostname}:80`
            window.open(url, '_blank', 'noopener,noreferrer')
          }}
        >
          ↗ Open
        </button>
      </div>
    </div>
  )
}

export default function Assets() {
  const qc = useQueryClient()
  const [addForm, setAddForm] = useState({ name: '', hostname: '', description: '' })
  const [showAdd, setShowAdd] = useState(false)
  const [scanningTargets, setScanningTargets] = useState<Set<string>>(new Set())

  const { data: targets = [], isLoading } = useQuery({
    queryKey: ['targets'],
    queryFn: () => targetApi.list(),
    retry: false,
    refetchInterval: 8000,
  })

  const createMutation = useMutation({
    mutationFn: (data: any) => targetApi.create(data),
    onSuccess: () => {
      toast.success('Target registered')
      qc.invalidateQueries({ queryKey: ['targets'] })
      setShowAdd(false)
      setAddForm({ name: '', hostname: '', description: '' })
    },
    onError: () => toast.error('Failed to register target'),
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => targetApi.delete(id),
    onSuccess: () => {
      toast.success('Target removed')
      qc.invalidateQueries({ queryKey: ['targets'] })
    },
  })

  const launchScan = async (target: any) => {
    setScanningTargets(prev => new Set([...prev, target.id]))
    try {
      const url = LAB_PRESETS.find(p => p.hostname === target.hostname)?.defaultUrl
        || `http://${target.hostname}:80`

      await scanApi.create({
        name: `${target.name} — AI Hunt ${new Date().toLocaleDateString()}`,
        mode: 'RED',
        plugin: 'nuclei',
        targets: [url],
        target_id: target.id,
        scan_type: 'web',
        profile: 'safe',
      })
      toast.success(`🕷️ AI Hunter dispatched to ${target.name}`)
      qc.invalidateQueries({ queryKey: ['scans'] })
    } catch (err: any) {
      const detail = err?.response?.data?.detail || 'Failed to launch scan'
      toast.error(detail.includes('AUTHORIZATION') ? '🔒 ' + detail.split('AUTHORIZATION ERROR: ')[1] : detail)
    } finally {
      setScanningTargets(prev => {
        const next = new Set(prev)
        next.delete(target.id)
        return next
      })
    }
  }

  return (
    <div>
      {/* Header */}
      <div className="page-header" style={{ marginBottom: 'var(--space-6)' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <span style={{ fontSize: '1.4rem' }}>◎</span>
            <h1 className="page-title gradient-text-cyan" style={{ margin: 0 }}>
              Bug Bounty Targets
            </h1>
          </div>
          <p className="page-subtitle" style={{ marginTop: 4 }}>
            Authorized lab targets — scope-validated, ready for AI-powered vulnerability hunting
          </p>
        </div>
        <div style={{ display: 'flex', gap: 10 }}>
          <button className="btn btn-secondary btn-sm" onClick={() => setShowAdd(s => !s)}>
            {showAdd ? '✕ Cancel' : '+ Add Target'}
          </button>
        </div>
      </div>

      {/* Authorization notice */}
      <div
        style={{
          background: 'rgba(0,255,136,0.04)',
          border: '1px solid rgba(0,255,136,0.2)',
          borderRadius: 8,
          padding: 'var(--space-3) var(--space-4)',
          marginBottom: 'var(--space-5)',
          display: 'flex',
          alignItems: 'flex-start',
          gap: 12,
          fontSize: '0.8rem',
        }}
      >
        <span style={{ color: '#00ff88', fontSize: '1.2rem', flexShrink: 0 }}>✓</span>
        <div>
          <div style={{ color: '#00ff88', fontWeight: 700, marginBottom: 2 }}>
            AUTHORIZED SCOPE ENFORCEMENT ACTIVE
          </div>
          <div style={{ color: 'var(--color-text-secondary)', lineHeight: 1.6 }}>
            All scan requests are validated against registered scopes before dispatch. Unauthorized targets will be
            automatically rejected with HTTP 403. Only OWASP lab targets below are pre-authorized for active testing.
          </div>
        </div>
      </div>

      {/* Add target form */}
      {showAdd && (
        <div className="card animate-fade-in" style={{ marginBottom: 'var(--space-5)' }}>
          <div className="card-header">
            <span className="card-title">Register New Target</span>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 'var(--space-3)' }}>
            <div className="form-group">
              <label className="form-label">Target Name</label>
              <input
                className="input"
                placeholder="e.g. OWASP Juice Shop"
                value={addForm.name}
                onChange={e => setAddForm(p => ({ ...p, name: e.target.value }))}
              />
            </div>
            <div className="form-group">
              <label className="form-label">Hostname / IP</label>
              <input
                className="input input-mono"
                placeholder="e.g. juice-shop or 192.168.1.50"
                value={addForm.hostname}
                onChange={e => setAddForm(p => ({ ...p, hostname: e.target.value }))}
              />
            </div>
          </div>
          <div className="form-group">
            <label className="form-label">Description</label>
            <input
              className="input"
              placeholder="Authorization details and target notes"
              value={addForm.description}
              onChange={e => setAddForm(p => ({ ...p, description: e.target.value }))}
            />
          </div>
          <div
            style={{
              background: 'rgba(255,59,92,0.06)',
              border: '1px solid rgba(255,59,92,0.2)',
              borderRadius: 6,
              padding: 'var(--space-3)',
              fontSize: '0.75rem',
              color: '#ff3b5c',
              marginBottom: 'var(--space-3)',
            }}
          >
            ⚠️ You must add an authorized scope (URL/IP/CIDR) before scanning. Target will require scope validation.
          </div>
          <button
            className="btn btn-primary"
            disabled={createMutation.isPending || !addForm.name || !addForm.hostname}
            onClick={() => createMutation.mutate(addForm)}
          >
            {createMutation.isPending ? 'Registering...' : 'Register Target'}
          </button>
        </div>
      )}

      {/* Pipeline info */}
      <div style={{ marginBottom: 'var(--space-4)' }}>
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 0,
            padding: '10px 16px',
            background: 'rgba(255,255,255,0.02)',
            borderRadius: 8,
            border: '1px solid rgba(255,255,255,0.05)',
            fontSize: '0.72rem',
            fontFamily: 'var(--font-mono)',
            color: 'var(--color-text-muted)',
            overflowX: 'auto',
          }}
        >
          {['Scope Check', 'Nmap Port Scan', 'Endpoint Spider', 'Nuclei Hunt', 'Normalizer', 'Dedup', 'AI Analysis', 'Report'].map(
            (stage, i) => (
              <div key={stage} style={{ display: 'flex', alignItems: 'center', flexShrink: 0 }}>
                {i > 0 && <span style={{ margin: '0 8px', color: 'rgba(0,229,255,0.4)' }}>→</span>}
                <span style={{ color: i === 0 ? '#00ff88' : 'var(--color-text-muted)' }}>{stage}</span>
              </div>
            )
          )}
        </div>
      </div>

      {/* Lab Targets grid */}
      <div style={{ marginBottom: 12 }}>
        <div style={{ fontSize: '0.7rem', fontWeight: 700, color: 'var(--color-text-muted)', letterSpacing: '0.1em', marginBottom: 12 }}>
          AUTHORIZED LAB TARGETS — {(targets as any[]).length} REGISTERED
        </div>
        {isLoading ? (
          <div style={{ color: 'var(--color-text-muted)', padding: 32, textAlign: 'center' }}>
            Loading targets...
          </div>
        ) : (targets as any[]).length === 0 ? (
          <div
            style={{
              textAlign: 'center',
              padding: 48,
              color: 'var(--color-text-muted)',
              border: '1px dashed rgba(255,255,255,0.06)',
              borderRadius: 12,
            }}
          >
            <div style={{ fontSize: '2.5rem', marginBottom: 12 }}>🕷️</div>
            <div style={{ fontWeight: 700, color: '#fff', marginBottom: 8 }}>No targets registered</div>
            <div style={{ fontSize: '0.8rem' }}>
              Start Docker Compose to auto-provision Juice Shop, DVWA, and WebGoat lab targets.
            </div>
            <code
              style={{
                display: 'block',
                marginTop: 16,
                padding: 12,
                background: 'rgba(0,0,0,0.4)',
                borderRadius: 6,
                fontFamily: 'var(--font-mono)',
                fontSize: '0.8rem',
                color: '#00ff88',
              }}
            >
              docker compose up -d
            </code>
          </div>
        ) : (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(340px, 1fr))', gap: 16 }}>
            {(targets as any[]).map((target: any) => (
              <TargetCard
                key={target.id}
                target={target}
                onScan={launchScan}
                isScanning={scanningTargets.has(target.id)}
              />
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
