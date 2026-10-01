import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { scanApi } from '../api/client'
import toast from 'react-hot-toast'

const PLUGINS = ['nmap', 'nuclei', 'zeek', 'yara']
const MODES = ['RED', 'BLUE', 'PURPLE']

export default function Scans() {
  const qc = useQueryClient()
  const [form, setForm] = useState({ name: '', mode: 'RED', plugin: 'nmap', targets: '', options: '{}' })

  const { data: scans = [] } = useQuery({ queryKey: ['scans'], queryFn: () => scanApi.list(), retry: false, refetchInterval: 3000 })

  const createMutation = useMutation({
    mutationFn: (data: any) => scanApi.create(data),
    onSuccess: () => { toast.success('Scan launched!'); qc.invalidateQueries({ queryKey: ['scans'] }) },
    onError: () => toast.error('Failed to launch scan'),
  })

  const cancelMutation = useMutation({
    mutationFn: (id: string) => scanApi.cancel(id),
    onSuccess: () => { toast.success('Scan cancelled'); qc.invalidateQueries({ queryKey: ['scans'] }) },
  })

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    const targets = form.targets.split('\n').map(t => t.trim()).filter(Boolean)
    if (!targets.length) { toast.error('Add at least one target'); return }
    createMutation.mutate({ ...form, targets, options: JSON.parse(form.options || '{}') })
  }

  const statusColor: Record<string, string> = {
    RUNNING: 'var(--color-safe)',
    PENDING: 'var(--color-medium)',
    COMPLETED: 'var(--color-blue)',
    FAILED: 'var(--color-red)',
    CANCELLED: 'var(--color-text-muted)',
  }

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title gradient-text-red">🔴 Security Scans</h1>
          <p className="page-subtitle">Launch and monitor Nmap, Nuclei, YARA, and more</p>
        </div>
      </div>

      <div className="grid-2">
        {/* Launch form */}
        <div className="card">
          <div className="card-header">
            <span className="card-title">🚀 New Scan</span>
          </div>
          <form className="scan-form" onSubmit={handleSubmit}>
            <div className="form-group">
              <label className="form-label">Scan Name</label>
              <input className="input" placeholder="e.g. Internal Network Q4 Audit" value={form.name} onChange={e => setForm(p => ({ ...p, name: e.target.value }))} required />
            </div>
            <div className="grid-2" style={{ gap: 'var(--space-3)' }}>
              <div className="form-group">
                <label className="form-label">Mode</label>
                <select className="input" value={form.mode} onChange={e => setForm(p => ({ ...p, mode: e.target.value }))}>
                  {MODES.map(m => <option key={m} value={m}>{m}</option>)}
                </select>
              </div>
              <div className="form-group">
                <label className="form-label">Plugin / Engine</label>
                <select className="input" value={form.plugin} onChange={e => setForm(p => ({ ...p, plugin: e.target.value }))}>
                  {PLUGINS.map(p => <option key={p} value={p}>{p}</option>)}
                </select>
              </div>
            </div>
            <div className="form-group">
              <label className="form-label">Targets (one per line)</label>
              <textarea className="input input-mono" rows={4} placeholder={'192.168.1.0/24\n10.0.0.1\nhttps://example.com'} value={form.targets} onChange={e => setForm(p => ({ ...p, targets: e.target.value }))} />
            </div>
            <div className="form-group">
              <label className="form-label">Options (JSON)</label>
              <input className="input input-mono" placeholder='{"scan_type": "full", "timing": 3}' value={form.options} onChange={e => setForm(p => ({ ...p, options: e.target.value }))} />
            </div>

            {/* Safety warning */}
            <div style={{
              background: 'rgba(255,59,92,0.08)',
              border: '1px solid rgba(255,59,92,0.2)',
              borderRadius: 'var(--radius-md)',
              padding: 'var(--space-3)',
              fontSize: '0.75rem',
              color: 'var(--color-red)',
            }}>
              ⚠️ Only scan systems you are authorised to test. Ensure a valid scope and authorization document exists.
            </div>

            <button className="btn btn-primary" type="submit" disabled={createMutation.isPending}>
              {createMutation.isPending ? '⏳ Launching...' : '🚀 Launch Scan'}
            </button>
          </form>
        </div>

        {/* Scan list */}
        <div className="card">
          <div className="card-header">
            <span className="card-title">📋 Active & Recent Scans</span>
            <span style={{ fontSize: '0.75rem', color: 'var(--color-text-muted)' }}>Auto-refreshes every 3s</span>
          </div>

          {/* Authorization Notice for Scan Answers */}
          <div style={{
            margin: 'var(--space-3) var(--space-4)',
            padding: 'var(--space-2) var(--space-3)',
            background: 'rgba(255,59,92,0.06)',
            border: '1px solid rgba(255,59,92,0.2)',
            borderRadius: 'var(--radius-sm)',
            fontSize: '0.73rem',
            color: 'var(--color-red)',
            display: 'flex',
            alignItems: 'center',
            gap: 6,
          }}>
            <span>⚠️</span>
            <span>Only scan systems you are authorised to test. Ensure a valid scope and authorization document exists.</span>
          </div>

          {scans.length === 0 ? (
            <div style={{ textAlign: 'center', padding: 'var(--space-10)', color: 'var(--color-text-muted)' }}>
              <div style={{ fontSize: '2rem', marginBottom: 'var(--space-3)' }}>🔍</div>
              <div>No scans yet. Launch your first scan →</div>
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
              {scans.map((scan: any) => (
                <div key={scan.id} className="scan-progress-card">
                  <div className="flex items-center justify-between" style={{ marginBottom: 'var(--space-2)' }}>
                    <div>
                      <div style={{ fontWeight: 600, fontSize: '0.875rem' }}>{scan.name}</div>
                      <div style={{ fontSize: '0.7rem', color: 'var(--color-text-muted)', fontFamily: 'var(--font-mono)' }}>
                        {scan.plugin} · {scan.mode} · {scan.targets?.length} targets
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="status-dot" style={{ background: statusColor[scan.status] || 'var(--color-text-muted)' }} />
                      <span style={{ fontSize: '0.75rem', color: statusColor[scan.status] || 'var(--color-text-muted)' }}>{scan.status}</span>
                    </div>
                  </div>
                  <div className="progress-bar">
                    <div className="progress-fill" style={{ width: `${scan.progress || (scan.status === 'COMPLETED' ? 100 : scan.status === 'RUNNING' ? 45 : 0)}%` }} />
                  </div>
                  <div style={{ fontSize: '0.68rem', color: 'rgba(255,59,92,0.85)', marginTop: 6, display: 'flex', alignItems: 'center', gap: 4 }}>
                    <span>⚠️</span>
                    <span>Only scan systems you are authorised to test. Ensure a valid scope and authorization document exists.</span>
                  </div>
                  {scan.status === 'RUNNING' && (
                    <div style={{ textAlign: 'right', marginTop: 'var(--space-2)' }}>
                      <button className="btn btn-sm btn-danger" onClick={() => cancelMutation.mutate(scan.id)}>Cancel</button>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
