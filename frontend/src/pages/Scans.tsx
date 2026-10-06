import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { scanApi, targetApi, experimentApi } from '../api/client'
import toast from 'react-hot-toast'

const PLUGINS = ['nuclei', 'nmap', 'zeek', 'yara']
const MODES = ['RED', 'BLUE', 'PURPLE']

const statusColor: Record<string, string> = {
  RUNNING: 'var(--color-safe)',
  PENDING: 'var(--color-medium)',
  QUEUED: 'var(--color-medium)',
  COMPLETED: 'var(--color-blue)',
  FAILED: 'var(--color-red)',
  CANCELLED: 'var(--color-text-muted)',
}

function ScanEventTimeline({ events }: { events: any[] }) {
  if (!events?.length) return null
  return (
    <div style={{ marginTop: 12, borderLeft: '2px solid rgba(0,229,255,0.2)', paddingLeft: 12 }}>
      {events.slice(-5).map((ev: any, i: number) => (
        <div key={i} style={{ display: 'flex', gap: 8, marginBottom: 6, fontSize: '0.7rem', color: 'var(--color-text-muted)' }}>
          <span style={{ color: 'var(--color-cyan)', flexShrink: 0 }}>▸</span>
          <span style={{ color: 'var(--color-text-secondary)' }}>{ev.event_type}</span>
          {ev.message && <span>{ev.message}</span>}
        </div>
      ))}
    </div>
  )
}

function MetricCard({ label, value, color = 'var(--color-cyan)', sub }: { label: string; value: any; color?: string; sub?: string }) {
  return (
    <div style={{
      background: 'var(--color-bg-surface)',
      border: '1px solid rgba(255,255,255,0.06)',
      borderRadius: 10,
      padding: 'var(--space-4)',
      textAlign: 'center',
    }}>
      <div style={{ fontSize: '1.6rem', fontWeight: 800, color, fontFamily: 'var(--font-mono)' }}>{value ?? '-'}</div>
      <div style={{ fontSize: '0.65rem', color: 'var(--color-text-muted)', marginTop: 4, textTransform: 'uppercase', letterSpacing: '0.08em' }}>{label}</div>
      {sub && <div style={{ fontSize: '0.65rem', color: 'var(--color-text-secondary)', marginTop: 2 }}>{sub}</div>}
    </div>
  )
}

export default function Scans() {
  const qc = useQueryClient()
  const [form, setForm] = useState({
    name: '',
    mode: 'RED',
    plugin: 'nuclei',
    targets: '',
    target_id: '',
    options: '{}',
  })
  const [selectedScan, setSelectedScan] = useState<string | null>(null)

  const { data: scans = [] } = useQuery({
    queryKey: ['scans'],
    queryFn: () => scanApi.list(),
    retry: false,
    refetchInterval: 4000,
  })

  const { data: targets = [] } = useQuery({
    queryKey: ['targets'],
    queryFn: () => targetApi.list(),
    retry: false,
  })

  const { data: metrics } = useQuery({
    queryKey: ['experiment-metrics'],
    queryFn: () => experimentApi.metrics(),
    retry: false,
    refetchInterval: 10000,
  })

  const { data: scanEvents = [] } = useQuery({
    queryKey: ['scan-events', selectedScan],
    queryFn: () => (selectedScan ? experimentApi.scanEvents(selectedScan) : Promise.resolve([])),
    enabled: !!selectedScan,
    refetchInterval: selectedScan ? 3000 : false,
  })

  const createMutation = useMutation({
    mutationFn: (data: any) => scanApi.create(data),
    onSuccess: () => {
      toast.success('🕷️ Scan dispatched to worker queue')
      qc.invalidateQueries({ queryKey: ['scans'] })
      qc.invalidateQueries({ queryKey: ['experiment-metrics'] })
    },
    onError: (err: any) => {
      const detail = err?.response?.data?.detail || 'Failed to launch scan'
      toast.error(detail)
    },
  })

  const cancelMutation = useMutation({
    mutationFn: (id: string) => scanApi.cancel(id),
    onSuccess: () => {
      toast.success('Scan cancelled')
      qc.invalidateQueries({ queryKey: ['scans'] })
    },
  })

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    const targetsArr = form.targets.split('\n').map(t => t.trim()).filter(Boolean)
    if (!targetsArr.length) { toast.error('Add at least one target'); return }
    try {
      JSON.parse(form.options || '{}')
    } catch {
      toast.error('Options must be valid JSON'); return
    }
    createMutation.mutate({
      ...form,
      targets: targetsArr,
      options: JSON.parse(form.options || '{}'),
      target_id: form.target_id || undefined,
    })
  }

  return (
    <div>
      {/* Header */}
      <div className="page-header">
        <div>
          <h1 className="page-title gradient-text-red">⚡ Scan Pipeline</h1>
          <p className="page-subtitle">Dispatch, monitor, and validate AI-powered security scans</p>
        </div>
      </div>

      {/* Experiment metrics bar */}
      {metrics && (
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(120px, 1fr))',
          gap: 10,
          marginBottom: 'var(--space-5)',
        }}>
          <MetricCard label="Total Scans" value={metrics.total_scans} />
          <MetricCard label="Completed" value={metrics.completed} color="var(--color-blue)" />
          <MetricCard label="Findings" value={metrics.total_findings} color="#ff9800" />
          <MetricCard label="Critical" value={metrics.critical_findings} color="var(--color-critical)" />
          <MetricCard label="High" value={metrics.high_findings} color="var(--color-high)" />
          <MetricCard label="Dedup Rate" value={metrics.dedup_rate != null ? `${metrics.dedup_rate}%` : '-'} color="var(--color-cyan)" />
          <MetricCard label="AI Analyzed" value={metrics.ai_analyzed} color="var(--color-purple)" />
          <MetricCard label="Active Targets" value={metrics.active_targets} color="var(--color-safe)" />
        </div>
      )}

      <div className="grid-2">
        {/* Launch form */}
        <div className="card">
          <div className="card-header">
            <span className="card-title">🚀 New Scan</span>
          </div>
          <form className="scan-form" onSubmit={handleSubmit}>
            <div className="form-group">
              <label className="form-label">Scan Name</label>
              <input
                className="input"
                placeholder="e.g. Juice Shop Full Hunt"
                value={form.name}
                onChange={e => setForm(p => ({ ...p, name: e.target.value }))}
                required
              />
            </div>

            {/* Quick-fill from targets */}
            {(targets as any[]).length > 0 && (
              <div className="form-group">
                <label className="form-label">Lab Target (optional)</label>
                <select
                  className="input"
                  value={form.target_id}
                  onChange={e => {
                    const t = (targets as any[]).find((x: any) => x.id === e.target.value)
                    setForm(p => ({
                      ...p,
                      target_id: e.target.value,
                      targets: t ? `http://${t.hostname}:3000\nhttp://${t.hostname}:80\nhttp://${t.hostname}:8080` : p.targets,
                      name: t ? `${t.name} — AI Hunt` : p.name,
                    }))
                  }}
                >
                  <option value="">— custom targets below —</option>
                  {(targets as any[]).map((t: any) => (
                    <option key={t.id} value={t.id}>
                      {t.name} ({t.hostname})
                    </option>
                  ))}
                </select>
              </div>
            )}

            <div className="grid-2" style={{ gap: 'var(--space-3)' }}>
              <div className="form-group">
                <label className="form-label">Mode</label>
                <select className="input" value={form.mode} onChange={e => setForm(p => ({ ...p, mode: e.target.value }))}>
                  {MODES.map(m => <option key={m} value={m}>{m}</option>)}
                </select>
              </div>
              <div className="form-group">
                <label className="form-label">Scanner Engine</label>
                <select className="input" value={form.plugin} onChange={e => setForm(p => ({ ...p, plugin: e.target.value }))}>
                  {PLUGINS.map(p => <option key={p} value={p}>{p}</option>)}
                </select>
              </div>
            </div>

            <div className="form-group">
              <label className="form-label">Targets (one per line)</label>
              <textarea
                className="input input-mono"
                rows={4}
                placeholder={'http://juice-shop:3000\nhttps://example.com\n192.168.1.0/24'}
                value={form.targets}
                onChange={e => setForm(p => ({ ...p, targets: e.target.value }))}
              />
            </div>

            <div className="form-group">
              <label className="form-label">Options (JSON)</label>
              <input
                className="input input-mono"
                placeholder='{"scan_type": "full", "severity": ["critical","high"]}'
                value={form.options}
                onChange={e => setForm(p => ({ ...p, options: e.target.value }))}
              />
            </div>

            {/* Pipeline preview */}
            <div style={{
              padding: 'var(--space-2) var(--space-3)',
              background: 'rgba(0,0,0,0.2)',
              borderRadius: 6,
              fontFamily: 'var(--font-mono)',
              fontSize: '0.68rem',
              color: 'var(--color-text-muted)',
              marginBottom: 'var(--space-2)',
            }}>
              🔴 {form.plugin} → Normalize → Dedup → AI Risk Score → Store
            </div>

            <div style={{
              background: 'rgba(255,59,92,0.08)',
              border: '1px solid rgba(255,59,92,0.2)',
              borderRadius: 'var(--radius-md)',
              padding: 'var(--space-3)',
              fontSize: '0.75rem',
              color: 'var(--color-red)',
            }}>
              ⚠️ Only scan systems you are authorised to test. Targets not in an authorized scope will be rejected.
            </div>

            <button className="btn btn-primary" type="submit" disabled={createMutation.isPending}>
              {createMutation.isPending ? '⏳ Dispatching...' : '🚀 Launch Scan'}
            </button>
          </form>
        </div>

        {/* Scan list */}
        <div className="card">
          <div className="card-header">
            <span className="card-title">📋 Active & Recent Scans</span>
            <span style={{ fontSize: '0.72rem', color: 'var(--color-text-muted)' }}>Live — 4s refresh</span>
          </div>

          {(scans as any[]).length === 0 ? (
            <div style={{ textAlign: 'center', padding: 'var(--space-10)', color: 'var(--color-text-muted)' }}>
              <div style={{ fontSize: '2rem', marginBottom: 'var(--space-3)' }}>🔍</div>
              <div>No scans yet. Launch your first scan →</div>
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)', maxHeight: 600, overflowY: 'auto', paddingRight: 4 }}>
              {(scans as any[]).map((scan: any) => {
                const progress = scan.progress ?? (
                  scan.status === 'COMPLETED' ? 100 :
                  scan.status === 'RUNNING' ? 50 :
                  scan.status === 'PENDING' || scan.status === 'QUEUED' ? 10 : 0
                )
                const isSelected = selectedScan === scan.id
                return (
                  <div
                    key={scan.id}
                    className="scan-progress-card"
                    style={{
                      cursor: 'pointer',
                      border: isSelected ? '1px solid rgba(0,229,255,0.3)' : undefined,
                    }}
                    onClick={() => setSelectedScan(isSelected ? null : scan.id)}
                  >
                    <div className="flex items-center justify-between" style={{ marginBottom: 'var(--space-2)' }}>
                      <div>
                        <div style={{ fontWeight: 600, fontSize: '0.875rem' }}>{scan.name}</div>
                        <div style={{ fontSize: '0.7rem', color: 'var(--color-text-muted)', fontFamily: 'var(--font-mono)' }}>
                          {scan.plugin} · {scan.mode} · {scan.targets?.length} targets
                          {scan.findings_count != null && (
                            <span style={{ color: '#ff9800', marginLeft: 6 }}>· {scan.findings_count} findings</span>
                          )}
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className="status-dot" style={{ background: statusColor[scan.status] || 'var(--color-text-muted)' }} />
                        <span style={{ fontSize: '0.75rem', color: statusColor[scan.status] || 'var(--color-text-muted)' }}>
                          {scan.status}
                        </span>
                      </div>
                    </div>

                    <div className="progress-bar">
                      <div
                        className="progress-fill"
                        style={{
                          width: `${progress}%`,
                          background: scan.status === 'FAILED' ? 'var(--color-red)' :
                            scan.status === 'COMPLETED' ? 'var(--color-blue)' :
                            'linear-gradient(90deg, var(--color-cyan), var(--color-purple))',
                        }}
                      />
                    </div>

                    {/* AI analysis indicator */}
                    {scan.status === 'COMPLETED' && (
                      <div style={{
                        fontSize: '0.65rem',
                        color: 'var(--color-purple)',
                        marginTop: 6,
                        display: 'flex',
                        alignItems: 'center',
                        gap: 4,
                      }}>
                        <span>✦</span>
                        <span>AI analysis complete · Risk-scored · Deduplicated</span>
                      </div>
                    )}

                    {/* Event timeline (expanded) */}
                    {isSelected && <ScanEventTimeline events={scanEvents} />}

                    {/* Actions */}
                    <div style={{ display: 'flex', gap: 6, marginTop: 8, justifyContent: 'flex-end' }}>
                      {scan.status === 'RUNNING' && (
                        <button
                          className="btn btn-sm btn-danger"
                          onClick={e => { e.stopPropagation(); cancelMutation.mutate(scan.id) }}
                        >
                          Cancel
                        </button>
                      )}
                      {scan.status === 'COMPLETED' && (
                        <button
                          className="btn btn-sm"
                          style={{ fontSize: '0.7rem', padding: '4px 10px', background: 'rgba(138,43,226,0.15)', border: '1px solid rgba(138,43,226,0.3)', color: 'var(--color-purple)' }}
                          onClick={e => {
                            e.stopPropagation()
                            experimentApi.generateScanReport(scan.id).then(() => {
                              toast.success('Report generated')
                              qc.invalidateQueries({ queryKey: ['reports'] })
                            }).catch(() => toast.error('Report generation failed'))
                          }}
                        >
                          📄 Generate Report
                        </button>
                      )}
                    </div>
                  </div>
                )
              })}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
