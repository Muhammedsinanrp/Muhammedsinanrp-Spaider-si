import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '../api/client'
import toast from 'react-hot-toast'

const REPORT_TYPES = [
  {
    type: 'executive',
    label: 'Executive Report',
    icon: '📊',
    desc: 'Security posture · Critical findings · Attack surface · Major risks · Board-ready',
    color: 'var(--color-cyan)',
    badge: 'C-Suite',
  },
  {
    type: 'technical',
    label: 'Technical Report',
    icon: '🔬',
    desc: 'Finding · Asset · Evidence · CVE · CVSS · MITRE · Reproduction · Remediation',
    color: 'var(--color-blue)',
    badge: 'Engineers',
  },
  {
    type: 'soc',
    label: 'SOC Report',
    icon: '🛡️',
    desc: 'Incident · Timeline · Indicators · Detection rules · MITRE · Response actions',
    color: 'var(--color-purple)',
    badge: 'SOC Team',
  },
]

function generateReportApi(data: any) {
  return api.post('/reports/generate', data).then(r => r.data)
}

function listReportsApi() {
  return api.get('/reports').then(r => r.data)
}

function deleteReportApi(id: string) {
  return api.delete(`/reports/${id}`).then(r => r.data)
}

function getReportApi(id: string) {
  return api.get(`/reports/${id}`).then(r => r.data)
}

function SeverityTable({ breakdown }: { breakdown: Record<string, number> }) {
  const colors: Record<string, string> = {
    CRITICAL: 'var(--color-critical)', HIGH: 'var(--color-high)',
    MEDIUM: 'var(--color-medium)', LOW: 'var(--color-low)', INFO: 'var(--color-info)',
  }
  return (
    <div style={{ display: 'flex', gap: 'var(--space-3)', flexWrap: 'wrap' }}>
      {Object.entries(breakdown).map(([sev, count]) => (
        <div key={sev} style={{
          background: 'rgba(255,255,255,0.04)', borderRadius: 'var(--radius-md)',
          border: `1px solid ${colors[sev] || 'var(--color-border)'}`,
          padding: 'var(--space-3) var(--space-4)', textAlign: 'center',
        }}>
          <div style={{ fontSize: '1.5rem', fontWeight: 800, color: colors[sev] }}>{count}</div>
          <div style={{ fontSize: '0.65rem', color: 'var(--color-text-muted)', fontWeight: 700, textTransform: 'uppercase' }}>{sev}</div>
        </div>
      ))}
    </div>
  )
}

function ReportView({ report }: { report: any }) {
  const content = report.content || {}
  const type = report.report_type

  return (
    <div className="animate-fade-in">
      <div style={{ marginBottom: 'var(--space-4)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <div style={{ fontSize: '0.7rem', color: 'var(--color-cyan)', fontWeight: 700, letterSpacing: '0.1em', textTransform: 'uppercase', marginBottom: 4 }}>
            {type?.toUpperCase()} REPORT
          </div>
          <h2 style={{ fontSize: '1.25rem', fontWeight: 700 }}>{report.title}</h2>
          <div style={{ fontSize: '0.75rem', color: 'var(--color-text-muted)', marginTop: 4 }}>
            Generated {new Date(report.created_at).toLocaleString()}
          </div>
        </div>
      </div>

      {type === 'executive' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}>
          <div className="card">
            <div className="card-header"><span className="card-title">Executive Summary</span></div>
            <p style={{ fontSize: '0.9rem', lineHeight: 1.7, color: 'var(--color-text-secondary)' }}>{content.executive_summary}</p>
          </div>
          {content.severity_breakdown && (
            <div className="card">
              <div className="card-header"><span className="card-title">Severity Breakdown</span></div>
              <SeverityTable breakdown={content.severity_breakdown} />
            </div>
          )}
          {content.top_risks?.length > 0 && (
            <div className="card">
              <div className="card-header"><span className="card-title">Top Risks</span></div>
              {content.top_risks.map((r: string, i: number) => (
                <div key={i} style={{ display: 'flex', gap: 'var(--space-3)', marginBottom: 'var(--space-2)', fontSize: '0.875rem' }}>
                  <span style={{ color: 'var(--color-red)', fontWeight: 700 }}>{i + 1}.</span>
                  <span>{r}</span>
                </div>
              ))}
            </div>
          )}
          <div className="card">
            <div className="card-header"><span className="card-title">Recommendation</span></div>
            <p style={{ fontSize: '0.9rem', lineHeight: 1.7, color: 'var(--color-text-secondary)' }}>{content.recommendation}</p>
          </div>
        </div>
      )}

      {type === 'technical' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}>
          {content.severity_breakdown && (
            <div className="card">
              <div className="card-header">
                <span className="card-title">Severity Breakdown</span>
                <span className="badge badge-medium">{content.total_findings} total</span>
              </div>
              <SeverityTable breakdown={content.severity_breakdown} />
            </div>
          )}
          {content.findings?.length > 0 && (
            <div className="card">
              <div className="card-header"><span className="card-title">Findings</span></div>
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Title</th>
                    <th>Severity</th>
                    <th>Plugin</th>
                    <th>CVEs</th>
                    <th>MITRE</th>
                  </tr>
                </thead>
                <tbody>
                  {content.findings.map((f: any) => (
                    <tr key={f.id}>
                      <td style={{ maxWidth: 320, fontSize: '0.8rem' }}>{f.title}</td>
                      <td><span className={`badge badge-${f.severity.toLowerCase()}`}>{f.severity}</span></td>
                      <td style={{ fontSize: '0.75rem', color: 'var(--color-text-muted)' }}>{f.plugin || '—'}</td>
                      <td style={{ fontSize: '0.7rem', fontFamily: 'var(--font-mono)' }}>{f.cve_ids?.join(', ') || '—'}</td>
                      <td style={{ fontSize: '0.7rem' }}>{f.mitre_techniques?.join(', ') || '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {type === 'soc' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}>
          <div className="stats-grid" style={{ gridTemplateColumns: 'repeat(3, 1fr)' }}>
            {[
              { label: 'Total Incidents', value: content.incident_count, icon: '🔔' },
              { label: 'Open Incidents', value: content.open_incidents, icon: '🚨' },
              { label: 'Detection Gaps', value: content.detection_gaps, icon: '⚠️' },
            ].map(s => (
              <div key={s.label} className="stat-card">
                <div className="stat-icon">{s.icon}</div>
                <div className="stat-value">{s.value}</div>
                <div className="stat-label">{s.label}</div>
              </div>
            ))}
          </div>
          {content.detection_sources?.length > 0 && (
            <div className="card">
              <div className="card-header"><span className="card-title">Detection Sources</span></div>
              <div className="flex gap-2">
                {content.detection_sources.map((src: string) => (
                  <span key={src} className="target-tag">{src}</span>
                ))}
              </div>
            </div>
          )}
          {content.mitre_techniques_observed?.length > 0 && (
            <div className="card">
              <div className="card-header"><span className="card-title">Observed MITRE ATT&CK Techniques</span></div>
              <div className="flex gap-2" style={{ flexWrap: 'wrap' }}>
                {content.mitre_techniques_observed.map((t: string) => (
                  <span key={t} className="mitre-chip">{t}</span>
                ))}
              </div>
            </div>
          )}
          {content.recommendations?.length > 0 && (
            <div className="card">
              <div className="card-header"><span className="card-title">Recommendations</span></div>
              {content.recommendations.map((r: string, i: number) => (
                <div key={i} style={{ display: 'flex', gap: 'var(--space-3)', marginBottom: 'var(--space-2)', fontSize: '0.875rem' }}>
                  <span style={{ color: 'var(--color-safe)', fontWeight: 700 }}>{i + 1}.</span>
                  <span>{r}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

export default function Reports() {
  const qc = useQueryClient()
  const [selectedType, setSelectedType] = useState<string | null>(null)
  const [title, setTitle] = useState('')
  const [generating, setGenerating] = useState(false)
  const [viewingReport, setViewingReport] = useState<any>(null)

  const { data: reports = [] } = useQuery({
    queryKey: ['reports'],
    queryFn: listReportsApi,
    retry: false,
    refetchInterval: 10000,
  })

  const generateMutation = useMutation({
    mutationFn: generateReportApi,
    onSuccess: (data) => {
      toast.success('Report generated!')
      qc.invalidateQueries({ queryKey: ['reports'] })
      setViewingReport(data)
      setSelectedType(null)
      setTitle('')
    },
    onError: () => toast.error('Failed to generate report'),
  })

  const deleteMutation = useMutation({
    mutationFn: deleteReportApi,
    onSuccess: () => {
      toast.success('Report deleted')
      qc.invalidateQueries({ queryKey: ['reports'] })
      if (viewingReport) setViewingReport(null)
    },
  })

  const handleGenerate = () => {
    if (!selectedType) { toast.error('Select a report type'); return }
    if (!title.trim()) { toast.error('Enter a report title'); return }
    generateMutation.mutate({
      title,
      report_type: selectedType,
      include_findings: true,
      include_alerts: true,
      include_mitre: true,
    })
  }

  const handleView = async (id: string) => {
    try {
      const report = await getReportApi(id)
      setViewingReport(report)
    } catch {
      toast.error('Failed to load report')
    }
  }

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title gradient-text-cyan">📑 Security Reports</h1>
          <p className="page-subtitle">AI-generated reports — Executive · Technical · SOC</p>
        </div>
      </div>

      {!viewingReport ? (
        <>
          {/* Report Type Selection */}
          <div className="grid-3 mb-6">
            {REPORT_TYPES.map(r => (
              <div
                key={r.type}
                className="card"
                onClick={() => setSelectedType(r.type)}
                style={{
                  textAlign: 'center',
                  cursor: 'pointer',
                  borderTop: `3px solid ${r.color}`,
                  outline: selectedType === r.type ? `2px solid ${r.color}` : 'none',
                  outlineOffset: 2,
                  transition: 'all 0.2s',
                  transform: selectedType === r.type ? 'scale(1.02)' : 'scale(1)',
                }}
              >
                <div style={{ fontSize: '2.5rem', marginBottom: 'var(--space-3)' }}>{r.icon}</div>
                <div style={{ fontWeight: 700, fontSize: '1rem', marginBottom: 'var(--space-2)' }}>{r.label}</div>
                <span className="target-tag" style={{ marginBottom: 'var(--space-3)', display: 'inline-block' }}>{r.badge}</span>
                <div style={{ fontSize: '0.78rem', color: 'var(--color-text-muted)', lineHeight: 1.6 }}>{r.desc}</div>
              </div>
            ))}
          </div>

          {/* Generate */}
          {selectedType && (
            <div className="card mb-6 animate-fade-in">
              <div className="card-header">
                <span className="card-title">Generate {REPORT_TYPES.find(r => r.type === selectedType)?.label}</span>
              </div>
              <div className="form-group" style={{ marginBottom: 'var(--space-4)' }}>
                <label className="form-label">Report Title</label>
                <input
                  className="input"
                  placeholder={`e.g. Q4 2026 ${REPORT_TYPES.find(r => r.type === selectedType)?.label}`}
                  value={title}
                  onChange={e => setTitle(e.target.value)}
                />
              </div>
              <div className="flex gap-2">
                <button
                  className="btn btn-primary"
                  onClick={handleGenerate}
                  disabled={generateMutation.isPending}
                >
                  {generateMutation.isPending ? '⏳ Generating...' : '🚀 Generate Report'}
                </button>
                <button className="btn btn-ghost" onClick={() => setSelectedType(null)}>Cancel</button>
              </div>
            </div>
          )}

          {/* Report list */}
          <div className="card">
            <div className="card-header">
              <span className="card-title">Recent Reports</span>
              <span style={{ fontSize: '0.75rem', color: 'var(--color-text-muted)' }}>{reports.length} reports</span>
            </div>
            {reports.length === 0 ? (
              <div style={{ textAlign: 'center', padding: 'var(--space-10)', color: 'var(--color-text-muted)' }}>
                <div style={{ fontSize: '2.5rem', marginBottom: 'var(--space-3)' }}>📑</div>
                <div>No reports yet. Select a type above and generate your first report.</div>
              </div>
            ) : (
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Title</th>
                    <th>Type</th>
                    <th>Generated</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {reports.map((r: any) => (
                    <tr key={r.id}>
                      <td style={{ fontWeight: 600 }}>{r.title}</td>
                      <td>
                        <span className="target-tag">{r.report_type}</span>
                      </td>
                      <td style={{ fontSize: '0.75rem', color: 'var(--color-text-muted)' }}>
                        {new Date(r.created_at).toLocaleString()}
                      </td>
                      <td>
                        <div className="flex gap-2">
                          <button className="btn btn-sm btn-primary" onClick={() => handleView(r.id)}>View</button>
                          <button
                            className="btn btn-sm btn-danger"
                            onClick={() => deleteMutation.mutate(r.id)}
                          >Delete</button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </>
      ) : (
        <div>
          <button className="btn btn-ghost mb-4" onClick={() => setViewingReport(null)}>
            ← Back to Reports
          </button>
          <ReportView report={viewingReport} />
        </div>
      )}
    </div>
  )
}
