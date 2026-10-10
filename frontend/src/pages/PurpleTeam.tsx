import { useEffect, useState } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import { findingApi, purpleApi } from '../api/client'
import toast from 'react-hot-toast'

const TECHNIQUES = [
  { id:'T1059.001', name:'PowerShell' },
  { id:'T1021.002', name:'SMB/Windows Admin Shares' },
  { id:'T1110', name:'Brute Force' },
  { id:'T1046', name:'Network Service Discovery' },
  { id:'T1071.001', name:'Web Protocols (C2)' },
  { id:'T1048', name:'Exfiltration Over Alternative Protocol' },
]

export default function PurpleTeam() {
  const [form, setForm] = useState({
    finding_id: '',
    test_technique: 'T1059.001',
    detection_sources: ['wazuh', 'zeek', 'suricata'],
    safe_mode: true,
  })
  const [result, setResult] = useState<any>(null)

  const findingsQuery = useQuery({
    queryKey: ['purple-findings'],
    queryFn: () => findingApi.list({ limit: 100 }),
    retry: false,
    refetchInterval: 15000,
  })
  const findings: any[] = Array.isArray(findingsQuery.data) ? findingsQuery.data : []
  const gapsQuery = useQuery({
    queryKey: ['purple-gaps'],
    queryFn: () => purpleApi.gaps(),
    retry: false,
    refetchInterval: 15000,
  })
  const gaps: any[] = Array.isArray(gapsQuery.data) ? gapsQuery.data : []

  useEffect(() => {
    if (!form.finding_id && findings.length) {
      setForm(p => ({ ...p, finding_id: String(findings[0].id) }))
    }
  }, [findings, form.finding_id])

  const validateMutation = useMutation({
    mutationFn: (data: any) => purpleApi.validate(data),
    onSuccess: (data: any) => {
      setResult(data)
      toast.success('Historical alert correlation complete')
      gapsQuery.refetch()
    },
    onError: (err: any) => {
      setResult(null)
      toast.error(String(err?.response?.data?.detail || 'Could not correlate stored alerts'))
    },
  })

  const toggleSource = (src: string) => {
    setForm(p => ({
      ...p,
      detection_sources: p.detection_sources.includes(src)
        ? p.detection_sources.filter(s => s !== src)
        : [...p.detection_sources, src],
    }))
  }

  const runCorrelation = () => {
    if (!form.finding_id) {
      toast.error('Run an authorized scan and save a finding first.')
      return
    }
    if (!form.detection_sources.length) {
      toast.error('Select at least one telemetry source.')
      return
    }
    setResult(null)
    validateMutation.mutate({
      finding_id: form.finding_id,
      test_technique: form.test_technique,
      detection_sources: form.detection_sources,
      safe_mode: true,
      lookback_hours: 168,
    })
  }

  const dateTime = (value?: string) => {
    if (!value) return 'Time unavailable'
    const date = new Date(value)
    return Number.isNaN(date.getTime()) ? 'Time unavailable' : date.toLocaleString()
  }

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title gradient-text-purple">🟣 Purple Team Telemetry</h1>
          <p className="page-subtitle">Correlate saved detections with ATT&CK techniques. No attack simulation is executed by this screen.</p>
        </div>
        <div className="flex gap-2">
          <span className="badge badge-info">HISTORICAL CORRELATION</span>
        </div>
      </div>

      <div style={{
        background:'linear-gradient(135deg, rgba(168,85,247,0.1), rgba(59,130,246,0.1))',
        border:'1px solid rgba(168,85,247,0.3)', borderRadius:'var(--radius-lg)',
        padding:'var(--space-5)', marginBottom:'var(--space-6)',
        display:'flex', gap:'var(--space-4)', alignItems:'center',
      }}>
        <div style={{ fontSize:'2rem' }}>🎯</div>
        <div>
          <div style={{ fontWeight:700, fontSize:'1rem', marginBottom:4 }}>Evidence-first defensive coverage</div>
          <div style={{ fontSize:'0.875rem', color:'var(--color-text-secondary)' }}>
            SPAiDER searches saved alert records for the selected technique over the last seven days.
            No matching alert is not proof of a detection failure; verify sensor health and use an approved controlled simulation before declaring a gap.
          </div>
        </div>
      </div>

      {(findingsQuery.isError || gapsQuery.isError) && (
        <div role="alert" className="card" style={{ marginBottom:'var(--space-5)', color:'var(--color-high)' }}>
          One or more API requests failed. The page will not substitute demo findings or gap records.
        </div>
      )}

      <div className="grid-2" style={{ alignItems:'start' }}>
        <div className="card">
          <div className="card-header"><span className="card-title">🔍 Correlate a saved finding</span></div>

          <div className="form-group">
            <label className="form-label" htmlFor="purple-finding">Saved finding</label>
            {findingsQuery.isLoading ? (
              <div style={{ fontSize:'0.8rem', color:'var(--color-text-muted)' }}>Loading findings…</div>
            ) : findings.length ? (
              <select id="purple-finding" className="input" value={form.finding_id}
                onChange={e => { setForm(p => ({ ...p, finding_id:e.target.value })); setResult(null) }}>
                {findings.map(f => (
                  <option key={f.id} value={String(f.id)}>[{String(f.severity || 'INFO').toUpperCase()}] {f.title}</option>
                ))}
              </select>
            ) : (
              <div style={{ fontSize:'0.8rem', color:'var(--color-text-muted)' }}>
                No saved findings yet. Run a scoped scan before doing telemetry correlation.
              </div>
            )}
          </div>

          <div className="form-group">
            <label className="form-label" htmlFor="purple-technique">ATT&CK Technique</label>
            <select id="purple-technique" className="input" value={form.test_technique}
              onChange={e => { setForm(p => ({ ...p, test_technique:e.target.value })); setResult(null) }}>
              {TECHNIQUES.map(t => <option key={t.id} value={t.id}>{t.id} — {t.name}</option>)}
            </select>
          </div>

          <div className="form-group">
            <label className="form-label">Stored telemetry sources to include</label>
            <div className="flex gap-2">
              {['wazuh','zeek','suricata'].map(src => (
                <button type="button" key={src}
                  className={`btn btn-sm ${form.detection_sources.includes(src) ? 'btn-primary' : 'btn-ghost'}`}
                  onClick={() => { toggleSource(src); setResult(null) }}>{src}</button>
              ))}
            </div>
          </div>

          <div style={{
            marginTop:'var(--space-3)', marginBottom:'var(--space-3)', padding:'var(--space-3)',
            background:'rgba(255,152,0,0.07)', border:'1px solid rgba(255,152,0,0.25)',
            borderRadius:'var(--radius-md)', fontSize:'0.76rem', color:'var(--color-medium)', lineHeight:1.55,
          }}>
            <strong>Correlation only:</strong> this action reads stored alert records from the database. It does not run PowerShell, brute force, lateral movement, exploit code, or any other ATT&CK behavior.
          </div>

          <button type="button" className="btn btn-primary" onClick={runCorrelation}
            disabled={validateMutation.isPending || findings.length === 0 || !form.detection_sources.length}>
            {validateMutation.isPending ? '⏳ Correlating saved alerts…' : '🟣 Correlate saved alerts'}
          </button>

          {result && (
            <div style={{ marginTop:'var(--space-6)' }} className="animate-fade-in">
              <div className="card-header" style={{ marginBottom:'var(--space-3)' }}>
                <span className="card-title">Correlation Result</span>
                <span className="badge badge-info">{result.status || 'RESULT'}</span>
              </div>
              <div style={{ fontSize:'0.75rem', color:'var(--color-text-muted)', marginBottom:'var(--space-3)' }}>
                Finding: {result.finding_title || result.finding_id} · Technique: {result.technique} · Lookback: {result.lookback_hours}h
              </div>

              <div style={{ display:'flex', gap:'var(--space-3)', marginBottom:'var(--space-4)' }}>
                <div style={{ flex:1, padding:'var(--space-4)', background:'rgba(0,230,118,0.06)', borderRadius:'var(--radius-md)', border:'1px solid rgba(0,230,118,0.2)', textAlign:'center' }}>
                  <div style={{ fontSize:'0.7rem', color:'var(--color-safe)', fontWeight:700, marginBottom:4 }}>MATCHING ALERT SOURCES</div>
                  {result.detected_by?.length
                    ? result.detected_by.map((d:string) => <div key={d} style={{ fontWeight:700 }}>{d}</div>)
                    : <div style={{ fontSize:'0.8rem', color:'var(--color-text-muted)' }}>No matches</div>}
                </div>
                <div style={{ flex:1, padding:'var(--space-4)', background:'rgba(255,152,0,0.06)', borderRadius:'var(--radius-md)', border:'1px solid rgba(255,152,0,0.2)', textAlign:'center' }}>
                  <div style={{ fontSize:'0.7rem', color:'var(--color-medium)', fontWeight:700, marginBottom:4 }}>NO MATCHING ALERT OBSERVED</div>
                  {result.no_matching_alert_observed?.length
                    ? result.no_matching_alert_observed.map((d:string) => <div key={d} style={{ fontWeight:700 }}>{d}</div>)
                    : <div style={{ fontSize:'0.8rem', color:'var(--color-text-muted)' }}>None</div>}
                </div>
              </div>

              <div style={{ padding:'var(--space-4)', background:'rgba(168,85,247,0.06)', borderRadius:'var(--radius-md)', border:'1px solid rgba(168,85,247,0.2)', marginBottom:'var(--space-4)' }}>
                <div style={{ fontSize:'0.7rem', color:'var(--color-purple)', fontWeight:700, marginBottom:4 }}>HISTORICAL ALERT MATCH RATE</div>
                <div style={{ fontSize:'2rem', fontWeight:900, color:'var(--color-purple)' }}>{result.coverage}%</div>
                <div style={{ fontSize:'0.7rem', color:'var(--color-text-muted)' }}>Not a measurement of sensor efficacy or exploit detection.</div>
              </div>

              {result.evidence?.length > 0 && (
                <div style={{ marginBottom:'var(--space-4)' }}>
                  <div className="form-label" style={{ marginBottom:8 }}>Matched alert evidence</div>
                  {result.evidence.map((e:any) => (
                    <div key={e.alert_id} style={{ padding:'var(--space-3)', border:'1px solid var(--color-border)', borderRadius:'var(--radius-md)', marginBottom:6 }}>
                      <div style={{ fontWeight:700, fontSize:'0.8rem' }}>{e.title}</div>
                      <div style={{ color:'var(--color-text-muted)', fontSize:'0.7rem', marginTop:4 }}>{e.source} · {dateTime(e.created_at)} · {e.alert_id}</div>
                    </div>
                  ))}
                </div>
              )}

              <div style={{ padding:'var(--space-4)', background:'rgba(255,255,255,0.025)', border:'1px solid var(--color-border)', borderRadius:'var(--radius-md)' }}>
                <div style={{ fontSize:'0.7rem', fontWeight:700, color:'var(--color-cyan)', marginBottom:6 }}>RECOMMENDED NEXT STEP</div>
                <div style={{ fontSize:'0.8rem', lineHeight:1.6 }}>{result.recommendation}</div>
              </div>
              <div style={{ fontSize:'0.72rem', color:'var(--color-text-muted)', marginTop:10 }}>{result.message}</div>
            </div>
          )}
        </div>

        <div className="card">
          <div className="card-header">
            <span className="card-title">⚠ Recorded Detection Gaps</span>
            <span className="badge badge-medium">{gaps.length} recorded</span>
          </div>
          {gapsQuery.isLoading && <div style={{ color:'var(--color-text-muted)', fontSize:'0.8rem' }}>Loading saved alert records…</div>}
          {gapsQuery.isError && <div role="alert" style={{ color:'var(--color-high)', fontSize:'0.8rem' }}>Could not load detection gaps from the backend.</div>}
          {!gapsQuery.isLoading && !gapsQuery.isError && gaps.length === 0 && (
            <div style={{ padding:'var(--space-6)', textAlign:'center', color:'var(--color-text-muted)' }}>
              <div style={{ fontSize:'2rem', marginBottom:8 }}>◈</div>
              <strong>No detection gaps are recorded</strong>
              <div style={{ fontSize:'0.78rem', marginTop:6 }}>Only alerts explicitly marked by an integration appear here; this page does not infer gaps from missing data.</div>
            </div>
          )}
          <div style={{ display:'flex', flexDirection:'column', gap:'var(--space-3)' }}>
            {gaps.map((g:any) => (
              <div key={g.alert_id} style={{ padding:'var(--space-4)', border:'1px solid rgba(255,59,92,0.25)', borderRadius:'var(--radius-md)', background:'rgba(255,59,92,0.04)' }}>
                <div className="flex items-center gap-2" style={{ marginBottom:'var(--space-2)' }}>
                  <span className={`badge badge-${String(g.severity || 'INFO').toLowerCase()}`}>{g.severity}</span>
                  {g.mitre_techniques?.map((t:string) => <span key={t} className="mitre-chip">{t}</span>)}
                </div>
                <div style={{ fontWeight:600, fontSize:'0.875rem', marginBottom:'var(--space-2)' }}>{g.title}</div>
                <div style={{ fontSize:'0.7rem', color:'var(--color-text-muted)', marginBottom:6 }}>{g.source || 'Unknown source'} · {dateTime(g.created_at)}</div>
                <div style={{ fontSize:'0.8rem', color:'var(--color-text-secondary)' }}>💡 {g.recommendation}</div>
              </div>
            ))}
          </div>

          <div style={{ marginTop:'var(--space-6)' }}>
            <div className="form-label" style={{ marginBottom:12 }}>Workflow status</div>
            {[
              ['1','Run a scoped scan','Save actual findings with endpoint evidence'],
              ['2','Connect telemetry','Ingest alerts from Wazuh, Zeek or Suricata'],
              ['3','Correlate history','Match saved alert records with ATT&CK techniques'],
              ['4','Verify manually','Use an approved controlled simulation before claiming a detection gap'],
            ].map(([step, label, desc]) => (
              <div key={step} style={{ display:'flex', gap:'var(--space-3)', marginBottom:'var(--space-3)', alignItems:'center' }}>
                <span style={{ fontSize:'0.9rem', flexShrink:0, width:26, height:26, display:'grid', placeItems:'center', border:'1px solid rgba(168,85,247,0.35)', borderRadius:'50%', color:'var(--color-purple)' }}>{step}</span>
                <div>
                  <div style={{ fontWeight:600, fontSize:'0.8rem' }}>{label}</div>
                  <div style={{ fontSize:'0.7rem', color:'var(--color-text-muted)' }}>{desc}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}
