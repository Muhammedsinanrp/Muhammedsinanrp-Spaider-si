import { useState } from 'react'
import { useMutation } from '@tanstack/react-query'
import { aiApi } from '../api/client'

const REASONING_STEPS = ['Asset','Service','Technology','Potential Weakness','Evidence','Risk Context','Related CVEs','Detection Opportunities','Recommended Remediation','Verification']

const SAMPLE_CONTEXTS = [
  'Port 445 open on Windows Server 2019. SMBv1 enabled. Host is on the corporate network with no segmentation.',
  'Apache HTTP Server 2.4.49 found on web01. Running without authentication. PATH_INFO traversal possible.',
  'Multiple failed SSH logins from 45.33.32.156 followed by successful login. Unusual outbound connection established.',
]

export default function AIAnalyst() {
  const [context, setContext] = useState('')
  const [mode, setMode] = useState('blue')
  const [result, setResult] = useState<any>(null)

  const analyzeMutation = useMutation({
    mutationFn: (data: any) => aiApi.analyze(data),
    onSuccess: (data) => setResult(data),
  })

  const handleAnalyze = () => {
    if (!context.trim()) return
    analyzeMutation.mutate({ context, mode })
  }

  const riskColor = (score: number) =>
    score >= 9 ? 'var(--color-critical)' : score >= 7 ? 'var(--color-high)' : score >= 4 ? 'var(--color-medium)' : 'var(--color-low)'

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title gradient-text-purple">🧠 AI Security Analyst</h1>
          <p className="page-subtitle">Security reasoning chain · CVE correlation · ATT&CK mapping · Remediation guidance</p>
        </div>
      </div>

      <div className="grid-2" style={{ alignItems:'start' }}>
        {/* Input */}
        <div className="card">
          <div className="card-header">
            <span className="card-title">Analysis Context</span>
            <div className="flex gap-2">
              {['red','blue','purple'].map(m => (
                <button key={m} className={`btn btn-sm ${mode===m?'btn-primary':'btn-ghost'}`} onClick={()=>setMode(m)}>
                  {m.toUpperCase()}
                </button>
              ))}
            </div>
          </div>

          <div className="form-group" style={{ marginBottom:'var(--space-4)' }}>
            <label className="form-label">Quick Samples</label>
            <div style={{ display:'flex', flexDirection:'column', gap:'var(--space-2)' }}>
              {SAMPLE_CONTEXTS.map((s,i) => (
                <button key={i} className="btn btn-ghost btn-sm" style={{ textAlign:'left', justifyContent:'flex-start', fontSize:'0.75rem' }}
                  onClick={()=>setContext(s)}>
                  {s.slice(0,70)}...
                </button>
              ))}
            </div>
          </div>

          <div className="form-group" style={{ marginBottom:'var(--space-4)' }}>
            <label className="form-label">Security Context / Observation</label>
            <textarea className="input input-mono" rows={6}
              placeholder="Describe the finding, alert, or observation to analyze..."
              value={context} onChange={e=>setContext(e.target.value)} />
          </div>

          <button className="btn btn-primary w-full" onClick={handleAnalyze} disabled={analyzeMutation.isPending || !context.trim()}>
            {analyzeMutation.isPending ? '🧠 Analyzing...' : '🧠 Run AI Reasoning Chain'}
          </button>

          {!result && (
            <div style={{ marginTop:'var(--space-6)' }}>
              <div className="form-label" style={{ marginBottom:12 }}>Reasoning Chain Steps</div>
              {REASONING_STEPS.map((s,i) => (
                <div key={s} style={{ display:'flex', gap:'var(--space-3)', alignItems:'center', marginBottom:'var(--space-2)', opacity: 0.5 }}>
                  <div style={{
                    width:24, height:24, borderRadius:'50%',
                    border:'2px solid var(--color-border)',
                    display:'flex', alignItems:'center', justifyContent:'center',
                    fontSize:'0.65rem', fontWeight:700, color:'var(--color-text-muted)',
                  }}>{i+1}</div>
                  <span style={{ fontSize:'0.875rem', color:'var(--color-text-muted)' }}>{s}</span>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Result */}
        <div>
          {analyzeMutation.isPending && (
            <div className="card">
              <div style={{ textAlign:'center', padding:'var(--space-10)' }}>
                <div style={{ fontSize:'2rem', marginBottom:'var(--space-4)' }}>🧠</div>
                <div style={{ fontWeight:700, marginBottom:'var(--space-2)' }}>AI Reasoning in progress...</div>
                <div style={{ color:'var(--color-text-muted)', fontSize:'0.875rem' }}>Building security reasoning chain</div>
                <div style={{ marginTop:'var(--space-4)', color:'var(--color-cyan)', fontSize:'0.8rem' }}>
                  Asset → Service → Technology → Weakness → Evidence...
                </div>
              </div>
            </div>
          )}

          {result && (
            <div className="animate-fade-in">
              {/* Summary */}
              <div className="card" style={{ marginBottom:'var(--space-4)', border:'1px solid var(--color-border-accent)' }}>
                <div style={{ display:'flex', justifyContent:'space-between', alignItems:'flex-start' }}>
                  <div style={{ flex:1 }}>
                    <div style={{ fontSize:'0.7rem', fontWeight:700, letterSpacing:'0.1em', color:'var(--color-cyan)', marginBottom:4, textTransform:'uppercase' }}>AI Summary</div>
                    <div style={{ fontWeight:700, fontSize:'1rem', lineHeight:1.5 }}>{result.summary}</div>
                  </div>
                  <div style={{ textAlign:'center', marginLeft:'var(--space-4)' }}>
                    <div style={{ fontSize:'2.5rem', fontWeight:900, color:riskColor(result.risk_score||5) }}>{(result.risk_score||5).toFixed(1)}</div>
                    <div style={{ fontSize:'0.65rem', color:'var(--color-text-muted)', textTransform:'uppercase' }}>Risk Score</div>
                  </div>
                </div>
                <div style={{ marginTop:'var(--space-3)' }}>
                  <span className={`badge badge-${(result.severity||'medium').toLowerCase()}`}>{result.severity}</span>
                </div>
              </div>

              {/* Reasoning Chain */}
              <div className="card" style={{ marginBottom:'var(--space-4)' }}>
                <div className="card-header"><span className="card-title">Reasoning Chain</span></div>
                <div className="reasoning-chain">
                  {result.reasoning_chain?.map((step: any, i: number) => (
                    <div key={i} className="reasoning-step">
                      <div className="step-dot">{i+1}</div>
                      <div className="step-content">
                        <div className="step-label">{step.step}</div>
                        <div className="step-text">{step.content}</div>
                        <div className="step-confidence">Confidence: {Math.round((step.confidence||0)*100)}%</div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* MITRE */}
              {result.mitre_techniques?.length > 0 && (
                <div className="card" style={{ marginBottom:'var(--space-4)' }}>
                  <div className="card-header"><span className="card-title">MITRE ATT&CK Mapping</span></div>
                  {result.mitre_techniques.map((t: any) => (
                    <div key={t.id} style={{ display:'flex', gap:'var(--space-3)', marginBottom:'var(--space-3)', padding:'var(--space-3)', background:'rgba(168,85,247,0.06)', borderRadius:'var(--radius-md)', border:'1px solid rgba(168,85,247,0.2)' }}>
                      <span className="mitre-chip">{t.id}</span>
                      <div>
                        <div style={{ fontWeight:600, fontSize:'0.875rem' }}>{t.name}</div>
                        <div style={{ fontSize:'0.75rem', color:'var(--color-text-muted)' }}>{t.tactic}</div>
                      </div>
                    </div>
                  ))}
                </div>
              )}

              {/* Actions */}
              <div className="card">
                <div className="card-header"><span className="card-title">Recommended Actions</span></div>
                {result.recommended_actions?.map((a: string, i: number) => (
                  <div key={i} style={{ display:'flex', gap:'var(--space-3)', marginBottom:'var(--space-3)', fontSize:'0.875rem' }}>
                    <span style={{ color:'var(--color-safe)', fontWeight:700, flexShrink:0 }}>{i+1}.</span>
                    <span>{a}</span>
                  </div>
                ))}
                {result.remediation && (
                  <div style={{ marginTop:'var(--space-4)', padding:'var(--space-4)', background:'rgba(0,230,118,0.05)', border:'1px solid rgba(0,230,118,0.15)', borderRadius:'var(--radius-md)' }}>
                    <div style={{ fontSize:'0.7rem', fontWeight:700, color:'var(--color-safe)', marginBottom:6, textTransform:'uppercase' }}>Remediation</div>
                    <p style={{ fontSize:'0.875rem', lineHeight:1.6 }}>{result.remediation}</p>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
