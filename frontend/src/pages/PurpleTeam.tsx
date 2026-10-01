import { useState } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import { purpleApi } from '../api/client'
import toast from 'react-hot-toast'

const TECHNIQUES = [
  { id:'T1059.001', name:'PowerShell' }, { id:'T1021.002', name:'SMB/Windows Admin Shares' },
  { id:'T1110', name:'Brute Force' }, { id:'T1046', name:'Network Service Discovery' },
  { id:'T1071.001', name:'Web Protocols (C2)' }, { id:'T1048', name:'Exfiltration Over Alt Protocol' },
]
const MOCK_GAPS = [
  { alert_id:'g1', title:'PowerShell encoded command execution not detected', severity:'CRITICAL', mitre_techniques:['T1059.001'], recommendation:'Enable PowerShell Script Block Logging and add Wazuh rule' },
  { alert_id:'g2', title:'SMB lateral movement bypasses Suricata signature', severity:'HIGH', mitre_techniques:['T1021.002'], recommendation:'Update Suricata to ruleset 6.0+ with ET Lateral Movement rules' },
]

export default function PurpleTeam() {
  const [form, setForm] = useState({ finding_id:'', test_technique:'T1059.001', detection_sources:['wazuh','zeek','suricata'], safe_mode:true })
  const [results, setResults] = useState<any[]>([])

  const { data: gaps = MOCK_GAPS } = useQuery({
    queryKey:['purple-gaps'], queryFn:()=>purpleApi.gaps(), retry:false, placeholderData:MOCK_GAPS,
  })

  const validateMutation = useMutation({
    mutationFn:(data:any)=>purpleApi.validate(data),
    onSuccess:()=>{ toast.success('Purple validation queued!') },
  })

  const toggleSource = (src: string) => {
    setForm(p => ({
      ...p,
      detection_sources: p.detection_sources.includes(src) ? p.detection_sources.filter(s=>s!==src) : [...p.detection_sources, src],
    }))
  }

  const MOCK_VALIDATION_RESULT = {
    technique:'T1059.001', detected_by:['wazuh'], missed_by:['zeek','suricata'],
    coverage: 33, gap: true, recommendation: 'Add Suricata rule: alert tcp any any -> any any (msg:"PS Encoded"; content:"-enc"; sid:9000001;)',
  }

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title gradient-text-purple">🟣 Purple Team Validation</h1>
          <p className="page-subtitle">Validate whether attacks would be detected by your defensive stack</p>
        </div>
      </div>

      {/* Concept banner */}
      <div style={{
        background:'linear-gradient(135deg, rgba(168,85,247,0.1), rgba(59,130,246,0.1))',
        border:'1px solid rgba(168,85,247,0.3)', borderRadius:'var(--radius-lg)',
        padding:'var(--space-5)', marginBottom:'var(--space-6)',
        display:'flex', gap:'var(--space-4)', alignItems:'center',
      }}>
        <div style={{ fontSize:'2rem' }}>🎯</div>
        <div>
          <div style={{ fontWeight:700, fontSize:'1rem', marginBottom:4 }}>SPAIDER's Killer Feature</div>
          <div style={{ fontSize:'0.875rem', color:'var(--color-text-secondary)' }}>
            Find → Understand → Validate → Detect → Remediate → Verify. SPAIDER doesn't just say "you have a vulnerability" — it asks <em style={{ color:'var(--color-purple)' }}>"can your security stack actually see this activity?"</em>
          </div>
        </div>
      </div>

      <div className="grid-2" style={{ alignItems:'start' }}>
        {/* Validation form */}
        <div className="card">
          <div className="card-header"><span className="card-title">🚀 New Validation</span></div>
          <div className="scan-form">
            <div className="form-group">
              <label className="form-label">ATT&CK Technique</label>
              <select className="input" value={form.test_technique} onChange={e=>setForm(p=>({...p,test_technique:e.target.value}))}>
                {TECHNIQUES.map(t=><option key={t.id} value={t.id}>{t.id} — {t.name}</option>)}
              </select>
            </div>
            <div className="form-group">
              <label className="form-label">Detection Sources to Test</label>
              <div className="flex gap-2">
                {['wazuh','zeek','suricata'].map(src=>(
                  <button key={src} className={`btn btn-sm ${form.detection_sources.includes(src)?'btn-primary':'btn-ghost'}`}
                    onClick={()=>toggleSource(src)}>{src}</button>
                ))}
              </div>
            </div>
            <div className="form-group">
              <label className="form-label">Safe Mode</label>
              <label style={{ display:'flex', alignItems:'center', gap:'var(--space-2)', cursor:'pointer' }}>
                <input type="checkbox" checked={form.safe_mode} onChange={e=>setForm(p=>({...p,safe_mode:e.target.checked}))} />
                <span style={{ fontSize:'0.875rem' }}>Enable safe mode (no destructive actions)</span>
              </label>
            </div>
            <div style={{
              marginTop: 'var(--space-3)',
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

            <button className="btn btn-primary" onClick={()=>{validateMutation.mutate(form);setResults([MOCK_VALIDATION_RESULT])}} disabled={validateMutation.isPending}>
              {validateMutation.isPending ? '⏳ Validating...' : '🟣 Run Purple Validation'}
            </button>
          </div>

          {/* Results */}
          {results.length > 0 && (
            <div style={{ marginTop:'var(--space-6)' }} className="animate-fade-in">
              <div className="card-header" style={{ marginBottom:'var(--space-4)' }}><span className="card-title">Validation Result</span></div>
              <div style={{
                marginBottom: 'var(--space-3)',
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
              {results.map((r,i) => (
                <div key={i}>
                  <div style={{ display:'flex', gap:'var(--space-3)', marginBottom:'var(--space-4)' }}>
                    <div style={{ flex:1, padding:'var(--space-4)', background:'rgba(0,230,118,0.08)', borderRadius:'var(--radius-md)', border:'1px solid rgba(0,230,118,0.2)', textAlign:'center' }}>
                      <div style={{ fontSize:'0.7rem', color:'var(--color-safe)', fontWeight:700, marginBottom:4 }}>DETECTED BY</div>
                      {r.detected_by.map((d:string)=><div key={d} style={{ fontWeight:700 }}>{d}</div>)}
                    </div>
                    <div style={{ flex:1, padding:'var(--space-4)', background:'rgba(255,23,68,0.08)', borderRadius:'var(--radius-md)', border:'1px solid rgba(255,23,68,0.2)', textAlign:'center' }}>
                      <div style={{ fontSize:'0.7rem', color:'var(--color-red)', fontWeight:700, marginBottom:4 }}>MISSED BY</div>
                      {r.missed_by.map((d:string)=><div key={d} style={{ fontWeight:700 }}>{d}</div>)}
                    </div>
                    <div style={{ flex:1, padding:'var(--space-4)', background:'rgba(168,85,247,0.08)', borderRadius:'var(--radius-md)', border:'1px solid rgba(168,85,247,0.2)', textAlign:'center' }}>
                      <div style={{ fontSize:'0.7rem', color:'var(--color-purple)', fontWeight:700, marginBottom:4 }}>COVERAGE</div>
                      <div style={{ fontSize:'2rem', fontWeight:900, color: r.coverage>70?'var(--color-safe)':'var(--color-red)' }}>{r.coverage}%</div>
                    </div>
                  </div>
                  {r.gap && (
                    <div style={{ padding:'var(--space-4)', background:'rgba(255,23,68,0.06)', border:'1px solid rgba(255,23,68,0.2)', borderRadius:'var(--radius-md)' }}>
                      <div style={{ fontSize:'0.7rem', fontWeight:700, color:'var(--color-red)', marginBottom:6 }}>⚠ DETECTION RULE RECOMMENDATION</div>
                      <pre style={{ fontFamily:'var(--font-mono)', fontSize:'0.75rem', color:'var(--color-text-secondary)', whiteSpace:'pre-wrap' }}>{r.recommendation}</pre>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Detection Gaps */}
        <div className="card">
          <div className="card-header">
            <span className="card-title">⚠ Detection Gaps</span>
            <span className="badge badge-critical">{(gaps as any[]).length} gaps</span>
          </div>
          <div style={{ display:'flex', flexDirection:'column', gap:'var(--space-3)' }}>
            {(gaps as any[]).map((g:any) => (
              <div key={g.alert_id} style={{ padding:'var(--space-4)', border:'1px solid rgba(255,59,92,0.25)', borderRadius:'var(--radius-md)', background:'rgba(255,59,92,0.04)' }}>
                <div className="flex items-center gap-2" style={{ marginBottom:'var(--space-2)' }}>
                  <span className={`badge badge-${g.severity.toLowerCase()}`}>{g.severity}</span>
                  {g.mitre_techniques?.map((t:string)=><span key={t} className="mitre-chip">{t}</span>)}
                </div>
                <div style={{ fontWeight:600, fontSize:'0.875rem', marginBottom:'var(--space-2)' }}>{g.title}</div>
                <div style={{ fontSize:'0.8rem', color:'var(--color-safe)' }}>💡 {g.recommendation}</div>
              </div>
            ))}
          </div>

          {/* Purple workflow */}
          <div style={{ marginTop:'var(--space-6)' }}>
            <div className="form-label" style={{ marginBottom:12 }}>Purple Team Workflow</div>
            {[
              ['🔴','Offensive Finding','SPAIDER discovers exposed service'],
              ['🧠','AI Analysis','Potential vulnerability identified'],
              ['🔍','Safe Validation','Scanner validates safely in scope'],
              ['🟣','Purple Check','Does defensive stack detect it?'],
              ['📊','Gap Report','Detection gap identified and reported'],
              ['🛡️','Rule Generation','AI recommends detection rule'],
              ['✅','Verify','Re-test after fix'],
            ].map(([icon, label, desc]) => (
              <div key={label as string} style={{ display:'flex', gap:'var(--space-3)', marginBottom:'var(--space-3)', alignItems:'center' }}>
                <span style={{ fontSize:'1.2rem', flexShrink:0 }}>{icon}</span>
                <div>
                  <div style={{ fontWeight:600, fontSize:'0.8rem' }}>{label as string}</div>
                  <div style={{ fontSize:'0.7rem', color:'var(--color-text-muted)' }}>{desc as string}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}
