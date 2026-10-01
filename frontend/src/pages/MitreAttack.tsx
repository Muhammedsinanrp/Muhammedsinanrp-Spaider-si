const TACTICS = [
  { id:'TA0001', name:'Initial Access', color:'#ff3b5c', techniques:['T1190 Exploit Public App','T1078 Valid Accounts','T1566 Phishing'] },
  { id:'TA0002', name:'Execution', color:'#ff6b35', techniques:['T1059 Command Scripting','T1106 Native API','T1203 Exploit Client Exec'] },
  { id:'TA0003', name:'Persistence', color:'#ff9800', techniques:['T1136 Create Account','T1053 Scheduled Task','T1574 Hijack Exec Flow'] },
  { id:'TA0004', name:'Priv Escalation', color:'#ffc107', techniques:['T1068 Exploit Vuln','T1548 Abuse Elevation','T1134 Access Token'] },
  { id:'TA0005', name:'Defense Evasion', color:'#00e5ff', techniques:['T1055 Process Injection','T1562 Impair Defenses','T1070 Indicator Removal'] },
  { id:'TA0006', name:'Cred Access', color:'#3b82f6', techniques:['T1110 Brute Force','T1003 OS Cred Dump','T1558 Steal Kerberos'] },
  { id:'TA0007', name:'Discovery', color:'#a855f7', techniques:['T1046 Net Service Scan','T1082 System Info','T1083 File Discovery'] },
  { id:'TA0008', name:'Lateral Movement', color:'#ff3b5c', techniques:['T1021 Remote Services','T1210 Exploit Remote','T1534 Internal Spear'] },
  { id:'TA0009', name:'Collection', color:'#ff6b35', techniques:['T1005 Local Data','T1039 Network Drive','T1113 Screen Capture'] },
  { id:'TA0011', name:'C2', color:'#ff9800', techniques:['T1071 App Layer Proto','T1095 Non-App Layer','T1572 Proto Tunneling'] },
  { id:'TA0010', name:'Exfiltration', color:'#00e676', techniques:['T1041 Exfil over C2','T1048 Exfil Alt Proto','T1052 Exfil Physical'] },
  { id:'TA0040', name:'Impact', color:'#ff1744', techniques:['T1486 Data Encrypted','T1485 Data Destruction','T1499 Endpoint DoS'] },
]

const DETECTED = ['T1110','T1046','T1059.001','T1021.002']

export default function MitreAttack() {
  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title gradient-text-purple">🧬 MITRE ATT&amp;CK</h1>
          <p className="page-subtitle">Attack chain visualization — mapped to your detections and findings</p>
        </div>
        <div className="flex gap-2">
          <span className="badge badge-critical">4 detected</span>
          <span className="badge badge-medium">8 not covered</span>
        </div>
      </div>

      {/* Legend */}
      <div className="flex gap-4 mb-6" style={{ fontSize:'0.75rem' }}>
        {[
          { color:'rgba(255,23,68,0.4)', border:'rgba(255,23,68,0.6)', label:'Finding mapped' },
          { color:'rgba(0,230,118,0.15)', border:'rgba(0,230,118,0.4)', label:'Alert detected' },
          { color:'rgba(255,255,255,0.04)', border:'rgba(255,255,255,0.08)', label:'Not covered' },
        ].map(l => (
          <span key={l.label} className="flex items-center gap-2">
            <span style={{ width:16, height:16, borderRadius:3, background:l.color, border:`1px solid ${l.border}`, display:'inline-block' }} />
            {l.label}
          </span>
        ))}
      </div>

      {/* ATT&CK Matrix */}
      <div style={{ overflowX:'auto' }}>
        <div style={{ display:'flex', gap:4, minWidth:1200 }}>
          {TACTICS.map(tactic => (
            <div key={tactic.id} style={{ flex:1, minWidth:90 }}>
              {/* Tactic header */}
              <div style={{
                background:`rgba(${hexToRgb(tactic.color)},0.15)`,
                border:`1px solid rgba(${hexToRgb(tactic.color)},0.4)`,
                borderRadius:'var(--radius-sm)', padding:'var(--space-2)',
                textAlign:'center', marginBottom:4,
              }}>
                <div style={{ fontSize:'0.65rem', fontWeight:700, color:tactic.color, textTransform:'uppercase', letterSpacing:'0.05em' }}>{tactic.name}</div>
                <div style={{ fontSize:'0.55rem', color:'var(--color-text-muted)' }}>{tactic.id}</div>
              </div>

              {/* Techniques */}
              {tactic.techniques.map(tech => {
                const tid = tech.split(' ')[0]
                const tname = tech.split(' ').slice(1).join(' ')
                const isDetected = DETECTED.some(d=>d.startsWith(tid))
                return (
                  <div key={tid} style={{
                    padding:'var(--space-2)',
                    borderRadius:'var(--radius-sm)',
                    border:`1px solid ${isDetected?'rgba(0,230,118,0.4)':'rgba(255,255,255,0.06)'}`,
                    background: isDetected?'rgba(0,230,118,0.08)':'rgba(255,255,255,0.02)',
                    marginBottom:3, cursor:'pointer', transition:'all 0.15s',
                  }}>
                    <div style={{ fontSize:'0.6rem', fontFamily:'var(--font-mono)', color:isDetected?'var(--color-safe)':'var(--color-text-muted)', fontWeight:700 }}>{tid}</div>
                    <div style={{ fontSize:'0.65rem', color:isDetected?'var(--color-text-primary)':'var(--color-text-muted)', lineHeight:1.3 }}>{tname}</div>
                    {isDetected && <div style={{ fontSize:'0.55rem', color:'var(--color-safe)', marginTop:2 }}>● Detected</div>}
                  </div>
                )
              })}
            </div>
          ))}
        </div>
      </div>

      {/* Attack chain */}
      <div className="card mt-4">
        <div className="card-header"><span className="card-title">Observed Attack Chain</span></div>
        <div className="flex items-center gap-3" style={{ flexWrap:'wrap' }}>
          {[
            { id:'T1190', name:'Exploit Public App', tactic:'Initial Access', color:'var(--color-red)' },
            { id:'T1059.001', name:'PowerShell', tactic:'Execution', color:'var(--color-high)' },
            { id:'T1046', name:'Net Service Scan', tactic:'Discovery', color:'var(--color-medium)' },
            { id:'T1021.002', name:'SMB Lateral Move', tactic:'Lateral Movement', color:'var(--color-red)' },
            { id:'T1110', name:'Brute Force', tactic:'Cred Access', color:'var(--color-high)' },
          ].map((t,i,arr) => (
            <div key={t.id} className="flex items-center gap-3">
              <div style={{ padding:'var(--space-3)', background:'rgba(168,85,247,0.08)', border:'1px solid rgba(168,85,247,0.3)', borderRadius:'var(--radius-md)', textAlign:'center' }}>
                <div style={{ fontFamily:'var(--font-mono)', fontSize:'0.7rem', color:'var(--color-purple)', fontWeight:700 }}>{t.id}</div>
                <div style={{ fontSize:'0.75rem', fontWeight:600, marginTop:2 }}>{t.name}</div>
                <div style={{ fontSize:'0.6rem', color:'var(--color-text-muted)' }}>{t.tactic}</div>
              </div>
              {i < arr.length-1 && <span style={{ color:'var(--color-text-muted)', fontSize:'1.2rem' }}>→</span>}
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

function hexToRgb(hex: string) {
  const r = parseInt(hex.slice(1,3),16)
  const g = parseInt(hex.slice(3,5),16)
  const b = parseInt(hex.slice(5,7),16)
  return `${r},${g},${b}`
}
