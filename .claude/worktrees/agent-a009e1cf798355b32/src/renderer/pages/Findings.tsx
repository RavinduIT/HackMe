import { useState, useEffect } from 'react';

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];
const CWE_DESCRIPTIONS: Record<string, string> = {
  'CWE-79': 'Improper Neutralization of Input During Web Page Generation (XSS)',
  'CWE-89': 'Improper Neutralization of Special Elements used in an SQL Command (SQLi)',
  'CWE-200': 'Exposure of Sensitive Information to an Unauthorized Actor',
  'CWE-284': 'Improper Access Control',
  'CWE-295': 'Improper Certificate Validation',
  'CWE-312': 'Cleartext Storage of Sensitive Information',
  'CWE-319': 'Cleartext Transmission of Sensitive Information',
  'CWE-327': 'Use of a Broken or Risky Cryptographic Algorithm',
  'CWE-330': 'Use of Insufficiently Random Values',
  'CWE-346': 'Origin Validation Error',
  'CWE-352': 'Cross-Site Request Forgery (CSRF)',
  'CWE-384': 'Session Fixation',
  'CWE-538': 'Insertion of Sensitive Information into Externally-Accessible File or Directory',
  'CWE-540': 'Inclusion of Sensitive Information in Source Code',
  'CWE-614': 'Sensitive Cookie in HTTPS Session Without Secure Attribute',
  'CWE-613': 'Insufficient Session Expiration',
  'CWE-615': 'Inclusion of Sensitive Information in Source Code Comments',
  'CWE-693': 'Protection Mechanism Failure',
  'CWE-798': 'Use of Hard-coded Credentials',
  'CWE-943': 'Improper Neutralization of Special Elements in Data Query Logic',
  'CWE-1004': 'Sensitive Cookie Without HttpOnly Flag',
  'CWE-1021': 'Improper Restriction of Rendered UI Layers or Frames',
  'CWE-1275': 'Sensitive Cookie with Improper SameSite Attribute',
};

const OWASP_NAMES: Record<string, string> = {
  'A01:2021': 'Broken Access Control',
  'A02:2021': 'Cryptographic Failures',
  'A03:2021': 'Injection',
  'A04:2021': 'Insecure Design',
  'A05:2021': 'Security Misconfiguration',
  'A06:2021': 'Vulnerable and Outdated Components',
  'A07:2021': 'Identification and Authentication Failures',
  'A08:2021': 'Software and Data Integrity Failures',
  'A09:2021': 'Security Logging and Monitoring Failures',
  'A10:2021': 'Server-Side Request Forgery',
};

function cvssLabel(score: number): string {
  if (score >= 9.0) return 'Critical';
  if (score >= 7.0) return 'High';
  if (score >= 4.0) return 'Medium';
  if (score >= 0.1) return 'Low';
  return 'None';
}

const sevColorMap: Record<string, string> = {
  critical: 'var(--crit)', high: 'var(--high)', medium: 'var(--med)', low: 'var(--low)', info: 'var(--info)',
};

export default function Findings() {
  const [findings, setFindings] = useState<any[]>([]);
  const [selected, setSelected] = useState<any | null>(null);
  const [filter, setFilter] = useState('all');

  useEffect(() => { load(); }, []);
  async function load() { setFindings(await window.hackme.getAllFindings() || []); }

  const filtered = filter === 'all' ? findings : findings.filter(f => f.severity === filter);
  const counts: Record<string, number> = {};
  findings.forEach(f => { counts[f.severity] = (counts[f.severity] || 0) + 1; });

  async function markFP(id: string, val: boolean) {
    await window.hackme.markFalsePositive(id, val);
    setFindings(prev => prev.map(f => f.id === id ? { ...f, false_positive: val ? 1 : 0 } : f));
    if (selected?.id === id) setSelected({ ...selected, false_positive: val ? 1 : 0 });
  }

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column', gap: 16 }}>
      {/* Filter bar */}
      <div style={{
        display: 'flex', alignItems: 'center', gap: 6,
        padding: '8px 12px',
        background: 'var(--bg-1)', borderRadius: 'var(--radius-lg)',
        border: '1px solid var(--border)',
      }}>
        {['all', 'critical', 'high', 'medium', 'low', 'info'].map(s => {
          const n = s === 'all' ? findings.length : (counts[s] || 0);
          const active = filter === s;
          return (
            <button key={s} onClick={() => setFilter(s)}
              style={{
                display: 'flex', alignItems: 'center', gap: 6,
                padding: '6px 12px', borderRadius: 'var(--radius)',
                border: 'none', cursor: 'pointer',
                background: active ? (s === 'all' ? 'var(--ac-lo)' : `${sevColorMap[s]}15`) : 'transparent',
                color: active ? (s === 'all' ? 'var(--ac)' : sevColorMap[s]) : 'var(--t3)',
                fontSize: 11, fontWeight: active ? 600 : 400,
                textTransform: 'uppercase', letterSpacing: '0.05em',
                transition: 'all 0.15s',
              }}
              onMouseEnter={e => { if (!active) e.currentTarget.style.background = 'var(--bg-2)'; }}
              onMouseLeave={e => { if (!active) e.currentTarget.style.background = active ? (s === 'all' ? 'var(--ac-lo)' : `${sevColorMap[s]}15`) : 'transparent'; }}
            >
              {s !== 'all' && <div style={{ width: 6, height: 6, borderRadius: 2, background: sevColorMap[s] }} />}
              {s}
              <span className="font-mono" style={{ fontSize: 10, opacity: 0.8 }}>{n}</span>
            </button>
          );
        })}
        <div style={{ flex: 1 }} />
        <button onClick={load} className="hm-btn hm-btn-ghost" style={{ fontSize: 10 }}>
          Refresh
        </button>
      </div>

      {/* Main area: list + detail */}
      <div style={{ flex: 1, display: 'flex', gap: 0, minHeight: 0 }}>

        {/* Findings list */}
        <div style={{
          width: selected ? 360 : '100%', flexShrink: 0,
          display: 'flex', flexDirection: 'column', minWidth: 0,
          border: '1px solid var(--border)',
          borderRadius: selected ? 'var(--radius-lg) 0 0 var(--radius-lg)' : 'var(--radius-lg)',
          overflow: 'hidden', background: 'var(--bg-0)',
        }}>
          <div style={{ flex: 1, overflowY: 'auto' }}>
            {filtered.length === 0 ? (
              <div style={{ padding: '64px 20px', textAlign: 'center', color: 'var(--t3)', fontSize: 13 }}>
                No findings yet. Run a scan first.
              </div>
            ) : filtered.map((f, idx) => (
              <div key={f.id} onClick={() => setSelected(f)}
                className={`sev-border-${f.severity}`}
                style={{
                  display: 'flex', alignItems: 'center', gap: 12,
                  padding: '12px 16px',
                  cursor: 'pointer', transition: 'background 0.12s',
                  background: selected?.id === f.id ? 'var(--ac-lo)' : 'transparent',
                  borderBottom: '1px solid var(--border)',
                  opacity: f.false_positive ? 0.4 : 1,
                }}
                onMouseEnter={e => { if (selected?.id !== f.id) e.currentTarget.style.background = 'var(--bg-1)'; }}
                onMouseLeave={e => { if (selected?.id !== f.id) e.currentTarget.style.background = 'transparent'; }}
              >
                <span className={`sev-pill sev-pill-${f.severity}`} style={{ flexShrink: 0 }}>{f.severity}</span>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontSize: 12, color: 'var(--t1)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {f.title}
                  </div>
                  <div className="font-mono" style={{ fontSize: 10, color: 'var(--t3)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', marginTop: 2 }}>
                    {f.url}
                  </div>
                </div>
                {f.cvss_score > 0 && (
                  <span className="font-mono" style={{ fontSize: 10, color: 'var(--t3)', flexShrink: 0 }}>{f.cvss_score}</span>
                )}
              </div>
            ))}
          </div>
        </div>

        {/* Detail panel */}
        {selected && (
          <div style={{
            flex: 1, display: 'flex', flexDirection: 'column', minWidth: 0,
            border: '1px solid var(--border)', borderLeft: 'none',
            borderRadius: '0 var(--radius-lg) var(--radius-lg) 0',
            overflow: 'hidden', background: 'var(--bg-0)',
          }}>
            {/* Detail header */}
            <div style={{
              padding: '20px 24px',
              borderBottom: `2px solid ${sevColorMap[selected.severity] || 'var(--border)'}`,
              background: 'var(--bg-1)',
            }}>
              <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between' }}>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
                    <span className={`sev-pill sev-pill-${selected.severity}`}>{selected.severity.toUpperCase()}</span>
                    {selected.cvss_score > 0 && (
                      <span className="font-mono" style={{
                        fontSize: 11, fontWeight: 600,
                        color: selected.cvss_score >= 9 ? 'var(--crit)' : selected.cvss_score >= 7 ? 'var(--high)' : selected.cvss_score >= 4 ? 'var(--med)' : 'var(--t3)',
                      }}>
                        CVSS {selected.cvss_score}
                      </span>
                    )}
                  </div>
                  <div style={{ fontSize: 16, fontWeight: 600, color: 'var(--t1)', lineHeight: 1.4, marginBottom: 6 }}>
                    {selected.title}
                  </div>
                  <div className="font-mono" style={{ fontSize: 11, color: 'var(--t3)', wordBreak: 'break-all' }}>
                    {selected.url}
                  </div>
                </div>
                <button onClick={() => setSelected(null)} style={{
                  background: 'none', border: 'none', color: 'var(--t3)',
                  fontSize: 20, cursor: 'pointer', padding: '0 4px', lineHeight: 1,
                  flexShrink: 0, marginLeft: 12,
                }}
                  onMouseEnter={e => e.currentTarget.style.color = 'var(--t1)'}
                  onMouseLeave={e => e.currentTarget.style.color = 'var(--t3)'}
                >x</button>
              </div>

              {/* Meta tags */}
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginTop: 14 }}>
                {selected.cwe_id && (
                  <Tag label={selected.cwe_id} />
                )}
                {selected.owasp_category && (
                  <Tag label={`OWASP ${selected.owasp_category}`} />
                )}
                {selected.module_id && (
                  <Tag label={selected.module_id} dim />
                )}
                {selected.false_positive ? (
                  <button onClick={() => markFP(selected.id, false)} style={{
                    fontSize: 10, padding: '3px 10px', borderRadius: 3,
                    border: '1px solid rgba(249,115,22,0.3)', color: '#f97316',
                    background: 'rgba(249,115,22,0.06)', cursor: 'pointer',
                  }}>
                    FALSE POSITIVE (undo)
                  </button>
                ) : (
                  <button onClick={() => markFP(selected.id, true)} style={{
                    fontSize: 10, padding: '3px 10px', borderRadius: 3,
                    border: '1px solid var(--border)', color: 'var(--t3)',
                    background: 'none', cursor: 'pointer', transition: 'all 0.15s',
                  }}
                    onMouseEnter={e => { e.currentTarget.style.borderColor = '#f97316'; e.currentTarget.style.color = '#f97316'; }}
                    onMouseLeave={e => { e.currentTarget.style.borderColor = 'var(--border)'; e.currentTarget.style.color = 'var(--t3)'; }}
                  >
                    Mark as FP
                  </button>
                )}
              </div>
            </div>

            {/* Detail body - scrollable */}
            <div style={{ flex: 1, overflowY: 'auto', padding: '24px' }}>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
                {/* Description */}
                <DetailSection title="Description">
                  <p style={{ fontSize: 13, color: 'var(--t2)', lineHeight: 1.8, margin: 0 }}>
                    {selected.description}
                  </p>
                </DetailSection>

                {/* Affected parameter */}
                {selected.parameter && (
                  <DetailSection title="Affected Parameter">
                    <code className="font-mono" style={{
                      fontSize: 13, color: 'var(--ac)',
                      background: 'var(--bg-2)', padding: '6px 12px',
                      borderRadius: 'var(--radius)', display: 'inline-block',
                      border: '1px solid var(--border)',
                    }}>
                      {selected.parameter}
                    </code>
                  </DetailSection>
                )}

                {/* Impact */}
                <DetailSection title="Impact">
                  <p style={{ fontSize: 13, color: 'var(--t2)', lineHeight: 1.8, margin: 0 }}>
                    {getImpactText(selected.severity, selected.cwe_id, selected.title)}
                  </p>
                </DetailSection>

                {/* Remediation */}
                {selected.remediation && (
                  <DetailSection title="Remediation">
                    <div style={{
                      fontSize: 13, color: 'var(--ac)', lineHeight: 1.8,
                      background: 'rgba(0,229,195,0.04)',
                      padding: '14px 18px', borderRadius: 'var(--radius)',
                      border: '1px solid rgba(0,229,195,0.12)',
                    }}>
                      {selected.remediation}
                    </div>
                  </DetailSection>
                )}

                {/* Evidence */}
                {selected.evidence && Object.keys(selected.evidence).length > 0 && (
                  <DetailSection title="Evidence">
                    <div style={{
                      background: 'var(--bg-1)', borderRadius: 'var(--radius)',
                      border: '1px solid var(--border)', overflow: 'hidden',
                    }}>
                      {Object.entries(selected.evidence).map(([key, val], idx, arr) => (
                        <div key={key} style={{
                          padding: '10px 16px',
                          borderBottom: idx < arr.length - 1 ? '1px solid var(--border)' : 'none',
                          display: 'flex', gap: 12,
                        }}>
                          <span className="font-mono" style={{ fontSize: 11, color: 'var(--t3)', flexShrink: 0, minWidth: 80 }}>{key}</span>
                          <span className="font-mono" style={{ fontSize: 11, color: 'var(--t2)', wordBreak: 'break-all' }}>
                            {typeof val === 'object' ? JSON.stringify(val, null, 2) : String(val)}
                          </span>
                        </div>
                      ))}
                    </div>
                  </DetailSection>
                )}

                {/* References */}
                <DetailSection title="References">
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                    {selected.cwe_id && (
                      <div style={{ fontSize: 12 }}>
                        <span className="font-mono" style={{ color: 'var(--ac)' }}>{selected.cwe_id}</span>
                        <span style={{ color: 'var(--t3)', margin: '0 6px' }}> -- </span>
                        <span style={{ color: 'var(--t2)' }}>{CWE_DESCRIPTIONS[selected.cwe_id] || 'Common Weakness Enumeration'}</span>
                      </div>
                    )}
                    {selected.owasp_category && (
                      <div style={{ fontSize: 12 }}>
                        <span className="font-mono" style={{ color: 'var(--ac)' }}>OWASP {selected.owasp_category}</span>
                        <span style={{ color: 'var(--t3)', margin: '0 6px' }}> -- </span>
                        <span style={{ color: 'var(--t2)' }}>{OWASP_NAMES[selected.owasp_category] || 'OWASP Top 10'}</span>
                      </div>
                    )}
                    {selected.cvss_score > 0 && (
                      <div style={{ fontSize: 12 }}>
                        <span className="font-mono" style={{ color: 'var(--ac)' }}>CVSS 3.1 Base Score: {selected.cvss_score}</span>
                        <span style={{ color: 'var(--t3)', margin: '0 6px' }}> -- </span>
                        <span style={{ color: 'var(--t2)' }}>{cvssLabel(selected.cvss_score)} severity. {getCvssVector(selected.cvss_score, selected.severity)}</span>
                      </div>
                    )}
                  </div>
                </DetailSection>

                {/* Metadata */}
                <DetailSection title="Metadata">
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px 24px' }}>
                    {[
                      ['Module', selected.module_id],
                      ['Scan ID', selected.scan_id?.slice(0, 8)],
                      ['Found at', selected.created_at?.slice(0, 19)],
                      ['Status', selected.false_positive ? 'False Positive' : 'Confirmed'],
                    ].map(([label, val]) => (
                      <div key={label as string} style={{ fontSize: 11 }}>
                        <span style={{ color: 'var(--t3)' }}>{label}: </span>
                        <span className="font-mono" style={{ color: 'var(--t2)' }}>{val}</span>
                      </div>
                    ))}
                  </div>
                </DetailSection>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

function Tag({ label, dim }: { label: string; dim?: boolean }) {
  return (
    <span className="font-mono" style={{
      fontSize: 10, padding: '3px 10px', borderRadius: 3,
      border: '1px solid var(--border)',
      color: dim ? 'var(--t3)' : 'var(--t2)',
      background: 'var(--bg-2)',
    }}>{label}</span>
  );
}

function DetailSection({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div>
      <div style={{
        fontSize: 10, textTransform: 'uppercase', letterSpacing: '0.14em',
        color: 'var(--t3)', fontWeight: 600, marginBottom: 10,
      }}>{title}</div>
      {children}
    </div>
  );
}

function getImpactText(severity: string, cweId: string, title: string): string {
  if (severity === 'critical') return 'This vulnerability poses an immediate and severe risk. An attacker can exploit this to gain unauthorized access, steal sensitive data, execute arbitrary code, or fully compromise the system. Immediate remediation is required.';
  if (severity === 'high') return 'This vulnerability represents a significant security risk. Exploitation could lead to unauthorized data access, privilege escalation, or significant disruption to the application. Remediation should be prioritized.';
  if (severity === 'medium') return 'This finding indicates a security weakness that could be exploited under certain conditions. While not immediately critical, it increases the overall attack surface and should be addressed in the near term.';
  if (severity === 'low') return 'This is a minor security observation that provides limited direct risk. However, it may aid an attacker in reconnaissance or be combined with other findings for a more significant attack.';
  return 'This is an informational finding that documents the application\'s configuration or behavior. While not a direct vulnerability, it provides context for understanding the overall security posture.';
}

function getCvssVector(score: number, severity: string): string {
  if (score >= 9) return 'Attack vector: Network. Attack complexity: Low. Privileges required: None. User interaction: None.';
  if (score >= 7) return 'Attack vector: Network. Attack complexity: Low. Requires some preconditions for exploitation.';
  if (score >= 4) return 'Attack vector: Network. Some conditions must be met for successful exploitation.';
  return 'Limited exploitability. Low impact on confidentiality, integrity, or availability.';
}
