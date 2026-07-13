import { useState, useEffect } from 'react';

type AnalysisMode = 'url' | 'javascript' | 'cookies' | 'findings';

interface AIVuln {
  type: string;
  evidence: string;
  severity: string;
  explanation: string;
}

export default function AiAnalysis() {
  const [configured, setConfigured] = useState<boolean | null>(null);
  const [mode, setMode] = useState<AnalysisMode>('url');
  const [input, setInput] = useState('');
  const [scanId, setScanId] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<any>(null);
  const [error, setError] = useState('');
  const [projects, setProjects] = useState<any[]>([]);
  const [scans, setScans] = useState<any[]>([]);
  const [selectedProject, setSelectedProject] = useState('');

  useEffect(() => {
    window.hackme.aiIsConfigured().then(setConfigured);
    window.hackme.getProjects().then(setProjects);
  }, []);

  useEffect(() => {
    if (selectedProject) {
      window.hackme.getScans(selectedProject).then(setScans);
    }
  }, [selectedProject]);

  async function runAnalysis() {
    setLoading(true); setResult(null); setError('');
    try {
      let res: any;
      switch (mode) {
        case 'url': res = await window.hackme.aiAnalyzeUrl(input); break;
        case 'javascript': res = await window.hackme.aiAnalyzeJs(input); break;
        case 'cookies': res = await window.hackme.aiAnalyzeCookies(input); break;
        case 'findings': res = await window.hackme.aiAnalyzeFindings(scanId); break;
      }
      if (res?.error) setError(res.error);
      else setResult(res);
    } catch (e: any) {
      setError(e.message || 'Analysis failed');
    }
    setLoading(false);
  }

  if (configured === null) return <div style={{ color: 'var(--t3)', fontSize: 12 }}>Loading...</div>;

  if (!configured) {
    return (
      <div style={{ maxWidth: 540, margin: '0 auto', paddingTop: 60 }}>
        <div style={{
          background: 'var(--bg-1)', borderRadius: 'var(--radius-lg)',
          border: '1px solid var(--border)', overflow: 'hidden',
        }}>
          <div style={{
            padding: '32px 32px 24px',
            borderBottom: '1px solid var(--border)',
            textAlign: 'center',
          }}>
            <div style={{ fontSize: 28, marginBottom: 8, opacity: 0.3 }}>AI</div>
            <div style={{ fontSize: 18, fontWeight: 600, color: 'var(--t1)', marginBottom: 8 }}>
              Setup Required
            </div>
            <div style={{ fontSize: 13, color: 'var(--t3)', lineHeight: 1.7 }}>
              AI-powered analysis requires a Gemini API key.
              HackMe uses Gemini 2.0 Flash (free tier) for vulnerability analysis.
            </div>
          </div>
          <div style={{ padding: '20px 32px' }}>
            <div style={{ fontSize: 12, color: 'var(--t3)', lineHeight: 1.8, marginBottom: 20 }}>
              1. Get a free API key from Google AI Studio<br />
              2. Go to Settings and paste your API key
            </div>
            <button onClick={() => window.location.hash = '#/settings'}
              className="hm-btn hm-btn-primary" style={{ width: '100%', padding: '12px' }}>
              Go to Settings
            </button>
          </div>
        </div>
      </div>
    );
  }

  const modeConfig: Record<AnalysisMode, { label: string; icon: string; desc: string; placeholder: string }> = {
    url: { label: 'Analyze URL', icon: '🌐', desc: 'Fetch and analyze an HTTP response for security issues', placeholder: 'https://example.com' },
    javascript: { label: 'Analyze JS', icon: '⚙', desc: 'Analyze a JavaScript file for secrets and dangerous sinks', placeholder: 'https://example.com/static/main.js' },
    cookies: { label: 'Cookies', icon: '🍪', desc: 'Fetch cookies and analyze session security', placeholder: 'https://example.com' },
    findings: { label: 'Correlate', icon: '🔗', desc: 'Correlate scan findings into attack chains', placeholder: '' },
  };

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column', gap: 20 }}>
      {/* Header */}
      <div>
        <h1 className="pg-title">AI Analysis</h1>
        <p className="pg-sub">Gemini-powered vulnerability detection and attack chain correlation</p>
      </div>

      {/* Mode selector - card style */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 8 }}>
        {(['url', 'javascript', 'cookies', 'findings'] as AnalysisMode[]).map(m => {
          const cfg = modeConfig[m];
          const active = mode === m;
          return (
            <button key={m}
              onClick={() => { setMode(m); setResult(null); setError(''); }}
              style={{
                padding: '14px 12px',
                border: `1.5px solid ${active ? 'var(--ac)' : 'var(--border)'}`,
                borderRadius: 'var(--radius)',
                background: active ? 'var(--ac-lo)' : 'var(--bg-0)',
                cursor: 'pointer', textAlign: 'center',
                transition: 'all 0.15s',
              }}
              onMouseEnter={e => { if (!active) e.currentTarget.style.borderColor = 'var(--border-s)'; }}
              onMouseLeave={e => { if (!active) e.currentTarget.style.borderColor = active ? 'var(--ac)' : 'var(--border)'; }}
            >
              <div style={{ fontSize: 12, fontWeight: 600, color: active ? 'var(--ac)' : 'var(--t2)' }}>
                {cfg.label}
              </div>
            </button>
          );
        })}
      </div>

      {/* Input section */}
      <div style={{
        padding: '20px 24px',
        background: 'var(--bg-1)', borderRadius: 'var(--radius-lg)',
        border: '1px solid var(--border)',
      }}>
        <div style={{ fontSize: 12, color: 'var(--t3)', marginBottom: 14, lineHeight: 1.5 }}>
          {modeConfig[mode].desc}
        </div>

        {mode !== 'findings' ? (
          <div style={{ display: 'flex', gap: 10 }}>
            <input
              className="hm-input hm-input-mono"
              style={{ flex: 1, fontSize: 13, padding: '10px 14px' }}
              placeholder={modeConfig[mode].placeholder}
              value={input}
              onChange={e => setInput(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && input && runAnalysis()}
            />
            <button onClick={runAnalysis} disabled={!input || loading}
              className="hm-btn hm-btn-primary" style={{ minWidth: 110 }}>
              {loading ? 'Analyzing...' : 'Analyze'}
            </button>
          </div>
        ) : (
          <div style={{ display: 'flex', gap: 10 }}>
            <select className="hm-input" style={{ flex: 1, fontSize: 12 }}
              value={selectedProject} onChange={e => setSelectedProject(e.target.value)}>
              <option value="">Select project...</option>
              {projects.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}
            </select>
            <select className="hm-input" style={{ flex: 1, fontSize: 12 }}
              value={scanId} onChange={e => setScanId(e.target.value)}>
              <option value="">Select scan...</option>
              {scans.filter((s: any) => s.status === 'completed').map((s: any) => (
                <option key={s.id} value={s.id}>{s.profile} - {s.completed_at?.slice(0, 16)}</option>
              ))}
            </select>
            <button onClick={runAnalysis} disabled={!scanId || loading}
              className="hm-btn hm-btn-primary" style={{ minWidth: 110 }}>
              {loading ? 'Analyzing...' : 'Correlate'}
            </button>
          </div>
        )}
      </div>

      {/* Error */}
      {error && (
        <div className="font-mono" style={{
          fontSize: 12, color: 'var(--crit)',
          background: 'rgba(239,68,68,0.06)',
          padding: '12px 18px', borderRadius: 'var(--radius)',
          border: '1px solid rgba(239,68,68,0.15)',
        }}>
          {error}
        </div>
      )}

      {/* Loading state */}
      {loading && (
        <div style={{
          padding: '24px',
          display: 'flex', alignItems: 'center', gap: 14,
          background: 'var(--bg-1)', borderRadius: 'var(--radius-lg)',
          border: '1px solid var(--border)',
        }}>
          <div className="cx-spinner" />
          <div>
            <div style={{ fontSize: 13, color: 'var(--t1)', fontWeight: 500, marginBottom: 4 }}>
              Analyzing with Gemini Flash...
            </div>
            <div style={{ fontSize: 11, color: 'var(--t3)' }}>
              {mode === 'findings' ? 'Correlating findings into attack chains' : `Processing ${input.slice(0, 60)}`}
            </div>
          </div>
        </div>
      )}

      {/* Results */}
      {result && !result.error && (
        <div style={{ flex: 1, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 16, minHeight: 0 }}>

          {/* Summary */}
          {result.summary && (
            <div style={{
              padding: '20px 24px',
              background: 'var(--bg-1)', borderRadius: 'var(--radius-lg)',
              border: '1px solid var(--border)',
            }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 }}>
                <span style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.12em', color: 'var(--t3)' }}>
                  AI Analysis Summary
                </span>
                {result.risk_level && (
                  <span className={`sev-pill sev-pill-${result.risk_level === 'none' ? 'low' : result.risk_level}`}>
                    {result.risk_level.toUpperCase()}
                  </span>
                )}
              </div>
              <div style={{ fontSize: 13, color: 'var(--t2)', lineHeight: 1.8 }}>
                {result.summary}
              </div>
            </div>
          )}

          {result.executive_summary && (
            <div style={{
              padding: '20px 24px',
              background: 'var(--bg-1)', borderRadius: 'var(--radius-lg)',
              border: '1px solid var(--border)',
            }}>
              <div style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.12em', color: 'var(--t3)', marginBottom: 12 }}>
                Executive Summary
              </div>
              <div style={{ fontSize: 13, color: 'var(--t2)', lineHeight: 1.8 }}>
                {result.executive_summary}
              </div>
            </div>
          )}

          {/* Vulnerabilities */}
          {result.vulnerabilities && result.vulnerabilities.length > 0 && (
            <div style={{
              borderRadius: 'var(--radius-lg)',
              border: '1px solid var(--border)',
              overflow: 'hidden',
            }}>
              <div style={{
                padding: '14px 20px',
                background: 'var(--bg-2)',
                borderBottom: '1px solid var(--border)',
                display: 'flex', alignItems: 'center', justifyContent: 'space-between',
              }}>
                <span style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.12em', color: 'var(--t3)' }}>
                  Vulnerabilities ({result.vulnerabilities.length})
                </span>
                {result.false_positive_likelihood && (
                  <span style={{ fontSize: 10, color: 'var(--t3)' }}>
                    FP likelihood: {result.false_positive_likelihood}
                  </span>
                )}
              </div>
              {result.vulnerabilities.map((v: AIVuln, i: number) => (
                <div key={i}
                  className={`sev-border-${v.severity || 'medium'}`}
                  style={{
                    padding: '16px 20px',
                    borderBottom: i < result.vulnerabilities.length - 1 ? '1px solid var(--border)' : 'none',
                    background: i % 2 === 0 ? 'var(--bg-0)' : 'var(--bg-1)',
                  }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
                    <span className={`sev-pill sev-pill-${v.severity || 'medium'}`}>
                      {(v.severity || 'MEDIUM').toUpperCase()}
                    </span>
                    <span style={{ fontSize: 13, fontWeight: 500, color: 'var(--t1)' }}>{v.type}</span>
                  </div>
                  <div style={{ fontSize: 12, color: 'var(--t2)', lineHeight: 1.7, marginBottom: 8 }}>
                    {v.explanation}
                  </div>
                  {v.evidence && (
                    <div className="font-mono" style={{
                      fontSize: 11, color: 'var(--ac)',
                      background: 'var(--bg-2)', padding: '8px 14px',
                      borderRadius: 'var(--radius)', wordBreak: 'break-all',
                      border: '1px solid var(--border)',
                    }}>
                      {v.evidence.slice(0, 300)}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}

          {/* Attack chains */}
          {result.attack_chains && result.attack_chains.length > 0 && (
            <div style={{
              padding: '20px 24px',
              background: 'var(--bg-1)', borderRadius: 'var(--radius-lg)',
              border: '1px solid var(--border)',
            }}>
              <div style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.12em', color: 'var(--t3)', marginBottom: 14 }}>
                Attack Chains
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                {result.attack_chains.map((chain: string, i: number) => (
                  <div key={i} style={{
                    fontSize: 12, color: 'var(--t2)', lineHeight: 1.7,
                    background: 'var(--bg-2)', padding: '12px 16px',
                    borderRadius: 'var(--radius)',
                    borderLeft: '3px solid var(--ac)',
                  }}>
                    <span className="font-mono" style={{ color: 'var(--ac)', marginRight: 8, fontWeight: 600 }}>
                      CHAIN {i + 1}
                    </span>
                    {chain}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Priority order */}
          {result.priority_order && result.priority_order.length > 0 && (
            <div style={{
              padding: '20px 24px',
              background: 'var(--bg-1)', borderRadius: 'var(--radius-lg)',
              border: '1px solid var(--border)',
            }}>
              <div style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.12em', color: 'var(--t3)', marginBottom: 14 }}>
                Remediation Priority
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                {result.priority_order.map((item: string, i: number) => (
                  <div key={i} style={{ display: 'flex', gap: 12, fontSize: 12, color: 'var(--t2)', lineHeight: 1.6 }}>
                    <span className="font-mono" style={{
                      color: 'var(--ac)', flexShrink: 0, fontWeight: 600,
                      width: 20, textAlign: 'right',
                    }}>{i + 1}.</span>
                    <span>{item}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Recommendations */}
          {result.recommendations && result.recommendations.length > 0 && (
            <div style={{
              padding: '20px 24px',
              background: 'var(--bg-1)', borderRadius: 'var(--radius-lg)',
              border: '1px solid var(--border)',
            }}>
              <div style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.12em', color: 'var(--t3)', marginBottom: 14 }}>
                Recommendations
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                {result.recommendations.map((rec: string, i: number) => (
                  <div key={i} style={{ display: 'flex', gap: 10, fontSize: 12, color: 'var(--t2)', lineHeight: 1.6 }}>
                    <span style={{ color: 'var(--ac)', flexShrink: 0 }}>--</span>
                    <span>{rec}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
