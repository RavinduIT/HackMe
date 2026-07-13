import { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';

export default function ActiveScan() {
  const { scanId } = useParams();
  const navigate = useNavigate();
  const [findings, setFindings] = useState<any[]>([]);
  const [progress, setProgress] = useState({ module: '', percent: 0, requests: 0 });
  const [cancelled, setCancelled] = useState(false);

  useEffect(() => {
    if (!scanId) return;
    loadFindings();
    const u1 = window.hackme.onScanProgress((d: any) => {
      if (d.scanId === scanId) {
        setProgress(d);
        if (d.module === 'Cancelled') setCancelled(true);
      }
    });
    const u2 = window.hackme.onScanFinding((d: any) => { if (d.scanId === scanId) loadFindings(); });
    return () => { u1(); u2(); };
  }, [scanId]);

  async function loadFindings() { if (scanId) setFindings(await window.hackme.getFindings(scanId) || []); }
  async function stop() {
    if (!scanId) return;
    setCancelled(true);
    await window.hackme.stopScan(scanId);
  }

  const done = progress.percent >= 100;
  const sevCounts: Record<string, number> = {};
  findings.forEach(f => { sevCounts[f.severity] = (sevCounts[f.severity] || 0) + 1; });

  const sevStyles: Record<string, { color: string; bg: string; border: string }> = {
    critical: { color: 'var(--crit)', bg: 'rgba(255,92,92,0.06)', border: 'rgba(255,92,92,0.2)' },
    high: { color: 'var(--high)', bg: 'rgba(255,140,66,0.06)', border: 'rgba(255,140,66,0.2)' },
    medium: { color: 'var(--med)', bg: 'rgba(229,197,66,0.06)', border: 'rgba(229,197,66,0.2)' },
    low: { color: 'var(--low)', bg: 'rgba(91,141,239,0.06)', border: 'rgba(91,141,239,0.2)' },
    info: { color: 'var(--info)', bg: 'rgba(94,105,128,0.06)', border: 'rgba(94,105,128,0.2)' },
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24, maxWidth: 900 }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between' }}>
        <div>
          <h1 className="pg-title">{cancelled ? 'Scan Cancelled' : done ? 'Scan Complete' : 'Scanning'}</h1>
          <p className="pg-sub">{cancelled ? `Stopped — ${findings.length} findings so far` : done ? `${findings.length} vulnerabilities found` : progress.module || 'Initializing...'}</p>
        </div>
        {done || cancelled ? (
          <div style={{ display: 'flex', gap: 8 }}>
            <button onClick={() => navigate('/findings')} className="hm-btn hm-btn-accent-ghost" style={{ fontSize: 12 }}>
              View Findings
            </button>
            <button onClick={() => navigate('/scanner/new')} className="hm-btn hm-btn-ghost" style={{ fontSize: 12 }}>
              New Scan
            </button>
          </div>
        ) : (
          <button onClick={stop} className="hm-btn hm-btn-danger" style={{ fontSize: 12 }}>
            Cancel Scan
          </button>
        )}
      </div>

      {/* Progress section */}
      <div style={{
        padding: '24px 28px',
        background: 'var(--bg-1)',
        borderRadius: 'var(--radius-lg)',
        border: '1px solid var(--border)',
      }}>
        {/* Percentage display */}
        <div style={{ display: 'flex', alignItems: 'flex-end', justifyContent: 'space-between', marginBottom: 16 }}>
          <div style={{ display: 'flex', alignItems: 'baseline', gap: 4 }}>
            <span className="font-mono" style={{ fontSize: 36, fontWeight: 700, color: done ? 'var(--ac)' : 'var(--t1)', lineHeight: 1 }}>
              {progress.percent}
            </span>
            <span className="font-mono" style={{ fontSize: 14, color: 'var(--t3)' }}>%</span>
          </div>
          <span className="font-mono" style={{ fontSize: 11, color: 'var(--t3)' }}>
            {progress.requests} requests sent
          </span>
        </div>

        {/* Progress bar */}
        <div style={{
          width: '100%', height: 6, background: 'var(--bg-3)',
          borderRadius: 3, overflow: 'hidden', position: 'relative',
        }}>
          <div style={{
            height: '100%', borderRadius: 3,
            width: `${progress.percent}%`,
            background: done
              ? 'var(--ac)'
              : 'linear-gradient(90deg, var(--ac), #00A893)',
            transition: 'width 0.4s ease',
            boxShadow: done ? 'none' : '0 0 12px rgba(0,229,195,0.3)',
          }} />
        </div>

        {/* Current module */}
        {!done && !cancelled && progress.module && (
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginTop: 14 }}>
            <div className="cx-spinner" />
            <span style={{ fontSize: 12, color: 'var(--t2)' }}>{progress.module}</span>
          </div>
        )}
        {cancelled && (
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 14 }}>
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--high)" strokeWidth="2.5">
              <path d="M18 6L6 18M6 6l12 12"/>
            </svg>
            <span style={{ fontSize: 12, color: 'var(--high)', fontWeight: 500 }}>Scan was cancelled by user</span>
          </div>
        )}
        {done && !cancelled && (
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 14 }}>
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--ac)" strokeWidth="2.5">
              <path d="M5 12l5 5L20 7"/>
            </svg>
            <span style={{ fontSize: 12, color: 'var(--ac)', fontWeight: 500 }}>Scan finished successfully</span>
          </div>
        )}
      </div>

      {/* Severity counters - card row */}
      {findings.length > 0 && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 8 }}>
          {['critical', 'high', 'medium', 'low', 'info'].map(sev => {
            const n = sevCounts[sev] || 0;
            const s = sevStyles[sev];
            return (
              <div key={sev} style={{
                padding: '14px 16px',
                background: n > 0 ? s.bg : 'var(--bg-1)',
                border: `1px solid ${n > 0 ? s.border : 'var(--border)'}`,
                borderRadius: 'var(--radius)',
                textAlign: 'center',
              }}>
                <div className="font-mono" style={{
                  fontSize: 22, fontWeight: 700,
                  color: n > 0 ? s.color : 'var(--t3)',
                  lineHeight: 1,
                }}>{n}</div>
                <div style={{
                  fontSize: 9, textTransform: 'uppercase', letterSpacing: '0.1em',
                  color: n > 0 ? s.color : 'var(--t3)',
                  marginTop: 6, fontWeight: 600,
                }}>{sev}</div>
              </div>
            );
          })}
        </div>
      )}

      {/* Findings feed */}
      <div>
        <div style={{
          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
          marginBottom: 12,
        }}>
          <span style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.12em', color: 'var(--t3)' }}>
            Findings
          </span>
          <span className="font-mono" style={{ fontSize: 11, color: 'var(--t2)' }}>
            {findings.length}
          </span>
        </div>

        <div style={{
          borderRadius: 'var(--radius-lg)',
          border: '1px solid var(--border)',
          overflow: 'hidden', maxHeight: 480,
          overflowY: 'auto',
        }}>
          {findings.length === 0 ? (
            <div style={{
              padding: '48px 20px', textAlign: 'center',
              color: 'var(--t3)', fontSize: 13,
              background: 'var(--bg-0)',
            }}>
              {done ? 'No vulnerabilities found.' : 'Scanning for vulnerabilities...'}
            </div>
          ) : findings.map((f, idx) => {
            const s = sevStyles[f.severity] || sevStyles.info;
            return (
              <div key={f.id}
                className={`sev-border-${f.severity}`}
                onClick={() => navigate('/findings')}
                style={{
                  display: 'flex', alignItems: 'center', gap: 14,
                  padding: '14px 20px',
                  background: idx % 2 === 0 ? 'var(--bg-0)' : 'var(--bg-1)',
                  cursor: 'pointer', transition: 'background 0.12s',
                  borderBottom: idx < findings.length - 1 ? '1px solid var(--border)' : 'none',
                }}
                onMouseEnter={e => e.currentTarget.style.background = 'var(--bg-2)'}
                onMouseLeave={e => e.currentTarget.style.background = idx % 2 === 0 ? 'var(--bg-0)' : 'var(--bg-1)'}
              >
                <span className={`sev-pill sev-pill-${f.severity}`}>{f.severity}</span>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontSize: 13, color: 'var(--t1)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {f.title}
                  </div>
                  <div className="font-mono" style={{ fontSize: 10, color: 'var(--t3)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', marginTop: 2 }}>
                    {f.url}
                  </div>
                </div>
                {f.cvss_score > 0 && (
                  <span className="font-mono" style={{ fontSize: 10, color: 'var(--t3)', flexShrink: 0 }}>
                    CVSS {f.cvss_score}
                  </span>
                )}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
