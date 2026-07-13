import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';

export default function ScanHistory() {
  const navigate = useNavigate();
  const [projects, setProjects] = useState<any[]>([]);
  const [scans, setScans] = useState<any[]>([]);
  const [selectedProject, setSelectedProject] = useState('');

  useEffect(() => {
    (async () => {
      const p = await window.hackme.getProjects();
      setProjects(p || []);
      if (p?.length) { setSelectedProject(p[0].id); loadScans(p[0].id); }
    })();
  }, []);

  async function loadScans(pid: string) { setSelectedProject(pid); setScans(await window.hackme.getScans(pid) || []); }

  const statusStyles: Record<string, { color: string; bg: string; label: string }> = {
    completed: { color: 'var(--ac)', bg: 'rgba(0,229,195,0.08)', label: 'Completed' },
    running: { color: 'var(--med)', bg: 'rgba(229,197,66,0.08)', label: 'Running' },
    failed: { color: 'var(--crit)', bg: 'rgba(255,92,92,0.08)', label: 'Failed' },
    cancelled: { color: 'var(--t3)', bg: 'var(--bg-2)', label: 'Cancelled' },
    pending: { color: 'var(--t3)', bg: 'var(--bg-2)', label: 'Pending' },
  };

  return (
    <div style={{ maxWidth: 860, display: 'flex', flexDirection: 'column', gap: 24 }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'flex-end', justifyContent: 'space-between' }}>
        <div>
          <h1 className="pg-title">Scan History</h1>
          <p className="pg-sub">{scans.length} scans recorded</p>
        </div>
        <select value={selectedProject} onChange={e => loadScans(e.target.value)}
          className="hm-input"
          style={{ width: 280, fontSize: 12 }}>
          {projects.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}
        </select>
      </div>

      {/* Scans list */}
      {scans.length === 0 ? (
        <div style={{
          padding: '64px 32px', textAlign: 'center',
          background: 'var(--bg-1)', borderRadius: 'var(--radius-lg)',
          border: '1px dashed var(--border)',
        }}>
          <div style={{ fontSize: 18, color: 'var(--t3)', marginBottom: 8 }}>No scans yet</div>
          <div style={{ fontSize: 13, color: 'var(--t3)' }}>Run a scan to see results here</div>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {scans.map(s => {
            const c = parseCounts(s.findings_count);
            const total = c.critical + c.high + c.medium + c.low + c.info;
            const st = statusStyles[s.status] || statusStyles.pending;

            return (
              <div key={s.id}
                onClick={() => s.status === 'completed' && navigate('/findings')}
                style={{
                  display: 'flex', alignItems: 'center', gap: 20,
                  padding: '18px 24px',
                  background: 'var(--bg-0)',
                  border: '1px solid var(--border)',
                  borderRadius: 'var(--radius-lg)',
                  cursor: s.status === 'completed' ? 'pointer' : 'default',
                  transition: 'all 0.15s',
                }}
                onMouseEnter={e => {
                  if (s.status === 'completed') {
                    e.currentTarget.style.borderColor = 'var(--border-s)';
                    e.currentTarget.style.background = 'var(--bg-1)';
                  }
                }}
                onMouseLeave={e => {
                  e.currentTarget.style.borderColor = 'var(--border)';
                  e.currentTarget.style.background = 'var(--bg-0)';
                }}
              >
                {/* Status indicator */}
                <div style={{
                  width: 10, height: 10, borderRadius: '50%', flexShrink: 0,
                  background: st.color,
                }} className={s.status === 'running' ? 'cx-pulse' : ''} />

                {/* Scan info */}
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 4 }}>
                    <span style={{ fontSize: 14, fontWeight: 600, color: 'var(--t1)', textTransform: 'uppercase' }}>
                      {s.profile}
                    </span>
                    <span style={{
                      fontSize: 10, padding: '2px 8px', borderRadius: 10,
                      background: st.bg, color: st.color, fontWeight: 500,
                    }}>
                      {st.label}
                    </span>
                  </div>
                  <div className="font-mono" style={{
                    fontSize: 11, color: 'var(--t3)',
                    overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                  }}>
                    {s.target_url}
                  </div>
                </div>

                {/* Severity counts */}
                <div style={{ display: 'flex', gap: 10, flexShrink: 0 }}>
                  {c.critical > 0 && <SevCount label="C" count={c.critical} color="var(--crit)" />}
                  {c.high > 0 && <SevCount label="H" count={c.high} color="var(--high)" />}
                  {c.medium > 0 && <SevCount label="M" count={c.medium} color="var(--med)" />}
                  {c.low > 0 && <SevCount label="L" count={c.low} color="var(--low)" />}
                  {total === 0 && (
                    <span className="font-mono" style={{ fontSize: 11, color: 'var(--t3)' }}>0 findings</span>
                  )}
                </div>

                {/* Date */}
                <div className="font-mono" style={{
                  fontSize: 11, color: 'var(--t3)', flexShrink: 0,
                  width: 80, textAlign: 'right',
                }}>
                  {s.completed_at ? new Date(s.completed_at).toLocaleDateString('en-US', { month: 'short', day: 'numeric' }) : '--'}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

function SevCount({ label, count, color }: { label: string; count: number; color: string }) {
  return (
    <div className="font-mono" style={{
      display: 'flex', alignItems: 'center', gap: 3,
      fontSize: 12, fontWeight: 700, color,
    }}>
      {count}<span style={{ fontSize: 10, fontWeight: 400, opacity: 0.7 }}>{label}</span>
    </div>
  );
}

function statusColor(s: string) {
  return { completed: '#00E5C3', running: '#E5C542', failed: '#FF5C5C', cancelled: '#5C6680', pending: '#5C6680' }[s] || '#5C6680';
}

function parseCounts(raw: any) {
  const d = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  try { Object.assign(d, typeof raw === 'string' ? JSON.parse(raw) : raw); } catch {}
  return d;
}
