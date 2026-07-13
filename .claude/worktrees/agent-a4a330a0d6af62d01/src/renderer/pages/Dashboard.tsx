import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';

export default function Dashboard() {
  const nav = useNavigate();
  const [projects, setProjects] = useState<any[]>([]);
  const [findings, setFindings] = useState<any[]>([]);
  const [newName, setNewName] = useState('');
  const [newUrl, setNewUrl] = useState('');
  const [showNew, setShowNew] = useState(false);

  useEffect(() => { load(); }, []);
  async function load() {
    const [p, f] = await Promise.all([window.hackme.getProjects(), window.hackme.getAllFindings()]);
    setProjects(p || []); setFindings(f || []);
  }
  async function create() {
    if (!newName.trim() || !newUrl.trim()) return;
    await window.hackme.createProject(newName.trim(), newUrl.trim());
    setNewName(''); setNewUrl(''); setShowNew(false); load();
  }
  async function remove(id: string, e: React.MouseEvent) {
    e.stopPropagation();
    await window.hackme.deleteProject(id); load();
  }

  const s = { c: 0, h: 0, m: 0, l: 0, i: 0 };
  findings.forEach(f => {
    if (f.severity === 'critical') s.c++;
    else if (f.severity === 'high') s.h++;
    else if (f.severity === 'medium') s.m++;
    else if (f.severity === 'low') s.l++;
    else s.i++;
  });
  const total = findings.length;

  return (
    <div style={{ maxWidth: 920 }}>
      {/* Hero */}
      <div style={{ padding: '32px 36px', borderRadius: 'var(--radius-lg)', marginBottom: 24, background: `linear-gradient(135deg, var(--bg-1) 0%, var(--bg-2) 100%)`, border: '1px solid var(--border)' }}>
        <div style={{ fontSize: 28, fontWeight: 800, color: 'var(--t1)', letterSpacing: '-0.02em', fontFamily: 'var(--font-ui)' }}>
          Welcome to <span style={{ color: 'var(--ac)' }}>HackMe</span>
        </div>
        <div style={{ fontSize: 14, color: 'var(--t3)', marginTop: 6 }}>
          {projects.length} project{projects.length !== 1 ? 's' : ''} · {total} finding{total !== 1 ? 's' : ''} · 29 scan modules ready
        </div>
      </div>

      {/* Stats row — each stat has its own visual weight */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr 1fr 1fr', gap: 12, marginBottom: 24 }}>
        <StatBox label="Critical" value={s.c} color="var(--crit)" glow={s.c > 0} />
        <StatBox label="High" value={s.h} color="var(--high)" />
        <StatBox label="Medium" value={s.m} color="var(--med)" />
        <StatBox label="Low" value={s.l} color="var(--low)" />
        <StatBox label="Info" value={s.i} color="var(--info)" />
      </div>

      {/* Risk bar */}
      {total > 0 && (
        <div style={{ marginBottom: 24 }}>
          <div style={{ fontSize: 'var(--label-size)', fontWeight: 'var(--label-weight)', letterSpacing: 'var(--label-spacing)', textTransform: 'uppercase' as const, color: 'var(--t3)', marginBottom: 8 }}>Risk Distribution</div>
          <div style={{ display: 'flex', height: 8, borderRadius: 99, overflow: 'hidden', background: 'var(--bg-2)' }}>
            {s.c > 0 && <div style={{ width: `${(s.c/total)*100}%`, background: 'var(--crit)' }} />}
            {s.h > 0 && <div style={{ width: `${(s.h/total)*100}%`, background: 'var(--high)' }} />}
            {s.m > 0 && <div style={{ width: `${(s.m/total)*100}%`, background: 'var(--med)' }} />}
            {s.l > 0 && <div style={{ width: `${(s.l/total)*100}%`, background: 'var(--low)' }} />}
            {s.i > 0 && <div style={{ width: `${(s.i/total)*100}%`, background: 'var(--info)' }} />}
          </div>
        </div>
      )}

      {/* Two column layout */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 360px', gap: 16, marginBottom: 24 }}>
        {/* Projects */}
        <div>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 }}>
            <div style={{ fontSize: 'var(--label-size)', fontWeight: 'var(--label-weight)', letterSpacing: 'var(--label-spacing)', textTransform: 'uppercase' as const, color: 'var(--t3)' }}>Projects</div>
            <button onClick={() => setShowNew(!showNew)} className="hm-btn hm-btn-accent-ghost" style={{ fontSize: 11, padding: '4px 12px' }}>
              {showNew ? 'Cancel' : '+ New'}
            </button>
          </div>

          {showNew && (
            <div style={{ display: 'flex', gap: 8, marginBottom: 12, padding: 12, background: 'var(--bg-1)', borderRadius: 'var(--radius)', border: '1px solid var(--border)' }}>
              <input className="hm-input" style={{ flex: 1 }} placeholder="Name" value={newName} onChange={e => setNewName(e.target.value)} />
              <input className="hm-input hm-input-mono" style={{ flex: 1.5 }} placeholder="https://target.com" value={newUrl} onChange={e => setNewUrl(e.target.value)} onKeyDown={e => e.key === 'Enter' && create()} />
              <button onClick={create} className="hm-btn hm-btn-primary">Create</button>
            </div>
          )}

          {projects.length === 0 ? (
            <div style={{ padding: '40px 0', textAlign: 'center', color: 'var(--t3)', fontSize: 13 }}>
              No projects yet. Create one to start scanning.
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              {projects.map(p => (
                <div key={p.id} onClick={() => nav('/scanner/new')}
                  style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '12px 16px', background: 'var(--bg-1)', borderRadius: 'var(--radius)', border: '1px solid var(--border)', cursor: 'pointer', transition: 'border-color .15s' }}
                  onMouseEnter={e => (e.currentTarget.style.borderColor = 'var(--border-s)')}
                  onMouseLeave={e => (e.currentTarget.style.borderColor = 'var(--border)')}>
                  {/* Avatar */}
                  <div style={{ width: 36, height: 36, borderRadius: 'var(--radius)', background: 'var(--ac-lo)', color: 'var(--ac)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 14, fontWeight: 700, flexShrink: 0 }}>
                    {p.name.charAt(0).toUpperCase()}
                  </div>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--t1)' }}>{p.name}</div>
                    <div style={{ fontSize: 11, fontFamily: 'var(--font-code)', color: 'var(--t3)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{p.target_url}</div>
                  </div>
                  <div style={{ fontSize: 10, color: 'var(--t3)', fontFamily: 'var(--font-code)', flexShrink: 0 }}>
                    {new Date(p.created_at).toLocaleDateString('en-US', { month: 'short', day: 'numeric' })}
                  </div>
                  <button onClick={e => remove(p.id, e)} style={{ fontSize: 10, color: 'var(--t3)', background: 'none', border: 'none', cursor: 'pointer', padding: '2px 6px', borderRadius: 'var(--radius)', opacity: 0.5 }}
                    onMouseEnter={e => { e.currentTarget.style.opacity = '1'; e.currentTarget.style.color = 'var(--crit)'; }}
                    onMouseLeave={e => { e.currentTarget.style.opacity = '0.5'; e.currentTarget.style.color = 'var(--t3)'; }}>
                    remove
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Recent findings — timeline style */}
        <div>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 }}>
            <div style={{ fontSize: 'var(--label-size)', fontWeight: 'var(--label-weight)', letterSpacing: 'var(--label-spacing)', textTransform: 'uppercase' as const, color: 'var(--t3)' }}>Recent Findings</div>
            {total > 0 && (
              <button onClick={() => nav('/findings')} style={{ fontSize: 11, color: 'var(--ac)', background: 'none', border: 'none', cursor: 'pointer' }}>View all</button>
            )}
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
            {findings.length === 0 ? (
              <div style={{ padding: '40px 0', textAlign: 'center', color: 'var(--t3)', fontSize: 13 }}>No findings yet</div>
            ) : findings.slice(0, 8).map(f => (
              <div key={f.id} onClick={() => nav('/findings')}
                style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '8px 12px', borderRadius: 'var(--radius)', cursor: 'pointer', borderLeft: `3px solid var(--${f.severity === 'critical' ? 'crit' : f.severity === 'high' ? 'high' : f.severity === 'medium' ? 'med' : f.severity === 'low' ? 'low' : 'info'})`, transition: 'background .1s' }}
                onMouseEnter={e => (e.currentTarget.style.background = 'var(--bg-1)')}
                onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}>
                <span className={`sev-pill sev-pill-${f.severity}`}>{f.severity[0].toUpperCase()}</span>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontSize: 12, color: 'var(--t1)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{f.title}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Quick actions — big clickable cards, not small buttons */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 12 }}>
        <ActionCard title="Start Scan" desc="Launch vulnerability assessment" accent="var(--ac)" onClick={() => nav('/scanner/new')} />
        <ActionCard title="Interceptor" desc="Capture and modify traffic" accent="var(--low)" onClick={() => nav('/proxy/intercept')} />
        <ActionCard title="AI Analysis" desc="Gemini-powered detection" accent="var(--med)" onClick={() => nav('/ai')} />
      </div>
    </div>
  );
}

function StatBox({ label, value, color, glow }: { label: string; value: number; color: string; glow?: boolean }) {
  return (
    <div style={{
      padding: 'var(--pad-section)',
      background: 'var(--bg-1)',
      borderRadius: 'var(--radius-lg)',
      border: `1px solid ${value > 0 && glow ? color : 'var(--border)'}`,
      boxShadow: value > 0 && glow ? `0 0 20px ${color}22` : 'none',
      textAlign: 'center',
    }}>
      <div style={{ fontSize: 'calc(var(--head-size) + 6px)', fontWeight: 800, fontFamily: 'var(--font-code)', color: value > 0 ? color : 'var(--t3)', lineHeight: 1 }}>{value}</div>
      <div style={{ fontSize: 'var(--label-size)', fontWeight: 'var(--label-weight)', letterSpacing: 'var(--label-spacing)', textTransform: 'uppercase', color: 'var(--t3)', marginTop: 6 }}>{label}</div>
    </div>
  );
}

function ActionCard({ title, desc, accent, onClick }: { title: string; desc: string; accent: string; onClick: () => void }) {
  return (
    <div onClick={onClick}
      style={{ padding: '20px 24px', background: 'var(--bg-1)', borderRadius: 'var(--radius-lg)', border: '1px solid var(--border)', cursor: 'pointer', transition: 'border-color .15s, transform .1s' }}
      onMouseEnter={e => { e.currentTarget.style.borderColor = accent; e.currentTarget.style.transform = 'translateY(-1px)'; }}
      onMouseLeave={e => { e.currentTarget.style.borderColor = 'var(--border)'; e.currentTarget.style.transform = 'translateY(0)'; }}>
      <div style={{ width: 8, height: 8, borderRadius: '50%', background: accent, marginBottom: 12 }} />
      <div style={{ fontSize: 15, fontWeight: 700, color: 'var(--t1)', marginBottom: 4 }}>{title}</div>
      <div style={{ fontSize: 12, color: 'var(--t3)' }}>{desc}</div>
    </div>
  );
}
