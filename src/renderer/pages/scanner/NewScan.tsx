import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';

export default function NewScan() {
  const navigate = useNavigate();
  const [projects, setProjects] = useState<any[]>([]);
  const [project, setProject] = useState('');
  const [profile, setProfile] = useState('standard');
  const [modules, setModules] = useState<any[]>([]);
  const [rate, setRate] = useState(10);
  const [authType, setAuthType] = useState('none');
  const [authValue, setAuthValue] = useState('');

  useEffect(() => {
    (async () => {
      const [p, m] = await Promise.all([window.hackme.getProjects(), window.hackme.getModules()]);
      setProjects(p || []); setModules(m || []);
      if (p?.length) setProject(p[0].id);
    })();
  }, []);

  function toggle(id: string) { setModules(prev => prev.map(m => m.id === id ? { ...m, enabled: !m.enabled } : m)); }

  async function launch() {
    if (!project) return;
    const auth = authType !== 'none' ? { type: authType, value: authType === 'basic' ? (() => { const p = authValue.split(':'); return { username: p[0] || '', password: p.slice(1).join(':') || '' }; })() : authType === 'custom' ? authValue.split('\n').filter(l => l.includes(':')).map(l => { const i = l.indexOf(':'); return { key: l.slice(0, i).trim(), value: l.slice(i + 1).trim() }; }) : authValue } : undefined;
    const config = { profile, modules: modules.filter(m => m.enabled).map(m => m.id), rate_limit: rate, max_concurrent: 5, timeout: 60000, respect_robots: true, auth };
    const scan = await window.hackme.createScan(project, config);
    await window.hackme.startScan(scan.id);
    navigate(`/scanner/active/${scan.id}`);
  }

  const groups = modules.reduce((a, m) => { (a[m.category] = a[m.category] || []).push(m); return a; }, {} as Record<string, any[]>);
  const enabledCount = modules.filter(m => m.enabled).length;

  const profiles: Record<string, { time: string; desc: string; color: string }> = {
    quick: { time: '~30s', desc: 'Headers, TLS, and recon only', color: '#22d3ee' },
    standard: { time: '~5min', desc: 'Injection, auth, and config checks', color: 'var(--ac)' },
    deep: { time: '~15min', desc: 'Advanced attacks + modern vectors', color: '#fbbf24' },
    full: { time: '~30min+', desc: 'All 29 modules enabled', color: 'var(--crit)' },
  };

  return (
    <div style={{ maxWidth: 780, display: 'flex', flexDirection: 'column', gap: 32 }}>
      {/* Header */}
      <div>
        <h1 className="pg-title">New Scan</h1>
        <p className="pg-sub">Configure and launch a vulnerability assessment</p>
      </div>

      {/* Target selector */}
      <div>
        <label style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.12em', color: 'var(--t3)', display: 'block', marginBottom: 10 }}>
          Target Project
        </label>
        <select value={project} onChange={e => setProject(e.target.value)}
          className="hm-input hm-input-mono"
          style={{ width: '100%', fontSize: 13, padding: '12px 14px' }}>
          {projects.map(p => <option key={p.id} value={p.id}>{p.name} -- {p.target_url}</option>)}
        </select>
        {projects.length === 0 && (
          <div style={{ fontSize: 12, color: 'var(--t3)', marginTop: 8 }}>
            Create a project on the Dashboard first.
          </div>
        )}
      </div>

      {/* Scan profile cards - horizontal layout */}
      <div>
        <label style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.12em', color: 'var(--t3)', display: 'block', marginBottom: 12 }}>
          Scan Profile
        </label>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 10 }}>
          {Object.entries(profiles).map(([key, p]) => {
            const active = profile === key;
            return (
              <button key={key} onClick={() => setProfile(key)}
                style={{
                  padding: '20px 16px',
                  border: `1.5px solid ${active ? p.color : 'var(--border)'}`,
                  borderRadius: 'var(--radius-lg)',
                  background: active ? `${p.color}08` : 'var(--bg-0)',
                  cursor: 'pointer', textAlign: 'left',
                  transition: 'all 0.2s',
                  boxShadow: active ? `0 0 20px ${p.color}15` : 'none',
                }}
                onMouseEnter={e => { if (!active) e.currentTarget.style.borderColor = 'var(--border-s)'; }}
                onMouseLeave={e => { if (!active) e.currentTarget.style.borderColor = 'var(--border)'; }}
              >
                <div style={{
                  fontSize: 14, fontWeight: 700, textTransform: 'uppercase',
                  letterSpacing: '0.06em',
                  color: active ? p.color : 'var(--t2)',
                  marginBottom: 6,
                }}>{key}</div>
                <div style={{ fontSize: 11, color: 'var(--t3)', lineHeight: 1.5, marginBottom: 10 }}>
                  {p.desc}
                </div>
                <div className="font-mono" style={{ fontSize: 10, color: active ? p.color : 'var(--t3)', opacity: 0.8 }}>
                  {p.time}
                </div>
              </button>
            );
          })}
        </div>
      </div>

      {/* Rate limit - inline design */}
      <div>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 }}>
          <label style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.12em', color: 'var(--t3)' }}>
            Rate Limit
          </label>
          <span className="font-mono" style={{
            fontSize: 18, fontWeight: 700, color: 'var(--ac)',
          }}>
            {rate} <span style={{ fontSize: 11, fontWeight: 400, color: 'var(--t3)' }}>req/s</span>
          </span>
        </div>
        <div style={{
          padding: '16px 20px',
          background: 'var(--bg-1)', borderRadius: 'var(--radius-lg)',
          border: '1px solid var(--border)',
        }}>
          <input type="range" min="1" max="100" value={rate}
            onChange={e => setRate(+e.target.value)}
            style={{ width: '100%', accentColor: 'var(--ac)' }} />
          <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 6 }}>
            <span className="font-mono" style={{ fontSize: 9, color: 'var(--t3)' }}>1</span>
            <span className="font-mono" style={{ fontSize: 9, color: 'var(--t3)' }}>25</span>
            <span className="font-mono" style={{ fontSize: 9, color: 'var(--t3)' }}>50</span>
            <span className="font-mono" style={{ fontSize: 9, color: 'var(--t3)' }}>75</span>
            <span className="font-mono" style={{ fontSize: 9, color: 'var(--t3)' }}>100</span>
          </div>
        </div>
      </div>

      {/* Authentication */}
      <div>
        <label style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.12em', color: 'var(--t3)', display: 'block', marginBottom: 12 }}>Authentication</label>
        <div style={{ padding: '16px 20px', background: 'var(--bg-1)', borderRadius: 'var(--radius-lg)', border: '1px solid var(--border)' }}>
          <div style={{ display: 'flex', gap: 6, marginBottom: authType !== 'none' ? 14 : 0 }}>
            {['none', 'cookie', 'bearer', 'basic', 'custom'].map(t => (
              <button key={t} onClick={() => setAuthType(t)} style={{
                padding: '6px 14px', borderRadius: 'var(--radius)', border: 'none', cursor: 'pointer',
                fontSize: 11, fontWeight: authType === t ? 600 : 400, textTransform: 'capitalize',
                background: authType === t ? 'var(--ac-lo)' : 'transparent',
                color: authType === t ? 'var(--ac)' : 'var(--t3)', transition: 'all 0.15s',
              }}>{t === 'none' ? 'None' : t === 'bearer' ? 'Bearer Token' : t === 'basic' ? 'Basic Auth' : t === 'custom' ? 'Custom Headers' : 'Cookie'}</button>
            ))}
          </div>
          {authType === 'cookie' && <input className="hm-input hm-input-mono" style={{ width: '100%' }} placeholder="session=abc123; token=xyz" value={authValue} onChange={e => setAuthValue(e.target.value)} />}
          {authType === 'bearer' && <input className="hm-input hm-input-mono" style={{ width: '100%' }} placeholder="eyJhbGciOi..." value={authValue} onChange={e => setAuthValue(e.target.value)} />}
          {authType === 'basic' && <input className="hm-input hm-input-mono" style={{ width: '100%' }} placeholder="username:password" value={authValue} onChange={e => setAuthValue(e.target.value)} />}
          {authType === 'custom' && <textarea className="raw-viewer" style={{ width: '100%', height: 80, resize: 'none', border: '1px solid var(--border)', borderRadius: 'var(--radius)', padding: '8px 12px', fontSize: 12 }} placeholder="X-API-Key: abc123&#10;Authorization: custom-token" value={authValue} onChange={e => setAuthValue(e.target.value)} />}
        </div>
      </div>

      {/* Modules section */}
      <div>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 14 }}>
          <div style={{ display: 'flex', alignItems: 'baseline', gap: 10 }}>
            <label style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.12em', color: 'var(--t3)' }}>
              Modules
            </label>
            <span className="font-mono" style={{ fontSize: 12, color: 'var(--ac)' }}>
              {enabledCount}<span style={{ color: 'var(--t3)' }}>/{modules.length}</span>
            </span>
          </div>
          <div style={{ display: 'flex', gap: 4 }}>
            <button onClick={() => setModules(prev => prev.map(m => ({ ...m, enabled: true })))}
              className="hm-btn hm-btn-ghost" style={{ fontSize: 10, padding: '4px 10px' }}>All</button>
            <button onClick={() => setModules(prev => prev.map(m => ({ ...m, enabled: false })))}
              className="hm-btn hm-btn-ghost" style={{ fontSize: 10, padding: '4px 10px' }}>None</button>
          </div>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
          {Object.entries(groups).map(([cat, mods]) => (
            <div key={cat}>
              <div style={{
                fontSize: 10, textTransform: 'uppercase', letterSpacing: '0.1em',
                color: 'var(--t3)', fontWeight: 600, marginBottom: 10,
                paddingBottom: 6, borderBottom: '1px solid var(--border)',
              }}>{cat}</div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 6 }}>
                {(mods as any[]).map(m => (
                  <button key={m.id} onClick={() => toggle(m.id)}
                    style={{
                      display: 'flex', alignItems: 'center', gap: 10,
                      padding: '10px 14px', borderRadius: 'var(--radius)',
                      border: `1px solid ${m.enabled ? 'rgba(0,229,195,0.2)' : 'var(--border)'}`,
                      background: m.enabled ? 'rgba(0,229,195,0.04)' : 'transparent',
                      cursor: 'pointer', textAlign: 'left',
                      transition: 'all 0.15s',
                    }}
                    onMouseEnter={e => { if (!m.enabled) e.currentTarget.style.borderColor = 'var(--border-s)'; }}
                    onMouseLeave={e => { if (!m.enabled) e.currentTarget.style.borderColor = 'var(--border)'; }}
                  >
                    {/* Checkbox */}
                    <div style={{
                      width: 16, height: 16, borderRadius: 3, flexShrink: 0,
                      border: `2px solid ${m.enabled ? 'var(--ac)' : 'var(--t3)'}`,
                      background: m.enabled ? 'var(--ac)' : 'transparent',
                      display: 'flex', alignItems: 'center', justifyContent: 'center',
                      transition: 'all 0.15s',
                    }}>
                      {m.enabled && (
                        <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="var(--bg-0)" strokeWidth="3">
                          <path d="M5 12l5 5L20 7"/>
                        </svg>
                      )}
                    </div>
                    <span style={{
                      fontSize: 12, color: m.enabled ? 'var(--t1)' : 'var(--t3)',
                      overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                    }}>{m.name}</span>
                  </button>
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Launch button */}
      <button onClick={launch} disabled={!project} className="hm-btn hm-btn-primary"
        style={{
          padding: '16px 24px', fontSize: 14, fontWeight: 700,
          letterSpacing: '0.1em', width: '100%',
          marginTop: 4,
        }}>
        START SCAN
      </button>
    </div>
  );
}
