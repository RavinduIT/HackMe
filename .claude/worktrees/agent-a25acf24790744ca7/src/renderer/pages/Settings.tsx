import { useState, useEffect } from 'react';
import { THEMES, applyTheme, getThemeById } from '../themes';

interface ProxySettings { enabled: boolean; host: string; port: number; username: string; password: string }

export default function Settings() {
  const [theme, setTheme] = useState('obsidian');
  const [proxy, setProxy] = useState<ProxySettings>({ enabled: false, host: '', port: 0, username: '', password: '' });
  const [paste, setPaste] = useState('');
  const [toast, setToast] = useState('');
  const [apiKey, setApiKey] = useState('');
  const [proxyCount, setProxyCount] = useState(0);
  const [exported, setExported] = useState(false);

  useEffect(() => {
    (async () => {
      try {
        const p = await window.hackme.getSetting('upstream_proxy');
        if (p) setProxy(p);
        const k = await window.hackme.getSetting('gemini_api_key');
        if (k) setApiKey(k);
        const t = await window.hackme.getSetting('ui_theme');
        if (t) setTheme(t);
        const pl = await window.hackme.getSetting('proxy_list');
        if (pl && Array.isArray(pl)) setProxyCount(pl.length);
      } catch {}
    })();
  }, []);

  function flash(msg: string) { setToast(msg); setTimeout(() => setToast(''), 3000); }

  function pickTheme(id: string) {
    setTheme(id);
    applyTheme(getThemeById(id));
    window.hackme.setSetting('ui_theme', id);
    flash('Theme applied');
  }

  function parsePaste() {
    const p = paste.trim().split(':');
    if (p.length === 4) {
      setProxy({ enabled: true, host: p[0], port: parseInt(p[1]) || 8080, username: p[2], password: p[3] });
      setPaste(''); flash('Parsed. Hit Save.');
    } else if (p.length === 2) {
      setProxy({ enabled: true, host: p[0], port: parseInt(p[1]) || 8080, username: '', password: '' });
      setPaste(''); flash('Parsed (no auth).');
    } else flash('Format: host:port:user:pass');
  }

  async function uploadProxies() {
    const input = document.createElement('input');
    input.type = 'file'; input.accept = '.txt,.csv';
    input.onchange = async () => {
      const file = input.files?.[0]; if (!file) return;
      const text = await file.text();
      const lines = text.split('\n').map(l => l.trim()).filter(l => l && !l.startsWith('#'));
      const list = lines.map(l => {
        const p = l.split(':');
        if (p.length === 4) return { host: p[0], port: parseInt(p[1]), username: p[2], password: p[3] };
        if (p.length === 2) return { host: p[0], port: parseInt(p[1]), username: '', password: '' };
        return null;
      }).filter(Boolean);
      await window.hackme.setSetting('proxy_list', list);
      setProxyCount(list.length);
      flash(`${list.length} proxies loaded from ${file.name}`);
    };
    input.click();
  }

  const S: React.CSSProperties = { fontSize: 'var(--label-size)', fontWeight: 'var(--label-weight)' as any, letterSpacing: 'var(--label-spacing)', textTransform: 'uppercase', color: 'var(--t3)', marginBottom: 6 };

  return (
    <div style={{ maxWidth: 660 }}>
      <div style={{ marginBottom: 28 }}>
        <div style={{ fontSize: 'var(--head-size)', fontWeight: 'var(--head-weight)' as any, color: 'var(--t1)' }}>Settings</div>
        <div style={{ fontSize: 'var(--body-size)', color: 'var(--t3)', marginTop: 4 }}>Appearance, proxies, AI configuration, and certificates</div>
      </div>

      {/* ─── THEME ─── */}
      <Section title="Appearance">
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 10 }}>
          {THEMES.map(t => (
            <div key={t.id} onClick={() => pickTheme(t.id)} style={{
              padding: 14, borderRadius: 'var(--radius-lg)', cursor: 'pointer', transition: 'all .15s',
              border: theme === t.id ? '2px solid var(--ac)' : '1px solid var(--border)',
              background: theme === t.id ? 'var(--ac-lo)' : 'var(--bg-2)',
            }}>
              <div style={{ display: 'flex', gap: 4, marginBottom: 10 }}>
                {[t.vars['--bg-0'], t.vars['--bg-3'], t.vars['--ac'], t.vars['--crit']].map((c, i) => (
                  <div key={i} style={{ width: 18, height: 18, borderRadius: 3, background: c }} />
                ))}
              </div>
              <div style={{ fontSize: 12, fontWeight: 600, color: theme === t.id ? 'var(--ac)' : 'var(--t1)' }}>{t.name}</div>
              <div style={{ fontSize: 10, color: 'var(--t3)', marginTop: 2 }}>{t.description}</div>
            </div>
          ))}
        </div>
      </Section>

      {/* ─── PROXY LIST ─── */}
      <Section title="Proxy Rotation">
        <div style={{ fontSize: 12, color: 'var(--t3)', marginBottom: 12, lineHeight: 1.6 }}>
          Upload a text file with one proxy per line. Format: <span style={{ fontFamily: 'var(--font-code)', color: 'var(--ac)' }}>host:port:username:password</span>
        </div>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <button onClick={uploadProxies} className="hm-btn hm-btn-accent-ghost">Upload Proxy List</button>
          {proxyCount > 0 && <span style={{ fontSize: 11, fontFamily: 'var(--font-code)', color: 'var(--ac)' }}>{proxyCount} proxies loaded</span>}
          {proxyCount > 0 && <button onClick={async () => { await window.hackme.setSetting('proxy_list', []); setProxyCount(0); flash('Cleared'); }} className="hm-btn hm-btn-ghost" style={{ marginLeft: 'auto', fontSize: 10, padding: '4px 10px' }}>Clear</button>}
        </div>
      </Section>

      {/* ─── SINGLE PROXY ─── */}
      <Section title="Single Proxy">
        <div style={S}>Quick paste</div>
        <div style={{ display: 'flex', gap: 8, marginBottom: 14 }}>
          <input className="hm-input hm-input-mono" style={{ flex: 1 }} placeholder="host:port:user:pass" value={paste} onChange={e => setPaste(e.target.value)} onKeyDown={e => e.key === 'Enter' && parsePaste()} />
          <button onClick={parsePaste} className="hm-btn hm-btn-ghost">Parse</button>
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, marginBottom: 14 }}>
          <div><div style={S}>Host</div><input className="hm-input hm-input-mono" style={{ width: '100%' }} value={proxy.host} onChange={e => setProxy({ ...proxy, host: e.target.value })} /></div>
          <div><div style={S}>Port</div><input className="hm-input hm-input-mono" style={{ width: '100%' }} type="number" value={proxy.port || ''} onChange={e => setProxy({ ...proxy, port: parseInt(e.target.value) || 0 })} /></div>
          <div><div style={S}>Username</div><input className="hm-input hm-input-mono" style={{ width: '100%' }} value={proxy.username} onChange={e => setProxy({ ...proxy, username: e.target.value })} /></div>
          <div><div style={S}>Password</div><input className="hm-input hm-input-mono" style={{ width: '100%' }} type="password" value={proxy.password} onChange={e => setProxy({ ...proxy, password: e.target.value })} /></div>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12 }}>
          <div onClick={() => setProxy({ ...proxy, enabled: !proxy.enabled })} style={{ width: 36, height: 20, borderRadius: 10, background: proxy.enabled ? 'var(--ac)' : 'var(--bg-4)', cursor: 'pointer', position: 'relative', transition: 'background .15s' }}>
            <div style={{ width: 16, height: 16, borderRadius: '50%', background: '#fff', position: 'absolute', top: 2, left: proxy.enabled ? 18 : 2, transition: 'left .15s' }} />
          </div>
          <span style={{ fontSize: 12, color: 'var(--t2)' }}>{proxy.enabled ? 'Enabled' : 'Disabled'}</span>
        </div>
        <button onClick={async () => { await window.hackme.setSetting('upstream_proxy', proxy); flash('Proxy saved'); }} className="hm-btn hm-btn-primary">Save Proxy</button>
      </Section>

      {/* ─── AI ─── */}
      <Section title="AI Analysis (Gemini)">
        <div style={{ fontSize: 12, color: 'var(--t3)', marginBottom: 10, lineHeight: 1.6 }}>
          Gemini 2.0 Flash analyzes responses, JS bundles, cookies, and correlates findings. Free tier — no cost.
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <input className="hm-input hm-input-mono" style={{ flex: 1 }} type="password" placeholder="Gemini API key" value={apiKey} onChange={e => setApiKey(e.target.value)} />
          <button onClick={async () => { await window.hackme.setSetting('gemini_api_key', apiKey); flash('API key saved'); }} className="hm-btn hm-btn-primary">Save</button>
        </div>
      </Section>

      {/* ─── CERT ─── */}
      <Section title="CA Certificate">
        <div style={{ fontSize: 12, color: 'var(--t3)', marginBottom: 10, lineHeight: 1.6 }}>
          Export the CA cert for HTTPS interception. Import it into your browser as a trusted root CA.
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <button onClick={async () => {
            const path = await window.hackme.showSaveDialog({ title: 'Export CA', defaultPath: 'hackme-ca.pem', filters: [{ name: 'PEM', extensions: ['pem'] }] });
            if (path) { await window.hackme.proxyExportCA(path); setExported(true); flash('Certificate exported'); }
          }} className="hm-btn hm-btn-accent-ghost">Export Certificate</button>
          {exported && <span style={{ fontSize: 11, fontFamily: 'var(--font-code)', color: 'var(--ac)' }}>Exported</span>}
        </div>
      </Section>

      {/* ─── DATA MANAGEMENT ─── */}
      <Section title="Data Management">
        <div style={{ fontSize: 12, color: 'var(--t3)', marginBottom: 14, lineHeight: 1.6 }}>
          Clear old scan data, findings, and proxy history to free up space and start fresh.
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '10px 14px', background: 'var(--bg-0)', borderRadius: 'var(--radius)', border: '1px solid var(--border)' }}>
            <div>
              <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--t1)' }}>Clear Proxy History</div>
              <div style={{ fontSize: 11, color: 'var(--t3)' }}>Remove all captured HTTP traffic</div>
            </div>
            <button onClick={async () => { await window.hackme.clearProxyHistory(); flash('Proxy history cleared'); }} className="hm-btn hm-btn-ghost" style={{ fontSize: 11, padding: '5px 14px' }}>Clear</button>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '10px 14px', background: 'var(--bg-0)', borderRadius: 'var(--radius)', border: '1px solid var(--border)' }}>
            <div>
              <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--t1)' }}>Clear Scan Findings</div>
              <div style={{ fontSize: 11, color: 'var(--t3)' }}>Remove all vulnerability findings</div>
            </div>
            <button onClick={async () => { await window.hackme.clearFindings(); flash('Findings cleared'); }} className="hm-btn hm-btn-ghost" style={{ fontSize: 11, padding: '5px 14px' }}>Clear</button>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '10px 14px', background: 'var(--bg-0)', borderRadius: 'var(--radius)', border: '1px solid var(--border)' }}>
            <div>
              <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--t1)' }}>Clear All Scans</div>
              <div style={{ fontSize: 11, color: 'var(--t3)' }}>Remove all scans, findings, and endpoints</div>
            </div>
            <button onClick={async () => { await window.hackme.clearScans(); flash('All scans cleared'); }} className="hm-btn hm-btn-ghost" style={{ fontSize: 11, padding: '5px 14px' }}>Clear</button>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '10px 14px', background: 'rgba(255,92,92,0.03)', borderRadius: 'var(--radius)', border: '1px solid rgba(255,92,92,0.12)' }}>
            <div>
              <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--crit)' }}>Reset Everything</div>
              <div style={{ fontSize: 11, color: 'var(--t3)' }}>Delete all projects, scans, findings, and proxy data</div>
            </div>
            <button onClick={async () => { if (confirm('This will delete ALL data. Are you sure?')) { await window.hackme.clearAllData(); flash('All data cleared'); } }} className="hm-btn hm-btn-danger" style={{ fontSize: 11, padding: '5px 14px' }}>Reset All</button>
          </div>
        </div>
      </Section>

      {/* ─── ABOUT ─── */}
      <Section title="About">
        <div style={{ fontFamily: 'var(--font-code)', fontSize: 12, color: 'var(--t3)', lineHeight: 1.8 }}>
          <span style={{ color: 'var(--ac)', fontWeight: 700 }}>HackMe</span> v1.0.0<br />
          Web Application Security Scanner<br />
          29 Modules · AI Analysis · Intercepting Proxy<br />
          <span style={{ color: 'var(--t2)' }}>Built by RavinduIT</span>
        </div>
      </Section>

      {/* Toast */}
      {toast && (
        <div style={{ position: 'fixed', bottom: 24, right: 24, padding: '10px 20px', borderRadius: 'var(--radius-lg)', background: 'var(--ac)', color: 'var(--bg-0)', fontSize: 12, fontWeight: 600, zIndex: 999, boxShadow: '0 4px 20px rgba(0,0,0,.4)' }}>
          {toast}
        </div>
      )}
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div style={{ marginBottom: 28, padding: '20px 24px', background: 'var(--bg-1)', borderRadius: 'var(--radius-lg)', border: '1px solid var(--border)' }}>
      <div style={{ fontSize: 14, fontWeight: 700, color: 'var(--t1)', marginBottom: 16 }}>{title}</div>
      {children}
    </div>
  );
}
