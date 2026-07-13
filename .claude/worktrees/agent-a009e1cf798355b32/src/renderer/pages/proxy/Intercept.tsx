import { useState, useEffect } from 'react';

export default function Intercept() {
  const [interceptOn, setInterceptOn] = useState(false);
  const [proxyOn, setProxyOn] = useState(false);
  const [queue, setQueue] = useState<any[]>([]);
  const [active, setActive] = useState<any | null>(null);
  const [raw, setRaw] = useState('');

  useEffect(() => {
    refresh();
    const unsub = window.hackme.onProxyIntercept((data: any) => {
      setQueue(prev => [data, ...prev]);
      setActive(prev => prev || data);
      if (!active) setRaw(formatReq(data));
    });
    return unsub;
  }, []);

  async function refresh() {
    const s = await window.hackme.proxyGetStatus();
    setProxyOn(s.running); setInterceptOn(s.intercept_enabled);
  }

  async function toggleProxy() { proxyOn ? await window.hackme.proxyStop() : await window.hackme.proxyStart(8080); refresh(); }
  async function toggleIntercept() { await window.hackme.proxySetIntercept(!interceptOn); setInterceptOn(!interceptOn); }
  async function forward() { if (!active) return; await window.hackme.proxyForward(active.queue_id); remove(active.queue_id); }
  async function drop() { if (!active) return; await window.hackme.proxyDrop(active.queue_id); remove(active.queue_id); }

  function remove(id: string) {
    const next = queue.filter(r => r.queue_id !== id);
    setQueue(next); setActive(next[0] || null); setRaw(next[0] ? formatReq(next[0]) : '');
  }

  function formatReq(req: any): string {
    if (!req) return '';
    try {
      const u = new URL(req.url);
      let out = `${req.method} ${u.pathname}${u.search} HTTP/1.1\nHost: ${u.host}\n`;
      if (req.headers) Object.entries(req.headers).forEach(([k, v]) => { if (k.toLowerCase() !== 'host') out += `${k}: ${v}\n`; });
      out += '\n';
      if (req.body) out += req.body;
      return out;
    } catch { return ''; }
  }

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column', gap: 20 }}>
      {/* Header row */}
      <div style={{ display: 'flex', alignItems: 'flex-end', justifyContent: 'space-between' }}>
        <div>
          <h1 className="pg-title">Intercept</h1>
          <p className="pg-sub">Capture, inspect, and modify HTTP/S requests in transit</p>
        </div>

        {/* Status beacon */}
        <div style={{
          display: 'flex', alignItems: 'center', gap: 10,
          background: proxyOn ? 'rgba(0,229,195,0.06)' : 'var(--bg-1)',
          border: `1px solid ${proxyOn ? 'rgba(0,229,195,0.2)' : 'var(--border)'}`,
          borderRadius: 'var(--radius)', padding: '8px 16px',
        }}>
          <div className={proxyOn ? 'cx-pulse' : ''} style={{
            width: 8, height: 8, borderRadius: '50%',
            background: proxyOn ? 'var(--ac)' : 'var(--t3)',
          }} />
          <span className="font-mono" style={{ fontSize: 11, color: proxyOn ? 'var(--ac)' : 'var(--t3)', letterSpacing: '0.04em' }}>
            {proxyOn ? 'LISTENING :8080' : 'PROXY STOPPED'}
          </span>
        </div>
      </div>

      {/* Controls strip */}
      <div style={{
        display: 'flex', alignItems: 'center', gap: 8,
        padding: '12px 16px',
        background: 'var(--bg-1)',
        borderRadius: 'var(--radius-lg)',
        border: '1px solid var(--border)',
      }}>
        <button onClick={toggleProxy} className={`hm-btn ${proxyOn ? 'hm-btn-danger' : 'hm-btn-primary'}`}
          style={{ minWidth: 120 }}>
          {proxyOn ? 'Stop Proxy' : 'Start Proxy'}
        </button>

        <div style={{ width: 1, height: 24, background: 'var(--border)', margin: '0 8px' }} />

        <button onClick={toggleIntercept} disabled={!proxyOn}
          className={`hm-btn ${interceptOn ? 'hm-btn-accent-ghost' : 'hm-btn-ghost'}`}>
          {interceptOn ? 'Intercept ON' : 'Intercept OFF'}
        </button>

        <div style={{ flex: 1 }} />

        <button onClick={forward} disabled={!active} className="hm-btn hm-btn-accent-ghost"
          style={{ minWidth: 90 }}>
          Forward
        </button>
        <button onClick={drop} disabled={!active} className="hm-btn hm-btn-danger"
          style={{ minWidth: 70 }}>
          Drop
        </button>
      </div>

      {/* Main workspace: queue + editor side by side */}
      <div style={{ flex: 1, display: 'flex', gap: 2, minHeight: 0, borderRadius: 'var(--radius-lg)', overflow: 'hidden', border: '1px solid var(--border)' }}>

        {/* Queue sidebar */}
        <div style={{
          width: 280, display: 'flex', flexDirection: 'column',
          background: 'var(--bg-1)',
          borderRight: '1px solid var(--border)',
        }}>
          {/* Queue header */}
          <div style={{
            padding: '14px 18px',
            borderBottom: '1px solid var(--border)',
            display: 'flex', alignItems: 'center', justifyContent: 'space-between',
          }}>
            <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--t2)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>
              Queue
            </span>
            <span className="font-mono" style={{
              fontSize: 10, color: 'var(--ac)',
              background: 'var(--ac-lo)', padding: '2px 8px',
              borderRadius: 10,
            }}>
              {queue.length}
            </span>
          </div>

          {/* Queue items */}
          <div style={{ flex: 1, overflowY: 'auto' }}>
            {queue.length === 0 ? (
              <div style={{ padding: '48px 20px', textAlign: 'center' }}>
                <div style={{ fontSize: 28, marginBottom: 12, opacity: 0.15 }}>
                  {interceptOn ? '⏳' : '⚡'}
                </div>
                <div style={{ fontSize: 12, color: 'var(--t3)', lineHeight: 1.6 }}>
                  {interceptOn ? 'Waiting for traffic...' : 'Enable intercept to begin capturing requests'}
                </div>
              </div>
            ) : queue.map((req, idx) => (
              <div key={req.queue_id}
                onClick={() => { setActive(req); setRaw(formatReq(req)); }}
                style={{
                  padding: '12px 18px',
                  cursor: 'pointer',
                  transition: 'background 0.15s',
                  background: active?.queue_id === req.queue_id ? 'var(--ac-lo)' : 'transparent',
                  borderBottom: '1px solid var(--border)',
                  borderLeft: active?.queue_id === req.queue_id ? '3px solid var(--ac)' : '3px solid transparent',
                }}
                onMouseEnter={e => { if (active?.queue_id !== req.queue_id) e.currentTarget.style.background = 'var(--bg-2)'; }}
                onMouseLeave={e => { if (active?.queue_id !== req.queue_id) e.currentTarget.style.background = 'transparent'; }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 4 }}>
                  <span className="font-mono" style={{
                    fontSize: 10, fontWeight: 700,
                    color: methodColor(req.method),
                    background: methodBg(req.method),
                    padding: '2px 6px', borderRadius: 3, letterSpacing: '0.02em',
                  }}>
                    {req.method}
                  </span>
                  <span className="font-mono" style={{ fontSize: 11, color: 'var(--t1)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {safePath(req.url)}
                  </span>
                </div>
                <div className="font-mono" style={{ fontSize: 10, color: 'var(--t3)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {safeHost(req.url)}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Raw editor area */}
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', background: 'var(--bg-0)' }}>
          <div style={{
            padding: '14px 20px',
            borderBottom: '1px solid var(--border)',
            display: 'flex', alignItems: 'center', justifyContent: 'space-between',
          }}>
            <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--t2)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>
              Raw Request
            </span>
            {active && (
              <span className="font-mono" style={{ fontSize: 10, color: 'var(--t3)' }}>
                {active.method} {safeHost(active.url)}{safePath(active.url)}
              </span>
            )}
          </div>

          <textarea
            value={raw}
            onChange={e => setRaw(e.target.value)}
            placeholder={interceptOn ? 'Intercepted request will appear here...' : 'Start the proxy and enable intercept to capture requests...'}
            className="raw-viewer"
            spellCheck={false}
            style={{
              flex: 1, resize: 'none', border: 'none', outline: 'none',
              fontSize: 13, lineHeight: 1.7, padding: 20,
            }}
          />
        </div>
      </div>
    </div>
  );
}

function safePath(url: string) { try { return new URL(url).pathname; } catch { return url; } }
function safeHost(url: string) { try { return new URL(url).host; } catch { return ''; } }
function methodColor(m: string) {
  const c: Record<string, string> = { GET: '#22d3ee', POST: '#a78bfa', PUT: '#fbbf24', DELETE: '#f87171', PATCH: '#fb923c', HEAD: '#94a3b8', OPTIONS: '#94a3b8' };
  return c[m] || 'var(--t2)';
}
function methodBg(m: string) {
  const c: Record<string, string> = { GET: 'rgba(34,211,238,0.1)', POST: 'rgba(167,139,250,0.1)', PUT: 'rgba(251,191,36,0.1)', DELETE: 'rgba(248,113,113,0.1)', PATCH: 'rgba(251,146,60,0.1)', HEAD: 'rgba(148,163,184,0.08)', OPTIONS: 'rgba(148,163,184,0.08)' };
  return c[m] || 'transparent';
}
