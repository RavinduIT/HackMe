import { useState } from 'react';

export default function Repeater() {
  const [method, setMethod] = useState('GET');
  const [url, setUrl] = useState('');
  const [hdrs, setHdrs] = useState('User-Agent: HackMe/1.0\nAccept: */*');
  const [body, setBody] = useState('');
  const [res, setRes] = useState<any | null>(null);
  const [loading, setLoading] = useState(false);

  async function send() {
    if (!url.trim()) return;
    setLoading(true); setRes(null);
    const headers: Record<string, string> = {};
    hdrs.split('\n').forEach(l => { const i = l.indexOf(':'); if (i > 0) headers[l.slice(0, i).trim()] = l.slice(i + 1).trim(); });
    setRes(await window.hackme.sendRequest(method, url.trim(), headers, body || null));
    setLoading(false);
  }

  const methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'];
  const methodColors: Record<string, string> = {
    GET: '#22d3ee', POST: '#a78bfa', PUT: '#fbbf24', DELETE: '#f87171',
    PATCH: '#fb923c', HEAD: '#94a3b8', OPTIONS: '#94a3b8',
  };

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column', gap: 16 }}>
      {/* Header */}
      <div>
        <h1 className="pg-title">Repeater</h1>
        <p className="pg-sub">Manually craft and send HTTP requests</p>
      </div>

      {/* URL bar -- Postman-style */}
      <div style={{
        display: 'flex', alignItems: 'stretch', gap: 0,
        borderRadius: 'var(--radius-lg)', overflow: 'hidden',
        border: '2px solid var(--border)',
        transition: 'border-color 0.15s',
      }}>
        {/* Method dropdown */}
        <select value={method} onChange={e => setMethod(e.target.value)}
          className="hm-input"
          style={{
            width: 120, border: 'none', borderRight: '1px solid var(--border)',
            borderRadius: 0, fontSize: 13, fontWeight: 700,
            fontFamily: 'var(--font-code)',
            color: methodColors[method] || 'var(--t2)',
            background: 'var(--bg-1)',
            textAlign: 'center',
          }}>
          {methods.map(m => <option key={m}>{m}</option>)}
        </select>

        {/* URL input */}
        <input
          className="hm-input hm-input-mono"
          style={{
            flex: 1, border: 'none', borderRadius: 0,
            fontSize: 13, padding: '12px 16px',
            background: 'var(--bg-0)',
          }}
          placeholder="https://target.com/api/endpoint"
          value={url}
          onChange={e => setUrl(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && send()}
        />

        {/* Send button */}
        <button onClick={send} disabled={loading || !url.trim()}
          className="hm-btn hm-btn-primary"
          style={{
            borderRadius: 0, minWidth: 100,
            fontSize: 13, fontWeight: 700, letterSpacing: '0.05em',
          }}>
          {loading ? 'Sending...' : 'Send'}
        </button>
      </div>

      {/* Request + Response side by side */}
      <div style={{ flex: 1, display: 'flex', gap: 12, minHeight: 0 }}>

        {/* Request pane */}
        <div style={{
          flex: 1, display: 'flex', flexDirection: 'column',
          border: '1px solid var(--border)',
          borderRadius: 'var(--radius-lg)', overflow: 'hidden',
          background: 'var(--bg-0)',
        }}>
          {/* Request section label */}
          <div style={{
            padding: '10px 18px',
            background: 'var(--bg-1)',
            borderBottom: '1px solid var(--border)',
            display: 'flex', alignItems: 'center', gap: 8,
          }}>
            <div style={{ width: 6, height: 6, borderRadius: '50%', background: '#a78bfa' }} />
            <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--t2)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>
              Request
            </span>
          </div>

          {/* Headers label */}
          <div style={{
            padding: '8px 18px 4px',
            fontSize: 10, fontWeight: 600, textTransform: 'uppercase',
            letterSpacing: '0.1em', color: 'var(--t3)',
          }}>Headers</div>

          <textarea
            value={hdrs}
            onChange={e => setHdrs(e.target.value)}
            placeholder="Header: Value"
            className="raw-viewer"
            spellCheck={false}
            style={{
              flex: 1, resize: 'none', border: 'none', outline: 'none',
              padding: '8px 18px', fontSize: 12, lineHeight: 1.7,
              borderBottom: '1px solid var(--border)',
              minHeight: 80,
            }}
          />

          {/* Body label */}
          <div style={{
            padding: '8px 18px 4px',
            fontSize: 10, fontWeight: 600, textTransform: 'uppercase',
            letterSpacing: '0.1em', color: 'var(--t3)',
          }}>Body</div>

          <textarea
            value={body}
            onChange={e => setBody(e.target.value)}
            placeholder="Request body (optional)"
            className="raw-viewer"
            spellCheck={false}
            style={{
              height: 100, resize: 'none', border: 'none', outline: 'none',
              padding: '8px 18px', fontSize: 12, lineHeight: 1.7,
            }}
          />
        </div>

        {/* Response pane */}
        <div style={{
          flex: 1, display: 'flex', flexDirection: 'column',
          border: '1px solid var(--border)',
          borderRadius: 'var(--radius-lg)', overflow: 'hidden',
          background: 'var(--bg-0)',
        }}>
          {/* Response header */}
          <div style={{
            padding: '10px 18px',
            background: 'var(--bg-1)',
            borderBottom: '1px solid var(--border)',
            display: 'flex', alignItems: 'center', justifyContent: 'space-between',
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <div style={{ width: 6, height: 6, borderRadius: '50%', background: res && !res.error ? 'var(--ac)' : 'var(--t3)' }} />
              <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--t2)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>
                Response
              </span>
            </div>
            {res && !res.error && (
              <div style={{ display: 'flex', gap: 16 }}>
                <span className="font-mono" style={{
                  fontSize: 12, fontWeight: 700,
                  color: res.status < 300 ? 'var(--ac)' : res.status < 400 ? '#60a5fa' : 'var(--crit)',
                }}>{res.status}</span>
                <span className="font-mono" style={{ fontSize: 11, color: 'var(--t3)' }}>{res.duration}ms</span>
                <span className="font-mono" style={{ fontSize: 11, color: 'var(--t3)' }}>{(res.size / 1024).toFixed(1)}KB</span>
              </div>
            )}
          </div>

          {/* Response body */}
          <div style={{ flex: 1, overflow: 'auto' }}>
            {res ? (
              res.error ? (
                <div style={{ padding: '24px 18px', fontSize: 13, color: 'var(--crit)' }} className="font-mono">
                  {res.error}
                </div>
              ) : (
                <div className="raw-viewer" style={{ padding: 18, fontSize: 12, lineHeight: 1.8 }}>
                  {Object.entries(res.headers || {}).map(([k, v]) => (
                    <div key={k}>
                      <span style={{ color: 'var(--ac)', opacity: 0.7 }}>{k}</span>
                      <span style={{ color: 'var(--t3)' }}>: </span>
                      <span style={{ color: 'var(--t2)' }}>{String(v)}</span>
                    </div>
                  ))}
                  <div style={{ borderTop: '1px dashed var(--border)', margin: '12px 0' }} />
                  <div style={{ color: 'var(--t1)', whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>{res.body}</div>
                </div>
              )
            ) : (
              <div style={{
                height: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center',
                flexDirection: 'column', gap: 12,
              }}>
                <div style={{ fontSize: 28, opacity: 0.12 }}>HTTP</div>
                <div style={{ fontSize: 13, color: 'var(--t3)' }}>Send a request to see the response</div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
