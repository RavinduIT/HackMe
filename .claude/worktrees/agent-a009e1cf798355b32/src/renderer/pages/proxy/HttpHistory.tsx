import { useState, useEffect } from 'react';

export default function HttpHistory() {
  const [history, setHistory] = useState<any[]>([]);
  const [selected, setSelected] = useState<any | null>(null);
  const [tab, setTab] = useState<'request' | 'response'>('request');

  useEffect(() => { load(); const unsub = window.hackme.onProxyRequest(() => load()); return unsub; }, []);
  async function load() { setHistory(await window.hackme.proxyGetHistory(500, 0) || []); }
  async function clear() { await window.hackme.proxyClearHistory(); setHistory([]); setSelected(null); }

  const colWidths = { id: 50, method: 60, url: 'minmax(200px, 1fr)', status: 56, size: 72, time: 64 };
  const gridTemplate = `${colWidths.id}px ${colWidths.method}px ${colWidths.url} ${colWidths.status}px ${colWidths.size}px ${colWidths.time}px`;

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column', gap: 20 }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'flex-end', justifyContent: 'space-between' }}>
        <div>
          <h1 className="pg-title">HTTP History</h1>
          <p className="pg-sub">{history.length} requests captured</p>
        </div>
        <button onClick={clear} className="hm-btn hm-btn-danger" style={{ fontSize: 11 }}>
          Clear History
        </button>
      </div>

      {/* Data grid + detail */}
      <div style={{ flex: 1, display: 'flex', gap: 0, minHeight: 0 }}>

        {/* Table */}
        <div style={{
          flex: 1, display: 'flex', flexDirection: 'column', minWidth: 0,
          border: '1px solid var(--border)',
          borderRadius: selected ? 'var(--radius-lg) 0 0 var(--radius-lg)' : 'var(--radius-lg)',
          overflow: 'hidden', background: 'var(--bg-0)',
        }}>
          {/* Column headers */}
          <div style={{
            display: 'grid', gridTemplateColumns: gridTemplate,
            padding: '0 16px', height: 36, alignItems: 'center',
            background: 'var(--bg-2)',
            borderBottom: '2px solid var(--border)',
          }}>
            {['#', 'Method', 'URL', 'Status', 'Size', 'Time'].map(col => (
              <span key={col} style={{
                fontSize: 10, fontWeight: 600, color: 'var(--t3)',
                textTransform: 'uppercase', letterSpacing: '0.1em',
              }}>{col}</span>
            ))}
          </div>

          {/* Rows */}
          <div style={{ flex: 1, overflowY: 'auto' }} className="striped-rows">
            {history.length === 0 ? (
              <div style={{ padding: '60px 20px', textAlign: 'center', color: 'var(--t3)', fontSize: 13 }}>
                No requests captured yet. Start the proxy to begin.
              </div>
            ) : history.map((e, idx) => (
              <div key={e.id} onClick={() => setSelected(e)}
                style={{
                  display: 'grid', gridTemplateColumns: gridTemplate,
                  padding: '0 16px', height: 34, alignItems: 'center',
                  cursor: 'pointer', transition: 'background 0.12s',
                  background: selected?.id === e.id ? 'var(--ac-lo)' : 'transparent',
                  borderLeft: selected?.id === e.id ? '3px solid var(--ac)' : '3px solid transparent',
                }}
                onMouseEnter={ev => { if (selected?.id !== e.id) ev.currentTarget.style.background = 'var(--bg-1)'; }}
                onMouseLeave={ev => { if (selected?.id !== e.id) ev.currentTarget.style.background = 'transparent'; }}
              >
                <span className="font-mono" style={{ fontSize: 10, color: 'var(--t3)' }}>{e.id}</span>
                <span className="font-mono" style={{
                  fontSize: 10, fontWeight: 700,
                  color: methodColor(e.method),
                }}>{e.method}</span>
                <span className="font-mono" style={{
                  fontSize: 11, color: 'var(--t2)',
                  overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                }}>{e.url}</span>
                <span className="font-mono" style={{
                  fontSize: 11, fontWeight: 600,
                  color: sc(e.response_status),
                }}>{e.response_status || '--'}</span>
                <span className="font-mono" style={{ fontSize: 10, color: 'var(--t3)' }}>
                  {e.response_length ? `${(e.response_length / 1024).toFixed(1)}k` : '--'}
                </span>
                <span className="font-mono" style={{ fontSize: 10, color: 'var(--t3)' }}>
                  {e.duration_ms ? `${e.duration_ms}ms` : '--'}
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* Detail sidebar */}
        {selected && (
          <div style={{
            width: 460, display: 'flex', flexDirection: 'column',
            border: '1px solid var(--border)', borderLeft: 'none',
            borderRadius: '0 var(--radius-lg) var(--radius-lg) 0',
            background: 'var(--bg-0)', overflow: 'hidden',
          }}>
            {/* Detail header with close */}
            <div style={{
              padding: '12px 18px', borderBottom: '1px solid var(--border)',
              display: 'flex', alignItems: 'center', justifyContent: 'space-between',
              background: 'var(--bg-1)',
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <span className="font-mono" style={{ fontSize: 10, fontWeight: 700, color: methodColor(selected.method) }}>
                  {selected.method}
                </span>
                <span className="font-mono" style={{ fontSize: 11, color: 'var(--t2)' }}>
                  #{selected.id}
                </span>
                {selected.response_status && (
                  <span className="font-mono" style={{ fontSize: 11, fontWeight: 600, color: sc(selected.response_status) }}>
                    {selected.response_status}
                  </span>
                )}
              </div>
              <button onClick={() => setSelected(null)} style={{
                background: 'none', border: 'none', color: 'var(--t3)', fontSize: 18,
                cursor: 'pointer', padding: '0 4px', lineHeight: 1,
              }}
                onMouseEnter={e => e.currentTarget.style.color = 'var(--t1)'}
                onMouseLeave={e => e.currentTarget.style.color = 'var(--t3)'}
              >x</button>
            </div>

            {/* Tabs */}
            <div style={{
              display: 'flex', borderBottom: '1px solid var(--border)',
              background: 'var(--bg-1)',
            }}>
              {(['request', 'response'] as const).map(t => (
                <button key={t} onClick={() => setTab(t)}
                  className={`hm-tab ${tab === t ? 'hm-tab-active' : ''}`}
                  style={{ flex: 1, textAlign: 'center' }}>
                  {t.charAt(0).toUpperCase() + t.slice(1)}
                </button>
              ))}
            </div>

            {/* Content */}
            <div style={{ flex: 1, overflow: 'auto' }}>
              <HttpViewer
                headers={tab === 'request' ? selected.request_headers : selected.response_headers}
                body={tab === 'request' ? selected.request_body : selected.response_body}
                statusLine={tab === 'response' ? `HTTP/1.1 ${selected.response_status}` : undefined}
              />
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

function HttpViewer({ headers, body, statusLine }: { headers: string | null; body: string | null; statusLine?: string }) {
  let parsed: Record<string, string> = {};
  try { parsed = headers ? (typeof headers === 'string' ? JSON.parse(headers) : headers) : {}; } catch {}
  return (
    <div className="raw-viewer" style={{ padding: 18, fontSize: 12, lineHeight: 1.8 }}>
      {statusLine && (
        <div style={{ marginBottom: 8 }}>
          <span style={{
            color: statusLine.includes(' 2') ? 'var(--ac)' : statusLine.includes(' 3') ? '#60a5fa' : statusLine.includes(' 4') ? 'var(--high)' : 'var(--crit)',
            fontWeight: 700,
          }}>{statusLine}</span>
        </div>
      )}
      {Object.entries(parsed).map(([k, v]) => (
        <div key={k}>
          <span style={{ color: 'var(--ac)', opacity: 0.7 }}>{k}</span>
          <span style={{ color: 'var(--t3)' }}>: </span>
          <span style={{ color: 'var(--t2)' }}>{String(v)}</span>
        </div>
      ))}
      {body && (
        <>
          <div style={{ borderTop: '1px dashed var(--border)', margin: '12px 0' }} />
          <div style={{ color: 'var(--t1)', whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>{body}</div>
        </>
      )}
    </div>
  );
}

function sc(s: number | null) {
  if (!s) return 'var(--t3)';
  if (s < 300) return 'var(--ac)';
  if (s < 400) return '#60a5fa';
  if (s < 500) return 'var(--high)';
  return 'var(--crit)';
}

function methodColor(m: string) {
  const c: Record<string, string> = { GET: '#22d3ee', POST: '#a78bfa', PUT: '#fbbf24', DELETE: '#f87171', PATCH: '#fb923c' };
  return c[m] || 'var(--t2)';
}
