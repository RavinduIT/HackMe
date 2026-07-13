import { useState } from 'react';

type Enc = 'base64' | 'url' | 'html' | 'hex' | 'unicode' | 'jwt';

export default function Decoder() {
  const [input, setInput] = useState('');
  const [output, setOutput] = useState('');
  const [mode, setMode] = useState<'encode' | 'decode'>('decode');
  const [enc, setEnc] = useState<Enc>('base64');

  function run() {
    try {
      if (enc === 'jwt') {
        const p = input.split('.');
        if (p.length < 2) { setOutput('Invalid JWT'); return; }
        const h = JSON.parse(atob(p[0].replace(/-/g, '+').replace(/_/g, '/')));
        const b = JSON.parse(atob(p[1].replace(/-/g, '+').replace(/_/g, '/')));
        setOutput(JSON.stringify({ header: h, payload: b }, null, 2));
        return;
      }
      if (mode === 'encode') {
        switch (enc) {
          case 'base64': setOutput(btoa(input)); break;
          case 'url': setOutput(encodeURIComponent(input)); break;
          case 'html': setOutput(input.replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c] || c)); break;
          case 'hex': setOutput(Array.from(new TextEncoder().encode(input)).map(b => b.toString(16).padStart(2, '0')).join(' ')); break;
          case 'unicode': setOutput(Array.from(input).map(c => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`).join('')); break;
        }
      } else {
        switch (enc) {
          case 'base64': setOutput(atob(input)); break;
          case 'url': setOutput(decodeURIComponent(input)); break;
          case 'html': setOutput(input.replace(/&amp;|&lt;|&gt;|&quot;|&#39;/g, e => ({ '&amp;': '&', '&lt;': '<', '&gt;': '>', '&quot;': '"', '&#39;': "'" })[e] || e)); break;
          case 'hex': setOutput(new TextDecoder().decode(new Uint8Array(input.trim().split(/\s+/).map(h => parseInt(h, 16))))); break;
          case 'unicode': setOutput(input.replace(/\\u([0-9a-fA-F]{4})/g, (_, h) => String.fromCharCode(parseInt(h, 16)))); break;
        }
      }
    } catch (e: any) { setOutput(`Error: ${e.message}`); }
  }

  const encodings: { key: Enc; label: string }[] = [
    { key: 'base64', label: 'Base64' },
    { key: 'url', label: 'URL' },
    { key: 'html', label: 'HTML' },
    { key: 'hex', label: 'Hex' },
    { key: 'unicode', label: 'Unicode' },
    { key: 'jwt', label: 'JWT' },
  ];

  return (
    <div style={{ maxWidth: 780, display: 'flex', flexDirection: 'column', gap: 24 }}>
      {/* Header */}
      <div>
        <h1 className="pg-title">Decoder</h1>
        <p className="pg-sub">Encode, decode, and transform data</p>
      </div>

      {/* Controls bar */}
      <div style={{
        display: 'flex', alignItems: 'center', gap: 16,
        padding: '12px 16px',
        background: 'var(--bg-1)', borderRadius: 'var(--radius-lg)',
        border: '1px solid var(--border)',
      }}>
        {/* Encoding type pills */}
        <div style={{ display: 'flex', gap: 4, flex: 1 }}>
          {encodings.map(e => {
            const active = enc === e.key;
            return (
              <button key={e.key} onClick={() => setEnc(e.key)}
                style={{
                  padding: '7px 14px', border: 'none', cursor: 'pointer',
                  borderRadius: 'var(--radius)',
                  fontSize: 11, fontWeight: active ? 600 : 400,
                  letterSpacing: '0.03em',
                  background: active ? 'var(--ac-lo)' : 'transparent',
                  color: active ? 'var(--ac)' : 'var(--t3)',
                  transition: 'all 0.15s',
                }}
                onMouseEnter={e => { if (!active) (e.currentTarget as HTMLElement).style.background = 'var(--bg-2)'; }}
                onMouseLeave={e => { if (!active) (e.currentTarget as HTMLElement).style.background = 'transparent'; }}
              >{e.label}</button>
            );
          })}
        </div>

        {/* Encode/Decode toggle */}
        {enc !== 'jwt' && (
          <div style={{
            display: 'flex', borderRadius: 'var(--radius)', overflow: 'hidden',
            border: '1px solid var(--border)',
          }}>
            {(['encode', 'decode'] as const).map(m => (
              <button key={m} onClick={() => setMode(m)}
                style={{
                  padding: '6px 16px', border: 'none', cursor: 'pointer',
                  fontSize: 11, fontWeight: 600, textTransform: 'uppercase',
                  letterSpacing: '0.06em',
                  background: mode === m ? 'var(--ac-lo)' : 'var(--bg-0)',
                  color: mode === m ? 'var(--ac)' : 'var(--t3)',
                  transition: 'all 0.15s',
                }}>{m}</button>
            ))}
          </div>
        )}
      </div>

      {/* Input / Output stacked with transform button between */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 0 }}>
        {/* Input area */}
        <div style={{
          borderRadius: 'var(--radius-lg) var(--radius-lg) 0 0',
          border: '1px solid var(--border)',
          borderBottom: 'none',
          overflow: 'hidden',
        }}>
          <div style={{
            padding: '10px 18px',
            background: 'var(--bg-1)',
            borderBottom: '1px solid var(--border)',
            display: 'flex', alignItems: 'center', gap: 8,
          }}>
            <span style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.1em', color: 'var(--t3)' }}>
              Input
            </span>
          </div>
          <textarea
            value={input}
            onChange={e => setInput(e.target.value)}
            placeholder="Paste data here..."
            className="raw-viewer"
            spellCheck={false}
            style={{
              width: '100%', height: 160, resize: 'none',
              border: 'none', outline: 'none',
              padding: '14px 18px', fontSize: 13, lineHeight: 1.7,
              boxSizing: 'border-box',
            }}
            onKeyDown={e => { if (e.key === 'Enter' && e.ctrlKey) run(); }}
          />
        </div>

        {/* Transform button */}
        <div style={{
          display: 'flex', alignItems: 'center',
          border: '1px solid var(--border)',
          borderTop: 'none', borderBottom: 'none',
          background: 'var(--bg-1)',
        }}>
          <button onClick={run} className="hm-btn hm-btn-primary"
            style={{
              width: '100%', padding: '12px 24px',
              fontSize: 13, fontWeight: 700, letterSpacing: '0.08em',
              borderRadius: 0,
            }}>
            {enc === 'jwt' ? 'DECODE JWT' : mode === 'encode' ? 'ENCODE' : 'DECODE'}
          </button>
        </div>

        {/* Output area */}
        <div style={{
          borderRadius: '0 0 var(--radius-lg) var(--radius-lg)',
          border: '1px solid var(--border)',
          borderTop: 'none',
          overflow: 'hidden',
        }}>
          <div style={{
            padding: '10px 18px',
            background: 'var(--bg-1)',
            borderBottom: '1px solid var(--border)',
            display: 'flex', alignItems: 'center', gap: 8,
          }}>
            <span style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.1em', color: 'var(--t3)' }}>
              Output
            </span>
            {output && (
              <button onClick={() => navigator.clipboard.writeText(output)} style={{
                marginLeft: 'auto', background: 'none', border: 'none',
                fontSize: 10, color: 'var(--t3)', cursor: 'pointer',
                transition: 'color 0.15s',
              }}
                onMouseEnter={e => e.currentTarget.style.color = 'var(--ac)'}
                onMouseLeave={e => e.currentTarget.style.color = 'var(--t3)'}
              >
                Copy
              </button>
            )}
          </div>
          <pre className="raw-viewer" style={{
            width: '100%', height: 160, overflow: 'auto',
            margin: 0, padding: '14px 18px', fontSize: 13, lineHeight: 1.7,
            color: output.startsWith('Error:') ? 'var(--crit)' : 'var(--ac)',
            boxSizing: 'border-box',
          }}>
            {output || 'Result will appear here'}
          </pre>
        </div>
      </div>

      {/* Keyboard hint */}
      <div style={{ fontSize: 11, color: 'var(--t3)', textAlign: 'center' }}>
        Press <span className="font-mono" style={{ color: 'var(--t2)', background: 'var(--bg-2)', padding: '2px 6px', borderRadius: 3 }}>Ctrl+Enter</span> to transform
      </div>
    </div>
  );
}
