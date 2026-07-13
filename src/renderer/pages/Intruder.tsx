import { useState, useEffect } from 'react';

export default function Intruder() {
  const [method, setMethod] = useState('POST');
  const [url, setUrl] = useState('');
  const [hdrs, setHdrs] = useState('Content-Type: application/x-www-form-urlencoded\nUser-Agent: HackMe/1.0');
  const [bodyTpl, setBodyTpl] = useState('');
  const [payloadText, setPayloadText] = useState('');
  const [builtinSets, setBuiltinSets] = useState<Record<string, string[]>>({});
  const [attackType, setAttackType] = useState<'sniper' | 'battering_ram' | 'pitchfork'>('sniper');
  const [rate, setRate] = useState(10);
  const [running, setRunning] = useState(false);
  const [results, setResults] = useState<any[]>([]);
  const [selected, setSelected] = useState<any>(null);
  const [sortCol, setSortCol] = useState<string>('index');
  const [sortAsc, setSortAsc] = useState(true);

  useEffect(() => { window.hackme.intruderGetPayloads().then(setBuiltinSets); }, []);

  useEffect(() => {
    const unsub = window.hackme.onIntruderResult((r: any) => setResults(prev => [...prev, r]));
    return unsub;
  }, []);

  async function start() {
    if (!url.trim()) return;
    setResults([]); setSelected(null); setRunning(true);
    const headers: Record<string, string> = {};
    hdrs.split('\n').forEach(l => { const i = l.indexOf(':'); if (i > 0) headers[l.slice(0, i).trim()] = l.slice(i + 1).trim(); });
    await window.hackme.intruderStart({ method, url: url.trim(), headers, bodyTemplate: bodyTpl, payloads: payloadText.split('\n').filter(l => l.trim()), attackType, rateLimit: rate });
    setRunning(false);
  }

  function stop() { window.hackme.intruderStop(); setRunning(false); }

  function loadBuiltin(name: string) {
    const set = builtinSets[name];
    if (set) setPayloadText(set.join('\n'));
  }

  function sort(col: string) {
    if (sortCol === col) setSortAsc(!sortAsc);
    else { setSortCol(col); setSortAsc(true); }
  }

  const sorted = [...results].sort((a, b) => {
    const v = sortAsc ? 1 : -1;
    if (sortCol === 'payload') return a.payload.localeCompare(b.payload) * v;
    return ((a[sortCol] || 0) - (b[sortCol] || 0)) * v;
  });

  const mc: Record<string, string> = { GET: '#22d3ee', POST: '#a78bfa', PUT: '#fbbf24', DELETE: '#f87171' };

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column', gap: 14 }}>
      <div><h1 className="pg-title">Intruder</h1><p className="pg-sub">Automated payload fuzzing with insertion points</p></div>

      {/* URL bar */}
      <div style={{ display: 'flex', gap: 0, borderRadius: 'var(--radius-lg)', overflow: 'hidden', border: '2px solid var(--border)' }}>
        <select value={method} onChange={e => setMethod(e.target.value)} className="hm-input" style={{ width: 100, border: 'none', borderRight: '1px solid var(--border)', borderRadius: 0, fontSize: 12, fontWeight: 700, fontFamily: 'var(--font-code)', color: mc[method] || 'var(--t2)', background: 'var(--bg-1)', textAlign: 'center' }}>
          {['GET','POST','PUT','DELETE','PATCH'].map(m => <option key={m}>{m}</option>)}
        </select>
        <input className="hm-input hm-input-mono" style={{ flex: 1, border: 'none', borderRadius: 0, fontSize: 13, padding: '10px 14px' }} placeholder="https://target.com/login" value={url} onChange={e => setUrl(e.target.value)} />
        <button onClick={running ? stop : start} className={`hm-btn ${running ? 'hm-btn-danger' : 'hm-btn-primary'}`} style={{ borderRadius: 0, minWidth: 110, fontSize: 12, fontWeight: 700 }}>
          {running ? 'Stop' : 'Start Attack'}
        </button>
      </div>

      {/* Config panels */}
      <div style={{ display: 'flex', gap: 10, minHeight: 0 }}>
        {/* Left: headers + body template */}
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 8 }}>
          <div style={{ fontSize: 9, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.1em', color: 'var(--t3)' }}>Headers</div>
          <textarea className="raw-viewer" spellCheck={false} value={hdrs} onChange={e => setHdrs(e.target.value)} style={{ height: 60, resize: 'none', border: '1px solid var(--border)', borderRadius: 'var(--radius)', padding: '8px 12px', fontSize: 12, lineHeight: 1.6 }} />
          <div style={{ fontSize: 9, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.1em', color: 'var(--t3)' }}>
            Body Template <span style={{ color: 'var(--ac)', fontWeight: 400, textTransform: 'none' }}>— wrap insertion points in § markers</span>
          </div>
          <textarea className="raw-viewer" spellCheck={false} value={bodyTpl} onChange={e => setBodyTpl(e.target.value)} placeholder="username=§admin§&password=§test§" style={{ height: 60, resize: 'none', border: '1px solid var(--border)', borderRadius: 'var(--radius)', padding: '8px 12px', fontSize: 12, lineHeight: 1.6 }} />
        </div>

        {/* Right: payloads + config */}
        <div style={{ width: 280, display: 'flex', flexDirection: 'column', gap: 8 }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <div style={{ fontSize: 9, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.1em', color: 'var(--t3)' }}>Payloads</div>
            <select onChange={e => e.target.value && loadBuiltin(e.target.value)} className="hm-input" style={{ width: 150, fontSize: 10, padding: '3px 6px' }}>
              <option value="">Load preset...</option>
              {Object.keys(builtinSets).map(k => <option key={k} value={k}>{k}</option>)}
            </select>
          </div>
          <textarea className="raw-viewer" spellCheck={false} value={payloadText} onChange={e => setPayloadText(e.target.value)} placeholder="One payload per line" style={{ flex: 1, minHeight: 60, resize: 'none', border: '1px solid var(--border)', borderRadius: 'var(--radius)', padding: '8px 12px', fontSize: 11, lineHeight: 1.5 }} />
          <div style={{ display: 'flex', gap: 4 }}>
            {(['sniper', 'battering_ram', 'pitchfork'] as const).map(t => (
              <button key={t} onClick={() => setAttackType(t)} style={{ flex: 1, padding: '5px 4px', border: 'none', cursor: 'pointer', borderRadius: 'var(--radius)', fontSize: 9, fontWeight: attackType === t ? 600 : 400, textTransform: 'capitalize', background: attackType === t ? 'var(--ac-lo)' : 'var(--bg-2)', color: attackType === t ? 'var(--ac)' : 'var(--t3)' }}>
                {t.replace('_', ' ')}
              </button>
            ))}
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span className="font-mono" style={{ fontSize: 10, color: 'var(--t3)' }}>Rate:</span>
            <input type="range" min="1" max="50" value={rate} onChange={e => setRate(+e.target.value)} style={{ flex: 1, accentColor: 'var(--ac)' }} />
            <span className="font-mono" style={{ fontSize: 11, color: 'var(--ac)', minWidth: 40 }}>{rate}/s</span>
          </div>
        </div>
      </div>

      {/* Results */}
      <div style={{ flex: 1, display: 'flex', gap: 0, minHeight: 0, border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)', overflow: 'hidden' }}>
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', background: 'var(--bg-0)' }}>
          {/* Header row */}
          <div style={{ display: 'grid', gridTemplateColumns: '50px 1fr 70px 80px 70px', padding: '0 14px', height: 32, alignItems: 'center', background: 'var(--bg-2)', borderBottom: '2px solid var(--border)' }}>
            {[['index','#'],['payload','Payload'],['status','Status'],['length','Length'],['duration','Time']].map(([col, label]) => (
              <span key={col} onClick={() => sort(col)} style={{ fontSize: 10, fontWeight: 600, color: sortCol === col ? 'var(--ac)' : 'var(--t3)', textTransform: 'uppercase', letterSpacing: '0.08em', cursor: 'pointer' }}>
                {label} {sortCol === col ? (sortAsc ? '↑' : '↓') : ''}
              </span>
            ))}
          </div>
          <div style={{ flex: 1, overflowY: 'auto' }}>
            {sorted.length === 0 ? (
              <div style={{ padding: '48px 20px', textAlign: 'center', color: 'var(--t3)', fontSize: 12 }}>
                {running ? 'Attack running...' : 'Configure payloads and start an attack'}
              </div>
            ) : sorted.map(r => (
              <div key={r.index} onClick={() => setSelected(r)} style={{ display: 'grid', gridTemplateColumns: '50px 1fr 70px 80px 70px', padding: '0 14px', height: 30, alignItems: 'center', cursor: 'pointer', background: selected?.index === r.index ? 'var(--ac-lo)' : 'transparent', borderBottom: '1px solid var(--border)', transition: 'background 0.1s' }}
                onMouseEnter={e => { if (selected?.index !== r.index) e.currentTarget.style.background = 'var(--bg-1)'; }}
                onMouseLeave={e => { if (selected?.index !== r.index) e.currentTarget.style.background = 'transparent'; }}>
                <span className="font-mono" style={{ fontSize: 10, color: 'var(--t3)' }}>{r.index}</span>
                <span className="font-mono" style={{ fontSize: 11, color: 'var(--t2)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{r.payload}</span>
                <span className="font-mono" style={{ fontSize: 11, fontWeight: 600, color: r.status < 300 ? 'var(--ac)' : r.status < 400 ? '#60a5fa' : r.status < 500 ? 'var(--high)' : 'var(--crit)' }}>{r.status || 'ERR'}</span>
                <span className="font-mono" style={{ fontSize: 10, color: 'var(--t3)' }}>{r.length}B</span>
                <span className="font-mono" style={{ fontSize: 10, color: 'var(--t3)' }}>{r.duration}ms</span>
              </div>
            ))}
          </div>
          <div style={{ padding: '6px 14px', borderTop: '1px solid var(--border)', background: 'var(--bg-1)', display: 'flex', gap: 16 }}>
            <span className="font-mono" style={{ fontSize: 10, color: 'var(--t3)' }}>Results: {results.length}</span>
            {running && <span className="font-mono" style={{ fontSize: 10, color: 'var(--ac)' }}>Running...</span>}
          </div>
        </div>
      </div>
    </div>
  );
}
