import { useState } from 'react';

export default function Comparer() {
  const [left, setLeft] = useState('');
  const [right, setRight] = useState('');
  const [diff, setDiff] = useState<{ type: 'same' | 'add' | 'remove'; line: string }[]>([]);

  function compare() {
    const lLines = left.split('\n');
    const rLines = right.split('\n');
    setDiff(computeDiff(lLines, rLines));
  }

  function computeDiff(a: string[], b: string[]): { type: 'same' | 'add' | 'remove'; line: string }[] {
    const m = a.length, n = b.length;
    const dp: number[][] = Array.from({ length: m + 1 }, () => Array(n + 1).fill(0));
    for (let i = 1; i <= m; i++) for (let j = 1; j <= n; j++) dp[i][j] = a[i-1] === b[j-1] ? dp[i-1][j-1] + 1 : Math.max(dp[i-1][j], dp[i][j-1]);
    const result: { type: 'same' | 'add' | 'remove'; line: string }[] = [];
    let i = m, j = n;
    while (i > 0 || j > 0) {
      if (i > 0 && j > 0 && a[i-1] === b[j-1]) { result.unshift({ type: 'same', line: a[i-1] }); i--; j--; }
      else if (j > 0 && (i === 0 || dp[i][j-1] >= dp[i-1][j])) { result.unshift({ type: 'add', line: b[j-1] }); j--; }
      else { result.unshift({ type: 'remove', line: a[i-1] }); i--; }
    }
    return result;
  }

  const added = diff.filter(d => d.type === 'add').length;
  const removed = diff.filter(d => d.type === 'remove').length;
  const same = diff.filter(d => d.type === 'same').length;

  const colors = { same: 'transparent', add: 'rgba(0,229,195,0.08)', remove: 'rgba(255,92,92,0.08)' };
  const borderColors = { same: 'transparent', add: 'rgba(0,229,195,0.25)', remove: 'rgba(255,92,92,0.25)' };
  const textColors = { same: 'var(--t2)', add: 'var(--ac)', remove: 'var(--crit)' };
  const prefixes = { same: ' ', add: '+', remove: '-' };

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div><h1 className="pg-title">Comparer</h1><p className="pg-sub">Diff two HTTP requests or responses side by side</p></div>

      {/* Two inputs side by side */}
      <div style={{ display: 'flex', gap: 10, minHeight: 0 }}>
        {[{ label: 'Left', val: left, set: setLeft }, { label: 'Right', val: right, set: setRight }].map(({ label, val, set }) => (
          <div key={label} style={{ flex: 1, display: 'flex', flexDirection: 'column', border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)', overflow: 'hidden' }}>
            <div style={{ padding: '8px 14px', background: 'var(--bg-1)', borderBottom: '1px solid var(--border)', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <span style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.1em', color: 'var(--t3)' }}>{label}</span>
              <button onClick={async () => { try { set(await navigator.clipboard.readText()); } catch {} }} className="hm-btn hm-btn-ghost" style={{ fontSize: 9, padding: '2px 8px' }}>Paste</button>
            </div>
            <textarea className="raw-viewer" spellCheck={false} value={val} onChange={e => set(e.target.value)} placeholder="Paste response or request here..." style={{ flex: 1, resize: 'none', border: 'none', outline: 'none', padding: '10px 14px', fontSize: 12, lineHeight: 1.6, minHeight: 120 }} />
          </div>
        ))}
      </div>

      <button onClick={compare} disabled={!left && !right} className="hm-btn hm-btn-primary" style={{ padding: '10px 24px', fontSize: 13, fontWeight: 700, letterSpacing: '0.08em' }}>
        Compare
      </button>

      {/* Diff output */}
      {diff.length > 0 && (
        <>
          <div style={{ display: 'flex', gap: 16, padding: '8px 14px', background: 'var(--bg-1)', borderRadius: 'var(--radius)', border: '1px solid var(--border)' }}>
            <span className="font-mono" style={{ fontSize: 11, color: 'var(--ac)' }}>+{added} added</span>
            <span className="font-mono" style={{ fontSize: 11, color: 'var(--crit)' }}>-{removed} removed</span>
            <span className="font-mono" style={{ fontSize: 11, color: 'var(--t3)' }}>{same} unchanged</span>
          </div>
          <div style={{ flex: 1, overflow: 'auto', border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)', background: 'var(--bg-0)' }}>
            {diff.map((d, i) => (
              <div key={i} style={{ display: 'flex', padding: '2px 14px', background: colors[d.type], borderLeft: `3px solid ${borderColors[d.type]}`, fontFamily: 'var(--font-code)', fontSize: 12, lineHeight: 1.6 }}>
                <span style={{ width: 20, color: textColors[d.type], fontWeight: 600, flexShrink: 0 }}>{prefixes[d.type]}</span>
                <span style={{ color: textColors[d.type], whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>{d.line}</span>
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  );
}
