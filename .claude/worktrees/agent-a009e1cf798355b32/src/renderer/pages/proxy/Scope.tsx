import { useState, useEffect } from 'react';

export default function Scope() {
  const [rules, setRules] = useState<any[]>([]);
  const [pattern, setPattern] = useState('');
  const [type, setType] = useState<'include' | 'exclude'>('include');

  useEffect(() => { load(); }, []);
  async function load() { setRules(await window.hackme.getScopeRules() || []); }
  async function add() {
    if (!pattern.trim()) return;
    await window.hackme.addScopeRule({ type, protocol: 'any', host_pattern: pattern.trim(), port: 'any', path_pattern: '*' });
    setPattern(''); load();
  }
  async function remove(id: number) { await window.hackme.deleteScopeRule(id); load(); }

  const includeRules = rules.filter(r => r.type === 'include');
  const excludeRules = rules.filter(r => r.type === 'exclude');

  return (
    <div style={{ maxWidth: 680, display: 'flex', flexDirection: 'column', gap: 28 }}>
      {/* Page header */}
      <div>
        <h1 className="pg-title">Scope</h1>
        <p className="pg-sub">Define which domains the proxy captures and scans</p>
      </div>

      {/* Add rule section */}
      <div style={{
        background: 'var(--bg-1)',
        borderRadius: 'var(--radius-lg)',
        border: '1px solid var(--border)',
        overflow: 'hidden',
      }}>
        <div style={{
          padding: '18px 24px',
          display: 'flex', alignItems: 'center', gap: 12,
        }}>
          {/* Include/Exclude toggle */}
          <div style={{
            display: 'flex', borderRadius: 'var(--radius)', overflow: 'hidden',
            border: '1px solid var(--border)',
          }}>
            {(['include', 'exclude'] as const).map(t => (
              <button key={t}
                onClick={() => setType(t)}
                style={{
                  padding: '8px 16px', border: 'none', cursor: 'pointer',
                  fontSize: 11, fontWeight: 600, textTransform: 'uppercase',
                  letterSpacing: '0.06em', transition: 'all 0.15s',
                  background: type === t
                    ? (t === 'include' ? 'rgba(0,229,195,0.12)' : 'rgba(255,92,92,0.12)')
                    : 'var(--bg-0)',
                  color: type === t
                    ? (t === 'include' ? 'var(--ac)' : 'var(--crit)')
                    : 'var(--t3)',
                }}>
                {t}
              </button>
            ))}
          </div>

          {/* Pattern input */}
          <input
            className="hm-input hm-input-mono"
            style={{ flex: 1, fontSize: 13 }}
            placeholder="*.example.com"
            value={pattern}
            onChange={e => setPattern(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && add()}
          />

          <button onClick={add} className="hm-btn hm-btn-primary" style={{ minWidth: 80 }}>
            Add Rule
          </button>
        </div>

        {/* Hint */}
        <div style={{
          padding: '0 24px 14px',
          fontSize: 11, color: 'var(--t3)', lineHeight: 1.5,
        }}>
          Use wildcards: <span className="font-mono" style={{ color: 'var(--t2)' }}>*.api.example.com</span> or exact: <span className="font-mono" style={{ color: 'var(--t2)' }}>staging.app.io</span>
        </div>
      </div>

      {/* Rules display */}
      {rules.length === 0 ? (
        <div style={{
          padding: '48px 32px', textAlign: 'center',
          background: 'var(--bg-1)', borderRadius: 'var(--radius-lg)',
          border: '1px dashed var(--border)',
        }}>
          <div style={{ fontSize: 24, color: 'var(--t3)', marginBottom: 12, opacity: 0.4 }}>No scope rules</div>
          <div style={{ fontSize: 13, color: 'var(--t3)', lineHeight: 1.6 }}>
            All traffic will be captured. Add include rules to limit scope,<br />
            or exclude rules to filter out specific domains.
          </div>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
          {/* Include rules */}
          {includeRules.length > 0 && (
            <RuleGroup
              label="Include"
              color="var(--ac)"
              bgColor="rgba(0,229,195,0.04)"
              borderColor="rgba(0,229,195,0.15)"
              rules={includeRules}
              onRemove={remove}
            />
          )}

          {/* Exclude rules */}
          {excludeRules.length > 0 && (
            <RuleGroup
              label="Exclude"
              color="var(--crit)"
              bgColor="rgba(255,92,92,0.04)"
              borderColor="rgba(255,92,92,0.15)"
              rules={excludeRules}
              onRemove={remove}
            />
          )}
        </div>
      )}
    </div>
  );
}

function RuleGroup({ label, color, bgColor, borderColor, rules, onRemove }: {
  label: string; color: string; bgColor: string; borderColor: string;
  rules: any[]; onRemove: (id: number) => void;
}) {
  return (
    <div style={{
      background: bgColor,
      border: `1px solid ${borderColor}`,
      borderRadius: 'var(--radius-lg)',
      overflow: 'hidden',
    }}>
      <div style={{
        padding: '10px 20px',
        borderBottom: `1px solid ${borderColor}`,
        display: 'flex', alignItems: 'center', gap: 10,
      }}>
        <div style={{ width: 6, height: 6, borderRadius: 2, background: color }} />
        <span style={{
          fontSize: 10, fontWeight: 700, textTransform: 'uppercase',
          letterSpacing: '0.12em', color,
        }}>
          {label} Rules
        </span>
        <span className="font-mono" style={{ fontSize: 10, color: 'var(--t3)', marginLeft: 4 }}>
          ({rules.length})
        </span>
      </div>
      {rules.map((r, idx) => (
        <div key={r.id} style={{
          padding: '12px 20px',
          display: 'flex', alignItems: 'center',
          borderBottom: idx < rules.length - 1 ? `1px solid ${borderColor}` : 'none',
          transition: 'background 0.12s',
        }}
          onMouseEnter={e => e.currentTarget.style.background = 'rgba(255,255,255,0.02)'}
          onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
        >
          <span className="font-mono" style={{ fontSize: 13, color: 'var(--t1)', flex: 1 }}>
            {r.host_pattern}
          </span>
          <button onClick={() => onRemove(r.id)} style={{
            background: 'none', border: 'none', cursor: 'pointer',
            fontSize: 10, color: 'var(--t3)', padding: '4px 8px',
            borderRadius: 'var(--radius)', transition: 'all 0.15s',
          }}
            onMouseEnter={e => { e.currentTarget.style.color = 'var(--crit)'; e.currentTarget.style.background = 'rgba(255,92,92,0.08)'; }}
            onMouseLeave={e => { e.currentTarget.style.color = 'var(--t3)'; e.currentTarget.style.background = 'none'; }}
          >
            remove
          </button>
        </div>
      ))}
    </div>
  );
}
