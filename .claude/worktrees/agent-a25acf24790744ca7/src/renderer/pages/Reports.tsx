import { useState, useEffect } from 'react';

export default function Reports() {
  const [projects, setProjects] = useState<any[]>([]);
  const [scans, setScans] = useState<any[]>([]);
  const [project, setProject] = useState('');
  const [scan, setScan] = useState('');
  const [format, setFormat] = useState('html');
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState('');

  useEffect(() => { (async () => setProjects(await window.hackme.getProjects() || []))(); }, []);

  async function loadScans(pid: string) {
    setProject(pid); setScan('');
    setScans(((await window.hackme.getScans(pid)) || []).filter((x: any) => x.status === 'completed'));
  }

  async function generate() {
    if (!scan) return;
    setBusy(true); setMsg('');
    const ext: Record<string, string> = { pdf: 'pdf', html: 'html', json: 'json' };
    const path = await window.hackme.showSaveDialog({
      title: 'Save Report', defaultPath: `hackme-report.${ext[format]}`,
      filters: [{ name: `${format.toUpperCase()} Report`, extensions: [ext[format]] }],
    });
    if (path) {
      const r = await window.hackme.generateReport(scan, format, path);
      setMsg(r === true ? `Saved to ${path}` : `Error: ${r?.error || 'Unknown'}`);
    }
    setBusy(false);
  }

  const formats: { key: string; label: string; desc: string }[] = [
    { key: 'html', label: 'HTML', desc: 'Interactive browser report' },
    { key: 'pdf', label: 'PDF', desc: 'Printable document' },
    { key: 'json', label: 'JSON', desc: 'Machine-readable data' },
  ];

  return (
    <div style={{ maxWidth: 600, display: 'flex', flexDirection: 'column', gap: 32 }}>
      {/* Header */}
      <div>
        <h1 className="pg-title">Reports</h1>
        <p className="pg-sub">Generate vulnerability assessment reports</p>
      </div>

      {/* Step 1: Project */}
      <div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 12 }}>
          <div style={{
            width: 24, height: 24, borderRadius: '50%',
            background: 'var(--ac-lo)', border: '1.5px solid var(--ac)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            fontSize: 12, fontWeight: 700, color: 'var(--ac)',
          }}>1</div>
          <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--t1)' }}>Select Project</span>
        </div>
        <select value={project} onChange={e => loadScans(e.target.value)}
          className="hm-input" style={{ width: '100%', fontSize: 13, padding: '12px 14px' }}>
          <option value="">Choose a project...</option>
          {projects.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}
        </select>
      </div>

      {/* Step 2: Scan */}
      {project && (
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 12 }}>
            <div style={{
              width: 24, height: 24, borderRadius: '50%',
              background: scans.length > 0 ? 'var(--ac-lo)' : 'var(--bg-2)',
              border: `1.5px solid ${scans.length > 0 ? 'var(--ac)' : 'var(--border)'}`,
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              fontSize: 12, fontWeight: 700, color: scans.length > 0 ? 'var(--ac)' : 'var(--t3)',
            }}>2</div>
            <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--t1)' }}>Select Scan</span>
          </div>
          {scans.length === 0 ? (
            <div style={{
              padding: '24px 20px', textAlign: 'center',
              background: 'var(--bg-1)', borderRadius: 'var(--radius)',
              border: '1px dashed var(--border)',
              fontSize: 12, color: 'var(--t3)',
            }}>
              No completed scans for this project
            </div>
          ) : (
            <select value={scan} onChange={e => setScan(e.target.value)}
              className="hm-input" style={{ width: '100%', fontSize: 13, padding: '12px 14px' }}>
              <option value="">Choose a scan...</option>
              {scans.map(s => {
                const c = typeof s.findings_count === 'string' ? JSON.parse(s.findings_count) : s.findings_count || {};
                const n = Object.values(c).reduce((a: number, b: any) => a + (b as number), 0);
                return <option key={s.id} value={s.id}>{s.profile} - {new Date(s.completed_at || s.started_at).toLocaleDateString()} - {n} findings</option>;
              })}
            </select>
          )}
        </div>
      )}

      {/* Step 3: Format */}
      {scan && (
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 12 }}>
            <div style={{
              width: 24, height: 24, borderRadius: '50%',
              background: 'var(--ac-lo)', border: '1.5px solid var(--ac)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              fontSize: 12, fontWeight: 700, color: 'var(--ac)',
            }}>3</div>
            <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--t1)' }}>Choose Format</span>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 8 }}>
            {formats.map(f => {
              const active = format === f.key;
              return (
                <button key={f.key} onClick={() => setFormat(f.key)}
                  style={{
                    padding: '16px 14px', textAlign: 'center',
                    border: `1.5px solid ${active ? 'var(--ac)' : 'var(--border)'}`,
                    borderRadius: 'var(--radius)',
                    background: active ? 'var(--ac-lo)' : 'var(--bg-0)',
                    cursor: 'pointer', transition: 'all 0.15s',
                  }}
                  onMouseEnter={e => { if (!active) e.currentTarget.style.borderColor = 'var(--border-s)'; }}
                  onMouseLeave={e => { if (!active) e.currentTarget.style.borderColor = active ? 'var(--ac)' : 'var(--border)'; }}
                >
                  <div style={{
                    fontSize: 14, fontWeight: 700, letterSpacing: '0.06em',
                    color: active ? 'var(--ac)' : 'var(--t2)',
                    marginBottom: 4,
                  }}>{f.label}</div>
                  <div style={{ fontSize: 11, color: 'var(--t3)' }}>{f.desc}</div>
                </button>
              );
            })}
          </div>
        </div>
      )}

      {/* Generate button */}
      {scan && (
        <button onClick={generate} disabled={!scan || busy}
          className="hm-btn hm-btn-primary"
          style={{
            padding: '16px 24px', fontSize: 14, fontWeight: 700,
            letterSpacing: '0.1em', width: '100%',
          }}>
          {busy ? 'Generating...' : 'Generate Report'}
        </button>
      )}

      {/* Result message */}
      {msg && (
        <div style={{
          padding: '14px 20px', borderRadius: 'var(--radius)',
          fontSize: 12, lineHeight: 1.5,
          background: msg.startsWith('Error') ? 'rgba(255,92,92,0.06)' : 'rgba(0,229,195,0.06)',
          border: `1px solid ${msg.startsWith('Error') ? 'rgba(255,92,92,0.15)' : 'rgba(0,229,195,0.15)'}`,
          color: msg.startsWith('Error') ? 'var(--crit)' : 'var(--ac)',
        }} className="font-mono">
          {msg}
        </div>
      )}
    </div>
  );
}
