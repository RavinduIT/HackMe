import { NavLink } from 'react-router-dom';
import { useState, useEffect } from 'react';

function Ic({ d }: { d: string }) {
  return <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round"><path d={d}/></svg>;
}

const IC: Record<string, string> = {
  dash: 'M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z M9 22V12h6v10',
  intercept: 'M10 9l-6 6 M4 9h6v6 M14 15l6-6 M20 15h-6V9',
  history: 'M12 8v4l3 3 M3 12a9 9 0 1 0 9-9 M3 3v6h6',
  scope: 'M12 22c5.523 0 10-4.477 10-10S17.523 2 12 2 2 6.477 2 12s4.477 10 10 10z M12 18a6 6 0 1 0 0-12 6 6 0 0 0 0 12z M12 14a2 2 0 1 0 0-4 2 2 0 0 0 0 4z',
  scan: 'M22 12h-4l-3 9L9 3l-3 9H2',
  findings: 'M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z M12 9v4 M12 17h.01',
  ai: 'M12 2a4 4 0 0 0-4 4v1H6a2 2 0 0 0-2 2v3a2 2 0 0 0 2 2h1v4a2 2 0 0 0 2 2h6a2 2 0 0 0 2-2v-4h1a2 2 0 0 0 2-2V9a2 2 0 0 0-2-2h-2V6a4 4 0 0 0-4-4z M9 10h.01 M15 10h.01 M9.5 15a3.5 3.5 0 0 0 5 0',
  repeater: 'M17 1l4 4-4 4 M3 11V9a4 4 0 0 1 4-4h14 M7 23l-4-4 4-4 M21 13v2a4 4 0 0 1-4 4H3',
  decoder: 'M16 18l6-6-6-6 M8 6l-6 6 6 6',
  scanHist: 'M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z M14 2v6h6 M16 13H8 M16 17H8 M10 9H8',
  reports: 'M4 4h16v16H4z M8 2v4 M16 2v4 M4 10h16',
  settings: 'M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6z M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z',
  chevL: 'M15 18l-6-6 6-6',
  chevR: 'M9 18l6-6-6-6',
};

interface NI { path: string; icon: string; label: string; section?: string }
const NAV: NI[] = [
  { path: '/', icon: 'dash', label: 'Dashboard' },
  { path: '/proxy/intercept', icon: 'intercept', label: 'Intercept', section: 'PROXY' },
  { path: '/proxy/history', icon: 'history', label: 'HTTP History' },
  { path: '/proxy/scope', icon: 'scope', label: 'Scope' },
  { path: '/scanner/new', icon: 'scan', label: 'New Scan', section: 'SCANNER' },
  { path: '/findings', icon: 'findings', label: 'Findings' },
  { path: '/ai', icon: 'ai', label: 'AI Analysis', section: 'AI' },
  { path: '/repeater', icon: 'repeater', label: 'Repeater', section: 'TOOLS' },
  { path: '/decoder', icon: 'decoder', label: 'Decoder' },
  { path: '/history', icon: 'scanHist', label: 'Scan History', section: 'DATA' },
  { path: '/reports', icon: 'reports', label: 'Reports' },
  { path: '/settings', icon: 'settings', label: 'Settings' },
];

export default function Sidebar() {
  const [open, setOpen] = useState(true);
  const [proxy, setProxy] = useState({ running: false, port: 8080 });
  let sec = '';

  useEffect(() => {
    const i = setInterval(async () => { try { setProxy(await window.hackme.proxyGetStatus()); } catch {} }, 2000);
    return () => clearInterval(i);
  }, []);

  return (
    <nav className="flex flex-col shrink-0 select-none" style={{ width: open ? 210 : 54, transition: 'width .2s ease', background: 'var(--bg-1)', borderRight: '1px solid var(--border)' }}>
      <div className="h-[52px] flex items-center px-3 gap-2.5" style={{ borderBottom: '1px solid var(--border)' }}>
        <div className="w-8 h-8 rounded-lg flex items-center justify-center shrink-0 cursor-pointer" style={{ background: 'var(--ac)' }} onClick={() => setOpen(!open)}>
          <svg width="14" height="14" viewBox="0 0 14 14" fill="var(--bg-0)"><path d="M2 2h4v4H2zM8 2h4v4H8zM2 8h4v4H2zM8 8h4v4H8z"/></svg>
        </div>
        {open && <span className="text-[13px] font-bold tracking-wide flex-1" style={{ color: 'var(--t1)' }}>HACKME</span>}
        {open && (
          <button onClick={() => setOpen(false)} className="w-6 h-6 flex items-center justify-center rounded hover:opacity-80 shrink-0" style={{ color: 'var(--t3)' }}>
            <Ic d={IC.chevL} />
          </button>
        )}
      </div>

      <div className="flex-1 overflow-y-auto py-1.5">
        {NAV.map(item => {
          const showSec = item.section && item.section !== sec;
          if (item.section) sec = item.section;
          return (
            <div key={item.path}>
              {showSec && open && <div className="px-4 pt-4 pb-1"><span className="text-[9px] font-semibold tracking-[.14em] uppercase" style={{ color: 'var(--t3)' }}>{item.section}</span></div>}
              {showSec && !open && <div className="mx-auto my-2" style={{ width: 20, height: 1, background: 'var(--border)' }} />}
              <NavLink to={item.path} end={item.path === '/'} className={() => `relative flex items-center gap-2.5 mx-1.5 transition-all ${open ? 'px-3 py-[7px]' : 'justify-center py-[7px]'}`}
                style={({ isActive }) => ({ color: isActive ? 'var(--ac)' : 'var(--t3)', background: isActive ? 'var(--ac-lo)' : 'transparent', borderRadius: 'var(--radius)' })}>
                {({ isActive }) => (<>
                  {isActive && <div className="absolute left-0 top-1/2 -translate-y-1/2 w-[3px] h-5 rounded-r-full" style={{ background: 'var(--ac)', marginLeft: -6 }} />}
                  <Ic d={IC[item.icon]} />
                  {open && <span className="text-[12px] font-medium truncate">{item.label}</span>}
                </>)}
              </NavLink>
            </div>
          );
        })}
      </div>

      <div className="px-3 py-3 flex items-center gap-2.5" style={{ borderTop: '1px solid var(--border)' }}>
        <div className={`w-2 h-2 rounded-full shrink-0 ${proxy.running ? 'cx-pulse' : ''}`} style={{ background: proxy.running ? 'var(--ac)' : 'var(--t3)' }} />
        {open && <span className="text-[10px] font-mono truncate" style={{ color: 'var(--t3)' }}>{proxy.running ? `proxy :${proxy.port}` : 'proxy off'}</span>}
        {open && <span className="text-[8px] font-mono ml-auto" style={{ color: 'var(--t3)' }}>v1.0</span>}
      </div>
    </nav>
  );
}
