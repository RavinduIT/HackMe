import { useLocation } from 'react-router-dom';

const PAGE_META: Record<string, { title: string; desc: string }> = {
  '/': { title: 'Dashboard', desc: 'Project overview and vulnerability summary' },
  '/proxy/intercept': { title: 'Intercept', desc: 'Capture and modify HTTP/S requests in transit' },
  '/proxy/history': { title: 'HTTP History', desc: 'All proxied traffic' },
  '/proxy/scope': { title: 'Scope', desc: 'Define target scope for proxy capture' },
  '/scanner/new': { title: 'New Scan', desc: 'Configure and launch a vulnerability scan' },
  '/findings': { title: 'Findings', desc: 'All discovered vulnerabilities' },
  '/repeater': { title: 'Repeater', desc: 'Manually craft and send HTTP requests' },
  '/decoder': { title: 'Decoder', desc: 'Encode and decode data transformations' },
  '/history': { title: 'Scan History', desc: 'Previous scan results' },
  '/reports': { title: 'Reports', desc: 'Generate scan reports' },
  '/settings': { title: 'Settings', desc: 'Application configuration' },
};

export default function TopBar() {
  const { pathname } = useLocation();
  const base = pathname.startsWith('/scanner/active') ? '/scanner/active' : pathname;
  const meta = PAGE_META[base] || { title: 'HackMe', desc: '' };
  const isActiveScan = pathname.startsWith('/scanner/active');

  return (
    <header className="h-9 bg-hm-surface border-b border-hm-border flex items-center px-4 shrink-0 gap-3">
      <span className="text-[12px] font-medium text-hm-text">{isActiveScan ? 'Active Scan' : meta.title}</span>
      <span className="text-[10px] text-hm-text-muted hidden sm:inline">{meta.desc}</span>
      <div className="ml-auto">
        <span className="text-[10px] text-hm-text-muted font-mono">v1.0.0</span>
      </div>
    </header>
  );
}
