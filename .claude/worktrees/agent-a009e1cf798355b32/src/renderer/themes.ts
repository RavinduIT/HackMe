export interface Theme {
  id: string;
  name: string;
  description: string;
  vars: Record<string, string>;
}

export const THEMES: Theme[] = [
  {
    id: 'obsidian',
    name: 'Obsidian',
    description: 'Sharp, dense, precision terminal',
    vars: {
      '--bg-0': '#050505', '--bg-1': '#0C0C0C', '--bg-2': '#141414', '--bg-3': '#1C1C1C',
      '--bg-4': '#262626', '--bg-5': '#303030',
      '--t1': '#E8E8E8', '--t2': '#999999', '--t3': '#555555',
      '--ac': '#F59E0B', '--ac-lo': 'rgba(245,158,11,0.08)', '--ac-md': 'rgba(245,158,11,0.18)',
      '--crit': '#EF4444', '--high': '#F97316', '--med': '#EAB308', '--low': '#3B82F6', '--info': '#6B7280',
      '--border': '#1C1C1C', '--border-s': '#2A2A2A',
      '--radius': '2px', '--radius-lg': '4px',
      '--font-ui': "'DM Sans', 'Segoe UI', sans-serif",
      '--font-code': "'IBM Plex Mono', 'Consolas', monospace",
      '--card-shadow': '0 1px 2px rgba(0,0,0,.5), 0 0 0 1px #1C1C1C',
      '--card-bg': '#0C0C0C',
      '--head-size': '18px', '--head-weight': '700', '--head-spacing': '0.02em',
      '--body-size': '12px', '--label-size': '9px', '--label-weight': '600', '--label-spacing': '0.12em',
      '--pad-card': '12px', '--pad-section': '16px',
      '--btn-pad': '6px 14px', '--btn-size': '11px', '--btn-weight': '600',
      '--input-pad': '6px 10px',
      '--pill-radius': '2px',
      '--sev-pill-pad': '1px 6px', '--sev-pill-size': '9px',
      '--nav-width-open': '190px', '--nav-width-closed': '48px', '--nav-item-pad': '6px',
      '--nav-font-size': '11px',
    },
  },
  {
    id: 'arctic',
    name: 'Arctic',
    description: 'Spacious, clean, glass surfaces',
    vars: {
      '--bg-0': '#0C1220', '--bg-1': '#111A2E', '--bg-2': '#182440', '--bg-3': '#1F2E50',
      '--bg-4': '#283A62', '--bg-5': '#324676',
      '--t1': '#E4EAF4', '--t2': '#8C9AB8', '--t3': '#506080',
      '--ac': '#38BDF8', '--ac-lo': 'rgba(56,189,248,0.08)', '--ac-md': 'rgba(56,189,248,0.18)',
      '--crit': '#F87171', '--high': '#FB923C', '--med': '#FBBF24', '--low': '#60A5FA', '--info': '#64748B',
      '--border': '#1F2E50', '--border-s': '#283A62',
      '--radius': '12px', '--radius-lg': '16px',
      '--font-ui': "'Outfit', 'Segoe UI', sans-serif",
      '--font-code': "'Fira Code', 'Consolas', monospace",
      '--card-shadow': '0 2px 12px rgba(0,0,0,.3), 0 0 0 1px rgba(31,46,80,.6)',
      '--card-bg': 'rgba(17,26,46,0.85)',
      '--head-size': '22px', '--head-weight': '700', '--head-spacing': '-0.01em',
      '--body-size': '13px', '--label-size': '10px', '--label-weight': '500', '--label-spacing': '0.08em',
      '--pad-card': '18px', '--pad-section': '20px',
      '--btn-pad': '8px 20px', '--btn-size': '12px', '--btn-weight': '600',
      '--input-pad': '9px 14px',
      '--pill-radius': '6px',
      '--sev-pill-pad': '3px 10px', '--sev-pill-size': '10px',
      '--nav-width-open': '220px', '--nav-width-closed': '60px', '--nav-item-pad': '9px',
      '--nav-font-size': '13px',
    },
  },
  {
    id: 'phantom',
    name: 'Phantom',
    description: 'Bold, luxe, neon purple glow',
    vars: {
      '--bg-0': '#09071A', '--bg-1': '#100D24', '--bg-2': '#181430', '--bg-3': '#201B3C',
      '--bg-4': '#2A2548', '--bg-5': '#342F54',
      '--t1': '#EAE4F8', '--t2': '#A496C8', '--t3': '#6A5C88',
      '--ac': '#C084FC', '--ac-lo': 'rgba(192,132,252,0.08)', '--ac-md': 'rgba(192,132,252,0.18)',
      '--crit': '#FB7185', '--high': '#F97316', '--med': '#FBBF24', '--low': '#818CF8', '--info': '#7C7C92',
      '--border': '#201B3C', '--border-s': '#2A2548',
      '--radius': '8px', '--radius-lg': '12px',
      '--font-ui': "'Plus Jakarta Sans', 'Segoe UI', sans-serif",
      '--font-code': "'JetBrains Mono', 'Consolas', monospace",
      '--card-shadow': '0 2px 8px rgba(0,0,0,.4), 0 0 0 1px rgba(32,27,60,.7)',
      '--card-bg': '#100D24',
      '--head-size': '20px', '--head-weight': '700', '--head-spacing': '-0.005em',
      '--body-size': '13px', '--label-size': '10px', '--label-weight': '600', '--label-spacing': '0.1em',
      '--pad-card': '16px', '--pad-section': '18px',
      '--btn-pad': '8px 18px', '--btn-size': '12px', '--btn-weight': '600',
      '--input-pad': '8px 12px',
      '--pill-radius': '4px',
      '--sev-pill-pad': '2px 8px', '--sev-pill-size': '10px',
      '--nav-width-open': '210px', '--nav-width-closed': '54px', '--nav-item-pad': '8px',
      '--nav-font-size': '12px',
    },
  },
  {
    id: 'tactical',
    name: 'Tactical',
    description: 'Military, condensed, operator HUD',
    vars: {
      '--bg-0': '#070907', '--bg-1': '#0D100D', '--bg-2': '#141814', '--bg-3': '#1B201B',
      '--bg-4': '#232A23', '--bg-5': '#2C362C',
      '--t1': '#C8D4C8', '--t2': '#7E9A7E', '--t3': '#4A6040',
      '--ac': '#4ADE80', '--ac-lo': 'rgba(74,222,128,0.08)', '--ac-md': 'rgba(74,222,128,0.18)',
      '--crit': '#EF4444', '--high': '#FB923C', '--med': '#FACC15', '--low': '#22D3EE', '--info': '#6B7280',
      '--border': '#1B201B', '--border-s': '#232A23',
      '--radius': '0px', '--radius-lg': '2px',
      '--font-ui': "'Space Grotesk', 'Segoe UI', sans-serif",
      '--font-code': "'IBM Plex Mono', 'Consolas', monospace",
      '--card-shadow': '0 1px 2px rgba(0,0,0,.4), 0 0 0 1px #1B201B',
      '--card-bg': '#0D100D',
      '--head-size': '16px', '--head-weight': '700', '--head-spacing': '0.04em',
      '--body-size': '12px', '--label-size': '8px', '--label-weight': '700', '--label-spacing': '0.16em',
      '--pad-card': '10px', '--pad-section': '14px',
      '--btn-pad': '5px 12px', '--btn-size': '11px', '--btn-weight': '700',
      '--input-pad': '5px 8px',
      '--pill-radius': '0px',
      '--sev-pill-pad': '1px 5px', '--sev-pill-size': '9px',
      '--nav-width-open': '175px', '--nav-width-closed': '44px', '--nav-item-pad': '5px',
      '--nav-font-size': '11px',
    },
  },
];

export function applyTheme(theme: Theme) {
  const root = document.documentElement;
  for (const [key, value] of Object.entries(theme.vars)) {
    root.style.setProperty(key, value);
  }
}

export function getThemeById(id: string): Theme {
  return THEMES.find(t => t.id === id) || THEMES[0];
}
