import React from 'react';
import ReactDOM from 'react-dom/client';
import { HashRouter } from 'react-router-dom';
import App from './App';
import { getThemeById, applyTheme } from './themes';
import './globals.css';

(async () => {
  try {
    const saved = await window.hackme.getSetting('ui_theme');
    if (saved) applyTheme(getThemeById(saved));
  } catch {}
})();

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <HashRouter>
      <App />
    </HashRouter>
  </React.StrictMode>
);
