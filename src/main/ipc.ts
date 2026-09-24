import { ipcMain, dialog, BrowserWindow } from 'electron';
import Database from 'better-sqlite3';
import { v4 as uuid } from 'uuid';
import { ProxyServer } from './proxy/server';
import { ScanOrchestrator } from './scanner/orchestrator';

const ALL_MODULES_META = [
  { id: 'recon', name: 'Reconnaissance', category: 'recon', description: 'Sensitive files, robots.txt, JS secrets, tech fingerprinting, source maps, HTML comments', severity: 'info', enabled: true },
  { id: 'headers', name: 'Security Headers', category: 'config', description: 'HSTS, CSP, X-Frame-Options, cookie flags, Referrer-Policy, Permissions-Policy', severity: 'medium', enabled: true },
  { id: 'tls-ssl', name: 'TLS/SSL Analysis', category: 'crypto', description: 'Certificate validation, weak TLS versions, weak ciphers, HTTPS enforcement', severity: 'medium', enabled: true },
  { id: 'sql-injection', name: 'SQL Injection', category: 'injection', description: 'Error-based, boolean-blind, time-based across MySQL, PostgreSQL, MSSQL, SQLite, Oracle', severity: 'critical', enabled: true },
  { id: 'xss', name: 'Cross-Site Scripting', category: 'injection', description: 'Reflected XSS with 10 payload variants, canary testing, filter bypass', severity: 'high', enabled: true },
  { id: 'command-injection', name: 'Command Injection', category: 'injection', description: 'Output-based (6 separators) and time-based detection for Linux/Windows', severity: 'critical', enabled: true },
  { id: 'ssti', name: 'Template Injection', category: 'injection', description: 'SSTI for Jinja2, Twig, Freemarker, Velocity, ERB, EJS, Razor, doT.js, Smarty', severity: 'critical', enabled: true },
  { id: 'nosql-injection', name: 'NoSQL Injection', category: 'injection', description: 'MongoDB $ne/$gt/$regex operator injection in query params and JSON', severity: 'critical', enabled: true },
  { id: 'crlf-injection', name: 'CRLF Injection', category: 'injection', description: 'Header injection, Set-Cookie injection, response splitting, 8 encoding variants', severity: 'high', enabled: true },
  { id: 'file-inclusion', name: 'File Inclusion (LFI)', category: 'injection', description: 'Path traversal, PHP wrappers (php://filter), encoding bypasses, include() detection', severity: 'critical', enabled: true },
  { id: 'jwt', name: 'JWT Analysis', category: 'auth', description: 'None algorithm, missing expiry, JWK/JKU injection, kid injection, sensitive payload data', severity: 'high', enabled: true },
  { id: 'access-control', name: 'Access Control', category: 'authz', description: '50+ admin paths, HTTP method tampering, directory listing, Actuator endpoints', severity: 'high', enabled: true },
  { id: 'csrf', name: 'CSRF Detection', category: 'authz', description: 'Missing CSRF tokens on state-changing endpoints, SameSite cookie check', severity: 'medium', enabled: true },
  { id: 'ssrf', name: 'SSRF Detection', category: 'advanced', description: '10 payloads: loopback variants, hex/octal IP, AWS/GCP/Azure metadata', severity: 'critical', enabled: true },
  { id: 'xxe', name: 'XXE Detection', category: 'advanced', description: 'File read, internal probe, parameter entities, DTD processing detection', severity: 'critical', enabled: true },
  { id: 'open-redirect', name: 'Open Redirect', category: 'advanced', description: '16 redirect params, 8 bypass payloads (//evil, /\\evil, @-based, encoding)', severity: 'medium', enabled: true },
  { id: 'cors', name: 'CORS Analysis', category: 'config', description: 'Origin reflection, null origin, wildcard+credentials, subdomain acceptance', severity: 'medium', enabled: true },
  { id: 'clickjacking', name: 'Clickjacking', category: 'config', description: 'Missing X-Frame-Options and CSP frame-ancestors analysis', severity: 'medium', enabled: true },
  { id: 'graphql', name: 'GraphQL', category: 'modern', description: 'Introspection, batching attacks, depth limit bypass', severity: 'medium', enabled: true },
  { id: 'prototype-pollution', name: 'Prototype Pollution', category: 'modern', description: 'Server-side __proto__/constructor.prototype, client-side URL param testing', severity: 'high', enabled: true },
  { id: 'request-smuggling', name: 'Request Smuggling', category: 'modern', description: 'CL.TE, TE.CL timing detection, TE.TE obfuscation (7 variants)', severity: 'critical', enabled: true },
  { id: 'cache-poisoning', name: 'Cache Poisoning', category: 'modern', description: '15 unkeyed headers, web cache deception (8 extensions, 6 delimiters)', severity: 'high', enabled: true },
  { id: 'subdomain-takeover', name: 'Subdomain Takeover', category: 'modern', description: '80+ subdomains, 25 cloud service fingerprints (S3, Azure, GitHub, Heroku, Vercel)', severity: 'high', enabled: true },
  { id: 'deserialization', name: 'Insecure Deserialization', category: 'advanced', description: 'Java/PHP/Node.js/Python/.NET serialized object detection and probing', severity: 'critical', enabled: true },
  { id: 'host-header', name: 'Host Header Attacks', category: 'advanced', description: 'Password reset poisoning, Host override headers, routing-based SSRF', severity: 'high', enabled: true },
  { id: 'cloud', name: 'Cloud Misconfiguration', category: 'infra', description: 'Firebase open rules, Elasticsearch, Redis, Docker API, Kubernetes, .DS_Store', severity: 'critical', enabled: true },
  { id: 'js-analysis', name: 'JavaScript Analysis', category: 'recon', description: 'Secret detection (30+ API key patterns), DOM XSS sinks, source map exposure, bundle analysis', severity: 'high', enabled: true },
  { id: 'cookie-analysis', name: 'Cookie & Session Analysis', category: 'auth', description: 'Cookie flags, session fixation, JWT in cookies, prefix misuse, base64 data, lifetime', severity: 'high', enabled: true },
  { id: 'database-attacks', name: 'Database Exposure', category: 'infra', description: 'MongoDB/CouchDB/Memcached exposure, DB admin panels, SQL dumps, S3 buckets, ES injection', severity: 'critical', enabled: true },
];

export function registerIpcHandlers(db: Database.Database, proxy: ProxyServer, orchestrator: ScanOrchestrator) {
  // ── Projects ──
  ipcMain.handle('db:getProjects', () => {
    return db.prepare('SELECT * FROM projects ORDER BY updated_at DESC').all();
  });

  ipcMain.handle('db:createProject', (_, name: string, url: string) => {
    const id = uuid();
    db.prepare('INSERT INTO projects (id, name, target_url) VALUES (?, ?, ?)').run(id, name, url);
    return db.prepare('SELECT * FROM projects WHERE id = ?').get(id);
  });

  ipcMain.handle('db:deleteProject', (_, id: string) => {
    db.prepare('DELETE FROM projects WHERE id = ?').run(id);
    return true;
  });

  // ── Scans ──
  ipcMain.handle('db:getScans', (_, projectId: string) => {
    return db.prepare('SELECT * FROM scans WHERE project_id = ? ORDER BY started_at DESC').all(projectId);
  });

  ipcMain.handle('scan:create', (_, projectId: string, config: any) => {
    const id = uuid();
    const project = db.prepare('SELECT * FROM projects WHERE id = ?').get(projectId) as any;
    if (!project) throw new Error('Project not found');
    db.prepare(
      'INSERT INTO scans (id, project_id, profile, target_url, config) VALUES (?, ?, ?, ?, ?)'
    ).run(id, projectId, config.profile || 'standard', project.target_url, JSON.stringify(config));
    return db.prepare('SELECT * FROM scans WHERE id = ?').get(id);
  });

  ipcMain.handle('scan:start', (_, scanId: string) => {
    orchestrator.startScan(scanId).catch((err) => console.error('[Scan] Error:', err));
    return true;
  });

  ipcMain.handle('scan:stop', (_, scanId: string) => {
    orchestrator.stopScan(scanId);
    return true;
  });

  ipcMain.handle('scan:getModules', () => {
    return ALL_MODULES_META;
  });

  ipcMain.handle('scan:fromHistory', async (_, historyId: number) => {
    const entry = db.prepare('SELECT * FROM proxy_history WHERE id = ?').get(historyId) as any;
    if (!entry) return { error: 'Entry not found' };

    // Create a project for this URL if none exists
    const url = new URL(entry.url);
    const baseUrl = `${url.protocol}//${url.host}`;
    let project = db.prepare('SELECT * FROM projects WHERE target_url = ?').get(baseUrl) as any;
    if (!project) {
      const id = uuid();
      db.prepare('INSERT INTO projects (id, name, target_url) VALUES (?, ?, ?)').run(id, url.host, baseUrl);
      project = { id };
    }

    // Create and start a scan
    const scanId = uuid();
    const config = { profile: 'standard', modules: [], rate_limit: 10, max_concurrent: 5 };
    db.prepare('INSERT INTO scans (id, project_id, profile, target_url, config) VALUES (?, ?, ?, ?, ?)').run(scanId, project.id, 'standard', entry.url, JSON.stringify(config));

    orchestrator.startScan(scanId).catch(err => console.error('[Scan from history]', err));
    return { scanId, projectId: project.id };
  });

  // ── Findings ──
  ipcMain.handle('db:getFindings', (_, scanId: string) => {
    const rows = db.prepare('SELECT * FROM findings WHERE scan_id = ? ORDER BY cvss_score DESC').all(scanId);
    return rows.map(parseJsonFields);
  });

  ipcMain.handle('db:getAllFindings', () => {
    const rows = db.prepare('SELECT * FROM findings ORDER BY created_at DESC LIMIT 500').all();
    return rows.map(parseJsonFields);
  });

  ipcMain.handle('db:markFalsePositive', (_, id: string, value: boolean) => {
    db.prepare('UPDATE findings SET false_positive = ? WHERE id = ?').run(value ? 1 : 0, id);
    return true;
  });

  // ── Proxy ──
  ipcMain.handle('proxy:start', (_, port: number) => {
    proxy.start(port);
    return true;
  });

  ipcMain.handle('proxy:stop', () => {
    proxy.stop();
    return true;
  });

  ipcMain.handle('proxy:setIntercept', (_, enabled: boolean) => {
    proxy.setInterceptEnabled(enabled);
    return true;
  });

  ipcMain.handle('proxy:forward', (_, queueId: string, modified?: any) => {
    proxy.forwardRequest(queueId, modified);
    return true;
  });

  ipcMain.handle('proxy:drop', (_, queueId: string) => {
    proxy.dropRequest(queueId);
    return true;
  });

  ipcMain.handle('proxy:getHistory', (_, limit: number, offset: number) => {
    return db.prepare('SELECT * FROM proxy_history ORDER BY id DESC LIMIT ? OFFSET ?').all(limit, offset);
  });

  ipcMain.handle('proxy:getIntercepted', () => {
    return proxy.getInterceptedRequests();
  });

  ipcMain.handle('proxy:clearHistory', () => {
    db.prepare('DELETE FROM proxy_history').run();
    return true;
  });

  ipcMain.handle('proxy:exportCA', (_, outputPath: string) => {
    return proxy.exportCACertificate(outputPath);
  });

  ipcMain.handle('proxy:getStatus', () => {
    return {
      running: proxy.isRunning(),
      port: proxy.getPort(),
      intercept_enabled: proxy.isInterceptEnabled(),
    };
  });

  // ── Scope ──
  ipcMain.handle('db:getScopeRules', () => {
    return db.prepare('SELECT * FROM proxy_scope ORDER BY id').all();
  });

  ipcMain.handle('db:addScopeRule', (_, rule: any) => {
    db.prepare(
      'INSERT INTO proxy_scope (type, protocol, host_pattern, port, path_pattern) VALUES (?, ?, ?, ?, ?)'
    ).run(rule.type, rule.protocol, rule.host_pattern, rule.port, rule.path_pattern);
    return true;
  });

  ipcMain.handle('db:deleteScopeRule', (_, id: number) => {
    db.prepare('DELETE FROM proxy_scope WHERE id = ?').run(id);
    return true;
  });

  // ── HTTP Repeater ──
  ipcMain.handle('http:sendRequest', async (_, method: string, url: string, headers: Record<string, string>, body: string | null) => {
    const { request } = await import('undici');
    const dispatcher = await getProxyDispatcher(db);
    const start = Date.now();
    try {
      const response = await request(url, {
        method: method as any,
        headers,
        body: body || undefined,
        headersTimeout: 30000,
        bodyTimeout: 30000,
        dispatcher,
      } as any);
      const responseBody = await response.body.text();
      const duration = Date.now() - start;
      return {
        status: response.statusCode,
        headers: Object.fromEntries(
          Object.entries(response.headers).map(([k, v]) => [k, Array.isArray(v) ? v.join(', ') : v || ''])
        ),
        body: responseBody,
        duration,
        size: Buffer.byteLength(responseBody),
      };
    } catch (err: any) {
      return { error: err.message, duration: Date.now() - start };
    }
  });

  // ── Reports ──
  ipcMain.handle('report:generate', async (_, scanId: string, format: string, outputPath: string) => {
    try {
      if (format === 'pdf') {
        const { generatePdfReport } = await import('./reports/pdf');
        generatePdfReport(db, scanId, outputPath);
      } else if (format === 'html') {
        const { generateHtmlReport } = await import('./reports/html');
        generateHtmlReport(db, scanId, outputPath);
      } else {
        const { generateJsonReport } = await import('./reports/json');
        generateJsonReport(db, scanId, outputPath);
      }
      return true;
    } catch (err: any) {
      return { error: err.message };
    }
  });

  // ── Settings ──
  ipcMain.handle('settings:get', (_, key: string) => {
    const row = db.prepare('SELECT value FROM app_settings WHERE key = ?').get(key) as any;
    if (!row) return null;
    try { return JSON.parse(row.value); } catch { return row.value; }
  });

  ipcMain.handle('settings:set', (_, key: string, value: any) => {
    const serialized = typeof value === 'string' ? value : JSON.stringify(value);
    db.prepare('INSERT OR REPLACE INTO app_settings (key, value) VALUES (?, ?)').run(key, serialized);
    return true;
  });

  ipcMain.handle('settings:getAll', () => {
    const rows = db.prepare('SELECT key, value FROM app_settings').all() as any[];
    const result: Record<string, any> = {};
    for (const row of rows) {
      try { result[row.key] = JSON.parse(row.value); } catch { result[row.key] = row.value; }
    }
    return result;
  });

  // ── Intruder ──
  let intruderEngine: any = null;
  ipcMain.handle('intruder:start', async (_, config: any) => {
    const { IntruderEngine } = await import('./intruder/engine');
    intruderEngine = new IntruderEngine(db);
    intruderEngine.attack(config, (result: any) => {
      for (const win of BrowserWindow.getAllWindows()) { win.webContents.send('intruder:result', result); }
    }).catch((e: any) => console.error('[Intruder]', e));
    return true;
  });
  ipcMain.handle('intruder:stop', () => { if (intruderEngine) intruderEngine.stop(); return true; });
  ipcMain.handle('intruder:payloads', async () => { const { getBuiltinPayloads } = await import('./intruder/engine'); return getBuiltinPayloads(); });

  // ── OOB Callback Server ──
  ipcMain.handle('oob:start', async () => {
    const { getOobServer } = await import('./scanner/oob-server');
    const oob = getOobServer();
    oob.start();
    return { running: true, port: oob.getPort() };
  });
  ipcMain.handle('oob:stop', async () => {
    const { getOobServer } = await import('./scanner/oob-server');
    getOobServer().stop();
    return true;
  });
  ipcMain.handle('oob:status', async () => {
    const { getOobServer } = await import('./scanner/oob-server');
    const oob = getOobServer();
    return { running: oob.isRunning(), port: oob.getPort(), results: oob.getPendingResults() };
  });
  ipcMain.handle('oob:generateId', async () => {
    const { getOobServer } = await import('./scanner/oob-server');
    return getOobServer().generateId();
  });

  // ── Proxy Testing ──
  ipcMain.handle('proxy:testSingle', async (_, proxy: { host: string; port: number; username?: string; password?: string }) => {
    const { quickTestProxy } = await import('./scanner/proxy-tester');
    return await quickTestProxy(proxy);
  });

  ipcMain.handle('proxy:testAll', async () => {
    const { ProxyTester } = await import('./scanner/proxy-tester');
    const listRow = db.prepare("SELECT value FROM app_settings WHERE key = 'proxy_list'").get() as any;
    if (!listRow) return { error: 'No proxies loaded' };

    try {
      const proxies = JSON.parse(listRow.value);
      if (!Array.isArray(proxies) || proxies.length === 0) return { error: 'No proxies loaded' };

      const tester = new ProxyTester(10000);
      const results = await tester.testProxies(proxies, 5);
      const summary = tester.summarizeResults(results);

      // Update proxy list with only alive proxies (optional - keep dead ones marked)
      const aliveProxies = results.filter(r => r.status === 'alive').map(r => r.proxy);

      return {
        results,
        summary,
        aliveCount: aliveProxies.length,
        deadCount: proxies.length - aliveProxies.length,
      };
    } catch (e: any) {
      return { error: e.message };
    }
  });

  ipcMain.handle('proxy:removeDeadProxies', async () => {
    const { ProxyTester } = await import('./scanner/proxy-tester');
    const listRow = db.prepare("SELECT value FROM app_settings WHERE key = 'proxy_list'").get() as any;
    if (!listRow) return { removed: 0, remaining: 0 };

    try {
      const proxies = JSON.parse(listRow.value);
      if (!Array.isArray(proxies) || proxies.length === 0) return { removed: 0, remaining: 0 };

      const tester = new ProxyTester(8000);
      const aliveProxies = await tester.filterAliveProxies(proxies, 10);

      // Save only alive proxies
      db.prepare("INSERT OR REPLACE INTO app_settings (key, value) VALUES ('proxy_list', ?)").run(JSON.stringify(aliveProxies));

      return {
        removed: proxies.length - aliveProxies.length,
        remaining: aliveProxies.length,
      };
    } catch (e: any) {
      return { error: e.message };
    }
  });

  // ── Clear Data ──
  ipcMain.handle('data:clearAll', () => {
    db.prepare('DELETE FROM findings').run();
    db.prepare('DELETE FROM endpoints').run();
    db.prepare('DELETE FROM scans').run();
    db.prepare('DELETE FROM projects').run();
    db.prepare('DELETE FROM proxy_history').run();
    db.prepare('DELETE FROM proxy_websocket').run();
    db.prepare('DELETE FROM proxy_scope').run();
    return true;
  });

  ipcMain.handle('data:clearFindings', () => {
    db.prepare('DELETE FROM findings').run();
    return true;
  });

  ipcMain.handle('data:clearProxyHistory', () => {
    db.prepare('DELETE FROM proxy_history').run();
    db.prepare('DELETE FROM proxy_websocket').run();
    return true;
  });

  ipcMain.handle('data:clearScans', () => {
    db.prepare('DELETE FROM findings').run();
    db.prepare('DELETE FROM endpoints').run();
    db.prepare('DELETE FROM scans').run();
    return true;
  });

  // ── Dialog ──
  ipcMain.handle('dialog:showSave', async (_, options: any) => {
    const win = BrowserWindow.getFocusedWindow();
    if (!win) return null;
    const result = await dialog.showSaveDialog(win, options);
    return result.canceled ? null : result.filePath;
  });

  // ── AI Analysis (Gemini) ──
  ipcMain.handle('ai:isConfigured', () => {
    const { GeminiAnalyzer } = require('./ai/gemini');
    const analyzer = new GeminiAnalyzer(db);
    return analyzer.isConfigured();
  });

  ipcMain.handle('ai:analyzeUrl', async (_, targetUrl: string) => {
    const { GeminiAnalyzer } = require('./ai/gemini');
    const analyzer = new GeminiAnalyzer(db);
    const { request } = await import('undici');
    const dispatcher = await getProxyDispatcher(db);
    try {
      const start = Date.now();
      const response = await request(targetUrl, {
        method: 'GET',
        headers: { 'User-Agent': 'HackMe/1.0' },
        headersTimeout: 15000,
        bodyTimeout: 15000,
        dispatcher,
      } as any);
      const body = await response.body.text();
      const reqHeaders = JSON.stringify({ 'User-Agent': 'HackMe/1.0' });
      const resHeaders = JSON.stringify(response.headers);
      const result = await analyzer.analyzeHttpResponse(
        targetUrl, 'GET', reqHeaders, null,
        response.statusCode, resHeaders, body
      );
      return { ...result, duration: Date.now() - start };
    } catch (err: any) {
      return { error: err.message };
    }
  });

  ipcMain.handle('ai:analyzeJs', async (_, jsUrl: string) => {
    const { GeminiAnalyzer } = require('./ai/gemini');
    const analyzer = new GeminiAnalyzer(db);
    const { request } = await import('undici');
    const dispatcher = await getProxyDispatcher(db);
    try {
      const response = await request(jsUrl, {
        method: 'GET',
        headers: { 'User-Agent': 'HackMe/1.0' },
        headersTimeout: 15000,
        bodyTimeout: 15000,
        dispatcher,
      } as any);
      const code = await response.body.text();
      return await analyzer.analyzeJavaScript(jsUrl, code);
    } catch (err: any) {
      return { error: err.message };
    }
  });

  ipcMain.handle('ai:analyzeFindings', async (_, scanId: string) => {
    const { GeminiAnalyzer } = require('./ai/gemini');
    const analyzer = new GeminiAnalyzer(db);
    try {
      const findings = db.prepare('SELECT * FROM findings WHERE scan_id = ?').all(scanId);
      if (!findings || findings.length === 0) return { error: 'No findings for this scan' };
      return await analyzer.analyzeFindings(findings);
    } catch (err: any) {
      return { error: err.message };
    }
  });

  ipcMain.handle('ai:analyzeCookies', async (_, targetUrl: string) => {
    const { GeminiAnalyzer } = require('./ai/gemini');
    const analyzer = new GeminiAnalyzer(db);
    const { request } = await import('undici');
    const dispatcher = await getProxyDispatcher(db);
    try {
      const response = await request(targetUrl, {
        method: 'GET',
        headers: { 'User-Agent': 'HackMe/1.0' },
        headersTimeout: 15000,
        bodyTimeout: 15000,
        dispatcher,
      } as any);
      await response.body.text();
      const setCookies = response.headers['set-cookie'];
      const cookies = setCookies ? (Array.isArray(setCookies) ? setCookies : [setCookies]) : [];
      if (cookies.length === 0) return { error: 'No cookies found at this URL' };
      return await analyzer.analyzeCookies(cookies, targetUrl);
    } catch (err: any) {
      return { error: err.message };
    }
  });
}

async function getProxyDispatcher(db: Database.Database) {
  const { Agent, ProxyAgent } = await import('undici');
  const listRow = db.prepare("SELECT value FROM app_settings WHERE key = 'proxy_list'").get() as any;
  if (listRow) { try { const list = JSON.parse(listRow.value); if (Array.isArray(list) && list.length > 0) { const p = list[Math.floor(Math.random() * list.length)]; const auth = p.username && p.password ? `${encodeURIComponent(p.username)}:${encodeURIComponent(p.password)}@` : ''; return new ProxyAgent({ uri: `http://${auth}${p.host}:${p.port}`, requestTls: { rejectUnauthorized: false } } as any); } } catch {} }
  const singleRow = db.prepare("SELECT value FROM app_settings WHERE key = 'upstream_proxy'").get() as any;
  if (singleRow) { try { const p = JSON.parse(singleRow.value); if (p.enabled && p.host) { const auth = p.username && p.password ? `${encodeURIComponent(p.username)}:${encodeURIComponent(p.password)}@` : ''; return new ProxyAgent({ uri: `http://${auth}${p.host}:${p.port}`, requestTls: { rejectUnauthorized: false } } as any); } } catch {} }
  return new Agent({ connect: { rejectUnauthorized: false } });
}

function parseJsonFields(row: any) {
  if (row.evidence && typeof row.evidence === 'string') {
    try { row.evidence = JSON.parse(row.evidence); } catch {}
  }
  if (row.config && typeof row.config === 'string') {
    try { row.config = JSON.parse(row.config); } catch {}
  }
  if (row.findings_count && typeof row.findings_count === 'string') {
    try { row.findings_count = JSON.parse(row.findings_count); } catch {}
  }
  return row;
}
