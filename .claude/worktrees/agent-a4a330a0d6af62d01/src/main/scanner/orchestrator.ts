import { BrowserWindow } from 'electron';
import Database from 'better-sqlite3';
import { v4 as uuid } from 'uuid';
import path from 'path';
import { HttpClient, ProxyConfig } from './http-client';
import { Crawler } from './crawler';
import type { Finding, ScanConfig, Endpoint } from '../../shared/types';

import { ReconModule } from '../modules/recon';
import { HeadersModule } from '../modules/headers';
import { TlsSslModule } from '../modules/tls-ssl';
import { SqlInjectionModule } from '../modules/sql-injection';
import { XssModule } from '../modules/xss';
import { CommandInjectionModule } from '../modules/command-injection';
import { SstiModule } from '../modules/ssti';
import { NosqlInjectionModule } from '../modules/nosql-injection';
import { CorsModule } from '../modules/cors';
import { OpenRedirectModule } from '../modules/open-redirect';
import { CsrfModule } from '../modules/csrf';
import { ClickjackingModule } from '../modules/clickjacking';
import { SsrfModule } from '../modules/ssrf';
import { JwtModule } from '../modules/jwt';
import { AccessControlModule } from '../modules/access-control';
import { GraphqlModule } from '../modules/graphql';
import { PrototypePollutionModule } from '../modules/prototype-pollution';
import { XxeModule } from '../modules/xxe';
import { RequestSmugglingModule } from '../modules/request-smuggling';
import { CachePoisoningModule } from '../modules/cache-poisoning';
import { SubdomainTakeoverModule } from '../modules/subdomain-takeover';
import { CrlfInjectionModule } from '../modules/crlf-injection';
import { FileInclusionModule } from '../modules/file-inclusion';
import { DeserializationModule } from '../modules/deserialization';
import { HostHeaderModule } from '../modules/host-header';
import { CloudModule } from '../modules/cloud';
import { JsAnalysisModule } from '../modules/js-analysis';
import { CookieAnalysisModule } from '../modules/cookie-analysis';
import { DatabaseAttacksModule } from '../modules/database-attacks';

export interface ScanModuleInterface {
  id: string;
  name: string;
  scan(url: string, endpoints: EndpointInfo[], client: HttpClient): Promise<ModuleFinding[]>;
}

export interface EndpointInfo {
  url: string;
  method: string;
  params: string[];
  contentType: string;
}

export interface ModuleFinding {
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string;
  description: string;
  url: string;
  parameter?: string;
  evidence?: any;
  remediation: string;
  cwe_id: string;
  owasp_category: string;
  cvss_score: number;
}

const ALL_MODULES: ScanModuleInterface[] = [
  new ReconModule(),
  new HeadersModule(),
  new TlsSslModule(),
  new SqlInjectionModule(),
  new XssModule(),
  new CommandInjectionModule(),
  new SstiModule(),
  new NosqlInjectionModule(),
  new CorsModule(),
  new OpenRedirectModule(),
  new CsrfModule(),
  new ClickjackingModule(),
  new SsrfModule(),
  new JwtModule(),
  new AccessControlModule(),
  new GraphqlModule(),
  new PrototypePollutionModule(),
  new XxeModule(),
  new RequestSmugglingModule(),
  new CachePoisoningModule(),
  new SubdomainTakeoverModule(),
  new CrlfInjectionModule(),
  new FileInclusionModule(),
  new DeserializationModule(),
  new HostHeaderModule(),
  new CloudModule(),
  new JsAnalysisModule(),
  new CookieAnalysisModule(),
  new DatabaseAttacksModule(),
];

export class ScanOrchestrator {
  private db: Database.Database;
  private running = new Map<string, boolean>();

  constructor(db: Database.Database) {
    this.db = db;
  }

  async startScan(scanId: string): Promise<void> {
    const scan = this.db.prepare('SELECT * FROM scans WHERE id = ?').get(scanId) as any;
    if (!scan) throw new Error('Scan not found');

    const config: ScanConfig = JSON.parse(scan.config || '{}');
    this.running.set(scanId, true);
    this.db.prepare("UPDATE scans SET status = 'running', started_at = CURRENT_TIMESTAMP WHERE id = ?").run(scanId);

    // Load upstream proxy from settings
    let proxyConfig: ProxyConfig | undefined;
    const proxySetting = this.db.prepare("SELECT value FROM app_settings WHERE key = 'upstream_proxy'").get() as any;
    if (proxySetting) {
      try {
        const p = JSON.parse(proxySetting.value);
        if (p.enabled && p.host) {
          proxyConfig = { host: p.host, port: p.port, username: p.username, password: p.password };
        }
      } catch {}
    }

    const client = new HttpClient({
      maxPerSecond: config.rate_limit || 10,
      maxConcurrent: config.max_concurrent || 5,
    }, proxyConfig);

    // Apply authentication headers if configured
    if ((config as any).auth && (config as any).auth.type !== 'none') {
      client.setAuthHeaders((config as any).auth);
    }

    // Load proxy list from database
    const proxyListSetting = this.db.prepare("SELECT value FROM app_settings WHERE key = 'proxy_list'").get() as any;
    if (proxyListSetting) {
      try {
        const list = JSON.parse(proxyListSetting.value);
        if (Array.isArray(list) && list.length > 0) {
          client.loadProxiesFromList(list);
        }
      } catch {}
    }

    try {
      console.log(`[Scanner] Starting scan ${scanId} on ${scan.target_url}`);

      // Pre-check: verify target is reachable
      this.emitProgress(scanId, { module: 'Connectivity check', percent: 2, requests: 0 });
      const checkRes = await client.get(scan.target_url);
      if (checkRes.status === 0) {
        console.error(`[Scanner] Target unreachable: ${scan.target_url}`);
        this.emitProgress(scanId, { module: 'ERROR: Target unreachable', percent: 0, requests: 0 });
        this.db.prepare("UPDATE scans SET status = 'failed', completed_at = CURRENT_TIMESTAMP WHERE id = ?").run(scanId);
        return;
      }
      console.log(`[Scanner] Target reachable: status ${checkRes.status}, ${checkRes.size} bytes`);

      this.emitProgress(scanId, { module: 'Crawling', percent: 5, requests: 0 });
      const crawler = new Crawler(client);
      const endpoints = await crawler.crawl(scan.target_url);
      console.log(`[Scanner] Crawled ${endpoints.length} endpoints`);

      // Filter endpoints by scope rules
      const scopeRules = this.db.prepare('SELECT * FROM proxy_scope ORDER BY id').all() as any[];
      const includeRules = scopeRules.filter(r => r.type === 'include');
      const excludeRules = scopeRules.filter(r => r.type === 'exclude');

      if (includeRules.length > 0 || excludeRules.length > 0) {
        const filtered = endpoints.filter(ep => this.isInScope(ep.url, includeRules, excludeRules));
        endpoints.length = 0;
        endpoints.push(...filtered);
        console.log(`[Scanner] ${endpoints.length} endpoints after scope filtering`);
      }

      for (const ep of endpoints) {
        this.db.prepare(
          'INSERT OR IGNORE INTO endpoints (id, scan_id, url, method, parameters, response_code, content_type) VALUES (?, ?, ?, ?, ?, ?, ?)'
        ).run(uuid(), scanId, ep.url, ep.method, JSON.stringify(ep.params), 200, ep.contentType);
      }

      const enabledModules = config.modules
        ? ALL_MODULES.filter((m) => config.modules.includes(m.id))
        : ALL_MODULES;

      let moduleIdx = 0;
      for (const mod of enabledModules) {
        if (!this.running.get(scanId)) break;

        moduleIdx++;
        const percent = Math.round(10 + (moduleIdx / enabledModules.length) * 85);
        this.emitProgress(scanId, {
          module: mod.name,
          percent,
          requests: client.getRequestCount(),
        });

        try {
          const moduleTimeout = new Promise<ModuleFinding[]>((_, reject) =>
            setTimeout(() => reject(new Error('Module timeout')), 60000)
          );
          const findings = await Promise.race([
            mod.scan(scan.target_url, endpoints, client),
            moduleTimeout,
          ]);
          console.log(`[Scanner] Module ${mod.id}: ${findings.length} findings`);
          for (const f of findings) {
            this.saveFinding(scanId, mod.id, f);
          }
        } catch (err: any) {
          console.error(`[Scanner] Module ${mod.id} error: ${err.message}`);
        }
      }

      const counts = this.countFindings(scanId);
      this.db.prepare(
        "UPDATE scans SET status = 'completed', completed_at = CURRENT_TIMESTAMP, total_requests = ?, findings_count = ? WHERE id = ?"
      ).run(client.getRequestCount(), JSON.stringify(counts), scanId);

      this.emitProgress(scanId, { module: 'Complete', percent: 100, requests: client.getRequestCount() });
    } catch (err) {
      this.db.prepare("UPDATE scans SET status = 'failed', completed_at = CURRENT_TIMESTAMP WHERE id = ?").run(scanId);
      console.error('[Scanner] Scan failed:', err);
    } finally {
      this.running.delete(scanId);
    }
  }

  stopScan(scanId: string) {
    this.running.set(scanId, false);
  }

  private saveFinding(scanId: string, moduleId: string, f: ModuleFinding) {
    const id = uuid();
    this.db.prepare(`
      INSERT INTO findings (id, scan_id, module_id, severity, title, description, url, parameter, evidence, remediation, cwe_id, owasp_category, cvss_score)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(id, scanId, moduleId, f.severity, f.title, f.description, f.url, f.parameter || null,
      JSON.stringify(f.evidence || {}), f.remediation, f.cwe_id, f.owasp_category, f.cvss_score);

    this.emitFinding(scanId, { id, ...f, module_id: moduleId });
  }

  private countFindings(scanId: string) {
    const rows = this.db.prepare(
      'SELECT severity, COUNT(*) as count FROM findings WHERE scan_id = ? GROUP BY severity'
    ).all(scanId) as any[];
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const r of rows) {
      (counts as any)[r.severity] = r.count;
    }
    return counts;
  }

  private emitProgress(scanId: string, data: any) {
    for (const win of BrowserWindow.getAllWindows()) {
      win.webContents.send('scan:progress', { scanId, ...data });
    }
  }

  private emitFinding(scanId: string, data: any) {
    for (const win of BrowserWindow.getAllWindows()) {
      win.webContents.send('scan:finding', { scanId, ...data });
    }
  }

  private isInScope(url: string, includes: any[], excludes: any[]): boolean {
    try {
      const parsed = new URL(url);
      const host = parsed.hostname;

      // Check excludes first -- if any exclude matches, it's out
      for (const rule of excludes) {
        if (this.matchesPattern(host, rule.host_pattern)) return false;
      }

      // If there are include rules, at least one must match
      if (includes.length > 0) {
        return includes.some(rule => this.matchesPattern(host, rule.host_pattern));
      }

      return true; // No include rules = everything in scope
    } catch { return true; }
  }

  private matchesPattern(host: string, pattern: string): boolean {
    if (pattern === '*') return true;
    if (pattern.startsWith('*.')) {
      return host.endsWith(pattern.slice(1)) || host === pattern.slice(2);
    }
    return host === pattern;
  }
}
