import * as cheerio from 'cheerio';
import dns from 'dns';
import { HttpClient } from './http-client';
import type { EndpointInfo } from './orchestrator';

const JS_URL_PATTERNS = [
  /fetch\s*\(\s*['"`](\/[^'"`\s]{2,}?)['"`]/g,
  /axios\s*\.\s*(?:get|post|put|delete|patch|request)\s*\(\s*['"`](\/[^'"`\s]{2,}?)['"`]/g,
  /\$\.(?:ajax|get|post)\s*\(\s*(?:\{[^}]*url\s*:\s*)?['"`](\/[^'"`\s]{2,}?)['"`]/g,
  /\.(?:open|send)\s*\(\s*['"`]\w+['"`]\s*,\s*['"`](\/[^'"`\s]{2,}?)['"`]/g,
  /['"`](\/api\/[^'"`\s]{1,}?)['"`]/g,
  /['"`](\/v[0-9]+\/[^'"`\s]{1,}?)['"`]/g,
  /['"`](\/(?:auth|user|admin|data|search|graphql|rest|internal|private|backend|gateway|service|webhook|callback|ws|socket|rpc|proxy)\/?[^'"`\s]*?)['"`]/gi,
  /(?:path|route|endpoint|url|uri|href|baseUrl|apiUrl|BASE_URL|API_URL|SERVER_URL)\s*[:=]\s*['"`](\/[^'"`\s]{2,}?)['"`]/gi,
  /(?:router|app)\s*\.\s*(?:get|post|put|delete|patch|use|all|route)\s*\(\s*['"`](\/[^'"`\s]{2,}?)['"`]/g,
];

const TECH_FINGERPRINTS: Record<string, { headers?: Record<string, RegExp>; bodyPatterns?: RegExp[]; paths: string[] }> = {
  wordpress: {
    bodyPatterns: [/wp-content/i, /wp-includes/i, /wp-json/i],
    headers: { 'x-powered-by': /WordPress/i, 'link': /wp-json/i },
    paths: ['/wp-json/wp/v2/users', '/wp-json/wp/v2/posts', '/wp-json/wp/v2/pages', '/wp-json/', '/wp-login.php', '/wp-admin/', '/xmlrpc.php', '/wp-content/uploads/', '/wp-includes/js/'],
  },
  django: {
    headers: { 'x-frame-options': /DENY/i, 'server': /WSGIServer/i },
    bodyPatterns: [/csrfmiddlewaretoken/i, /django/i],
    paths: ['/admin/', '/admin/login/', '/api/schema/', '/api/docs/', '/__debug__/', '/static/admin/'],
  },
  spring: {
    headers: { 'x-application-context': /.*/i },
    bodyPatterns: [/Whitelabel Error Page/i, /springframework/i],
    paths: ['/actuator', '/actuator/health', '/actuator/env', '/actuator/beans', '/actuator/mappings', '/swagger-ui/', '/swagger-ui/index.html', '/v3/api-docs', '/v2/api-docs', '/api-docs', '/h2-console'],
  },
  express: {
    headers: { 'x-powered-by': /Express/i },
    bodyPatterns: [/Cannot (GET|POST|PUT|DELETE)/i],
    paths: ['/api-docs', '/docs', '/health', '/ready', '/live'],
  },
  laravel: {
    bodyPatterns: [/laravel/i, /XSRF-TOKEN/i],
    headers: { 'set-cookie': /laravel_session/i },
    paths: ['/telescope', '/horizon', '/nova', '/nova-api/', '/sanctum/csrf-cookie', '/broadcasting/auth', '/api/user', '/storage/'],
  },
  nextjs: {
    bodyPatterns: [/__NEXT_DATA__/i, /_next\/static/i],
    paths: ['/_next/data/', '/api/', '/api/auth/session', '/api/auth/providers', '/api/auth/csrf'],
  },
  rails: {
    headers: { 'x-powered-by': /Phusion Passenger/i, 'x-runtime': /\d/i },
    bodyPatterns: [/csrf-token/i, /authenticity_token/i],
    paths: ['/rails/info', '/rails/mailers', '/sidekiq', '/admin', '/api/v1/'],
  },
  aspnet: {
    headers: { 'x-aspnet-version': /.*/i, 'x-powered-by': /ASP\.NET/i },
    paths: ['/elmah.axd', '/trace.axd', '/swagger/', '/api/values', '/_framework/blazor.boot.json'],
  },
  flask: {
    bodyPatterns: [/Werkzeug/i, /flask/i],
    paths: ['/static/', '/api/', '/docs', '/redoc', '/openapi.json'],
  },
  graphql: {
    bodyPatterns: [/graphql/i, /__schema/i],
    paths: ['/graphql', '/graphiql', '/playground', '/altair', '/api/graphql', '/gql', '/query'],
  },
};

export class Crawler {
  private client: HttpClient;
  private visited = new Set<string>();
  private maxPages = 150;
  private maxJsFiles = 40;
  private discoveredUrls = new Set<string>();

  constructor(client: HttpClient) { this.client = client; }

  async crawl(baseUrl: string): Promise<EndpointInfo[]> {
    const endpoints: EndpointInfo[] = [];
    const baseOrigin = new URL(baseUrl).origin;
    const baseDomain = new URL(baseUrl).hostname;
    const jsUrls: string[] = [];
    const jsUrlSet = new Set<string>();

    console.log(`[Crawler] Starting discovery on ${baseUrl}`);

    // Phase 1: Initial fetch + technology fingerprinting
    const initialRes = await this.client.send(baseUrl, { method: 'GET', timeout: 10000 });
    if (initialRes.status === 0) { console.error('[Crawler] Target unreachable'); return endpoints; }

    const detectedTech = this.detectTechnology(initialRes);
    console.log(`[Crawler] Detected technologies: ${detectedTech.length > 0 ? detectedTech.join(', ') : 'none identified'}`);

    // Phase 2: Parallel discovery — robots, sitemap, subdomains, crt.sh
    const [robotsEps, sitemapEps, subdomains] = await Promise.all([
      this.parseRobotsTxt(baseOrigin),
      this.parseSitemapXml(`${baseOrigin}/sitemap.xml`, baseOrigin, 0),
      this.discoverSubdomains(baseDomain),
    ]);

    for (const ep of [...robotsEps, ...sitemapEps]) {
      this.addEndpoint(endpoints, ep);
      if (!this.visited.has(ep.url)) this.discoveredUrls.add(ep.url);
    }

    if (subdomains.length > 0) {
      console.log(`[Crawler] Found ${subdomains.length} subdomains: ${subdomains.slice(0, 10).join(', ')}${subdomains.length > 10 ? '...' : ''}`);
      for (const sub of subdomains) {
        this.addEndpoint(endpoints, { url: `https://${sub}`, method: 'GET', params: [], contentType: '' });
        this.addEndpoint(endpoints, { url: `http://${sub}`, method: 'GET', params: [], contentType: '' });
      }
    }

    // Phase 3: Technology-specific probing
    const techPaths = this.getTechPaths(detectedTech);
    const baseline404 = await this.get404Baseline(baseOrigin);

    for (const path of techPaths) {
      const fullUrl = `${baseOrigin}${path}`;
      if (this.discoveredUrls.has(fullUrl)) continue;
      this.discoveredUrls.add(fullUrl);
      if (!this.visited.has(fullUrl)) this.discoveredUrls.add(fullUrl);
    }

    // Phase 4: Recursive HTML crawl with deep extraction
    const queue = [baseUrl, ...this.discoveredUrls];
    while (queue.length > 0 && this.visited.size < this.maxPages) {
      const url = queue.shift()!;
      if (this.visited.has(url)) continue;

      try {
        const parsed = new URL(url);
        if (parsed.origin !== baseOrigin) continue;
      } catch { continue; }

      this.visited.add(url);

      try {
        const res = await this.client.send(url, { method: 'GET', timeout: 8000 });
        if (res.status === 0) continue;
        if (this.matches404(res, baseline404)) continue;

        console.log(`[Crawler] ${res.status} ${url} (${res.size}b)`);
        const parsedUrl = new URL(url);
        this.addEndpoint(endpoints, {
          url, method: 'GET',
          params: Array.from(parsedUrl.searchParams.keys()),
          contentType: res.headers['content-type'] || '',
        });

        if (!res.headers['content-type']?.includes('text/html')) continue;
        const $ = cheerio.load(res.body);

        // Extract links (a href, area href)
        $('a[href], area[href]').each((_, el) => {
          const href = $(el).attr('href');
          if (!href || href.startsWith('#') || href.startsWith('mailto:') || href.startsWith('tel:') || href.startsWith('javascript:')) return;
          this.resolveAndQueue(href, url, baseOrigin, queue);
        });

        // Extract forms with ALL input types
        $('form').each((_, el) => {
          const action = $(el).attr('action') || url;
          const method = ($(el).attr('method') || 'GET').toUpperCase();
          const formParams: string[] = [];
          $(el).find('input[name], textarea[name], select[name], button[name]').each((_, inp) => {
            const name = $(inp).attr('name');
            if (name) formParams.push(name);
          });
          try {
            const formUrl = new URL(action, url).href;
            if (new URL(formUrl).origin === baseOrigin) {
              this.addEndpoint(endpoints, { url: formUrl, method, params: formParams, contentType: 'application/x-www-form-urlencoded' });
            }
          } catch {}
        });

        // Extract JS file URLs
        $('script[src]').each((_, el) => {
          const src = $(el).attr('src');
          if (!src) return;
          try {
            const jsUrl = new URL(src, url);
            this.addEndpoint(endpoints, { url: jsUrl.href, method: 'GET', params: [], contentType: 'application/javascript' });
            if (!jsUrlSet.has(jsUrl.href)) { jsUrlSet.add(jsUrl.href); jsUrls.push(jsUrl.href); }
          } catch {}
        });

        // Extract URLs from inline scripts
        $('script:not([src])').each((_, el) => {
          const code = $(el).html() || '';
          this.extractUrlsFromJs(code, url, baseOrigin, queue, endpoints);
        });

        // Extract URLs from HTML comments
        const commentRegex = /<!--([\s\S]*?)-->/g;
        let cm;
        while ((cm = commentRegex.exec(res.body)) !== null) {
          const urls = cm[1].match(/(?:https?:\/\/[^\s"'<>]+|\/[a-zA-Z][^\s"'<>]*)/g);
          if (urls) urls.forEach(u => this.resolveAndQueue(u, url, baseOrigin, queue));
        }

        // Extract from meta tags
        $('meta[content]').each((_, el) => {
          const content = $(el).attr('content') || '';
          const urls = content.match(/https?:\/\/[^\s"'<>]+/g);
          if (urls) urls.forEach(u => this.resolveAndQueue(u, url, baseOrigin, queue));
        });

        // Extract from link tags (stylesheets, preload, prefetch, etc.)
        $('link[href]').each((_, el) => {
          const href = $(el).attr('href');
          if (href) this.resolveAndQueue(href, url, baseOrigin, queue);
        });

        // Extract URLs from data attributes
        $('[data-url], [data-href], [data-src], [data-endpoint], [data-action], [data-api]').each((_, el) => {
          for (const attr of ['data-url', 'data-href', 'data-src', 'data-endpoint', 'data-action', 'data-api']) {
            const val = $(el).attr(attr);
            if (val) this.resolveAndQueue(val, url, baseOrigin, queue);
          }
        });

        // Extract from iframe src
        $('iframe[src], embed[src], object[data]').each((_, el) => {
          const src = $(el).attr('src') || $(el).attr('data');
          if (src) this.resolveAndQueue(src, url, baseOrigin, queue);
        });

        // Extract subdomains mentioned in page content
        const domainRegex = new RegExp(`[a-zA-Z0-9][-a-zA-Z0-9]*\\.${baseDomain.replace(/\./g, '\\.')}`, 'g');
        const contentDomains = res.body.match(domainRegex);
        if (contentDomains) {
          for (const d of new Set(contentDomains)) {
            if (d !== baseDomain) {
              this.addEndpoint(endpoints, { url: `https://${d}`, method: 'GET', params: [], contentType: '' });
            }
          }
        }

        // Detect technology from each page
        const pageTech = this.detectTechnology(res);
        for (const path of this.getTechPaths(pageTech)) {
          this.resolveAndQueue(path, url, baseOrigin, queue);
        }

      } catch {}
    }

    // Phase 5: Deep JS analysis — extract API endpoints from JavaScript files
    const jsEndpoints = await this.extractJsEndpoints(jsUrls, baseOrigin);
    for (const ep of jsEndpoints) this.addEndpoint(endpoints, ep);

    // Phase 6: Probe discovered tech-specific paths
    for (const path of techPaths) {
      const fullUrl = `${baseOrigin}${path}`;
      if (this.visited.has(fullUrl)) continue;
      this.visited.add(fullUrl);
      try {
        const res = await this.client.send(fullUrl, { method: 'GET', timeout: 5000 });
        if (res.status === 0 || res.status === 404) continue;
        if (this.matches404(res, baseline404)) continue;
        this.addEndpoint(endpoints, { url: fullUrl, method: 'GET', params: [], contentType: res.headers['content-type'] || '' });

        if (res.headers['content-type']?.includes('text/html') || res.headers['content-type']?.includes('json')) {
          const $ = cheerio.load(res.body);
          $('form').each((_, el) => {
            const action = $(el).attr('action') || fullUrl;
            const method = ($(el).attr('method') || 'GET').toUpperCase();
            const formParams: string[] = [];
            $(el).find('input[name], textarea[name], select[name]').each((_, inp) => { const n = $(inp).attr('name'); if (n) formParams.push(n); });
            if (formParams.length > 0) {
              try { this.addEndpoint(endpoints, { url: new URL(action, fullUrl).href, method, params: formParams, contentType: 'application/x-www-form-urlencoded' }); } catch {}
            }
          });
        }
      } catch {}
    }

    // Phase 7: CSP/CORS header analysis for related domains
    try {
      const csp = initialRes.headers['content-security-policy'] || '';
      const domains = csp.match(/https?:\/\/[^\s;']+/g);
      if (domains) {
        for (const d of new Set(domains)) {
          try {
            const parsed = new URL(d);
            if (parsed.hostname.endsWith(baseDomain) || parsed.hostname.includes(baseDomain.split('.')[0])) {
              this.addEndpoint(endpoints, { url: parsed.origin, method: 'GET', params: [], contentType: '' });
            }
          } catch {}
        }
      }
    } catch {}

    // Deduplicate
    const seen = new Set<string>();
    const unique = endpoints.filter(ep => {
      const key = `${ep.method}:${ep.url}:${ep.params.sort().join(',')}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });

    console.log(`[Crawler] Discovery complete: ${unique.length} unique endpoints from ${this.visited.size} pages`);
    return unique;
  }

  private detectTechnology(res: { headers: Record<string, string>; body: string }): string[] {
    const detected: string[] = [];
    for (const [tech, fp] of Object.entries(TECH_FINGERPRINTS)) {
      if (fp.headers) {
        for (const [header, pattern] of Object.entries(fp.headers)) {
          if (res.headers[header] && pattern.test(res.headers[header])) { detected.push(tech); break; }
        }
      }
      if (!detected.includes(tech) && fp.bodyPatterns) {
        for (const pattern of fp.bodyPatterns) {
          if (pattern.test(res.body)) { detected.push(tech); break; }
        }
      }
    }
    return [...new Set(detected)];
  }

  private getTechPaths(techs: string[]): string[] {
    const paths: string[] = [];
    for (const tech of techs) {
      const fp = TECH_FINGERPRINTS[tech];
      if (fp) paths.push(...fp.paths);
    }
    return [...new Set(paths)];
  }

  private async discoverSubdomains(baseDomain: string): Promise<string[]> {
    const found: string[] = [];
    const COMMON_SUBS = [
      'www', 'api', 'admin', 'app', 'dev', 'staging', 'test', 'beta', 'alpha',
      'mail', 'smtp', 'pop', 'imap', 'webmail', 'email',
      'cdn', 'static', 'assets', 'media', 'img', 'images', 'files',
      'auth', 'sso', 'login', 'id', 'oauth', 'accounts',
      'dashboard', 'panel', 'console', 'portal', 'manage', 'cms',
      'docs', 'wiki', 'help', 'support', 'status', 'monitor',
      'git', 'gitlab', 'github', 'bitbucket', 'jenkins', 'ci', 'cd',
      'db', 'database', 'mysql', 'postgres', 'redis', 'mongo', 'elastic',
      'vpn', 'proxy', 'gateway', 'lb', 'edge',
      'internal', 'intranet', 'corp', 'private', 'secure',
      'shop', 'store', 'pay', 'billing', 'payment',
      'blog', 'forum', 'community', 'social',
      'm', 'mobile', 'android', 'ios',
      'ws', 'wss', 'socket', 'realtime', 'push', 'notify',
      'search', 'analytics', 'metrics', 'logs', 'grafana', 'kibana',
      'v1', 'v2', 'v3', 'sandbox', 'demo', 'preview', 'uat',
      'backup', 'bak', 'old', 'legacy', 'archive',
      'ns1', 'ns2', 'mx', 'ftp', 'sftp', 'ssh',
    ];

    // DNS resolution (fast, parallel in batches)
    const batchSize = 20;
    for (let i = 0; i < COMMON_SUBS.length; i += batchSize) {
      const batch = COMMON_SUBS.slice(i, i + batchSize);
      const results = await Promise.allSettled(
        batch.map(sub => new Promise<string>((resolve, reject) => {
          const full = `${sub}.${baseDomain}`;
          dns.resolve4(full, (err) => { if (err) reject(err); else resolve(full); });
        }))
      );
      for (const r of results) {
        if (r.status === 'fulfilled') found.push(r.value);
      }
    }

    // Certificate Transparency via crt.sh
    try {
      const { request } = await import('undici');
      const res = await request(`https://crt.sh/?q=%25.${baseDomain}&output=json`, {
        headersTimeout: 10000, bodyTimeout: 10000,
      } as any);
      const text = await res.body.text();
      const entries = JSON.parse(text) as any[];
      const ctDomains = new Set<string>();
      for (const entry of entries.slice(0, 200)) {
        const names = (entry.name_value || '').split('\n');
        for (const name of names) {
          const clean = name.trim().replace(/^\*\./, '');
          if (clean.endsWith(baseDomain) && clean !== baseDomain && !clean.includes('*')) {
            ctDomains.add(clean);
          }
        }
      }
      for (const d of ctDomains) {
        if (!found.includes(d)) found.push(d);
      }
      console.log(`[Crawler] crt.sh: found ${ctDomains.size} subdomains from Certificate Transparency`);
    } catch (e: any) {
      console.log(`[Crawler] crt.sh lookup failed: ${e.message}`);
    }

    return [...new Set(found)];
  }

  private extractUrlsFromJs(code: string, pageUrl: string, baseOrigin: string, queue: string[], endpoints: EndpointInfo[]) {
    for (const pattern of JS_URL_PATTERNS) {
      pattern.lastIndex = 0;
      let match;
      while ((match = pattern.exec(code)) !== null) {
        const path = match[1];
        if (path && path.length > 1 && !path.includes('*') && !path.includes('{') && path.length < 200) {
          this.resolveAndQueue(path, pageUrl, baseOrigin, queue);
          try {
            const fullUrl = new URL(path, baseOrigin).href;
            this.addEndpoint(endpoints, { url: fullUrl, method: 'GET', params: [], contentType: '' });
          } catch {}
        }
      }
    }
  }

  private resolveAndQueue(href: string, baseUrl: string, baseOrigin: string, queue: string[]) {
    try {
      const resolved = new URL(href, baseUrl);
      resolved.hash = '';
      if (resolved.origin === baseOrigin && !this.visited.has(resolved.href) && !this.discoveredUrls.has(resolved.href)) {
        this.discoveredUrls.add(resolved.href);
        queue.push(resolved.href);
      }
    } catch {}
  }

  private addEndpoint(endpoints: EndpointInfo[], ep: EndpointInfo) {
    endpoints.push(ep);
  }

  private normalize404(body: string): string {
    return body
      .replace(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi, '')
      .replace(/\d{10,13}/g, '')
      .replace(/[0-9a-f]{32,}/gi, '')
      .replace(/\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}/g, '')
      .replace(/"[^"]*token[^"]*"\s*:\s*"[^"]*"/gi, '')
      .replace(/name="csrf[^"]*"\s*value="[^"]*"/gi, '')
      .replace(/\s+/g, ' ')
      .slice(0, 500);
  }

  private async get404Baseline(baseOrigin: string): Promise<{ size: number; prefix: string } | null> {
    try {
      const res = await this.client.send(`${baseOrigin}/hm_nonexistent_${Date.now()}_404check`, { method: 'GET', timeout: 5000 });
      return { size: res.size, prefix: this.normalize404(res.body) };
    } catch { return null; }
  }

  private matches404(res: { size: number; body: string }, baseline: { size: number; prefix: string } | null): boolean {
    if (!baseline) return false;
    return Math.abs(res.size - baseline.size) < 200 && this.normalize404(res.body) === baseline.prefix;
  }

  private async parseRobotsTxt(baseOrigin: string): Promise<EndpointInfo[]> {
    const endpoints: EndpointInfo[] = [];
    try {
      const res = await this.client.send(`${baseOrigin}/robots.txt`, { method: 'GET', timeout: 8000 });
      if (res.status !== 200) return endpoints;
      for (const line of res.body.split('\n')) {
        const m = line.trim().match(/^(?:Dis)?allow:\s*(.+)/i);
        if (m && m[1].trim() !== '/' && !m[1].includes('*')) {
          try { endpoints.push({ url: new URL(m[1].trim(), baseOrigin).href, method: 'GET', params: [], contentType: '' }); } catch {}
        }
        const sm = line.trim().match(/^Sitemap:\s*(.+)/i);
        if (sm) {
          const sitemapEps = await this.parseSitemapXml(sm[1].trim(), baseOrigin, 0);
          endpoints.push(...sitemapEps);
        }
      }
      console.log(`[Crawler] robots.txt: ${endpoints.length} paths`);
    } catch {}
    return endpoints;
  }

  private async parseSitemapXml(sitemapUrl: string, baseOrigin: string, depth: number): Promise<EndpointInfo[]> {
    if (depth > 3) return [];
    const endpoints: EndpointInfo[] = [];
    try {
      const res = await this.client.send(sitemapUrl, { method: 'GET', timeout: 8000 });
      if (res.status !== 200) return endpoints;
      let m;
      const indexRe = /<sitemap>\s*<loc>\s*(.*?)\s*<\/loc>/gi;
      while ((m = indexRe.exec(res.body)) !== null) {
        endpoints.push(...await this.parseSitemapXml(m[1].trim(), baseOrigin, depth + 1));
      }
      const locRe = /<url>\s*<loc>\s*(.*?)\s*<\/loc>/gi;
      while ((m = locRe.exec(res.body)) !== null) {
        try {
          const parsed = new URL(m[1].trim());
          if (parsed.origin === baseOrigin) endpoints.push({ url: parsed.href, method: 'GET', params: Array.from(parsed.searchParams.keys()), contentType: '' });
        } catch {}
      }
      console.log(`[Crawler] sitemap: ${endpoints.length} URLs`);
    } catch {}
    return endpoints;
  }

  private async extractJsEndpoints(jsUrls: string[], baseOrigin: string): Promise<EndpointInfo[]> {
    const endpoints: EndpointInfo[] = [];
    const discoveredPaths = new Set<string>();
    for (const jsUrl of jsUrls.slice(0, this.maxJsFiles)) {
      try {
        const res = await this.client.send(jsUrl, { method: 'GET', timeout: 8000 });
        if (res.status !== 200) continue;
        for (const pattern of JS_URL_PATTERNS) {
          pattern.lastIndex = 0;
          let match;
          while ((match = pattern.exec(res.body)) !== null) {
            const path = match[1];
            if (path && !discoveredPaths.has(path) && path.length < 200 && !path.includes('*')) {
              discoveredPaths.add(path);
              try { endpoints.push({ url: new URL(path, baseOrigin).href, method: 'GET', params: [], contentType: '' }); } catch {}
            }
          }
        }
      } catch {}
    }
    console.log(`[Crawler] JS analysis: ${endpoints.length} API endpoints from ${Math.min(jsUrls.length, this.maxJsFiles)} files`);
    return endpoints;
  }
}
