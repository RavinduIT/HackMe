import * as cheerio from 'cheerio';
import { HttpClient } from './http-client';
import type { EndpointInfo } from './orchestrator';

export class Crawler {
  private client: HttpClient;
  private visited = new Set<string>();
  private maxPages = 20;

  constructor(client: HttpClient) {
    this.client = client;
  }

  async crawl(baseUrl: string): Promise<EndpointInfo[]> {
    const endpoints: EndpointInfo[] = [];
    const queue = [baseUrl];
    const baseOrigin = new URL(baseUrl).origin;

    while (queue.length > 0 && this.visited.size < this.maxPages) {
      const url = queue.shift()!;
      if (this.visited.has(url)) continue;
      this.visited.add(url);

      try {
        const res = await this.client.send(url, { method: 'GET', timeout: 8000 });
        if (res.status === 0) continue;

        console.log(`[Crawler] ${res.status} ${url} (${res.size}b)`);

        const parsedUrl = new URL(url);
        const params = Array.from(parsedUrl.searchParams.keys());
        endpoints.push({
          url,
          method: 'GET',
          params,
          contentType: res.headers['content-type'] || '',
        });

        if (!res.headers['content-type']?.includes('text/html')) continue;

        const $ = cheerio.load(res.body);

        $('a[href]').each((_, el) => {
          const href = $(el).attr('href');
          if (!href || href.startsWith('#') || href.startsWith('mailto:') || href.startsWith('tel:')) return;
          try {
            const resolved = new URL(href, url);
            if (resolved.origin === baseOrigin && !this.visited.has(resolved.href)) {
              resolved.hash = '';
              queue.push(resolved.href);
            }
          } catch {}
        });

        $('form').each((_, el) => {
          const action = $(el).attr('action') || url;
          const method = ($(el).attr('method') || 'GET').toUpperCase();
          const formParams: string[] = [];
          $(el).find('input[name], textarea[name], select[name]').each((_, input) => {
            const name = $(input).attr('name');
            if (name) formParams.push(name);
          });

          try {
            const formUrl = new URL(action, url).href;
            if (new URL(formUrl).origin === baseOrigin) {
              endpoints.push({ url: formUrl, method, params: formParams, contentType: 'application/x-www-form-urlencoded' });
            }
          } catch {}
        });

        $('script[src]').each((_, el) => {
          const src = $(el).attr('src');
          if (!src) return;
          try {
            const jsUrl = new URL(src, url);
            if (jsUrl.origin === baseOrigin) {
              endpoints.push({ url: jsUrl.href, method: 'GET', params: [], contentType: 'application/javascript' });
            }
          } catch {}
        });

      } catch {}
    }

    // Probe common web paths to discover endpoints not linked in HTML
    await this.probeCommonPaths(baseOrigin, endpoints);

    console.log(`[Crawler] Done: ${endpoints.length} endpoints from ${this.visited.size} pages`);
    return endpoints;
  }

  private async probeCommonPaths(baseOrigin: string, endpoints: EndpointInfo[]): Promise<void> {
    const COMMON_PATHS = [
      '/login', '/signin', '/signup', '/register', '/logout', '/forgot-password', '/reset-password',
      '/profile', '/account', '/settings', '/dashboard', '/admin', '/panel', '/console',
      '/api', '/api/v1', '/api/v2', '/api/users', '/api/auth', '/api/login', '/api/search',
      '/api/products', '/api/orders', '/api/config', '/api/status', '/api/health',
      '/search', '/contact', '/about', '/help', '/faq', '/feedback',
      '/upload', '/download', '/files', '/export', '/import',
      '/users', '/user', '/members', '/posts', '/comments', '/categories',
      '/products', '/cart', '/checkout', '/orders', '/payments', '/invoices',
      '/notifications', '/messages', '/inbox',
      '/graphql', '/graphiql', '/playground',
      '/health', '/status', '/ping', '/version', '/info', '/metrics',
      '/feed', '/rss', '/sitemap.xml', '/manifest.json',
      '/wp-login.php', '/wp-admin', '/administrator', '/wp-json/wp/v2/users',
      '/.well-known/openid-configuration', '/.well-known/security.txt',
    ];

    // Get 404 baseline
    let baselineSize = 0;
    let baselinePrefix = '';
    try {
      const baseline = await this.client.send(`${baseOrigin}/hm_nonexistent_path_${Date.now()}`, { method: 'GET', timeout: 5000 });
      baselineSize = baseline.size;
      baselinePrefix = baseline.body.slice(0, 300);
    } catch {}

    const existingUrls = new Set(endpoints.map(e => e.url));

    for (const path of COMMON_PATHS) {
      if (this.visited.size >= this.maxPages) break;
      const fullUrl = `${baseOrigin}${path}`;
      if (existingUrls.has(fullUrl) || this.visited.has(fullUrl)) continue;

      try {
        const res = await this.client.send(fullUrl, { method: 'GET', timeout: 5000 });
        if (res.status === 0 || res.status === 404) continue;
        // Skip if response matches 404 baseline (SPA catch-all detection)
        if (Math.abs(res.size - baselineSize) < 100 && res.body.slice(0, 300) === baselinePrefix) continue;

        this.visited.add(fullUrl);
        endpoints.push({ url: fullUrl, method: 'GET', params: [], contentType: res.headers['content-type'] || '' });

        // If it's HTML, also parse it for forms and links
        if (res.headers['content-type']?.includes('text/html')) {
          const $ = cheerio.load(res.body);
          $('form').each((_, el) => {
            const action = $(el).attr('action') || fullUrl;
            const method = ($(el).attr('method') || 'GET').toUpperCase();
            const formParams: string[] = [];
            $(el).find('input[name], textarea[name], select[name]').each((_, inp) => {
              const name = $(inp).attr('name');
              if (name) formParams.push(name);
            });
            if (formParams.length > 0) {
              try {
                const formUrl = new URL(action, fullUrl).href;
                endpoints.push({ url: formUrl, method, params: formParams, contentType: 'application/x-www-form-urlencoded' });
              } catch {}
            }
          });
        }
      } catch {}
    }

    console.log(`[Crawler] Common path probing: checked ${COMMON_PATHS.length} paths`);
  }
}
