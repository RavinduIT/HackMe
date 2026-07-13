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

    console.log(`[Crawler] Done: ${endpoints.length} endpoints from ${this.visited.size} pages`);
    return endpoints;
  }
}
