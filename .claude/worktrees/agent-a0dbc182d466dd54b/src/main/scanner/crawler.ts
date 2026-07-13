import * as cheerio from 'cheerio';
import { HttpClient } from './http-client';
import type { EndpointInfo } from './orchestrator';

const API_PATH_REGEX = /['"`](\/(?:api|v[0-9]|graphql|rest|auth|user|admin|data|search|login|register|upload|download|webhook|callback)[\/\w.-]*?)['"`]/gi;

export class Crawler {
  private client: HttpClient;
  private visited = new Set<string>();
  private maxPages = 100;
  private maxJsFiles = 30;

  constructor(client: HttpClient) {
    this.client = client;
  }

  async crawl(baseUrl: string): Promise<EndpointInfo[]> {
    const endpoints: EndpointInfo[] = [];
    const queue = [baseUrl];
    const baseOrigin = new URL(baseUrl).origin;
    const jsUrls: string[] = [];
    const jsUrlSet = new Set<string>();

    // Fetch robots.txt and sitemap.xml in parallel before crawling
    const [robotsEndpoints, sitemapEndpoints] = await Promise.all([
      this.parseRobotsTxt(baseOrigin),
      this.parseSitemapXml(`${baseOrigin}/sitemap.xml`, baseOrigin, 0),
    ]);

    // Add robots.txt discovered paths to the crawl queue
    for (const ep of robotsEndpoints) {
      if (!this.visited.has(ep.url)) {
        queue.push(ep.url);
      }
      endpoints.push(ep);
    }

    // Add sitemap discovered URLs to the crawl queue
    for (const ep of sitemapEndpoints) {
      if (!this.visited.has(ep.url)) {
        queue.push(ep.url);
      }
      endpoints.push(ep);
    }

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
              if (!jsUrlSet.has(jsUrl.href)) {
                jsUrlSet.add(jsUrl.href);
                jsUrls.push(jsUrl.href);
              }
            }
          } catch {}
        });

      } catch {}
    }

    // Extract API endpoints from discovered JS files
    const jsEndpoints = await this.extractJsEndpoints(jsUrls, baseOrigin);
    endpoints.push(...jsEndpoints);

    console.log(`[Crawler] Done: ${endpoints.length} endpoints from ${this.visited.size} pages`);
    return endpoints;
  }

  private async parseRobotsTxt(baseOrigin: string): Promise<EndpointInfo[]> {
    const endpoints: EndpointInfo[] = [];
    const sitemapUrls: string[] = [];

    try {
      const res = await this.client.send(`${baseOrigin}/robots.txt`, { method: 'GET', timeout: 8000 });
      if (res.status !== 200) return endpoints;

      const lines = res.body.split('\n');
      for (const line of lines) {
        const trimmed = line.trim();

        // Parse Disallow and Allow directives
        const disallowMatch = trimmed.match(/^Disallow:\s*(.+)/i);
        const allowMatch = trimmed.match(/^Allow:\s*(.+)/i);
        const pathValue = disallowMatch?.[1]?.trim() || allowMatch?.[1]?.trim();

        if (pathValue && pathValue !== '/' && !pathValue.includes('*')) {
          try {
            const fullUrl = new URL(pathValue, baseOrigin).href;
            endpoints.push({
              url: fullUrl,
              method: 'GET',
              params: [],
              contentType: '',
            });
          } catch {}
        }

        // Parse Sitemap directives
        const sitemapMatch = trimmed.match(/^Sitemap:\s*(.+)/i);
        if (sitemapMatch?.[1]) {
          sitemapUrls.push(sitemapMatch[1].trim());
        }
      }

      // Fetch any sitemaps referenced in robots.txt
      for (const sitemapUrl of sitemapUrls) {
        try {
          const sitemapEndpoints = await this.parseSitemapXml(sitemapUrl, baseOrigin, 0);
          endpoints.push(...sitemapEndpoints);
        } catch {}
      }

      console.log(`[Crawler] robots.txt: found ${endpoints.length} paths`);
    } catch {
      console.log('[Crawler] robots.txt: not found or error');
    }

    return endpoints;
  }

  private async parseSitemapXml(sitemapUrl: string, baseOrigin: string, depth: number): Promise<EndpointInfo[]> {
    const endpoints: EndpointInfo[] = [];
    if (depth > 3) return endpoints; // Max 3 nested sitemaps

    try {
      const res = await this.client.send(sitemapUrl, { method: 'GET', timeout: 8000 });
      if (res.status !== 200) return endpoints;

      // Check for sitemap index files - extract nested sitemap URLs
      const sitemapIndexRegex = /<sitemap>\s*<loc>\s*(.*?)\s*<\/loc>/gi;
      let sitemapMatch;
      while ((sitemapMatch = sitemapIndexRegex.exec(res.body)) !== null) {
        const nestedUrl = sitemapMatch[1].trim();
        try {
          const nestedEndpoints = await this.parseSitemapXml(nestedUrl, baseOrigin, depth + 1);
          endpoints.push(...nestedEndpoints);
        } catch {}
      }

      // Extract <loc> URLs from regular sitemap entries (not inside <sitemap>)
      const locRegex = /<url>\s*<loc>\s*(.*?)\s*<\/loc>/gi;
      let locMatch;
      while ((locMatch = locRegex.exec(res.body)) !== null) {
        const locUrl = locMatch[1].trim();
        try {
          const parsed = new URL(locUrl);
          if (parsed.origin === baseOrigin) {
            endpoints.push({
              url: parsed.href,
              method: 'GET',
              params: Array.from(parsed.searchParams.keys()),
              contentType: '',
            });
          }
        } catch {}
      }

      console.log(`[Crawler] sitemap (${sitemapUrl}): found ${endpoints.length} URLs`);
    } catch {
      console.log(`[Crawler] sitemap (${sitemapUrl}): not found or error`);
    }

    return endpoints;
  }

  private async extractJsEndpoints(jsUrls: string[], baseOrigin: string): Promise<EndpointInfo[]> {
    const endpoints: EndpointInfo[] = [];
    const discoveredPaths = new Set<string>();
    const filesToScan = jsUrls.slice(0, this.maxJsFiles);

    for (const jsUrl of filesToScan) {
      try {
        const res = await this.client.send(jsUrl, { method: 'GET', timeout: 8000 });
        if (res.status !== 200) continue;

        let match;
        API_PATH_REGEX.lastIndex = 0;
        while ((match = API_PATH_REGEX.exec(res.body)) !== null) {
          const apiPath = match[1];
          if (!discoveredPaths.has(apiPath)) {
            discoveredPaths.add(apiPath);
            try {
              const fullUrl = new URL(apiPath, baseOrigin).href;
              endpoints.push({
                url: fullUrl,
                method: 'GET',
                params: [],
                contentType: '',
              });
            } catch {}
          }
        }
      } catch {}
    }

    console.log(`[Crawler] JS extraction: found ${endpoints.length} API endpoints from ${filesToScan.length} JS files`);
    return endpoints;
  }
}
