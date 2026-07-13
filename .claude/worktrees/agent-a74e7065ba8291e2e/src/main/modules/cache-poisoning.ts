import type { ScanModuleInterface, EndpointInfo, ModuleFinding } from '../scanner/orchestrator';
import type { HttpClient } from '../scanner/http-client';

const UNKEYED_HEADERS = [
  'X-Forwarded-Host', 'X-Host', 'X-Forwarded-Server', 'X-Original-Host',
  'X-Forwarded-Scheme', 'X-Forwarded-Proto', 'X-Original-URL', 'X-Rewrite-URL',
  'X-Forwarded-For', 'X-Real-IP', 'X-Custom-IP-Authorization',
  'X-HTTP-Method-Override', 'X-Method-Override',
  'Forwarded', 'CF-Connecting-IP', 'True-Client-IP',
  'X-WAP-Profile', 'X-Requested-With',
];

const CACHE_HIT_INDICATORS = ['x-cache', 'cf-cache-status', 'x-varnish', 'x-drupal-cache', 'x-proxy-cache', 'x-rack-cache', 'fastly-restarts', 'age'];

const DECEPTION_EXTENSIONS = ['.css', '.js', '.jpg', '.png', '.gif', '.svg', '.ico', '.woff2'];
const DECEPTION_DELIMITERS = [';', '%23', '%3f', '%00', '/', '..%2f'];

export class CachePoisoningModule implements ScanModuleInterface {
  id = 'cache-poisoning';
  name = 'Cache Poisoning';

  async scan(url: string, endpoints: EndpointInfo[], client: HttpClient): Promise<ModuleFinding[]> {
    const findings: ModuleFinding[] = [];

    // 1. Detect if caching is present
    const cacheBuster = `?hm_cb=${Date.now()}`;
    const res1 = await client.get(url + cacheBuster);
    const res2 = await client.get(url + cacheBuster);

    const cacheHeaders = CACHE_HIT_INDICATORS.filter((h) => res2.headers[h]);
    const isCached = cacheHeaders.some((h) => {
      const val = res2.headers[h]?.toLowerCase() || '';
      return val.includes('hit') || (h === 'age' && parseInt(val) > 0);
    });

    if (cacheHeaders.length === 0 && !isCached) {
      return findings;
    }

    // 2. Unkeyed header poisoning test
    const canary = 'hm-poison-' + Date.now();

    for (const header of UNKEYED_HEADERS) {
      const cb = `?hm_cb=${Date.now()}_${Math.random().toString(36).slice(2)}`;
      const poisonRes = await client.get(url + cb, { [header]: canary });

      if (poisonRes.body.includes(canary)) {
        // Header value is reflected — check if it gets cached
        const verifyRes = await client.get(url + cb);

        if (verifyRes.body.includes(canary)) {
          findings.push({
            severity: 'critical',
            title: `Web Cache Poisoning via ${header}`,
            description: `The header "${header}" is unkeyed (not part of the cache key) but its value is reflected in the response. When the poisoned response is cached, all subsequent users receive the attacker-controlled content. This can be escalated to stored XSS, phishing, or malware distribution by injecting a malicious URL in a <script src> or <link href>.`,
            url, parameter: header,
            remediation: 'Include this header in the cache key (Vary header), or stop using its value in the response. If using a CDN, configure it to strip or normalize these headers.',
            cwe_id: 'CWE-444', owasp_category: 'A05:2021', cvss_score: 9.1,
            evidence: { header, canary, reflected: true, cached: true },
          });
        } else {
          findings.push({
            severity: 'medium',
            title: `Unkeyed Header Reflected: ${header}`,
            description: `The header "${header}" value is reflected in the response but was not served from cache in the verification request. This may still be exploitable if cache timing differs or if certain endpoints cache more aggressively.`,
            url, parameter: header,
            remediation: 'Stop reflecting the header value in responses, or add it to the Vary header.',
            cwe_id: 'CWE-444', owasp_category: 'A05:2021', cvss_score: 5.3,
            evidence: { header, canary, reflected: true, cached: false },
          });
        }
      }
    }

    // 3. Web Cache Deception — path confusion
    for (const ext of DECEPTION_EXTENSIONS) {
      for (const delim of DECEPTION_DELIMITERS) {
        const deceptionUrl = url.replace(/\/$/, '') + delim + 'nonexistent' + ext;
        const deceptionRes = await client.get(deceptionUrl);

        if (deceptionRes.status === 200 && deceptionRes.size > 200) {
          // Check if the response contains dynamic/authenticated content
          // by comparing with the base page
          const baseRes = await client.get(url);
          const similarity = this.similarity(baseRes.body, deceptionRes.body);

          if (similarity > 0.7) {
            // Same content served for path with static extension — check if cached
            const cachedHeader = CACHE_HIT_INDICATORS.find((h) => {
              const val = deceptionRes.headers[h]?.toLowerCase() || '';
              return val.includes('hit') || val.includes('miss');
            });

            if (cachedHeader) {
              findings.push({
                severity: 'high',
                title: 'Web Cache Deception',
                description: `The URL "${deceptionUrl}" returns the same dynamic content as the base page, but with a static file extension (${ext}) that CDNs typically cache. If an authenticated user visits this URL, their personal data gets cached and served to subsequent anonymous visitors. Delimiter used: "${delim}".`,
                url: deceptionUrl,
                remediation: 'Configure the cache to respect Cache-Control headers from the origin. Never cache responses based solely on file extension. Use the Vary header.',
                cwe_id: 'CWE-525', owasp_category: 'A05:2021', cvss_score: 7.5,
                evidence: { deception_url: deceptionUrl, extension: ext, delimiter: delim, cache_header: cachedHeader, similarity: Math.round(similarity * 100) + '%' },
              });
              break;
            }
          }
        }
      }
    }

    return findings;
  }

  private similarity(a: string, b: string): number {
    if (a.length === 0 || b.length === 0) return 0;
    const shorter = a.length < b.length ? a : b;
    const longer = a.length < b.length ? b : a;
    if (longer.length === 0) return 1.0;
    let matches = 0;
    const chunkSize = 100;
    for (let i = 0; i < shorter.length; i += chunkSize) {
      const chunk = shorter.slice(i, i + chunkSize);
      if (longer.includes(chunk)) matches++;
    }
    const totalChunks = Math.ceil(shorter.length / chunkSize);
    return totalChunks > 0 ? matches / totalChunks : 0;
  }
}
