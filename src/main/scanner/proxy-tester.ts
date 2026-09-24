/**
 * Proxy Tester Module
 * Features:
 * - Live connectivity testing
 * - GeoIP location detection
 * - Speed/latency measurement
 * - Automatic dead proxy removal
 * - Health status tracking
 */

import { request, Agent, ProxyAgent } from 'undici';

export interface ProxyConfig {
  host: string;
  port: number;
  username?: string;
  password?: string;
}

export interface ProxyTestResult {
  proxy: ProxyConfig;
  status: 'alive' | 'dead' | 'timeout' | 'auth_failed';
  latency: number;  // ms
  country?: string;
  city?: string;
  ip?: string;
  isp?: string;
  anonymity?: 'transparent' | 'anonymous' | 'elite';
  error?: string;
  testedAt: string;
}

// GeoIP lookup endpoints (free, no API key needed)
const GEO_ENDPOINTS = [
  'http://ip-api.com/json',           // Returns: country, city, isp, query (IP)
  'https://ipapi.co/json/',            // Backup
  'http://www.geoplugin.net/json.gp',  // Second backup
];

// Test endpoint to verify proxy works
const TEST_ENDPOINTS = [
  'http://httpbin.org/ip',
  'https://api.ipify.org?format=json',
  'http://checkip.amazonaws.com',
];

export class ProxyTester {
  private testTimeout: number;

  constructor(testTimeout = 10000) {
    this.testTimeout = testTimeout;
  }

  /**
   * Test a single proxy and return detailed results
   */
  async testProxy(proxy: ProxyConfig): Promise<ProxyTestResult> {
    const startTime = Date.now();
    const result: ProxyTestResult = {
      proxy,
      status: 'dead',
      latency: 0,
      testedAt: new Date().toISOString(),
    };

    try {
      // Build proxy URI
      const auth = proxy.username && proxy.password
        ? `${encodeURIComponent(proxy.username)}:${encodeURIComponent(proxy.password)}@`
        : '';
      const proxyUri = `http://${auth}${proxy.host}:${proxy.port}`;

      const dispatcher = new ProxyAgent({
        uri: proxyUri,
        requestTls: { rejectUnauthorized: false },
      });

      // Test connectivity
      let responseIp: string | null = null;

      for (const testUrl of TEST_ENDPOINTS) {
        try {
          const response = await request(testUrl, {
            method: 'GET',
            dispatcher,
            headersTimeout: this.testTimeout,
            bodyTimeout: this.testTimeout,
          });

          if (response.statusCode === 200) {
            const body = await response.body.text();
            result.latency = Date.now() - startTime;
            result.status = 'alive';

            // Extract IP from response
            try {
              const json = JSON.parse(body);
              responseIp = json.origin || json.ip || json.query || null;
            } catch {
              // Plain text response (checkip.amazonaws.com)
              responseIp = body.trim();
            }
            break;
          } else if (response.statusCode === 407) {
            result.status = 'auth_failed';
            result.error = 'Proxy requires authentication';
            return result;
          }
        } catch (e: any) {
          // Try next endpoint
          continue;
        }
      }

      if (result.status !== 'alive') {
        result.status = 'dead';
        result.error = 'Failed to connect through proxy';
        result.latency = Date.now() - startTime;
        return result;
      }

      result.ip = responseIp || undefined;

      // Get GeoIP info
      const geoInfo = await this.getGeoInfo(proxy, proxyUri);
      if (geoInfo) {
        result.country = geoInfo.country;
        result.city = geoInfo.city;
        result.isp = geoInfo.isp;
        if (!result.ip) result.ip = geoInfo.ip;
      }

      // Check anonymity level
      result.anonymity = this.checkAnonymity(responseIp, proxy.host);

    } catch (e: any) {
      result.status = e.code === 'ETIMEDOUT' || e.code === 'TIMEOUT' ? 'timeout' : 'dead';
      result.error = e.message || 'Connection failed';
      result.latency = Date.now() - startTime;
    }

    return result;
  }

  /**
   * Test multiple proxies in parallel
   */
  async testProxies(proxies: ProxyConfig[], concurrency = 10): Promise<ProxyTestResult[]> {
    const results: ProxyTestResult[] = [];
    const queue = [...proxies];

    const workers = Array(Math.min(concurrency, proxies.length)).fill(null).map(async () => {
      while (queue.length > 0) {
        const proxy = queue.shift();
        if (!proxy) break;
        const result = await this.testProxy(proxy);
        results.push(result);
      }
    });

    await Promise.all(workers);
    return results;
  }

  /**
   * Get GeoIP information through the proxy
   */
  private async getGeoInfo(proxy: ProxyConfig, proxyUri: string): Promise<{
    country?: string;
    city?: string;
    isp?: string;
    ip?: string;
  } | null> {
    const dispatcher = new ProxyAgent({
      uri: proxyUri,
      requestTls: { rejectUnauthorized: false },
    });

    for (const geoUrl of GEO_ENDPOINTS) {
      try {
        const response = await request(geoUrl, {
          method: 'GET',
          dispatcher,
          headersTimeout: 5000,
          bodyTimeout: 5000,
        });

        if (response.statusCode === 200) {
          const body = await response.body.text();
          const json = JSON.parse(body);

          // ip-api.com format
          if (json.country && json.query) {
            return {
              country: json.country,
              city: json.city,
              isp: json.isp,
              ip: json.query,
            };
          }

          // ipapi.co format
          if (json.country_name && json.ip) {
            return {
              country: json.country_name,
              city: json.city,
              isp: json.org,
              ip: json.ip,
            };
          }

          // geoplugin format
          if (json.geoplugin_countryName) {
            return {
              country: json.geoplugin_countryName,
              city: json.geoplugin_city,
              isp: json.geoplugin_request,
              ip: json.geoplugin_request,
            };
          }
        }
      } catch {
        continue;
      }
    }

    return null;
  }

  /**
   * Check proxy anonymity level
   */
  private checkAnonymity(responseIp: string | null, proxyHost: string): 'transparent' | 'anonymous' | 'elite' {
    if (!responseIp) return 'anonymous';

    // If response IP matches proxy host, it's elite (high anonymity)
    if (responseIp === proxyHost) return 'elite';

    // If we can see the proxy's IP but not the real IP, it's anonymous
    // In a real scenario, we'd check X-Forwarded-For headers
    return 'anonymous';
  }

  /**
   * Filter and return only working proxies
   */
  async filterAliveProxies(proxies: ProxyConfig[], concurrency = 10): Promise<ProxyConfig[]> {
    const results = await this.testProxies(proxies, concurrency);
    return results
      .filter(r => r.status === 'alive')
      .map(r => r.proxy);
  }

  /**
   * Get summary statistics
   */
  summarizeResults(results: ProxyTestResult[]): {
    total: number;
    alive: number;
    dead: number;
    timeout: number;
    authFailed: number;
    avgLatency: number;
    countries: Record<string, number>;
  } {
    const alive = results.filter(r => r.status === 'alive');
    const countries: Record<string, number> = {};

    for (const r of alive) {
      if (r.country) {
        countries[r.country] = (countries[r.country] || 0) + 1;
      }
    }

    return {
      total: results.length,
      alive: alive.length,
      dead: results.filter(r => r.status === 'dead').length,
      timeout: results.filter(r => r.status === 'timeout').length,
      authFailed: results.filter(r => r.status === 'auth_failed').length,
      avgLatency: alive.length > 0
        ? Math.round(alive.reduce((sum, r) => sum + r.latency, 0) / alive.length)
        : 0,
      countries,
    };
  }
}

/**
 * Quick single-proxy test for UI
 */
export async function quickTestProxy(proxy: ProxyConfig): Promise<{
  alive: boolean;
  latency: number;
  ip?: string;
  country?: string;
  error?: string;
}> {
  const tester = new ProxyTester(8000);
  const result = await tester.testProxy(proxy);

  return {
    alive: result.status === 'alive',
    latency: result.latency,
    ip: result.ip,
    country: result.country,
    error: result.error,
  };
}

/**
 * Batch test proxies from list
 */
export async function batchTestProxies(
  proxies: ProxyConfig[],
  onProgress?: (completed: number, total: number, result: ProxyTestResult) => void
): Promise<ProxyTestResult[]> {
  const tester = new ProxyTester(10000);
  const results: ProxyTestResult[] = [];

  for (let i = 0; i < proxies.length; i++) {
    const result = await tester.testProxy(proxies[i]);
    results.push(result);
    if (onProgress) {
      onProgress(i + 1, proxies.length, result);
    }
  }

  return results;
}
