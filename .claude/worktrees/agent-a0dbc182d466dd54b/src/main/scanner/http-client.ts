import { request, ProxyAgent, Agent, Dispatcher, interceptors } from 'undici';
import fs from 'fs';
import path from 'path';

interface RateLimiterOptions {
  maxPerSecond: number;
  maxConcurrent: number;
}

export interface ProxyConfig {
  host: string;
  port: number;
  username: string;
  password: string;
}

interface HttpResponse {
  status: number;
  headers: Record<string, string>;
  body: string;
  duration: number;
  size: number;
  error?: string;
}

interface RequestOptions {
  method?: string;
  headers?: Record<string, string>;
  body?: string | null;
  followRedirects?: boolean;
  timeout?: number;
}

class TokenBucket {
  private tokens: number;
  private lastRefill: number;
  private maxTokens: number;
  private refillRate: number;

  constructor(maxPerSecond: number) {
    this.maxTokens = maxPerSecond;
    this.tokens = maxPerSecond;
    this.refillRate = maxPerSecond;
    this.lastRefill = Date.now();
  }

  async acquire(): Promise<void> {
    this.refill();
    if (this.tokens >= 1) {
      this.tokens -= 1;
      return;
    }
    const waitMs = ((1 - this.tokens) / this.refillRate) * 1000;
    await new Promise((r) => setTimeout(r, waitMs));
    this.refill();
    this.tokens -= 1;
  }

  private refill() {
    const now = Date.now();
    const elapsed = (now - this.lastRefill) / 1000;
    this.tokens = Math.min(this.maxTokens, this.tokens + elapsed * this.refillRate);
    this.lastRefill = now;
  }

  setRate(maxPerSecond: number) {
    this.maxTokens = maxPerSecond;
    this.refillRate = maxPerSecond;
  }
}

export class HttpClient {
  private rateLimiter: TokenBucket;
  private activeRequests = 0;
  private maxConcurrent: number;
  private requestCount = 0;
  private proxyList: ProxyConfig[] = [];
  private proxyIndex = 0;
  private singleProxy: ProxyConfig | null = null;
  private redirectAgent: Dispatcher;
  private noRedirectAgent: Dispatcher;
  private defaultHeaders: Record<string, string> = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'identity',
    'Connection': 'keep-alive',
  };

  constructor(options: RateLimiterOptions = { maxPerSecond: 10, maxConcurrent: 5 }, proxy?: ProxyConfig) {
    this.rateLimiter = new TokenBucket(options.maxPerSecond);
    this.maxConcurrent = options.maxConcurrent;
    this.redirectAgent = new Agent({ connect: { rejectUnauthorized: false } })
      .compose(interceptors.redirect({ maxRedirections: 5 }));
    this.noRedirectAgent = new Agent({ connect: { rejectUnauthorized: false } });
    if (proxy) this.singleProxy = proxy;
  }

  loadProxiesFromList(list: ProxyConfig[]) {
    this.proxyList = list.filter(p => p && p.host);
    if (this.proxyList.length > 0) {
      console.log(`[HttpClient] Loaded ${this.proxyList.length} proxies from database`);
    }
  }

  loadProxiesFromFile(filePath: string) {
    try {
      if (!fs.existsSync(filePath)) return;
      const content = fs.readFileSync(filePath, 'utf-8');
      const lines = content.split('\n').map(l => l.trim()).filter(l => l && !l.startsWith('#'));
      this.proxyList = lines.map(line => {
        const parts = line.split(':');
        if (parts.length === 4) {
          return { host: parts[0], port: parseInt(parts[1]), username: parts[2], password: parts[3] };
        } else if (parts.length === 2) {
          return { host: parts[0], port: parseInt(parts[1]), username: '', password: '' };
        }
        return null;
      }).filter(Boolean) as ProxyConfig[];
      if (this.proxyList.length > 0) {
        console.log(`[HttpClient] Loaded ${this.proxyList.length} proxies from ${filePath}`);
      }
    } catch (e: any) {
      console.error(`[HttpClient] Failed to load proxies: ${e.message}`);
    }
  }

  private getDispatcher(followRedirects: boolean): Dispatcher {
    const proxy = this.getNextProxy();
    if (proxy) {
      const auth = proxy.username && proxy.password
        ? `${encodeURIComponent(proxy.username)}:${encodeURIComponent(proxy.password)}@`
        : '';
      const uri = `http://${auth}${proxy.host}:${proxy.port}`;
      const agent = new ProxyAgent({ uri, requestTls: { rejectUnauthorized: false } } as any);
      if (followRedirects) {
        return agent.compose(interceptors.redirect({ maxRedirections: 5 }));
      }
      return agent;
    }
    return followRedirects ? this.redirectAgent : this.noRedirectAgent;
  }

  private getNextProxy(): ProxyConfig | null {
    if (this.singleProxy) return this.singleProxy;
    if (this.proxyList.length === 0) return null;
    const proxy = this.proxyList[this.proxyIndex % this.proxyList.length];
    this.proxyIndex++;
    return proxy;
  }

  getRequestCount(): number {
    return this.requestCount;
  }

  setRateLimit(maxPerSecond: number) {
    this.rateLimiter.setRate(maxPerSecond);
  }

  setMaxConcurrent(max: number) {
    this.maxConcurrent = max;
  }

  async send(url: string, options: RequestOptions = {}): Promise<HttpResponse> {
    while (this.activeRequests >= this.maxConcurrent) {
      await new Promise((r) => setTimeout(r, 50));
    }

    await this.rateLimiter.acquire();
    this.activeRequests++;
    this.requestCount++;

    const start = Date.now();
    const followRedirects = options.followRedirects !== false;

    try {
      const headers = { ...this.defaultHeaders, ...options.headers };
      const dispatcher = this.getDispatcher(followRedirects);

      const reqOpts: any = {
        method: (options.method || 'GET'),
        headers,
        body: options.body || undefined,
        headersTimeout: options.timeout || 15000,
        bodyTimeout: options.timeout || 15000,
        dispatcher,
      };

      const response = await request(url, reqOpts);
      const body = await response.body.text();
      const duration = Date.now() - start;

      const flatHeaders: Record<string, string> = {};
      for (const [k, v] of Object.entries(response.headers)) {
        flatHeaders[k] = Array.isArray(v) ? v.join(', ') : (v as string) || '';
      }

      return { status: response.statusCode, headers: flatHeaders, body, duration, size: Buffer.byteLength(body) };
    } catch (err: any) {
      console.error(`[HttpClient] ${options.method || 'GET'} ${url} - ${err.message}`);
      return { status: 0, headers: {}, body: '', duration: Date.now() - start, size: 0, error: err.message };
    } finally {
      this.activeRequests--;
    }
  }

  async get(url: string, headers?: Record<string, string>): Promise<HttpResponse> {
    return this.send(url, { method: 'GET', headers });
  }

  async post(url: string, body: string, headers?: Record<string, string>): Promise<HttpResponse> {
    return this.send(url, { method: 'POST', body, headers });
  }

  async head(url: string): Promise<HttpResponse> {
    return this.send(url, { method: 'HEAD' });
  }

  async options(url: string): Promise<HttpResponse> {
    return this.send(url, { method: 'OPTIONS' });
  }

  async request(url: string, options: RequestOptions): Promise<HttpResponse> {
    return this.send(url, options);
  }

  async sendRaw(method: string, url: string, headers: Record<string, string>, body?: string): Promise<HttpResponse> {
    return this.send(url, { method, headers, body, followRedirects: false });
  }
}
