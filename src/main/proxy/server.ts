import http from 'http';
import net from 'net';
import tls from 'tls';
import { URL } from 'url';
import { v4 as uuid } from 'uuid';
import Database from 'better-sqlite3';
import { BrowserWindow } from 'electron';
import { generateHostCert, exportCACert, getOrCreateCA } from './certificate';
import { PassiveScanner } from './passive-scanner';
import type { InterceptedRequest } from '../../shared/types';
import type { Dispatcher } from 'undici';

interface QueuedRequest {
  id: string;
  clientSocket: net.Socket | http.ServerResponse;
  request: InterceptedRequest;
  resolve: (modified?: any) => void;
}

export class ProxyServer {
  private server: http.Server | null = null;
  private db: Database.Database;
  private port = 8080;
  private running = false;
  private interceptEnabled = false;
  private interceptQueue = new Map<string, QueuedRequest>();

  private passiveScanner = new PassiveScanner();

  constructor(db: Database.Database) {
    this.db = db;
  }

  start(port: number = 8080): void {
    if (this.running) return;
    this.port = port;
    getOrCreateCA();

    this.server = http.createServer((req, res) => {
      this.handleHttpRequest(req, res);
    });

    this.server.on('connect', (req: http.IncomingMessage, clientSocket: any, head: Buffer) => {
      this.handleConnect(req, clientSocket, head);
    });

    this.server.on('error', (err) => {
      console.error('[Proxy] Server error:', err.message);
    });

    this.server.listen(port, '127.0.0.1', () => {
      this.running = true;
      console.log(`[Proxy] Listening on 127.0.0.1:${port}`);
    });
  }

  stop(): void {
    if (this.server) {
      this.server.close();
      this.server = null;
    }
    this.running = false;
    this.interceptQueue.clear();
  }

  isRunning(): boolean {
    return this.running;
  }

  getPort(): number {
    return this.port;
  }

  isInterceptEnabled(): boolean {
    return this.interceptEnabled;
  }

  setInterceptEnabled(enabled: boolean): void {
    this.interceptEnabled = enabled;
    if (!enabled) {
      for (const [id] of this.interceptQueue) {
        this.forwardRequest(id);
      }
    }
  }

  getInterceptedRequests(): InterceptedRequest[] {
    return Array.from(this.interceptQueue.values()).map((q) => q.request);
  }

  forwardRequest(queueId: string, modified?: any): void {
    const queued = this.interceptQueue.get(queueId);
    if (!queued) return;
    this.interceptQueue.delete(queueId);
    queued.resolve(modified);
  }

  dropRequest(queueId: string): void {
    const queued = this.interceptQueue.get(queueId);
    if (!queued) return;
    this.interceptQueue.delete(queueId);
    if (queued.clientSocket instanceof http.ServerResponse) {
      queued.clientSocket.writeHead(502, { 'Content-Type': 'text/plain' });
      queued.clientSocket.end('Request dropped by HackMe proxy');
    } else {
      queued.clientSocket.end();
    }
  }

  exportCACertificate(outputPath: string): boolean {
    return exportCACert(outputPath);
  }

  private async getUpstreamDispatcher(): Promise<Dispatcher> {
    const { Agent, ProxyAgent } = await import('undici');
    const listRow = this.db.prepare("SELECT value FROM app_settings WHERE key = 'proxy_list'").get() as any;
    if (listRow) {
      try {
        const list = JSON.parse(listRow.value);
        if (Array.isArray(list) && list.length > 0) {
          const p = list[Math.floor(Math.random() * list.length)];
          if (p && p.host) {
            const auth = p.username && p.password ? `${encodeURIComponent(p.username)}:${encodeURIComponent(p.password)}@` : '';
            return new ProxyAgent({ uri: `http://${auth}${p.host}:${p.port}`, requestTls: { rejectUnauthorized: false } } as any);
          }
        }
      } catch {}
    }
    const singleRow = this.db.prepare("SELECT value FROM app_settings WHERE key = 'upstream_proxy'").get() as any;
    if (singleRow) {
      try {
        const p = JSON.parse(singleRow.value);
        if (p.enabled && p.host) {
          const auth = p.username && p.password ? `${encodeURIComponent(p.username)}:${encodeURIComponent(p.password)}@` : '';
          return new ProxyAgent({ uri: `http://${auth}${p.host}:${p.port}`, requestTls: { rejectUnauthorized: false } } as any);
        }
      } catch {}
    }
    return new Agent({ connect: { rejectUnauthorized: false } });
  }

  private async handleHttpRequest(req: http.IncomingMessage, res: http.ServerResponse) {
    const startTime = Date.now();
    let url = req.url || '/';
    let method = req.method || 'GET';
    let headers = this.flattenHeaders(req.headers);

    let body: string | null = null;
    if (method !== 'GET' && method !== 'HEAD') {
      body = await this.readBody(req);
    }

    if (this.interceptEnabled) {
      const modified = await this.queueForIntercept({
        method,
        url,
        headers,
        body,
        is_https: false,
        timestamp: Date.now(),
      }, res);
      if (modified) {
        if (modified.method) method = modified.method;
        if (modified.url) url = modified.url;
        if (modified.headers) headers = modified.headers;
        if (modified.body !== undefined) body = modified.body;
      }
    }

    try {
      const parsedUrl = new URL(url);
      const { request: undiciRequest } = await import('undici');
      const dispatcher = await this.getUpstreamDispatcher();

      const response = await undiciRequest(url, {
        method: method as any,
        headers: headers as any,
        body: body || undefined,
        headersTimeout: 30000,
        bodyTimeout: 30000,
        dispatcher,
      } as any);

      const responseBody = await response.body.text();
      const duration = Date.now() - startTime;
      const responseHeaders: Record<string, string> = {};
      for (const [k, v] of Object.entries(response.headers)) {
        responseHeaders[k] = Array.isArray(v) ? v.join(', ') : (v as string) || '';
      }

      this.logToHistory({
        method, url, host: parsedUrl.hostname, port: parseInt(parsedUrl.port) || 80,
        is_https: false, request_headers: headers, request_body: body,
        response_status: response.statusCode,
        response_headers: responseHeaders,
        response_body: responseBody,
        response_length: Buffer.byteLength(responseBody),
        content_type: responseHeaders['content-type'] || null,
        duration_ms: duration, intercepted: false,
      });

      const resHeaders: Record<string, string | string[]> = {};
      for (const [k, v] of Object.entries(response.headers)) {
        if (v !== undefined && k !== 'transfer-encoding') resHeaders[k] = v;
      }
      res.writeHead(response.statusCode, resHeaders);
      res.end(responseBody);
    } catch (err: any) {
      res.writeHead(502, { 'Content-Type': 'text/plain' });
      res.end(`Proxy error: ${err.message}`);
    }
  }

  private handleConnect(req: http.IncomingMessage, clientSocket: net.Socket, head: Buffer) {
    const [hostname, portStr] = (req.url || '').split(':');
    const port = parseInt(portStr) || 443;

    clientSocket.on('error', (err) => {
      console.error(`[Proxy] Client socket error (${hostname}):`, err.message);
    });

    clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');

    try {
      const { cert, key } = generateHostCert(hostname);
      const tlsSocket = new tls.TLSSocket(clientSocket, {
        isServer: true,
        cert,
        key,
      });

      tlsSocket.on('error', (err) => {
        console.error(`[Proxy] TLS error (${hostname}):`, err.message);
        tlsSocket.destroy();
      });

      if (head.length > 0) {
        tlsSocket.unshift(head);
      }

      // Parse HTTP requests from the decrypted TLS stream directly
      const httpServer = http.createServer();
      httpServer.on('request', (req2, res2) => {
        const fullUrl = `https://${hostname}${port !== 443 ? ':' + port : ''}${req2.url}`;
        this.handleMitmRequest(req2, res2, hostname, port, fullUrl);
      });
      httpServer.emit('connection', tlsSocket as any);

      // Clean up the http server when the socket closes
      tlsSocket.on('close', () => {
        httpServer.close();
      });
    } catch (err: any) {
      console.error(`[Proxy] CONNECT handler error (${hostname}):`, err.message);
      clientSocket.end();
    }
  }

  private async handleMitmRequest(
    req: http.IncomingMessage,
    res: http.ServerResponse,
    hostname: string,
    port: number,
    fullUrl: string
  ) {
    const startTime = Date.now();
    let method = req.method || 'GET';
    let headers = this.flattenHeaders(req.headers);
    let body: string | null = null;

    if (method !== 'GET' && method !== 'HEAD') {
      body = await this.readBody(req);
    }

    if (this.interceptEnabled) {
      const modified = await this.queueForIntercept({
        method,
        url: fullUrl,
        headers,
        body,
        is_https: true,
        timestamp: Date.now(),
      }, res);
      if (modified) {
        if (modified.method) method = modified.method;
        if (modified.url) fullUrl = modified.url;
        if (modified.headers) headers = modified.headers;
        if (modified.body !== undefined) body = modified.body;
      }
    }

    try {
      const { request: undiciRequest } = await import('undici');
      const dispatcher = await this.getUpstreamDispatcher();
      const response = await undiciRequest(fullUrl, {
        method: method as any,
        headers: { ...req.headers, host: hostname },
        body: body || undefined,
        headersTimeout: 30000,
        bodyTimeout: 30000,
        dispatcher,
      } as any);

      const responseBody = await response.body.text();
      const duration = Date.now() - startTime;

      const responseHeaders: Record<string, string> = {};
      for (const [k, v] of Object.entries(response.headers)) {
        responseHeaders[k] = Array.isArray(v) ? v.join(', ') : (v as string) || '';
      }

      this.logToHistory({
        method, url: fullUrl, host: hostname, port,
        is_https: true, request_headers: headers, request_body: body,
        response_status: response.statusCode,
        response_headers: responseHeaders,
        response_body: responseBody,
        response_length: Buffer.byteLength(responseBody),
        content_type: responseHeaders['content-type'] || null,
        duration_ms: duration, intercepted: this.interceptEnabled,
      });

      this.emitToRenderer('proxy:request', {
        method, url: fullUrl, status: response.statusCode,
        content_type: responseHeaders['content-type'], duration, host: hostname,
      });

      const resHeaders: Record<string, string | string[]> = {};
      for (const [k, v] of Object.entries(response.headers)) {
        if (v !== undefined && k !== 'transfer-encoding') {
          resHeaders[k] = v;
        }
      }

      res.writeHead(response.statusCode, resHeaders);
      res.end(responseBody);
    } catch (err: any) {
      res.writeHead(502, { 'Content-Type': 'text/plain' });
      res.end(`Proxy error: ${err.message}`);
    }
  }

  private queueForIntercept(request: Omit<InterceptedRequest, 'queue_id'>, clientRes: http.ServerResponse): Promise<any> {
    return new Promise((resolve) => {
      const queueId = uuid();
      const intercepted: InterceptedRequest = { ...request, queue_id: queueId };
      this.interceptQueue.set(queueId, {
        id: queueId,
        clientSocket: clientRes,
        request: intercepted,
        resolve,
      });
      this.emitToRenderer('proxy:intercept', intercepted);
    });
  }

  private logToHistory(entry: any) {
    try {
      this.db.prepare(`
        INSERT INTO proxy_history (method, url, host, port, is_https, request_headers, request_body,
          response_status, response_headers, response_body, response_length, content_type, duration_ms, intercepted)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        entry.method, entry.url, entry.host, entry.port, entry.is_https ? 1 : 0,
        JSON.stringify(entry.request_headers), entry.request_body,
        entry.response_status, JSON.stringify(entry.response_headers),
        entry.response_body, entry.response_length, entry.content_type,
        entry.duration_ms, entry.intercepted ? 1 : 0
      );

      // Run passive scanner on the traffic entry
      const passiveFindings = this.passiveScanner.analyze({
        method: entry.method,
        url: entry.url,
        host: entry.host,
        request_headers: entry.request_headers,
        response_status: entry.response_status,
        response_headers: entry.response_headers,
        response_body: entry.response_body,
      });

      for (const finding of passiveFindings) {
        this.emitToRenderer('proxy:passiveFinding', finding);
      }
    } catch (err) {
      console.error('[Proxy] Failed to log history:', err);
    }
  }

  private flattenHeaders(headers: http.IncomingHttpHeaders): Record<string, string> {
    const flat: Record<string, string> = {};
    for (const [k, v] of Object.entries(headers)) {
      flat[k] = Array.isArray(v) ? v.join(', ') : v || '';
    }
    return flat;
  }

  private readBody(req: http.IncomingMessage): Promise<string> {
    return new Promise((resolve) => {
      const chunks: Buffer[] = [];
      req.on('data', (chunk) => chunks.push(chunk));
      req.on('end', () => resolve(Buffer.concat(chunks).toString()));
      req.on('error', () => resolve(''));
    });
  }

  private emitToRenderer(channel: string, data: any) {
    const wins = BrowserWindow.getAllWindows();
    for (const win of wins) {
      win.webContents.send(channel, data);
    }
  }
}
