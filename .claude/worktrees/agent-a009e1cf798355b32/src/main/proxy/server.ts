import http from 'http';
import net from 'net';
import tls from 'tls';
import { URL } from 'url';
import { v4 as uuid } from 'uuid';
import Database from 'better-sqlite3';
import { BrowserWindow } from 'electron';
import { generateHostCert, exportCACert, getOrCreateCA } from './certificate';
import type { InterceptedRequest } from '../../shared/types';

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

  private async handleHttpRequest(req: http.IncomingMessage, res: http.ServerResponse) {
    const startTime = Date.now();
    const url = req.url || '/';
    const method = req.method || 'GET';
    const headers = this.flattenHeaders(req.headers);

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
        // Use modified request data
      }
    }

    try {
      const parsedUrl = new URL(url);
      const options: http.RequestOptions = {
        hostname: parsedUrl.hostname,
        port: parsedUrl.port || 80,
        path: parsedUrl.pathname + parsedUrl.search,
        method,
        headers: req.headers,
      };

      const proxyReq = http.request(options, (proxyRes) => {
        const duration = Date.now() - startTime;
        let responseBody = '';
        proxyRes.on('data', (chunk) => { responseBody += chunk; });
        proxyRes.on('end', () => {
          this.logToHistory({
            method, url, host: parsedUrl.hostname, port: parseInt(parsedUrl.port) || 80,
            is_https: false, request_headers: headers, request_body: body,
            response_status: proxyRes.statusCode || 0,
            response_headers: this.flattenHeaders(proxyRes.headers),
            response_body: responseBody,
            response_length: Buffer.byteLength(responseBody),
            content_type: (proxyRes.headers['content-type'] as string) || null,
            duration_ms: duration, intercepted: false,
          });
        });

        res.writeHead(proxyRes.statusCode || 502, proxyRes.headers);
        proxyRes.pipe(res);
      });

      proxyReq.on('error', (err) => {
        res.writeHead(502, { 'Content-Type': 'text/plain' });
        res.end(`Proxy error: ${err.message}`);
      });

      if (body) proxyReq.write(body);
      proxyReq.end();
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
    const method = req.method || 'GET';
    const headers = this.flattenHeaders(req.headers);
    let body: string | null = null;

    if (method !== 'GET' && method !== 'HEAD') {
      body = await this.readBody(req);
    }

    if (this.interceptEnabled) {
      await this.queueForIntercept({
        method,
        url: fullUrl,
        headers,
        body,
        is_https: true,
        timestamp: Date.now(),
      }, res);
    }

    try {
      const { request: undiciRequest } = await import('undici');
      const { Agent } = await import('undici');
      const agent = new Agent({ connect: { rejectUnauthorized: false } });
      const response = await undiciRequest(fullUrl, {
        method: method as any,
        headers: { ...req.headers, host: hostname },
        body: body || undefined,
        headersTimeout: 30000,
        bodyTimeout: 30000,
        dispatcher: agent,
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
