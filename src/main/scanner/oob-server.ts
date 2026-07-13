import http from 'http';
import dns from 'dns';
import { BrowserWindow } from 'electron';

interface OobCallback {
  id: string;
  type: 'http' | 'dns';
  sourceIp: string;
  timestamp: number;
  details: string;
}

export class OobServer {
  private server: http.Server | null = null;
  private port = 9999;
  private running = false;
  private callbacks = new Map<string, OobCallback[]>();
  private pendingChecks = new Map<string, { module: string; title: string; url: string; payload: string }>();
  private interactshSession: string | null = null;

  generateId(): string {
    const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
    let id = 'hm';
    for (let i = 0; i < 10; i++) id += chars[Math.floor(Math.random() * chars.length)];
    return id;
  }

  getCallbackUrl(id: string): string {
    return `http://127.0.0.1:${this.port}/cb/${id}`;
  }

  registerCheck(id: string, meta: { module: string; title: string; url: string; payload: string }) {
    this.pendingChecks.set(id, meta);
  }

  getCallbacks(id: string): OobCallback[] {
    return this.callbacks.get(id) || [];
  }

  hasCallback(id: string): boolean {
    return (this.callbacks.get(id)?.length || 0) > 0;
  }

  start(port: number = 9999): void {
    if (this.running) return;
    this.port = port;

    this.server = http.createServer((req, res) => {
      const url = req.url || '/';
      const match = url.match(/\/cb\/([a-z0-9]+)/);

      if (match) {
        const id = match[1];
        const callback: OobCallback = {
          id,
          type: 'http',
          sourceIp: req.socket.remoteAddress || 'unknown',
          timestamp: Date.now(),
          details: `${req.method} ${url} from ${req.socket.remoteAddress} — User-Agent: ${req.headers['user-agent'] || 'none'}`,
        };

        if (!this.callbacks.has(id)) this.callbacks.set(id, []);
        this.callbacks.get(id)!.push(callback);

        console.log(`[OOB] HTTP callback received for ${id} from ${req.socket.remoteAddress}`);
        this.emitCallback(id, callback);
      }

      res.writeHead(200, { 'Content-Type': 'text/plain' });
      res.end('ok');
    });

    this.server.listen(port, '0.0.0.0', () => {
      this.running = true;
      console.log(`[OOB] Callback server listening on 0.0.0.0:${port}`);
    });

    this.server.on('error', (err: any) => {
      if (err.code === 'EADDRINUSE') {
        console.log(`[OOB] Port ${port} in use, trying ${port + 1}`);
        this.port = port + 1;
        this.server?.listen(port + 1, '0.0.0.0');
      }
    });
  }

  stop(): void {
    if (this.server) {
      this.server.close();
      this.server = null;
    }
    this.running = false;
    this.callbacks.clear();
    this.pendingChecks.clear();
  }

  isRunning(): boolean { return this.running; }
  getPort(): number { return this.port; }

  getPendingResults(): { id: string; meta: any; received: boolean; callbacks: OobCallback[] }[] {
    const results: any[] = [];
    for (const [id, meta] of this.pendingChecks) {
      results.push({
        id, meta,
        received: this.hasCallback(id),
        callbacks: this.getCallbacks(id),
      });
    }
    return results;
  }

  private emitCallback(id: string, callback: OobCallback) {
    const meta = this.pendingChecks.get(id);
    for (const win of BrowserWindow.getAllWindows()) {
      win.webContents.send('oob:callback', { id, callback, meta });
    }
  }
}

let globalOobServer: OobServer | null = null;

export function getOobServer(): OobServer {
  if (!globalOobServer) {
    globalOobServer = new OobServer();
  }
  return globalOobServer;
}
