import type { ScanModuleInterface, EndpointInfo, ModuleFinding } from '../scanner/orchestrator';
import type { HttpClient } from '../scanner/http-client';

const ERROR_PATTERNS = [
  { db: 'MySQL', patterns: [/you have an error in your sql syntax/i, /warning: mysql/i, /unclosed quotation mark/i, /mysql_fetch/i, /mysqli?_/i, /MariaDB/i] },
  { db: 'PostgreSQL', patterns: [/pg_query\(\)/i, /pg_exec\(\)/i, /psql:/i, /unterminated quoted string/i, /syntax error at or near/i, /ERROR:\s+syntax error/i] },
  { db: 'MSSQL', patterns: [/unclosed quotation mark after/i, /mssql_query\(\)/i, /microsoft sql server/i, /odbc sql server driver/i, /\[Microsoft\]\[ODBC/i, /SQL Server/i] },
  { db: 'Oracle', patterns: [/ORA-\d{5}/i, /oracle error/i, /quoted string not properly terminated/i, /oracle.*driver/i] },
  { db: 'SQLite', patterns: [/sqlite3?\.OperationalError/i, /unrecognized token/i, /SQLITE_ERROR/i, /near ".*": syntax error/i, /SQLite\/JDBCDriver/i] },
];

const ERROR_PAYLOADS = ["'", "''", '"', '`', "' OR '1'='1", "' OR '1'='1' --", "1' ORDER BY 1--", "1' UNION SELECT NULL--", "') OR ('1'='1"];
const BOOLEAN_TRUE = ["' OR '1'='1' --", "1 OR 1=1", "' OR 1=1 --"];
const BOOLEAN_FALSE = ["' AND '1'='2' --", "1 AND 1=2", "' AND 0 --"];
const TIME_PAYLOADS = [
  { payload: "' AND SLEEP(3)--", db: 'MySQL', delay: 3 },
  { payload: "'; WAITFOR DELAY '0:0:3'--", db: 'MSSQL', delay: 3 },
  { payload: "' AND pg_sleep(3)--", db: 'PostgreSQL', delay: 3 },
  { payload: "' AND 1=randomblob(300000000)--", db: 'SQLite', delay: 3 },
];

export class SqlInjectionModule implements ScanModuleInterface {
  id = 'sql-injection';
  name = 'SQL Injection';

  async scan(url: string, endpoints: EndpointInfo[], client: HttpClient): Promise<ModuleFinding[]> {
    const findings: ModuleFinding[] = [];
    const tested = new Set<string>();

    for (const ep of endpoints) {
      if (ep.params.length === 0) continue;

      for (const param of ep.params) {
        const key = `${ep.url}:${param}`;
        if (tested.has(key)) continue;
        tested.add(key);

        // Error-based detection
        const errorResult = await this.testErrorBased(ep, param, client);
        if (errorResult) { findings.push(errorResult); continue; }

        // Boolean-based blind detection
        const boolResult = await this.testBooleanBlind(ep, param, client);
        if (boolResult) { findings.push(boolResult); continue; }

        // Time-based blind detection
        const timeResult = await this.testTimeBlind(ep, param, client);
        if (timeResult) { findings.push(timeResult); continue; }
      }
    }

    return findings;
  }

  private async testErrorBased(ep: EndpointInfo, param: string, client: HttpClient): Promise<ModuleFinding | null> {
    for (const payload of ERROR_PAYLOADS) {
      const res = await this.sendWithPayload(ep, param, payload, client);
      if (res.status === 0) continue;

      for (const { db, patterns } of ERROR_PATTERNS) {
        for (const pattern of patterns) {
          if (pattern.test(res.body)) {
            return {
              severity: 'critical', title: `SQL Injection (Error-Based) — ${db}`,
              description: `The parameter "${param}" is vulnerable to error-based SQL injection. The ${db} database returned a syntax error when injected with a single quote, confirming unsanitized input is concatenated directly into SQL queries.`,
              url: ep.url, parameter: param,
              remediation: 'Use parameterized queries (prepared statements). Never concatenate user input into SQL strings.',
              cwe_id: 'CWE-89', owasp_category: 'A03:2021', cvss_score: 9.8,
              evidence: { payload, db_type: db, error_match: res.body.match(pattern)?.[0] },
            };
          }
        }
      }
    }
    return null;
  }

  private async testBooleanBlind(ep: EndpointInfo, param: string, client: HttpClient): Promise<ModuleFinding | null> {
    const baseline = await this.sendWithPayload(ep, param, 'normalvalue', client);
    if (baseline.status === 0) return null;

    for (let i = 0; i < BOOLEAN_TRUE.length; i++) {
      const trueRes = await this.sendWithPayload(ep, param, BOOLEAN_TRUE[i], client);
      const falseRes = await this.sendWithPayload(ep, param, BOOLEAN_FALSE[i], client);

      if (trueRes.status === 0 || falseRes.status === 0) continue;

      const trueDiff = Math.abs(trueRes.size - baseline.size);
      const falseDiff = Math.abs(falseRes.size - baseline.size);
      const tfDiff = Math.abs(trueRes.size - falseRes.size);

      if (tfDiff > 50 && trueDiff < tfDiff && trueRes.status === baseline.status) {
        return {
          severity: 'critical', title: 'SQL Injection (Boolean-Based Blind)',
          description: `The parameter "${param}" shows different responses for always-true vs always-false SQL conditions. The true condition returned ${trueRes.size} bytes while the false condition returned ${falseRes.size} bytes (${tfDiff} byte difference), indicating the injected condition is evaluated within a SQL query.`,
          url: ep.url, parameter: param,
          remediation: 'Use parameterized queries. Validate and sanitize all user inputs.',
          cwe_id: 'CWE-89', owasp_category: 'A03:2021', cvss_score: 9.8,
          evidence: { true_payload: BOOLEAN_TRUE[i], false_payload: BOOLEAN_FALSE[i], true_size: trueRes.size, false_size: falseRes.size },
        };
      }
    }
    return null;
  }

  private async testTimeBlind(ep: EndpointInfo, param: string, client: HttpClient): Promise<ModuleFinding | null> {
    const baseline = await this.sendWithPayload(ep, param, 'normalvalue', client);
    if (baseline.status === 0) return null;

    for (const { payload, db, delay } of TIME_PAYLOADS) {
      const res = await this.sendWithPayload(ep, param, payload, client);
      if (res.duration > (delay * 1000 - 500) && res.duration > baseline.duration + 2000) {
        return {
          severity: 'critical', title: `SQL Injection (Time-Based Blind) — ${db}`,
          description: `The parameter "${param}" appears vulnerable to time-based blind SQL injection. A SLEEP/WAITFOR payload caused a ${(res.duration / 1000).toFixed(1)}s response delay (baseline: ${(baseline.duration / 1000).toFixed(1)}s), indicating the injected SQL was executed.`,
          url: ep.url, parameter: param,
          remediation: 'Use parameterized queries. Never concatenate user input into SQL.',
          cwe_id: 'CWE-89', owasp_category: 'A03:2021', cvss_score: 9.8,
          evidence: { payload, db_type: db, response_time_ms: res.duration, baseline_ms: baseline.duration },
        };
      }
    }
    return null;
  }

  private async sendWithPayload(ep: EndpointInfo, param: string, payload: string, client: HttpClient) {
    if (ep.method === 'GET') {
      const u = new URL(ep.url);
      u.searchParams.set(param, payload);
      return client.send(u.href, { timeout: 10000 });
    }
    if (ep.contentType?.includes('json')) {
      const obj: Record<string, string> = {};
      for (const p of ep.params) obj[p] = p === param ? payload : 'test';
      return client.post(ep.url, JSON.stringify(obj), { 'Content-Type': 'application/json' });
    }
    const body = ep.params.map((p) => `${encodeURIComponent(p)}=${encodeURIComponent(p === param ? payload : 'test')}`).join('&');
    return client.post(ep.url, body, { 'Content-Type': 'application/x-www-form-urlencoded' });
  }
}
