import type { ScanModuleInterface, EndpointInfo, ModuleFinding } from '../scanner/orchestrator';
import type { HttpClient } from '../scanner/http-client';

export class NosqlInjectionModule implements ScanModuleInterface {
  id = 'nosql-injection';
  name = 'NoSQL Injection';

  async scan(url: string, endpoints: EndpointInfo[], client: HttpClient): Promise<ModuleFinding[]> {
    const findings: ModuleFinding[] = [];

    for (const ep of endpoints) {
      if (ep.params.length === 0) continue;

      // Test query parameter operator injection (e.g., username[$ne]=&password[$ne]=)
      const baseline = await client.get(ep.url);

      for (const param of ep.params) {
        // $ne operator in query string
        const neUrl = new URL(ep.url);
        neUrl.searchParams.delete(param);
        neUrl.searchParams.set(`${param}[$ne]`, '');
        const neRes = await client.get(neUrl.href);

        if (neRes.status === 200 && neRes.size !== baseline.size && Math.abs(neRes.size - baseline.size) > 50) {
          findings.push({
            severity: 'critical', title: 'NoSQL Injection (Query Operator $ne)',
            description: `The parameter "${param}" accepts MongoDB query operators. Injecting "${param}[$ne]=" produced a different response (${neRes.size} bytes vs ${baseline.size} bytes baseline). An attacker can bypass authentication or extract data using operators like $gt, $regex, $where.`,
            url: ep.url, parameter: param,
            remediation: 'Validate input types strictly. Reject objects/arrays where strings are expected. Use an ORM with type checking.',
            cwe_id: 'CWE-943', owasp_category: 'A03:2021', cvss_score: 9.1,
            evidence: { payload: `${param}[$ne]=`, baseline_size: baseline.size, injected_size: neRes.size },
          });
        }

        // Additional query string operators
        const additionalOps = [
          { op: '[$gt]', value: '' },
          { op: '[$regex]', value: '.*' },
          { op: '[$exists]', value: 'true' },
        ];
        for (const { op, value } of additionalOps) {
          const opUrl = new URL(ep.url);
          opUrl.searchParams.delete(param);
          opUrl.searchParams.set(`${param}${op}`, value);
          const opRes = await client.get(opUrl.href);
          if (opRes.status === 200 && Math.abs(opRes.size - baseline.size) > 50) {
            findings.push({
              severity: 'critical', title: `NoSQL Injection (Query Operator ${op})`,
              description: `The parameter "${param}" accepts MongoDB query operator ${op}. The response differed from baseline (${opRes.size} vs ${baseline.size} bytes).`,
              url: ep.url, parameter: param,
              remediation: 'Validate input types strictly. Reject objects/arrays where strings are expected. Use an ORM with type checking.',
              cwe_id: 'CWE-943', owasp_category: 'A03:2021', cvss_score: 9.1,
              evidence: { payload: `${param}${op}=${value}`, baseline_size: baseline.size, injected_size: opRes.size },
            });
            break;
          }
        }

        // Error-based detection: send quote characters and look for MongoDB errors
        for (const char of ["'", '"']) {
          const errUrl = new URL(ep.url);
          errUrl.searchParams.set(param, char);
          const errRes = await client.get(errUrl.href);
          const mongoErrors = ['MongoError', 'E11000', 'BSONTypeError'];
          for (const errPattern of mongoErrors) {
            if (errRes.body.includes(errPattern)) {
              findings.push({
                severity: 'high', title: `NoSQL Error Disclosure (${errPattern})`,
                description: `Injecting "${char}" into parameter "${param}" triggered a MongoDB error "${errPattern}" in the response. This confirms a NoSQL backend and suggests unsanitized input.`,
                url: ep.url, parameter: param,
                remediation: 'Sanitize all user input before passing to database queries. Suppress detailed error messages in production.',
                cwe_id: 'CWE-943', owasp_category: 'A03:2021', cvss_score: 7.5,
                evidence: { payload: char, error_pattern: errPattern },
              });
              break;
            }
          }
        }
      }

      // Test JSON body injection for POST endpoints
      if (ep.method === 'POST' && ep.contentType.includes('json')) {
        const jsonBaseline = await client.post(ep.url, JSON.stringify(ep.params.reduce((o: any, p) => { o[p] = 'test'; return o; }, {})),
          { 'Content-Type': 'application/json' });

        const payloads = [
          { desc: '$ne operator', body: ep.params.reduce((o: any, p) => { o[p] = { '$ne': '' }; return o; }, {}) },
          { desc: '$gt operator', body: ep.params.reduce((o: any, p) => { o[p] = { '$gt': '' }; return o; }, {}) },
          { desc: '$regex operator', body: ep.params.reduce((o: any, p) => { o[p] = { '$regex': '.*' }; return o; }, {}) },
          { desc: '$exists operator', body: ep.params.reduce((o: any, p) => { o[p] = { '$exists': true }; return o; }, {}) },
          { desc: '$or auth bypass', body: { '$or': [{}, { 'a': 'a' }] } },
        ];

        for (const { desc, body } of payloads) {
          const res = await client.post(ep.url, JSON.stringify(body), { 'Content-Type': 'application/json' });
          if (res.status === 200 && res.size !== jsonBaseline.size && Math.abs(res.size - jsonBaseline.size) > 50) {
            findings.push({
              severity: 'critical', title: `NoSQL Injection (${desc})`,
              description: `The JSON body accepts MongoDB operators. Injecting ${desc} produced a different response, indicating the object is passed directly to a MongoDB query without sanitization.`,
              url: ep.url,
              remediation: 'Sanitize JSON input. Strip keys starting with $ from user-provided objects. Use mongoose schema validation.',
              cwe_id: 'CWE-943', owasp_category: 'A03:2021', cvss_score: 9.1,
              evidence: { payload: JSON.stringify(body), baseline_size: jsonBaseline.size, injected_size: res.size },
            });
            break;
          }
        }

        // Time-based $where injection
        const wherePayload = JSON.stringify({ '$where': 'sleep(2000)' });
        const whereStart = Date.now();
        const whereRes = await client.post(ep.url, wherePayload, { 'Content-Type': 'application/json' });
        const whereDuration = Date.now() - whereStart;
        if (whereRes.status !== 0 && whereDuration > 2000) {
          findings.push({
            severity: 'critical', title: 'NoSQL Injection ($where Time-Based)',
            description: `The endpoint accepted a $where operator with sleep(). Response took ${whereDuration}ms, indicating server-side JavaScript execution in the database query.`,
            url: ep.url,
            remediation: 'Disable $where in MongoDB queries. Use mongo-sanitize or similar input validation.',
            cwe_id: 'CWE-943', owasp_category: 'A03:2021', cvss_score: 9.8,
            evidence: { payload: wherePayload, response_time_ms: whereDuration },
          });
        }

        // Error-based detection for JSON endpoints
        for (const char of ["'", '"']) {
          const errBody = ep.params.reduce((o: any, p) => { o[p] = char; return o; }, {} as any);
          const errRes = await client.post(ep.url, JSON.stringify(errBody), { 'Content-Type': 'application/json' });
          const mongoErrors = ['MongoError', 'E11000', 'BSONTypeError'];
          for (const errPattern of mongoErrors) {
            if (errRes.body.includes(errPattern)) {
              findings.push({
                severity: 'high', title: `NoSQL Error Disclosure (${errPattern})`,
                description: `Injecting "${char}" into the JSON body triggered a MongoDB error "${errPattern}". This confirms a NoSQL backend and suggests unsanitized input.`,
                url: ep.url,
                remediation: 'Sanitize all user input before passing to database queries. Suppress detailed error messages in production.',
                cwe_id: 'CWE-943', owasp_category: 'A03:2021', cvss_score: 7.5,
                evidence: { payload: char, error_pattern: errPattern },
              });
              break;
            }
          }
        }
      }
    }
    return findings;
  }
}
