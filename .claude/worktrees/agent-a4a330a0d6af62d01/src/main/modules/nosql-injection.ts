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
      for (const param of ep.params) {
        const u = new URL(ep.url);
        const baseline = await client.get(ep.url);

        // $ne operator in query string
        u.searchParams.delete(param);
        u.searchParams.set(`${param}[$ne]`, '');
        const neRes = await client.get(u.href);

        if (neRes.status === 200 && neRes.size !== baseline.size && Math.abs(neRes.size - baseline.size) > 50) {
          findings.push({
            severity: 'critical', title: 'NoSQL Injection (Query Operator)',
            description: `The parameter "${param}" accepts MongoDB query operators. Injecting "${param}[$ne]=" produced a different response (${neRes.size} bytes vs ${baseline.size} bytes baseline). An attacker can bypass authentication or extract data using operators like $gt, $regex, $where.`,
            url: ep.url, parameter: param,
            remediation: 'Validate input types strictly. Reject objects/arrays where strings are expected. Use an ORM with type checking.',
            cwe_id: 'CWE-943', owasp_category: 'A03:2021', cvss_score: 9.1,
            evidence: { payload: `${param}[$ne]=`, baseline_size: baseline.size, injected_size: neRes.size },
          });
        }
      }

      // Test JSON body injection for POST endpoints
      if (ep.method === 'POST' && ep.contentType.includes('json')) {
        const payloads = [
          { desc: '$ne operator', body: ep.params.reduce((o: any, p) => { o[p] = { '$ne': '' }; return o; }, {}) },
          { desc: '$gt operator', body: ep.params.reduce((o: any, p) => { o[p] = { '$gt': '' }; return o; }, {}) },
          { desc: '$regex operator', body: ep.params.reduce((o: any, p) => { o[p] = { '$regex': '.*' }; return o; }, {}) },
        ];

        const baseline = await client.post(ep.url, JSON.stringify(ep.params.reduce((o: any, p) => { o[p] = 'test'; return o; }, {})),
          { 'Content-Type': 'application/json' });

        for (const { desc, body } of payloads) {
          const res = await client.post(ep.url, JSON.stringify(body), { 'Content-Type': 'application/json' });
          if (res.status === 200 && res.size !== baseline.size && Math.abs(res.size - baseline.size) > 50) {
            findings.push({
              severity: 'critical', title: `NoSQL Injection (${desc})`,
              description: `The JSON body accepts MongoDB operators. Injecting ${desc} produced a different response, indicating the object is passed directly to a MongoDB query without sanitization.`,
              url: ep.url,
              remediation: 'Sanitize JSON input. Strip keys starting with $ from user-provided objects. Use mongoose schema validation.',
              cwe_id: 'CWE-943', owasp_category: 'A03:2021', cvss_score: 9.1,
              evidence: { payload: JSON.stringify(body), baseline_size: baseline.size, injected_size: res.size },
            });
            break;
          }
        }
      }
    }
    return findings;
  }
}
