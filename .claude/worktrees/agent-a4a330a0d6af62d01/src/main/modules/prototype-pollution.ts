import type { ScanModuleInterface, EndpointInfo, ModuleFinding } from '../scanner/orchestrator';
import type { HttpClient } from '../scanner/http-client';

export class PrototypePollutionModule implements ScanModuleInterface {
  id = 'prototype-pollution';
  name = 'Prototype Pollution';

  async scan(url: string, endpoints: EndpointInfo[], client: HttpClient): Promise<ModuleFinding[]> {
    const findings: ModuleFinding[] = [];

    // Test JSON body endpoints for server-side prototype pollution
    const jsonEndpoints = endpoints.filter((ep) => ep.method === 'POST' && (ep.contentType.includes('json') || ep.params.length > 0));

    for (const ep of jsonEndpoints) {
      const payloads: { body: any; desc: string }[] = [
        { body: JSON.parse('{"__proto__":{"polluted":"hm_pp_test"}}'), desc: '__proto__' },
        { body: JSON.parse('{"constructor":{"prototype":{"polluted":"hm_pp_test"}}}'), desc: 'constructor.prototype' },
      ];

      for (const { body, desc } of payloads) {
        // Merge with existing params
        const fullBody: any = {};
        for (const p of ep.params) fullBody[p] = 'test';
        Object.assign(fullBody, body);

        const res = await client.post(ep.url, JSON.stringify(fullBody), { 'Content-Type': 'application/json' });

        // Check if the pollution affected the response
        if (res.status === 500 || res.body.includes('polluted') || res.body.includes('hm_pp_test')) {
          findings.push({
            severity: 'high',
            title: `Server-Side Prototype Pollution (${desc})`,
            description: `The endpoint "${ep.url}" may be vulnerable to prototype pollution via ${desc}. The server processed a JSON object with prototype-modifying keys. If the application uses object merge/extend functions without sanitization, attackers can modify application behavior, bypass security checks, or achieve RCE.`,
            url: ep.url,
            remediation: 'Sanitize JSON input — reject or strip keys like __proto__, constructor, prototype. Use Object.create(null) for lookup maps. Use Map instead of plain objects.',
            cwe_id: 'CWE-1321', owasp_category: 'A03:2021', cvss_score: 7.5,
            evidence: { payload: desc, body: JSON.stringify(body) },
          });
          break;
        }
      }
    }

    // Test URL parameter pollution (client-side via query string)
    const u = new URL(url);
    u.searchParams.set('__proto__[polluted]', 'hm_pp_test');
    const paramRes = await client.get(u.href);
    if (paramRes.body.includes('hm_pp_test')) {
      findings.push({
        severity: 'medium',
        title: 'Client-Side Prototype Pollution via URL Parameters',
        description: 'The page processes URL parameters in a way that allows prototype pollution. The value injected via __proto__[polluted] appeared in the response, indicating a JavaScript object merge function parses query parameters unsafely.',
        url,
        remediation: 'Use a URL parameter parser that ignores __proto__ and constructor keys. Libraries like qs have prototype pollution protection built in.',
        cwe_id: 'CWE-1321', owasp_category: 'A03:2021', cvss_score: 6.1,
        evidence: { payload: '__proto__[polluted]=hm_pp_test' },
      });
    }

    return findings;
  }
}
