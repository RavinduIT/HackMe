import type { ScanModuleInterface, EndpointInfo, ModuleFinding } from '../scanner/orchestrator';
import type { HttpClient } from '../scanner/http-client';
import { expandEndpoint } from './_params';

const SSTI_PROBES = [
  { payload: '{{7*7}}', expected: '49', engines: ['Jinja2', 'Twig', 'Nunjucks', 'Django'] },
  { payload: '${7*7}', expected: '49', engines: ['Freemarker', 'Velocity', 'Spring EL', 'Mako'] },
  { payload: '#{7*7}', expected: '49', engines: ['Ruby ERB', 'Pebble', 'Thymeleaf'] },
  { payload: '<%= 7*7 %>', expected: '49', engines: ['EJS', 'ERB', 'Slim'] },
  { payload: '{{7*\'7\'}}', expected: '7777777', engines: ['Jinja2'] },
  { payload: '{{7*\'7\'}}', expected: '49', engines: ['Twig'] },
  { payload: '${7*7}', expected: '49', engines: ['Freemarker'] },
  { payload: '#set($x=7*7)${x}', expected: '49', engines: ['Velocity'] },
  { payload: '@(7*7)', expected: '49', engines: ['Razor'] },
  { payload: '{{= 7*7}}', expected: '49', engines: ['doT.js'] },
  { payload: '[= 7*7]', expected: '49', engines: ['Smarty'] },
  { payload: '{7*7}', expected: '49', engines: ['Smarty'] },
];

export class SstiModule implements ScanModuleInterface {
  id = 'ssti';
  name = 'Template Injection (SSTI)';

  async scan(url: string, endpoints: EndpointInfo[], client: HttpClient): Promise<ModuleFinding[]> {
    const findings: ModuleFinding[] = [];
    const tested = new Set<string>();

    for (const rawEp of endpoints) {
      const expanded = expandEndpoint(rawEp);
      for (const ep of expanded) {
        if (ep.params.length === 0) continue;

        for (const param of ep.params) {
          const key = `${ep.url}:${param}`;
          if (tested.has(key)) continue;
          tested.add(key);

          for (const { payload, expected, engines } of SSTI_PROBES) {
            const res = await this.inject(ep, param, payload, client);
            if (res.status === 0) continue;

            if (res.body.includes(expected) && !res.body.includes(payload)) {
              findings.push({
                severity: 'critical',
                title: `Server-Side Template Injection (${engines.join('/')})`,
                description: `The parameter "${param}" is vulnerable to SSTI. The expression "${payload}" was evaluated server-side and returned "${expected}". This typically leads to Remote Code Execution. Likely template engine: ${engines.join(' or ')}.`,
                url: ep.url, parameter: param,
                remediation: 'Never pass user input directly into template expressions. Use sandboxed template contexts and restrict available functions.',
                cwe_id: 'CWE-94', owasp_category: 'A03:2021', cvss_score: 9.8,
                evidence: { payload, expected, possible_engines: engines },
              });
              break;
            }
          }
        }
      }
    }
    return findings;
  }

  private async inject(ep: EndpointInfo, param: string, payload: string, client: HttpClient) {
    if (ep.method === 'GET') {
      const u = new URL(ep.url);
      u.searchParams.set(param, payload);
      return client.get(u.href);
    }
    const body = ep.params.map((p) => `${encodeURIComponent(p)}=${encodeURIComponent(p === param ? payload : 'test')}`).join('&');
    return client.post(ep.url, body, { 'Content-Type': 'application/x-www-form-urlencoded' });
  }
}
