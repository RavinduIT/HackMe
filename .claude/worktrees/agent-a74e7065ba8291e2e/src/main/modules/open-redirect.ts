import type { ScanModuleInterface, EndpointInfo, ModuleFinding } from '../scanner/orchestrator';
import type { HttpClient } from '../scanner/http-client';

const REDIRECT_PARAMS = ['url', 'redirect', 'redirect_uri', 'return', 'return_url', 'returnTo', 'next', 'goto', 'target', 'dest', 'destination', 'rurl', 'out', 'view', 'login', 'link', 'forward', 'continue', 'callback'];
const REDIRECT_PAYLOADS = [
  'https://evil.com',
  '//evil.com',
  '/\\evil.com',
  'https://evil.com%2F%2F',
  'https://evil.com@legitimate.com',
  '////evil.com',
  'https:evil.com',
  'http://evil.com%E3%80%82legitimate.com',
];

export class OpenRedirectModule implements ScanModuleInterface {
  id = 'open-redirect';
  name = 'Open Redirect';

  async scan(url: string, endpoints: EndpointInfo[], client: HttpClient): Promise<ModuleFinding[]> {
    const findings: ModuleFinding[] = [];
    const tested = new Set<string>();

    for (const ep of endpoints) {
      const allParams = [...ep.params, ...REDIRECT_PARAMS];
      const uniqueParams = [...new Set(allParams)];

      for (const param of uniqueParams) {
        const key = `${ep.url}:${param}`;
        if (tested.has(key)) continue;
        tested.add(key);

        for (const payload of REDIRECT_PAYLOADS) {
          const u = new URL(ep.url);
          u.searchParams.set(param, payload);
          const res = await client.send(u.href, { followRedirects: false });

          if ([301, 302, 303, 307, 308].includes(res.status)) {
            const location = res.headers['location'] || '';
            if (location.includes('evil.com')) {
              findings.push({
                severity: 'medium',
                title: 'Open Redirect',
                description: `The parameter "${param}" allows redirection to external domains. The server responded with ${res.status} redirecting to "${location}". Attackers use open redirects for phishing, OAuth token theft, and bypassing domain-based security controls.`,
                url: ep.url, parameter: param,
                remediation: 'Validate redirect URLs against an allowlist. Only allow relative paths or same-domain redirects.',
                cwe_id: 'CWE-601', owasp_category: 'A01:2021', cvss_score: 4.7,
                evidence: { payload, redirect_status: res.status, location },
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
