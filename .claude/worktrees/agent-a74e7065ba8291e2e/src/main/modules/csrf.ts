import type { ScanModuleInterface, EndpointInfo, ModuleFinding } from '../scanner/orchestrator';
import type { HttpClient } from '../scanner/http-client';

export class CsrfModule implements ScanModuleInterface {
  id = 'csrf';
  name = 'CSRF Detection';

  async scan(url: string, endpoints: EndpointInfo[], client: HttpClient): Promise<ModuleFinding[]> {
    const findings: ModuleFinding[] = [];

    const postEndpoints = endpoints.filter((ep) => ['POST', 'PUT', 'DELETE', 'PATCH'].includes(ep.method));

    for (const ep of postEndpoints) {
      // Skip CSRF check for API endpoints with alternative protection
      if (ep.contentType.includes('json') || ep.url.includes('/api/') || ep.url.includes('/graphql')) continue;

      const csrfParams = ep.params.filter((p) =>
        /csrf|token|_token|csrfmiddlewaretoken|authenticity_token|__RequestVerificationToken|_csrf/i.test(p)
      );

      if (csrfParams.length === 0) {
        findings.push({
          severity: 'medium',
          title: 'Missing CSRF Token',
          description: `The ${ep.method} endpoint "${ep.url}" has no CSRF token parameter. State-changing requests without CSRF protection can be triggered by a malicious website if the user is authenticated.`,
          url: ep.url,
          remediation: 'Include a CSRF token in all state-changing forms and validate it server-side. Use SameSite=Strict cookies as defense-in-depth.',
          cwe_id: 'CWE-352', owasp_category: 'A01:2021', cvss_score: 4.3,
          evidence: { method: ep.method, params: ep.params },
        });
      }
    }

    // Check SameSite cookie attribute (already in headers module but we add context here)
    const mainRes = await client.get(url);
    const cookies = mainRes.headers['set-cookie'];
    if (cookies && !cookies.toLowerCase().includes('samesite')) {
      findings.push({
        severity: 'low',
        title: 'Session Cookie Missing SameSite Attribute',
        description: 'The session cookie does not set SameSite. Without SameSite, the cookie is sent with cross-origin requests, making CSRF attacks possible even if tokens are used.',
        url,
        remediation: 'Set SameSite=Lax or SameSite=Strict on session cookies.',
        cwe_id: 'CWE-1275', owasp_category: 'A01:2021', cvss_score: 3.1,
      });
    }

    return findings;
  }
}
