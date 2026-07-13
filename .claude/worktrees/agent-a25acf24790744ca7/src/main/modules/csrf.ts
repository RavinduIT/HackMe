import type { ScanModuleInterface, EndpointInfo, ModuleFinding } from '../scanner/orchestrator';
import type { HttpClient } from '../scanner/http-client';

export class CsrfModule implements ScanModuleInterface {
  id = 'csrf';
  name = 'CSRF Detection';

  async scan(url: string, endpoints: EndpointInfo[], client: HttpClient): Promise<ModuleFinding[]> {
    const findings: ModuleFinding[] = [];

    const postEndpoints = endpoints.filter((ep) => ['POST', 'PUT', 'DELETE', 'PATCH'].includes(ep.method));

    for (const ep of postEndpoints) {
      const csrfParams = ep.params.filter((p) =>
        /csrf|token|_token|csrfmiddlewaretoken|authenticity_token|__RequestVerificationToken|_csrf/i.test(p)
      );

      if (csrfParams.length === 0) {
        findings.push({
          severity: 'info',
          title: 'Missing CSRF Token',
          description: `The ${ep.method} endpoint "${ep.url}" has no CSRF token parameter. State-changing requests without CSRF protection can be triggered by a malicious website if the user is authenticated.`,
          url: ep.url,
          remediation: 'Include a CSRF token in all state-changing forms and validate it server-side. Use SameSite=Strict cookies as defense-in-depth.',
          cwe_id: 'CWE-352', owasp_category: 'A01:2021', cvss_score: 4.3,
          evidence: { method: ep.method, params: ep.params },
        });
      } else {
        // Validate that the CSRF token is actually checked server-side
        const csrfParam = csrfParams[0];

        // Send baseline request with a normal token value
        const baselineBody = ep.params.map(p => `${encodeURIComponent(p)}=${encodeURIComponent('test')}`).join('&');
        const baselineRes = await client.post(ep.url, baselineBody, { 'Content-Type': 'application/x-www-form-urlencoded' });

        // Send request with invalid CSRF token
        const invalidBody = ep.params.map(p => {
          if (p === csrfParam) return `${encodeURIComponent(p)}=${encodeURIComponent('invalid_csrf_test_value')}`;
          return `${encodeURIComponent(p)}=${encodeURIComponent('test')}`;
        }).join('&');
        const invalidRes = await client.post(ep.url, invalidBody, { 'Content-Type': 'application/x-www-form-urlencoded' });

        // If the server returns 200 for the invalid token (same as baseline), CSRF is not validated
        if (invalidRes.status === 200 && baselineRes.status === 200 && Math.abs(invalidRes.size - baselineRes.size) < 100) {
          findings.push({
            severity: 'medium',
            title: 'CSRF Token Not Validated Server-Side',
            description: `The ${ep.method} endpoint "${ep.url}" has a CSRF token parameter "${csrfParam}" but does not validate it server-side. Sending an invalid token value produced the same response as the baseline, meaning the token check is cosmetic only.`,
            url: ep.url,
            remediation: 'Validate CSRF tokens server-side on every state-changing request. Reject requests with missing or invalid tokens.',
            cwe_id: 'CWE-352', owasp_category: 'A01:2021', cvss_score: 6.5,
            evidence: { method: ep.method, csrf_param: csrfParam, baseline_status: baselineRes.status, invalid_token_status: invalidRes.status },
          });
        }
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
