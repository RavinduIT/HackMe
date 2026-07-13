import type { ScanModuleInterface, EndpointInfo, ModuleFinding } from '../scanner/orchestrator';
import type { HttpClient } from '../scanner/http-client';

export class HeadersModule implements ScanModuleInterface {
  id = 'headers';
  name = 'Security Headers';

  async scan(url: string, endpoints: EndpointInfo[], client: HttpClient): Promise<ModuleFinding[]> {
    const findings: ModuleFinding[] = [];
    const res = await client.get(url);
    if (res.status === 0) return findings;

    const h = res.headers;

    // Strict-Transport-Security
    if (!h['strict-transport-security'] && url.startsWith('https')) {
      findings.push({
        severity: 'medium', title: 'Missing Strict-Transport-Security (HSTS)',
        description: 'The server does not set HSTS. Browsers may connect over HTTP, enabling downgrade attacks and cookie theft via network MITM.',
        url, remediation: 'Add header: Strict-Transport-Security: max-age=63072000; includeSubDomains; preload',
        cwe_id: 'CWE-319', owasp_category: 'A02:2021', cvss_score: 5.4,
      });
    } else if (h['strict-transport-security']) {
      const maxAge = parseInt(h['strict-transport-security'].match(/max-age=(\d+)/)?.[1] || '0');
      if (maxAge < 31536000) {
        findings.push({
          severity: 'low', title: 'HSTS max-age Too Short',
          description: `HSTS max-age is ${maxAge} seconds (${Math.round(maxAge / 86400)} days). Minimum recommended is 1 year (31536000).`,
          url, remediation: 'Set max-age to at least 31536000 (1 year).',
          cwe_id: 'CWE-319', owasp_category: 'A02:2021', cvss_score: 3.1,
        });
      }
    }

    // Content-Security-Policy
    const csp = h['content-security-policy'];
    if (!csp) {
      findings.push({
        severity: 'medium', title: 'Missing Content-Security-Policy (CSP)',
        description: 'No CSP header detected. CSP mitigates XSS, clickjacking, and data injection attacks by restricting resource loading.',
        url, remediation: "Add a restrictive CSP. Start with: Content-Security-Policy: default-src 'self'",
        cwe_id: 'CWE-693', owasp_category: 'A05:2021', cvss_score: 5.0,
      });
    } else {
      if (csp.includes("'unsafe-inline'")) {
        findings.push({
          severity: 'medium', title: "CSP Allows 'unsafe-inline'",
          description: "The CSP includes 'unsafe-inline' which permits inline scripts, significantly weakening XSS protection.",
          url, remediation: "Remove 'unsafe-inline' and use nonces or hashes for inline scripts.",
          cwe_id: 'CWE-693', owasp_category: 'A05:2021', cvss_score: 4.7,
          evidence: { csp },
        });
      }
      if (csp.includes("'unsafe-eval'")) {
        findings.push({
          severity: 'medium', title: "CSP Allows 'unsafe-eval'",
          description: "The CSP includes 'unsafe-eval' which permits eval(), Function(), and setTimeout with strings. This enables DOM-based XSS.",
          url, remediation: "Remove 'unsafe-eval'. Refactor code that uses eval().",
          cwe_id: 'CWE-693', owasp_category: 'A05:2021', cvss_score: 4.7,
          evidence: { csp },
        });
      }
      if (csp.includes('*') && !csp.includes('*.')) {
        findings.push({
          severity: 'high', title: 'CSP Contains Wildcard Source',
          description: 'The CSP uses a wildcard (*) source which allows loading resources from any origin, effectively disabling CSP protection.',
          url, remediation: 'Replace wildcard with specific trusted domains.',
          cwe_id: 'CWE-693', owasp_category: 'A05:2021', cvss_score: 6.1,
          evidence: { csp },
        });
      }
    }

    // X-Content-Type-Options
    if (h['x-content-type-options']?.toLowerCase() !== 'nosniff') {
      findings.push({
        severity: 'low', title: 'Missing X-Content-Type-Options: nosniff',
        description: 'Without nosniff, browsers may MIME-sniff responses, potentially executing uploaded files as scripts.',
        url, remediation: 'Add header: X-Content-Type-Options: nosniff',
        cwe_id: 'CWE-693', owasp_category: 'A05:2021', cvss_score: 3.1,
      });
    }

    // X-Frame-Options
    if (!h['x-frame-options'] && !csp?.includes('frame-ancestors')) {
      findings.push({
        severity: 'medium', title: 'Missing Clickjacking Protection',
        description: 'Neither X-Frame-Options nor CSP frame-ancestors is set. The page can be embedded in an iframe for clickjacking attacks.',
        url, remediation: 'Add header: X-Frame-Options: DENY or use CSP frame-ancestors.',
        cwe_id: 'CWE-1021', owasp_category: 'A05:2021', cvss_score: 4.7,
      });
    }

    // Referrer-Policy
    if (!h['referrer-policy']) {
      findings.push({
        severity: 'low', title: 'Missing Referrer-Policy',
        description: 'Without Referrer-Policy, the full URL (including query parameters with tokens) may leak to external sites via the Referer header.',
        url, remediation: 'Add header: Referrer-Policy: strict-origin-when-cross-origin',
        cwe_id: 'CWE-200', owasp_category: 'A05:2021', cvss_score: 3.1,
      });
    }

    // Permissions-Policy
    if (!h['permissions-policy'] && !h['feature-policy']) {
      findings.push({
        severity: 'low', title: 'Missing Permissions-Policy',
        description: 'No Permissions-Policy header. Browser features like camera, microphone, and geolocation are not restricted.',
        url, remediation: 'Add Permissions-Policy to disable unnecessary browser features.',
        cwe_id: 'CWE-693', owasp_category: 'A05:2021', cvss_score: 2.1,
      });
    }

    // Cookie analysis
    const setCookies = res.headers['set-cookie'];
    if (setCookies) {
      const cookies = Array.isArray(setCookies) ? setCookies : [setCookies];
      for (const cookie of cookies) {
        const name = cookie.split('=')[0]?.trim();
        if (!cookie.toLowerCase().includes('httponly')) {
          findings.push({
            severity: 'medium', title: `Cookie Missing HttpOnly Flag: ${name}`,
            description: `Cookie "${name}" is accessible via JavaScript (document.cookie). XSS attacks can steal it.`,
            url, remediation: 'Add the HttpOnly flag to cookies that don\'t need JavaScript access.',
            cwe_id: 'CWE-1004', owasp_category: 'A05:2021', cvss_score: 4.7,
            evidence: { cookie_name: name },
          });
        }
        if (url.startsWith('https') && !cookie.toLowerCase().includes('secure')) {
          findings.push({
            severity: 'medium', title: `Cookie Missing Secure Flag: ${name}`,
            description: `Cookie "${name}" can be sent over HTTP. An attacker on the network can intercept it.`,
            url, remediation: 'Add the Secure flag to all cookies on HTTPS sites.',
            cwe_id: 'CWE-614', owasp_category: 'A02:2021', cvss_score: 4.7,
            evidence: { cookie_name: name },
          });
        }
        if (!cookie.toLowerCase().includes('samesite')) {
          findings.push({
            severity: 'low', title: `Cookie Missing SameSite Attribute: ${name}`,
            description: `Cookie "${name}" has no SameSite attribute. It may be sent with cross-site requests, enabling CSRF.`,
            url, remediation: 'Add SameSite=Lax or SameSite=Strict to cookies.',
            cwe_id: 'CWE-1275', owasp_category: 'A05:2021', cvss_score: 3.1,
            evidence: { cookie_name: name },
          });
        }
      }
    }

    return findings;
  }
}
