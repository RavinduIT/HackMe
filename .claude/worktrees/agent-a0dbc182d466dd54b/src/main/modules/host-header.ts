import type { ScanModuleInterface, EndpointInfo, ModuleFinding } from '../scanner/orchestrator';
import type { HttpClient } from '../scanner/http-client';

const CANARY_HOST = 'hm-evil-canary.com';

const HOST_OVERRIDE_HEADERS = [
  { header: 'X-Forwarded-Host', value: CANARY_HOST },
  { header: 'X-Host', value: CANARY_HOST },
  { header: 'X-Forwarded-Server', value: CANARY_HOST },
  { header: 'X-Original-Host', value: CANARY_HOST },
  { header: 'Forwarded', value: `host=${CANARY_HOST}` },
];

const RESET_PATHS = ['/forgot-password', '/reset-password', '/forgot', '/password/reset', '/password/forgot', '/account/recover', '/auth/forgot', '/api/auth/forgot-password', '/api/forgot-password'];
const RESET_PARAMS = ['email', 'user', 'username', 'login'];

export class HostHeaderModule implements ScanModuleInterface {
  id = 'host-header';
  name = 'Host Header Attacks';

  async scan(url: string, endpoints: EndpointInfo[], client: HttpClient): Promise<ModuleFinding[]> {
    const findings: ModuleFinding[] = [];
    const parsedUrl = new URL(url);
    const realHost = parsedUrl.hostname;

    // 1. Host header reflection
    const res = await client.get(url, { 'Host': CANARY_HOST });
    if (res.body.includes(CANARY_HOST)) {
      findings.push({
        severity: 'medium',
        title: 'Host Header Value Reflected in Response',
        description: `The application uses the Host header to generate URLs in the response body. When the Host header was set to "${CANARY_HOST}", this value appeared in the HTML output. This enables cache poisoning (if cached), phishing via absolute URLs, and password reset poisoning.`,
        url,
        remediation: 'Hardcode the application\'s canonical hostname. Never use the Host header to construct URLs. Use a configured SERVER_NAME instead.',
        cwe_id: 'CWE-644', owasp_category: 'A05:2021', cvss_score: 5.3,
        evidence: { injected_host: CANARY_HOST, reflected: true },
      });
    }

    // 2. X-Forwarded-Host and similar overrides
    for (const { header, value } of HOST_OVERRIDE_HEADERS) {
      const overrideRes = await client.get(url, { [header]: value });
      if (overrideRes.body.includes(CANARY_HOST) || overrideRes.headers['location']?.includes(CANARY_HOST)) {
        findings.push({
          severity: 'high',
          title: `Host Override via ${header}`,
          description: `The application trusts the "${header}" header for URL generation. Setting "${header}: ${CANARY_HOST}" caused the canary hostname to appear in the response. This is exploitable for cache poisoning, password reset poisoning, and SSRF depending on how the host value is used.`,
          url, parameter: header,
          remediation: `Ignore ${header} from untrusted sources, or validate it against an allowlist of trusted proxies.`,
          cwe_id: 'CWE-644', owasp_category: 'A05:2021', cvss_score: 7.5,
          evidence: { header, value, reflected_in: overrideRes.headers['location']?.includes(CANARY_HOST) ? 'Location header' : 'response body' },
        });
      }
    }

    // 3. Password reset poisoning
    const baseUrl = parsedUrl.origin;
    for (const resetPath of RESET_PATHS) {
      const resetUrl = baseUrl + resetPath;
      const probeRes = await client.get(resetUrl);
      if (probeRes.status === 404 || probeRes.status === 0) continue;

      // Found a reset endpoint — test host header poisoning
      for (const param of RESET_PARAMS) {
        const body = `${param}=test@example.com`;
        const poisonRes = await client.post(resetUrl, body, {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Host': CANARY_HOST,
        });

        if (poisonRes.status === 200 || poisonRes.status === 302) {
          if (poisonRes.body.includes(CANARY_HOST) || poisonRes.headers['location']?.includes(CANARY_HOST)) {
            findings.push({
              severity: 'high',
              title: 'Password Reset Poisoning via Host Header',
              description: `The password reset endpoint at "${resetUrl}" uses the Host header to construct the reset link. By setting Host to "${CANARY_HOST}", the reset email would contain a link pointing to the attacker's domain, leaking the reset token when the victim clicks it.`,
              url: resetUrl,
              remediation: 'Hardcode the reset link domain. Never use Host header for constructing password reset URLs.',
              cwe_id: 'CWE-644', owasp_category: 'A07:2021', cvss_score: 8.1,
              evidence: { reset_endpoint: resetUrl, injected_host: CANARY_HOST },
            });
            break;
          }
        }
      }
    }

    // 4. Routing-based SSRF via Host header
    const internalHosts = ['127.0.0.1', 'localhost', '169.254.169.254', '[::1]'];
    for (const internalHost of internalHosts) {
      const ssrfRes = await client.get(url, { 'Host': internalHost });
      if (ssrfRes.status === 200 && ssrfRes.body !== res.body && ssrfRes.size > 0) {
        const sizeDiff = Math.abs(ssrfRes.size - res.size);
        if (sizeDiff > 100) {
          findings.push({
            severity: 'high',
            title: `Routing-Based SSRF via Host Header (${internalHost})`,
            description: `Setting Host to "${internalHost}" returned a different response (${ssrfRes.size} bytes vs ${res.size} bytes), suggesting the reverse proxy routed the request to an internal service. This may allow access to admin panels, internal APIs, or cloud metadata.`,
            url,
            remediation: 'Configure the reverse proxy to reject requests with unknown Host headers. Use a strict virtual host configuration.',
            cwe_id: 'CWE-918', owasp_category: 'A10:2021', cvss_score: 8.1,
            evidence: { host: internalHost, response_size: ssrfRes.size, normal_size: res.size },
          });
          break;
        }
      }
    }

    return findings;
  }
}
