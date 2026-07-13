import type { ScanModuleInterface, EndpointInfo, ModuleFinding } from '../scanner/orchestrator';
import type { HttpClient } from '../scanner/http-client';

export class CorsModule implements ScanModuleInterface {
  id = 'cors';
  name = 'CORS Analysis';

  async scan(url: string, endpoints: EndpointInfo[], client: HttpClient): Promise<ModuleFinding[]> {
    const findings: ModuleFinding[] = [];

    // Test with arbitrary origin
    const evilOrigin = 'https://evil-attacker.com';
    const res1 = await client.get(url, { 'Origin': evilOrigin });
    const acao = res1.headers['access-control-allow-origin'];
    const acac = res1.headers['access-control-allow-credentials'];

    if (acao === evilOrigin) {
      const sev = acac?.toLowerCase() === 'true' ? 'high' as const : 'medium' as const;
      findings.push({
        severity: sev,
        title: acac ? 'CORS: Origin Reflected with Credentials' : 'CORS: Arbitrary Origin Reflected',
        description: acac
          ? `The server reflects any Origin in Access-Control-Allow-Origin AND sets Access-Control-Allow-Credentials: true. An attacker's website can make authenticated cross-origin requests and read the response, stealing user data.`
          : `The server reflects any Origin in the ACAO header. While credentials aren't allowed, this still permits cross-origin data access.`,
        url,
        remediation: 'Validate the Origin header against an allowlist. Never reflect arbitrary origins when credentials are enabled.',
        cwe_id: 'CWE-346', owasp_category: 'A05:2021', cvss_score: sev === 'high' ? 8.1 : 5.3,
        evidence: { sent_origin: evilOrigin, acao, acac },
      });
    }

    // Test null origin
    const res2 = await client.get(url, { 'Origin': 'null' });
    const acao2 = res2.headers['access-control-allow-origin'];
    if (acao2 === 'null') {
      findings.push({
        severity: 'medium', title: 'CORS: Null Origin Allowed',
        description: 'The server allows the "null" origin. Sandboxed iframes and data: URIs send null origin, which can be exploited for cross-origin attacks.',
        url,
        remediation: 'Do not accept "null" as a valid origin.',
        cwe_id: 'CWE-346', owasp_category: 'A05:2021', cvss_score: 5.3,
        evidence: { acao: acao2 },
      });
    }

    // Test wildcard with credentials
    if (acao === '*' && acac?.toLowerCase() === 'true') {
      findings.push({
        severity: 'high', title: 'CORS: Wildcard with Credentials (Invalid but Risky)',
        description: 'The server returns Access-Control-Allow-Origin: * with Credentials: true. While browsers block this combination, it indicates a misconfigured CORS policy.',
        url,
        remediation: 'Fix the CORS configuration. Wildcard and credentials are mutually exclusive.',
        cwe_id: 'CWE-346', owasp_category: 'A05:2021', cvss_score: 6.1,
      });
    }

    // Test with subdomain of target
    const targetHost = new URL(url).hostname;
    const subdomainOrigin = `https://evil.${targetHost}`;
    const res3 = await client.get(url, { 'Origin': subdomainOrigin });
    const acao3 = res3.headers['access-control-allow-origin'];
    if (acao3 === subdomainOrigin) {
      findings.push({
        severity: 'medium', title: 'CORS: Subdomain Origin Accepted',
        description: `The server accepts origins matching *.${targetHost}. If any subdomain is compromised or allows XSS, it can be used to attack the main domain.`,
        url,
        remediation: 'Use an explicit allowlist of trusted origins rather than wildcard subdomain matching.',
        cwe_id: 'CWE-346', owasp_category: 'A05:2021', cvss_score: 5.3,
        evidence: { sent_origin: subdomainOrigin, acao: acao3 },
      });
    }

    return findings;
  }
}
