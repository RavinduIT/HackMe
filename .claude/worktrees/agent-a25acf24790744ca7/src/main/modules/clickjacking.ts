import type { ScanModuleInterface, EndpointInfo, ModuleFinding } from '../scanner/orchestrator';
import type { HttpClient } from '../scanner/http-client';

export class ClickjackingModule implements ScanModuleInterface {
  id = 'clickjacking';
  name = 'Clickjacking';

  async scan(url: string, endpoints: EndpointInfo[], client: HttpClient): Promise<ModuleFinding[]> {
    const findings: ModuleFinding[] = [];
    const res = await client.get(url);
    if (res.status === 0) return findings;

    const xfo = res.headers['x-frame-options']?.toLowerCase();
    const csp = res.headers['content-security-policy'] || '';
    const hasFrameAncestors = csp.includes('frame-ancestors');

    if (!xfo && !hasFrameAncestors) {
      findings.push({
        severity: 'medium', title: 'Clickjacking: No Frame Protection',
        description: 'The page has neither X-Frame-Options nor CSP frame-ancestors. An attacker can embed this page in a transparent iframe and trick users into clicking hidden buttons (e.g., "Delete Account", "Transfer Funds").',
        url,
        remediation: 'Add "X-Frame-Options: DENY" or "Content-Security-Policy: frame-ancestors \'none\'" to prevent framing.',
        cwe_id: 'CWE-1021', owasp_category: 'A05:2021', cvss_score: 4.7,
      });
    } else if (xfo === 'allowall') {
      findings.push({
        severity: 'medium', title: 'Clickjacking: X-Frame-Options Set to ALLOWALL',
        description: 'X-Frame-Options is set to ALLOWALL which explicitly permits framing from any origin.',
        url,
        remediation: 'Change to DENY or SAMEORIGIN.',
        cwe_id: 'CWE-1021', owasp_category: 'A05:2021', cvss_score: 4.7,
      });
    }

    if (hasFrameAncestors) {
      const faMatch = csp.match(/frame-ancestors\s+([^;]+)/);
      if (faMatch) {
        const value = faMatch[1].trim();
        if (value === '*' || value.includes('* ')) {
          findings.push({
            severity: 'medium', title: 'Clickjacking: CSP frame-ancestors Wildcard',
            description: `frame-ancestors is set to "${value}" which allows framing from any domain.`,
            url,
            remediation: "Use frame-ancestors 'self' or specify explicit trusted domains.",
            cwe_id: 'CWE-1021', owasp_category: 'A05:2021', cvss_score: 4.7,
          });
        }
      }
    }

    return findings;
  }
}
