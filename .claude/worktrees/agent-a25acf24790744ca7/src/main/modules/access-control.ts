import type { ScanModuleInterface, EndpointInfo, ModuleFinding } from '../scanner/orchestrator';
import type { HttpClient } from '../scanner/http-client';

const ADMIN_PATHS = [
  '/admin', '/admin/', '/administrator', '/admin/login', '/admin/dashboard',
  '/wp-admin', '/wp-admin/', '/wp-login.php',
  '/cpanel', '/cPanel', '/webmail',
  '/phpmyadmin', '/phpmyadmin/', '/pma',
  '/adminer', '/adminer.php',
  '/manager', '/manager/html',
  '/console', '/actuator', '/actuator/env', '/actuator/health',
  '/_debug', '/debug', '/debug/default/view',
  '/api/admin', '/api/v1/admin', '/api/users', '/api/config',
  '/graphql', '/graphiql', '/playground',
  '/swagger', '/swagger-ui', '/swagger-ui.html', '/api-docs', '/api/docs',
  '/redoc', '/openapi.json', '/openapi.yaml',
  '/status', '/health', '/healthcheck', '/metrics', '/prometheus',
  '/trace', '/env', '/configprops', '/beans', '/mappings',
  '/solr', '/jenkins', '/kibana', '/grafana',
  '/elmah.axd', '/errorlog',
  '/.well-known/security.txt',
];

const DANGEROUS_METHODS = ['PUT', 'DELETE', 'PATCH', 'TRACE', 'TRACK'];

export class AccessControlModule implements ScanModuleInterface {
  id = 'access-control';
  name = 'Access Control';

  private isSimilar(a: string, b: string): boolean {
    const sa = a.slice(0, 500);
    const sb = b.slice(0, 500);
    if (sa === sb) return true;
    const maxLen = Math.max(sa.length, sb.length);
    if (maxLen === 0) return true;
    let matches = 0;
    const minLen = Math.min(sa.length, sb.length);
    for (let i = 0; i < minLen; i++) {
      if (sa[i] === sb[i]) matches++;
    }
    return (matches / maxLen) > 0.8;
  }

  async scan(url: string, endpoints: EndpointInfo[], client: HttpClient): Promise<ModuleFinding[]> {
    const findings: ModuleFinding[] = [];
    const baseUrl = new URL(url).origin;

    // Establish 404 baseline for SPA detection
    const baselinePath = `/hm-random-404-check-${Date.now()}.html`;
    const baselineRes = await client.get(baseUrl + baselinePath);
    const baselineStatus = baselineRes.status;
    const baselineSize = baselineRes.size;
    const baselineSnippet = baselineRes.body.slice(0, 500);

    // 1. Admin panel / sensitive path enumeration
    for (const path of ADMIN_PATHS) {
      const res = await client.get(baseUrl + path);
      if (res.status === 200 && res.size > 100) {
        // SPA catch-all detection: skip if response looks like the 404 baseline
        if (baselineStatus === 200 && Math.abs(res.size - baselineSize) < 100 && this.isSimilar(res.body.slice(0, 500), baselineSnippet)) {
          continue;
        }
        const isLoginPage = /login|sign.?in|password|username|email/i.test(res.body);
        const isApiDoc = /swagger|openapi|graphql|playground/i.test(res.body);
        const isActuator = /actuator|health|beans|mappings|env/i.test(path);

        if (isActuator && res.body.includes('{')) {
          findings.push({
            severity: 'high', title: `Exposed Actuator Endpoint: ${path}`,
            description: `Spring Boot Actuator endpoint "${path}" is accessible without authentication. This exposes internal application configuration, environment variables, and potentially secrets.`,
            url: baseUrl + path, remediation: 'Restrict actuator endpoints to internal networks. Require authentication.',
            cwe_id: 'CWE-200', owasp_category: 'A01:2021', cvss_score: 7.5,
          });
        } else if (isApiDoc) {
          findings.push({
            severity: 'medium', title: `Exposed API Documentation: ${path}`,
            description: `API documentation is publicly accessible at "${path}". This reveals all API endpoints, parameters, and data models to potential attackers.`,
            url: baseUrl + path, remediation: 'Restrict API documentation to authenticated users or internal networks.',
            cwe_id: 'CWE-200', owasp_category: 'A01:2021', cvss_score: 5.3,
          });
        } else if (isLoginPage) {
          findings.push({
            severity: 'low', title: `Admin Login Page Found: ${path}`,
            description: `An admin login page was found at "${path}". While protected by authentication, its existence is useful for targeted attacks.`,
            url: baseUrl + path, remediation: 'Consider restricting admin panel access by IP or using a non-standard URL.',
            cwe_id: 'CWE-200', owasp_category: 'A01:2021', cvss_score: 2.1,
          });
        } else {
          findings.push({
            severity: 'high', title: `Accessible Admin/Debug Path: ${path}`,
            description: `The path "${path}" returns a 200 response with content. This may be an admin panel, debug interface, or management tool accessible without proper authentication.`,
            url: baseUrl + path, remediation: 'Require authentication. Restrict access by IP or VPN.',
            cwe_id: 'CWE-862', owasp_category: 'A01:2021', cvss_score: 7.5,
          });
        }
      }
    }

    // 2. HTTP Method Tampering
    for (const method of DANGEROUS_METHODS) {
      const res = await client.sendRaw(method, url, { 'Content-Length': '0' });
      if (res.status === 200 || res.status === 204) {
        if (method === 'TRACE' && res.body.includes('TRACE')) {
          findings.push({
            severity: 'medium', title: 'HTTP TRACE Method Enabled',
            description: 'The TRACE method is enabled. This can be exploited for Cross-Site Tracing (XST) to steal credentials from HttpOnly cookies.',
            url, remediation: 'Disable TRACE method in the web server configuration.',
            cwe_id: 'CWE-693', owasp_category: 'A05:2021', cvss_score: 5.3,
          });
        } else if (method !== 'TRACE') {
          findings.push({
            severity: 'low', title: `HTTP ${method} Method Allowed`,
            description: `The server accepts ${method} requests. If not intentionally enabled, this could allow unauthorized data modification or deletion.`,
            url, remediation: `Disable ${method} method if not required. Use method-based access control.`,
            cwe_id: 'CWE-749', owasp_category: 'A05:2021', cvss_score: 3.1,
          });
        }
      }
    }

    // 3. Directory listing check
    const pathsToCheck = [url, baseUrl + '/images/', baseUrl + '/uploads/', baseUrl + '/static/', baseUrl + '/assets/'];
    for (const checkUrl of pathsToCheck) {
      const res = await client.get(checkUrl);
      if (res.status === 200 && /index of\s*\//i.test(res.body)) {
        findings.push({
          severity: 'medium', title: 'Directory Listing Enabled',
          description: `Directory listing is enabled at "${checkUrl}". An attacker can browse all files in this directory.`,
          url: checkUrl, remediation: 'Disable directory listing in the web server configuration.',
          cwe_id: 'CWE-548', owasp_category: 'A05:2021', cvss_score: 5.3,
        });
      }
    }

    return findings;
  }
}
