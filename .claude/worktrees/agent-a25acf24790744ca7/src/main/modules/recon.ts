import type { ScanModuleInterface, EndpointInfo, ModuleFinding } from '../scanner/orchestrator';
import type { HttpClient } from '../scanner/http-client';
import * as cheerio from 'cheerio';

const SENSITIVE_PATHS = [
  '/.env', '/.git/HEAD', '/.gitignore',
  '/robots.txt', '/sitemap.xml',
  '/wp-config.php.bak', '/web.config',
  '/server-status', '/server-info',
  '/phpinfo.php',
  '/backup.sql', '/dump.sql',
  '/.htaccess', '/.htpasswd',
  '/package.json', '/composer.json',
  '/Dockerfile', '/docker-compose.yml',
  '/config.json', '/config.yml',
  '/application.yml', '/application.properties',
];

const SECRET_PATTERNS = [
  { name: 'AWS Access Key', pattern: /AKIA[0-9A-Z]{16}/g },
  { name: 'AWS Secret Key', pattern: /[0-9a-zA-Z/+]{40}(?=\s|$|")/g },
  { name: 'Google API Key', pattern: /AIza[0-9A-Za-z_-]{35}/g },
  { name: 'Stripe Secret Key', pattern: /sk_live_[0-9a-zA-Z]{24,}/g },
  { name: 'Stripe Publishable Key', pattern: /pk_live_[0-9a-zA-Z]{24,}/g },
  { name: 'GitHub Token', pattern: /ghp_[0-9a-zA-Z]{36}/g },
  { name: 'Slack Token', pattern: /xox[bpors]-[0-9a-zA-Z]{10,}/g },
  { name: 'Firebase API Key', pattern: /AIza[0-9A-Za-z_-]{35}/g },
  { name: 'Twilio API Key', pattern: /SK[0-9a-fA-F]{32}/g },
  { name: 'SendGrid API Key', pattern: /SG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}/g },
  { name: 'Mailgun API Key', pattern: /key-[0-9a-zA-Z]{32}/g },
  { name: 'JWT Token', pattern: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g },
  { name: 'Private Key', pattern: /-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----/g },
  { name: 'Basic Auth', pattern: /[Bb]asic\s+[A-Za-z0-9+/]{20,}={0,2}/g },
  { name: 'Bearer Token', pattern: /[Bb]earer\s+[A-Za-z0-9_.-]{20,}/g },
  { name: 'Password in URL', pattern: /[?&](password|passwd|pwd|secret|token|api_key|apikey)=[^&\s]{3,}/gi },
  { name: 'Database Connection String', pattern: /(mongodb|postgres|mysql|redis|amqp):\/\/[^\s"'<>]{10,}/gi },
  { name: 'Internal IP Address', pattern: /(?:^|\s|"|'|=)((?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3})(?:\s|"|'|$)/g },
];

export class ReconModule implements ScanModuleInterface {
  id = 'recon';
  name = 'Reconnaissance';

  async scan(url: string, endpoints: EndpointInfo[], client: HttpClient): Promise<ModuleFinding[]> {
    const findings: ModuleFinding[] = [];
    const baseUrl = new URL(url).origin;

    // 1. Get baseline (404-like) response to filter SPA catch-all
    const baseline404 = await client.send(baseUrl + '/hackme-nonexistent-path-check-' + Date.now(), { method: 'GET', timeout: 8000 });
    const baselineSize = baseline404.size;
    const baselineHash = baseline404.body.slice(0, 500);

    // Sensitive file enumeration
    for (const path of SENSITIVE_PATHS) {
      const res = await client.send(baseUrl + path, { method: 'GET', timeout: 8000 });
      if (res.status === 200 && res.size > 0) {
        // Skip if response matches the SPA catch-all (same size and same body start)
        if (Math.abs(res.size - baselineSize) < 50 && res.body.slice(0, 500) === baselineHash) continue;

        if (path === '/.git/HEAD' && res.body.startsWith('ref:')) {
          findings.push({
            severity: 'critical', title: 'Exposed Git Repository',
            description: `The .git directory is accessible at ${baseUrl}/.git/HEAD. An attacker can download the entire source code, commit history, and potentially credentials.`,
            url: baseUrl + path, remediation: 'Block access to .git directories in your web server configuration.',
            cwe_id: 'CWE-538', owasp_category: 'A05:2021', cvss_score: 9.1,
            evidence: { response_preview: res.body.slice(0, 200) },
          });
        } else if (path === '/.env' && (res.body.includes('=') && !res.body.includes('<html'))) {
          findings.push({
            severity: 'critical', title: 'Exposed Environment File (.env)',
            description: `The .env file is publicly accessible and likely contains database credentials, API keys, and secrets.`,
            url: baseUrl + path, remediation: 'Block access to .env files. Never store them in web-accessible directories.',
            cwe_id: 'CWE-200', owasp_category: 'A05:2021', cvss_score: 9.5,
            evidence: { response_preview: res.body.slice(0, 300) },
          });
        } else if (res.status === 200 && res.size > 50 && !this.looksLikeCustom404(res.body, path)) {
          const sev = path.includes('.sql') || path.includes('config') || path.includes('credential')
            ? 'high' as const : 'medium' as const;
          findings.push({
            severity: sev, title: `Sensitive File Exposed: ${path}`,
            description: `The file ${path} is publicly accessible and may contain sensitive information.`,
            url: baseUrl + path, remediation: `Block access to ${path} or remove it from the web root.`,
            cwe_id: 'CWE-538', owasp_category: 'A05:2021', cvss_score: sev === 'high' ? 7.5 : 5.3,
            evidence: { status: res.status, size: res.size },
          });
        }
      }
    }

    // 2. robots.txt analysis
    const robotsRes = await client.get(baseUrl + '/robots.txt');
    if (robotsRes.status === 200 && robotsRes.body.includes('Disallow')) {
      const disallowed = robotsRes.body.split('\n')
        .filter((l) => l.trim().toLowerCase().startsWith('disallow:'))
        .map((l) => l.split(':').slice(1).join(':').trim())
        .filter((p) => p && p !== '/');

      if (disallowed.length > 0) {
        findings.push({
          severity: 'info', title: 'robots.txt Reveals Hidden Paths',
          description: `robots.txt disallows ${disallowed.length} paths which may indicate admin panels, sensitive directories, or internal endpoints.`,
          url: baseUrl + '/robots.txt', remediation: 'Review disallowed paths. Do not rely on robots.txt for security.',
          cwe_id: 'CWE-200', owasp_category: 'A05:2021', cvss_score: 0,
          evidence: { disallowed_paths: disallowed.slice(0, 20) },
        });
      }
    }

    // 3. Technology fingerprinting from main page
    const mainRes = await client.get(url);
    if (mainRes.status > 0) {
      const server = mainRes.headers['server'];
      const poweredBy = mainRes.headers['x-powered-by'];
      const aspVersion = mainRes.headers['x-aspnet-version'];

      if (server) {
        findings.push({
          severity: 'low', title: 'Server Version Disclosed',
          description: `The Server header reveals: ${server}. This helps attackers identify specific vulnerabilities.`,
          url, remediation: 'Remove or obfuscate the Server header.',
          cwe_id: 'CWE-200', owasp_category: 'A05:2021', cvss_score: 2.1,
          evidence: { header: 'Server', value: server },
        });
      }
      if (poweredBy) {
        findings.push({
          severity: 'low', title: 'Technology Stack Disclosed (X-Powered-By)',
          description: `X-Powered-By: ${poweredBy}. This reveals the backend framework.`,
          url, remediation: 'Remove the X-Powered-By header.',
          cwe_id: 'CWE-200', owasp_category: 'A05:2021', cvss_score: 2.1,
          evidence: { header: 'X-Powered-By', value: poweredBy },
        });
      }

      // HTML comment analysis
      const $ = cheerio.load(mainRes.body);
      const comments: string[] = [];
      const walk = (nodes: any) => {
        nodes.each((_: any, node: any) => {
          if (node.type === 'comment') {
            const text = (node.data || '').trim();
            if (text.length > 10 && (
              /password|secret|key|token|todo|fixme|hack|bug|internal|admin|debug/i.test(text)
            )) {
              comments.push(text.slice(0, 200));
            }
          }
          if (node.children) walk($(node.children));
        });
      };
      walk($.root().children());

      if (comments.length > 0) {
        findings.push({
          severity: 'low', title: 'Sensitive HTML Comments Found',
          description: `Found ${comments.length} HTML comments that may reveal internal information.`,
          url, remediation: 'Remove all sensitive comments from production HTML.',
          cwe_id: 'CWE-615', owasp_category: 'A05:2021', cvss_score: 2.1,
          evidence: { comments: comments.slice(0, 5) },
        });
      }
    }

    // 4. JavaScript secret scanning
    for (const ep of endpoints) {
      if (!ep.contentType.includes('javascript') && !ep.url.endsWith('.js')) continue;
      const jsRes = await client.get(ep.url);
      if (jsRes.status !== 200) continue;

      for (const { name, pattern } of SECRET_PATTERNS) {
        pattern.lastIndex = 0;
        const matches = jsRes.body.match(pattern);
        if (matches && matches.length > 0) {
          findings.push({
            severity: name.includes('Private Key') || name.includes('AWS') ? 'critical' as const : 'high' as const,
            title: `${name} Found in JavaScript`,
            description: `A ${name} pattern was detected in ${ep.url}. This may be a hardcoded credential or secret.`,
            url: ep.url, remediation: 'Remove hardcoded secrets from client-side code. Use environment variables.',
            cwe_id: 'CWE-798', owasp_category: 'A02:2021', cvss_score: 8.2,
            evidence: { pattern: name, match_preview: matches[0].slice(0, 40) + '...' },
          });
          break;
        }
      }
    }

    // 5. Source map detection
    for (const ep of endpoints) {
      if (!ep.url.endsWith('.js')) continue;
      const mapUrl = ep.url + '.map';
      const mapRes = await client.head(mapUrl);
      if (mapRes.status === 200) {
        findings.push({
          severity: 'medium', title: 'JavaScript Source Map Exposed',
          description: `Source map file accessible at ${mapUrl}. This reveals the original unminified source code.`,
          url: mapUrl, remediation: 'Remove source map files from production or restrict access.',
          cwe_id: 'CWE-540', owasp_category: 'A05:2021', cvss_score: 5.3,
        });
      }
    }

    return findings;
  }

  private looksLikeCustom404(body: string, path: string): boolean {
    const lower = body.toLowerCase();
    if (/not\s*found|page\s*not\s*found|404|does\s*not\s*exist/i.test(lower.slice(0, 2000))) return true;
    if (path.endsWith('.json') && lower.includes('{')) return false;
    if (path.endsWith('.yml') || path.endsWith('.yaml') || path.endsWith('.env') || path.endsWith('.txt')) return false;
    if (path.endsWith('.sql') || path.endsWith('.zip') || path.endsWith('.tar.gz')) return false;
    return false;
  }
}
