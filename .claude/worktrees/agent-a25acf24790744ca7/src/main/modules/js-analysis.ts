import type { ScanModuleInterface, EndpointInfo, ModuleFinding } from '../scanner/orchestrator';
import type { HttpClient } from '../scanner/http-client';
import * as cheerio from 'cheerio';

const SECRET_PATTERNS: { name: string; pattern: RegExp; severity: 'critical' | 'high' | 'medium' }[] = [
  { name: 'AWS Access Key', pattern: /AKIA[0-9A-Z]{16}/g, severity: 'critical' },
  { name: 'AWS Secret Key', pattern: /(?:aws_secret|AWS_SECRET)[_\s]*(?:access_key|ACCESS_KEY)?[_\s]*[:=]\s*["']?([A-Za-z0-9/+]{40})["']?/gi, severity: 'critical' },
  { name: 'OpenAI API Key', pattern: /sk-(?:proj-)?[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}/g, severity: 'critical' },
  { name: 'Anthropic API Key', pattern: /sk-ant-api\d+-[A-Za-z0-9_-]{90,}/g, severity: 'critical' },
  { name: 'Google API Key', pattern: /AIza[0-9A-Za-z_-]{35}/g, severity: 'critical' },
  { name: 'Firebase API Key', pattern: /(?:firebase|FIREBASE)[^"']*["']?(AIza[0-9A-Za-z_-]{35})["']?/gi, severity: 'critical' },
  { name: 'Stripe Secret Key', pattern: /sk_live_[0-9a-zA-Z]{24,}/g, severity: 'critical' },
  { name: 'Stripe Publishable Key', pattern: /pk_live_[0-9a-zA-Z]{24,}/g, severity: 'high' },
  { name: 'GitHub Token', pattern: /(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}/g, severity: 'critical' },
  { name: 'GitHub Classic Token', pattern: /(?:token|key|secret|password|auth)\s*[:=]\s*['"]([0-9a-f]{40})['"]/gi, severity: 'medium' },
  { name: 'Slack Token', pattern: /xox[bpros]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}/g, severity: 'critical' },
  { name: 'Slack Webhook', pattern: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]+/g, severity: 'high' },
  { name: 'Twilio Account SID', pattern: /AC[a-z0-9]{32}/g, severity: 'high' },
  { name: 'Twilio Auth Token', pattern: /(?:twilio|TWILIO)[^"']*["']?([a-z0-9]{32})["']?/gi, severity: 'critical' },
  { name: 'SendGrid API Key', pattern: /SG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}/g, severity: 'critical' },
  { name: 'Mailgun API Key', pattern: /key-[0-9a-zA-Z]{32}/g, severity: 'critical' },
  { name: 'JWT Token', pattern: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g, severity: 'high' },
  { name: 'RSA Private Key', pattern: /-----BEGIN RSA PRIVATE KEY-----/g, severity: 'critical' },
  { name: 'Private Key', pattern: /-----BEGIN (?:EC |DSA )?PRIVATE KEY-----/g, severity: 'critical' },
  { name: 'Password in Code', pattern: /(?:password|passwd|pwd|secret|api_secret)\s*[:=]\s*["']([^"']{6,})["']/gi, severity: 'high' },
  { name: 'Database Connection String', pattern: /(?:mongodb|postgres|mysql|redis|amqp|mssql):\/\/[^\s"'<>]{15,}/gi, severity: 'critical' },
  { name: 'Environment Variable Leak', pattern: /process\.env\.[A-Z_]{4,}|import\.meta\.env\.[A-Z_]{4,}/g, severity: 'medium' },
  { name: 'Internal IP Address', pattern: /(?:["'`\s=])((?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3})(?:["'`\s])/g, severity: 'medium' },
  { name: 'Hardcoded Basic Auth', pattern: /Authorization:\s*Basic\s+[A-Za-z0-9+/]{20,}/gi, severity: 'critical' },
  { name: 'Bearer Token Hardcoded', pattern: /Authorization:\s*Bearer\s+[A-Za-z0-9._-]{20,}/gi, severity: 'high' },
  { name: 'Mapbox Token', pattern: /pk\.eyJ1[A-Za-z0-9._-]{50,}/g, severity: 'high' },
  { name: 'Algolia API Key', pattern: /[a-f0-9]{32}(?=.*algolia)/gi, severity: 'high' },
  { name: 'HuggingFace Token', pattern: /hf_[A-Za-z0-9]{30,}/g, severity: 'high' },
  { name: 'Cloudinary URL', pattern: /cloudinary:\/\/[0-9]+:[A-Za-z0-9_-]+@[a-z0-9]+/g, severity: 'high' },
];

const DANGEROUS_SINKS = [
  { pattern: /\.innerHTML\s*=\s*(?!["']<[a-z])/g, name: 'innerHTML XSS sink' },
  { pattern: /document\.write\s*\(/g, name: 'document.write XSS sink' },
  { pattern: /\beval\s*\(/g, name: 'eval() code execution' },
  { pattern: /new\s+Function\s*\(/g, name: 'Function() code execution' },
  { pattern: /setTimeout\s*\(\s*(?:["'`]|[a-z_$])/g, name: 'setTimeout string eval' },
  { pattern: /location\.href\s*=\s*(?!["']https:\/\/)/g, name: 'Open redirect via location.href' },
  { pattern: /location\.replace\s*\(/g, name: 'Open redirect via location.replace' },
  { pattern: /window\.open\s*\(/g, name: 'window.open with dynamic URL' },
  { pattern: /dangerouslySetInnerHTML/g, name: 'React dangerouslySetInnerHTML' },
  { pattern: /\$\s*\(\s*(?:location|document\.URL|window\.location)/g, name: 'jQuery DOM XSS' },
  { pattern: /postMessage\s*\((?![^)]*["']https?:\/\/)/g, name: 'postMessage without origin restriction' },
  { pattern: /addEventListener\s*\(\s*["']message["']/g, name: 'postMessage listener (check origin validation)' },
  { pattern: /Object\.assign\s*\(\s*\{\}/g, name: 'Object.assign prototype pollution risk' },
  { pattern: /Math\.random\s*\(\)/g, name: 'Math.random() for crypto (insecure)' },
];

export class JsAnalysisModule implements ScanModuleInterface {
  id = 'js-analysis';
  name = 'JavaScript Analysis';

  async scan(url: string, endpoints: EndpointInfo[], client: HttpClient): Promise<ModuleFinding[]> {
    const findings: ModuleFinding[] = [];
    const baseUrl = new URL(url).origin;

    // Collect all JS files from the main page
    const mainRes = await client.get(url);
    if (mainRes.status === 0) return findings;

    const $ = cheerio.load(mainRes.body);
    const jsUrls = new Set<string>();

    // Static script tags
    $('script[src]').each((_, el) => {
      const src = $(el).attr('src');
      if (!src) return;
      try {
        const resolved = new URL(src, url);
        if (resolved.origin === baseUrl || resolved.href.includes('/_next/') || resolved.href.includes('/static/')) {
          jsUrls.add(resolved.href);
        }
      } catch {}
    });

    // Also check for dynamically referenced chunks via Next.js / Webpack manifests
    const dynamicPatterns = [
      '/_next/static/chunks/webpack.js',
      '/static/js/main.chunk.js',
      '/static/js/runtime-main.js',
      '/asset-manifest.json',
      '/_next/static/development/_buildManifest.js',
    ];

    for (const dp of dynamicPatterns) {
      const manifestRes = await client.get(baseUrl + dp);
      if (manifestRes.status === 200 && manifestRes.size > 0) {
        const chunkMatches = manifestRes.body.match(/\/_next\/static\/chunks\/[^"'\s]+\.js/g) || [];
        for (const chunk of chunkMatches.slice(0, 10)) {
          jsUrls.add(baseUrl + chunk);
        }
      }
    }

    // Scan each JS file
    for (const jsUrl of Array.from(jsUrls).slice(0, 20)) {
      const jsRes = await client.get(jsUrl);
      if (jsRes.status !== 200 || jsRes.size === 0) continue;

      const code = jsRes.body;
      const fileFindings: ModuleFinding[] = [];

      // Pattern-based secret detection
      for (const { name, pattern, severity } of SECRET_PATTERNS) {
        pattern.lastIndex = 0;
        const match = pattern.exec(code);
        if (!match) continue;

        // Skip obvious test/example patterns
        const ctx = code.slice(Math.max(0, match.index - 30), match.index + 80);
        if (/test|example|sample|placeholder|xxxx|your[_-]?key|insert[_-]?key/i.test(ctx)) continue;
        // Skip if it appears in comments
        if (/^\s*(?:\/\/|#|\/\*|\*)/.test(code.slice(Math.max(0, match.index - 100), match.index))) continue;

        fileFindings.push({
          severity,
          title: `${name} Found in JavaScript Bundle`,
          description: `A ${name} pattern was detected in ${jsUrl}. This credential is embedded in client-side JavaScript and is accessible to anyone who visits the site. The value must be rotated immediately.`,
          url: jsUrl,
          remediation: `Rotate/revoke the exposed credential immediately. Move all secrets to server-side environment variables. Never include API keys or secrets in client-side bundles.`,
          cwe_id: 'CWE-312',
          owasp_category: 'A02:2021',
          cvss_score: severity === 'critical' ? 9.8 : severity === 'high' ? 7.5 : 5.3,
          evidence: { secret_type: name, context: ctx.replace(/\s+/g, ' ').trim(), file: jsUrl },
        });
      }

      // Dangerous sink detection
      for (const { pattern, name } of DANGEROUS_SINKS) {
        pattern.lastIndex = 0;
        const match = pattern.exec(code);
        if (!match) continue;
        const ctx = code.slice(Math.max(0, match.index - 50), match.index + 100);

        fileFindings.push({
          severity: 'medium',
          title: `Dangerous DOM Sink: ${name}`,
          description: `Found use of ${name} in ${jsUrl}. If user-controlled data reaches this sink, it could lead to XSS or code execution.`,
          url: jsUrl,
          remediation: 'Audit all data flowing into this sink. Ensure user input is sanitized or use safer alternatives (textContent instead of innerHTML).',
          cwe_id: 'CWE-79',
          owasp_category: 'A03:2021',
          cvss_score: 5.3,
          evidence: { sink: name, context: ctx.replace(/\s+/g, ' ').trim() },
        });
      }

      // Check for source maps
      if (code.includes('sourceMappingURL=') || code.includes('//# sourceMappingURL')) {
        const mapMatch = code.match(/\/\/#\s*sourceMappingURL=(.+)/);
        if (mapMatch) {
          const mapUrl = new URL(mapMatch[1].trim(), jsUrl).href;
          const mapRes = await client.head(mapUrl);
          if (mapRes.status === 200) {
            fileFindings.push({
              severity: 'medium',
              title: 'Source Map Publicly Accessible',
              description: `Source map at ${mapUrl} is publicly accessible. This reveals your original unminified source code including comments, variable names, and logic that should remain private.`,
              url: mapUrl,
              remediation: 'Remove source maps from production, or restrict access via server rules.',
              cwe_id: 'CWE-540',
              owasp_category: 'A05:2021',
              cvss_score: 5.3,
              evidence: { source_map_url: mapUrl },
            });
          }
        }
      }

      findings.push(...fileFindings.slice(0, 5));
    }

    return findings;
  }
}
