import type { ScanModuleInterface, EndpointInfo, ModuleFinding } from '../scanner/orchestrator';
import type { HttpClient } from '../scanner/http-client';
import { expandEndpoint } from './_params';

const CANARY = 'hm7x9k3p';

const PAYLOADS = [
  { payload: `<script>alert('${CANARY}')</script>`, context: 'HTML body script injection', severity: 'high' as const },
  { payload: `"><img src=x onerror=alert('${CANARY}')>`, context: 'Attribute breakout to event handler', severity: 'high' as const },
  { payload: `'><svg/onload=alert('${CANARY}')>`, context: 'SVG event handler injection', severity: 'high' as const },
  { payload: `<details/open/ontoggle=alert('${CANARY}')>`, context: 'Details element event', severity: 'high' as const },
  { payload: `<img src=x onerror=alert\`${CANARY}\`>`, context: 'Template literal bypass', severity: 'high' as const },
  { payload: `javascript:alert('${CANARY}')`, context: 'JavaScript protocol in href', severity: 'medium' as const },
  { payload: `"-alert('${CANARY}')-"`, context: 'JavaScript string breakout', severity: 'high' as const },
  { payload: `{{91*97}}`, context: 'Client-side template injection', severity: 'medium' as const },
];

export class XssModule implements ScanModuleInterface {
  id = 'xss';
  name = 'Cross-Site Scripting';

  async scan(url: string, endpoints: EndpointInfo[], client: HttpClient): Promise<ModuleFinding[]> {
    const findings: ModuleFinding[] = [];
    const tested = new Set<string>();

    for (const rawEp of endpoints) {
      for (const ep of expandEndpoint(rawEp)) {
      if (ep.params.length === 0) continue;

      for (const param of ep.params) {
        const key = `${ep.url}:${param}`;
        if (tested.has(key)) continue;
        tested.add(key);

        // Step 1: Check reflection with unique canary
        const canaryRes = await this.injectPayload(ep, param, CANARY, client);
        if (canaryRes.status === 0 || !canaryRes.body.includes(CANARY)) continue;

        // Determine reflection context
        const ctx = this.detectContext(canaryRes.body, CANARY);

        // Step 2: Test payloads
        for (const { payload, context, severity } of PAYLOADS) {
          const res = await this.injectPayload(ep, param, payload, client);
          if (res.status === 0) continue;

          // Exact match — payload rendered unencoded
          if (res.body.includes(payload)) {
            findings.push({
              severity,
              title: `Reflected XSS: ${context}`,
              description: `Parameter "${param}" at ${ep.url} reflects user input directly into the HTML response without encoding. The payload "${payload.slice(0, 50)}" appears verbatim in the response body. An attacker can craft a URL that executes arbitrary JavaScript in the victim's browser, enabling session hijacking, credential theft, defacement, or phishing.`,
              url: ep.url, parameter: param,
              remediation: 'Apply context-aware output encoding: HTML-encode for body content, attribute-encode for attributes, JavaScript-encode for script contexts. Implement Content-Security-Policy with nonce-based script-src. Use frameworks with automatic escaping (React, Angular).',
              cwe_id: 'CWE-79', owasp_category: 'A03:2021', cvss_score: 6.1,
              evidence: {
                payload,
                context,
                reflection_context: ctx,
                method: ep.method,
                parameter: param,
                response_snippet: this.extractSnippet(res.body, payload),
              },
            });
            break;
          }

          // Check for template injection ({{91*97}} → 8827)
          if (payload === '{{91*97}}') {
            // Fetch baseline without SSTI payload to confirm 8827 is not naturally present
            const baselineRes = await this.injectPayload(ep, param, 'harmless_test_value', client);
            if (!baselineRes.body.includes('8827') && res.body.includes('8827')) {
              findings.push({
                severity: 'critical',
                title: 'Client-Side Template Injection',
                description: `Parameter "${param}" is interpreted by a client-side template engine. The expression {{91*97}} was evaluated to 8827, confirming template injection. This can escalate to XSS via constructor.constructor payloads or to server-side template injection if processed server-side.`,
                url: ep.url, parameter: param,
                remediation: 'Sanitize user input before template rendering. Use template engines that sandbox expressions. Avoid placing user input inside template delimiters.',
                cwe_id: 'CWE-79', owasp_category: 'A03:2021', cvss_score: 9.8,
                evidence: { payload: '{{91*97}}', result: '8827', parameter: param },
              });
              break;
            }
          }

          // Check if angle brackets are encoded but other dangerous chars pass through
          if (payload.includes('<') && !res.body.includes(payload)) {
            const stripped = payload.replace(/<[^>]*>/g, '').trim();
            if (stripped.length > 5 && res.body.includes(stripped)) {
              const encoded = payload.replace(/</g, '&lt;').replace(/>/g, '&gt;');
              if (res.body.includes(encoded)) continue;

              findings.push({
                severity: 'low',
                title: `XSS: Partial Input Reflection (${context})`,
                description: `Parameter "${param}" reflects parts of the input but HTML tags appear to be stripped or encoded. The application has some XSS protection, but event handlers or JavaScript context breakout may still be possible with context-specific payloads.`,
                url: ep.url, parameter: param,
                remediation: 'Verify encoding is context-aware. Test with attribute-context and JavaScript-context payloads. Implement CSP as defense-in-depth.',
                cwe_id: 'CWE-79', owasp_category: 'A03:2021', cvss_score: 3.1,
                evidence: { payload, reflection: 'partial', context: ctx },
              });
            }
          }
        }
      }
    }}

    return findings;
  }

  private detectContext(body: string, canary: string): string {
    const idx = body.indexOf(canary);
    if (idx === -1) return 'unknown';
    const before = body.slice(Math.max(0, idx - 100), idx);
    if (/<script[^>]*>[^<]*$/i.test(before)) return 'inside <script> tag';
    if (/=\s*["'][^"']*$/.test(before)) return 'inside HTML attribute value';
    if (/<!--[^>]*$/.test(before)) return 'inside HTML comment';
    if (/<style[^>]*>[^<]*$/i.test(before)) return 'inside <style> tag';
    if (/<textarea[^>]*>[^<]*$/i.test(before)) return 'inside <textarea>';
    return 'HTML body context';
  }

  private extractSnippet(body: string, payload: string): string {
    const idx = body.indexOf(payload);
    if (idx === -1) return '';
    const start = Math.max(0, idx - 40);
    const end = Math.min(body.length, idx + payload.length + 40);
    return body.slice(start, end).replace(/\s+/g, ' ');
  }

  private async injectPayload(ep: EndpointInfo, param: string, payload: string, client: HttpClient) {
    if (ep.method === 'GET') {
      const u = new URL(ep.url);
      u.searchParams.set(param, payload);
      return client.send(u.href, { timeout: 8000 });
    }
    if (ep.contentType?.includes('json')) {
      const obj: Record<string, string> = {};
      for (const p of ep.params) obj[p] = p === param ? payload : 'test';
      return client.post(ep.url, JSON.stringify(obj), { 'Content-Type': 'application/json' });
    }
    const body = ep.params.map(p => `${encodeURIComponent(p)}=${encodeURIComponent(p === param ? payload : 'test')}`).join('&');
    return client.post(ep.url, body, { 'Content-Type': 'application/x-www-form-urlencoded' });
  }
}
