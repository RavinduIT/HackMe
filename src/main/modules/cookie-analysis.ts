import type { ScanModuleInterface, EndpointInfo, ModuleFinding } from '../scanner/orchestrator';
import type { HttpClient } from '../scanner/http-client';

export class CookieAnalysisModule implements ScanModuleInterface {
  id = 'cookie-analysis';
  name = 'Cookie & Session Analysis';

  async scan(url: string, endpoints: EndpointInfo[], client: HttpClient): Promise<ModuleFinding[]> {
    const findings: ModuleFinding[] = [];
    const res = await client.get(url);
    if (res.status === 0) return findings;

    const setCookieHeaders = this.extractSetCookies(res.headers);

    if (setCookieHeaders.length === 0) return findings;

    for (const raw of setCookieHeaders) {
      const parsed = this.parseCookie(raw);
      if (!parsed.name) continue;

      const isSession = /sess|sid|token|auth|jwt|login|csrftoken|_id/i.test(parsed.name);

      if (!parsed.secure && url.startsWith('https')) {
        findings.push({
          severity: isSession ? 'high' : 'medium',
          title: `Cookie "${parsed.name}" Missing Secure Flag`,
          description: `The cookie "${parsed.name}" is set without the Secure attribute on an HTTPS site. The browser will send it over plain HTTP connections, exposing it to network sniffing.`,
          url,
          remediation: 'Add the Secure flag to all cookies on HTTPS sites.',
          cwe_id: 'CWE-614', owasp_category: 'A05:2021', cvss_score: isSession ? 6.5 : 4.3,
          evidence: { cookie: parsed.name, raw: raw.slice(0, 200) },
        });
      }

      if (!parsed.httpOnly && isSession) {
        findings.push({
          severity: 'high',
          title: `Session Cookie "${parsed.name}" Missing HttpOnly`,
          description: `The session cookie "${parsed.name}" lacks the HttpOnly attribute. JavaScript (including XSS payloads) can read this cookie via document.cookie, enabling session theft.`,
          url,
          remediation: 'Add HttpOnly to all session cookies.',
          cwe_id: 'CWE-1004', owasp_category: 'A05:2021', cvss_score: 6.5,
          evidence: { cookie: parsed.name },
        });
      }

      if (!parsed.sameSite) {
        findings.push({
          severity: 'medium',
          title: `Cookie "${parsed.name}" Missing SameSite`,
          description: `The cookie "${parsed.name}" has no SameSite attribute. Browsers may send it with cross-site requests, making CSRF attacks possible.`,
          url,
          remediation: 'Set SameSite=Lax or SameSite=Strict.',
          cwe_id: 'CWE-352', owasp_category: 'A01:2021', cvss_score: 4.3,
          evidence: { cookie: parsed.name },
        });
      }

      if (parsed.sameSite?.toLowerCase() === 'none' && !parsed.secure) {
        findings.push({
          severity: 'high',
          title: `Cookie "${parsed.name}" SameSite=None Without Secure`,
          description: `SameSite=None requires the Secure flag. Without it, the browser will reject the cookie entirely in modern browsers, or fall back to no SameSite protection.`,
          url,
          remediation: 'Add Secure flag when using SameSite=None.',
          cwe_id: 'CWE-614', owasp_category: 'A05:2021', cvss_score: 5.3,
          evidence: { cookie: parsed.name },
        });
      }

      if (parsed.name.startsWith('__Host-')) {
        if (!parsed.secure || parsed.domain || parsed.path !== '/') {
          findings.push({
            severity: 'medium',
            title: `Cookie Prefix __Host- Misused: "${parsed.name}"`,
            description: `Cookies prefixed with __Host- must have Secure, no Domain attribute, and Path=/. This cookie violates those requirements, undermining the prefix's security guarantee.`,
            url,
            remediation: 'Ensure __Host- cookies have Secure, Path=/, and no Domain.',
            cwe_id: 'CWE-16', owasp_category: 'A05:2021', cvss_score: 4.3,
            evidence: { cookie: parsed.name, raw: raw.slice(0, 200) },
          });
        }
      }

      if (parsed.name.startsWith('__Secure-') && !parsed.secure) {
        findings.push({
          severity: 'medium',
          title: `Cookie Prefix __Secure- Misused: "${parsed.name}"`,
          description: `Cookies prefixed with __Secure- must have the Secure flag.`,
          url,
          remediation: 'Add Secure flag to __Secure- prefixed cookies.',
          cwe_id: 'CWE-16', owasp_category: 'A05:2021', cvss_score: 4.3,
          evidence: { cookie: parsed.name },
        });
      }

      if (parsed.maxAge && parsed.maxAge > 86400 * 30 && isSession) {
        findings.push({
          severity: 'medium',
          title: `Session Cookie "${parsed.name}" Has Excessive Lifetime`,
          description: `The session cookie has a max-age of ${Math.round(parsed.maxAge / 86400)} days. Long-lived session cookies increase the window for session hijacking.`,
          url,
          remediation: 'Reduce session cookie lifetime to 24 hours or less.',
          cwe_id: 'CWE-613', owasp_category: 'A07:2021', cvss_score: 4.3,
          evidence: { cookie: parsed.name, max_age_seconds: parsed.maxAge },
        });
      }

      if (isSession && parsed.value) {
        if (parsed.value.length < 16) {
          findings.push({
            severity: 'high',
            title: `Weak Session Token Length: "${parsed.name}"`,
            description: `The session token is only ${parsed.value.length} characters long. Short tokens are susceptible to brute-force attacks.`,
            url,
            remediation: 'Use at least 128 bits (32 hex chars) of cryptographically random data for session tokens.',
            cwe_id: 'CWE-330', owasp_category: 'A02:2021', cvss_score: 7.5,
            evidence: { cookie: parsed.name, value_length: parsed.value.length },
          });
        }

        if (/^eyJ/.test(parsed.value)) {
          findings.push({
            severity: 'medium',
            title: `JWT Stored in Cookie: "${parsed.name}"`,
            description: `A JWT token is stored in cookie "${parsed.name}". Check that the JWT is validated server-side, uses a strong algorithm (RS256/ES256), and has reasonable expiry.`,
            url,
            remediation: 'Validate JWT signatures server-side. Use short expiry. Add HttpOnly and Secure flags.',
            cwe_id: 'CWE-522', owasp_category: 'A02:2021', cvss_score: 5.3,
            evidence: { cookie: parsed.name, jwt_preview: parsed.value.slice(0, 50) + '...' },
          });
        }

        try {
          const decoded = Buffer.from(parsed.value, 'base64').toString('utf-8');
          if (/password|email|user|admin|role|credit|ssn|secret/i.test(decoded) && decoded.length > 5) {
            findings.push({
              severity: 'high',
              title: `Sensitive Data in Base64 Cookie: "${parsed.name}"`,
              description: `The cookie "${parsed.name}" contains base64-encoded data that appears to include sensitive information (${decoded.slice(0, 80)}...).`,
              url,
              remediation: 'Never store sensitive data in cookies. Use server-side sessions.',
              cwe_id: 'CWE-315', owasp_category: 'A02:2021', cvss_score: 6.5,
              evidence: { cookie: parsed.name, decoded_preview: decoded.slice(0, 100) },
            });
          }
        } catch {}
      }
    }

    // Session fixation check: only flag when server does NOT issue a new session cookie at all
    const res2 = await client.get(url);
    const cookies2 = this.extractSetCookies(res2.headers);
    for (const raw of setCookieHeaders) {
      const p1 = this.parseCookie(raw);
      if (!/sess|sid|token/i.test(p1.name)) continue;
      const hasNewCookie = cookies2.some((raw2) => {
        const p2 = this.parseCookie(raw2);
        return p2.name === p1.name;
      });
      if (!hasNewCookie) {
        findings.push({
          severity: 'medium',
          title: 'Possible Session Fixation',
          description: `The server did not issue a new "${p1.name}" cookie on a subsequent request, suggesting it does not regenerate session IDs. This may allow session fixation attacks if an attacker can set the cookie value before authentication.`,
          url,
          remediation: 'Regenerate session IDs on each new session and after authentication.',
          cwe_id: 'CWE-384', owasp_category: 'A07:2021', cvss_score: 5.4,
          evidence: { cookie: p1.name, second_request_has_set_cookie: false },
        });
        break;
      }
    }

    return findings;
  }

  private extractSetCookies(rawHeaders: string | Record<string, string>): string[] {
    if (typeof rawHeaders === 'string') {
      try {
        const h = JSON.parse(rawHeaders);
        const sc = h['set-cookie'] || h['Set-Cookie'];
        return sc ? (Array.isArray(sc) ? sc : [sc]) : [];
      } catch { return []; }
    }
    const sc = (rawHeaders as any)['set-cookie'] || (rawHeaders as any)['Set-Cookie'];
    return sc ? (Array.isArray(sc) ? sc : [sc]) : [];
  }

  private parseCookie(raw: string) {
    const parts = raw.split(';').map(p => p.trim());
    const [nameVal, ...attrs] = parts;
    const eqIdx = nameVal.indexOf('=');
    const name = eqIdx > -1 ? nameVal.slice(0, eqIdx).trim() : nameVal.trim();
    const value = eqIdx > -1 ? nameVal.slice(eqIdx + 1).trim() : '';

    let secure = false, httpOnly = false, sameSite = '', domain = '', path = '', maxAge = 0;
    for (const attr of attrs) {
      const lower = attr.toLowerCase();
      if (lower === 'secure') secure = true;
      else if (lower === 'httponly') httpOnly = true;
      else if (lower.startsWith('samesite=')) sameSite = attr.split('=')[1]?.trim() || '';
      else if (lower.startsWith('domain=')) domain = attr.split('=')[1]?.trim() || '';
      else if (lower.startsWith('path=')) path = attr.split('=')[1]?.trim() || '';
      else if (lower.startsWith('max-age=')) maxAge = parseInt(attr.split('=')[1] || '0');
    }

    return { name, value, secure, httpOnly, sameSite, domain, path, maxAge };
  }
}
