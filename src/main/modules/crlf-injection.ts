import type { ScanModuleInterface, EndpointInfo, ModuleFinding } from '../scanner/orchestrator';
import type { HttpClient } from '../scanner/http-client';
import { expandEndpoint } from './_params';

const CRLF_PAYLOADS = [
  { payload: '%0d%0aX-HackMe-Injected: true', marker: 'x-hackme-injected', encoding: 'URL-encoded' },
  { payload: '%0D%0AX-HackMe-Injected: true', marker: 'x-hackme-injected', encoding: 'uppercase URL' },
  { payload: '%E5%98%8A%E5%98%8DX-HackMe-Injected: true', marker: 'x-hackme-injected', encoding: 'Unicode U+560A' },
  { payload: '%0d%0aSet-Cookie: hm_crlf=injected', marker: 'hm_crlf=injected', encoding: 'Set-Cookie injection' },
  { payload: '%0d%0a%0d%0a<html>CRLF_SPLIT</html>', marker: 'CRLF_SPLIT', encoding: 'Response splitting' },
  { payload: '%0aX-HackMe-Injected: true', marker: 'x-hackme-injected', encoding: 'LF only' },
  { payload: '%0dX-HackMe-Injected: true', marker: 'x-hackme-injected', encoding: 'CR only' },
  { payload: '%250d%250aX-HackMe-Injected: true', marker: 'x-hackme-injected', encoding: 'Double encoding' },
];

export class CrlfInjectionModule implements ScanModuleInterface {
  id = 'crlf-injection';
  name = 'CRLF Injection';

  async scan(url: string, endpoints: EndpointInfo[], client: HttpClient): Promise<ModuleFinding[]> {
    const findings: ModuleFinding[] = [];
    const tested = new Set<string>();

    for (const rawEp of endpoints) {
      const expanded = expandEndpoint(rawEp);
      for (const ep of expanded) {
        if (ep.params.length === 0) continue;

        for (const param of ep.params) {
          const key = `${ep.url}:${param}`;
          if (tested.has(key)) continue;
          tested.add(key);

          for (const { payload, marker, encoding } of CRLF_PAYLOADS) {
            const u = new URL(ep.url);
            u.searchParams.set(param, 'value' + payload);
            const res = await client.send(u.href, { followRedirects: false });

            const headerInjected = res.headers[marker] !== undefined;
            const bodyInjected = marker === 'CRLF_SPLIT' && res.body.includes(marker);
            const cookieInjected = marker === 'hm_crlf=injected' && (res.headers['set-cookie'] || '').includes(marker);

            if (headerInjected || bodyInjected || cookieInjected) {
              const isResponseSplit = bodyInjected;
              findings.push({
                severity: isResponseSplit ? 'high' as const : 'medium' as const,
                title: isResponseSplit ? 'HTTP Response Splitting (CRLF)' : `CRLF Header Injection (${encoding})`,
                description: isResponseSplit
                  ? `The parameter "${param}" allows HTTP response splitting. By injecting double CRLF (\\r\\n\\r\\n), an attacker can inject a complete HTTP response body, enabling XSS, cache poisoning, and session fixation regardless of other security controls.`
                  : `The parameter "${param}" allows CRLF injection into HTTP response headers via ${encoding}. An attacker can inject arbitrary headers including Set-Cookie (for session fixation), or manipulate caching behavior.`,
                url: ep.url, parameter: param,
                remediation: 'Strip or reject \\r and \\n characters from all user input before including it in HTTP headers. Use framework-level response APIs that automatically encode header values.',
                cwe_id: 'CWE-93', owasp_category: 'A03:2021', cvss_score: isResponseSplit ? 8.1 : 6.1,
                evidence: { payload: encoding, injected_marker: marker, header_injected: headerInjected, response_split: bodyInjected },
              });
              break;
            }
          }
        }
      }
    }

    // Also test the URL path directly for frameworks that reflect path in headers
    for (const { payload, marker, encoding } of CRLF_PAYLOADS.slice(0, 3)) {
      const testUrl = url.replace(/\/$/, '') + '/' + payload;
      const res = await client.send(testUrl, { followRedirects: false });
      if (res.headers[marker] !== undefined) {
        findings.push({
          severity: 'medium',
          title: `CRLF Injection via URL Path (${encoding})`,
          description: `The URL path allows CRLF injection. Injected header "${marker}" appeared in the response.`,
          url: testUrl,
          remediation: 'Validate and sanitize URL paths. Strip CRLF characters.',
          cwe_id: 'CWE-93', owasp_category: 'A03:2021', cvss_score: 6.1,
          evidence: { payload: encoding, injected_via: 'URL path' },
        });
        break;
      }
    }

    return findings;
  }
}
