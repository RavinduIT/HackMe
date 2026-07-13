import type { ScanModuleInterface, EndpointInfo, ModuleFinding } from '../scanner/orchestrator';
import type { HttpClient } from '../scanner/http-client';

const OUTPUT_PAYLOADS = [
  { payload: '; echo hm_cmd_test_7x9', marker: 'hm_cmd_test_7x9', separator: ';' },
  { payload: '| echo hm_cmd_test_7x9', marker: 'hm_cmd_test_7x9', separator: '|' },
  { payload: '`echo hm_cmd_test_7x9`', marker: 'hm_cmd_test_7x9', separator: 'backtick' },
  { payload: '$(echo hm_cmd_test_7x9)', marker: 'hm_cmd_test_7x9', separator: '$()' },
  { payload: '\necho hm_cmd_test_7x9\n', marker: 'hm_cmd_test_7x9', separator: 'newline' },
  { payload: '& echo hm_cmd_test_7x9', marker: 'hm_cmd_test_7x9', separator: '&' },
];

const TIME_PAYLOADS = [
  { payload: '; sleep 3', delay: 3, os: 'Linux' },
  { payload: '| sleep 3', delay: 3, os: 'Linux' },
  { payload: '`sleep 3`', delay: 3, os: 'Linux' },
  { payload: '$(sleep 3)', delay: 3, os: 'Linux' },
  { payload: '& timeout /t 3', delay: 3, os: 'Windows' },
  { payload: '| ping -n 4 127.0.0.1', delay: 3, os: 'Windows' },
];

export class CommandInjectionModule implements ScanModuleInterface {
  id = 'command-injection';
  name = 'Command Injection';

  async scan(url: string, endpoints: EndpointInfo[], client: HttpClient): Promise<ModuleFinding[]> {
    const findings: ModuleFinding[] = [];
    const tested = new Set<string>();

    for (const ep of endpoints) {
      for (const param of ep.params) {
        const key = `${ep.url}:${param}`;
        if (tested.has(key)) continue;
        tested.add(key);

        // Output-based detection
        for (const { payload, marker, separator } of OUTPUT_PAYLOADS) {
          const res = await this.inject(ep, param, payload, client);
          if (res.body.includes(marker)) {
            findings.push({
              severity: 'critical', title: `OS Command Injection (${separator})`,
              description: `The parameter "${param}" is vulnerable to OS command injection. The injected command "echo ${marker}" was executed and its output appeared in the response. An attacker can execute arbitrary system commands.`,
              url: ep.url, parameter: param,
              remediation: 'Never pass user input to shell commands. Use language-specific APIs instead of system/exec calls. If unavoidable, use strict allowlisting.',
              cwe_id: 'CWE-78', owasp_category: 'A03:2021', cvss_score: 10.0,
              evidence: { payload, separator, output_found: marker },
            });
            break;
          }
        }

        // Time-based detection
        const baseline = await this.inject(ep, param, 'normalvalue', client);
        for (const { payload, delay, os } of TIME_PAYLOADS) {
          const res = await this.inject(ep, param, payload, client);
          if (res.duration > (delay * 1000 - 500) && res.duration > baseline.duration + 2000) {
            findings.push({
              severity: 'critical', title: `OS Command Injection (Time-Based — ${os})`,
              description: `The parameter "${param}" shows a ${(res.duration / 1000).toFixed(1)}s delay when injected with a sleep command (baseline: ${(baseline.duration / 1000).toFixed(1)}s). This strongly indicates the command was executed on the server.`,
              url: ep.url, parameter: param,
              remediation: 'Never pass user input to shell commands.',
              cwe_id: 'CWE-78', owasp_category: 'A03:2021', cvss_score: 10.0,
              evidence: { payload, os, response_time_ms: res.duration, baseline_ms: baseline.duration },
            });
            break;
          }
        }
      }
    }
    return findings;
  }

  private async inject(ep: EndpointInfo, param: string, payload: string, client: HttpClient) {
    if (ep.method === 'GET') {
      const u = new URL(ep.url);
      u.searchParams.set(param, payload);
      return client.get(u.href);
    }
    const body = ep.params.map((p) => `${encodeURIComponent(p)}=${encodeURIComponent(p === param ? payload : 'test')}`).join('&');
    return client.post(ep.url, body, { 'Content-Type': 'application/x-www-form-urlencoded' });
  }
}
