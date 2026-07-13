import type { ScanModuleInterface, EndpointInfo, ModuleFinding } from '../scanner/orchestrator';
import type { HttpClient } from '../scanner/http-client';

const URL_PARAMS = ['url', 'uri', 'link', 'href', 'src', 'path', 'redirect', 'return', 'next',
  'target', 'dest', 'destination', 'rurl', 'redirect_uri', 'callback', 'return_url',
  'image', 'img', 'load', 'page', 'file', 'proxy', 'endpoint', 'domain', 'host', 'fetch',
  'webhook', 'api', 'service', 'forward'];

const SSRF_PAYLOADS = [
  { payload: 'http://127.0.0.1/', name: 'IPv4 loopback', markers: ['root:', 'localhost', '<html', 'Apache', 'nginx', 'IIS'] },
  { payload: 'http://[::1]/', name: 'IPv6 loopback', markers: ['root:', 'localhost', '<html'] },
  { payload: 'http://0x7f000001/', name: 'Hex IP bypass', markers: ['root:', 'localhost', '<html'] },
  { payload: 'http://2130706433/', name: 'Decimal IP bypass', markers: ['root:', 'localhost', '<html'] },
  { payload: 'http://169.254.169.254/latest/meta-data/', name: 'AWS IMDS v1', markers: ['ami-id', 'instance-id', 'iam', 'security-credentials'] },
  { payload: 'http://metadata.google.internal/computeMetadata/v1/', name: 'GCP metadata', markers: ['project-id', 'zone', 'attributes'] },
  { payload: 'http://169.254.169.254/metadata/instance?api-version=2021-02-01', name: 'Azure IMDS', markers: ['vmId', 'subscriptionId', 'resourceGroupName'] },
];

export class SsrfModule implements ScanModuleInterface {
  id = 'ssrf';
  name = 'SSRF Detection';

  async scan(url: string, endpoints: EndpointInfo[], client: HttpClient): Promise<ModuleFinding[]> {
    const findings: ModuleFinding[] = [];
    const tested = new Set<string>();

    for (const ep of endpoints) {
      const urlLikeParams = ep.params.filter(p => URL_PARAMS.includes(p.toLowerCase()));
      if (urlLikeParams.length === 0) continue;

      for (const param of urlLikeParams) {
        const key = `${ep.url}:${param}`;
        if (tested.has(key)) continue;
        tested.add(key);

        // Baseline: the normal page without injection
        const baseline = await this.injectParam(ep, param, 'https://httpbin.org/robots.txt', client);
        if (baseline.status === 0) continue;

        for (const { payload, name, markers } of SSRF_PAYLOADS) {
          const res = await this.injectParam(ep, param, payload, client);
          if (res.status === 0) continue;

          const hasMarker = markers.some(m => res.body.toLowerCase().includes(m.toLowerCase()));
          const sizeDiff = Math.abs(res.size - baseline.size);
          const contentDiffers = sizeDiff > 100 && res.body.slice(0, 200) !== baseline.body.slice(0, 200);

          if (hasMarker && contentDiffers) {
            const isCloud = name.includes('AWS') || name.includes('GCP') || name.includes('Azure');
            findings.push({
              severity: isCloud ? 'critical' : 'high',
              title: `SSRF: ${name}${isCloud ? ' — Cloud Metadata Exposure' : ''}`,
              description: isCloud
                ? `Parameter "${param}" is vulnerable to SSRF. The server fetched cloud metadata from ${payload}, exposing IAM credentials and infrastructure details that can compromise the entire cloud environment.`
                : `Parameter "${param}" is vulnerable to SSRF. The server fetched internal content from ${payload}, allowing internal network scanning, admin interface access, and potential RCE via internal APIs.`,
              url: ep.url, parameter: param,
              remediation: isCloud
                ? 'Enforce IMDSv2. Whitelist allowed destinations. Block link-local and private IP ranges at the network level.'
                : 'Whitelist allowed URL schemes and destinations. Block RFC 1918 and link-local addresses. Disable redirect following.',
              cwe_id: 'CWE-918', owasp_category: 'A10:2021',
              cvss_score: isCloud ? 9.8 : 7.5,
              evidence: { payload, bypass_technique: name, parameter: param, response_preview: res.body.slice(0, 300), markers_found: markers.filter(m => res.body.toLowerCase().includes(m.toLowerCase())) },
            });
            break;
          }
        }
      }
    }

    return findings;
  }

  private async injectParam(ep: EndpointInfo, param: string, payload: string, client: HttpClient) {
    if (ep.method === 'GET') {
      const u = new URL(ep.url);
      u.searchParams.set(param, payload);
      return client.send(u.href, { timeout: 8000 });
    }
    const body = ep.params.map(p => `${encodeURIComponent(p)}=${encodeURIComponent(p === param ? payload : 'test')}`).join('&');
    return client.post(ep.url, body, { 'Content-Type': 'application/x-www-form-urlencoded' });
  }
}
