import type { ScanModuleInterface, EndpointInfo, ModuleFinding } from '../scanner/orchestrator';
import type { HttpClient } from '../scanner/http-client';

export class CloudModule implements ScanModuleInterface {
  id = 'cloud';
  name = 'Cloud Misconfiguration';

  async scan(url: string, endpoints: EndpointInfo[], client: HttpClient): Promise<ModuleFinding[]> {
    const findings: ModuleFinding[] = [];
    const domain = new URL(url).hostname;

    // 1. Firebase Firestore open rules
    const firebasePatterns = [
      domain.replace(/\./g, '-'),
      domain.split('.')[0],
    ];

    for (const project of firebasePatterns) {
      const fbUrl = `https://${project}-default-rtdb.firebaseio.com/.json`;
      const res = await client.get(fbUrl);
      if (res.status === 200 && res.body.trim() !== 'null' && res.size > 5) {
        findings.push({
          severity: 'critical',
          title: 'Firebase Realtime Database Publicly Readable',
          description: `The Firebase Realtime Database at "${fbUrl}" is publicly accessible without authentication. All data in the database can be read by anyone. This typically exposes user data, application state, and potentially credentials.`,
          url: fbUrl,
          remediation: 'Set Firebase security rules to require authentication: { "rules": { ".read": "auth != null", ".write": "auth != null" } }',
          cwe_id: 'CWE-284', owasp_category: 'A01:2021', cvss_score: 9.1,
          evidence: { firebase_url: fbUrl, data_preview: res.body.slice(0, 200) },
        });
        break;
      }
    }

    // 2. Exposed Elasticsearch
    const esPorts = [9200, 9300];
    for (const port of esPorts) {
      const esUrl = `http://${domain}:${port}`;
      const res = await client.get(esUrl);
      if (res.status === 200 && res.body.includes('cluster_name')) {
        findings.push({
          severity: 'critical',
          title: 'Exposed Elasticsearch Instance',
          description: `An Elasticsearch instance is publicly accessible at ${esUrl}. An attacker can read, modify, or delete all indices and data.`,
          url: esUrl,
          remediation: 'Restrict Elasticsearch to localhost or internal networks. Enable X-Pack security with authentication.',
          cwe_id: 'CWE-284', owasp_category: 'A01:2021', cvss_score: 9.8,
          evidence: { response_preview: res.body.slice(0, 300) },
        });

        // Check indices
        const indicesRes = await client.get(`${esUrl}/_cat/indices?v`);
        if (indicesRes.status === 200) {
          findings.push({
            severity: 'critical',
            title: 'Elasticsearch Indices Enumerable',
            description: `The /_cat/indices endpoint is accessible, revealing all database indices and their sizes.`,
            url: `${esUrl}/_cat/indices`,
            remediation: 'Restrict access to Elasticsearch management endpoints.',
            cwe_id: 'CWE-284', owasp_category: 'A01:2021', cvss_score: 9.1,
            evidence: { indices_preview: indicesRes.body.slice(0, 500) },
          });
        }
        break;
      }
    }

    // 3. Exposed Redis
    // We can't directly test Redis protocol via HTTP, but check common HTTP proxies
    const redisUrl = `http://${domain}:6379`;
    const redisRes = await client.get(redisUrl);
    if (redisRes.body.includes('DENIED') || redisRes.body.includes('redis_version') || redisRes.body.includes('-ERR')) {
      findings.push({
        severity: 'critical',
        title: 'Redis Instance Publicly Accessible',
        description: `A Redis instance appears to be accessible on port 6379. Redis typically has no authentication by default, allowing an attacker to read/write all cached data, or achieve RCE via the CONFIG SET command.`,
        url: redisUrl,
        remediation: 'Bind Redis to 127.0.0.1. Enable requirepass authentication. Use firewall rules to block external access.',
        cwe_id: 'CWE-284', owasp_category: 'A01:2021', cvss_score: 9.8,
      });
    }

    // 4. Docker API exposure
    for (const dPort of [2375, 2376]) {
      const dockerUrl = `http://${domain}:${dPort}/version`;
      const dRes = await client.get(dockerUrl);
      if (dRes.status === 200 && dRes.body.includes('ApiVersion')) {
        findings.push({
          severity: 'critical',
          title: 'Docker API Publicly Exposed',
          description: `The Docker Remote API is accessible at port ${dPort} without authentication. An attacker can create, start, and exec into containers, effectively gaining root access to the host.`,
          url: dockerUrl,
          remediation: 'Disable the Docker Remote API or restrict it to TLS with client certificates. Never expose port 2375/2376 to the internet.',
          cwe_id: 'CWE-284', owasp_category: 'A01:2021', cvss_score: 10.0,
          evidence: { response_preview: dRes.body.slice(0, 300) },
        });
        break;
      }
    }

    // 5. Kubernetes endpoints
    const k8sPaths = ['/api/v1/pods', '/api/v1/secrets', '/api/v1/namespaces', '/api/v1/nodes'];
    for (const kPath of k8sPaths) {
      const kRes = await client.get(url.replace(/\/$/, '') + kPath);
      if (kRes.status === 200 && (kRes.body.includes('"items"') || kRes.body.includes('"kind"'))) {
        findings.push({
          severity: 'critical',
          title: `Kubernetes API Exposed: ${kPath}`,
          description: `The Kubernetes API endpoint "${kPath}" is accessible. This exposes cluster configuration, running pods, and potentially secrets.`,
          url: url + kPath,
          remediation: 'Enable RBAC on the Kubernetes API server. Never expose the API to the public internet.',
          cwe_id: 'CWE-284', owasp_category: 'A01:2021', cvss_score: 9.8,
          evidence: { path: kPath, response_preview: kRes.body.slice(0, 300) },
        });
        break;
      }
    }

    // 6. Exposed .DS_Store (macOS directory listing)
    const dsRes = await client.get(new URL(url).origin + '/.DS_Store');
    if (dsRes.status === 200 && dsRes.body.includes('\x00\x00\x00\x01Bud1')) {
      findings.push({
        severity: 'medium',
        title: 'Exposed .DS_Store File',
        description: 'A macOS .DS_Store file is accessible. This file reveals the directory structure and filenames, which aids attacker reconnaissance.',
        url: new URL(url).origin + '/.DS_Store',
        remediation: 'Block access to .DS_Store files in web server configuration. Remove them from deployments.',
        cwe_id: 'CWE-538', owasp_category: 'A05:2021', cvss_score: 5.3,
      });
    }

    return findings;
  }
}
