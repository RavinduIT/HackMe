import type { ScanModuleInterface, EndpointInfo, ModuleFinding } from '../scanner/orchestrator';
import type { HttpClient } from '../scanner/http-client';
import net from 'net';

const TE_OBFUSCATIONS = [
  'Transfer-Encoding: xchunked',
  'Transfer-Encoding : chunked',
  'Transfer-Encoding:\tchunked',
  ' Transfer-Encoding: chunked',
  'Transfer-Encoding: chunked\r\nTransfer-Encoding: cow',
  'Transfer-Encoding:\n chunked',
  'Transfer-Encoding: CHunked',
];

export class RequestSmugglingModule implements ScanModuleInterface {
  id = 'request-smuggling';
  name = 'Request Smuggling';

  async scan(url: string, endpoints: EndpointInfo[], client: HttpClient): Promise<ModuleFinding[]> {
    const findings: ModuleFinding[] = [];
    const parsed = new URL(url);
    const host = parsed.hostname;
    const port = parseInt(parsed.port) || (parsed.protocol === 'https:' ? 443 : 80);
    const isHttps = parsed.protocol === 'https:';

    // CL.TE timing detection — send Content-Length that's short, with chunked body
    // If backend uses TE, it'll process the chunk and respond quickly
    // If backend uses CL, it'll read only CL bytes and hang waiting
    const clteResult = await this.timingProbe(host, port, isHttps, 'CL.TE',
      `POST / HTTP/1.1\r\nHost: ${host}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nZ\r\nQ`
    );

    if (clteResult.suspicious) {
      findings.push({
        severity: 'critical',
        title: 'HTTP Request Smuggling (CL.TE)',
        description: `Timing analysis suggests a CL.TE request smuggling vulnerability. The front-end server uses Content-Length while the back-end uses Transfer-Encoding: chunked. A probe request caused a ${clteResult.delay}ms delay (baseline: ${clteResult.baseline}ms), indicating the back-end waited for chunked data that never arrived. An attacker can prepend arbitrary content to other users' requests, potentially stealing credentials, bypassing access controls, or poisoning the web cache.`,
        url,
        remediation: 'Configure the front-end server to normalize ambiguous requests. Disable HTTP/1.1 connection reuse between front-end and back-end, or ensure both agree on Transfer-Encoding handling.',
        cwe_id: 'CWE-444', owasp_category: 'A05:2021', cvss_score: 9.1,
        evidence: { variant: 'CL.TE', delay_ms: clteResult.delay, baseline_ms: clteResult.baseline },
      });
    }

    // TE.CL timing detection
    const teclResult = await this.timingProbe(host, port, isHttps, 'TE.CL',
      `POST / HTTP/1.1\r\nHost: ${host}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nX`
    );

    if (teclResult.suspicious) {
      findings.push({
        severity: 'critical',
        title: 'HTTP Request Smuggling (TE.CL)',
        description: `Timing analysis suggests a TE.CL request smuggling vulnerability. The front-end uses Transfer-Encoding while the back-end uses Content-Length. Response delay: ${teclResult.delay}ms vs baseline ${teclResult.baseline}ms.`,
        url,
        remediation: 'Normalize Transfer-Encoding handling across all servers in the request chain.',
        cwe_id: 'CWE-444', owasp_category: 'A05:2021', cvss_score: 9.1,
        evidence: { variant: 'TE.CL', delay_ms: teclResult.delay, baseline_ms: teclResult.baseline },
      });
    }

    // TE.TE obfuscation detection
    for (const obfuscation of TE_OBFUSCATIONS) {
      const headerName = obfuscation.split(':')[0].trim();
      const res = await client.send(url, {
        method: 'POST',
        headers: {
          [headerName]: obfuscation.split(':').slice(1).join(':').trim(),
          'Content-Length': '0',
        },
        body: '0\r\n\r\n',
      });

      if (res.status === 200 || res.status === 400) {
        // Check if the server processed the obfuscated TE header differently
        const normalRes = await client.send(url, {
          method: 'POST',
          headers: { 'Transfer-Encoding': 'chunked', 'Content-Length': '0' },
          body: '0\r\n\r\n',
        });

        if (res.status !== normalRes.status || Math.abs(res.size - normalRes.size) > 100) {
          findings.push({
            severity: 'high',
            title: 'HTTP Request Smuggling (TE.TE Obfuscation)',
            description: `The server processes obfuscated Transfer-Encoding headers differently from standard ones. The variant "${obfuscation}" produced status ${res.status} while the standard header produced ${normalRes.status}. This discrepancy between front-end and back-end TE parsing enables request smuggling.`,
            url,
            remediation: 'Reject requests with ambiguous or obfuscated Transfer-Encoding headers.',
            cwe_id: 'CWE-444', owasp_category: 'A05:2021', cvss_score: 8.1,
            evidence: { obfuscation, obfuscated_status: res.status, normal_status: normalRes.status },
          });
          break;
        }
      }
    }

    return findings;
  }

  private timingProbe(host: string, port: number, _isHttps: boolean, _variant: string, payload: string): Promise<{ suspicious: boolean; delay: number; baseline: number }> {
    return new Promise((resolve) => {
      // Baseline request
      const baselineStart = Date.now();
      const baselineReq = `GET / HTTP/1.1\r\nHost: ${host}\r\nConnection: close\r\n\r\n`;

      const baseSocket = net.connect({ host, port }, () => {
        baseSocket.write(baselineReq);
      });

      let baselineDone = false;
      baseSocket.on('data', () => {
        if (!baselineDone) {
          baselineDone = true;
          const baseline = Date.now() - baselineStart;
          baseSocket.destroy();

          // Smuggling probe
          const probeStart = Date.now();
          const probeSocket = net.connect({ host, port }, () => {
            probeSocket.write(payload);
          });

          const timeout = setTimeout(() => {
            const delay = Date.now() - probeStart;
            probeSocket.destroy();
            resolve({ suspicious: delay > baseline + 3000, delay, baseline });
          }, 10000);

          probeSocket.on('data', () => {
            clearTimeout(timeout);
            const delay = Date.now() - probeStart;
            probeSocket.destroy();
            resolve({ suspicious: delay > baseline + 3000, delay, baseline });
          });

          probeSocket.on('error', () => {
            clearTimeout(timeout);
            resolve({ suspicious: false, delay: 0, baseline });
          });
        }
      });

      baseSocket.on('error', () => {
        resolve({ suspicious: false, delay: 0, baseline: 0 });
      });

      setTimeout(() => {
        baseSocket.destroy();
        resolve({ suspicious: false, delay: 0, baseline: 0 });
      }, 15000);
    });
  }
}
