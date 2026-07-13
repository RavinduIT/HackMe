import tls from 'tls';
import type { ScanModuleInterface, EndpointInfo, ModuleFinding } from '../scanner/orchestrator';
import type { HttpClient } from '../scanner/http-client';

export class TlsSslModule implements ScanModuleInterface {
  id = 'tls-ssl';
  name = 'TLS/SSL Analysis';

  async scan(url: string, endpoints: EndpointInfo[], client: HttpClient): Promise<ModuleFinding[]> {
    const findings: ModuleFinding[] = [];
    if (!url.startsWith('https://')) {
      // Check if HTTP with no HTTPS redirect
      const httpRes = await client.send(url.replace('https://', 'http://'), { followRedirects: false });
      if (httpRes.status > 0 && httpRes.status !== 301 && httpRes.status !== 302) {
        findings.push({
          severity: 'high', title: 'HTTPS Not Enforced',
          description: 'The site is accessible over HTTP without redirecting to HTTPS. All traffic is unencrypted.',
          url, remediation: 'Redirect all HTTP traffic to HTTPS.',
          cwe_id: 'CWE-319', owasp_category: 'A02:2021', cvss_score: 7.5,
        });
      }
      return findings;
    }

    const hostname = new URL(url).hostname;
    const port = parseInt(new URL(url).port) || 443;

    try {
      const certInfo = await this.getCertificateInfo(hostname, port);

      if (certInfo.expired) {
        findings.push({
          severity: 'high', title: 'SSL Certificate Expired',
          description: `The certificate expired on ${certInfo.validTo}. Browsers will show security warnings.`,
          url, remediation: 'Renew the SSL certificate.',
          cwe_id: 'CWE-295', owasp_category: 'A02:2021', cvss_score: 7.4,
          evidence: { valid_to: certInfo.validTo, subject: certInfo.subject },
        });
      }

      if (certInfo.selfSigned) {
        findings.push({
          severity: 'medium', title: 'Self-Signed Certificate',
          description: 'The certificate is self-signed and not trusted by default by browsers or clients.',
          url, remediation: 'Use a certificate from a trusted Certificate Authority (e.g., Let\'s Encrypt).',
          cwe_id: 'CWE-295', owasp_category: 'A02:2021', cvss_score: 5.9,
        });
      }

      if (certInfo.daysRemaining !== null && certInfo.daysRemaining < 30 && !certInfo.expired) {
        findings.push({
          severity: 'low', title: 'Certificate Expiring Soon',
          description: `The certificate expires in ${certInfo.daysRemaining} days (${certInfo.validTo}).`,
          url, remediation: 'Renew the certificate before expiration.',
          cwe_id: 'CWE-295', owasp_category: 'A02:2021', cvss_score: 2.1,
        });
      }

      if (certInfo.protocol && ['TLSv1', 'TLSv1.1'].includes(certInfo.protocol)) {
        findings.push({
          severity: 'high', title: `Deprecated TLS Version: ${certInfo.protocol}`,
          description: `The server supports ${certInfo.protocol} which has known vulnerabilities and is deprecated.`,
          url, remediation: 'Disable TLS 1.0 and 1.1. Only allow TLS 1.2 and 1.3.',
          cwe_id: 'CWE-327', owasp_category: 'A02:2021', cvss_score: 7.4,
        });
      }

      if (certInfo.cipher) {
        const weakCiphers = ['RC4', 'DES', '3DES', 'NULL', 'EXPORT', 'anon'];
        for (const weak of weakCiphers) {
          if (certInfo.cipher.toUpperCase().includes(weak)) {
            findings.push({
              severity: 'high', title: `Weak Cipher Suite: ${certInfo.cipher}`,
              description: `The server uses a weak cipher suite containing ${weak}.`,
              url, remediation: 'Configure the server to use only strong cipher suites.',
              cwe_id: 'CWE-327', owasp_category: 'A02:2021', cvss_score: 7.4,
            });
          }
        }
      }

      // Check for HTTP fallback
      const httpUrl = url.replace('https://', 'http://');
      const httpRes = await client.send(httpUrl, { followRedirects: false, timeout: 5000 });
      if (httpRes.status > 0 && httpRes.status < 400 && httpRes.status !== 301 && httpRes.status !== 302) {
        findings.push({
          severity: 'medium', title: 'HTTP Port Open Without Redirect',
          description: 'The site serves content over HTTP (port 80) without redirecting to HTTPS.',
          url: httpUrl, remediation: 'Configure a 301 redirect from HTTP to HTTPS.',
          cwe_id: 'CWE-319', owasp_category: 'A02:2021', cvss_score: 5.4,
        });
      }

    } catch (err: any) {
      if (err.code === 'CERT_HAS_EXPIRED') {
        findings.push({
          severity: 'high', title: 'SSL Certificate Expired',
          description: 'TLS connection failed because the certificate has expired.',
          url, remediation: 'Renew the SSL certificate.',
          cwe_id: 'CWE-295', owasp_category: 'A02:2021', cvss_score: 7.4,
        });
      }
    }

    return findings;
  }

  private getCertificateInfo(hostname: string, port: number): Promise<any> {
    return new Promise((resolve, reject) => {
      const socket = tls.connect({ host: hostname, port, rejectUnauthorized: false, servername: hostname }, () => {
        const cert = socket.getPeerCertificate();
        const cipher = socket.getCipher();
        const protocol = socket.getProtocol();
        const authorized = socket.authorized;

        const validTo = cert.valid_to ? new Date(cert.valid_to) : null;
        const now = new Date();
        const expired = validTo ? validTo < now : false;
        const daysRemaining = validTo ? Math.floor((validTo.getTime() - now.getTime()) / 86400000) : null;

        socket.end();
        resolve({
          subject: cert.subject?.CN || '',
          issuer: cert.issuer?.CN || '',
          validFrom: cert.valid_from,
          validTo: cert.valid_to,
          expired,
          daysRemaining,
          selfSigned: cert.subject?.CN === cert.issuer?.CN && !authorized,
          protocol,
          cipher: cipher?.name || '',
          bits: cipher?.version || '',
          serialNumber: cert.serialNumber,
          fingerprint: cert.fingerprint,
        });
      });
      socket.on('error', reject);
      socket.setTimeout(10000, () => { socket.destroy(); reject(new Error('Timeout')); });
    });
  }
}
