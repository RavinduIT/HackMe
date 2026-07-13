import type { ScanModuleInterface, EndpointInfo, ModuleFinding } from '../scanner/orchestrator';
import type { HttpClient } from '../scanner/http-client';

const JAVA_SIGNATURES = [/rO0AB/i, /aced0005/i, /ObjectInputStream/i, /ClassNotFoundException/i, /java\.io\.InvalidClassException/i, /java\.lang\.ClassCastException.*serialize/i, /writeObject/i];
const PHP_SIGNATURES = [/unserialize\(\)/i, /O:\d+:"/i, /a:\d+:\{/i, /PHP Fatal error.*unserialize/i, /__wakeup/i, /__destruct/i];
const PYTHON_SIGNATURES = [/pickle\.loads/i, /unpickling/i, /cPickle/i, /_reconstructor/i, /gASV/];
const DOTNET_SIGNATURES = [/AAEAAAD/i, /BinaryFormatter/i, /SoapFormatter/i, /ObjectStateFormatter/i, /LosFormatter/i, /System\.Runtime\.Serialization/i];
const NODE_SIGNATURES = [/\$\$ND_FUNC\$\$/i, /node-serialize/i, /funcster/i, /cryo/i];

const JAVA_PROBES = ['rO0ABXNyABFqYXZhLmxhbmcuQm9vbGVhbtT/'];
const PHP_PROBES = ['O:8:"DateTime":0:{}', 'a:1:{i:0;s:4:"test";}', 'O:8:"stdClass":0:{}'];
const NODE_PROBES = ['{"test":"_$$ND_FUNC$$_function(){return 1}()"}'];

export class DeserializationModule implements ScanModuleInterface {
  id = 'deserialization';
  name = 'Insecure Deserialization';

  async scan(url: string, endpoints: EndpointInfo[], client: HttpClient): Promise<ModuleFinding[]> {
    const findings: ModuleFinding[] = [];

    // Scan response headers and cookies for serialized data markers
    const mainRes = await client.get(url);
    const allHeaders = JSON.stringify(mainRes.headers);
    const setCookies = mainRes.headers['set-cookie'] || '';

    // Check for Java serialized data in cookies
    if (/rO0AB|aced0005/i.test(setCookies) || /rO0AB/i.test(allHeaders)) {
      findings.push({
        severity: 'high',
        title: 'Java Serialized Object in Cookie/Headers',
        description: 'A Java serialized object signature (rO0AB / AC ED 00 05) was detected in cookies or response headers. If the application deserializes this data without validation, it is vulnerable to Remote Code Execution via gadget chains (ysoserial).',
        url,
        remediation: 'Never deserialize untrusted data. Replace Java serialization with JSON. If unavoidable, use ObjectInputFilter (JEP 290) to restrict allowed classes.',
        cwe_id: 'CWE-502', owasp_category: 'A08:2021', cvss_score: 9.8,
        evidence: { detection: 'Java serialization signature in cookies/headers' },
      });
    }

    // Check for .NET ViewState
    if (mainRes.body.includes('__VIEWSTATE')) {
      const viewstateMatch = mainRes.body.match(/name="__VIEWSTATE"[^>]*value="([^"]+)"/);
      const macMatch = mainRes.body.match(/name="__VIEWSTATEGENERATOR"[^>]*value="([^"]+)"/);
      const eventValidation = mainRes.body.includes('__EVENTVALIDATION');

      if (viewstateMatch && !eventValidation) {
        findings.push({
          severity: 'high',
          title: 'ASP.NET ViewState Without MAC Validation',
          description: 'The page uses ASP.NET ViewState and may lack MAC (Message Authentication Code) validation. If ViewState MAC is disabled or the MachineKey is known/predictable, an attacker can inject serialized .NET objects for Remote Code Execution.',
          url,
          remediation: 'Ensure enableViewStateMac="true" in web.config. Use strong, randomly generated MachineKeys. Upgrade to ASP.NET 4.5+ which enforces ViewState MAC by default.',
          cwe_id: 'CWE-502', owasp_category: 'A08:2021', cvss_score: 8.1,
          evidence: { viewstate_length: viewstateMatch[1].length, has_event_validation: eventValidation },
        });
      }
    }

    // Test POST endpoints with serialized payloads
    for (const ep of endpoints) {
      if (ep.method !== 'POST') continue;

      // PHP deserialization probes
      for (const probe of PHP_PROBES) {
        for (const param of ep.params) {
          const res = await this.inject(ep, param, probe, client);
          if (res.status === 0) continue;

          for (const sig of PHP_SIGNATURES) {
            if (sig.test(res.body)) {
              findings.push({
                severity: 'critical',
                title: 'PHP Deserialization Detected',
                description: `The parameter "${param}" processes PHP serialized data. A test object "${probe}" triggered a deserialization-related response. An attacker can craft malicious serialized objects using PHPGGC to achieve Remote Code Execution via PHP magic methods (__wakeup, __destruct, __toString).`,
                url: ep.url, parameter: param,
                remediation: 'Never use unserialize() on user input. Use json_decode() instead. If unavoidable, use allowed_classes parameter to restrict deserialization.',
                cwe_id: 'CWE-502', owasp_category: 'A08:2021', cvss_score: 9.8,
                evidence: { probe, signature_matched: sig.toString() },
              });
              break;
            }
          }
        }
      }

      // Node.js deserialization probes
      for (const probe of NODE_PROBES) {
        const res = await client.post(ep.url, probe, { 'Content-Type': 'application/json' });
        if (res.status === 0) continue;

        for (const sig of NODE_SIGNATURES) {
          if (sig.test(res.body) || (res.status === 200 && res.body.includes('1'))) {
            // Check if the function executed
            const verifyProbe = '{"test":"_$$ND_FUNC$$_function(){return \\"hm_deser_confirmed\\"}()"}';
            const verifyRes = await client.post(ep.url, verifyProbe, { 'Content-Type': 'application/json' });

            if (verifyRes.body.includes('hm_deser_confirmed')) {
              findings.push({
                severity: 'critical',
                title: 'Node.js Deserialization RCE (node-serialize)',
                description: `The endpoint processes serialized Node.js objects with function execution. The _$$ND_FUNC$$_ pattern was executed server-side. This is a direct Remote Code Execution vulnerability.`,
                url: ep.url,
                remediation: 'Remove the node-serialize package. Never deserialize untrusted data. Use JSON.parse() instead.',
                cwe_id: 'CWE-502', owasp_category: 'A08:2021', cvss_score: 10.0,
                evidence: { probe: verifyProbe, confirmed: true },
              });
            }
            break;
          }
        }
      }
    }

    // Check for deserialization error messages in error responses
    const errorRes = await client.post(url, 'invalid_serialized_data', { 'Content-Type': 'application/x-java-serialized-object' });
    const allSigs = [...JAVA_SIGNATURES, ...DOTNET_SIGNATURES, ...PYTHON_SIGNATURES];
    for (const sig of allSigs) {
      if (sig.test(errorRes.body)) {
        const lang = JAVA_SIGNATURES.includes(sig) ? 'Java' : DOTNET_SIGNATURES.includes(sig) ? '.NET' : 'Python';
        findings.push({
          severity: 'medium',
          title: `${lang} Deserialization Endpoint Detected`,
          description: `The server processes ${lang} serialized data (detected signature: ${sig}). While exploitation requires a valid gadget chain, the presence of deserialization functionality is a significant risk.`,
          url,
          remediation: `Migrate away from ${lang} native serialization. Use JSON or Protocol Buffers instead.`,
          cwe_id: 'CWE-502', owasp_category: 'A08:2021', cvss_score: 5.3,
          evidence: { language: lang, signature: sig.toString() },
        });
        break;
      }
    }

    return findings;
  }

  private async inject(ep: EndpointInfo, param: string, payload: string, client: HttpClient) {
    const body = ep.params.map((p) => `${encodeURIComponent(p)}=${encodeURIComponent(p === param ? payload : 'test')}`).join('&');
    return client.post(ep.url, body, { 'Content-Type': 'application/x-www-form-urlencoded' });
  }
}
