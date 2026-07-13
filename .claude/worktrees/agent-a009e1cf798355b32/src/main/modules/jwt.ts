import type { ScanModuleInterface, EndpointInfo, ModuleFinding } from '../scanner/orchestrator';
import type { HttpClient } from '../scanner/http-client';

const JWT_REGEX = /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{0,}/g;
const WEAK_SECRETS = ['secret', 'password', 'key', '123456', 'admin', 'jwt_secret', 'changeme', 'test', 'default', 'hackme', 'supersecret', 'mysecret'];

export class JwtModule implements ScanModuleInterface {
  id = 'jwt';
  name = 'JWT Analysis';

  async scan(url: string, endpoints: EndpointInfo[], client: HttpClient): Promise<ModuleFinding[]> {
    const findings: ModuleFinding[] = [];
    const res = await client.get(url);
    const allText = JSON.stringify(res.headers) + res.body;

    // Find JWTs in responses and cookies
    const jwts = allText.match(JWT_REGEX) || [];
    const cookies = res.headers['set-cookie'] || '';
    const cookieJwts = cookies.match(JWT_REGEX) || [];
    const allJwts = [...new Set([...jwts, ...cookieJwts])];

    for (const jwt of allJwts) {
      try {
        const [headerB64, payloadB64] = jwt.split('.');
        const header = JSON.parse(Buffer.from(headerB64, 'base64url').toString());
        const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString());

        // Check for "none" algorithm
        if (header.alg?.toLowerCase() === 'none' || header.alg === '') {
          findings.push({
            severity: 'critical', title: 'JWT: None Algorithm Accepted',
            description: 'The JWT uses alg:"none" which means the signature is not verified. Any user can forge tokens by setting the algorithm to "none" and removing the signature.',
            url, remediation: 'Reject tokens with alg:"none". Enforce a specific algorithm server-side.',
            cwe_id: 'CWE-345', owasp_category: 'A07:2021', cvss_score: 9.8,
            evidence: { header, payload_keys: Object.keys(payload) },
          });
        }

        // Check for weak HMAC algorithm
        if (header.alg === 'HS256' || header.alg === 'HS384' || header.alg === 'HS512') {
          findings.push({
            severity: 'info', title: `JWT: HMAC Algorithm (${header.alg})`,
            description: `The JWT uses ${header.alg}. If the secret is weak, the token can be brute-forced offline. RS256 with asymmetric keys is generally more secure.`,
            url, remediation: 'Use a strong random secret (256+ bits). Consider RS256 for better key management.',
            cwe_id: 'CWE-326', owasp_category: 'A02:2021', cvss_score: 0,
            evidence: { algorithm: header.alg },
          });
        }

        // Check for sensitive data in payload
        const sensitiveKeys = Object.keys(payload).filter((k) =>
          /password|secret|ssn|credit_card|card_number|cvv|social_security/i.test(k)
        );
        if (sensitiveKeys.length > 0) {
          findings.push({
            severity: 'high', title: 'JWT: Sensitive Data in Payload',
            description: `The JWT payload contains potentially sensitive fields: ${sensitiveKeys.join(', ')}. JWT payloads are base64-encoded, NOT encrypted — anyone can read them.`,
            url, remediation: 'Never store sensitive data in JWT payloads. Only include identifiers and claims.',
            cwe_id: 'CWE-200', owasp_category: 'A02:2021', cvss_score: 6.5,
            evidence: { sensitive_fields: sensitiveKeys },
          });
        }

        // Check for missing expiry
        if (!payload.exp) {
          findings.push({
            severity: 'medium', title: 'JWT: No Expiration Claim',
            description: 'The JWT has no "exp" claim. Tokens without expiration never become invalid, meaning a stolen token provides permanent access.',
            url, remediation: 'Always set an expiration time. Use short-lived access tokens with refresh token rotation.',
            cwe_id: 'CWE-613', owasp_category: 'A07:2021', cvss_score: 5.4,
          });
        } else {
          const exp = new Date(payload.exp * 1000);
          const now = new Date();
          const hoursUntilExpiry = (exp.getTime() - now.getTime()) / 3600000;
          if (hoursUntilExpiry > 168) {
            findings.push({
              severity: 'low', title: 'JWT: Long Expiration Time',
              description: `The JWT expires in ${Math.round(hoursUntilExpiry / 24)} days. Long-lived tokens increase the window for token theft exploitation.`,
              url, remediation: 'Use short expiry times (15-60 minutes) for access tokens.',
              cwe_id: 'CWE-613', owasp_category: 'A07:2021', cvss_score: 3.1,
            });
          }
        }

        // Check for JWK/JKU header injection potential
        if (header.jku || header.jwk || header.x5u) {
          findings.push({
            severity: 'high', title: 'JWT: External Key Reference (jku/jwk/x5u)',
            description: `The JWT header contains "${header.jku ? 'jku' : header.jwk ? 'jwk' : 'x5u'}" which points to an external key source. If the server fetches keys from this URL without validation, an attacker can supply their own signing key.`,
            url, remediation: 'Do not trust jku/jwk/x5u headers from tokens. Use a hardcoded key or trusted JWKS endpoint.',
            cwe_id: 'CWE-345', owasp_category: 'A07:2021', cvss_score: 8.1,
            evidence: { header },
          });
        }

        // Check kid header for injection
        if (header.kid) {
          const suspiciousKid = /['"\/\\;|&$]/.test(header.kid);
          if (suspiciousKid) {
            findings.push({
              severity: 'medium', title: 'JWT: Suspicious kid Header',
              description: `The JWT kid (Key ID) header contains special characters: "${header.kid}". If kid is used in file paths or SQL queries, this could lead to path traversal or SQL injection.`,
              url, remediation: 'Validate kid against an allowlist. Never use kid in file system operations or SQL queries.',
              cwe_id: 'CWE-20', owasp_category: 'A07:2021', cvss_score: 5.3,
              evidence: { kid: header.kid },
            });
          }
        }
      } catch {}
    }

    return findings;
  }
}
