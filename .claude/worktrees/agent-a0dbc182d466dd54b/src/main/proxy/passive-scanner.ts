interface PassiveFinding {
  title: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  url: string;
  evidence: any;
  cwe_id: string;
  owasp_category: string;
}

interface TrafficEntry {
  method: string;
  url: string;
  host: string;
  request_headers: Record<string, string>;
  response_status: number;
  response_headers: Record<string, string>;
  response_body: string;
}

export class PassiveScanner {
  private seenFindings = new Set<string>();

  analyze(entry: TrafficEntry): PassiveFinding[] {
    const findings: PassiveFinding[] = [];
    this.checkSecurityHeaders(entry, findings);
    this.checkCookieFlags(entry, findings);
    this.checkInformationDisclosure(entry, findings);
    this.checkSensitiveData(entry, findings);

    // Deduplicate: only report each finding type once per host per session
    const deduplicated: PassiveFinding[] = [];
    for (const finding of findings) {
      const key = `${entry.host}:${finding.title}`;
      if (!this.seenFindings.has(key)) {
        this.seenFindings.add(key);
        deduplicated.push(finding);
      }
    }

    return deduplicated;
  }

  private checkSecurityHeaders(entry: TrafficEntry, findings: PassiveFinding[]): void {
    const headers = entry.response_headers;
    const lowerHeaders: Record<string, string> = {};
    for (const [k, v] of Object.entries(headers)) {
      lowerHeaders[k.toLowerCase()] = v;
    }

    // Check for missing HSTS
    if (!lowerHeaders['strict-transport-security']) {
      findings.push({
        title: 'Missing Strict-Transport-Security Header',
        description: 'The response does not include a Strict-Transport-Security (HSTS) header. This allows downgrade attacks and cookie hijacking via unencrypted HTTP connections.',
        severity: 'medium',
        url: entry.url,
        evidence: { missing_header: 'Strict-Transport-Security' },
        cwe_id: 'CWE-319',
        owasp_category: 'A05:2021 Security Misconfiguration',
      });
    }

    // Check for missing X-Content-Type-Options
    if (!lowerHeaders['x-content-type-options']) {
      findings.push({
        title: 'Missing X-Content-Type-Options Header',
        description: 'The response does not include X-Content-Type-Options: nosniff. This allows MIME-type sniffing which can lead to XSS attacks.',
        severity: 'low',
        url: entry.url,
        evidence: { missing_header: 'X-Content-Type-Options' },
        cwe_id: 'CWE-693',
        owasp_category: 'A05:2021 Security Misconfiguration',
      });
    }

    // Check for missing X-Frame-Options
    if (!lowerHeaders['x-frame-options']) {
      findings.push({
        title: 'Missing X-Frame-Options Header',
        description: 'The response does not include an X-Frame-Options header. This can allow clickjacking attacks by embedding the page in an iframe.',
        severity: 'medium',
        url: entry.url,
        evidence: { missing_header: 'X-Frame-Options' },
        cwe_id: 'CWE-1021',
        owasp_category: 'A05:2021 Security Misconfiguration',
      });
    }

    // Check for Server version disclosure
    if (lowerHeaders['server'] && /[\d.]+/.test(lowerHeaders['server'])) {
      findings.push({
        title: 'Server Version Disclosure',
        description: `The Server header discloses version information: "${lowerHeaders['server']}". This helps attackers identify known vulnerabilities for the specific server version.`,
        severity: 'info',
        url: entry.url,
        evidence: { header: 'Server', value: lowerHeaders['server'] },
        cwe_id: 'CWE-200',
        owasp_category: 'A05:2021 Security Misconfiguration',
      });
    }

    // Check for X-Powered-By disclosure
    if (lowerHeaders['x-powered-by']) {
      findings.push({
        title: 'X-Powered-By Header Disclosure',
        description: `The X-Powered-By header discloses technology information: "${lowerHeaders['x-powered-by']}". This helps attackers fingerprint the application stack.`,
        severity: 'info',
        url: entry.url,
        evidence: { header: 'X-Powered-By', value: lowerHeaders['x-powered-by'] },
        cwe_id: 'CWE-200',
        owasp_category: 'A05:2021 Security Misconfiguration',
      });
    }
  }

  private checkCookieFlags(entry: TrafficEntry, findings: PassiveFinding[]): void {
    const headers = entry.response_headers;

    // Collect all Set-Cookie headers (may be comma-separated in flattened form)
    const setCookieValue = headers['set-cookie'] || headers['Set-Cookie'];
    if (!setCookieValue) return;

    const cookies = setCookieValue.split(/,(?=\s*\w+=)/);
    for (const cookie of cookies) {
      const cookieName = cookie.split('=')[0]?.trim();
      if (!cookieName) continue;

      const lowerCookie = cookie.toLowerCase();

      if (!lowerCookie.includes('secure')) {
        findings.push({
          title: 'Cookie Missing Secure Flag',
          description: `The cookie "${cookieName}" is set without the Secure flag. This means the cookie can be transmitted over unencrypted HTTP connections.`,
          severity: 'medium',
          url: entry.url,
          evidence: { cookie_name: cookieName, set_cookie: cookie.trim() },
          cwe_id: 'CWE-614',
          owasp_category: 'A05:2021 Security Misconfiguration',
        });
      }

      if (!lowerCookie.includes('httponly')) {
        findings.push({
          title: 'Cookie Missing HttpOnly Flag',
          description: `The cookie "${cookieName}" is set without the HttpOnly flag. This allows JavaScript to access the cookie, increasing the impact of XSS attacks.`,
          severity: 'medium',
          url: entry.url,
          evidence: { cookie_name: cookieName, set_cookie: cookie.trim() },
          cwe_id: 'CWE-1004',
          owasp_category: 'A05:2021 Security Misconfiguration',
        });
      }

      if (!lowerCookie.includes('samesite')) {
        findings.push({
          title: 'Cookie Missing SameSite Attribute',
          description: `The cookie "${cookieName}" is set without the SameSite attribute. This can make the application vulnerable to CSRF attacks.`,
          severity: 'low',
          url: entry.url,
          evidence: { cookie_name: cookieName, set_cookie: cookie.trim() },
          cwe_id: 'CWE-1275',
          owasp_category: 'A01:2021 Broken Access Control',
        });
      }
    }
  }

  private checkInformationDisclosure(entry: TrafficEntry, findings: PassiveFinding[]): void {
    const body = entry.response_body;
    if (!body) return;

    // Check for internal IP addresses
    const internalIpRegex = /\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b/g;
    const ipMatches = body.match(internalIpRegex);
    if (ipMatches) {
      const uniqueIps = [...new Set(ipMatches)];
      findings.push({
        title: 'Internal IP Address Disclosure',
        description: `The response body contains internal IP address(es): ${uniqueIps.join(', ')}. This reveals internal network topology to attackers.`,
        severity: 'low',
        url: entry.url,
        evidence: { internal_ips: uniqueIps },
        cwe_id: 'CWE-200',
        owasp_category: 'A01:2021 Broken Access Control',
      });
    }

    // Check for email addresses
    const emailRegex = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g;
    const emailMatches = body.match(emailRegex);
    if (emailMatches) {
      const uniqueEmails = [...new Set(emailMatches)].slice(0, 10);
      findings.push({
        title: 'Email Address Disclosure',
        description: `The response body contains email address(es) that may be used for social engineering or enumeration attacks.`,
        severity: 'info',
        url: entry.url,
        evidence: { emails: uniqueEmails },
        cwe_id: 'CWE-200',
        owasp_category: 'A01:2021 Broken Access Control',
      });
    }

    // Check for stack traces
    const stackTracePatterns = [
      // Java
      /(?:java\.\w+\.[\w.$]+|at\s+[\w.$]+\([\w.]+:\d+\))/i,
      // Python
      /Traceback\s*\(most recent call last\)/i,
      /File\s+"[^"]+",\s+line\s+\d+/i,
      // PHP
      /(?:Fatal error|Parse error|Warning):\s+.+\s+in\s+.+\s+on\s+line\s+\d+/i,
      // Node.js
      /at\s+(?:Object\.|Module\.|Function\.|)[\w.]+\s+\([^)]*\.js:\d+:\d+\)/i,
      // .NET
      /(?:System\.[\w.]+Exception|Unhandled Exception|Stack Trace:)/i,
    ];

    for (const pattern of stackTracePatterns) {
      if (pattern.test(body)) {
        findings.push({
          title: 'Stack Trace Disclosure',
          description: 'The response body contains a stack trace or detailed error message. This reveals internal implementation details, file paths, and potentially sensitive configuration to attackers.',
          severity: 'medium',
          url: entry.url,
          evidence: { pattern: pattern.source, matched: true },
          cwe_id: 'CWE-209',
          owasp_category: 'A05:2021 Security Misconfiguration',
        });
        break; // One stack trace finding is enough
      }
    }

    // Check for SQL error messages
    const sqlErrorPatterns = [
      /SQL syntax.*?MySQL/i,
      /Warning.*?\Wmysqli?_/i,
      /PostgreSQL.*?ERROR/i,
      /ORA-\d{5}/i,
      /Microsoft SQL Native Client.*?Error/i,
      /ODBC SQL Server Driver/i,
      /SQLite3?::(?:SQLException|Query)/i,
      /Unclosed quotation mark/i,
      /quoted string not properly terminated/i,
    ];

    for (const pattern of sqlErrorPatterns) {
      if (pattern.test(body)) {
        findings.push({
          title: 'SQL Error Message Disclosure',
          description: 'The response body contains a SQL error message. This reveals database type and query structure, which can aid SQL injection attacks.',
          severity: 'medium',
          url: entry.url,
          evidence: { pattern: pattern.source, matched: true },
          cwe_id: 'CWE-209',
          owasp_category: 'A05:2021 Security Misconfiguration',
        });
        break; // One SQL error finding is enough
      }
    }
  }

  private checkSensitiveData(entry: TrafficEntry, findings: PassiveFinding[]): void {
    const body = entry.response_body;
    const headers = entry.response_headers;
    const isHttps = entry.url.startsWith('https://');

    // Check for API keys in common formats
    const apiKeyPatterns = [
      { name: 'AWS Access Key', pattern: /\bAKIA[0-9A-Z]{16}\b/ },
      { name: 'Google API Key', pattern: /\bAIza[0-9A-Za-z_-]{35}\b/ },
      { name: 'Slack Token', pattern: /\bxox[bporas]-[0-9a-zA-Z-]+\b/ },
      { name: 'GitHub Token', pattern: /\bgh[ps]_[A-Za-z0-9_]{36,}\b/ },
      { name: 'Generic API Key', pattern: /(?:api[_-]?key|apikey|api[_-]?secret)\s*[:=]\s*['"]([a-zA-Z0-9_\-]{20,})['"]/ },
    ];

    const textToCheck = body + '\n' + Object.values(headers).join('\n');

    for (const { name, pattern } of apiKeyPatterns) {
      const match = textToCheck.match(pattern);
      if (match) {
        findings.push({
          title: `Potential ${name} Exposure`,
          description: `A potential ${name} was detected in the response. API keys and secrets should never be exposed in HTTP responses.`,
          severity: 'high',
          url: entry.url,
          evidence: { key_type: name, matched_value: match[0].substring(0, 12) + '...' },
          cwe_id: 'CWE-798',
          owasp_category: 'A07:2021 Identification and Authentication Failures',
        });
      }
    }

    // Check for JWTs in response body
    if (body) {
      const jwtRegex = /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+\b/;
      const jwtMatch = body.match(jwtRegex);
      if (jwtMatch) {
        findings.push({
          title: 'JWT Token in Response Body',
          description: 'A JSON Web Token (JWT) was found in the response body. Ensure tokens are transmitted securely and not logged or cached.',
          severity: 'info',
          url: entry.url,
          evidence: { token_preview: jwtMatch[0].substring(0, 30) + '...' },
          cwe_id: 'CWE-200',
          owasp_category: 'A07:2021 Identification and Authentication Failures',
        });
      }
    }

    // Check for password fields in cleartext (non-HTTPS) responses
    if (!isHttps && body) {
      const passwordFieldRegex = /(?:type\s*=\s*['"]?password['"]?|name\s*=\s*['"]?(?:password|passwd|pass|pwd)['"]?)/i;
      if (passwordFieldRegex.test(body)) {
        findings.push({
          title: 'Password Field Over Unencrypted Connection',
          description: 'A password input field was detected in a page served over unencrypted HTTP. Credentials submitted through this form will be transmitted in cleartext.',
          severity: 'high',
          url: entry.url,
          evidence: { transport: 'HTTP (unencrypted)', contains_password_field: true },
          cwe_id: 'CWE-319',
          owasp_category: 'A02:2021 Cryptographic Failures',
        });
      }
    }
  }
}
