import https from 'https';
import Database from 'better-sqlite3';

const GEMINI_MODEL = 'gemini-2.0-flash';
const API_BASE = 'generativelanguage.googleapis.com';

export interface AIAnalysisResult {
  summary: string;
  risk_level: 'critical' | 'high' | 'medium' | 'low' | 'none';
  vulnerabilities: AIVulnerability[];
  attack_chains: string[];
  recommendations: string[];
  false_positive_likelihood: 'high' | 'medium' | 'low';
}

export interface AIVulnerability {
  type: string;
  evidence: string;
  severity: string;
  explanation: string;
}

function getApiKey(db: Database.Database): string | null {
  try {
    const row = db.prepare("SELECT value FROM app_settings WHERE key = 'gemini_api_key'").get() as any;
    return row?.value?.replace(/^"|"$/g, '') || null;
  } catch {
    return null;
  }
}

function geminiRequest(apiKey: string, body: any): Promise<any> {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify(body);
    const path = `/v1beta/models/${GEMINI_MODEL}:generateContent?key=${apiKey}`;
    const options = {
      hostname: API_BASE,
      path,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(data),
      },
    };

    const req = https.request(options, (res) => {
      let body = '';
      res.on('data', (chunk) => { body += chunk; });
      res.on('end', () => {
        try { resolve(JSON.parse(body)); }
        catch { reject(new Error('Invalid JSON response from Gemini')); }
      });
    });
    req.on('error', reject);
    req.setTimeout(30000, () => { req.destroy(); reject(new Error('Gemini request timeout')); });
    req.write(data);
    req.end();
  });
}

function extractText(response: any): string {
  return response?.candidates?.[0]?.content?.parts?.[0]?.text || '';
}

export class GeminiAnalyzer {
  private db: Database.Database;

  constructor(db: Database.Database) {
    this.db = db;
  }

  isConfigured(): boolean {
    return !!getApiKey(this.db);
  }

  async analyzeHttpResponse(url: string, method: string, requestHeaders: string, requestBody: string | null, responseStatus: number, responseHeaders: string, responseBody: string): Promise<AIAnalysisResult> {
    const apiKey = getApiKey(this.db);
    if (!apiKey) throw new Error('Gemini API key not configured');

    const truncatedBody = responseBody.slice(0, 8000);
    const prompt = `You are an expert web application security analyst. Analyze this HTTP exchange for security vulnerabilities.

URL: ${url}
Method: ${method}
Request Headers: ${requestHeaders.slice(0, 1000)}
Request Body: ${requestBody?.slice(0, 500) || '(none)'}

Response Status: ${responseStatus}
Response Headers: ${responseHeaders.slice(0, 1000)}
Response Body (truncated): ${truncatedBody}

Analyze for ALL of these:
1. Information disclosure (stack traces, server versions, internal paths, API keys, tokens, credentials in response)
2. Security header issues (missing HSTS, CSP, X-Frame-Options, etc.)
3. Sensitive data exposure (PII, credit cards, SSNs, passwords, tokens)
4. JWT or session token issues visible in response
5. Error messages revealing database/framework details
6. Insecure direct object references (IDs, file paths)
7. Business logic hints (pricing, admin flags, role fields)
8. JavaScript secrets or hardcoded credentials
9. Open redirects or XSS reflection points
10. API key patterns or credentials

Respond ONLY with valid JSON in this exact format:
{
  "summary": "one paragraph summary",
  "risk_level": "critical|high|medium|low|none",
  "vulnerabilities": [
    {"type": "vulnerability name", "evidence": "exact text from response", "severity": "critical|high|medium|low", "explanation": "why this is dangerous"}
  ],
  "attack_chains": ["how multiple issues chain together"],
  "recommendations": ["specific fix"],
  "false_positive_likelihood": "high|medium|low"
}`;

    const response = await geminiRequest(apiKey, {
      contents: [{ parts: [{ text: prompt }] }],
      generationConfig: { temperature: 0.1, maxOutputTokens: 2048 },
    });

    const text = extractText(response);
    const jsonMatch = text.match(/\{[\s\S]*\}/);
    if (!jsonMatch) throw new Error('No JSON in Gemini response');
    return JSON.parse(jsonMatch[0]);
  }

  async analyzeJavaScript(url: string, code: string): Promise<AIAnalysisResult> {
    const apiKey = getApiKey(this.db);
    if (!apiKey) throw new Error('Gemini API key not configured');

    const truncated = code.slice(0, 12000);
    const prompt = `You are an expert web application security analyst specializing in JavaScript security. Analyze this JavaScript code/bundle for security vulnerabilities.

Source URL: ${url}
JavaScript Code (may be minified/bundled):
\`\`\`javascript
${truncated}
\`\`\`

Look for ALL of these issues:
1. Hardcoded API keys (AWS: AKIA..., Stripe: sk_live_..., Twilio, SendGrid, Firebase, Google Maps, OpenAI, Anthropic, GitHub tokens, etc.)
2. Hardcoded passwords, secrets, encryption keys, JWT secrets
3. Internal API endpoints, admin routes, debug endpoints
4. Database connection strings
5. Private IP addresses or internal hostnames
6. Authentication bypass logic (admin checks, role comparisons)
7. Dangerous functions: eval(), innerHTML, document.write(), dangerouslySetInnerHTML
8. PostMessage without origin validation
9. Prototype pollution sinks (Object.assign, merge, extend with user input)
10. DOM-based XSS sinks (innerHTML, outerHTML with location.*)
11. Client-side template injection
12. Sensitive business logic (pricing calculations, permission checks)
13. Cryptographic weaknesses (Math.random() for tokens, MD5, hardcoded IVs)
14. Environment variables leaked (process.env.*, import.meta.env.*)
15. CORS policy in code (hardcoded allowlist with *)

Respond ONLY with valid JSON:
{
  "summary": "one paragraph summary",
  "risk_level": "critical|high|medium|low|none",
  "vulnerabilities": [
    {"type": "name", "evidence": "exact code snippet proving the issue", "severity": "critical|high|medium|low", "explanation": "why dangerous"}
  ],
  "attack_chains": ["how issues chain"],
  "recommendations": ["specific fix"],
  "false_positive_likelihood": "high|medium|low"
}`;

    const response = await geminiRequest(apiKey, {
      contents: [{ parts: [{ text: prompt }] }],
      generationConfig: { temperature: 0.1, maxOutputTokens: 2048 },
    });

    const text = extractText(response);
    const jsonMatch = text.match(/\{[\s\S]*\}/);
    if (!jsonMatch) throw new Error('No JSON in Gemini response');
    return JSON.parse(jsonMatch[0]);
  }

  async analyzeFindings(findings: any[]): Promise<{ attack_chains: string[]; priority_order: string[]; executive_summary: string }> {
    const apiKey = getApiKey(this.db);
    if (!apiKey) throw new Error('Gemini API key not configured');

    const findingSummary = findings.slice(0, 30).map(f =>
      `[${f.severity.toUpperCase()}] ${f.title} - ${f.url} (${f.cwe_id})`
    ).join('\n');

    const prompt = `You are a senior penetration tester. Given these security findings from a web application scan, identify attack chains and prioritize for remediation.

Findings:
${findingSummary}

Analyze:
1. Which findings chain together to create more serious attacks (e.g., SSRF + cloud metadata = credential theft)
2. Which single finding has the highest real-world impact
3. What's the most realistic attack scenario for a malicious actor
4. Priority order for remediation

Respond ONLY with valid JSON:
{
  "attack_chains": ["detailed chain: Finding A + Finding B leads to full compromise because..."],
  "priority_order": ["1. Fix X first because...", "2. Then fix Y..."],
  "executive_summary": "paragraph for non-technical management about overall risk"
}`;

    const response = await geminiRequest(apiKey, {
      contents: [{ parts: [{ text: prompt }] }],
      generationConfig: { temperature: 0.2, maxOutputTokens: 1024 },
    });

    const text = extractText(response);
    const jsonMatch = text.match(/\{[\s\S]*\}/);
    if (!jsonMatch) throw new Error('No JSON in Gemini response');
    return JSON.parse(jsonMatch[0]);
  }

  async analyzeCookies(cookies: string[], url: string): Promise<AIAnalysisResult> {
    const apiKey = getApiKey(this.db);
    if (!apiKey) throw new Error('Gemini API key not configured');

    const prompt = `Analyze these HTTP cookies from ${url} for security vulnerabilities.

Cookies:
${cookies.join('\n')}

Check for:
1. Missing Secure flag (sent over HTTP)
2. Missing HttpOnly flag (accessible via JS)
3. Missing SameSite attribute (CSRF risk)
4. Weak/predictable session tokens (short length, sequential, timestamp-based)
5. JWT tokens in cookies (decode and check claims, expiry, algorithm)
6. Base64-encoded data (decode and check for sensitive info)
7. Cookie prefixes (__Secure-, __Host-) misuse
8. Session fixation indicators
9. Long-lived sessions (max-age > 24 hours)
10. Sensitive data stored in cookies (usernames, roles, prices)

Respond ONLY with valid JSON:
{
  "summary": "one paragraph",
  "risk_level": "critical|high|medium|low|none",
  "vulnerabilities": [
    {"type": "name", "evidence": "the actual cookie value/attribute", "severity": "critical|high|medium|low", "explanation": "why dangerous"}
  ],
  "attack_chains": ["how cookie issues chain"],
  "recommendations": ["specific fix"],
  "false_positive_likelihood": "high|medium|low"
}`;

    const response = await geminiRequest(apiKey, {
      contents: [{ parts: [{ text: prompt }] }],
      generationConfig: { temperature: 0.1, maxOutputTokens: 1024 },
    });

    const text = extractText(response);
    const jsonMatch = text.match(/\{[\s\S]*\}/);
    if (!jsonMatch) throw new Error('No JSON in Gemini response');
    return JSON.parse(jsonMatch[0]);
  }
}
