import fs from 'fs';
import Database from 'better-sqlite3';

export function generateJsonReport(db: Database.Database, scanId: string, outputPath: string): void {
  const scan = db.prepare('SELECT * FROM scans WHERE id = ?').get(scanId) as any;
  if (!scan) throw new Error('Scan not found');

  const findings = db.prepare('SELECT * FROM findings WHERE scan_id = ? ORDER BY cvss_score DESC').all(scanId) as any[];
  const endpoints = db.prepare('SELECT * FROM endpoints WHERE scan_id = ?').all(scanId) as any[];

  const report = {
    meta: {
      tool: 'HackMe Security Scanner',
      version: '1.0.0',
      generated_at: new Date().toISOString(),
    },
    scan: {
      id: scan.id,
      target_url: scan.target_url,
      profile: scan.profile,
      status: scan.status,
      started_at: scan.started_at,
      completed_at: scan.completed_at,
      total_requests: scan.total_requests,
      findings_count: JSON.parse(scan.findings_count || '{}'),
    },
    findings: findings.map((f) => ({
      id: f.id,
      severity: f.severity,
      title: f.title,
      description: f.description,
      url: f.url,
      parameter: f.parameter,
      evidence: f.evidence ? JSON.parse(f.evidence) : null,
      remediation: f.remediation,
      cwe_id: f.cwe_id,
      owasp_category: f.owasp_category,
      cvss_score: f.cvss_score,
      module: f.module_id,
    })),
    endpoints: endpoints.map((e) => ({
      url: e.url,
      method: e.method,
      parameters: e.parameters ? JSON.parse(e.parameters) : [],
      content_type: e.content_type,
    })),
  };

  fs.writeFileSync(outputPath, JSON.stringify(report, null, 2));
}
