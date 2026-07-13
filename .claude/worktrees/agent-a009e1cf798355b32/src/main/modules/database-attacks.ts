import type { ScanModuleInterface, EndpointInfo, ModuleFinding } from '../scanner/orchestrator';
import type { HttpClient } from '../scanner/http-client';

export class DatabaseAttacksModule implements ScanModuleInterface {
  id = 'database-attacks';
  name = 'Database Exposure & Injection';

  async scan(url: string, endpoints: EndpointInfo[], client: HttpClient): Promise<ModuleFinding[]> {
    const findings: ModuleFinding[] = [];
    const base = new URL(url).origin;
    const domain = new URL(url).hostname;

    // 1. MongoDB REST/HTTP interface
    for (const port of [27017, 28017]) {
      const mongoUrl = `http://${domain}:${port}`;
      const res = await client.get(mongoUrl);
      if (res.status === 200 && (res.body.includes('ismaster') || res.body.includes('mongod') || res.body.includes('serverStatus'))) {
        findings.push({
          severity: 'critical',
          title: `MongoDB HTTP Interface Exposed (port ${port})`,
          description: `MongoDB's HTTP interface is publicly accessible on port ${port}. An attacker can enumerate databases, collections, and extract all stored data.`,
          url: mongoUrl,
          remediation: 'Disable MongoDB HTTP interface. Bind to localhost. Enable authentication. Use firewall rules.',
          cwe_id: 'CWE-284', owasp_category: 'A01:2021', cvss_score: 9.8,
          evidence: { port, response_preview: res.body.slice(0, 200) },
        });
        break;
      }
    }

    // 2. CouchDB exposed
    const couchUrl = `http://${domain}:5984/_all_dbs`;
    const couchRes = await client.get(couchUrl);
    if (couchRes.status === 200 && couchRes.body.startsWith('[')) {
      findings.push({
        severity: 'critical',
        title: 'CouchDB Publicly Accessible',
        description: `CouchDB at ${couchUrl} is accessible without auth. The /_all_dbs endpoint reveals all databases. An attacker can read, modify, or delete all data.`,
        url: couchUrl,
        remediation: 'Enable CouchDB authentication. Restrict to localhost. Use firewall rules.',
        cwe_id: 'CWE-284', owasp_category: 'A01:2021', cvss_score: 9.8,
        evidence: { databases_preview: couchRes.body.slice(0, 200) },
      });
    }

    // 3. Memcached exposed (HTTP proxy or stats page)
    const memcachedUrl = `http://${domain}:11211`;
    const memRes = await client.get(memcachedUrl);
    if (memRes.body.includes('STAT') || memRes.body.includes('END') || memRes.body.includes('memcached')) {
      findings.push({
        severity: 'critical',
        title: 'Memcached Publicly Accessible',
        description: `Memcached on port 11211 is accessible. An attacker can read cached data (sessions, tokens, user data) or perform DDoS amplification attacks.`,
        url: memcachedUrl,
        remediation: 'Bind Memcached to 127.0.0.1. Enable SASL authentication. Block port 11211 at firewall.',
        cwe_id: 'CWE-284', owasp_category: 'A01:2021', cvss_score: 9.8,
      });
    }

    // 4. phpMyAdmin / Adminer exposed
    const dbAdmins = [
      { path: '/phpmyadmin/', name: 'phpMyAdmin', sig: 'phpMyAdmin' },
      { path: '/pma/', name: 'phpMyAdmin (alias)', sig: 'phpMyAdmin' },
      { path: '/adminer.php', name: 'Adminer', sig: 'adminer' },
      { path: '/adminer/', name: 'Adminer', sig: 'adminer' },
      { path: '/dbadmin/', name: 'Database Admin', sig: 'phpMyAdmin' },
      { path: '/mysql/', name: 'MySQL Admin', sig: 'phpMyAdmin' },
      { path: '/pgadmin/', name: 'pgAdmin', sig: 'pgAdmin' },
      { path: '/mongo-express/', name: 'Mongo Express', sig: 'mongo-express' },
    ];

    for (const { path, name, sig } of dbAdmins) {
      const res = await client.get(base + path);
      if (res.status === 200 && res.body.toLowerCase().includes(sig.toLowerCase())) {
        findings.push({
          severity: 'critical',
          title: `${name} Panel Publicly Accessible`,
          description: `A database administration panel (${name}) is accessible at ${base}${path}. An attacker can attempt to log in with default credentials or exploit known vulnerabilities to gain full database access.`,
          url: base + path,
          remediation: `Restrict ${name} access to internal networks only. Use IP whitelisting or VPN. Remove from production servers.`,
          cwe_id: 'CWE-284', owasp_category: 'A01:2021', cvss_score: 9.1,
          evidence: { admin_panel: name, path },
        });
      }
    }

    // 5. Database dump/backup files
    const backupPaths = [
      '/dump.sql', '/backup.sql', '/database.sql', '/db.sql',
      '/dump.sql.gz', '/backup.sql.gz', '/db.sql.gz',
      '/data.sql', '/export.sql', '/db_backup.sql',
      '/mysql.sql', '/postgres.sql', '/backup.zip',
      '/db-backup.tar.gz', '/site.sql', '/production.sql',
    ];

    for (const bp of backupPaths) {
      const res = await client.head(base + bp);
      if (res.status === 200) {
        const getRes = await client.get(base + bp);
        const looksLikeSql = /^(--|CREATE|INSERT|DROP|ALTER|GRANT|\/\*)/im.test(getRes.body.slice(0, 500));
        if (looksLikeSql || /^\x1f\x8b/.test(getRes.body.slice(0, 2))) {
          findings.push({
            severity: 'critical',
            title: `Database Dump File Accessible: ${bp}`,
            description: `A database dump file is publicly downloadable at ${base}${bp}. This file likely contains the entire database including user credentials, personal data, and business data.`,
            url: base + bp,
            remediation: 'Remove database dump files from web-accessible directories. Restrict access via web server rules.',
            cwe_id: 'CWE-538', owasp_category: 'A01:2021', cvss_score: 9.8,
            evidence: { path: bp, content_preview: getRes.body.slice(0, 100) },
          });
        }
      }
    }

    // 6. Elasticsearch query injection on endpoints
    for (const ep of endpoints.slice(0, 10)) {
      for (const param of ep.params) {
        const payload = '{"size":1,"query":{"match_all":{}}}';
        const testUrl = ep.url.includes('?')
          ? ep.url + `&${param}=${encodeURIComponent(payload)}`
          : ep.url + `?${param}=${encodeURIComponent(payload)}`;

        const res = await client.get(testUrl);
        if (res.body.includes('"hits"') && res.body.includes('"_source"')) {
          findings.push({
            severity: 'critical',
            title: `Elasticsearch Query Injection via "${param}"`,
            description: `Parameter "${param}" at ${ep.url} appears to pass queries directly to Elasticsearch. An attacker can extract all indexed data using match_all queries.`,
            url: ep.url,
            parameter: param,
            remediation: 'Never pass user input directly to Elasticsearch queries. Use parameterized queries or a whitelist of allowed fields.',
            cwe_id: 'CWE-943', owasp_category: 'A03:2021', cvss_score: 9.1,
            evidence: { param, payload, response_preview: res.body.slice(0, 200) },
          });
          break;
        }
      }
    }

    // 7. GraphQL database exposure (deep introspection for DB-linked fields)
    const gqlPaths = ['/graphql', '/api/graphql', '/graphql/v1'];
    for (const gp of gqlPaths) {
      const introRes = await client.request(base + gp, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          query: '{__schema{types{name,fields{name,type{name,kind,ofType{name}}}}}}'
        }),
      });

      if (introRes.status === 200 && introRes.body.includes('__schema')) {
        const dbFieldPatterns = /password|secret|token|apikey|credit_card|ssn|hash|salt/i;
        if (dbFieldPatterns.test(introRes.body)) {
          findings.push({
            severity: 'high',
            title: 'GraphQL Schema Exposes Sensitive Database Fields',
            description: `The GraphQL schema at ${base}${gp} exposes field names suggesting direct database column mapping. Sensitive fields like passwords or tokens may be queryable.`,
            url: base + gp,
            remediation: 'Disable introspection in production. Remove sensitive fields from the GraphQL schema. Use field-level authorization.',
            cwe_id: 'CWE-200', owasp_category: 'A01:2021', cvss_score: 7.5,
            evidence: { path: gp },
          });
        }
        break;
      }
    }

    // 8. Firebase Firestore REST API check
    const firebaseProjects = [
      domain.replace(/\./g, '-'),
      domain.split('.')[0],
    ];
    for (const proj of firebaseProjects) {
      const fsUrl = `https://firestore.googleapis.com/v1/projects/${proj}/databases/(default)/documents`;
      const fsRes = await client.get(fsUrl);
      if (fsRes.status === 200 && fsRes.body.includes('"documents"')) {
        findings.push({
          severity: 'critical',
          title: 'Firestore Database Publicly Readable',
          description: `The Firestore database for project "${proj}" is publicly accessible. All document collections can be enumerated and read without authentication.`,
          url: fsUrl,
          remediation: 'Configure Firestore security rules to require authentication for all reads and writes.',
          cwe_id: 'CWE-284', owasp_category: 'A01:2021', cvss_score: 9.1,
          evidence: { project: proj, response_preview: fsRes.body.slice(0, 200) },
        });
        break;
      }
    }

    // 9. S3 bucket open listing
    const bucketNames = [
      domain.replace(/\./g, '-'),
      domain.split('.')[0],
      domain.split('.')[0] + '-assets',
      domain.split('.')[0] + '-backup',
      domain.split('.')[0] + '-uploads',
      domain.split('.')[0] + '-data',
      domain.split('.')[0] + '-static',
      domain.split('.')[0] + '-prod',
    ];

    for (const bucket of bucketNames) {
      const s3Url = `https://${bucket}.s3.amazonaws.com`;
      const res = await client.get(s3Url);
      if (res.status === 200 && res.body.includes('<ListBucketResult')) {
        findings.push({
          severity: 'critical',
          title: `S3 Bucket Publicly Listable: ${bucket}`,
          description: `The S3 bucket "${bucket}" allows anonymous listing. All objects in the bucket are enumerable and potentially downloadable.`,
          url: s3Url,
          remediation: 'Set bucket policy to deny public listing. Enable "Block all public access" in S3 settings.',
          cwe_id: 'CWE-284', owasp_category: 'A01:2021', cvss_score: 9.1,
          evidence: { bucket, response_preview: res.body.slice(0, 300) },
        });
      }
    }

    return findings;
  }
}
