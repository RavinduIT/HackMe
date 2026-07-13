import dns from 'dns';
import { promisify } from 'util';
import type { ScanModuleInterface, EndpointInfo, ModuleFinding } from '../scanner/orchestrator';
import type { HttpClient } from '../scanner/http-client';

const resolveCname = promisify(dns.resolveCname);
const resolve4 = promisify(dns.resolve4);

const COMMON_SUBDOMAINS = [
  'www', 'mail', 'blog', 'dev', 'staging', 'test', 'api', 'app', 'admin',
  'portal', 'cdn', 'static', 'assets', 'media', 'img', 'images', 'docs',
  'help', 'support', 'status', 'shop', 'store', 'beta', 'demo', 'stage',
  'uat', 'qa', 'preprod', 'sandbox', 'preview', 'dashboard', 'panel',
  'cms', 'auth', 'login', 'sso', 'id', 'accounts', 'my', 'vpn', 'remote',
  'git', 'gitlab', 'jenkins', 'ci', 'cd', 'deploy', 'monitor', 'grafana',
  'kibana', 'logs', 'metrics', 'internal', 'intranet', 'wiki', 'jira',
  'confluence', 'slack', 'email', 'smtp', 'imap', 'pop', 'mx', 'ns1', 'ns2',
  'ftp', 'sftp', 'backup', 'db', 'database', 'redis', 'elastic', 'search',
  'proxy', 'gateway', 'lb', 'edge', 'origin', 'web', 'www2', 'old', 'legacy',
  'new', 'm', 'mobile', 'wap', 'feeds', 'rss', 'newsletter', 'events',
  'calendar', 'chat', 'forum', 'community', 'social', 'video', 'stream',
];

const TAKEOVER_FINGERPRINTS: { service: string; cname_pattern: string; fingerprint: string; vulnerable: boolean }[] = [
  { service: 'AWS S3', cname_pattern: '.s3.amazonaws.com', fingerprint: 'The specified bucket does not exist', vulnerable: true },
  { service: 'AWS S3 (website)', cname_pattern: '.s3-website', fingerprint: 'The specified bucket does not exist', vulnerable: true },
  { service: 'AWS Elastic Beanstalk', cname_pattern: '.elasticbeanstalk.com', fingerprint: 'NXDOMAIN', vulnerable: true },
  { service: 'Azure', cname_pattern: '.cloudapp.net', fingerprint: 'NXDOMAIN', vulnerable: true },
  { service: 'Azure', cname_pattern: '.azurewebsites.net', fingerprint: 'NXDOMAIN', vulnerable: true },
  { service: 'Azure', cname_pattern: '.azure-api.net', fingerprint: 'NXDOMAIN', vulnerable: true },
  { service: 'Azure', cname_pattern: '.azurefd.net', fingerprint: 'NXDOMAIN', vulnerable: true },
  { service: 'Azure TrafficManager', cname_pattern: '.trafficmanager.net', fingerprint: 'NXDOMAIN', vulnerable: true },
  { service: 'GitHub Pages', cname_pattern: '.github.io', fingerprint: "There isn't a GitHub Pages site here", vulnerable: true },
  { service: 'Heroku', cname_pattern: '.herokuapp.com', fingerprint: 'No such app', vulnerable: true },
  { service: 'Shopify', cname_pattern: '.myshopify.com', fingerprint: 'Sorry, this shop is currently unavailable', vulnerable: true },
  { service: 'Bitbucket', cname_pattern: '.bitbucket.io', fingerprint: 'Repository not found', vulnerable: true },
  { service: 'Ghost', cname_pattern: '.ghost.io', fingerprint: 'Site unavailable', vulnerable: true },
  { service: 'Pantheon', cname_pattern: '.pantheonsite.io', fingerprint: '404 error unknown site', vulnerable: true },
  { service: 'WordPress.com', cname_pattern: '.wordpress.com', fingerprint: 'Do you want to register', vulnerable: true },
  { service: 'Surge.sh', cname_pattern: '.surge.sh', fingerprint: 'project not found', vulnerable: true },
  { service: 'Readme.io', cname_pattern: '.readme.io', fingerprint: 'The creators of this project', vulnerable: true },
  { service: 'Agile CRM', cname_pattern: '.agilecrm.com', fingerprint: 'Sorry, this page is no longer available', vulnerable: true },
  { service: 'Ngrok', cname_pattern: '.ngrok.io', fingerprint: 'Tunnel .*.ngrok.io not found', vulnerable: true },
  { service: 'Strikingly', cname_pattern: '.strikinglydns.com', fingerprint: 'PAGE NOT FOUND', vulnerable: true },
  { service: 'Help Scout', cname_pattern: '.helpscoutdocs.com', fingerprint: 'No settings were found', vulnerable: true },
  { service: 'Cargo', cname_pattern: '.cargocollective.com', fingerprint: '404 Not Found', vulnerable: true },
  { service: 'Feedpress', cname_pattern: '.redirect.feedpress.me', fingerprint: 'The feed has not been found', vulnerable: true },
  { service: 'Fly.io', cname_pattern: '.fly.dev', fingerprint: 'NXDOMAIN', vulnerable: true },
  { service: 'Vercel', cname_pattern: '.vercel.app', fingerprint: 'DEPLOYMENT_NOT_FOUND', vulnerable: true },
];

export class SubdomainTakeoverModule implements ScanModuleInterface {
  id = 'subdomain-takeover';
  name = 'Subdomain Takeover';

  async scan(url: string, endpoints: EndpointInfo[], client: HttpClient): Promise<ModuleFinding[]> {
    const findings: ModuleFinding[] = [];
    const domain = new URL(url).hostname;
    const baseDomain = domain.split('.').slice(-2).join('.');

    for (const sub of COMMON_SUBDOMAINS) {
      const subdomain = `${sub}.${baseDomain}`;

      try {
        // Check for CNAME records
        const cnames = await resolveCname(subdomain).catch(() => null);
        if (!cnames || cnames.length === 0) continue;

        const cnameTarget = cnames[0].toLowerCase();

        // Check against takeover fingerprints
        for (const fp of TAKEOVER_FINGERPRINTS) {
          if (!cnameTarget.includes(fp.cname_pattern)) continue;

          // Check if CNAME target resolves
          const resolves = await resolve4(cnameTarget).catch(() => null);

          if (!resolves) {
            // CNAME points to non-existent target — takeover possible
            findings.push({
              severity: 'high',
              title: `Subdomain Takeover: ${subdomain} (${fp.service})`,
              description: `The subdomain "${subdomain}" has a CNAME record pointing to "${cnameTarget}" (${fp.service}), but the target does not resolve (NXDOMAIN). An attacker can claim this resource on ${fp.service} and serve arbitrary content on your subdomain, enabling phishing, cookie theft, and account takeover.`,
              url: `https://${subdomain}`,
              remediation: `Remove the dangling CNAME record for ${subdomain}, or reclaim the resource on ${fp.service}.`,
              cwe_id: 'CWE-284', owasp_category: 'A05:2021', cvss_score: 8.2,
              evidence: { subdomain, cname: cnameTarget, service: fp.service, status: 'NXDOMAIN' },
            });
            break;
          }

          // CNAME resolves but check HTTP response for fingerprint
          try {
            const httpRes = await client.get(`https://${subdomain}`);
            if (httpRes.body.includes(fp.fingerprint)) {
              findings.push({
                severity: 'high',
                title: `Subdomain Takeover: ${subdomain} (${fp.service})`,
                description: `The subdomain "${subdomain}" points to ${fp.service} via CNAME "${cnameTarget}", and the response contains the error fingerprint "${fp.fingerprint}", indicating the resource is unclaimed. An attacker can register this resource and serve malicious content.`,
                url: `https://${subdomain}`,
                remediation: `Remove the CNAME record or reclaim the ${fp.service} resource.`,
                cwe_id: 'CWE-284', owasp_category: 'A05:2021', cvss_score: 8.2,
                evidence: { subdomain, cname: cnameTarget, service: fp.service, fingerprint: fp.fingerprint },
              });
            }
          } catch {}
          break;
        }
      } catch {}
    }

    return findings;
  }
}
