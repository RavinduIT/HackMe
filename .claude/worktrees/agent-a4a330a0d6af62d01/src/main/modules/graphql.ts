import type { ScanModuleInterface, EndpointInfo, ModuleFinding } from '../scanner/orchestrator';
import type { HttpClient } from '../scanner/http-client';

const GRAPHQL_PATHS = ['/graphql', '/graphiql', '/v1/graphql', '/api/graphql', '/query', '/gql'];

const INTROSPECTION_QUERY = '{"query":"{ __schema { types { name fields { name type { name } } } } }"}';
const DEPTH_QUERY = '{"query":"{ __schema { types { name fields { name type { ofType { name fields { name type { ofType { name } } } } } } } } }"}';

export class GraphqlModule implements ScanModuleInterface {
  id = 'graphql';
  name = 'GraphQL';

  async scan(url: string, endpoints: EndpointInfo[], client: HttpClient): Promise<ModuleFinding[]> {
    const findings: ModuleFinding[] = [];
    const baseUrl = new URL(url).origin;

    for (const path of GRAPHQL_PATHS) {
      const gqlUrl = baseUrl + path;

      // 1. Check if GraphQL endpoint exists
      const probeRes = await client.post(gqlUrl, '{"query":"{ __typename }"}', { 'Content-Type': 'application/json' });
      if (probeRes.status !== 200) continue;

      let parsed;
      try { parsed = JSON.parse(probeRes.body); } catch { continue; }
      if (!parsed.data && !parsed.errors) continue;

      // 2. Introspection test
      const introRes = await client.post(gqlUrl, INTROSPECTION_QUERY, { 'Content-Type': 'application/json' });
      try {
        const introData = JSON.parse(introRes.body);
        if (introData.data?.__schema?.types) {
          const types = introData.data.__schema.types;
          const userTypes = types.filter((t: any) => !t.name.startsWith('__'));
          findings.push({
            severity: 'medium', title: 'GraphQL Introspection Enabled',
            description: `The GraphQL endpoint at "${gqlUrl}" has introspection enabled, exposing the complete API schema with ${userTypes.length} types. Attackers can discover all queries, mutations, and data structures.`,
            url: gqlUrl,
            remediation: 'Disable introspection in production. Most GraphQL frameworks have a configuration option for this.',
            cwe_id: 'CWE-200', owasp_category: 'A05:2021', cvss_score: 5.3,
            evidence: { types_count: types.length, sample_types: userTypes.slice(0, 10).map((t: any) => t.name) },
          });
        }
      } catch {}

      // 3. Batching attack test
      const batchPayload = JSON.stringify([
        { query: '{ __typename }' },
        { query: '{ __typename }' },
        { query: '{ __typename }' },
      ]);
      const batchRes = await client.post(gqlUrl, batchPayload, { 'Content-Type': 'application/json' });
      try {
        const batchData = JSON.parse(batchRes.body);
        if (Array.isArray(batchData) && batchData.length >= 3) {
          findings.push({
            severity: 'medium', title: 'GraphQL Batching Allowed',
            description: `The GraphQL endpoint accepts batched queries. An attacker can send hundreds of operations in a single request to bypass rate limiting or brute-force mutations.`,
            url: gqlUrl,
            remediation: 'Limit the number of operations per batch request. Implement per-operation rate limiting.',
            cwe_id: 'CWE-770', owasp_category: 'A05:2021', cvss_score: 5.3,
            evidence: { batch_size: batchData.length },
          });
        }
      } catch {}

      // 4. Depth limit test
      const depthRes = await client.post(gqlUrl, DEPTH_QUERY, { 'Content-Type': 'application/json' });
      try {
        const depthData = JSON.parse(depthRes.body);
        if (depthData.data && !depthData.errors) {
          findings.push({
            severity: 'low', title: 'GraphQL: No Query Depth Limit',
            description: 'The GraphQL endpoint does not enforce query depth limits. Deeply nested queries can cause DoS by consuming excessive server resources.',
            url: gqlUrl,
            remediation: 'Implement query depth limiting (recommended: max depth 10-15). Use query complexity analysis.',
            cwe_id: 'CWE-400', owasp_category: 'A05:2021', cvss_score: 3.1,
          });
        }
      } catch {}

      break;
    }

    return findings;
  }
}
