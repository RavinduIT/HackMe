import type { EndpointInfo } from '../scanner/orchestrator';

// Common parameter names to test when no params are discovered
export const COMMON_PARAMS = [
  'id', 'user_id', 'uid', 'username', 'email', 'password', 'name',
  'search', 'query', 'q', 'keyword', 's',
  'page', 'limit', 'offset', 'sort', 'order', 'filter',
  'url', 'redirect', 'next', 'return', 'callback', 'ref',
  'file', 'path', 'dir', 'filename', 'document',
  'action', 'type', 'category', 'tag', 'status',
  'token', 'key', 'api_key', 'code',
  'comment', 'message', 'title', 'body', 'content', 'description',
  'price', 'amount', 'quantity', 'count',
];

// Extract path parameters (numeric or UUID segments that look like IDs)
export function extractPathParams(url: string): { baseUrl: string; paramIndex: number; original: string }[] {
  try {
    const parsed = new URL(url);
    const segments = parsed.pathname.split('/').filter(Boolean);
    const pathParams: { baseUrl: string; paramIndex: number; original: string }[] = [];

    segments.forEach((seg, i) => {
      // Match numeric IDs, UUIDs, hex strings, or short alphanumeric tokens
      if (/^\d+$/.test(seg) || /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(seg) || (/^[a-f0-9]{16,}$/i.test(seg))) {
        pathParams.push({ baseUrl: url, paramIndex: i, original: seg });
      }
    });
    return pathParams;
  } catch { return []; }
}

// Build a URL with a modified path segment
export function replacePathSegment(url: string, segIndex: number, value: string): string {
  try {
    const parsed = new URL(url);
    const segments = parsed.pathname.split('/').filter(Boolean);
    segments[segIndex] = value;
    parsed.pathname = '/' + segments.join('/');
    return parsed.href;
  } catch { return url; }
}

// Expand an endpoint: if it has no params, return versions with common params to test
// Limits to the first N common params to avoid excessive testing
export function expandEndpoint(ep: EndpointInfo, maxParams: number = 8): EndpointInfo[] {
  if (ep.params.length > 0) return [ep];

  // Pick relevant common params based on URL hints
  const urlLower = ep.url.toLowerCase();
  const relevant: string[] = [];

  // Always include these
  relevant.push('id', 'q', 'search');

  // Context-specific params
  if (urlLower.includes('login') || urlLower.includes('auth') || urlLower.includes('signin')) {
    relevant.push('username', 'email', 'password', 'user', 'pass');
  }
  if (urlLower.includes('user') || urlLower.includes('profile') || urlLower.includes('account')) {
    relevant.push('user_id', 'uid', 'username', 'email', 'name');
  }
  if (urlLower.includes('search') || urlLower.includes('find') || urlLower.includes('query')) {
    relevant.push('query', 'keyword', 's', 'term', 'filter');
  }
  if (urlLower.includes('product') || urlLower.includes('item') || urlLower.includes('shop')) {
    relevant.push('product_id', 'category', 'price', 'name');
  }
  if (urlLower.includes('api')) {
    relevant.push('token', 'key', 'api_key', 'page', 'limit', 'offset');
  }
  if (urlLower.includes('file') || urlLower.includes('doc') || urlLower.includes('download')) {
    relevant.push('file', 'filename', 'path', 'document');
  }
  if (urlLower.includes('redirect') || urlLower.includes('return') || urlLower.includes('next')) {
    relevant.push('url', 'redirect', 'next', 'return', 'callback');
  }

  // Add generic fallbacks
  relevant.push('page', 'sort', 'order', 'type', 'action', 'callback', 'url', 'redirect');

  // Deduplicate and limit
  const unique = [...new Set(relevant)].slice(0, maxParams);

  return [{ ...ep, params: unique }];
}
