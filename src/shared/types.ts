export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type ScanStatus = 'pending' | 'running' | 'completed' | 'failed' | 'cancelled';

export type ScanProfile = 'quick' | 'standard' | 'deep' | 'full' | 'custom';

export interface Project {
  id: string;
  name: string;
  target_url: string;
  created_at: string;
  updated_at: string;
}

export interface Scan {
  id: string;
  project_id: string;
  profile: ScanProfile;
  status: ScanStatus;
  target_url: string;
  config: ScanConfig | null;
  started_at: string | null;
  completed_at: string | null;
  total_requests: number;
  findings_count: FindingsCount;
}

export interface ScanConfig {
  profile?: string;
  modules: string[];
  rate_limit: number;
  max_concurrent: number;
  timeout: number;
  auth?: AuthConfig;
  respect_robots: boolean;
}

export interface AuthConfig {
  type: 'none' | 'bearer' | 'basic' | 'cookie' | 'custom';
  value?: any;
  token?: string;
  username?: string;
  password?: string;
  cookies?: string;
}

export interface FindingsCount {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface Finding {
  id: string;
  scan_id: string;
  module_id: string;
  severity: Severity;
  title: string;
  description: string;
  url: string;
  parameter: string | null;
  evidence: Evidence;
  remediation: string;
  cwe_id: string;
  owasp_category: string;
  cvss_score: number;
  false_positive: boolean;
  created_at: string;
}

export interface Evidence {
  request?: string;
  response?: string;
  payload?: string;
  proof?: string;
}

export interface Endpoint {
  id: string;
  scan_id: string;
  url: string;
  method: string;
  parameters: string[] | null;
  response_code: number;
  content_type: string;
  technology: string[] | null;
}

export interface ProxyHistoryEntry {
  id: number;
  method: string;
  url: string;
  host: string;
  port: number | null;
  is_https: boolean;
  request_headers: Record<string, string>;
  request_body: string | null;
  response_status: number | null;
  response_headers: Record<string, string> | null;
  response_body: string | null;
  response_length: number | null;
  content_type: string | null;
  duration_ms: number | null;
  intercepted: boolean;
  notes: string | null;
  timestamp: string;
}

export interface ProxyScopeRule {
  id: number;
  type: 'include' | 'exclude';
  protocol: string;
  host_pattern: string;
  port: string;
  path_pattern: string;
}

export interface InterceptedRequest {
  queue_id: string;
  method: string;
  url: string;
  headers: Record<string, string>;
  body: string | null;
  is_https: boolean;
  timestamp: number;
}

export interface ScanModule {
  id: string;
  name: string;
  category: string;
  description: string;
  severity: Severity;
  enabled: boolean;
}

export interface ScanTarget {
  url: string;
  endpoints: Endpoint[];
  config: ScanConfig;
}

export interface ProxySettings {
  port: number;
  intercept_enabled: boolean;
  scope_rules: ProxyScopeRule[];
}

export interface AppSettings {
  proxy_port: number;
  rate_limit: number;
  max_concurrent: number;
  scan_timeout: number;
  respect_robots: boolean;
  theme: 'dark' | 'light';
}
