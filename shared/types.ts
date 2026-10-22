export type Mode = 'MAC_DIRECT' | 'CLASH_HTTP' | 'DISABLED';
export type State = 'STOPPED' | 'STARTING' | 'HEALTHY' | 'DEGRADED' | 'RECONNECTING' | 'FAILED' | 'AUTH_REQUIRED' | 'PORT_CONFLICT';
export interface Server {
  id: string; name: string; host: string; ssh_alias: string | null; ssh_port: number; user: string;
  identity_file_ref: string | null; group_id: string | null; remote_proxy_port: number;
  mode: Mode; proxy_port: number; auto_reconnect: boolean; restore_on_login: boolean;
  management: 'MANAGED' | 'OBSERVED_EXTERNAL'; desired_state: 'STOPPED' | 'RUNNING';
  health_url: string; expected_status: number[]; revision: number;
  created_at: string; updated_at: string;
}
export interface Runtime {
  server_id: string; state: State; reason_code: string | null; process_alive: boolean;
  ssh_connected: boolean; remote_listener: string; http_status: number | null;
  total_ms: number | null; tls_completed_ms: number | null; observed_at: string;
  consecutive_failures: number; reconnect_count: number;
  last_disconnected_at: string | null; last_recovered_at: string | null;
  direct_path_verification: 'UNVERIFIED'; stale: boolean; pid: number | null;
  proxy_health?: 'HEALTHY' | 'UNHEALTHY' | 'UNKNOWN';
  tls_handshake_ms?: number | null;
  ssh_latency_ms?: number | null;
  http_connect_status?: number | null;
  http_transport_ok?: boolean;
  last_success_at?: string | null;
  remote_listener_evidence?: string | null;
  monitoring_capability?: 'FULL' | 'PARTIAL' | 'UNAVAILABLE';
}
export interface Group { id: string; name: string }
export interface Metric { observed_at: string; state: State; http_status: number | null; total_ms: number | null; tls_completed_ms: number | null; error_code: string | null }
export interface MetricHistory {
  server_id: string;
  range: '5m' | '1h' | '24h' | '7d';
  from: string; to: string;
  sampling?: { strategy: 'LATEST_OBSERVATION_PER_BUCKET'; bucket_seconds: number; displayed_count: number; summary_scope: 'ALL_OBSERVATIONS' };
  samples: Metric[];
  summary: { sample_count: number; success_count: number; success_ratio: number | null;
    avg_total_ms: number | null; p50_total_ms: number | null; first_observed_at: string | null;
    last_observed_at: string | null; };
}
export interface DiscoveryFinding {
  id: string; kind: 'SSH_CONFIG' | 'LAUNCHD' | 'PROCESS' | 'LISTENER' | 'HISTORICAL';
  label: string; state: 'CONFIGURED' | 'OBSERVED' | 'INACCESSIBLE' | 'UNINSPECTED';
  ownership: 'OBSERVED_EXTERNAL' | 'UNKNOWN';
  details: Record<string, string | number | boolean | null>;
  observed_at: string | null;
  health: 'UNKNOWN' | 'HEALTHY' | 'UNHEALTHY';
}
export interface DiscoveryResponse {
  discovery_id: string; observed_at: string; ownership: 'OBSERVED_EXTERNAL'; health: 'UNKNOWN';
  ssh_config: { state: string; candidates: Partial<Server>[]; warnings: string[]; sha256?: string };
  launchd: { state: string; jobs: Record<string, unknown>[] };
  processes: { state: string; items: Record<string, unknown>[] };
  listeners: { state: string; items: Record<string, unknown>[] };
}
export interface ActivityEvent { id: string | number; occurred_at: string; action: string; result: string; server_id: string | null; details: Record<string, unknown>; }
export interface PreflightResult {
  server_id: string; ownership: string; can_start: boolean; blocking_reasons: string[];
  proposed_mode: Mode; local_reservation_conflicts: string[]; remote_listener: string;
  current_runtime: Runtime; local_proxy: { port: number; tcp_reachable: boolean; owned: boolean; http_health: string };
  ordinary_ssh_login_affected: false; production_control_enabled: false;
}
export interface DiagnosticResult {
  server_id: string; target_url: string; observed_at: string; mode: Mode;
  local_proxy_port: number; remote_proxy_port: number; ssh_connected: boolean;
  ssh_latency_ms: number | null; remote_listener: string; http_reachable: boolean;
  http_status: number | null; total_ms: number | null; tls_completed_ms: number | null;
  tls_handshake_ms: number | null; http_connect_status: number | null;
  llm_completion_verified: false; disclaimer: string;
}
export type CodexCredentialStatus = 'READABLE' | 'OAUTH_ONLY' | 'MISSING_KEY' | 'NOT_FOUND' | 'UNREADABLE' | 'TOO_LARGE' | 'INVALID_JSON' | 'INVALID_KEY' | 'REMOTE_TOOL_UNAVAILABLE' | 'CHECK_UNAVAILABLE' | 'NOT_TESTED';
export interface CodexCredentialCheck {
  credential_state: Exclude<CodexCredentialStatus, 'NOT_TESTED'>;
  key_readable: boolean | null; auth_mode: 'API_KEY' | 'OAUTH' | 'UNKNOWN';
  source_location: 'CODEX_HOME' | 'HOME_DEFAULT' | 'UNKNOWN';
  check_completed: boolean; ssh_connected: boolean; ownership: 'MANAGED';
  authentication: 'NOT_TESTED'; model_completion: 'NOT_TESTED';
  observed_at: string; reason_code: string | null;
}
export type CodexWireApi = 'responses' | 'chat';
export interface CodexModelPreview {
  source: 'REMOTE_CODEX_AUTH_JSON'; server_id: string; ownership: 'MANAGED'; ssh_connected: boolean;
  base_url: string | null; model: string | null; wire_api: CodexWireApi | null;
  config_state: 'READY' | 'NOT_FOUND' | 'UNREADABLE' | 'INVALID_CONFIG' | 'UNSUPPORTED_PROVIDER' | 'REMOTE_TOOL_UNAVAILABLE' | 'CHECK_UNAVAILABLE';
  reason_code: string | null; observed_at: string; profile_revision: number;
}
export interface CodexModelTestInput {
  source: 'REMOTE_CODEX_AUTH_JSON'; consent: true;
  base_url: string; model: string; wire_api: CodexWireApi; expected_revision: number;
}
export type CodexModelTestState = 'SUCCESS' | 'AUTH_REJECTED' | 'PERMISSION_DENIED' | 'RATE_LIMITED' | 'MODEL_UNAVAILABLE' | 'NETWORK_ERROR' | 'TLS_ERROR' | 'TIMEOUT' | 'INVALID_RESPONSE' | 'EMPTY_OUTPUT' | 'INCOMPLETE' | 'CREDENTIAL_UNAVAILABLE' | 'CHECK_UNAVAILABLE' | 'UPSTREAM_ERROR';
export interface CodexModelTestResult {
  source: 'REMOTE_CODEX_AUTH_JSON'; server_id: string; ownership: 'MANAGED'; ssh_connected: boolean;
  state: CodexModelTestState;
  authentication: 'VERIFIED' | 'REJECTED' | 'UNKNOWN' | 'NOT_TESTED';
  model_completion: 'SUCCEEDED' | 'FAILED' | 'NOT_TESTED'; llm_completion_verified: boolean;
  http_status: number | null; total_ms: number | null;
  credential_state: Exclude<CodexCredentialStatus, 'NOT_TESTED'> | 'NOT_CHECKED';
  reason_code: string | null; observed_at: string;
}
export interface Operation { id: string; operation_id?: string; status: string; server_id: string; action: string; error_code?: string | null }
export interface LogEntry { occurred_at: string; level: string; message: string }
export interface ApiError { code: string; message: string; details?: Record<string, unknown>; correlation_id?: string }
