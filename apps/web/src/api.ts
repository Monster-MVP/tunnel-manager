import type { ApiError, CodexCredentialCheck, CodexModelPreview, CodexModelTestInput, CodexModelTestResult, Group, LogEntry, Metric, Mode, Operation, Runtime, Server } from '../../../shared/types';

export type Overview = { servers: Server[]; runtimes: Record<string, Runtime>; groups: Group[]; dependencies?: Record<string, unknown> };
export type ImportPreview = { preview_id: string; candidates: Partial<Server>[]; warnings: string[]; source_sha256?: string };
export type Artifact = { artifact_id: string; download_url?: string; filename?: string };
export type MigrationPreview = { state: string; prerequisites: string[]; steps: string[]; rollback: string[]; plan_sha256: string; execution_enabled: false };
export type DiscoveryResponse = { observed_at: string; discovery_id?: string; ssh_config: { state: string; candidates: Array<Partial<Server> & { source?: string; health?: string }>; warnings: string[] }; launchd: { state: string; jobs: Array<{ label: string; pid_observed: boolean }> }; processes: { state: string; items: Array<{ program: string; pid: number }> }; listeners: { state: string; items: Array<{ port: number; bind_host: string }> }; warning?: string };
export type ActivityEvent = { occurred_at: string; action: string; result: string; server_id?: string | null; details?: Record<string, unknown> };
export type HistoryResponse = { range: string; samples: Metric[]; summary: { sample_count: number; success_count: number; success_ratio: number | null; avg_total_ms: number | null; p50_total_ms: number | null; last_observed_at: string | null } };

let csrf = '';
let sessionAttempt: Promise<boolean> | null = null;

function errorFrom(status: number, body: unknown): ApiError {
  if (body && typeof body === 'object' && 'detail' in body) body = (body as { detail: unknown }).detail;
  if (body && typeof body === 'object' && 'code' in body && 'message' in body) return body as ApiError;
  if (Array.isArray(body)) return { code: 'VALIDATION_ERROR', message: body.map(item => item.msg || '参数无效').join('；') };
  return { code: `HTTP_${status}`, message: status === 401 ? '会话已过期，请重新打开应用。' : `请求失败（${status}）` };
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  headers.set('Accept', 'application/json');
  if (init.body && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json');
  if (csrf && init.method && init.method !== 'GET') headers.set('X-CSRF-Token', csrf);
  const response = await fetch(`/api/v1${path}`, { ...init, headers, credentials: 'include' });
  const text = await response.text();
  let body: unknown = null;
  try { body = text ? JSON.parse(text) : null; } catch { body = text; }
  if (!response.ok) throw errorFrom(response.status, body);
  return body as T;
}

export function establishSession(): Promise<boolean> {
  sessionAttempt ??= establishSessionOnce();
  return sessionAttempt;
}

async function establishSessionOnce(): Promise<boolean> {
  try {
    const ticket = new URLSearchParams(window.location.hash.slice(1)).get('ticket');
    if (ticket) {
      window.history.replaceState(null, '', `${window.location.pathname}${window.location.search}`);
      await request('/sessions/exchange', { method: 'POST', body: JSON.stringify({ ticket }) });
    }
    const current = await request<{ csrf: string }>('/sessions/current');
    csrf = current?.csrf ?? '';
    return true;
  } catch { return false; }
}

export async function getOverview() { return request<Overview>('/overview'); }
export async function getServers() { return request<Server[]>('/servers'); }
const editableServer = (data: Partial<Server>, includeMode = false) => Object.fromEntries(Object.entries(data).filter(([key]) => ['name', 'host', 'ssh_alias', 'ssh_port', 'user', 'identity_file_ref', 'group_id', 'remote_proxy_port', ...(includeMode ? ['mode'] : []), 'proxy_port', 'auto_reconnect', 'restore_on_login', 'management', 'health_url', 'expected_status'].includes(key)));
export async function createServer(data: Partial<Server>) { return request<Server>('/servers', { method: 'POST', body: JSON.stringify(editableServer(data, true)) }); }
export async function updateServer(id: string, data: Partial<Server>, revision?: number) { return request<Server>(`/servers/${encodeURIComponent(id)}`, { method: 'PATCH', headers: revision === undefined ? undefined : { 'If-Match': String(revision) }, body: JSON.stringify(editableServer(data)) }); }
export async function deleteServer(id: string) { return request<void>(`/servers/${encodeURIComponent(id)}`, { method: 'DELETE' }); }
export async function setMode(id: string, mode: Mode, proxy_port?: number, revision?: number) { return request<Operation>(`/servers/${encodeURIComponent(id)}/mode`, { method: 'PUT', headers: revision === undefined ? undefined : { 'If-Match': String(revision) }, body: JSON.stringify({ mode, ...(proxy_port ? { proxy_port } : {}) }) }); }
export async function tunnelAction(id: string, action: 'start' | 'stop' | 'restart') { return request<Operation>(`/servers/${encodeURIComponent(id)}/actions/${action}`, { method: 'POST', headers: { 'Idempotency-Key': crypto.randomUUID() } }); }
export async function getRuntime(id: string) { return request<Runtime>(`/servers/${encodeURIComponent(id)}/runtime`); }
export async function probe(id: string) { return request<Operation>(`/servers/${encodeURIComponent(id)}/probes`, { method: 'POST', headers: { 'Idempotency-Key': crypto.randomUUID() } }); }
export async function getMetrics(id: string) { return request<Metric[]>(`/servers/${encodeURIComponent(id)}/metrics`); }
export async function getLogs(id: string, q = '') { return request<LogEntry[]>(`/servers/${encodeURIComponent(id)}/logs?limit=200${q ? `&q=${encodeURIComponent(q)}` : ''}`); }
export async function getGroups() { return request<Group[]>('/groups'); }
export async function createGroup(name: string) { return request<Group>('/groups', { method: 'POST', body: JSON.stringify({ name }) }); }
export async function deleteGroup(id: string) { return request<void>(`/groups/${encodeURIComponent(id)}`, { method: 'DELETE' }); }
export async function getSettings() { return request<Record<string, unknown>>('/settings'); }
export async function updateSettings(data: Record<string, unknown>) { return request<Record<string, unknown>>('/settings', { method: 'PATCH', body: JSON.stringify(data) }); }
export async function exportConfig(includeConnectionDetails = false) { return request<Artifact>('/configuration/export', { method: 'POST', body: JSON.stringify({ include_connection_details: includeConnectionDetails }) }); }
export async function importPreview(content: string) { return request<ImportPreview>('/imports/ssh-config/preview', { method: 'POST', body: JSON.stringify({ content }) }); }
export async function commitImport(preview: ImportPreview, indexes: number[]) { return request<{ servers: Server[] }>('/imports/' + encodeURIComponent(preview.preview_id) + '/commit', { method: 'POST', body: JSON.stringify({ indexes, expected_hash: preview.source_sha256 }) }); }
export async function configImportPreview(content: unknown) { return request<{ preview_id: string; servers: number; warnings: string[] }>('/configuration/import/preview', { method: 'POST', body: JSON.stringify(content) }); }
export async function commitConfigImport(id: string) { return request<{ servers: Server[] }>(`/configuration/import/${encodeURIComponent(id)}/commit`, { method: 'POST', body: '{}' }); }
export async function diagnosticsExport() { return request<Artifact>('/diagnostics/exports', { method: 'POST', body: '{}' }); }
export function downloadArtifact(artifact: Artifact) { const a = document.createElement('a'); a.href = artifact.download_url || `/api/v1/artifacts/${encodeURIComponent(artifact.artifact_id)}`; a.download = artifact.filename || ''; a.click(); }
export async function wsTicket() { return request<{ ticket: string }>('/ws-tickets', { method: 'POST', body: '{}' }); }
export async function migrationPreview(serverId: string) { return request<MigrationPreview>('/migrations/proposals', { method: 'POST', body: JSON.stringify({ server_id: serverId }) }); }
export async function getDiscovery() { return request<DiscoveryResponse>('/discovery'); }
export async function importDiscovery(indexes: number[], discovery_id?: string) { return request<{ servers: Server[] }>('/discovery/import', { method: 'POST', body: JSON.stringify({ indexes, discovery_id }) }); }
export async function getActivity(limit = 30) { return request<ActivityEvent[]>(`/activity?limit=${Math.min(100, Math.max(1, limit))}`); }
export async function getMetricsHistory(id: string, range: '5m' | '1h' | '24h' | '7d' = '24h') { return request<HistoryResponse>(`/servers/${encodeURIComponent(id)}/metrics/history?range=${range}`); }
export async function preflight(id: string, mode?: Mode, proxy_port?: number) { return request<Record<string, unknown>>(`/servers/${encodeURIComponent(id)}/preflight`, { method: 'POST', body: JSON.stringify({ ...(mode ? {mode} : {}), ...(proxy_port ? {proxy_port} : {}) }) }); }
export async function runDiagnostics(id: string, target_url = 'https://hubway.cc/v1') { return request<Record<string, unknown>>(`/servers/${encodeURIComponent(id)}/diagnostics`, { method: 'POST', body: JSON.stringify({ target_url }) }); }
export async function checkCodexCredentials(id: string) { return request<CodexCredentialCheck>(`/servers/${encodeURIComponent(id)}/credentials/codex/check`, { method: 'POST', body: JSON.stringify({ source: 'REMOTE_CODEX_AUTH_JSON', consent: true }) }); }
export async function previewCodexModel(id: string) { return request<CodexModelPreview>(`/servers/${encodeURIComponent(id)}/model-test/preview`, { method: 'POST', body: JSON.stringify({ source: 'REMOTE_CODEX_AUTH_JSON' }) }); }
export async function testCodexModel(id: string, data: CodexModelTestInput) { return request<CodexModelTestResult>(`/servers/${encodeURIComponent(id)}/model-test`, { method: 'POST', body: JSON.stringify(data) }); }
export async function getOperation(id: string) { return request<Operation>(`/operations/${encodeURIComponent(id)}`); }
export async function testConnection(id: string, kind: 'connection' | 'proxy' = 'proxy') { return request<Record<string, unknown>>(`/servers/${encodeURIComponent(id)}/tests`, { method: 'POST', body: JSON.stringify({ kind }) }); }
export function setCsrf(value: string) { csrf = value; }
