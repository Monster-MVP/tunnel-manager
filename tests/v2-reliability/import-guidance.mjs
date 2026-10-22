/** Independent candidate-copy audit; no user profiles or existing service controls. */
import { chromium } from 'playwright';
import { expect } from '@playwright/test';
import fs from 'node:fs';
import path from 'node:path';
import net from 'node:net';

const root = process.cwd();
const metadata = JSON.parse(fs.readFileSync(process.argv[2] || 'var/reports/import-guidance-fixture.json', 'utf8'));
const out = path.resolve(root, process.argv[3] || 'var/reports/import-guidance-reliability');
if (!out.startsWith(root + path.sep)) throw new Error('Audit output must remain project-local');
if (!metadata.fixture_socket || !metadata.profiles?.external || !metadata.profiles?.healthy)
  throw new Error('This check requires the isolated fixture metadata, never the default user app');
fs.mkdirSync(out, { recursive: true, mode: 0o700 });
const ticket = await new Promise((resolve, reject) => {
  const channel = net.createConnection(metadata.ipc_socket);
  let body = '';
  channel.setTimeout(3000);
  channel.on('connect', () => channel.write('{"command":"ticket"}\n'));
  channel.on('data', part => { body += part; if (body.includes('\n')) { channel.end(); resolve(JSON.parse(body)); } });
  channel.on('error', reject);
  channel.on('timeout', () => { channel.destroy(); reject(new Error('Fixture IPC timed out')); });
});
const browser = await chromium.launch({ channel: 'chrome', headless: true });
const context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
const page = await context.newPage();
const errors = [];
const uiControlRequests = [];
const externalId = metadata.profiles.external.id;
page.on('pageerror', error => errors.push(error.message));
page.on('request', request => {
  if (request.method() !== 'GET' && request.url().includes(`/servers/${externalId}/`) &&
      /\/(?:actions|mode|probes|tests|diagnostics)(?:\/|$)/.test(new URL(request.url()).pathname))
    uiControlRequests.push({ method: request.method(), path: new URL(request.url()).pathname });
});
const evidence = { scope: 'Isolated candidate web fixture; no default app changes', checks: [],
  fixture: metadata.evidence, ui_control_requests: uiControlRequests, api_control_results: [], failures: [] };
const stateEvidence = (profile, runtime) => ({
  management: profile.management, mode: profile.mode, revision: profile.revision, desired_state: profile.desired_state,
  state: runtime.state, reason_code: runtime.reason_code, process_alive: runtime.process_alive,
  ssh_connected: runtime.ssh_connected, remote_listener: runtime.remote_listener, proxy_health: runtime.proxy_health,
});
const api = async endpoint => {
  const response = await page.request.get(metadata.origin + '/api/v1' + endpoint);
  expect(response.status()).toBe(200);
  return response.json();
};
try {
  await page.goto(metadata.origin + '/#ticket=' + encodeURIComponent(ticket.ticket));
  await expect(page.getByRole('heading', { name: '隧道总览', exact: true })).toBeVisible();
  await expect(page.locator('.local-indicator')).toContainText('实时同步');
  const before = await api(`/servers/${externalId}`);
  const beforeRuntime = await api(`/servers/${externalId}/runtime`);
  expect(before.management).toBe('OBSERVED_EXTERNAL');
  expect(before.desired_state).toBe('STOPPED');
  expect(beforeRuntime.process_alive).toBe(false);
  evidence.external_before = stateEvidence(before, beforeRuntime);
  const row = page.locator(`[data-testid="channel-summary"][data-server-id="${externalId}"]`);
  await expect(row.getByRole('switch')).toBeDisabled();
  await expect(row).toContainText('外部健康未知');
  await row.getByRole('button', { name: '详情', exact: true }).click();
  const summary = page.getByTestId('detail-channel-summary');
  await expect(summary).toContainText('外部健康未知');
  const control = page.getByRole('button', { name: '外部服务不可控制', exact: true });
  await expect(control).toBeDisabled();
  await expect(control).not.toHaveClass(/primary-button/);
  await expect(page.getByRole('button', { name: '启动隧道', exact: true })).toHaveCount(0);
  for (const name of ['停止隧道', '重启隧道', '立即探测', '运行诊断'])
    await expect(page.getByRole('button', { name, exact: true })).toBeDisabled();
  for (const option of await page.locator('.mode-option').all()) await expect(option).toBeDisabled();
  const guidance = page.locator('[data-testid="external-control-guidance"]');
  await expect(summary).toContainText('外部观察记录');
  await expect(summary).toContainText('未建立应用托管通道');
  await expect(summary).toContainText('不会自动接管原服务');
  await expect(guidance).toContainText('添加服务器');
  await expect(guidance).toContainText('接管');
  await expect(guidance).toContainText('授权');
  await expect(page.locator('.fact-grid')).toContainText('仅观察，不执行重连');
  for (const label of ['SSH 进程', 'SSH 连接'])
    await expect(page.locator('.metric-line').filter({ hasText: label })).toContainText('未观测');
  const disabledControls = [control, ...['停止隧道', '重启隧道', '立即探测', '运行诊断']
    .map(name => page.getByRole('button', { name, exact: true }))];
  for (const button of disabledControls) await button.dispatchEvent('click');
  for (const option of await page.locator('.mode-option').all()) await option.dispatchEvent('click');
  for (let index = 0; index < 24; index++) {
    await page.keyboard.press('Tab');
    expect(await page.evaluate(() => document.activeElement?.matches('button:disabled'))).toBe(false);
  }
  expect(uiControlRequests).toEqual([]);
  await summary.evaluate(element => {
    for (let current = element.parentElement; current; current = current.parentElement) current.scrollTop = 0;
    window.scrollTo(0, 0);
  });
  await page.screenshot({ path: path.join(out, 'external-guidance.png'), animations: 'disabled', mask: [page.locator('[data-sensitive]')] });
  evidence.checks.push('External neutral disabled label, explicit observation/new-channel/takeover guidance, zero UI control requests');
  const session = await api('/sessions/current');
  const headers = { Origin: metadata.origin, 'X-CSRF-Token': session.csrf };
  for (const action of ['start', 'stop', 'restart']) {
    const endpoint = `/servers/${externalId}/actions/${action}`;
    const response = await page.request.post(`${metadata.origin}/api/v1${endpoint}`, { headers });
    evidence.api_control_results.push({ method: 'POST', endpoint, status: response.status() });
    expect(response.status()).toBe(403);
  }
  const mode = await page.request.put(`${metadata.origin}/api/v1/servers/${externalId}/mode`,
    { headers: { ...headers, 'If-Match': String(before.revision) }, data: { mode: 'MAC_DIRECT', proxy_port: 18988 } });
  evidence.api_control_results.push({ method: 'PUT', endpoint: `/servers/${externalId}/mode`, status: mode.status() });
  expect(mode.status()).toBe(403);
  for (const [endpoint, data] of [['probes', {}], ['tests', { kind: 'proxy' }], ['diagnostics', {}]]) {
    const response = await page.request.post(`${metadata.origin}/api/v1/servers/${externalId}/${endpoint}`, { headers, data });
    evidence.api_control_results.push({ method: 'POST', endpoint: `/servers/${externalId}/${endpoint}`, status: response.status() });
    expect(response.status()).toBe(403);
  }
  const after = await api(`/servers/${externalId}`);
  expect(after).toEqual(before);
  const afterRuntime = await api(`/servers/${externalId}/runtime`);
  evidence.external_after = stateEvidence(after, afterRuntime);
  expect(evidence.external_after).toEqual(evidence.external_before);
  expect(uiControlRequests).toEqual([]);
  evidence.checks.push('Actual API rejects all external controls with 403; profile revision/ownership/intent and process state unchanged');
  await page.locator('.sidebar').getByRole('button', { name: '总览', exact: true }).click();
  const healthy = page.locator(`[data-testid="channel-summary"][data-server-id="${metadata.profiles.healthy.id}"]`);
  await healthy.getByRole('button', { name: '详情', exact: true }).click();
  await expect(page.getByRole('button', { name: '启动隧道', exact: true })).toHaveCount(1);
  await expect(page.getByRole('button', { name: '外部服务不可控制', exact: true })).toHaveCount(0);
  const managed = await api(`/servers/${metadata.profiles.healthy.id}`);
  const managedRuntime = await api(`/servers/${metadata.profiles.healthy.id}/runtime`);
  expect(managed.management).toBe('MANAGED');
  expect(managedRuntime.state).toBe('HEALTHY');
  expect(managedRuntime.process_alive).toBe(true);
  evidence.managed_observed = stateEvidence(managed, managedRuntime);
  evidence.checks.push('Managed profile retains the original 启动隧道 control contract and real HEALTHY owned process');
  expect(errors).toEqual([]);
} catch (error) {
  evidence.failures.push(error.message);
  await page.screenshot({ path: path.join(out, 'failure.png'), animations: 'disabled', mask: [page.locator('[data-sensitive]')] });
} finally {
  await context.close();
  await browser.close();
  fs.writeFileSync(path.join(out, 'evidence.json'), JSON.stringify(evidence, null, 2));
  console.log(JSON.stringify(evidence));
  if (evidence.failures.length) process.exitCode = 1;
}
