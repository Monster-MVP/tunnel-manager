/** Independent browser QA against actual isolated OpenSSH/tinyproxy/verified TLS. */
import { chromium } from 'playwright';
import { expect } from '@playwright/test';
import fs from 'node:fs';
import net from 'node:net';
import path from 'node:path';

const root = process.cwd();
const metadata = JSON.parse(fs.readFileSync(process.argv[2] || 'var/reports/v2-reliability-fixture.json', 'utf8'));
const output = path.resolve(root, process.argv[3] || 'var/reports/v2-reliability-browser');
if (!output.startsWith(root + path.sep)) throw new Error('All audit output must stay inside project root');
fs.mkdirSync(output, { recursive: true, mode: 0o700 });
const evidence = { source: 'Actual isolated system OpenSSH, tinyproxy, verified TLS; API responses never mocked',
  fixture: metadata.evidence, checks: [], failures: [] };
function rpc(socketPath, request) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection(socketPath);
    let body = '';
    socket.setTimeout(3000);
    socket.on('connect', () => socket.write(JSON.stringify(request) + '\n'));
    socket.on('data', part => { body += part; if (body.includes('\n')) { socket.end(); resolve(JSON.parse(body.trim())); } });
    socket.on('error', reject);
    socket.on('timeout', () => { socket.destroy(); reject(new Error('Owned fixture IPC timeout')); });
  });
}
const browser = await chromium.launch({ channel: 'chrome', headless: true });
const context = await browser.newContext({ viewport: { width: 1440, height: 900 },
  recordVideo: { dir: path.join(output, 'video'), size: { width: 1440, height: 900 } } });
const page = await context.newPage();
const video = page.video();
const errors = [];
page.on('pageerror', error => errors.push(error.message));
let allowSocket = true;
let active;
await page.routeWebSocket(metadata.origin.replace('http://', 'ws://') + '/api/v1/ws', ws => {
  if (!allowSocket) { void ws.close({ code: 1012, reason: 'Isolated V2 reliability fault' }); return; }
  active = ws;
  ws.connectToServer(); // Actual backend frames; no synthetic state injection.
});
const row = key => page.locator(`[data-testid="channel-summary"][data-server-id="${metadata.profiles[key].id}"]`);
async function freePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const value = server.address().port;
      server.close(() => resolve(value));
    });
  });
}
const get = async endpoint => {
  const response = await page.request.get(metadata.origin + '/api/v1' + endpoint);
  expect(response.status(), endpoint).toBe(200);
  return response.json();
};
const headers = async () => ({ Origin: metadata.origin, 'X-CSRF-Token': (await get('/sessions/current')).csrf });
const runtime = key => get(`/servers/${metadata.profiles[key].id}/runtime`);
async function snapshot(name) {
  // Viewport capture avoids stitching fixed navigation into misleading positions.
  await page.screenshot({ path: path.join(output, name + '.png'), fullPage: false, animations: 'disabled' });
}
async function check(name, action) {
  const started = Date.now();
  try { await action(); evidence.checks.push({ name, result: 'PASS', duration_ms: Date.now() - started }); }
  catch (error) { evidence.failures.push({ name, message: error.message }); await snapshot('failure-' + evidence.failures.length); }
}
async function home() { await page.locator('.sidebar').getByRole('button', { name: '总览', exact: true }).click(); }
async function detail(key) {
  await home();
  await row(key).getByRole('button', { name: '详情', exact: true }).click();
  await expect(page.getByRole('heading', { name: metadata.profiles[key].name, exact: true })).toBeVisible();
}
try {
  const ticket = await rpc(metadata.ipc_socket, { command: 'ticket' });
  await page.goto(metadata.origin + '/#ticket=' + encodeURIComponent(ticket.ticket));
  await expect(page.locator('.local-indicator')).toContainText('实时同步');
  await check('Five-second channel distinction and topology equality', async () => {
    const before = Date.now();
    const overview = await get('/overview');
    for (const [key, profile] of Object.entries(metadata.profiles)) {
      const server = overview.servers.find(server => server.id === profile.id);
      const observed = overview.runtimes[profile.id];
      await expect(row(key)).toHaveAttribute('data-mode', server.mode);
      await expect(row(key)).toHaveAttribute('data-desired-state', server.desired_state);
      await expect(row(key)).toHaveAttribute('data-management', server.management);
      const proxy = row(key).getByRole('switch');
      if (server.desired_state === 'RUNNING' && server.mode !== 'DISABLED') await expect(proxy).toBeChecked();
      else await expect(proxy).not.toBeChecked();
      if (key === 'external') { await expect(proxy).toBeDisabled(); await expect(row(key)).toContainText('外部健康未知'); }
      else await expect(row(key)).toHaveAttribute('data-state', observed.state);
    }
    expect(Date.now() - before).toBeLessThan(5000);
    await expect(row('healthy')).toContainText('代理请求已通过');
    await expect(row('degraded')).toContainText('代理请求失败');
    await expect(page.getByTestId('topology-server')).toHaveCount(overview.servers.length);
    await snapshot('01-overview-authoritative');
  });
  await check('Real upstream HTTP503 degrades UI while switch stays enabled; HTTP200 restores', async () => {
    await rpc(metadata.fixture_socket, { command: 'upstream', status: 503 });
    await expect.poll(async () => (await runtime('healthy')).state, { timeout: 12000 }).toBe('DEGRADED');
    await expect(row('healthy')).toHaveAttribute('data-state', 'DEGRADED');
    await expect(row('healthy').getByRole('switch')).toBeChecked();
    await expect(row('healthy')).toContainText('代理请求失败');
    await snapshot('02-real-http503');
    await rpc(metadata.fixture_socket, { command: 'upstream', status: 200 });
    await expect.poll(async () => (await runtime('healthy')).state, { timeout: 12000 }).toBe('HEALTHY');
    await expect(row('healthy')).toHaveAttribute('data-state', 'HEALTHY');
    await expect(row('healthy')).toContainText('代理请求已通过');
  });
  await check('Chinese actual proxy switch stop/start with exact backend intent', async () => {
    await row('healthy').getByRole('switch').click();
    await page.getByRole('dialog', { name: '停止指定隧道？' }).getByRole('button', { name: '确认停止' }).click();
    await expect.poll(async () => (await runtime('healthy')).state).toBe('STOPPED');
    await expect(row('healthy')).toHaveAttribute('data-state', 'STOPPED');
    await expect(row('healthy').locator('.state-badge')).toHaveText('已停止');
    await expect(row('healthy').getByRole('switch')).not.toBeChecked();
    const stopped = await runtime('healthy');
    expect(stopped.process_alive).toBe(false);
    expect(stopped.proxy_health).not.toBe('HEALTHY');
    await snapshot('03-switch-stopped');
    await row('healthy').getByRole('switch').click();
    await expect.poll(async () => (await runtime('healthy')).state, { timeout: 12000 }).toBe('HEALTHY');
    await expect(row('healthy').getByRole('switch')).toBeChecked();
  });
  await check('Actual detail controls, monitoring timings and all history windows', async () => {
    await detail('healthy');
    const before = await runtime('healthy');
    await page.getByRole('button', { name: '重启隧道', exact: true }).click();
    await page.getByRole('dialog', { name: '重启指定隧道？' }).getByRole('button', { name: '确认重启' }).click();
    await expect.poll(async () => (await runtime('healthy')).pid, { timeout: 12000 }).not.toBe(before.pid);
    await expect.poll(async () => (await runtime('healthy')).state, { timeout: 12000 }).toBe('HEALTHY');
    await page.getByRole('button', { name: '立即探测', exact: true }).click();
    await expect(page.locator('.hero-status .state-badge')).toHaveText('健康');
    const fresh = await runtime('healthy');
    expect(fresh.http_status).toBe(200);
    expect(fresh.http_connect_status).toBe(200);
    expect(fresh.ssh_latency_ms).toBeGreaterThan(0);
    expect(fresh.tls_completed_ms).toBeGreaterThan(0);
    expect(fresh.tls_handshake_ms).toBeGreaterThanOrEqual(0);
    expect(fresh.total_ms).toBeGreaterThan(0);
    for (const [range, label] of Object.entries({ '5m': '5 分钟', '1h': '1 小时', '24h': '24 小时', '7d': '7 天' })) {
      await page.getByRole('group', { name: '历史时间范围' }).getByRole('button', { name: label, exact: true }).click();
      const history = await get(`/servers/${metadata.profiles.healthy.id}/metrics/history?range=${range}`);
      expect(history.summary.sample_count).toBeGreaterThan(0);
      expect(history.summary.success_count).toBeLessThanOrEqual(history.summary.sample_count);
      expect(history.samples.some(sample => sample.http_status === 200 && sample.http_connect_status === 200)).toBe(true);
      await expect(page.locator('.chart-panel')).toContainText('个实际探测样本');
    }
    await snapshot('04-detail-real-timings-history');
  });
  await check('Custom exit preflight then actual healthy mode switch', async () => {
    const target = (await get(`/servers/${metadata.profiles.degraded.id}`)).proxy_port;
    await page.locator('.mode-option').filter({ hasText: 'Clash HTTP' }).click();
    const dialog = page.getByRole('dialog', { name: '确认切换代理出口' });
    await dialog.getByLabel('目标本机代理端口', { exact: true }).fill(String(target));
    await dialog.getByRole('button', { name: '检查目标出口', exact: true }).click();
    await expect(dialog).toContainText('目标出口检查完成');
    await dialog.getByRole('button', { name: '确认切换', exact: true }).click();
    await expect.poll(async () => (await get(`/servers/${metadata.profiles.healthy.id}`)).mode).toBe('CLASH_HTTP');
    await expect.poll(async () => (await runtime('healthy')).state, { timeout: 12000 }).toBe('HEALTHY');
    expect((await get(`/servers/${metadata.profiles.healthy.id}`)).proxy_port).toBe(target);
    await expect(page.locator('.mode-option.selected')).toContainText('Clash HTTP');
    await snapshot('05-custom-exit-switched');
  });
  await check('Unavailable target exit blocks confirmation and preserves owned PID', async () => {
    const before = await runtime('healthy');
    await page.locator('.mode-option').filter({ hasText: 'Mac 直连' }).click();
    const dialog = page.getByRole('dialog', { name: '确认切换代理出口' });
    // The actual external tinyproxy listening port cannot be adopted for managed tinyproxy.
    const occupied = (await get(`/servers/${metadata.profiles.degraded.id}`)).proxy_port;
    await dialog.getByLabel('目标本机代理端口', { exact: true }).fill(String(occupied));
    await dialog.getByRole('button', { name: '检查目标出口', exact: true }).click();
    await expect(dialog).toContainText('发现阻断条件');
    await expect(dialog.getByRole('button', { name: '确认切换', exact: true })).toBeDisabled();
    await dialog.getByRole('button', { name: '取消', exact: true }).click();
    expect((await runtime('healthy')).pid).toBe(before.pid);
    expect((await get(`/servers/${metadata.profiles.healthy.id}`)).mode).toBe('CLASH_HTTP');
  });
  await check('Wizard actual connection/proxy tests save stopped profile and clean up', async () => {
    const source = await get(`/servers/${metadata.profiles.healthy.id}`);
    await home();
    await page.getByRole('button', { name: '添加服务器', exact: true }).first().click();
    const dialog = page.getByRole('dialog', { name: '添加服务器', exact: true });
    await dialog.getByLabel('显示名称').fill('中文向导 · 实际链路测试');
    await dialog.getByLabel('SSH 主机').fill(source.host);
    await dialog.getByLabel('SSH 用户').fill(source.user);
    await dialog.getByLabel('SSH 端口', { exact: true }).fill(String(source.ssh_port));
    await dialog.getByRole('button', { name: '下一步', exact: true }).click();
    await dialog.getByRole('combobox', { name: '代理出口', exact: true }).selectOption('CLASH_HTTP');
    const port = await freePort();
    await dialog.getByLabel('远程代理端口').fill(String(port));
    await dialog.getByLabel('本地监听端口').fill(String(source.proxy_port));
    await dialog.getByText('高级设置', { exact: true }).click();
    await dialog.getByLabel('健康检查 URL').fill(source.health_url);
    await dialog.getByLabel('自动重连').uncheck();
    await dialog.getByRole('button', { name: '下一步', exact: true }).click();
    await dialog.getByRole('button', { name: '保存并测试连接', exact: true }).click();
    await expect(dialog.locator('.test-result')).toContainText('测试通过', { timeout: 12000 });
    await dialog.getByRole('button', { name: '保存并测试代理链路', exact: true }).click();
    await expect(dialog.locator('.test-result')).toContainText('代理请求通过', { timeout: 12000 });
    await expect(dialog.locator('.test-result')).toContainText('临时连接已停止');
    const saved = (await get('/servers')).find(server => server.name === '中文向导 · 实际链路测试');
    expect(saved.desired_state).toBe('STOPPED');
    const observed = await get(`/servers/${saved.id}/runtime`);
    expect(observed.state).toBe('STOPPED');
    expect(observed.process_alive).toBe(false);
    expect(observed.proxy_health).not.toBe('HEALTHY');
    await snapshot('06-wizard-real-tests-cleanup');
    await dialog.getByRole('button', { name: '添加服务器', exact: true }).click();
    await expect(dialog).not.toBeVisible();
  });
  await check('External resource controls remain disabled and backend forbidden', async () => {
    await detail('external');
    await expect(page.locator('.hero-status')).toContainText('外部健康未知');
    for (const label of ['外部服务不可控制', '停止隧道', '重启隧道', '立即探测', '运行诊断'])
      await expect(page.getByRole('button', { name: label, exact: true })).toBeDisabled();
    const response = await page.request.post(metadata.origin + `/api/v1/servers/${metadata.profiles.external.id}/actions/start`, { headers: await headers() });
    expect(response.status()).toBe(403);
    await snapshot('07-external-observation');
  });
  await check('Actual WebSocket loss shows stale state while backend remains healthy, then resync', async () => {
    await detail('healthy');
    allowSocket = false;
    await active.close({ code: 1012, reason: 'Isolated actual browser WebSocket fault' });
    await expect(page.locator('.local-indicator')).toContainText('连接中断');
    await expect(page.locator('.hero-status .state-badge')).toContainText('观测过期');
    await expect(page.locator('.hero-status .state-badge')).not.toHaveClass(/good/);
    expect((await runtime('healthy')).state).toBe('HEALTHY');
    await snapshot('08-websocket-lost-not-false-healthy');
    allowSocket = true;
    await expect(page.locator('.local-indicator')).toContainText('实时同步', { timeout: 12000 });
    await expect(page.locator('.hero-status .state-badge')).toHaveText('健康');
  });
  await check('Actual Codex diagnostic presents reachability evidence without LLM claim', async () => {
    const completed = page.waitForResponse(response => response.url().endsWith('/diagnostics') && response.request().method() === 'POST');
    await page.getByRole('button', { name: '运行诊断', exact: true }).click();
    const response = await completed;
    expect(response.status()).toBe(200);
    const observed = await response.json();
    expect(observed.target_url).toBe('https://hubway.cc/v1');
    expect(observed.llm_completion_verified).toBe(false);
    expect(observed.ssh_connected).toBe(true);
    expect(observed.remote_listener).toBe('LISTENING');
    expect(observed.request_elapsed_ms).toBeGreaterThan(0);
    await expect(page.locator('.diagnostic-result:not([data-testid="codex-credential-result"])')).toContainText('https://hubway.cc/v1');
    await expect(page.locator('.diagnostic-result:not([data-testid="codex-credential-result"])')).toContainText(observed.http_status == null ? '未完成' : String(observed.http_status));
    await expect(page.getByText('网络诊断的 HTTP 可达只证明本次代理链路请求完成，不代表模型生成或鉴权成功。网络诊断不读取 API Key。', { exact: true })).toBeVisible();
    await snapshot('09-real-codex-diagnostic');
  });
  const cookieState = await context.cookies(); // Memory only; never saved in evidence.
  const beforeClose = await runtime('healthy');
  await context.close();
  await video.saveAs(path.join(output, 'key-chinese-workflows.webm'));
  const requestContext = await browser.newContext();
  await requestContext.addCookies(cookieState);
  const afterClose = await requestContext.request.get(metadata.origin + `/api/v1/servers/${metadata.profiles.healthy.id}/runtime`);
  const fresh = await afterClose.json();
  expect(afterClose.status()).toBe(200);
  expect(fresh.state).toBe('HEALTHY');
  expect(fresh.process_alive).toBe(true);
  expect(fresh.pid).toBe(beforeClose.pid);
  evidence.checks.push({ name: 'Browser closed; actual owned backend/tunnel still healthy same PID', result: 'PASS' });
  await requestContext.close();
  expect(errors).toEqual([]);
} catch (error) {
  evidence.failures.push({ name: 'Harness/final browser-close verification', message: error.message });
} finally {
  await context.close();
  await browser.close();
  fs.writeFileSync(path.join(output, 'evidence.json'), JSON.stringify(evidence, null, 2));
  console.log(JSON.stringify({ checks: evidence.checks, failures: evidence.failures, output }));
  if (evidence.failures.length) process.exitCode = 1;
}
