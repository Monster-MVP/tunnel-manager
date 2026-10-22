/** Independent UI audit against packaged candidate and synthetic real SSH checks. */
import { chromium } from 'playwright';
import { expect } from '@playwright/test';
import fs from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import crypto from 'node:crypto';
import { insideRoot, contrast, contrastRatio, viewports } from '../../scripts/v2-ui-audit.mjs';

const root = process.cwd();
process.env.TMPDIR = path.join(root, 'var/tmp');
process.env.PLAYWRIGHT_BROWSERS_PATH = path.join(root, 'var/cache/playwright');
const metadataPath = insideRoot(root, process.argv[2] || 'var/reports/codex-credentials-fixture-r2.json');
const output = insideRoot(root, process.argv[3] || 'var/reports/codex-credentials-ui-final');
const fixture = JSON.parse(fs.readFileSync(metadataPath, 'utf8'));
if (fs.existsSync(output)) throw new Error('Preserve earlier audit evidence; choose a fresh directory');
if (new URL(fixture.origin).hostname !== '127.0.0.1' || !fixture.evidence?.synthetic_credentials
    || !fixture.packaged_app || !fixture.ipc_socket.startsWith(root + path.sep)
    || !fixture.fixture_socket.startsWith(root + path.sep)) throw new Error('Owned packaged synthetic loopback fixture required');
fs.mkdirSync(output, { recursive: true, mode: 0o700 });
const evidence = { started_at: new Date().toISOString(), status: 'IN_PROGRESS', candidate: fixture.packaged_app_path,
  fixture: fixture.evidence, mocked_responses: false, server_mutations: false,
  baseline: 'var/reports/v2-ui/round3/screenshots/light-1440x900-detail.png', baseline_viewed_before_audit: true,
  privacy: 'Document-start data-sensitive masking; one-use tickets only in memory; no HAR, trace, video, credential body, raw errors or URLs saved',
  checks: [], failures: [], screenshots: [], assets: [], page_errors: 0, credential_requests: 0 };
const labels = { READABLE: '可读取 API 密钥', OAUTH_ONLY: '仅存在 OAuth 登录凭据', MISSING_KEY: '未找到 API 密钥',
  NOT_FOUND: '凭据文件不存在', UNREADABLE: '凭据文件不可读取', INVALID_JSON: '凭据文件格式无效',
  INVALID_KEY: 'API 密钥字段无效', TOO_LARGE: '凭据文件超过检查大小限制' };
let checkpoint = 'initial';
let diagnostics = {};
function rpc(socketPath, request) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection(socketPath); let body = '';
    socket.setTimeout(4000);
    socket.on('connect', () => socket.write(JSON.stringify(request) + '\n'));
    socket.on('data', chunk => {
      body += chunk;
      if (body.length > 10000) { socket.destroy(); reject(new Error('IPC bound exceeded')); return; }
      if (body.includes('\n')) { socket.end(); try { resolve(JSON.parse(body.trim())); } catch { reject(new Error('Invalid owned IPC result')); } }
    });
    socket.on('error', () => reject(new Error('Owned IPC unavailable')));
    socket.on('timeout', () => { socket.destroy(); reject(new Error('Owned IPC timeout')); });
  });
}
async function installPrivacy(page) {
  await page.addInitScript(() => {
    localStorage.setItem('tm-theme', 'system');
    const install = () => {
      if (!document.documentElement || document.getElementById('credentials-audit-privacy')) return false;
      const style = document.createElement('style'); style.id = 'credentials-audit-privacy';
      style.textContent = '[data-sensitive]{color:transparent!important;text-shadow:none!important;background:#85858a!important} [data-sensitive] *{visibility:hidden!important}';
      document.documentElement.append(style); return true;
    };
    if (!install()) { const observer = new MutationObserver(() => { if (install()) observer.disconnect(); }); observer.observe(document, { childList: true, subtree: true }); }
  });
}
const section = page => page.getByRole('region', { name: '远程 Codex 登录凭据', exact: true });
const consent = page => section(page).getByRole('checkbox', { name: '允许在远端读取 Codex auth.json 并仅返回状态', exact: true });
const button = page => section(page).getByRole('button', { name: '检查远程 Codex 登录凭据', exact: true });
const metric = (page, name) => section(page).locator('.metric-line').filter({ has: page.locator('span').filter({ hasText: new RegExp('^' + name + '$') }) }).locator('strong');
const modelMetric = (page, name) => page.getByRole('region', { name: '模型调用测试', exact: true }).locator('.metric-line').filter({ has: page.locator('span').filter({ hasText: new RegExp('^' + name + '$') }) }).locator('strong');
async function navigate(page, name) {
  const mobile = page.getByRole('button', { name: '打开导航', exact: true });
  if (await mobile.isVisible()) await mobile.click();
  await page.locator('.sidebar').getByRole('button', { name, exact: true }).click();
  if (await mobile.isVisible()) await expect.poll(() => page.locator('.sidebar').evaluate(el => el.getBoundingClientRect().right)).toBeLessThanOrEqual(1);
}
async function detail(page, key) {
  await navigate(page, '服务器');
  await page.locator(`[data-testid="channel-summary"][data-server-id="${fixture.profiles[key].id}"]`).locator('.server-main').click();
  await expect(section(page)).toBeAttached();
  await expect(page.locator('.local-indicator')).toContainText('实时同步');
}
async function scrollSection(page) {
  await section(page).evaluate(async el => {
    const topbar = document.querySelector('.topbar').getBoundingClientRect();
    window.scrollTo({ top: window.scrollY + el.getBoundingClientRect().top - topbar.height - 18, left: 0, behavior: 'instant' });
    await new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)));
  });
}
async function capture(page, name) {
  await expect(page.locator('#credentials-audit-privacy')).toBeAttached();
  await expect.poll(() => page.evaluate(() => [...document.querySelectorAll('[data-sensitive]')].every(el => getComputedStyle(el).color === 'rgba(0, 0, 0, 0)'))).toBe(true);
  // Locator screenshots scroll tall regions to y=0, placing a sticky header
  // across their heading. Capture a document-coordinate clip from scroll0 so
  // the actual section remains visible without falsifying the sticky UI.
  await page.evaluate(async () => { window.scrollTo({ top: 0, left: 0, behavior: 'instant' }); await new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))); });
  await expect.poll(() => page.evaluate(() => window.scrollY)).toBe(0);
  const box = await section(page).boundingBox();
  await page.screenshot({ path: path.join(output, name + '.png'), fullPage: true, clip: box, animations: 'disabled' });
  evidence.screenshots.push(name + '.png');
}
async function layout(page) {
  const result = await section(page).evaluate(el => {
    const visible = target => { const r = target.getBoundingClientRect(); const s = getComputedStyle(target); return r.width > 0 && r.height > 0 && s.display !== 'none' && s.visibility !== 'hidden'; };
    const items = [...el.querySelectorAll('h2,p,button,label,.metric-line,strong,span')].filter(visible);
    const overflow = items.filter(target => { const r = target.getBoundingClientRect(); return r.left < -2 || r.right > innerWidth + 2 || target.scrollWidth > target.clientWidth + 3; })
      .map(target => ({ tag: target.tagName, class: target.className }));
    const targets = items.filter(target => target.matches('button,input') && !target.disabled);
    return { viewport: innerWidth, document_width: document.documentElement.scrollWidth, body_font_px: parseFloat(getComputedStyle(document.body).fontSize), overflow,
      targets: targets.map(target => ({ tag: target.tagName, height: target.getBoundingClientRect().height, width: target.getBoundingClientRect().width })) };
  });
  diagnostics.layout = result;
  expect(result.document_width).toBeLessThanOrEqual(result.viewport + 2);
  expect(result.overflow).toEqual([]);
  const colors = await contrast(page);
  const metricColors = await section(page).locator('.metric-line span,.metric-line strong').evaluateAll(items => {
    const canvas = document.createElement('canvas'); canvas.width = canvas.height = 1;
    const painter = canvas.getContext('2d', { willReadFrequently: true });
    const color = value => { painter.clearRect(0, 0, 1, 1); painter.fillStyle = value; painter.fillRect(0, 0, 1, 1); return [...painter.getImageData(0, 0, 1, 1).data].slice(0, 3); };
    return items.map(el => ({ name: el.textContent, foreground: color(getComputedStyle(el).color),
      background: color(getComputedStyle(document.body).backgroundColor), font_px: parseFloat(getComputedStyle(el).fontSize),
      font_weight: parseInt(getComputedStyle(el).fontWeight, 10) }));
  });
  for (const sample of metricColors) { sample.ratio = Number(contrastRatio(sample.foreground, sample.background).toFixed(2)); sample.required = sample.font_px >= 24 || sample.font_px >= 18.66 && sample.font_weight >= 700 ? 3 : 4.5; }
  const failures = [...colors, ...metricColors].filter(sample => sample.ratio < sample.required);
  diagnostics.contrast = failures;
  expect(failures).toEqual([]);
  return { layout: result, active_text_contrast_failures: 0 };
}
async function check(page, name, action) {
  checkpoint = 'initial'; diagnostics = {};
  try { evidence.checks.push({ name, result: 'PASS', ...(await action() || {}) }); }
  catch { evidence.failures.push({ name, result: 'FAIL', checkpoint, diagnostics, detail: 'Assertion failed; raw browser/API/error content withheld' });
    try { await capture(page, 'failure-' + evidence.failures.length); } catch { /* audit unavailable */ }
  }
}
async function get(page, endpoint) {
  const response = await page.request.get(fixture.origin + '/api/v1' + endpoint); expect(response.status()).toBe(200); return response.json();
}
async function actualCheck(page, expected, method = 'pointer') {
  const before = await rpc(fixture.fixture_socket, { command: 'status' });
  const control = await rpc(fixture.fixture_socket, { command: 'credential-case', case: expected });
  expect(control.case).toBe(expected); expect(control.synthetic_only).toBe(true);
  await expect(button(page)).toBeEnabled();
  const responsePromise = page.waitForResponse(response => response.url().endsWith(`/servers/${fixture.profiles.healthy.id}/credentials/codex/check`) && response.request().method() === 'POST');
  if (method === 'keyboard') { await button(page).focus(); await page.keyboard.press('Enter'); }
  else await button(page).click();
  const response = await responsePromise; expect(response.status()).toBe(200);
  const result = await response.json();
  const expectedState = expected === 'MIXED' ? 'READABLE' : expected;
  expect(result.credential_state).toBe(expectedState); expect(result.authentication).toBe('NOT_TESTED'); expect(result.model_completion).toBe('NOT_TESTED');
  expect(result.ownership).toBe('MANAGED'); expect(result.ssh_connected).toBe(true); expect(result.check_completed).toBe(true);
  expect(result.source_location).toBe('CODEX_HOME'); expect(Number.isNaN(new Date(result.observed_at).valueOf())).toBe(false);
  expect(Object.keys(result).sort()).toEqual(['authentication','auth_mode','check_completed','credential_state','key_readable','llm_completion_verified','model_completion','observed_at','ownership','reason_code','server_id','source','source_label','source_location','ssh_connected'].sort());
  expect(result.source).toBe('REMOTE_CODEX_AUTH_JSON'); expect(result.llm_completion_verified).toBe(false);
  const after = await rpc(fixture.fixture_socket, { command: 'status' });
  expect(after.credential_checks).toBe(before.credential_checks + 1);
  await expect(metric(page, '凭据检查')).toHaveText(labels[expectedState]);
  await expect(metric(page, 'API 密钥可读取')).toHaveText(result.key_readable === true ? '是' : result.key_readable === false ? '否' : '无法确定');
  await expect(metric(page, '检测到的凭据类型')).toHaveText(result.auth_mode === 'API_KEY' ? 'API 密钥' : result.auth_mode === 'OAUTH' ? 'OAuth 登录凭据' : '无法确定');
  expect(await section(page).getByText('认证方式', { exact: true }).count()).toBe(0);
  await expect(metric(page, '文件来源')).toHaveText('远程会话指定的 Codex 目录');
  await expect(metric(page, '检查是否完成')).toHaveText('已完成');
  const time = await page.evaluate(value => new Date(value).toLocaleString('zh-CN', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit' }), result.observed_at);
  await expect(metric(page, '检查时间')).toHaveText(time);
  // Credential reads still do not test authentication. The separate model
  // action owns these two results so a later generation cannot be contradicted.
  await expect(section(page)).toContainText('此检查不调用鉴权或模型接口。');
  await expect(section(page)).toContainText('读取凭据不代表模型可调用。');
  await expect(modelMetric(page, '鉴权测试')).toHaveText('未测试'); await expect(modelMetric(page, '模型调用')).toHaveText('未测试');
  return { credential_state: result.credential_state, key_readable: result.key_readable, auth_mode: result.auth_mode,
    source_location: result.source_location, check_completed: true, api_equals_ui: true, observed_at_present: true,
    authentication: 'NOT_TESTED', model_completion: 'NOT_TESTED', actual_remote_checks: 1 };
}

const browser = await chromium.launch({ channel: 'chrome', headless: true });
const context = await browser.newContext({ viewport: viewports[0], colorScheme: 'light', reducedMotion: 'reduce' });
const page = await context.newPage();
page.on('pageerror', () => { evidence.page_errors += 1; });
page.on('request', request => { if (request.url().endsWith('/credentials/codex/check')) evidence.credential_requests += 1; });
try {
  await installPrivacy(page);
  const ticket = await rpc(fixture.ipc_socket, { command: 'ticket' });
  await page.goto(fixture.origin + '/#ticket=' + encodeURIComponent(ticket.ticket));
  await expect(page.getByRole('heading', { name: '隧道总览', exact: true })).toBeVisible();
  expect(new URL(page.url()).hash).not.toContain('ticket');
  const assets = await page.evaluate(() => [...document.querySelectorAll('script[src],link[rel="stylesheet"]')].map(el => el.getAttribute('src') || el.getAttribute('href')).filter(value => value?.startsWith('/assets/')));
  for (const asset of assets) { const response = await page.request.get(fixture.origin + asset); expect(response.status()).toBe(200); evidence.assets.push({ path: asset, sha256: crypto.createHash('sha256').update(await response.body()).digest('hex') }); }
  await detail(page, 'healthy');
  await check(page, 'initial result and consent do not auto-check remote credentials', async () => {
    const before = await rpc(fixture.fixture_socket, { command: 'status' });
    checkpoint = 'initial untested status';
    await expect(consent(page)).not.toBeChecked(); await expect(button(page)).toBeDisabled();
    await expect(metric(page, '凭据检查')).toHaveText('尚未检查');
    await expect(section(page)).toContainText('文件不存在不能说明 Codex 未登录');
    await expect(section(page)).toContainText('环境可能与编辑器或终端不同');
    expect(evidence.credential_requests).toBe(0);
    await capture(page, 'light-1440-initial');
    checkpoint = 'keyboard explicit consent';
    await consent(page).focus(); await page.keyboard.press('Space');
    await expect(consent(page)).toBeChecked(); await expect(button(page)).toBeEnabled();
    await page.keyboard.press('Tab'); await expect(button(page)).not.toBeFocused();
    // DOM order is heading button then consent. Shift+Tab reaches the check control.
    await consent(page).focus(); await page.keyboard.press('Shift+Tab'); await expect(button(page)).toBeFocused();
    const focus = await button(page).evaluate(el => ({ outline: getComputedStyle(el).outlineStyle, outline_width: getComputedStyle(el).outlineWidth }));
    expect(focus.outline).not.toBe('none'); expect(parseFloat(focus.outline_width)).toBeGreaterThanOrEqual(2);
    expect(evidence.credential_requests).toBe(0);
    await capture(page, 'light-1440-keyboard-consent');
    const after = await rpc(fixture.fixture_socket, { command: 'status' });
    expect(after.credential_checks).toBe(before.credential_checks);
    return { initial: 'NOT_TESTED', consent_only_requests: 0, actual_remote_checks: 0, keyboard_space: true, reverse_tab_check_button: true, focus };
  });
  for (const state of Object.keys(labels)) {
    await check(page, 'actual synthetic SSH result ' + state, async () => {
      checkpoint = 'actual credential click and API/UI equality';
      const result = await actualCheck(page, state, state === 'READABLE' ? 'keyboard' : 'pointer');
      await capture(page, 'light-1440-result-' + state.toLowerCase()); return result;
    });
  }
  await check(page, 'mixed chatgpt plus key file reports found credential type, never active auth choice', async () => {
    checkpoint = 'actual mixed synthetic file and label';
    const result = await actualCheck(page, 'MIXED');
    await expect(section(page)).toContainText('读取凭据不代表模型可调用。');
    await expect(modelMetric(page, '鉴权测试')).toHaveText('未测试');
    await expect(modelMetric(page, '模型调用')).toHaveText('未测试');
    await capture(page, 'light-1440-result-mixed'); return { ...result, active_authentication_choice: 'NOT_TESTED', label: '检测到的凭据类型' };
  });
  // Restore successful result for shared layout matrix, through the real control.
  await actualCheck(page, 'READABLE');
  for (const theme of ['light', 'dark']) {
    await page.setViewportSize(viewports[0]);
    await page.locator('.sidebar').getByRole('button', { name: theme === 'light' ? '切换主题：浅色' : '切换主题：深色', exact: true }).click();
    await expect(page.locator('html')).toHaveAttribute('data-theme', theme);
    for (const viewport of viewports) {
      await page.setViewportSize(viewport);
      await check(page, `${theme}-${viewport.width}x${viewport.height} new credential section layout/contrast`, async () => {
        checkpoint = 'new section layout and active contrast'; const result = await layout(page);
        await capture(page, `${theme}-${viewport.width}x${viewport.height}-readable`); return result;
      });
    }
    for (const viewport of [viewports[0], viewports[3]]) {
      await page.setViewportSize(viewport); await page.evaluate(() => { document.documentElement.style.fontSize = '32px'; });
      await check(page, `${theme}-${viewport.width}x${viewport.height}-font200 readable layout/contrast`, async () => {
        checkpoint = '200 percent font layout'; const result = await layout(page); expect(result.layout.body_font_px).toBe(32);
        await capture(page, `${theme}-${viewport.width}x${viewport.height}-font200-readable`); return result;
      });
      await page.evaluate(() => { document.documentElement.style.fontSize = ''; });
    }
  }
  await page.setViewportSize(viewports[0]);
  await check(page, 'System theme follows real media changes and reduced motion remains active', async () => {
    await page.locator('.sidebar').getByRole('button', { name: '切换主题：跟随系统', exact: true }).click();
    await page.emulateMedia({ colorScheme: 'light', reducedMotion: 'reduce' }); await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
    await page.emulateMedia({ colorScheme: 'dark', reducedMotion: 'reduce' }); await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
    expect(await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches)).toBe(true);
    await capture(page, 'system-dark-1440-readable'); return { system_light: true, system_dark: true, reduced_motion: true };
  });
  for (const key of ['stopped', 'external']) {
    await check(page, key + ' disabled explicit check and zero credential read invocation', async () => {
      checkpoint = 'unchanged disabled profile';
      const before = evidence.credential_requests;
      const remoteBefore = await rpc(fixture.fixture_socket, { command: 'status' });
      await detail(page, key); await expect(consent(page)).not.toBeChecked(); await expect(button(page)).toBeDisabled();
      await expect(metric(page, '凭据检查')).toHaveText('尚未检查');
      const runtime = await get(page, `/servers/${fixture.profiles[key].id}/runtime`);
      expect(runtime.process_alive).toBe(false); expect(runtime.ssh_connected).toBe(false);
      if (key === 'external') { await expect(consent(page)).toBeDisabled(); await expect(section(page)).toContainText('外部服务仅供观察，不能读取登录凭据'); }
      else { await expect(consent(page)).toBeEnabled(); await consent(page).focus(); await page.keyboard.press('Space'); await expect(consent(page)).toBeChecked(); await expect(button(page)).toBeDisabled(); await expect(section(page)).toContainText('请先启用此托管通道并等待 SSH 连接建立'); }
      await capture(page, 'system-dark-1440-' + key);
      expect(evidence.credential_requests).toBe(before);
      const remoteAfter = await rpc(fixture.fixture_socket, { command: 'status' });
      expect(remoteAfter.credential_checks).toBe(remoteBefore.credential_checks);
      return { credential_requests: 0, actual_remote_checks: 0, automatic_ssh_start: false, backend_process_alive: false, backend_ssh_connected: false };
    });
  }
  await check(page, 'navigating back to owned detail resets consent and result without reads', async () => {
    const before = evidence.credential_requests; await detail(page, 'healthy');
    await expect(consent(page)).not.toBeChecked(); await expect(button(page)).toBeDisabled(); await expect(metric(page, '凭据检查')).toHaveText('尚未检查');
    expect(evidence.credential_requests).toBe(before); return { reset_consent: true, reset_result: true, automatic_reads: 0 };
  });
} catch {
  evidence.failures.push({ name: 'browser audit completion', result: 'FAIL', checkpoint, diagnostics, detail: 'Audit setup or unwrapped assertion failed; raw content withheld' });
} finally {
  await context.close(); await browser.close(); evidence.completed_at = new Date().toISOString();
  evidence.status = evidence.failures.length || evidence.page_errors ? 'FAIL' : 'PASS';
  fs.writeFileSync(path.join(output, 'evidence.json'), JSON.stringify(evidence, null, 2), { mode: 0o600 });
  console.log(JSON.stringify({ status: evidence.status, checks: evidence.checks.length, failures: evidence.failures, screenshots: evidence.screenshots.length, credential_requests: evidence.credential_requests, page_errors: evidence.page_errors, evidence: path.relative(root, path.join(output, 'evidence.json')) }, null, 2));
  if (evidence.status === 'FAIL') process.exitCode = 1;
}
