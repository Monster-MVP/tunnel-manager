import { chromium } from 'playwright';
import { expect } from '@playwright/test';
import fs from 'node:fs';
import path from 'node:path';
import net from 'node:net';
import crypto from 'node:crypto';
import { contrast, contrastRatio, insideRoot, viewports } from '../../scripts/v2-ui-audit.mjs';

const root = process.cwd();
process.env.TMPDIR = path.join(root, 'var/tmp');
process.env.PLAYWRIGHT_BROWSERS_PATH = path.join(root, 'var/cache/playwright');
const output = insideRoot(root, process.argv[2] || 'var/reports/import-guidance-ui');
if (fs.existsSync(output)) throw new Error('Retain prior independent evidence; use a fresh output directory');
fs.mkdirSync(output, { recursive: true, mode: 0o700 });
const fixture = JSON.parse(fs.readFileSync(path.join(root, 'var/reports/import-guidance-fixture.json'), 'utf8'));
const origin = new URL(fixture.origin);
if (origin.hostname !== '127.0.0.1' || !fixture.ipc_socket.startsWith(root + path.sep)) {
  throw new Error('This audit requires a project-owned loopback fixture');
}
const evidence = { started_at: new Date().toISOString(), status: 'IN_PROGRESS', source_candidate: true,
  packaged_app: fixture.packaged_app, mocked_responses: false, server_mutations: false,
  privacy: 'Sensitive fields masked at document start; tickets remain in memory; no trace/video/raw API saved',
  checks: [], errors: [], screenshots: [], page_errors: 0, assets: [] };

function ticket() {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection(fixture.ipc_socket);
    let body = '';
    socket.setTimeout(4000);
    socket.on('connect', () => socket.write('{"command":"ticket"}\n'));
    socket.on('data', chunk => {
      body += chunk;
      if (body.length > 10000) { socket.destroy(); reject(new Error('Bounded IPC response exceeded')); return; }
      if (body.includes('\n')) {
        socket.end();
        try { resolve(JSON.parse(body)); } catch { reject(new Error('Invalid fixture IPC response')); }
      }
    });
    socket.on('error', () => reject(new Error('Fixture IPC unavailable')));
    socket.on('timeout', () => { socket.destroy(); reject(new Error('Fixture IPC timeout')); });
  });
}

let checkpoint = 'initial';
let diagnostics = {};
async function check(name, action) {
  checkpoint = 'initial'; diagnostics = {};
  try { const result = await action(); evidence.checks.push({ name, result: 'PASS', ...(result || {}) }); }
  catch { evidence.errors.push({ name, result: 'FAIL', checkpoint, diagnostics,
    detail: 'Assertion did not pass; no raw browser/API/error content retained' }); }
}

async function installPrivacy(page) {
  await page.addInitScript(() => {
    localStorage.setItem('tm-theme', 'system');
    const install = () => {
      if (!document.documentElement || document.querySelector('#import-guidance-privacy')) return false;
      const style = document.createElement('style');
      style.id = 'import-guidance-privacy';
      style.textContent = '[data-sensitive]{color:transparent!important;text-shadow:none!important;background:#85858a!important} [data-sensitive] *{visibility:hidden!important}';
      document.documentElement.append(style);
      return true;
    };
    if (!install()) {
      const observer = new MutationObserver(() => { if (install()) observer.disconnect(); });
      observer.observe(document, { childList: true, subtree: true });
    }
  });
}

async function navigate(page, name) {
  const menu = page.getByRole('button', { name: '打开导航', exact: true });
  if (await menu.isVisible()) await menu.click();
  await page.locator('.sidebar').getByRole('button', { name, exact: true }).click();
  if (await menu.isVisible()) await expect.poll(() => page.locator('.sidebar').evaluate(el => el.getBoundingClientRect().right)).toBeLessThanOrEqual(1);
}

async function openExternal(page) {
  await navigate(page, '服务器');
  const row = page.locator(`[data-testid="channel-summary"][data-server-id="${fixture.profiles.external.id}"]`);
  await expect(row).toBeVisible();
  await row.locator('.server-main').click();
  await expect(page.getByTestId('external-control-guidance')).toBeVisible();
  await expect(page.locator('.local-indicator')).toContainText('实时同步');
  await page.waitForTimeout(200);
}

async function screenshot(page, name) {
  await expect(page.locator('#import-guidance-privacy')).toBeAttached();
  await expect.poll(() => page.evaluate(() => [...document.querySelectorAll('[data-sensitive]')].every(el => getComputedStyle(el).color === 'rgba(0, 0, 0, 0)'))).toBe(true);
  // Route changes and live font scaling can preserve a prior scroll anchor in
  // this SPA. Capture each page from its real top so sticky navigation is not
  // duplicated into the screenshot as a harness artifact.
  await page.evaluate(async (keepFocus) => {
    if (!keepFocus && document.activeElement instanceof HTMLElement) document.activeElement.blur();
    window.scrollTo({ top: 0, left: 0, behavior: 'instant' });
    await new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)));
  }, /keyboard|wizard/.test(name));
  await expect.poll(() => page.evaluate(() => window.scrollY)).toBe(0);
  await page.screenshot({ path: path.join(output, name + '.png'), fullPage: true, animations: 'disabled' });
  evidence.screenshots.push(name + '.png');
}

async function layout(page) {
  return page.evaluate(() => {
    const visible = el => { const box = el.getBoundingClientRect(); const css = getComputedStyle(el); return box.width > 0 && box.height > 0 && css.visibility !== 'hidden' && css.display !== 'none'; };
    const elements = [...document.querySelectorAll('.page h1,.page h2,.page p,.page button,.page label,.page small,.channel-facts .fact,.fact-grid .fact,.metric-line')]
      .filter(visible).filter(el => !el.closest('[data-sensitive]'));
    const overflow = elements.filter(el => { const box = el.getBoundingClientRect(); return box.left < -2 || box.right > innerWidth + 2 || el.scrollWidth > el.clientWidth + 3; })
      .map(el => ({ tag: el.tagName, class: el.className, label: el.getAttribute('data-testid') || el.getAttribute('aria-label') || '[content omitted]' }));
    return { viewport: innerWidth, document_width: document.documentElement.scrollWidth, body_font_px: parseFloat(getComputedStyle(document.body).fontSize), overflow };
  });
}

async function disabledAppearance(page) {
  const sample = await page.getByRole('button', { name: '外部服务不可控制', exact: true }).evaluate(el => {
    const canvas = document.createElement('canvas'); canvas.width = 1; canvas.height = 1;
    const context = canvas.getContext('2d', { willReadFrequently: true });
    const color = value => { context.clearRect(0, 0, 1, 1); context.fillStyle = value; context.fillRect(0, 0, 1, 1); const pixel = context.getImageData(0, 0, 1, 1).data; return [pixel[0], pixel[1], pixel[2], pixel[3] / 255]; };
    const mix = (a, b) => { const alpha = a[3] + b[3] * (1 - a[3]); return [...a.slice(0, 3).map((value, i) => (value * a[3] + b[i] * b[3] * (1 - a[3])) / alpha), alpha]; };
    let behind = [0, 0, 0, 0]; let cursor = el.parentElement;
    while (cursor) { behind = mix(behind, color(getComputedStyle(cursor).backgroundColor)); cursor = cursor.parentElement; }
    behind = mix(behind, [255, 255, 255, 1]);
    const style = getComputedStyle(el); const opacity = Number(style.opacity);
    const bg = mix(color(style.backgroundColor), behind);
    const fg = mix(color(style.color), bg);
    const display = source => mix([...source.slice(0, 3), opacity], behind);
    return { class: el.className, disabled: el.disabled, font_px: parseFloat(style.fontSize), opacity, foreground: display(fg), background: display(bg) };
  });
  return { ...sample, effective_contrast_ratio: Number(contrastRatio(sample.foreground, sample.background).toFixed(2)),
    contrast_note: 'Disabled controls are WCAG contrast-exempt; effective compositing is recorded for visual judgment' };
}

async function externalAssertions(page) {
  checkpoint = 'external observation explanation and next step';
  const summary = page.getByTestId('detail-channel-summary');
  await expect(summary).toContainText('这是导入的外部观察记录');
  await expect(summary).toContainText('未建立应用托管通道');
  await expect(summary).toContainText('未验证远程连通性');
  await expect(summary).toContainText('若要另建独立通道');
  await expect(summary).toContainText('添加服务器');
  await expect(summary).toContainText('与既有服务不冲突的端口');
  await expect(summary).toContainText('另行授权');
  await expect(summary).toContainText('当前仅提供接管预览');
  await expect(page.getByRole('button', { name: '外部服务不可控制', exact: true })).toBeDisabled();
  expect(await summary.getByRole('button', { name: '启动隧道', exact: true }).count()).toBe(0);
  checkpoint = 'external disabled control semantics';
  for (const name of ['停止隧道', '重启隧道', '立即探测', '运行诊断']) await expect(page.getByRole('button', { name, exact: true })).toBeDisabled();
  checkpoint = 'external SSH and reconnect semantics';
  for (const name of ['SSH 进程', 'SSH 连接']) await expect(page.locator('.metric-line').filter({ has: page.locator('span', { hasText: name }) }).first()).toContainText('未观测');
  await expect(page.locator('.fact').filter({ hasText: '自动重连' })).toContainText('仅观察，不执行重连');
  const shape = await layout(page);
  checkpoint = 'external layout'; diagnostics.layout = shape;
  expect(shape.document_width).toBeLessThanOrEqual(shape.viewport + 2);
  expect(shape.overflow).toEqual([]);
  const colors = await contrast(page);
  checkpoint = 'external active text contrast'; diagnostics.active_text_contrast_failures = colors.filter(item => item.ratio < item.required);
  expect(colors.filter(item => item.ratio < item.required)).toEqual([]);
  const disabled = await disabledAppearance(page);
  checkpoint = 'external disabled text contrast'; diagnostics.disabled_control = disabled;
  expect(disabled.class).toBe('quiet-button');
  return { layout: shape, disabled_control: disabled, active_text_contrast_failures: 0 };
}

async function discoveryAssertions(page) {
  checkpoint = 'discovery semantics';
  await expect(page.getByRole('heading', { name: '发现服务', exact: true })).toBeVisible();
  await expect(page.locator('.discovery-warning')).toContainText('不会接管');
  await expect(page.getByRole('button', { name: '导入选中 (0)', exact: true })).toBeDisabled();
  const shape = await layout(page);
  checkpoint = 'discovery layout'; diagnostics.layout = shape;
  expect(shape.document_width).toBeLessThanOrEqual(shape.viewport + 2);
  expect(shape.overflow).toEqual([]);
  const colors = await contrast(page);
  checkpoint = 'discovery active text contrast'; diagnostics.active_text_contrast_failures = colors.filter(item => item.ratio < item.required);
  expect(colors.filter(item => item.ratio < item.required)).toEqual([]);
  return { layout: shape, candidate_count: await page.locator('.discovery-row').count(), active_text_contrast_failures: 0 };
}

const browser = await chromium.launch({ channel: 'chrome', headless: true });
try {
  for (const theme of ['light', 'dark']) {
    const context = await browser.newContext({ viewport: viewports[0], colorScheme: theme, reducedMotion: 'reduce' });
    const page = await context.newPage();
    page.on('pageerror', () => { evidence.page_errors += 1; });
    await installPrivacy(page);
    const session = await ticket();
    await page.goto(`${fixture.origin}/#ticket=${encodeURIComponent(session.ticket)}`);
    await expect(page.getByRole('heading', { name: '隧道总览', exact: true })).toBeVisible();
    expect(new URL(page.url()).hash).not.toContain('ticket');
    await expect(page.locator('html')).toHaveAttribute('data-theme', theme);
    if (evidence.assets.length === 0) {
      const assets = await page.evaluate(() => [...document.querySelectorAll('script[src],link[rel="stylesheet"]')].map(el => el.getAttribute('src') || el.getAttribute('href')).filter(value => value?.startsWith('/assets/')));
      for (const asset of assets) {
        const response = await page.request.get(fixture.origin + asset);
        expect(response.status()).toBe(200);
        const body = await response.body();
        evidence.assets.push({ path: asset, sha256: crypto.createHash('sha256').update(body).digest('hex') });
      }
    }
    const response = await page.request.get(fixture.origin + '/api/v1/overview');
    expect(response.status()).toBe(200);
    const overview = await response.json();
    const external = overview.servers.find(item => item.id === fixture.profiles.external.id);
    expect(external.management).toBe('OBSERVED_EXTERNAL');
    expect(external.desired_state).toBe('STOPPED');
    expect(overview.runtimes[external.id].state).toBe('STOPPED');
    evidence.checks.push({ name: `${theme} actual external API ownership/state`, result: 'PASS', management: external.management,
      mode: external.mode, desired_state: external.desired_state, observed_state: overview.runtimes[external.id].state });
    for (const viewport of viewports) {
      await page.setViewportSize(viewport);
      await openExternal(page);
      const prefix = `${theme}-${viewport.width}x${viewport.height}`;
      await check(prefix + ' external detail semantics/layout/contrast', () => externalAssertions(page));
      await screenshot(page, prefix + '-external-detail');
      await navigate(page, '发现服务');
      await expect(page.locator('.discovery-warning')).toBeVisible();
      await check(prefix + ' discovery semantics/layout/contrast', () => discoveryAssertions(page));
      await screenshot(page, prefix + '-discovery');
    }
    for (const viewport of [viewports[0], viewports[3]]) {
      await page.setViewportSize(viewport);
      await page.evaluate(() => { document.documentElement.style.fontSize = '32px'; });
      const prefix = `${theme}-${viewport.width}x${viewport.height}-font200`;
      await openExternal(page);
      await check(prefix + ' external detail', async () => { const result = await externalAssertions(page); expect(result.layout.body_font_px).toBe(32); return result; });
      await screenshot(page, prefix + '-external-detail');
      await navigate(page, '发现服务');
      await expect(page.locator('.discovery-warning')).toBeVisible();
      await check(prefix + ' discovery', () => discoveryAssertions(page));
      await screenshot(page, prefix + '-discovery');
      await page.evaluate(() => { document.documentElement.style.fontSize = ''; });
    }
    await page.setViewportSize(viewports[0]);
    await openExternal(page);
    await check(theme + ' read-only takeover preview keyboard trap and dismiss', async () => {
      const button = page.getByRole('button', { name: '接管预览', exact: true });
      await button.focus();
      await page.keyboard.press('Enter');
      const dialog = page.getByRole('dialog', { name: '接管影响与回滚预览', exact: true });
      await expect(dialog).toBeVisible();
      await expect(dialog).toContainText('生产接管尚未授权');
      await page.keyboard.press('Tab');
      expect(await dialog.evaluate(el => el.contains(document.activeElement))).toBe(true);
      await page.keyboard.press('Shift+Tab');
      expect(await dialog.evaluate(el => el.contains(document.activeElement))).toBe(true);
      await screenshot(page, theme + '-takeover-preview-keyboard');
      await page.keyboard.press('Escape');
      await expect(dialog).toHaveCount(0);
      await expect(button).toBeFocused();
      return { service_control: false, read_only_preview: true, focus_trap: true, focus_restored: true };
    });
    await check(theme + ' external disabled controls skipped by real keyboard navigation', async () => {
      const anchor = page.getByRole('button', { name: '返回服务器', exact: true });
      await anchor.focus();
      const focused = [];
      // The detail page has eight enabled controls after the back link. Stop
      // at the final enabled control so the browser's body/skip-link cycle is
      // not misreported as a product focus failure.
      for (let index = 0; index < 8; index += 1) {
        await page.keyboard.press('Tab');
        focused.push(await page.evaluate(() => {
          const el = document.activeElement; const style = getComputedStyle(el);
          const focusContainer = el.closest('.search-field,.log-search');
          const containerStyle = focusContainer ? getComputedStyle(focusContainer) : null;
          return { name: el.getAttribute('aria-label') || el.textContent?.trim().slice(0, 70),
            disabled: Boolean(el.disabled), outline: style.outlineStyle, outline_width: style.outlineWidth,
            focus_indicator: (style.outline !== 'none' && parseFloat(style.outlineWidth) >= 2)
              || Boolean(containerStyle && containerStyle.outline !== 'none' && parseFloat(containerStyle.outlineWidth) >= 2) };
        }));
      }
      checkpoint = 'focus outline'; diagnostics.focus_sequence = focused;
      expect(focused.every(item => !item.disabled && item.focus_indicator)).toBe(true);
      expect(focused.some(item => item.name?.includes('外部服务不可控制'))).toBe(false);
      await screenshot(page, theme + '-external-keyboard-focus');
      return { focus_sequence: focused };
    });
    await check(theme + ' guidance next step opens Chinese independent-channel wizard without saving', async () => {
      checkpoint = 'return button and independent wizard';
      await page.getByRole('button', { name: '返回服务器', exact: true }).click();
      await page.getByRole('button', { name: '添加服务器', exact: true }).focus();
      await page.keyboard.press('Enter');
      const dialog = page.getByRole('dialog', { name: '添加服务器', exact: true });
      await expect(dialog).toBeVisible();
      checkpoint = 'wizard SSH fields';
      const firstStepFields = [
        ['显示名称', dialog.getByLabel('显示名称', { exact: true })],
        ['分组', dialog.locator('label').filter({ hasText: /^分组/ }).locator('select')],
        ['SSH 主机', dialog.getByLabel('SSH 主机', { exact: true })],
        ['SSH 用户', dialog.getByLabel('SSH 用户', { exact: true })],
        ['SSH 端口', dialog.getByLabel('SSH 端口', { exact: true })],
      ];
      for (const [label, field] of firstStepFields) {
        checkpoint = `wizard field ${label}`;
        await expect(field).toBeVisible();
      }
      // Inspect every wizard step using local-only values. Advancing steps is
      // client state only; the final submit is deliberately never invoked.
      await dialog.getByLabel('显示名称', { exact: true }).fill('审查用通道');
      await dialog.getByLabel('SSH 主机', { exact: true }).fill('example.invalid');
      await dialog.getByLabel('SSH 用户', { exact: true }).fill('review-user');
      await dialog.getByRole('button', { name: '下一步', exact: true }).click();
      checkpoint = 'wizard exit fields';
      const exitFields = [
        ['代理出口', dialog.locator('label').filter({ hasText: /^代理出口/ }).locator('select')],
        ['远程代理端口', dialog.getByLabel('远程代理端口', { exact: true })],
        ['本地监听端口', dialog.getByLabel('本地监听端口', { exact: true })],
      ];
      for (const [label, field] of exitFields) {
        checkpoint = `wizard field ${label}`;
        await expect(field).toBeVisible();
      }
      await dialog.getByRole('button', { name: '下一步', exact: true }).click();
      checkpoint = 'wizard review labels';
      await expect(dialog.getByText('保存并测试连接', { exact: true })).toBeVisible();
      await expect(dialog.getByText('保存并测试代理链路', { exact: true })).toBeVisible();
      await screenshot(page, theme + '-independent-channel-wizard');
      await page.keyboard.press('Escape');
      await expect(dialog).toHaveCount(0);
      return { save_or_connection_attempt: false, real_wizard_opened: true };
    });
    await check(theme + ' system theme responds to actual browser media changes', async () => {
      const other = theme === 'light' ? 'dark' : 'light';
      await page.emulateMedia({ colorScheme: other, reducedMotion: 'reduce' });
      await expect(page.locator('html')).toHaveAttribute('data-theme', other);
      await page.emulateMedia({ colorScheme: theme, reducedMotion: 'reduce' });
      await expect(page.locator('html')).toHaveAttribute('data-theme', theme);
      return { initial: theme, switched: other, restored: theme };
    });
    await check(theme + ' external state retained after UI-only audit', async () => {
      const current = await (await page.request.get(fixture.origin + '/api/v1/overview')).json();
      const server = current.servers.find(item => item.id === external.id);
      expect(server.management).toBe(external.management); expect(server.desired_state).toBe(external.desired_state); expect(server.mode).toBe(external.mode);
      expect(current.runtimes[server.id].state).toBe('STOPPED');
      return { management: server.management, desired_state: server.desired_state, mode: server.mode, observed_state: 'STOPPED' };
    });
    await context.close();
  }
} catch {
  evidence.errors.push({ name: 'browser audit completion', result: 'FAIL', detail: 'Audit unavailable or setup/navigation assertion failed; raw details withheld' });
} finally {
  await browser.close();
  evidence.completed_at = new Date().toISOString();
  evidence.status = evidence.errors.length || evidence.page_errors ? 'FAIL' : 'PASS';
  fs.writeFileSync(path.join(output, 'evidence.json'), JSON.stringify(evidence, null, 2), { mode: 0o600 });
  console.log(JSON.stringify({ status: evidence.status, checks: evidence.checks.length, failures: evidence.errors,
    screenshots: evidence.screenshots.length, page_errors: evidence.page_errors, evidence: path.relative(root, path.join(output, 'evidence.json')) }, null, 2));
  if (evidence.status === 'FAIL') process.exitCode = 1;
}
