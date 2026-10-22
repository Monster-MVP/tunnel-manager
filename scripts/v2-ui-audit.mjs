import { chromium } from 'playwright';
import { expect } from '@playwright/test';
import fs from 'node:fs';
import path from 'node:path';
import net from 'node:net';
import { pathToFileURL } from 'node:url';

export const viewports = [
  { width: 1440, height: 900 }, { width: 1280, height: 800 },
  { width: 1024, height: 768 }, { width: 768, height: 900 },
];

export async function topologyFirstScreen(page) {
  return page.getByTestId('topology-server').evaluateAll(elements => elements.map(element => {
    const bounds = element.getBoundingClientRect();
    return { id: element.getAttribute('data-server-id'), top: Number(bounds.top.toFixed(2)),
      bottom: Number(bounds.bottom.toFixed(2)), fully_in_first_screen: bounds.top >= 0 && bounds.bottom <= innerHeight,
      state_present: Boolean(element.querySelector('.state-badge')), desired_text_present: Boolean(element.textContent?.includes('期望')) };
  }));
}

export function contrastRatio(a, b) {
  const luminance = color => color.slice(0, 3).map(value => {
    const scaled = value / 255;
    return scaled <= 0.04045 ? scaled / 12.92 : ((scaled + 0.055) / 1.055) ** 2.4;
  }).reduce((sum, value, index) => sum + value * [0.2126, 0.7152, 0.0722][index], 0);
  const values = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (values[0] + 0.05) / (values[1] + 0.05);
}

export function insideRoot(root, candidate) {
  const resolved = path.resolve(root, candidate);
  const relative = path.relative(root, resolved);
  if (!relative || relative.startsWith('..' + path.sep) || path.isAbsolute(relative))
    throw new Error('Audit outputs must be in a child directory of the project root');
  return resolved;
}

function parseOptions(argv) {
  const options = {};
  for (let index = 0; index < argv.length; index += 2) {
    if (!argv[index]?.startsWith('--') || !argv[index + 1]) throw new Error('Expected --option value pairs');
    options[argv[index].slice(2)] = argv[index + 1];
  }
  return options;
}

function ipc(socketPath, command) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection(socketPath);
    let body = '';
    socket.setTimeout(4000);
    socket.on('connect', () => socket.write(JSON.stringify({ command }) + '\n'));
    socket.on('data', chunk => {
      body += chunk;
      if (body.length > 10000) { socket.destroy(); reject(new Error('IPC response exceeded audit limit')); }
      if (body.includes('\n')) {
        socket.end();
        try { resolve(JSON.parse(body.trim())); } catch { reject(new Error('IPC response is invalid')); }
      }
    });
    socket.on('error', reject);
    socket.on('timeout', () => { socket.destroy(); reject(new Error('Audit IPC timed out')); });
  });
}

async function navigate(page, name) {
  const mobile = page.getByRole('button', { name: '打开导航', exact: true });
  if (await mobile.isVisible()) await mobile.click();
  const sidebar = page.locator('.sidebar');
  const nav = sidebar.getByRole('button', { name, exact: true });
  await nav.click();
  if (await mobile.isVisible()) {
    await expect.poll(() => sidebar.evaluate(element => element.getBoundingClientRect().right)).toBeLessThanOrEqual(1);
  }
  await page.waitForTimeout(250);
}

async function currentOverview(page, origin) {
  const response = await page.request.get(origin + '/api/v1/overview');
  expect(response.status()).toBe(200);
  return response.json();
}

function installEvidenceRedaction(page) {
  return page.addInitScript(() => {
    const install = () => {
      if (!document.documentElement || document.querySelector('#v2-audit-privacy')) return false;
      const style = document.createElement('style');
      style.id = 'v2-audit-privacy';
      style.textContent = '[data-sensitive]{color:transparent!important;text-shadow:none!important;background:var(--audit-mask,#85858a)!important} [data-sensitive] *{visibility:hidden!important}';
      document.documentElement.append(style);
      return true;
    };
    if (!install()) {
      const observer = new MutationObserver(() => { if (install()) observer.disconnect(); });
      observer.observe(document, { childList: true, subtree: true });
    }
  });
}

function safeOverview(data) {
  return {
    captured_at: new Date().toISOString(),
    server_count: data.servers.length,
    channels: data.servers.map(server => {
      const runtime = data.runtimes[server.id];
      return { id: server.id, management: server.management, mode: server.mode,
        desired_state: server.desired_state, observed_state: runtime?.state ?? 'UNKNOWN',
        stale: runtime?.stale ?? true, process_alive: runtime?.process_alive ?? false,
        ssh_connected: runtime?.ssh_connected ?? false, remote_listener: runtime?.remote_listener ?? 'UNKNOWN',
        proxy_health: runtime?.proxy_health ?? 'UNKNOWN', http_status: runtime?.http_status ?? null,
        observed_at: runtime?.observed_at ?? null };
    }),
  };
}

async function geometry(page) {
  return page.evaluate(() => {
    const viewport = document.documentElement.clientWidth;
    const renderedViewport = window.innerWidth;
    const safeText = element => {
      const copy = element.cloneNode(true);
      copy.querySelectorAll('[data-sensitive]').forEach(child => child.remove());
      return element.closest('[data-sensitive]') ? '[redacted]' : copy.textContent?.trim().slice(0, 80) || '';
    };
    const visible = element => {
      const bounds = element.getBoundingClientRect();
      const style = getComputedStyle(element);
      return bounds.width > 0 && bounds.height > 0 && style.visibility !== 'hidden' && style.display !== 'none';
    };
    const controls = [...document.querySelectorAll('main button,main input,main select,main textarea,[role="dialog"] button,[role="dialog"] input,[role="dialog"] select,[role="dialog"] textarea,main [role="switch"]')]
      .filter(visible).map(element => {
        const bounds = element.getBoundingClientRect();
        const style = getComputedStyle(element);
        return { tag: element.tagName, name: element.getAttribute('aria-label') || safeText(element),
          font_px: Number.parseFloat(style.fontSize), x: bounds.x, right: bounds.right,
          width: bounds.width, height: bounds.height, scroll_width: element.scrollWidth,
          client_width: element.clientWidth, outline: style.outlineStyle, outline_width: style.outlineWidth };
      });
    const overflowing = [...document.querySelectorAll('main h1,main h2,main h3,main p,main button,main label,[role="dialog"] h2,[role="dialog"] p,[role="dialog"] button,[role="dialog"] label,[data-testid="channel-summary"]')]
      .filter(visible).filter(element => {
        const bounds = element.getBoundingClientRect();
        return bounds.left < -2 || bounds.right > renderedViewport + 2 || element.scrollWidth > element.clientWidth + 3;
      }).map(element => ({ tag: element.tagName, class: element.className,
        name: element.getAttribute('aria-label') || safeText(element) }));
    const smallText = [...document.querySelectorAll('main button,main label,main input,main select,[role="dialog"] button,[role="dialog"] label,[role="dialog"] input,[role="dialog"] select,[data-testid="channel-state"],[data-testid="channel-exit"],[data-testid="channel-enabled"]')]
      .filter(visible).filter(element => Number.parseFloat(getComputedStyle(element).fontSize) < 13.9)
      .map(element => ({ tag: element.tagName, name: element.getAttribute('aria-label') || safeText(element),
        font_px: Number.parseFloat(getComputedStyle(element).fontSize) }));
    return { viewport, rendered_viewport: renderedViewport, scroll_width: document.documentElement.scrollWidth,
      body_font_px: Number.parseFloat(getComputedStyle(document.body).fontSize),
      h1_font_px: document.querySelector('h1') ? Number.parseFloat(getComputedStyle(document.querySelector('h1')).fontSize) : null,
      controls, overflowing, small_text: smallText };
  });
}

export async function contrast(page) {
  const samples = await page.evaluate(() => {
    const safeText = element => {
      const copy = element.cloneNode(true);
      copy.querySelectorAll('[data-sensitive]').forEach(child => child.remove());
      return copy.textContent?.trim().slice(0, 80) || '';
    };
    // Chromium may serialize color-mix results as color(srgb ...) with 0–1
    // coordinates rather than rgb(...) with 0–255. Let its own canvas color
    // parser normalize every supported CSS format into sRGB pixel bytes.
    const canvas = document.createElement('canvas');
    canvas.width = 1; canvas.height = 1;
    const painter = canvas.getContext('2d', { willReadFrequently: true });
    const color = value => {
      if (!painter || !CSS.supports('color', value)) return null;
      painter.clearRect(0, 0, 1, 1);
      painter.fillStyle = value;
      painter.fillRect(0, 0, 1, 1);
      const pixel = painter.getImageData(0, 0, 1, 1).data;
      return [pixel[0], pixel[1], pixel[2], pixel[3] / 255];
    };
    const composite = (top, bottom) => {
      const opacity = top[3] + bottom[3] * (1 - top[3]);
      return [...top.slice(0, 3).map((value, index) =>
        opacity ? (value * top[3] + bottom[index] * bottom[3] * (1 - top[3])) / opacity : 0), opacity];
    };
    const backdrop = element => {
      let result = [0, 0, 0, 0];
      let cursor = element;
      while (cursor) {
        const background = color(getComputedStyle(cursor).backgroundColor);
        if (background) result = composite(result, background);
        if (result[3] > 0.999) return result;
        cursor = cursor.parentElement;
      }
      return composite(result, [255, 255, 255, 1]);
    };
    return [...document.querySelectorAll('main h1,main h2,main h3,main p,main button,main label,main small,[role="dialog"] h2,[role="dialog"] p,[role="dialog"] button,[role="dialog"] label,[data-testid="channel-state"],[data-testid="channel-exit"],[data-testid="channel-enabled"],.local-indicator')]
      .filter(element => {
        const bounds = element.getBoundingClientRect();
        const style = getComputedStyle(element);
        return bounds.width > 0 && bounds.height > 0 && style.display !== 'none' && style.visibility !== 'hidden'
          && Number(style.opacity) > 0.99 && !element.closest('[data-sensitive]') && !element.disabled;
      }).map(element => {
        const style = getComputedStyle(element);
        const background = backdrop(element);
        const foreground = color(style.color);
        return { name: element.getAttribute('aria-label') || safeText(element),
          foreground: foreground ? composite(foreground, background) : null, background,
          font_px: Number.parseFloat(style.fontSize), font_weight: Number.parseInt(style.fontWeight, 10),
          glass: Boolean(element.closest('.sidebar,.topbar,.glass-toolbar')) };
      }).filter(sample => sample.name && sample.foreground);
  });
  return samples.map(sample => ({ ...sample,
    ratio: Number(contrastRatio(sample.foreground, sample.background).toFixed(2)),
    required: sample.font_px >= 24 || sample.font_px >= 18.66 && sample.font_weight >= 700 ? 3 : 4.5 }));
}

async function assertChannels(page, overview, result) {
  const summaries = page.getByTestId('channel-summary');
  expect(await summaries.count()).toBe(overview.servers.length);
  result.channel_matches = [];
  for (const server of overview.servers) {
    const card = page.locator(`[data-testid="channel-summary"][data-server-id="${server.id}"]`);
    await expect(card).toBeVisible();
    for (const marker of ['channel-enabled', 'channel-state', 'channel-exit']) await expect(card.getByTestId(marker)).toBeVisible();
    const attributes = await card.evaluate(element => ({ state: element.getAttribute('data-state'), mode: element.getAttribute('data-mode'),
      desired: element.getAttribute('data-desired-state'), management: element.getAttribute('data-management') }));
    const runtime = overview.runtimes[server.id];
    if (attributes.mode) expect(attributes.mode).toBe(server.mode);
    if (attributes.desired) expect(attributes.desired).toBe(server.desired_state);
    if (attributes.management) expect(attributes.management).toBe(server.management);
    if (attributes.state && runtime && !runtime.stale) expect(attributes.state).toBe(runtime.state);
    result.channel_matches.push({ id: server.id, ...attributes, fields_visible: true });
  }
  const topology = page.getByTestId('network-topology');
  await expect(topology).toBeVisible();
  result.topology = { visible: true, text: await topology.evaluate(element => {
    const copy = element.cloneNode(true);
    copy.querySelectorAll('[data-sensitive]').forEach(child => child.remove());
    return copy.textContent?.trim().slice(0, 1200) || '';
  }) };
  result.topology.first_screen_nodes = await topologyFirstScreen(page);
}

async function capture(page, output, name, results, options = {}) {
  const record = { name, captured_at: new Date().toISOString(), theme: await page.locator('html').getAttribute('data-theme'),
    geometry: await geometry(page), contrast: await contrast(page) };
  if (options.overview) await assertChannels(page, options.overview, record);
  const png = name + '.png';
  await page.screenshot({ path: path.join(output, 'screenshots', png), fullPage: true,
    animations: 'disabled', timeout: 20000 });
  record.screenshot = 'screenshots/' + png;
  if (name.endsWith('-overview') || await page.getByRole('dialog').isVisible()) {
    const viewportPng = name + '-viewport.png';
    await page.screenshot({ path: path.join(output, 'screenshots', viewportPng), fullPage: false,
      animations: 'disabled', timeout: 20000 });
    record.viewport_screenshot = 'screenshots/' + viewportPng;
  }
  record.blockers = [];
  if (record.geometry.scroll_width > record.geometry.viewport + 2) record.blockers.push('document horizontal overflow');
  if (record.geometry.overflowing.length) record.blockers.push('visible text/control overflow');
  if (record.geometry.small_text.length) record.blockers.push('critical text below 14px');
  if (record.contrast.some(sample => !sample.glass && sample.ratio < sample.required)) record.blockers.push('content text contrast below requirement');
  if (/^(?:light|dark)-1440x900-overview$/.test(name) && record.topology?.first_screen_nodes.length <= 5
      && record.topology?.first_screen_nodes.some(node => !node.fully_in_first_screen))
    record.blockers.push('five-channel first screen scan incomplete');
  results.captures.push(record);
  fs.writeFileSync(path.join(output, 'audit-results.json'), JSON.stringify(results, null, 2), { mode: 0o600 });
}

async function openDetail(page, serverId, name) {
  const card = page.locator(`[data-testid="channel-summary"][data-server-id="${serverId}"]`);
  if (await card.count()) {
    const button = card.getByRole('button', { name: /详情/ }).first();
    if (await button.count()) await button.click();
    else await card.locator('.server-main').click();
  } else {
    await page.locator('.server-main').filter({ hasText: name }).first().click();
  }
  await expect(page.getByRole('heading', { name, exact: true })).toBeVisible();
  await page.waitForTimeout(250);
}

async function setTheme(page, theme) {
  await navigate(page, '系统设置');
  await page.getByRole('button', { name: theme === 'light' ? '浅色' : theme === 'dark' ? '深色' : '跟随系统', exact: true }).click();
  if (theme !== 'system') await expect(page.locator('html')).toHaveAttribute('data-theme', theme);
}

async function wizardCaptures(page, output, prefix, results) {
  await navigate(page, '总览');
  await page.getByRole('button', { name: '添加服务器', exact: true }).first().click();
  const dialog = page.getByRole('dialog', { name: '添加服务器', exact: true });
  await expect(dialog).toBeVisible();
  await capture(page, output, `${prefix}-wizard-connection`, results);
  await dialog.getByLabel('显示名称', { exact: true }).fill('视觉验收 · 新增通道');
  await dialog.getByLabel('SSH 主机', { exact: true }).fill('127.0.0.1');
  await dialog.getByLabel('SSH 用户', { exact: true }).fill('qa');
  await dialog.getByRole('button', { name: '下一步', exact: true }).click();
  await capture(page, output, `${prefix}-wizard-exit`, results);
  await dialog.getByRole('button', { name: '下一步', exact: true }).click();
  await capture(page, output, `${prefix}-wizard-review`, results);
  await page.keyboard.press('Escape');
  await expect(dialog).not.toBeVisible();
}

async function detailOverlays(page, output, prefix, results) {
  const currentMode = await page.locator('.mode-option[aria-pressed="true"]').textContent();
  const alternative = page.locator('.mode-option').filter({ hasText: currentMode?.includes('Mac 直连') ? 'Clash HTTP' : 'Mac 直连' });
  await alternative.click();
  const confirm = page.getByRole('dialog', { name: '确认切换代理出口', exact: true });
  await expect(confirm).toBeVisible();
  await expect(confirm.getByText('正在检查目标出口', { exact: true })).not.toBeVisible({ timeout: 10000 });
  await capture(page, output, `${prefix}-mode-confirmation`, results);
  await page.keyboard.press('Escape');
  await expect(confirm).not.toBeVisible();
  await page.getByRole('button', { name: '接管预览', exact: true }).click();
  const migration = page.getByRole('dialog', { name: '接管影响与回滚预览', exact: true });
  await expect(migration).toBeVisible();
  await capture(page, output, `${prefix}-migration-preview`, results);
  await page.keyboard.press('Escape');
  await expect(migration).not.toBeVisible();
}

async function staleCapture(page, output, prefix, origin, selected, results) {
  let accepting = true;
  let active;
  await page.routeWebSocket(origin.replace('http://', 'ws://') + '/api/v1/ws', route => {
    if (!accepting) { void route.close({ code: 1012, reason: 'Isolated UI audit transport disconnect' }); return; }
    active = route;
    route.connectToServer();
  });
  await page.reload({ waitUntil: 'domcontentloaded' });
  await expect(page.locator('.local-indicator')).toContainText('实时同步', { timeout: 10000 });
  await navigate(page, '服务器');
  await openDetail(page, selected.id, selected.name);
  const realBefore = await currentOverview(page, origin);
  const before = realBefore.runtimes[selected.id];
  expect(before.state).toBe('HEALTHY');
  accepting = false;
  await active.close({ code: 1012, reason: 'Isolated UI audit transport disconnect' });
  await expect(page.locator('.local-indicator')).toContainText('连接中断', { timeout: 6000 });
  await expect(page.locator('.hero-status .state-badge')).toHaveText('观测过期');
  await expect(page.locator('.hero-status .state-badge')).not.toHaveClass(/good/);
  const realAfter = await currentOverview(page, origin);
  expect(realAfter.runtimes[selected.id].state).toBe('HEALTHY');
  await capture(page, output, `${prefix}-stale-detail`, results);
  await navigate(page, '总览');
  await capture(page, output, `${prefix}-stale-overview`, results);
  results.stale_checks = [...(results.stale_checks || []), { prefix, backend_before: before.state,
    backend_after: realAfter.runtimes[selected.id].state, display: '观测过期', fabricated_frames: false }];
  accepting = true;
  await expect(page.locator('.local-indicator')).toContainText('实时同步', { timeout: 15000 });
}

async function diagnosticCapture(page, output, prefix, results) {
  const button = page.getByRole('button', { name: '运行诊断', exact: true });
  await expect(button).toBeEnabled();
  await button.click();
  await expect(page.locator('.diagnostic-result')).toBeVisible({ timeout: 30000 });
  await capture(page, output, `${prefix}-diagnostic-result`, results);
}

async function keyboardAudit(page, output, results, theme) {
  await navigate(page, '总览');
  const trigger = page.getByRole('button', { name: '添加服务器', exact: true }).first();
  await trigger.focus();
  await page.keyboard.press('Enter');
  const dialog = page.getByRole('dialog');
  await expect(dialog).toBeVisible();
  const focusRecords = [];
  for (let index = 0; index < 18; index++) {
    await page.keyboard.press(index % 3 === 0 ? 'Shift+Tab' : 'Tab');
    const focused = await page.evaluate(() => {
      const element = document.activeElement;
      if (!element) return null;
      const style = getComputedStyle(element);
      return { in_dialog: Boolean(element.closest('[role="dialog"]')), tag: element.tagName,
        name: element.getAttribute('aria-label') || element.textContent?.trim().slice(0, 80) || '',
        outline_style: style.outlineStyle, outline_width: style.outlineWidth,
        box_shadow: style.boxShadow };
    });
    expect(focused?.in_dialog).toBeTruthy();
    expect(focused?.outline_style !== 'none' && Number.parseFloat(focused?.outline_width || '0') > 0
      || focused?.box_shadow !== 'none', 'Keyboard focus must have a visible ring or shadow').toBeTruthy();
    focusRecords.push(focused);
  }
  await capture(page, output, `${theme}-keyboard-wizard-focus`, results);
  await page.keyboard.press('Escape');
  await expect(dialog).not.toBeVisible();
  await expect(trigger).toBeFocused();
  results.keyboard = [...(results.keyboard || []), { theme, modal_tab_containment: true, escape: true, focus_restore: true, focus_records: focusRecords }];
}

export async function runAudit(options) {
  const root = fs.realpathSync(process.cwd());
  const output = insideRoot(root, options.out || 'var/reports/v2-ui/round2');
  if (fs.existsSync(output)) throw new Error('Use a fresh evidence output directory; earlier runs must remain retained');
  fs.mkdirSync(path.join(output, 'screenshots'), { recursive: true, mode: 0o700 });
  fs.mkdirSync(path.join(output, 'videos'), { recursive: true, mode: 0o700 });
  fs.mkdirSync(path.join(root, 'var/tmp'), { recursive: true, mode: 0o700 });
  process.env.TMPDIR = path.join(root, 'var/tmp');
  process.env.PLAYWRIGHT_BROWSERS_PATH = path.join(root, 'var/cache/playwright');
  const socket = insideRoot(root, options.socket || '.run/app/control.sock');
  const results = { started_at: new Date().toISOString(), status: 'IN_PROGRESS', reviewer: 'independent UI Critic',
    browser: 'installed Chrome channel', fabricated_responses: false, captures: [], errors: [],
    limits: ['Visual capture does not establish production takeover or login/wake acceptance.'] };
  const browser = await chromium.launch({ headless: true, channel: 'chrome' });
  let context;
  try {
    for (const theme of ['light', 'dark']) {
      for (const viewport of viewports) {
        const info = await ipc(socket, 'ticket');
        const origin = `http://127.0.0.1:${info.port}`;
        context = await browser.newContext({ viewport, colorScheme: theme,
          recordVideo: viewport.width === 1440 ? { dir: path.join(output, 'videos'), size: viewport } : undefined });
        const page = await context.newPage();
        page.on('pageerror', error => results.errors.push({ type: 'pageerror', message: error.message.slice(0, 300) }));
        await page.addInitScript(() => localStorage.setItem('tm-theme', 'system'));
        await installEvidenceRedaction(page);
        await page.goto(`${origin}/#ticket=${encodeURIComponent(info.ticket)}`, { waitUntil: 'domcontentloaded' });
        await expect(page.getByRole('heading', { name: '隧道总览', exact: true })).toBeVisible();
        await expect(page).toHaveURL(origin + '/');
        await expect(page.locator('.local-indicator')).toContainText('实时同步', { timeout: 10000 });
        await setTheme(page, theme);
        const prefix = `${theme}-${viewport.width}x${viewport.height}`;
        const overview = await currentOverview(page, origin);
        const serverId = options['server-id'] || overview.servers[0]?.id;
        const selected = overview.servers.find(server => server.id === serverId);
        results.observed = safeOverview(overview);
        results.observed_snapshots = [...(results.observed_snapshots || []), { prefix, ...safeOverview(overview) }];
        for (const view of ['总览', '服务器', '发现服务', '系统设置']) {
          await navigate(page, view);
          const slug = { 总览: 'overview', 服务器: 'servers', 发现服务: 'discovery', 系统设置: 'settings' }[view];
          await capture(page, output, `${prefix}-${slug}`, results, view === '总览' ? { overview } : {});
          if (view === '服务器' && selected) {
            await openDetail(page, selected.id, selected.name);
            await capture(page, output, `${prefix}-detail`, results);
            await detailOverlays(page, output, prefix, results);
            if (options.diagnostics === 'true') await diagnosticCapture(page, output, prefix, results);
          }
        }
        await wizardCaptures(page, output, prefix, results);
        if (viewport.width === 1440) {
          if (selected && overview.runtimes[selected.id]?.state === 'HEALTHY')
            await staleCapture(page, output, prefix, origin, selected, results);
          await setTheme(page, 'system');
          await page.emulateMedia({ colorScheme: 'light' });
          await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
          await page.emulateMedia({ colorScheme: 'dark' });
          await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
          results.system_theme_live_change = true;
          await setTheme(page, theme);
          const unscaledBodyFont = await page.evaluate(() => Number.parseFloat(getComputedStyle(document.body).fontSize));
          for (const factor of [1.25, 1.5, 2]) {
            await page.evaluate(scale => document.documentElement.style.fontSize = `${16 * scale}px`, factor);
            const actualBodyFont = await page.evaluate(() => Number.parseFloat(getComputedStyle(document.body).fontSize));
            results.font_scaling = [...(results.font_scaling || []), { theme, requested: factor, unscaled_body_px: unscaledBodyFont,
              actual_body_px: actualBodyFont, changed: actualBodyFont >= unscaledBodyFont * factor - 0.5 }];
            for (const view of ['总览', '服务器', '发现服务', '系统设置']) {
              await navigate(page, view);
              await capture(page, output, `${theme}-font-${Math.round(factor * 100)}-${{ 总览: 'overview', 服务器: 'servers', 发现服务: 'discovery', 系统设置: 'settings' }[view]}`, results,
                view === '总览' ? { overview: await currentOverview(page, origin) } : {});
              if (view === '服务器' && selected) {
                await openDetail(page, selected.id, selected.name);
                await capture(page, output, `${theme}-font-${Math.round(factor * 100)}-detail`, results);
              }
            }
            await wizardCaptures(page, output, `${theme}-font-${Math.round(factor * 100)}`, results);
          }
          await page.evaluate(() => document.documentElement.style.fontSize = '');
          for (const factor of [1.25, 1.5, 2]) {
            await page.evaluate(scale => document.documentElement.style.zoom = String(scale), factor);
            await navigate(page, '总览');
            await capture(page, output, `${theme}-pagezoom-${Math.round(factor * 100)}-overview`, results,
              { overview: await currentOverview(page, origin) });
            await navigate(page, '服务器');
            if (selected) {
              await openDetail(page, selected.id, selected.name);
              await capture(page, output, `${theme}-pagezoom-${Math.round(factor * 100)}-detail`, results);
            }
          }
          await page.evaluate(() => document.documentElement.style.zoom = '');
          await page.emulateMedia({ reducedMotion: 'reduce' });
          await navigate(page, '总览');
          await capture(page, output, `${theme}-reduced-motion-overview`, results, { overview: await currentOverview(page, origin) });
          const motion = await page.evaluate(() => [...document.querySelectorAll('*')]
            .map(element => ({ name: element.className?.baseVal ?? element.className, duration: getComputedStyle(element).animationDuration,
              iterations: getComputedStyle(element).animationIterationCount }))
            .filter(element => element.iterations === 'infinite' && element.duration !== '0s' && element.duration !== '0.001s'));
          results.reduced_motion = motion;
          await page.emulateMedia({ reducedMotion: 'no-preference' });
          await keyboardAudit(page, output, results, theme);
          if (options['state-capture'] === 'true') {
            results.limits.push('State capture is enabled; only supplied real fixture states are reviewed.');
          }
        }
        const video = page.video();
        await context.close();
        context = null;
        if (video) results.video_paths = [...(results.video_paths || []), path.relative(output, await video.path())];
      }
    }
    results.status = results.errors.length || results.captures.some(capture => capture.blockers.length) || results.reduced_motion?.length
      || results.font_scaling?.some(scale => !scale.changed) ? 'NO-GO' : 'AUTOMATED_CHECKS_PASSED_MANUAL_REVIEW_REQUIRED';
  } catch (error) {
    results.status = 'NO-GO';
    results.errors.push({ type: 'assertion', message: String(error.message || error).slice(0, 2000) });
  } finally {
    if (context) await context.close();
    await browser.close();
    results.completed_at = new Date().toISOString();
    fs.writeFileSync(path.join(output, 'audit-results.json'), JSON.stringify(results, null, 2), { mode: 0o600 });
    fs.writeFileSync(path.join(output, 'screenshot-index.md'), '# V2 UI screenshot index\n\n' + results.captures.map(capture =>
      `- [${capture.name}](${capture.screenshot})${capture.viewport_screenshot ? ` · [实际首屏](${capture.viewport_screenshot})` : ''}`
    ).join('\n') + '\n', { mode: 0o600 });
  }
  console.log(JSON.stringify({ status: results.status, captures: results.captures.length, evidence: path.relative(root, output),
    blockers: results.captures.filter(capture => capture.blockers.length).map(capture => ({ name: capture.name, blockers: capture.blockers })), errors: results.errors }, null, 2));
  if (results.status === 'NO-GO') process.exitCode = 1;
  return results;
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  try { await runAudit(parseOptions(process.argv.slice(2))); }
  catch (error) { console.error(error.message); process.exitCode = 1; }
}
