import { chromium } from 'playwright';
import { expect } from '@playwright/test';
import fs from 'node:fs';
import path from 'node:path';
import net from 'node:net';

const root = process.cwd();
process.env.TMPDIR = path.join(root, 'var/tmp');
process.env.PLAYWRIGHT_BROWSERS_PATH = path.join(root, 'var/cache/playwright');
const fixture = JSON.parse(fs.readFileSync(path.join(root, 'var/reports/v2-packaged-fixture.json'), 'utf8'));
const output = path.join(root, 'var/reports/v2-ui/round3-interactions');
if (fs.existsSync(output)) throw new Error('Prior independent evidence must be retained');
fs.mkdirSync(output, { recursive: true, mode: 0o700 });
const evidence = { started_at: new Date().toISOString(), frozen_native_fixture: fixture.packaged_app,
  mutations: false, fabricated_responses: false, checks: [], status: 'IN_PROGRESS' };
function ticket() {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection(fixture.ipc_socket);
    let body = '';
    socket.setTimeout(4000);
    socket.on('connect', () => socket.write('{"command":"ticket"}\n'));
    socket.on('data', chunk => {
      body += chunk;
      if (body.includes('\n')) { socket.end(); resolve(JSON.parse(body)); }
    });
    socket.on('error', reject);
    socket.on('timeout', () => { socket.destroy(); reject(new Error('Private fixture IPC timeout')); });
  });
}
const browser = await chromium.launch({ channel: 'chrome', headless: true });
try {
  for (const theme of ['light', 'dark']) {
    const context = await browser.newContext({ viewport: { width: 1440, height: 900 }, colorScheme: theme });
    const page = await context.newPage();
    await page.addInitScript(() => localStorage.setItem('tm-theme', 'system'));
    const session = await ticket();
    await page.goto(`${fixture.origin}/#ticket=${encodeURIComponent(session.ticket)}`);
    await expect(page.getByRole('heading', { name: '隧道总览', exact: true })).toBeVisible();
    await expect(page.locator('.local-indicator')).toContainText('实时同步');
    const response = await page.request.get(fixture.origin + '/api/v1/overview');
    expect(response.status()).toBe(200);
    const current = await response.json();
    await expect(page.getByTestId('topology-server')).toHaveCount(current.servers.length);
    await page.getByLabel('拓扑出口筛选', { exact: true }).selectOption('MAC_DIRECT');
    const direct = current.servers.filter(server => server.mode === 'MAC_DIRECT');
    await expect(page.getByTestId('topology-server')).toHaveCount(direct.length);
    await page.getByLabel('拓扑出口筛选', { exact: true }).selectOption('CLASH_HTTP');
    const clash = current.servers.filter(server => server.mode === 'CLASH_HTTP');
    await expect(page.getByTestId('topology-server')).toHaveCount(clash.length);
    await page.getByRole('button', { name: '适应视图', exact: true }).click();
    await expect(page.getByTestId('topology-server')).toHaveCount(current.servers.length);
    if (current.groups.length) {
      await page.getByLabel('拓扑分组筛选', { exact: true }).selectOption(current.groups[0].id);
      await expect(page.getByTestId('topology-server')).toHaveCount(current.servers.filter(server => server.group_id === current.groups[0].id).length);
      await page.getByRole('button', { name: '适应视图', exact: true }).click();
    }
    const before = await page.locator('.topology-map').evaluate(element => getComputedStyle(element).zoom);
    await page.getByRole('button', { name: '放大拓扑', exact: true }).click();
    const after = await page.locator('.topology-map').evaluate(element => getComputedStyle(element).zoom);
    expect(Number(after)).toBeGreaterThan(Number(before));
    await page.getByRole('button', { name: '适应视图', exact: true }).click();
    await expect.poll(() => page.locator('.topology-map').evaluate(element => getComputedStyle(element).zoom)).toBe('1');
    await page.getByRole('button', { name: '查看汇总', exact: true }).click();
    const topology = page.getByTestId('network-topology');
    for (const server of current.servers) {
      const actual = topology.getByRole('button').filter({ hasText: server.name });
      await expect(actual).toBeVisible();
      await expect(actual).toContainText(server.desired_state === 'RUNNING' && server.mode !== 'DISABLED' ? '期望开启' : '期望关闭');
      expect(await actual.locator('.state-badge').count()).toBe(1);
    }
    await page.screenshot({ path: path.join(output, `${theme}-truthful-aggregation.png`), fullPage: false, animations: 'disabled' });
    await page.getByRole('button', { name: '展开全部路径', exact: true }).click();
    evidence.checks.push({ theme, name: 'actual topology exit/group filters, zoom, reset and complete aggregation',
      direct_count: direct.length, clash_count: clash.length, all_count: current.servers.length, zoom_before: before,
      zoom_after: after, all_names_and_desired_states_retained: true, result: 'PASS' });

    const cdp = await context.newCDPSession(page);
    await cdp.send('Emulation.setEmulatedMedia', { features: [
      { name: 'prefers-color-scheme', value: theme }, { name: 'prefers-reduced-transparency', value: 'reduce' },
      { name: 'prefers-contrast', value: 'more' }, { name: 'prefers-reduced-motion', value: 'reduce' },
    ] });
    const accessibility = await page.evaluate(() => ({
      transparency: matchMedia('(prefers-reduced-transparency: reduce)').matches,
      contrast: matchMedia('(prefers-contrast: more)').matches,
      motion: matchMedia('(prefers-reduced-motion: reduce)').matches,
      materials: [...document.querySelectorAll('.sidebar,.topbar')].map(element => {
        const style = getComputedStyle(element);
        return { background: style.backgroundColor, blur: style.backdropFilter };
      }),
    }));
    expect(accessibility.transparency).toBe(true);
    expect(accessibility.contrast).toBe(true);
    expect(accessibility.motion).toBe(true);
    for (const material of accessibility.materials) {
      expect(material.blur).toBe('none');
      expect(material.background).not.toContain('rgba');
    }
    await page.screenshot({ path: path.join(output, `${theme}-opaque-high-contrast.png`), fullPage: false, animations: 'disabled' });
    evidence.checks.push({ theme, name: 'actual browser reduced transparency / increased contrast / reduced motion fallback',
      ...accessibility, result: 'PASS' });
    await context.close();
  }
  evidence.status = 'PASS';
} catch (error) {
  evidence.status = 'FAIL';
  evidence.error = String(error.message || error).slice(0, 2000);
  process.exitCode = 1;
} finally {
  await browser.close();
  evidence.completed_at = new Date().toISOString();
  fs.writeFileSync(path.join(output, 'evidence.json'), JSON.stringify(evidence, null, 2), { mode: 0o600 });
  console.log(JSON.stringify(evidence, null, 2));
}
