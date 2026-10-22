import { chromium } from 'playwright';
import fs from 'node:fs';
import path from 'node:path';
import { expect } from '@playwright/test';

const request = JSON.parse(fs.readFileSync(0, 'utf8'));
const output = path.join(process.cwd(), 'var/reports/v2-native-history');
fs.mkdirSync(output, { recursive: true });
const browser = await chromium.launch({ channel: 'chrome', headless: true });
let allow = true;
let active;
try {
  const context = await browser.newContext({ viewport: { width: 1440, height: 960 } });
  const page = await context.newPage();
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.routeWebSocket(request.origin.replace('http://', 'ws://') + '/api/v1/ws', ws => {
    if (!allow) { void ws.close({ code: 1012, reason: 'Isolated native QA disconnect' }); return; }
    active = ws;
    ws.connectToServer();
  });
  await page.goto(`${request.origin}/#ticket=${encodeURIComponent(request.ticket)}`);
  await expect(page.locator('.local-indicator')).toContainText('实时同步');
  await page.locator('.server-main').filter({ hasText: request.name }).click();
  await expect(page.locator('.hero-status')).toContainText('健康');
  await expect(page.locator('.state-history-segment.good').first()).toBeVisible();
  const current = await page.request.get(request.origin + `/api/v1/servers/${request.server_id}/metrics`);
  const samples = await current.json();
  expect(samples.length).toBeGreaterThan(0);
  expect(samples.every(sample => sample.http_status === 200 && sample.total_ms !== null)).toBeTruthy();
  expect(samples.some(sample => sample.state === 'HEALTHY')).toBeTruthy();
  // V2 aggregates the default 24h range into 120-second buckets. A recently
  // recovered tunnel may have one honest bucket, which cannot form a curve.
  // Select the actual 5m range and wait for at least two observed buckets;
  // keep the rendered curve and clip assertions instead of inventing points.
  await page.getByRole('group', { name: '历史时间范围' }).getByRole('button', { name: '5 分钟', exact: true }).click();
  await expect.poll(async () => {
    const response = await page.request.get(request.origin + `/api/v1/servers/${request.server_id}/metrics/history?range=5m`);
    const history = await response.json();
    return history.samples.length;
  }, { timeout: 12000 }).toBeGreaterThanOrEqual(2);
  await expect.poll(() => page.locator('.recharts-area-curve').count()).toBeGreaterThan(0);
  await expect.poll(() => page.locator('.recharts-area-curve').evaluate(element => element.getAttribute('d')?.length || 0)).toBeGreaterThan(20);
  await expect.poll(() => page.locator('.chart-wrap clipPath rect').evaluateAll(rectangles =>
    rectangles.length > 0 && rectangles.every(rectangle => Number(rectangle.getAttribute('width')) > 300)
  )).toBeTruthy();
  for (const width of [1440, 1280, 1024, 768]) {
    await page.setViewportSize({ width, height: 960 });
    await page.screenshot({ path: path.join(output, `healthy-detail-${width}.png`), fullPage: true, animations: 'disabled' });
    const size = await page.evaluate(() => [document.documentElement.scrollWidth, document.documentElement.clientWidth]);
    expect(size[0]).toBeLessThanOrEqual(size[1] + 2);
  }
  await page.setViewportSize({ width: 1440, height: 960 });
  allow = false;
  await active.close({ code: 1012, reason: 'Isolated native QA disconnect' });
  await expect(page.locator('.local-indicator')).toContainText('连接中断');
  await expect(page.locator('.hero-status .state-badge')).toHaveText('观测过期');
  await expect(page.locator('.hero-status .state-badge')).not.toHaveClass(/good/);
  const runtime = await page.request.get(request.origin + `/api/v1/servers/${request.server_id}/runtime`);
  expect((await runtime.json()).state).toBe('HEALTHY');
  await page.screenshot({ path: path.join(output, 'websocket-lost.png'), fullPage: true, animations: 'disabled' });
  allow = true;
  await expect(page.locator('.local-indicator')).toContainText('实时同步', { timeout: 10000 });
  await expect(page.locator('.hero-status')).toContainText('健康');
  expect(errors).toEqual([]);
  await context.close();
  console.log('QA_NATIVE_BROWSER: real HTTP metric history and stale WebSocket display passed; browser closed');
} finally {
  await browser.close();
}
