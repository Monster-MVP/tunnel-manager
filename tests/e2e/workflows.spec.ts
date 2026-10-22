import { test, expect } from './live.fixture';
import type { Page, WebSocketRoute } from '@playwright/test';
import fs from 'node:fs';
import net from 'node:net';

test.use({ channel: 'chrome', viewport: { width: 1440, height: 960 } });

async function add(page: Page, name = 'QA localhost') {
  await page.getByRole('button', { name: '添加服务器', exact: true }).first().click();
  const dialog = page.getByRole('dialog', { name: '添加服务器', exact: true });
  await dialog.getByLabel('显示名称').fill(name);
  await dialog.getByLabel('SSH 主机').fill('127.0.0.1');
  await dialog.getByLabel('SSH 用户').fill('qa');
  await dialog.getByLabel('SSH 端口', { exact: true }).fill('22001');
  await dialog.getByRole('button', { name: '下一步', exact: true }).click();
  await dialog.getByRole('combobox', { name: '代理出口', exact: true }).selectOption('DISABLED');
  await dialog.getByLabel('远程代理端口').fill('19991');
  await dialog.getByText('高级设置', { exact: true }).click();
  await dialog.getByLabel('自动重连').uncheck();
  await dialog.getByRole('button', { name: '下一步', exact: true }).click();
  await dialog.getByRole('button', { name: '添加服务器', exact: true }).click();
  await expect(dialog).not.toBeVisible();
  await expect(page.getByText(name, { exact: true }).first()).toBeVisible();
}

async function unusedLoopbackPort() {
  return new Promise<number>((resolve, reject) => {
    const server = net.createServer();
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const address = server.address() as net.AddressInfo;
      server.close(() => resolve(address.port));
    });
  });
}

test('CRUD, actual mode/action API, detail, filters, logs and deletion', async ({ page, backend }) => {
  const errors: string[] = [];
  page.on('pageerror', error => errors.push(error.message));
  await add(page);
  await page.locator('.server-main').filter({ hasText: 'QA localhost' }).click();
  await expect(page.getByRole('heading', { name: 'QA localhost', exact: true })).toBeVisible();
  await page.getByRole('button', { name: '编辑', exact: true }).click();
  const dialog = page.getByRole('dialog', { name: '编辑服务器' });
  await dialog.getByLabel('显示名称').fill('QA edited');
  await dialog.getByRole('button', { name: '保存更改' }).click();
  await expect(dialog).not.toBeVisible();
  await expect(page.getByRole('heading', { name: 'QA edited', exact: true })).toBeVisible();
  await page.locator('.mode-option').filter({ hasText: 'Mac 直连' }).click();
  const directMode = page.getByRole('dialog', { name: '确认切换代理出口' });
  await directMode.getByLabel('目标本机代理端口', { exact: true }).fill(String(await unusedLoopbackPort()));
  await directMode.getByRole('button', { name: '检查目标出口', exact: true }).click();
  await expect(directMode).toContainText('目标出口检查完成');
  await directMode.getByRole('button', { name: '确认切换' }).click();
  await expect(page.locator('.mode-option.selected')).toContainText('Mac 直连');
  await page.locator('.mode-option').filter({ hasText: '已停用' }).click();
  await page.getByRole('dialog', { name: '确认切换代理出口' }).getByRole('button', { name: '确认切换' }).click();
  await expect(page.locator('.mode-option.selected')).toContainText('已停用');
  await expect(page.getByRole('button', { name: '启动隧道', exact: true })).toBeDisabled();
  await expect(page.locator('.hero-status')).toContainText('已停止');
  await expect(page.getByRole('button', { name: '重启隧道', exact: true })).toBeDisabled();
  await expect(page.getByRole('button', { name: '立即探测', exact: true })).toBeDisabled();
  await expect(page.getByText('暂无历史指标', { exact: true })).toBeVisible();
  await expect(page.getByText('此服务器尚无可显示的连接日志。', { exact: true })).toBeVisible();
  await page.getByPlaceholder('筛选日志').fill('does-not-exist');
  await page.getByRole('button', { name: '返回服务器' }).click();
  await page.getByPlaceholder('搜索名称、主机或用户').fill('does-not-exist');
  await expect(page.getByText('还没有服务器', { exact: true })).toBeVisible();
  await page.getByPlaceholder('搜索名称、主机或用户').fill('');
  await page.getByLabel('服务器状态筛选').selectOption('STOPPED');
  await page.locator('.server-main').filter({ hasText: 'QA edited' }).click();
  await page.getByRole('button', { name: '删除服务器', exact: true }).click();
  await page.getByRole('button', { name: '确认删除', exact: true }).click();
  await expect(page.getByText('QA edited', { exact: true })).toHaveCount(0);
  expect(errors).toEqual([]);
  expect(backend.process.exitCode).toBeNull();
});

test('settings, groups, SSH preview/commit, configuration roundtrip and diagnostics downloads', async ({ page, backend }, info) => {
  await page.getByRole('button', { name: '系统设置', exact: true }).click();
  await page.getByLabel('新分组名称').fill('QA group');
  await page.getByRole('button', { name: '创建分组' }).click();
  await expect(page.locator('.group-item')).toContainText('QA group');
  await page.getByLabel('探测间隔（秒）').fill('7');
  await page.getByRole('button', { name: '保存设置', exact: true }).click();
  await expect(page.getByRole('status')).toContainText('设置已保存');
  await page.locator('.setting-row').getByRole('button', { name: '浅色', exact: true }).click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await page.locator('.setting-row').getByRole('button', { name: '深色', exact: true }).click();
  await page.getByRole('button', { name: '导入 SSH 配置', exact: true }).click();
  const dialog = page.getByRole('dialog', { name: '导入 SSH Config' });
  await dialog.locator('textarea').fill('Host qa-import\n  HostName example.test\n  User qa\n  Port 22002\n');
  await dialog.getByRole('button', { name: '生成预览' }).click();
  await expect(dialog.getByText('qa-import', { exact: true })).toBeVisible();
  await dialog.getByRole('button', { name: '导入 1 项', exact: true }).click();
  await expect(dialog).not.toBeVisible();
  await page.getByLabel('备份包含主机、账户和密钥路径引用').check();
  const downloaded = page.waitForEvent('download');
  await page.getByRole('button', { name: '导出配置', exact: true }).click();
  const download = await downloaded;
  const saved = info.outputPath('configuration.json');
  await download.saveAs(saved);
  const configuration = JSON.parse(fs.readFileSync(saved, 'utf8'));
  expect(configuration.servers).toHaveLength(1);
  expect(configuration.servers[0].host).toBe('example.test');
  await page.getByRole('button', { name: '恢复配置', exact: true }).click();
  const restore = page.getByRole('dialog', { name: '恢复配置备份' });
  await restore.locator('textarea').fill(JSON.stringify(configuration));
  await restore.getByRole('button', { name: '预览备份' }).click();
  await restore.getByRole('button', { name: '确认恢复' }).click();
  await expect(restore).not.toBeVisible();
  const diagnosticPromise = page.waitForEvent('download');
  await page.getByRole('button', { name: '诊断日志', exact: true }).click();
  const diagnostic = await diagnosticPromise;
  const diagnosticPath = info.outputPath('diagnostics.json');
  await diagnostic.saveAs(diagnosticPath);
  expect(JSON.parse(fs.readFileSync(diagnosticPath, 'utf8')).servers).toHaveLength(2);
  await page.getByRole('button', { name: '删除分组 QA group', exact: true }).click();
  await expect(page.locator('.group-item')).toHaveCount(0);
  expect(backend.process.exitCode).toBeNull();
});

test('validation errors and keyboard modal dismissal do not claim success', async ({ page, backend }) => {
  const trigger = page.getByRole('button', { name: '添加服务器', exact: true }).first();
  await trigger.click();
  const dialog = page.getByRole('dialog', { name: '添加服务器' });
  await dialog.getByLabel('显示名称').fill('Invalid QA');
  await dialog.getByLabel('SSH 主机').fill('-oProxyCommand=bad');
  await dialog.getByLabel('SSH 用户').fill('qa');
  await dialog.getByRole('button', { name: '下一步', exact: true }).click();
  await dialog.getByRole('button', { name: '下一步', exact: true }).click();
  await dialog.getByRole('button', { name: '添加服务器', exact: true }).click();
  await expect(dialog.locator('.form-error')).toBeVisible();
  await expect(dialog).toBeVisible();
  await page.keyboard.press('Shift+Tab');
  expect(await page.evaluate(() => Boolean(document.activeElement?.closest('[role="dialog"]')))).toBeTruthy();
  await page.keyboard.press('Escape');
  await expect(dialog).not.toBeVisible();
  await expect(trigger).toBeFocused();
  expect(backend.process.exitCode).toBeNull();
});

test('responsive all-page snapshots, overflow checks and authenticated reload', async ({ page, backend }, info) => {
  const errors: string[] = [];
  page.on('pageerror', error => errors.push(error.message));
  await add(page, 'Long QA server name with readable labels');
  for (const width of [1440, 1280, 1024, 768, 390]) {
    await page.setViewportSize({ width, height: 960 });
    if (width > 820) await expect(page.getByRole('button', { name: '打开导航' })).not.toBeVisible();
    for (const view of ['总览', '服务器', '系统设置']) {
      if (await page.getByRole('button', { name: '打开导航' }).isVisible())
        await page.getByRole('button', { name: '打开导航' }).click();
      await page.locator('.sidebar').getByRole('button', { name: view, exact: true }).click();
      if (width <= 820) await expect.poll(() => page.locator('.sidebar').evaluate(element => element.getBoundingClientRect().right)).toBeLessThanOrEqual(1);
      await page.screenshot({ path: info.outputPath(`${width}-${view}.png`), fullPage: true, animations: 'disabled' });
      const geometry = await page.evaluate(() => ({ scroll: document.documentElement.scrollWidth, width: document.documentElement.clientWidth }));
      expect(geometry.scroll, `${width} ${view} horizontal overflow`).toBeLessThanOrEqual(geometry.width + 2);
      if (view === '服务器') {
        await page.locator('.server-main').first().click();
        await page.screenshot({ path: info.outputPath(`${width}-detail.png`), fullPage: true, animations: 'disabled' });
        const detailGeometry = await page.evaluate(() => ({ scroll: document.documentElement.scrollWidth, width: document.documentElement.clientWidth }));
        expect(detailGeometry.scroll, `${width} detail horizontal overflow`).toBeLessThanOrEqual(detailGeometry.width + 2);
      }
    }
  }
  await page.reload();
  await expect(page.getByRole('heading', { name: '隧道总览', exact: true })).toBeVisible();
  expect(page.url()).toBe(backend.origin + '/');
  expect(errors).toEqual([]);
});

test('actual SSH failure logs update while detail remains open', async ({ page, backend }) => {
  const proxy = net.createServer(socket => socket.end());
  await new Promise<void>(resolve => proxy.listen(0, '127.0.0.1', resolve));
  const address = proxy.address() as net.AddressInfo;
  try {
    await add(page, 'QA log stream');
    await page.locator('.server-main').filter({ hasText: 'QA log stream' }).click();
  await expect(page.getByText('此服务器尚无可显示的连接日志。', { exact: true })).toBeVisible();
    const session = await page.request.get(backend.origin + '/api/v1/sessions/current');
    const headers = { Origin: backend.origin, 'X-CSRF-Token': (await session.json()).csrf };
    const servers = await page.request.get(backend.origin + '/api/v1/servers');
    const server = (await servers.json())[0];
    const mode = await page.request.put(`${backend.origin}/api/v1/servers/${server.id}/mode`, {
      headers: { ...headers, 'If-Match': String(server.revision) }, data: { mode: 'CLASH_HTTP', proxy_port: address.port },
    });
    expect(mode.status()).toBe(202);
    await expect(page.locator('.mode-option.selected')).toContainText('Clash HTTP');
  await page.getByRole('button', { name: '启动隧道', exact: true }).click();
    await expect(page.locator('.hero-status')).toContainText('失败');
    // System OpenSSH produces the failure line, the backend persists it and pushes server.log.
    await expect(page.locator('.logs')).toContainText('Connection refused', { timeout: 5000 });
  } finally {
    await new Promise<void>(resolve => proxy.close(() => resolve()));
  }
});

test('actual WebSocket loss shows disconnection and restores authoritative snapshot', async ({ page, backend }) => {
  await add(page, 'QA websocket state');
  let allowConnections = true;
  let active: WebSocketRoute | undefined;
  await page.routeWebSocket(`${backend.origin.replace('http://', 'ws://')}/api/v1/ws`, ws => {
    if (!allowConnections) { void ws.close({ code: 1012, reason: 'QA isolated disconnect' }); return; }
    active = ws;
    ws.connectToServer(); // Keep actual backend frames; no mock state or messages.
  });
  await page.reload();
  await expect(page.getByRole('heading', { name: '隧道总览', exact: true })).toBeVisible();
  await expect(page.locator('.local-indicator')).toContainText('实时同步', { timeout: 5000 });
  expect(active).toBeDefined();
  allowConnections = false;
  await active!.close({ code: 1012, reason: 'QA isolated disconnect' });
  await expect(page.locator('.local-indicator')).toContainText('连接中断', { timeout: 5000 });
  const session = await page.request.get(backend.origin + '/api/v1/sessions/current');
  const created = await page.request.post(backend.origin + '/api/v1/servers', {
    headers: { Origin: backend.origin, 'X-CSRF-Token': (await session.json()).csrf },
    data: { name: 'QA added while websocket lost', host: '127.0.0.1', user: 'qa', mode: 'DISABLED' },
  });
  expect(created.status()).toBe(201);
  expect((await page.request.get(backend.origin + '/healthz')).status()).toBe(200);
  allowConnections = true;
  await expect(page.locator('.local-indicator')).toContainText('实时同步', { timeout: 10000 });
  await expect(page.getByText('QA added while websocket lost', { exact: true }).first()).toBeVisible();
  expect(backend.process.exitCode).toBeNull();
});
