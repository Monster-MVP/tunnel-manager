import { test, expect } from './live.fixture';

test.use({ channel: 'chrome', viewport: { width: 1440, height: 960 } });

test('remote Codex consent stays explicit and stopped/external profiles never request credentials', async ({ page, backend }, info) => {
  const session = await page.request.get(backend.origin + '/api/v1/sessions/current');
  const headers = { Origin: backend.origin, 'X-CSRF-Token': (await session.json()).csrf };
  for (const [name, management] of [['QA stopped Codex', 'MANAGED'], ['QA external Codex', 'OBSERVED_EXTERNAL']]) {
    const response = await page.request.post(backend.origin + '/api/v1/servers', {
      headers, data: { name, management, host: '127.0.0.1', user: 'qa', ssh_port: 22001, mode: 'DISABLED' },
    });
    expect(response.status()).toBe(201);
  }
  let credentialRequests = 0;
  page.on('request', request => { if (request.url().endsWith('/credentials/codex/check')) credentialRequests += 1; });
  await page.getByRole('button', { name: '服务器', exact: true }).click();
  await expect(page.getByText('QA stopped Codex', { exact: true }).first()).toBeVisible();
  await page.locator('.server-main').filter({ hasText: 'QA stopped Codex' }).click();
  const consent = page.getByRole('checkbox', { name: '允许在远端读取 Codex auth.json 并仅返回状态', exact: true });
  const check = page.getByRole('button', { name: '检查远程 Codex 登录凭据', exact: true });
  await expect(consent).not.toBeChecked();
  await expect(check).toBeDisabled();
  await consent.check();
  await expect(check).toBeDisabled();
  await expect(page.getByTestId('codex-credential-result')).toContainText('尚未检查');
  await expect(page.getByText('请先启用此托管通道并等待 SSH 连接建立，再检查远程凭据。', { exact: true })).toBeVisible();
  await page.getByRole('heading', { name: '远程 Codex 登录凭据', exact: true }).scrollIntoViewIfNeeded();
  await page.screenshot({ path: info.outputPath('codex-credentials-stopped-1440.png'), animations: 'disabled' });
  await page.getByRole('button', { name: '返回服务器', exact: true }).click();
  await page.locator('.server-main').filter({ hasText: 'QA external Codex' }).click();
  await expect(consent).not.toBeChecked();
  await expect(consent).toBeDisabled();
  await expect(check).toBeDisabled();
  await expect(page.getByRole('button', { name: '外部服务不可控制', exact: true })).toBeDisabled();
  await expect(page.getByRole('button', { name: '运行诊断', exact: true })).toBeDisabled();
  await expect(page.getByRole('button', { name: '立即探测', exact: true })).toBeDisabled();
  await expect(page.getByTestId('codex-credential-result')).toContainText('尚未检查');
  await expect(page.getByText('外部服务仅供观察，不能读取登录凭据。请另建获授权的托管通道。', { exact: true })).toBeVisible();
  expect(credentialRequests).toBe(0);
  expect(backend.process.exitCode).toBeNull();
});
