import { test, expect } from './live.fixture';

test.use({ channel: 'chrome', viewport: { width: 1440, height: 960 } });

test('model test uses separate consent and never requests stopped or external profiles', async ({ page, backend }, info) => {
  const session = await page.request.get(backend.origin + '/api/v1/sessions/current');
  const headers = { Origin: backend.origin, 'X-CSRF-Token': (await session.json()).csrf };
  for (const [name, management] of [['QA stopped model', 'MANAGED'], ['QA external model', 'OBSERVED_EXTERNAL']]) {
    const created = await page.request.post(backend.origin + '/api/v1/servers', {
      headers, data: { name, management, host: '127.0.0.1', user: 'qa', ssh_port: 22001, mode: 'DISABLED' },
    });
    expect(created.status()).toBe(201);
  }
  let modelRequests = 0;
  let credentialRequests = 0;
  page.on('request', request => {
    if (/\/model-test(?:\/preview)?$/.test(request.url())) modelRequests += 1;
    if (request.url().endsWith('/credentials/codex/check')) credentialRequests += 1;
  });
  await page.getByRole('button', { name: '服务器', exact: true }).click();
  await page.locator('.server-main').filter({ hasText: 'QA stopped model' }).click();
  const section = page.getByTestId('codex-model-test');
  const preview = section.getByRole('button', { name: '读取远程模型配置', exact: true });
  const consent = section.getByRole('checkbox', { name: '允许使用远端 API 密钥向上述服务发送一次模型测试请求（可能消耗额度）', exact: true });
  const modelTest = section.getByRole('button', { name: '测试鉴权与模型调用', exact: true });
  await expect(section.getByRole('heading', { name: '模型调用测试', exact: true })).toBeVisible();
  await expect(preview).toBeDisabled();
  await expect(consent).not.toBeChecked();
  await expect(consent).toBeDisabled();
  await expect(modelTest).toBeDisabled();
  await section.getByLabel('服务地址（HTTPS）', { exact: true }).fill('https://provider.invalid/v1');
  await section.getByLabel('模型名称', { exact: true }).fill('qa-synthetic-model');
  await section.getByLabel('接口协议', { exact: true }).selectOption('responses');
  await expect(consent).toBeDisabled();
  await expect(modelTest).toBeDisabled();
  const credentialConsent = page.getByRole('checkbox', { name: '允许在远端读取 Codex auth.json 并仅返回状态', exact: true });
  await credentialConsent.check();
  await expect(consent).not.toBeChecked();
  await expect(section.getByTestId('codex-model-result')).toContainText('未测试');
  await section.scrollIntoViewIfNeeded();
  await page.screenshot({ path: info.outputPath('codex-model-stopped-1440.png'), animations: 'disabled' });
  await page.getByRole('button', { name: '返回服务器', exact: true }).click();
  await page.locator('.server-main').filter({ hasText: 'QA external model' }).click();
  await expect(section.getByLabel('服务地址（HTTPS）', { exact: true })).toHaveValue('');
  await expect(section.getByLabel('服务地址（HTTPS）', { exact: true })).toBeDisabled();
  await expect(section.getByLabel('模型名称', { exact: true })).toHaveValue('');
  await expect(section.getByLabel('接口协议', { exact: true })).toHaveValue('');
  await expect(preview).toBeDisabled();
  await expect(consent).not.toBeChecked();
  await expect(consent).toBeDisabled();
  await expect(modelTest).toBeDisabled();
  await expect(section).toContainText('外部服务仅供观察，不能读取模型配置或发送测试请求。');
  expect(modelRequests).toBe(0);
  expect(credentialRequests).toBe(0);
  expect(backend.process.exitCode).toBeNull();
});
