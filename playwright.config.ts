import { defineConfig } from '@playwright/test';
export default defineConfig({
  testDir: './tests/e2e',
  timeout: 30000,
  workers: 1,
  use: { headless: true, channel: 'chrome', trace: 'retain-on-failure', screenshot: 'only-on-failure' },
  outputDir: 'var/reports/playwright-results',
  reporter: [['list'], ['html', { outputFolder: 'var/reports/playwright-html', open: 'never' }]],
});
