import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { chromium } from 'playwright';
import { contrast } from '../../scripts/v2-ui-audit.mjs';

test('actual browser CSS srgb and rgb backgrounds give the same text contrast evidence', async () => {
  const root = process.cwd();
  const temporary = path.join(root, 'var/tmp');
  fs.mkdirSync(temporary, { recursive: true, mode: 0o700 });
  process.env.TMPDIR = temporary;
  const browser = await chromium.launch({ channel: 'chrome', headless: true });
  try {
    const page = await browser.newPage();
    await page.setContent('<main style="background:white"><p style="color:#bb2836;background:color(srgb .981333 .94098 .944824)">srgb sample</p><p style="color:#bb2836;background:rgb(250,240,241)">rgb sample</p></main>');
    const values = await contrast(page);
    const first = values.find(sample => sample.name === 'srgb sample');
    const second = values.find(sample => sample.name === 'rgb sample');
    assert.ok(first.ratio >= 4.5);
    assert.ok(Math.abs(first.ratio - second.ratio) < 0.03);
    assert.deepEqual(first.background.slice(0, 3), [250, 240, 241]);
    assert.deepEqual(second.background.slice(0, 3), [250, 240, 241]);
  } finally {
    await browser.close();
  }
});
