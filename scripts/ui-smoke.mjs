import { chromium } from 'playwright';
import net from 'node:net';
import path from 'node:path';
import fs from 'node:fs';

const root = process.cwd();
const socketPath = path.resolve(process.argv[2] || '.run/dev/control.sock');
async function ticket() {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection(socketPath);
    socket.setTimeout(3000);
    let data = '';
    socket.on('connect', () => socket.write('{"command":"ticket"}\n'));
    socket.on('data', chunk => {
      data += chunk;
      if (data.includes('\n')) {
        socket.end();
        try { resolve(JSON.parse(data.trim())); } catch (error) { reject(error); }
      }
    });
    socket.on('timeout', () => { socket.destroy(); reject(new Error('IPC timeout')); });
    socket.on('error', reject);
  });
}

// The bundled headless shell on this macOS build can hang in screenshot capture;
// use the installed Chrome channel for the same browser automation path.
const browser = await chromium.launch({ headless: true, channel: 'chrome' });
const results = [];
try {
  for (const width of [1440, 1280, 1024, 768]) {
    const context = await browser.newContext({ viewport: { width, height: 960 } });
    const page = await context.newPage();
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    const info = await ticket();
    await page.goto(`http://127.0.0.1:${info.port}/#ticket=${encodeURIComponent(info.ticket)}`, { waitUntil: 'networkidle' });
    await page.waitForTimeout(300);
    await page.screenshot({ path: path.join(root, `var/reports/ui-${width}.png`), fullPage: true, timeout: 15000 });
    results.push({ width, errors, body: (await page.locator('body').innerText()).slice(0, 1000),
      geometry: await page.evaluate(() => ({ content: document.documentElement.scrollWidth, viewport: document.documentElement.clientWidth })),
      authenticated: !await page.getByText('无法建立本地会话').count(),
      buttons: await page.locator('button').count() });
    await context.close();
  }
} finally {
  await browser.close();
}
fs.writeFileSync(path.join(root, 'var/reports/ui-smoke.json'), JSON.stringify(results, null, 2));
console.log(JSON.stringify(results, null, 2));
if (results.some(item => item.errors.length || !item.authenticated || item.geometry.content > item.geometry.viewport + 2)) process.exitCode = 1;
