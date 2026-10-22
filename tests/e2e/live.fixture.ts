import { test as base, expect } from '@playwright/test';
import type { ChildProcess } from 'node:child_process';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import net from 'node:net';
import { randomUUID } from 'node:crypto';

const root = process.cwd();
type Backend = { origin: string; runtime: string; data: string; process: ChildProcess; ipc: (command: string) => Promise<{ port: number; ticket?: string }> };

function ipc(runtime: string, command: string) {
  return new Promise<{ port: number; ticket?: string }>((resolve, reject) => {
    const socket = net.createConnection(path.join(runtime, 'control.sock'));
    let data = '';
    socket.setTimeout(3000);
    socket.on('connect', () => socket.write(JSON.stringify({ command }) + '\n'));
    socket.on('data', chunk => {
      data += chunk;
      if (data.includes('\n')) {
        socket.end();
        try { resolve(JSON.parse(data.trim())); } catch (error) { reject(error); }
      }
    });
    socket.on('error', reject);
    socket.on('timeout', () => { socket.destroy(); reject(new Error('QA IPC timed out')); });
  });
}

export const test = base.extend<{ backend: Backend }>({
  backend: async ({ page }, use, testInfo) => {
    const id = randomUUID().slice(0, 6);
    const data = path.join(root, 'var/tmp/reliability-e2e', id, 'data');
    const runtime = path.join(root, '.run', 'qe-' + id);
    const logs = path.join(root, 'var/tmp/reliability-e2e', id, 'backend.log');
    fs.mkdirSync(path.dirname(logs), { recursive: true, mode: 0o700 });
    const output = fs.openSync(logs, 'a', 0o600);
    const child = spawn(path.join(root, '.venv/bin/python'), [ '-m', 'app.bootstrap', '--data-dir', data,
      '--runtime-dir', runtime, '--web-dir', path.join(root, 'var/build/web'), '--port', '0',
      '--tinyproxy-executable', path.join(root, 'var/dist/Tunnel Manager.app/Contents/Resources/tinyproxy') ], {
      cwd: root, env: { ...process.env, PYTHONPATH: path.join(root, 'apps/backend'),
        PYTHONDONTWRITEBYTECODE: '1', TMPDIR: path.join(root, 'var/tmp') }, stdio: ['ignore', output, output],
    });
    const endpoint = path.join(runtime, 'endpoint.json');
    try {
      await expect.poll(() => fs.existsSync(endpoint), { timeout: 10000 }).toBeTruthy();
      const { origin } = JSON.parse(fs.readFileSync(endpoint, 'utf8'));
      const ticket = await ipc(runtime, 'ticket');
      await page.goto(`${origin}/#ticket=${encodeURIComponent(ticket.ticket!)}`);
      await expect(page.getByRole('heading', { name: '隧道总览', exact: true })).toBeVisible();
      await expect(page).toHaveURL(origin + '/');
      await use({ origin, runtime, data, process: child, ipc: command => ipc(runtime, command) });
    } finally {
      if (child.exitCode === null) {
        await ipc(runtime, 'shutdown').catch(() => {});
        await new Promise<void>(resolve => {
          const timer = setTimeout(() => { child.kill('SIGTERM'); resolve(); }, 5000);
          child.once('exit', () => { clearTimeout(timer); resolve(); });
        });
      }
      fs.closeSync(output);
      if (testInfo.status !== testInfo.expectedStatus)
        await testInfo.attach('backend-log', { path: logs, contentType: 'text/plain' });
    }
  },
});
export { expect };
