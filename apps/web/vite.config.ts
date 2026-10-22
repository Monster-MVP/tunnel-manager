import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'node:path';
export default defineConfig({
  root: path.resolve('apps/web'), plugins: [react()],
  build: { outDir: path.resolve('var/build/web'), emptyOutDir: true },
  server: { host: '127.0.0.1', port: 18400, strictPort: true }
});
