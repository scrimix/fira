import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'node:path';

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: { '@': path.resolve(__dirname, 'src') },
  },
  server: {
    port: 5173,
    host: true,
    proxy: {
      // The api mounts everything under `/api/*` (and `/health` at root for
      // Fly). Forward unchanged — no strip — so dev and prod hit the same
      // paths.
      '/api': {
        target: 'http://dev:3000',
        changeOrigin: true,
      },
    },
  },
});
