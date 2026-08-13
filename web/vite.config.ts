import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'node:path';

// API target is env-driven so a second Vite dev server can point at a second
// API instance — see `pnpm dev:second` in package.json. Used to test
// cross-machine WS fan-out: tab A on :5173 talks to API :3000, tab B on
// :5174 talks to API :3001, both share Postgres + the LISTEN/NOTIFY bus.
const API_HOST = process.env.API_HOST ?? 'dev';
const API_PORT = process.env.API_PORT ?? '3000';
const PORT = Number(process.env.PORT ?? 5173);

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: { '@': path.resolve(__dirname, 'src') },
  },
  build: {
    // Never inline font files. Vite's default 4 kB threshold base64s the
    // smaller unicode subsets (greek, cyrillic-ext, …) straight into the
    // stylesheet, which defeats the whole point of `unicode-range`: an inlined
    // face ships to every visitor whether or not they ever render a glyph from
    // it, and base64 adds ~33% on top. Returning undefined for everything else
    // leaves Vite's normal threshold in place for other assets.
    assetsInlineLimit: (filePath: string) =>
      /\.(woff2?|ttf|otf|eot)$/i.test(filePath) ? false : undefined,
  },
  server: {
    port: PORT,
    host: true,
    proxy: {
      // The api mounts everything under `/api/*` (and `/health` at root for
      // Fly). Forward unchanged — no strip — so dev and prod hit the same
      // paths. `ws: true` upgrades /api/ws through the proxy.
      '/api': {
        target: `http://${API_HOST}:${API_PORT}`,
        changeOrigin: true,
        ws: true,
      },
    },
  },
});
