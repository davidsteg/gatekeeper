/// <reference types="vitest/config" />
import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { fileURLToPath } from "node:url";
import { defineConfig } from "vite";

// The SPA is served by gatekeeper itself at /app (src/gatekeeper/api/web.py),
// under `script-src 'self'` with Trusted Types enforced: no inline script,
// no CDN, no eval. `npm run dev` proxies /api to a local gatekeeper (see
// AGENTS.md, "Frontend dev loop").
const backend = process.env.GATEKEEPER_DEV_BACKEND ?? "http://127.0.0.1:8080";

export default defineConfig({
  base: "/app/",
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: { "@": fileURLToPath(new URL("./src", import.meta.url)) },
  },
  build: {
    outDir: "dist",
    assetsDir: "assets",
    // The polyfill is bundled into the entry chunk either way; turning it
    // off keeps the build free of anything resembling an inline loader.
    modulePreload: { polyfill: false },
    // Never inline assets as data: URIs into JS -- keeps the CSP's
    // img-src/font-src honest about where bytes come from.
    assetsInlineLimit: 0,
    sourcemap: false,
    // One bundle for a LAN admin console is fine; Recharts is most of it.
    chunkSizeWarningLimit: 800,
  },
  server: {
    proxy: { "/api": { target: backend, changeOrigin: false } },
  },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./src/test/setup.ts"],
    css: false,
  },
});
