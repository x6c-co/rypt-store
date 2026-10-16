import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

const backend = process.env.RYPT_STORE_DEV_BACKEND ?? "https://localhost:8443";
const proxy = { target: backend, secure: false, changeOrigin: false };

export default defineConfig({
  plugins: [react()],
  build: {
    outDir: "dist",
    emptyOutDir: true,
    // The server's CSP is default-src 'self': no data: URIs, so every asset
    // (fonts included) must be emitted as a file.
    assetsInlineLimit: 0,
    sourcemap: false,
    chunkSizeWarningLimit: 800,
  },
  server: {
    proxy: {
      "/api": proxy,
      "/healthz": proxy,
      "/readyz": proxy,
    },
  },
  test: {
    environment: "jsdom",
    include: ["src/**/*.test.{ts,tsx}"],
    setupFiles: ["src/test/setup.ts"],
  },
});
