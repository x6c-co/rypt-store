import { defineConfig, devices } from "@playwright/test";

// The specs run in order against one fresh instance: 01 completes setup,
// later files sign in with the stored credentials. Start the server first
// and pass its setup token in RYPT_STORE_E2E_SETUP_TOKEN.
export default defineConfig({
  testDir: "e2e",
  fullyParallel: false,
  workers: 1,
  retries: 0,
  timeout: 120_000,
  expect: { timeout: 10_000 },
  reporter: [["list"]],
  use: {
    baseURL: process.env.RYPT_STORE_E2E_URL ?? "https://localhost:8443",
    ignoreHTTPSErrors: true,
    trace: "retain-on-failure",
    permissions: ["clipboard-read", "clipboard-write"],
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
});
