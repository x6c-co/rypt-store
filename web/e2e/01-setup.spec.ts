import { expect, test } from "@playwright/test";
import { currentStep, saveState, totp, type E2EState } from "./helpers";

test("setup wizard creates the admin with TOTP and shows recovery codes", async ({ page }) => {
  const token = process.env.RYPT_STORE_E2E_SETUP_TOKEN;
  test.skip(!token, "RYPT_STORE_E2E_SETUP_TOKEN is not set");

  const state: E2EState = {
    email: "admin@example.com",
    password: "correct horse battery staple",
    organization: "Acme Agency",
    totpSecret: "",
    lastStep: 0,
  };

  await page.goto("/");
  await expect(page).toHaveURL(/\/setup$/);
  await expect(page.getByRole("heading", { name: "Set up rypt-store" })).toBeVisible();

  await page.getByLabel("Setup token").fill(token!);
  await page.getByLabel("Organization").fill(state.organization);
  await page.getByLabel("Your name").fill("Ada Admin");
  await page.getByLabel("Email").fill(state.email);
  await page.getByLabel("Password", { exact: true }).fill(state.password);
  await page.getByLabel("Confirm password").fill(state.password);
  await page.getByRole("button", { name: "Continue" }).click();

  // Two-factor step: read the secret shown for manual entry.
  const secretEl = page.getByTestId("totp-secret");
  await expect(secretEl).toBeVisible();
  await expect(page.getByRole("img", { name: /QR code/ })).toBeVisible();
  state.totpSecret = (await secretEl.textContent())!.trim();
  const step = currentStep();
  await page.getByLabel("Code from the app").fill(totp(state.totpSecret, step));
  state.lastStep = step;
  await page.getByRole("button", { name: "Finish setup" }).click();

  const codes = page.getByTestId("recovery-codes").getByRole("listitem");
  await expect(codes).toHaveCount(10);
  saveState(state);

  await page.getByRole("button", { name: "Continue to rypt-store" }).click();
  await expect(page.getByRole("heading", { level: 1, name: state.organization })).toBeVisible();
  // One tenant: no tenant switcher (core 6.3). Local provider notice is shown.
  await expect(page.getByRole("button", { name: /Switch tenant/ })).toHaveCount(0);
  await expect(page.getByText("Keys are stored on this server's disk.")).toBeVisible();
});
