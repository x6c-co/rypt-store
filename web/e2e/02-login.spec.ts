import { expect, test } from "@playwright/test";
import { freshCode, loadState, saveState, signIn, totp } from "./helpers";

test("login requires the TOTP second factor", async ({ page }) => {
  let s = loadState();

  // Unauthenticated visits go to the login page.
  await page.goto("/account");
  await expect(page).toHaveURL(/\/login\?next=/);

  // A wrong password is refused.
  await page.getByLabel("Email").fill(s.email);
  await page.getByLabel("Password", { exact: true }).fill("not the password at all");
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByRole("alert").first()).toBeVisible();

  // The right password leads to the MFA step; a wrong code is refused.
  await page.getByLabel("Password", { exact: true }).fill(s.password);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page).toHaveURL(/\/login\/mfa/);
  const { step } = await freshCode(s.totpSecret, s.lastStep);
  const wrong = totp(s.totpSecret, step + 1000);
  await page.getByLabel("Code from your authenticator app").fill(wrong);
  await page.getByRole("button", { name: "Verify" }).click();
  await expect(page.getByRole("alert").first()).toBeVisible();

  const { code, step: used } = await freshCode(s.totpSecret, s.lastStep);
  await page.getByLabel("Code from your authenticator app").fill(code);
  await page.getByRole("button", { name: "Verify" }).click();
  await expect(page.getByRole("heading", { level: 1, name: "Account" })).toBeVisible();
  s = { ...s, lastStep: used };
  saveState(s);

  // Sign out and back in through the helper.
  await page.getByRole("button", { name: "Sign out" }).click();
  await expect(page).toHaveURL(/\/login/);
  await signIn(page, s);
});
