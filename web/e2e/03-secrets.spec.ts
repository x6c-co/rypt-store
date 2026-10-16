import { expect, test, type Page } from "@playwright/test";
import { loadState, signIn } from "./helpers";

async function addSecret(page: Page, name: string, value: string, env?: string) {
  await page.getByRole("button", { name: "Add secret" }).first().click();
  const dialog = page.getByRole("dialog", { name: "Add secret" });
  await dialog.getByLabel("Name").fill(name);
  if (env) await dialog.getByLabel("Environment").selectOption(env);
  await dialog.getByLabel("Value").fill(value);
  await dialog.getByRole("button", { name: "Add secret" }).click();
  await expect(dialog).toBeHidden();
}

test("add, reveal, edit, history, restore, import, and compare", async ({ page }) => {
  await signIn(page, loadState());

  // Create a project; it opens on the Compare grid.
  await page.getByRole("button", { name: "Create project" }).first().click();
  const create = page.getByRole("dialog", { name: "Create project" });
  await create.getByLabel("Name").fill("Payments API");
  await create.getByRole("button", { name: "Create project" }).click();
  await expect(page.getByRole("heading", { level: 1, name: "Payments API" })).toBeVisible();
  await expect(page.getByText(/No secrets in Payments API yet/)).toBeVisible();

  // Add a secret in dev.
  await page.getByRole("navigation", { name: "Project views" }).getByRole("link", { name: "dev" }).click();
  await expect(page.getByText("No secrets in dev.")).toBeVisible();
  await addSecret(page, "DATABASE_URL", "postgres://dev-one");
  const row = page.getByRole("row", { name: /DATABASE_URL/ });
  await expect(row.getByText("v1")).toBeVisible();

  // Reveal shows the value; Hide masks it again.
  await row.getByRole("button", { name: "Reveal DATABASE_URL" }).click();
  await expect(page.getByTestId("value-DATABASE_URL")).toHaveText("postgres://dev-one");
  await row.getByRole("button", { name: "Hide DATABASE_URL" }).click();
  await expect(page.getByTestId("value-DATABASE_URL")).toHaveCount(0);

  // Edit creates version 2.
  await row.getByRole("button", { name: "Edit DATABASE_URL" }).click();
  const edit = page.getByRole("dialog", { name: "Edit DATABASE_URL" });
  await expect(edit.getByLabel("Value")).toHaveValue("postgres://dev-one");
  await edit.getByLabel("Value").fill("postgres://dev-two");
  await edit.getByRole("button", { name: "Save" }).click();
  await expect(edit).toBeHidden();
  await expect(row.getByText("v2")).toBeVisible();

  // History lists both versions; reveal version 1, then restore it.
  await row.getByRole("button", { name: "History of DATABASE_URL" }).click();
  const drawer = page.getByRole("dialog", { name: "History of DATABASE_URL" });
  await expect(drawer.getByText("Version 2")).toBeVisible();
  await drawer.getByRole("button", { name: "Reveal version 1" }).click();
  await expect(drawer.getByLabel("Value of version 1")).toHaveText("postgres://dev-one");
  await drawer.getByRole("button", { name: "Restore version 1" }).click();
  const confirm = page.getByRole("dialog", { name: "Restore version 1?" });
  await confirm.getByRole("button", { name: "Restore version 1" }).click();
  await expect(drawer.getByText("Version 3")).toBeVisible();
  await expect(drawer.getByText("restored from version 1")).toBeVisible();
  await drawer.getByRole("button", { name: "Close" }).click();
  await row.getByRole("button", { name: "Reveal DATABASE_URL" }).click();
  await expect(page.getByTestId("value-DATABASE_URL")).toHaveText("postgres://dev-one");

  // prod: same DATABASE_URL as dev, and a prod-only secret.
  await addSecret(page, "DATABASE_URL", "postgres://dev-one", "prod");
  await addSecret(page, "LOG_LEVEL", "warn", "prod");

  // Import a .env into staging.
  await page.getByRole("navigation", { name: "Project views" }).getByRole("link", { name: "staging" }).click();
  await page.getByRole("button", { name: "Import .env" }).first().click();
  const imp = page.getByRole("dialog", { name: "Import .env into staging" });
  await imp.getByLabel("Or paste the contents").fill('# staging\nexport DATABASE_URL="postgres://staging"\nLOG_LEVEL=warn\n1BAD=x\n');
  await expect(imp.getByText(/2 secrets found, 1 line will be rejected/)).toBeVisible();
  await imp.getByRole("button", { name: "Import" }).click();
  await expect(imp.getByText("Created (2)")).toBeVisible();
  await expect(imp.getByText(/Line 4/)).toBeVisible();
  await imp.getByRole("button", { name: "Done" }).click();
  await expect(page.getByRole("row", { name: /LOG_LEVEL/ })).toBeVisible();

  // Compare: prod repeats dev's DATABASE_URL; staging differs. LOG_LEVEL is
  // missing in dev and equal between staging and prod.
  await page.getByRole("navigation", { name: "Project views" }).getByRole("link", { name: "Compare" }).click();
  await expect(page.getByRole("button", { name: "DATABASE_URL in prod has the same value as in dev" })).toBeVisible();
  await expect(page.getByRole("button", { name: "DATABASE_URL in staging differs from every other environment" })).toBeVisible();
  await expect(page.getByRole("button", { name: /LOG_LEVEL is missing in dev\. Add to dev/ })).toBeVisible();
  await expect(page.getByRole("button", { name: "LOG_LEVEL in prod has the same value as in staging" })).toBeVisible();
  // No value ever reaches the grid.
  await expect(page.getByText("postgres://")).toHaveCount(0);

  // Clicking a cell opens that environment with the secret highlighted.
  await page.getByRole("button", { name: "DATABASE_URL in prod has the same value as in dev" }).click();
  await expect(page).toHaveURL(/\/e\/prod\?secret=DATABASE_URL/);
});
