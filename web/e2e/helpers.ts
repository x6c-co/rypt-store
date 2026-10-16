import { createHmac } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { expect, type Page } from "@playwright/test";

const STATE_FILE = join(dirname(fileURLToPath(import.meta.url)), ".state", "state.json");

export interface E2EState {
  email: string;
  password: string;
  organization: string;
  totpSecret: string;
  /** The last TOTP time step used, so a code is never replayed. */
  lastStep: number;
}

export function saveState(s: E2EState): void {
  mkdirSync(dirname(STATE_FILE), { recursive: true });
  writeFileSync(STATE_FILE, JSON.stringify(s, null, 2));
}

export function loadState(): E2EState {
  return JSON.parse(readFileSync(STATE_FILE, "utf8")) as E2EState;
}

/** Decodes RFC 4648 base32 (the TOTP secret alphabet). */
export function base32Decode(s: string): Buffer {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const clean = s.toUpperCase().replace(/=+$/g, "").replace(/\s+/g, "");
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of clean) {
    const idx = alphabet.indexOf(ch);
    if (idx < 0) throw new Error(`invalid base32 character ${ch}`);
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

/** RFC 6238 TOTP: SHA-1, 6 digits, 30-second steps. */
export function totp(secret: string, step: number): string {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(step));
  const mac = createHmac("sha1", base32Decode(secret)).update(counter).digest();
  const offset = mac[mac.length - 1]! & 0x0f;
  const bin = ((mac[offset]! & 0x7f) << 24) | (mac[offset + 1]! << 16) | (mac[offset + 2]! << 8) | mac[offset + 3]!;
  return String(bin % 1_000_000).padStart(6, "0");
}

export function currentStep(now = Date.now()): number {
  return Math.floor(now / 1000 / 30);
}

/** A code from a step after lastStep, waiting for the next step if needed. */
export async function freshCode(secret: string, lastStep: number): Promise<{ code: string; step: number }> {
  let step = currentStep();
  if (step <= lastStep) {
    const wait = (lastStep + 1) * 30_000 - Date.now() + 250;
    await new Promise((r) => setTimeout(r, Math.max(wait, 0)));
    step = currentStep();
  }
  return { code: totp(secret, step), step };
}

/** Signs in with password and TOTP; returns the updated state. */
export async function signIn(page: Page, s: E2EState): Promise<E2EState> {
  await page.goto("/login");
  await page.getByLabel("Email").fill(s.email);
  await page.getByLabel("Password", { exact: true }).fill(s.password);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page).toHaveURL(/\/login\/mfa/);
  const { code, step } = await freshCode(s.totpSecret, s.lastStep);
  await page.getByLabel("Code from your authenticator app").fill(code);
  await page.getByRole("button", { name: "Verify" }).click();
  await expect(page.getByRole("heading", { level: 1, name: s.organization })).toBeVisible();
  const next = { ...s, lastStep: step };
  saveState(next);
  return next;
}
