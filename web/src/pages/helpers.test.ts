import { describe, expect, it } from "vitest";
import { slugify, shortHash } from "../lib/format";
import { safeNext } from "./Login";
import { passwordProblem } from "./Setup";

describe("passwordProblem", () => {
  it("enforces length only (core 7.2)", () => {
    expect(passwordProblem("short")).toMatch(/12/);
    expect(passwordProblem("a".repeat(12))).toBeUndefined();
    expect(passwordProblem("a".repeat(1024))).toBeUndefined();
    expect(passwordProblem("a".repeat(1025))).toMatch(/1024/);
  });
});

describe("safeNext", () => {
  it("keeps in-app paths and drops everything else", () => {
    expect(safeNext(encodeURIComponent("/t/acme/p/api?x=1"))).toBe("/t/acme/p/api?x=1");
    expect(safeNext("//evil.example")).toBe("/");
    expect(safeNext("https://evil.example")).toBe("/");
    expect(safeNext("/login/mfa")).toBe("/");
    expect(safeNext(null)).toBe("/");
    expect(safeNext("%E0%A4%A")).toBe("/");
  });
});

describe("format", () => {
  it("slugifies names to the API pattern", () => {
    expect(slugify("Billing API (v2)")).toBe("billing-api-v2");
    expect(slugify("  --  ")).toBe("");
    expect(slugify("x".repeat(80)).length).toBe(64);
  });
  it("shortens hashes", () => {
    expect(shortHash("a".repeat(64), 4)).toBe("aaaa…aaaa");
    expect(shortHash("abc")).toBe("abc");
  });
});
