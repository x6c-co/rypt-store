import { beforeEach, describe, expect, it } from "vitest";
import { STORAGE_KEYS } from "./storage";
import { applyTheme, getThemePreference, nextTheme, setThemePreference } from "./theme";

describe("theme", () => {
  beforeEach(() => {
    localStorage.clear();
    delete document.documentElement.dataset.theme;
  });

  it("follows the system by default", () => {
    expect(getThemePreference()).toBe("system");
    applyTheme("system");
    expect(document.documentElement.dataset.theme).toBeUndefined();
  });

  it("persists an override and applies it to <html>", () => {
    setThemePreference("dark");
    expect(localStorage.getItem(STORAGE_KEYS.theme)).toBe("dark");
    expect(document.documentElement.dataset.theme).toBe("dark");
    expect(getThemePreference()).toBe("dark");
    setThemePreference("system");
    expect(localStorage.getItem(STORAGE_KEYS.theme)).toBeNull();
    expect(document.documentElement.dataset.theme).toBeUndefined();
  });

  it("ignores junk in storage", () => {
    localStorage.setItem(STORAGE_KEYS.theme, "purple");
    expect(getThemePreference()).toBe("system");
  });

  it("cycles system, light, dark", () => {
    expect(nextTheme("system")).toBe("light");
    expect(nextTheme("light")).toBe("dark");
    expect(nextTheme("dark")).toBe("system");
  });
});
