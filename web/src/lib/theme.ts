import { readStorage, STORAGE_KEYS, writeStorage } from "./storage";

// The theme follows prefers-color-scheme unless the viewer overrides it
// (core 14.2). The override lives in localStorage.

export type ThemePreference = "system" | "light" | "dark";

export function getThemePreference(): ThemePreference {
  const v = readStorage(STORAGE_KEYS.theme);
  return v === "light" || v === "dark" ? v : "system";
}

export function applyTheme(pref: ThemePreference, root: HTMLElement = document.documentElement): void {
  if (pref === "system") delete root.dataset.theme;
  else root.dataset.theme = pref;
}

export function setThemePreference(pref: ThemePreference): void {
  writeStorage(STORAGE_KEYS.theme, pref === "system" ? null : pref);
  applyTheme(pref);
}

export function nextTheme(pref: ThemePreference): ThemePreference {
  return pref === "system" ? "light" : pref === "light" ? "dark" : "system";
}
