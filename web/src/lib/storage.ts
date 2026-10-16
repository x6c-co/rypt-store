// localStorage holds only per-viewer conveniences (theme, last tenant,
// dismissed notices). Storage can be unavailable or throw, so every access
// is guarded and the app works without it.

export function readStorage(key: string): string | null {
  try {
    return window.localStorage.getItem(key);
  } catch {
    return null;
  }
}

export function writeStorage(key: string, value: string | null): void {
  try {
    if (value === null) window.localStorage.removeItem(key);
    else window.localStorage.setItem(key, value);
  } catch {
    // Storage is a convenience; ignore failures.
  }
}

export const STORAGE_KEYS = {
  theme: "rypt-store:theme",
  lastTenant: "rypt-store:last-tenant",
  dismissLocalNotice: "rypt-store:dismiss-local-notice",
} as const;
