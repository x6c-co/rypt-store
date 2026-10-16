import { useSyncExternalStore } from "react";
import { ApiError, authRedirectFor, type AuthRedirect } from "./errors";
import type { Schemas } from "./client";

// Two app-wide signals derived from API errors: where authentication must
// send the user, and the key provider's state for the banner (core 5.6).

type AuthListener = (to: AuthRedirect) => void;
const authListeners = new Set<AuthListener>();

export function onAuthRedirect(fn: AuthListener): () => void {
  authListeners.add(fn);
  return () => authListeners.delete(fn);
}

export interface ProviderState {
  unavailable: boolean;
  quota: Schemas["ProviderQuota"] | null;
}

let providerState: ProviderState = { unavailable: false, quota: null };
const providerListeners = new Set<() => void>();

export function setProviderState(next: Partial<ProviderState>): void {
  const merged = { ...providerState, ...next };
  if (merged.unavailable === providerState.unavailable && merged.quota === providerState.quota) return;
  providerState = merged;
  for (const l of providerListeners) l();
}

export function useProviderState(): ProviderState {
  return useSyncExternalStore(
    (l) => {
      providerListeners.add(l);
      return () => providerListeners.delete(l);
    },
    () => providerState,
  );
}

/** Routes an error to the auth and provider signals; returns true if it was an auth error. */
export function handleGlobalError(err: unknown): boolean {
  if (err instanceof ApiError) {
    if (err.code === "key_provider_unavailable") setProviderState({ unavailable: true });
    if (err.code === "key_provider_quota" && !providerState.quota) setProviderState({ quota: { provider: "rypt" } as Schemas["ProviderQuota"] });
  }
  const to = authRedirectFor(err);
  if (to) {
    for (const l of authListeners) l(to);
    return true;
  }
  return false;
}
