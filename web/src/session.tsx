import { useEffect } from "react";
import { useMatch } from "react-router";
import type { Schemas } from "./api/client";
import { useMe } from "./api/queries";
import { setProviderState } from "./api/events";
import type { Role } from "./lib/authz";
import { readStorage, STORAGE_KEYS, writeStorage } from "./lib/storage";

/** The signed-in user's /me; only call under RequireAuth, where it is loaded. */
export function useCurrentMe(): Schemas["Me"] {
  const { data } = useMe();
  if (!data) throw new Error("useCurrentMe outside RequireAuth");
  return data;
}

/** The tenant slug from the URL, or null outside tenant routes. */
export function useTenantSlug(): string | null {
  const m = useMatch("/t/:tenant/*");
  return m?.params.tenant ?? null;
}

export function useTenant(slug: string | null): Schemas["Tenant"] | undefined {
  const me = useCurrentMe();
  return me.tenants?.find((t) => t.slug === slug);
}

export function useRole(slug: string | null): Role | undefined {
  return useTenant(slug)?.role as Role | undefined;
}

export function lastTenant(): string | null {
  return readStorage(STORAGE_KEYS.lastTenant);
}

/** Remembers the tenant in view so the app reopens on it. */
export function useRememberTenant(slug: string | null) {
  useEffect(() => {
    if (slug) writeStorage(STORAGE_KEYS.lastTenant, slug);
  }, [slug]);
}

/** Copies /me notices into the provider banner state. */
export function useSyncNotices(me: Schemas["Me"] | undefined) {
  useEffect(() => {
    if (!me?.notices) return;
    setProviderState({ unavailable: !!me.notices.provider_unavailable, quota: me.notices.provider_quota ?? null });
  }, [me?.notices]);
}
