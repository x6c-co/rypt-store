import { useQuery } from "@tanstack/react-query";
import { api, call, type Schemas } from "./client";

// Query keys and read hooks. Mutations live next to the components that
// use them and invalidate these keys.

export const qk = {
  setup: ["setup-status"] as const,
  me: ["me"] as const,
  sessions: ["me", "sessions"] as const,
  passkeys: ["me", "passkeys"] as const,
  projects: (t: string) => ["tenants", t, "projects"] as const,
  project: (t: string, p: string) => ["tenants", t, "projects", p] as const,
  compare: (t: string, p: string) => ["tenants", t, "projects", p, "compare"] as const,
  secrets: (t: string, p: string, e: string) => ["tenants", t, "projects", p, "env", e, "secrets"] as const,
  deleted: (t: string, p: string, e: string) => ["tenants", t, "projects", p, "env", e, "deleted"] as const,
  versions: (t: string, p: string, e: string, secret: string) => ["tenants", t, "projects", p, "env", e, "versions", secret] as const,
  tokens: (t: string, p: string) => ["tenants", t, "projects", p, "tokens"] as const,
  members: (t: string) => ["tenants", t, "members"] as const,
  invitations: (t: string) => ["tenants", t, "invitations"] as const,
  tenantAudit: (t: string) => ["tenants", t, "audit"] as const,
  instanceAudit: ["instance", "audit"] as const,
  instanceSettings: ["instance", "settings"] as const,
  instanceKeys: ["instance", "keys"] as const,
  migrations: ["instance", "migrations"] as const,
  migration: (id: string) => ["instance", "migrations", id] as const,
  users: ["instance", "users"] as const,
  allTenants: ["instance", "tenants"] as const,
};

/** Project-scoped keys share this prefix, for broad invalidation. */
export const projectPrefix = (t: string, p: string) => ["tenants", t, "projects", p] as const;

export function useSetupStatus() {
  return useQuery({
    queryKey: qk.setup,
    queryFn: () => call(api.GET("/api/v1/setup/status")),
    // Setup state changes only through the wizard, which refetches it; a
    // background refetch must not pull the wizard away from its last step.
    staleTime: Infinity,
    refetchOnWindowFocus: false,
  });
}

export function useMe(enabled = true) {
  return useQuery({
    queryKey: qk.me,
    queryFn: () => call(api.GET("/api/v1/me")),
    enabled,
    staleTime: 15_000,
    retry: false,
  });
}

export function useProjects(tenant: string | undefined) {
  return useQuery({
    queryKey: qk.projects(tenant ?? ""),
    queryFn: () => call(api.GET("/api/v1/tenants/{tenant}/projects", { params: { path: { tenant: tenant! } } })),
    enabled: !!tenant,
  });
}

export function useProject(tenant: string, project: string) {
  return useQuery({
    queryKey: qk.project(tenant, project),
    queryFn: () => call(api.GET("/api/v1/tenants/{tenant}/projects/{project}", { params: { path: { tenant, project } } })),
  });
}

export function useCompare(tenant: string, project: string) {
  return useQuery({
    queryKey: qk.compare(tenant, project),
    queryFn: () => call(api.GET("/api/v1/tenants/{tenant}/projects/{project}/compare", { params: { path: { tenant, project } } })),
  });
}

/** Lists every secret of an environment, following cursors. */
export function useSecrets(tenant: string, project: string, environment: string) {
  return useQuery({
    queryKey: qk.secrets(tenant, project, environment),
    queryFn: async () => {
      const all: Schemas["Secret"][] = [];
      let cursor: string | undefined;
      for (let i = 0; i < 100; i++) {
        const page = await call(
          api.GET("/api/v1/tenants/{tenant}/projects/{project}/environments/{environment}/secrets", {
            params: { path: { tenant, project, environment }, query: { limit: 500, cursor } },
          }),
        );
        all.push(...page.secrets);
        if (!page.next_cursor) break;
        cursor = page.next_cursor;
      }
      return all;
    },
  });
}

export function useDeletedSecrets(tenant: string, project: string, environment: string, enabled: boolean) {
  return useQuery({
    queryKey: qk.deleted(tenant, project, environment),
    queryFn: () =>
      call(api.GET("/api/v1/tenants/{tenant}/projects/{project}/environments/{environment}/secrets/deleted", { params: { path: { tenant, project, environment } } })),
    enabled,
  });
}

/** Versions of one secret, by secret ID. */
export function useVersions(tenant: string, project: string, environment: string, secret: string | null) {
  return useQuery({
    queryKey: qk.versions(tenant, project, environment, secret ?? ""),
    queryFn: () =>
      call(
        api.GET("/api/v1/tenants/{tenant}/projects/{project}/environments/{environment}/secrets/{secret}/versions", {
          params: { path: { tenant, project, environment, secret: secret! } },
        }),
      ),
    enabled: !!secret,
  });
}

export function useTokens(tenant: string, project: string, enabled = true) {
  return useQuery({
    queryKey: qk.tokens(tenant, project),
    queryFn: () => call(api.GET("/api/v1/tenants/{tenant}/projects/{project}/tokens", { params: { path: { tenant, project } } })),
    enabled,
  });
}

export function useMembers(tenant: string) {
  return useQuery({
    queryKey: qk.members(tenant),
    queryFn: () => call(api.GET("/api/v1/tenants/{tenant}/members", { params: { path: { tenant } } })),
    enabled: !!tenant,
  });
}

export function useInvitations(tenant: string, enabled: boolean) {
  return useQuery({
    queryKey: qk.invitations(tenant),
    queryFn: () => call(api.GET("/api/v1/tenants/{tenant}/invitations", { params: { path: { tenant } } })),
    enabled,
  });
}

export function useInstanceSettings(enabled = true) {
  return useQuery({
    queryKey: qk.instanceSettings,
    queryFn: () => call(api.GET("/api/v1/instance/settings")),
    enabled,
  });
}

export function useInstanceKeys(enabled = true) {
  return useQuery({
    queryKey: qk.instanceKeys,
    queryFn: () => call(api.GET("/api/v1/instance/keys")),
    enabled,
    retry: false,
  });
}

export function useMigrations(enabled = true) {
  return useQuery({
    queryKey: qk.migrations,
    queryFn: () => call(api.GET("/api/v1/instance/keys/migrations")),
    enabled,
    refetchInterval: (q) => (q.state.data?.migrations.some((m) => m.state === "queued" || m.state === "running") ? 2000 : false),
  });
}

/** Polls one migration while it runs. */
export function useMigration(id: string | null, enabled: boolean) {
  return useQuery({
    queryKey: qk.migration(id ?? ""),
    queryFn: () => call(api.GET("/api/v1/instance/keys/migrations/{id}", { params: { path: { id: id! } } })),
    enabled: !!id && enabled,
    retry: false,
    refetchInterval: (q) => (q.state.data && (q.state.data.state === "queued" || q.state.data.state === "running") ? 1500 : false),
  });
}

export function useInstanceUsers(enabled = true) {
  return useQuery({
    queryKey: qk.users,
    queryFn: () => call(api.GET("/api/v1/instance/users")),
    enabled,
  });
}

export function useAllTenants(enabled = true) {
  return useQuery({
    queryKey: qk.allTenants,
    queryFn: () => call(api.GET("/api/v1/tenants", { params: { query: { scope: "all" } } })),
    enabled,
  });
}

export function useSessions() {
  return useQuery({
    queryKey: qk.sessions,
    queryFn: () => call(api.GET("/api/v1/me/sessions")),
  });
}

export function usePasskeys() {
  return useQuery({
    queryKey: qk.passkeys,
    queryFn: () => call(api.GET("/api/v1/me/mfa/webauthn")),
  });
}
