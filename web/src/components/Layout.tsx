import * as Menu from "@radix-ui/react-dropdown-menu";
import { useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { Link, NavLink, Outlet, useLocation, useNavigate } from "react-router";
import { api, call } from "../api/client";
import { useProviderState } from "../api/events";
import { useProjects } from "../api/queries";
import { can } from "../lib/authz";
import { formatDateTime } from "../lib/format";
import { readStorage, STORAGE_KEYS, writeStorage } from "../lib/storage";
import { getThemePreference, nextTheme, setThemePreference, type ThemePreference } from "../lib/theme";
import { lastTenant, useCurrentMe, useRememberTenant, useRole, useTenantSlug } from "../session";
import { Button } from "./ui";

export const LOCAL_NOTICE = "Keys are stored on this server's disk. Move them to rypt.dev with ";
export const LOCAL_NOTICE_COMMAND = "rypt-store keys migrate --to rypt";

export function LocalProviderText() {
  return (
    <>
      {LOCAL_NOTICE}
      <code>{LOCAL_NOTICE_COMMAND}</code>.
    </>
  );
}

function ThemeToggle() {
  const [pref, setPref] = useState<ThemePreference>(getThemePreference);
  const label = pref === "system" ? "Theme: system" : pref === "light" ? "Theme: light" : "Theme: dark";
  return (
    <Button
      variant="ghost"
      size="sm"
      onClick={() => {
        const n = nextTheme(pref);
        setThemePreference(n);
        setPref(n);
      }}
      aria-label={`${label}. Change theme`}
    >
      {label}
    </Button>
  );
}

function TenantSwitcher({ current }: { current: string | null }) {
  const me = useCurrentMe();
  const navigate = useNavigate();
  const tenants = me.tenants ?? [];
  // The switcher appears only with two or more tenants (core 6.3).
  if (tenants.length < 2) return null;
  const active = tenants.find((t) => t.slug === current);
  return (
    <Menu.Root modal={false}>
      <Menu.Trigger asChild>
        <Button size="sm" aria-label={`Tenant: ${active?.name ?? "choose"}. Switch tenant`}>
          {active?.name ?? "Choose tenant"} ▾
        </Button>
      </Menu.Trigger>
      <Menu.Portal>
        <Menu.Content className="menu" align="start" sideOffset={4}>
          <Menu.Label className="menu-label">Switch tenant</Menu.Label>
          {tenants.map((t) => (
            <Menu.Item key={t.id} className="menu-item" onSelect={() => navigate(`/t/${t.slug}`)}>
              {t.name}
              {t.slug === current && <span className="small muted">(current)</span>}
            </Menu.Item>
          ))}
        </Menu.Content>
      </Menu.Portal>
    </Menu.Root>
  );
}

function ProjectNav({ tenant }: { tenant: string }) {
  const projects = useProjects(tenant);
  return (
    <nav className="nav-section" aria-label="Projects">
      <div className="nav-heading">Projects</div>
      {projects.data?.projects.map((p) => (
        <NavLink key={p.id} to={`/t/${tenant}/p/${p.slug}`} className="nav-link">
          {p.name}
        </NavLink>
      ))}
      {projects.data && projects.data.projects.length === 0 && <span className="small muted nav-link">No projects yet.</span>}
      <NavLink to={`/t/${tenant}`} end className="nav-link small muted">
        All projects
      </NavLink>
    </nav>
  );
}

function SidebarNotices() {
  const me = useCurrentMe();
  const [dismissed, setDismissed] = useState(() => readStorage(STORAGE_KEYS.dismissLocalNotice) === "1");
  const n = me.notices;
  return (
    <>
      {n?.self_signed_tls && (
        <div className="notice notice-brass small" role="note">
          This server uses a self-signed TLS certificate. Configure ACME or certificate files for production.
        </div>
      )}
      {n?.local_provider && !dismissed && (
        <div className="notice notice-brass small" role="note">
          <LocalProviderText />
          <div className="notice-actions">
            <Button
              variant="link"
              onClick={() => {
                writeStorage(STORAGE_KEYS.dismissLocalNotice, "1");
                setDismissed(true);
              }}
            >
              Dismiss
            </Button>
          </div>
        </div>
      )}
    </>
  );
}

function ProviderBanner() {
  const st = useProviderState();
  if (st.quota) {
    return (
      <div className="notice notice-crit" role="alert">
        <strong>rypt.dev quota reached. </strong>
        The rypt.dev monthly operation quota{st.quota.cap ? ` of ${st.quota.cap.toLocaleString()} operations` : ""} is used up, so secret values cannot be
        read or written{st.quota.resets_at ? ` until it resets on ${formatDateTime(st.quota.resets_at)}` : " until it resets"}.
      </div>
    );
  }
  if (st.unavailable) {
    return (
      <div className="notice notice-crit" role="alert">
        <strong>Key provider unreachable. </strong>
        rypt.dev cannot be reached, so some secret values cannot be read or written right now.
      </div>
    );
  }
  return null;
}

export function AppShell() {
  const me = useCurrentMe();
  const urlTenant = useTenantSlug();
  const tenants = me.tenants ?? [];
  const remembered = lastTenant();
  const tenant = urlTenant ?? (tenants.some((t) => t.slug === remembered) ? remembered : (tenants[0]?.slug ?? null));
  const role = useRole(tenant);
  const [open, setOpen] = useState(false);
  const loc = useLocation();
  const navigate = useNavigate();
  const qc = useQueryClient();
  useRememberTenant(urlTenant);

  useEffect(() => setOpen(false), [loc.pathname]);

  const signOut = async () => {
    try {
      await call(api.POST("/api/v1/auth/logout"));
    } finally {
      qc.clear();
      navigate("/login", { replace: true });
    }
  };

  return (
    <div className="shell">
      <header className="topbar">
        <Link to="/" className="brand">
          rypt-store
        </Link>
        <Button size="sm" aria-expanded={open} aria-controls="sidebar" onClick={() => setOpen((o) => !o)}>
          {open ? "Close menu" : "Menu"}
        </Button>
      </header>
      <aside id="sidebar" className={`sidebar${open ? " open" : ""}`}>
        <Link to="/" className="brand">
          rypt-store
        </Link>
        <TenantSwitcher current={tenant} />
        {tenant && <ProjectNav tenant={tenant} />}
        {tenant && (
          <nav className="nav-section" aria-label="Tenant">
            <div className="nav-heading">Tenant</div>
            {can(role, "audit.read") && (
              <NavLink to={`/t/${tenant}/audit`} className="nav-link">
                Audit log
              </NavLink>
            )}
            <NavLink to={`/t/${tenant}/members`} className="nav-link">
              Members
            </NavLink>
          </nav>
        )}
        <nav className="nav-section" aria-label="Account and settings">
          {me.user?.is_instance_admin && (
            <NavLink to="/settings" className="nav-link">
              Settings
            </NavLink>
          )}
          <NavLink to="/account" className="nav-link">
            Account
          </NavLink>
        </nav>
        <SidebarNotices />
        <div className="spacer" />
        <div className="stack-sm">
          <span className="small muted" title={me.user?.email}>
            {me.user?.display_name}
          </span>
          <div className="row">
            <ThemeToggle />
            <Button variant="ghost" size="sm" onClick={signOut}>
              Sign out
            </Button>
          </div>
        </div>
      </aside>
      <main className="main" id="main">
        <ProviderBanner />
        <Outlet />
      </main>
    </div>
  );
}
