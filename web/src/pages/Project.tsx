import * as Menu from "@radix-ui/react-dropdown-menu";
import { useQueryClient } from "@tanstack/react-query";
import { useEffect, useMemo, useState } from "react";
import { Link, Navigate, NavLink, Outlet, useNavigate, useOutletContext, useParams, useSearchParams } from "react-router";
import { api, call, envPath, rawFetch, type Schemas } from "../api/client";
import { ApiError, errorMessage } from "../api/errors";
import { projectPrefix, qk, useCompare, useProject, useProjects, useSecrets, useSetupStatus } from "../api/queries";
import { CompareGrid, CompareLegend } from "../components/CompareGrid";
import { ConfirmByName, Modal } from "../components/Dialog";
import { actorName, HistoryDrawer, ImportDialog, RecentlyDeletedDialog, SecretEditor } from "../components/secrets";
import { useToast } from "../components/Toast";
import { Button, EmptyState, ErrorNotice, Loading, SelectField, TextField } from "../components/ui";
import { can, type Role } from "../lib/authz";
import { copyText, downloadText } from "../lib/browser";
import { formatDateTime, relativeTime, slugify } from "../lib/format";
import { useReveal } from "../lib/useReveal";
import { lastTenant, useCurrentMe, useRole } from "../session";

/** Opens the last tenant, or the first. */
export function HomePage() {
  const me = useCurrentMe();
  const tenants = me.tenants ?? [];
  const remembered = lastTenant();
  const pick = tenants.find((t) => t.slug === remembered) ?? tenants[0];
  if (pick) return <Navigate to={`/t/${pick.slug}`} replace />;
  return (
    <EmptyState action={me.user?.is_instance_admin ? <Link to="/settings">Create a tenant in Settings</Link> : undefined}>
      You do not belong to any tenant yet. Ask a tenant owner to invite you.
    </EmptyState>
  );
}

/** A tenant's projects. */
export function TenantHomePage() {
  const { tenant = "" } = useParams();
  const me = useCurrentMe();
  const role = useRole(tenant);
  const projects = useProjects(tenant);
  const [creating, setCreating] = useState(false);
  const t = me.tenants?.find((x) => x.slug === tenant);
  if (!t) {
    return <ErrorNotice error={new Error("You are not a member of this tenant, or it does not exist.")} />;
  }
  return (
    <>
      <div className="page-header">
        <h1>{t.name}</h1>
        {can(role, "project.manage") && (
          <Button variant="primary" onClick={() => setCreating(true)}>
            Create project
          </Button>
        )}
      </div>
      {projects.isPending ? (
        <Loading />
      ) : projects.isError ? (
        <ErrorNotice error={projects.error} />
      ) : projects.data.projects.length === 0 ? (
        <EmptyState
          action={
            can(role, "project.manage") ? (
              <Button variant="primary" onClick={() => setCreating(true)}>
                Create project
              </Button>
            ) : undefined
          }
        >
          No projects in {t.name} yet. {can(role, "project.manage") ? "Create one to start adding secrets." : "Ask an admin to create one."}
        </EmptyState>
      ) : (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Project</th>
                <th>Environments</th>
                <th>Key mode</th>
                <th>Created</th>
              </tr>
            </thead>
            <tbody>
              {projects.data.projects.map((p) => (
                <tr key={p.id}>
                  <td>
                    <Link to={`/t/${tenant}/p/${p.slug}`}>{p.name}</Link> <span className="mono small muted">{p.slug}</span>
                  </td>
                  <td>{p.environments.map((e) => e.name).join(", ")}</td>
                  <td className="mono">{p.key_mode}</td>
                  <td className="nowrap">{formatDateTime(p.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <CreateProjectDialog tenant={tenant} open={creating} onOpenChange={setCreating} />
    </>
  );
}

function CreateProjectDialog({ tenant, open, onOpenChange }: { tenant: string; open: boolean; onOpenChange(o: boolean): void }) {
  const qc = useQueryClient();
  const toast = useToast();
  const navigate = useNavigate();
  const status = useSetupStatus();
  const [name, setName] = useState("");
  const [slug, setSlug] = useState("");
  const [slugEdited, setSlugEdited] = useState(false);
  const [mode, setMode] = useState<"" | Schemas["KeyMode"]>("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const effectiveSlug = slugEdited ? slug : slugify(name);
  const defaultMode = status.data?.default_key_mode;

  return (
    <Modal
      open={open}
      onOpenChange={(o) => {
        if (!o) {
          setName("");
          setSlug("");
          setSlugEdited(false);
          setMode("");
          setError(null);
        }
        onOpenChange(o);
      }}
      title="Create project"
      description="New projects start with dev, staging, and prod environments."
      footer={
        <>
          <Button onClick={() => onOpenChange(false)}>Cancel</Button>
          <Button type="submit" form="create-project" variant="primary" busy={busy}>
            Create project
          </Button>
        </>
      }
    >
      <form
        id="create-project"
        className="stack"
        onSubmit={async (e) => {
          e.preventDefault();
          setBusy(true);
          setError(null);
          try {
            const p = await call(
              api.POST("/api/v1/tenants/{tenant}/projects", {
                params: { path: { tenant } },
                body: { name: name.trim(), slug: effectiveSlug || undefined, key_mode: mode || undefined },
              }),
            );
            toast.show(`Created project ${p.name}.`);
            await qc.invalidateQueries({ queryKey: qk.projects(tenant) });
            onOpenChange(false);
            navigate(`/t/${tenant}/p/${p.slug}`);
          } catch (err) {
            setError(err);
          } finally {
            setBusy(false);
          }
        }}
      >
        <TextField label="Name" value={name} onChange={(e) => setName(e.target.value)} required maxLength={128} autoFocus />
        <TextField
          label="Slug"
          hint="Used in URLs and the CLI."
          value={effectiveSlug}
          onChange={(e) => {
            setSlugEdited(true);
            setSlug(e.target.value);
          }}
          mono
          pattern="[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?"
          error={error instanceof ApiError ? error.fieldError("slug") : undefined}
        />
        <SelectField label="Key mode" value={mode} onChange={(e) => setMode(e.target.value as typeof mode)} hint={<KeyModeHint />}>
          <option value="">Instance default{defaultMode ? ` (${defaultMode})` : ""}</option>
          <option value="A">A — root key, then project key</option>
          <option value="B">B — project key</option>
          <option value="C">C — one key per secret version</option>
        </SelectField>
        <ErrorNotice error={error} />
      </form>
    </Modal>
  );
}

function KeyModeHint() {
  return <>The mode sets how many key provider operations reads cost. You can change it later in project settings.</>;
}

export interface ProjectContext {
  tenant: string;
  project: Schemas["Project"];
  role: Role | undefined;
  openAdd(environment?: string, name?: string): void;
}

export function useProjectContext(): ProjectContext {
  return useOutletContext<ProjectContext>();
}

/** Project header, Add secret, and tabs: Compare, one per environment, Settings. */
export function ProjectLayout() {
  const { tenant = "", project: slug = "" } = useParams();
  const role = useRole(tenant);
  const project = useProject(tenant, slug);
  const [editor, setEditor] = useState<{ mode: "create"; environment: string; name?: string } | null>(null);

  if (project.isPending) return <Loading />;
  if (project.isError) return <ErrorNotice error={project.error} />;
  const p = project.data;
  const envs = p.environments;
  const openAdd = (environment?: string, name?: string) => {
    const target = environment ?? envs[0]?.slug;
    if (target) setEditor({ mode: "create", environment: target, name });
  };
  const ctx: ProjectContext = { tenant, project: p, role, openAdd };
  const base = `/t/${tenant}/p/${p.slug}`;

  return (
    <>
      <div className="page-header">
        <div>
          <h1>{p.name}</h1>
          <span className="small muted">
            <span className="mono">{p.slug}</span> · key mode <span className="mono">{p.key_mode}</span>
          </span>
        </div>
        {can(role, "secret.write") && envs.length > 0 && (
          <Button variant="primary" onClick={() => openAdd()}>
            Add secret
          </Button>
        )}
      </div>
      <nav className="tabs" aria-label="Project views">
        <NavLink to={base} end className="tab">
          Compare
        </NavLink>
        {envs.map((e) => (
          <NavLink key={e.id} to={`${base}/e/${e.slug}`} className="tab">
            {e.name}
          </NavLink>
        ))}
        <NavLink to={`${base}/settings`} className="tab">
          Settings
        </NavLink>
      </nav>
      <Outlet context={ctx} />
      <SecretEditor tenant={tenant} project={p.slug} environments={envs} target={editor} onClose={() => setEditor(null)} />
    </>
  );
}

export function ComparePage() {
  const { tenant, project, role, openAdd } = useProjectContext();
  const navigate = useNavigate();
  const grid = useCompare(tenant, project.slug);
  if (grid.isPending) return <Loading />;
  if (grid.isError) return <ErrorNotice error={grid.error} />;
  if (project.environments.length === 0) {
    return <EmptyState>This project has no environments. Add one in Settings.</EmptyState>;
  }
  if (grid.data.rows.length === 0) {
    return (
      <EmptyState
        action={
          can(role, "secret.write") ? (
            <Button variant="primary" onClick={() => openAdd()}>
              Add secret
            </Button>
          ) : undefined
        }
      >
        No secrets in {project.name} yet. Add one, or open an environment to import a .env file.
      </EmptyState>
    );
  }
  return (
    <div className="stack">
      <CompareLegend />
      <CompareGrid
        grid={grid.data}
        canWrite={can(role, "secret.write")}
        onOpen={(env, name) => navigate(`/t/${tenant}/p/${project.slug}/e/${env}?secret=${encodeURIComponent(name)}`)}
        onAdd={(env, name) => openAdd(env, name)}
      />
    </div>
  );
}

/** One environment's secrets with masked values (feature 01 §6). */
export function EnvironmentPage() {
  const { tenant, project, role, openAdd } = useProjectContext();
  const { env = "" } = useParams();
  const [params] = useSearchParams();
  const focusName = params.get("secret");
  const qc = useQueryClient();
  const toast = useToast();
  const environment = project.environments.find((e) => e.slug === env);
  const secrets = useSecrets(tenant, project.slug, env);
  const { revealed, reveal, hide, hideAll } = useReveal();
  const [editing, setEditing] = useState<string | null>(null);
  const [history, setHistory] = useState<string | null>(null);
  const [deleting, setDeleting] = useState<string | null>(null);
  const [importing, setImporting] = useState(false);
  const [showDeleted, setShowDeleted] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  const canWrite = can(role, "secret.write");
  const editorTarget = useMemo(() => (editing ? { mode: "edit" as const, environment: env, name: editing } : null), [editing, env]);

  useEffect(() => hideAll(), [env, hideAll]);
  useEffect(() => {
    if (!focusName || !secrets.data) return;
    document.getElementById(`secret-${focusName}`)?.scrollIntoView({ block: "center" });
  }, [focusName, secrets.data]);

  if (!environment) return <ErrorNotice error={new Error(`There is no environment ${env} in ${project.name}.`)} />;
  const envName = environment.name;

  const fetchValue = async (name: string) =>
    (
      await call(
        api.GET("/api/v1/tenants/{tenant}/projects/{project}/environments/{environment}/secrets/{name}", {
          params: { path: { tenant, project: project.slug, environment: env, name } },
        }),
      )
    ).value;

  const act = async (key: string, fn: () => Promise<void>) => {
    setBusy(key);
    try {
      await fn();
    } catch (err) {
      toast.error(errorMessage(err));
    } finally {
      setBusy(null);
    }
  };

  const exportAs = (format: "dotenv" | "json") =>
    act(`export-${format}`, async () => {
      const res = await rawFetch(`${envPath(tenant, project.slug, env)}/secrets/export?format=${format}`);
      const text = await res.text();
      downloadText(format === "json" ? `${project.slug}-${env}.json` : `${project.slug}-${env}.env`, text, format === "json" ? "application/json" : "text/plain");
      toast.show(`Exported ${envName} as ${format === "json" ? "JSON" : ".env"}.`);
    });

  return (
    <div className="stack">
      <div className="row">
        {canWrite && (
          <Button variant="primary" onClick={() => openAdd(env)}>
            Add secret
          </Button>
        )}
        {canWrite && <Button onClick={() => setImporting(true)}>Import .env</Button>}
        <Menu.Root modal={false}>
          <Menu.Trigger asChild>
            <Button busy={busy?.startsWith("export") ?? false}>Export ▾</Button>
          </Menu.Trigger>
          <Menu.Portal>
            <Menu.Content className="menu" sideOffset={4} align="start">
              <Menu.Item className="menu-item" onSelect={() => void exportAs("dotenv")}>
                Export as .env
              </Menu.Item>
              <Menu.Item className="menu-item" onSelect={() => void exportAs("json")}>
                Export as JSON
              </Menu.Item>
            </Menu.Content>
          </Menu.Portal>
        </Menu.Root>
        <Button onClick={() => setShowDeleted(true)}>Recently deleted</Button>
      </div>

      {secrets.isPending ? (
        <Loading />
      ) : secrets.isError ? (
        <ErrorNotice error={secrets.error} />
      ) : secrets.data.length === 0 ? (
        <EmptyState
          action={
            canWrite ? (
              <div className="row" style={{ justifyContent: "center" }}>
                <Button variant="primary" onClick={() => openAdd(env)}>
                  Add secret
                </Button>
                <Button onClick={() => setImporting(true)}>Import .env</Button>
              </div>
            ) : undefined
          }
        >
          No secrets in {envName}. {canWrite ? "Add one, or import a .env file." : ""}
        </EmptyState>
      ) : (
        <div className="table-wrap">
          <table className="table">
            <caption className="visually-hidden">Secrets in {envName}</caption>
            <thead>
              <tr>
                <th scope="col">Name</th>
                <th scope="col">Value</th>
                <th scope="col">Version</th>
                <th scope="col">Updated</th>
                <th scope="col">Updated by</th>
                <th scope="col">
                  <span className="visually-hidden">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {secrets.data.map((s) => {
                const shown = s.name in revealed;
                return (
                  <tr key={s.id} id={`secret-${s.name}`} className={focusName === s.name ? "highlight" : undefined}>
                    <td className="mono">
                      {s.name}
                      {s.comment && <div className="secret-comment">{s.comment}</div>}
                    </td>
                    <td className="value-cell mono">
                      {shown ? (
                        <span className="value-revealed" data-testid={`value-${s.name}`}>
                          {revealed[s.name]}
                        </span>
                      ) : (
                        <span className="value-masked" aria-label="Hidden value">
                          ••••••••
                        </span>
                      )}
                    </td>
                    <td className="mono">v{s.version}</td>
                    <td className="nowrap" title={formatDateTime(s.updated_at)}>
                      {relativeTime(s.updated_at)}
                    </td>
                    <td>{actorName(s.updated_by)}</td>
                    <td className="actions">
                      <div className="row" style={{ justifyContent: "flex-end", flexWrap: "nowrap" }}>
                        {shown ? (
                          <Button size="sm" onClick={() => hide(s.name)} aria-label={`Hide ${s.name}`}>
                            Hide
                          </Button>
                        ) : (
                          <Button
                            size="sm"
                            busy={busy === `reveal-${s.name}`}
                            aria-label={`Reveal ${s.name}`}
                            onClick={() => act(`reveal-${s.name}`, async () => reveal(s.name, await fetchValue(s.name)))}
                          >
                            Reveal
                          </Button>
                        )}
                        <Button
                          size="sm"
                          busy={busy === `copy-${s.name}`}
                          aria-label={`Copy ${s.name}`}
                          onClick={() =>
                            act(`copy-${s.name}`, async () => {
                              await copyText(await fetchValue(s.name));
                              toast.show(`Copied ${s.name}.`);
                            })
                          }
                        >
                          Copy
                        </Button>
                        {canWrite && (
                          <Button size="sm" aria-label={`Edit ${s.name}`} onClick={() => setEditing(s.name)}>
                            Edit
                          </Button>
                        )}
                        <Button size="sm" aria-label={`History of ${s.name}`} onClick={() => setHistory(s.name)}>
                          History
                        </Button>
                        {canWrite && (
                          <Button size="sm" variant="ghost" aria-label={`Delete ${s.name}`} onClick={() => setDeleting(s.name)}>
                            Delete
                          </Button>
                        )}
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      <SecretEditor tenant={tenant} project={project.slug} environments={project.environments} target={editorTarget} onClose={() => setEditing(null)} />
      <HistoryDrawer tenant={tenant} project={project.slug} environment={env} name={history} canWrite={canWrite} onClose={() => setHistory(null)} />
      <ImportDialog tenant={tenant} project={project.slug} environment={env} envName={envName} open={importing} onOpenChange={setImporting} />
      <RecentlyDeletedDialog
        tenant={tenant}
        project={project.slug}
        environment={env}
        envName={envName}
        open={showDeleted}
        onOpenChange={setShowDeleted}
        canWrite={canWrite}
      />
      <ConfirmByName
        open={!!deleting}
        onOpenChange={(o) => !o && setDeleting(null)}
        title="Delete secret"
        description={`${deleting} moves to Recently deleted in ${envName} and can be restored until it is purged.`}
        name={deleting ?? ""}
        action="Delete secret"
        onConfirm={async () => {
          const name = deleting!;
          await call(
            api.DELETE("/api/v1/tenants/{tenant}/projects/{project}/environments/{environment}/secrets/{name}", {
              params: { path: { tenant, project: project.slug, environment: env, name } },
            }),
          );
          hide(name);
          toast.show(`Deleted ${name}.`);
          await qc.invalidateQueries({ queryKey: projectPrefix(tenant, project.slug) });
        }}
      />
    </div>
  );
}
