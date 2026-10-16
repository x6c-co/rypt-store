import { useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { useNavigate } from "react-router";
import { api, call, type Schemas } from "../api/client";
import { ApiError } from "../api/errors";
import { projectPrefix, qk, useInstanceKeys, useMigration, useTokens } from "../api/queries";
import { ConfirmByName, Modal } from "../components/Dialog";
import { useToast } from "../components/Toast";
import { Badge, Button, CopyField, ErrorNotice, Loading, Notice, Progress, SelectField, TextField } from "../components/ui";
import { can } from "../lib/authz";
import { formatDate, formatDateTime, relativeTime, slugify } from "../lib/format";
import { useCurrentMe } from "../session";
import { useProjectContext } from "./Project";

/** Per-read costs of each mode (core 5.2, feature 01 3.2), when the server's table is not available. */
export const STATIC_MODE_COSTS: Schemas["ModeCost"][] = [
  { mode: "A", chain: "provider → root key → project key → data key → value", read_cost: "One unwrap per root key cache miss", write_cost: "None" },
  { mode: "B", chain: "provider → project key → data key → value", read_cost: "One unwrap per project per project key cache miss", write_cost: "None" },
  {
    mode: "C",
    chain: "provider → data key → value",
    read_cost: "One unwrap per secret version per data key cache miss",
    write_cost: "One wrap per secret write",
  },
];

export function ProjectSettingsPage() {
  const { tenant, project, role } = useProjectContext();
  return (
    <div className="stack">
      <GeneralSection />
      <EnvironmentsSection />
      {can(role, "token.manage") && <TokensSection />}
      <KeyModeSection />
      {can(role, "project.manage") && <DangerSection key={`${tenant}/${project.slug}`} />}
    </div>
  );
}

function GeneralSection() {
  const { tenant, project, role } = useProjectContext();
  const qc = useQueryClient();
  const toast = useToast();
  const navigate = useNavigate();
  const [open, setOpen] = useState(false);
  const [name, setName] = useState(project.name);
  const [slug, setSlug] = useState(project.slug);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  return (
    <section className="panel stack-sm" aria-labelledby="general-h">
      <div className="row-between">
        <h2 id="general-h">Project</h2>
        {can(role, "project.manage") && (
          <Button
            size="sm"
            onClick={() => {
              setName(project.name);
              setSlug(project.slug);
              setOpen(true);
            }}
          >
            Rename project
          </Button>
        )}
      </div>
      <p className="muted small">
        Name {project.name} · slug <span className="mono">{project.slug}</span> · created {formatDate(project.created_at)} · ID{" "}
        <span className="mono">{project.id}</span>
      </p>
      <Modal
        open={open}
        onOpenChange={setOpen}
        title="Rename project"
        footer={
          <>
            <Button onClick={() => setOpen(false)}>Cancel</Button>
            <Button type="submit" form="rename-project" variant="primary" busy={busy}>
              Rename project
            </Button>
          </>
        }
      >
        <form
          id="rename-project"
          className="stack"
          onSubmit={async (e) => {
            e.preventDefault();
            setBusy(true);
            setError(null);
            try {
              const p = await call(
                api.PATCH("/api/v1/tenants/{tenant}/projects/{project}", { params: { path: { tenant, project: project.slug } }, body: { name: name.trim(), slug } }),
              );
              toast.show(`Renamed project to ${p.name}.`);
              await qc.invalidateQueries({ queryKey: qk.projects(tenant) });
              setOpen(false);
              if (p.slug !== project.slug) navigate(`/t/${tenant}/p/${p.slug}/settings`, { replace: true });
              else await qc.invalidateQueries({ queryKey: projectPrefix(tenant, project.slug) });
            } catch (err) {
              setError(err);
            } finally {
              setBusy(false);
            }
          }}
        >
          <TextField label="Name" value={name} onChange={(e) => setName(e.target.value)} required maxLength={128} />
          <TextField
            label="Slug"
            hint="Changing the slug changes URLs and CLI context files."
            value={slug}
            onChange={(e) => setSlug(e.target.value)}
            required
            mono
            error={error instanceof ApiError ? error.fieldError("slug") : undefined}
          />
          <ErrorNotice error={error} />
        </form>
      </Modal>
    </section>
  );
}

function EnvironmentsSection() {
  const { tenant, project, role } = useProjectContext();
  const qc = useQueryClient();
  const toast = useToast();
  const manage = can(role, "project.manage");
  const [edit, setEdit] = useState<Schemas["Environment"] | "new" | null>(null);
  const [del, setDel] = useState<Schemas["Environment"] | null>(null);
  const [name, setName] = useState("");
  const [slug, setSlug] = useState("");
  const [position, setPosition] = useState("0");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const refresh = () => qc.invalidateQueries({ queryKey: projectPrefix(tenant, project.slug) });

  const openEdit = (e: Schemas["Environment"] | "new") => {
    setError(null);
    if (e === "new") {
      setName("");
      setSlug("");
      setPosition(String(project.environments.length));
    } else {
      setName(e.name);
      setSlug(e.slug);
      setPosition(String(e.position));
    }
    setEdit(e);
  };

  return (
    <section className="panel stack-sm" aria-labelledby="envs-h">
      <div className="row-between">
        <h2 id="envs-h">Environments</h2>
        {manage && (
          <Button size="sm" onClick={() => openEdit("new")}>
            Add environment
          </Button>
        )}
      </div>
      {project.environments.length === 0 ? (
        <p className="muted">No environments. Add one to start adding secrets.</p>
      ) : (
        <div className="table-wrap">
          <table className="table dense">
            <thead>
              <tr>
                <th>Name</th>
                <th>Slug</th>
                <th>Position</th>
                {manage && (
                  <th>
                    <span className="visually-hidden">Actions</span>
                  </th>
                )}
              </tr>
            </thead>
            <tbody>
              {project.environments.map((e) => (
                <tr key={e.id}>
                  <td>{e.name}</td>
                  <td className="mono">{e.slug}</td>
                  <td>{e.position}</td>
                  {manage && (
                    <td className="actions">
                      <Button size="sm" onClick={() => openEdit(e)} aria-label={`Rename ${e.name}`}>
                        Rename
                      </Button>{" "}
                      <Button size="sm" variant="ghost" onClick={() => setDel(e)} aria-label={`Delete ${e.name}`}>
                        Delete
                      </Button>
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <Modal
        open={edit !== null}
        onOpenChange={(o) => !o && setEdit(null)}
        title={edit === "new" ? "Add environment" : "Rename environment"}
        footer={
          <>
            <Button onClick={() => setEdit(null)}>Cancel</Button>
            <Button type="submit" form="env-form" variant="primary" busy={busy}>
              {edit === "new" ? "Add environment" : "Rename environment"}
            </Button>
          </>
        }
      >
        <form
          id="env-form"
          className="stack"
          onSubmit={async (ev) => {
            ev.preventDefault();
            setBusy(true);
            setError(null);
            try {
              const pos = Number(position) || 0;
              if (edit === "new") {
                const e = await call(
                  api.POST("/api/v1/tenants/{tenant}/projects/{project}/environments", {
                    params: { path: { tenant, project: project.slug } },
                    body: { name: name.trim(), slug: slug || slugify(name) || undefined, position: pos },
                  }),
                );
                toast.show(`Added environment ${e.name}.`);
              } else if (edit) {
                const e = await call(
                  api.PATCH("/api/v1/tenants/{tenant}/projects/{project}/environments/{environment}", {
                    params: { path: { tenant, project: project.slug, environment: edit.slug } },
                    body: { name: name.trim(), slug, position: pos },
                  }),
                );
                toast.show(`Renamed environment to ${e.name}.`);
              }
              await refresh();
              setEdit(null);
            } catch (err) {
              setError(err);
            } finally {
              setBusy(false);
            }
          }}
        >
          <TextField label="Name" value={name} onChange={(e) => setName(e.target.value)} required maxLength={64} autoFocus />
          <TextField
            label="Slug"
            value={edit === "new" && !slug ? slugify(name) : slug}
            onChange={(e) => setSlug(e.target.value)}
            mono
            error={error instanceof ApiError ? error.fieldError("slug") : undefined}
          />
          <TextField label="Position" hint="Tabs and Compare columns are ordered by position." type="number" value={position} onChange={(e) => setPosition(e.target.value)} />
          <ErrorNotice error={error} />
        </form>
      </Modal>
      <ConfirmByName
        open={!!del}
        onOpenChange={(o) => !o && setDel(null)}
        title="Delete environment"
        description={`Deleting ${del?.name} deletes every secret in it, with all versions. This cannot be undone.`}
        name={del?.name ?? ""}
        action="Delete environment"
        onConfirm={async () => {
          await call(
            api.DELETE("/api/v1/tenants/{tenant}/projects/{project}/environments/{environment}", {
              params: { path: { tenant, project: project.slug, environment: del!.slug } },
            }),
          );
          toast.show(`Deleted environment ${del!.name}.`);
          await refresh();
        }}
      />
    </section>
  );
}

function defaultExpiry(days: number): string {
  const d = new Date(Date.now() + days * 86400_000);
  return d.toISOString().slice(0, 10);
}

function TokensSection() {
  const { tenant, project } = useProjectContext();
  const qc = useQueryClient();
  const toast = useToast();
  const tokens = useTokens(tenant, project.slug);
  const [creating, setCreating] = useState(false);
  const [created, setCreated] = useState<{ name: string; secret: string } | null>(null);
  const [revoke, setRevoke] = useState<Schemas["ServiceToken"] | null>(null);
  const [name, setName] = useState("");
  const [envs, setEnvs] = useState<string[]>([]);
  const [permission, setPermission] = useState<Schemas["TokenPermission"]>("read");
  const [expires, setExpires] = useState(defaultExpiry(90));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const envName = (slug: string) => project.environments.find((e) => e.slug === slug)?.name ?? slug;

  const resetForm = () => {
    setName("");
    setEnvs([]);
    setPermission("read");
    setExpires(defaultExpiry(90));
    setError(null);
    setCreated(null);
  };

  return (
    <section className="panel stack-sm" aria-labelledby="tokens-h">
      <div className="row-between">
        <h2 id="tokens-h">Service tokens</h2>
        <Button
          size="sm"
          onClick={() => {
            resetForm();
            setCreating(true);
          }}
        >
          Create token
        </Button>
      </div>
      <p className="muted small">
        Service tokens let CI and servers read this project's secrets with <code>RYPT_STORE_TOKEN</code>.
      </p>
      {tokens.isPending ? (
        <Loading />
      ) : tokens.isError ? (
        <ErrorNotice error={tokens.error} />
      ) : tokens.data.tokens.length === 0 ? (
        <p className="muted">No service tokens. Create one for a CI job or a server.</p>
      ) : (
        <div className="table-wrap">
          <table className="table dense">
            <thead>
              <tr>
                <th>Label</th>
                <th>Prefix</th>
                <th>Environments</th>
                <th>Permission</th>
                <th>Expires</th>
                <th>Last used</th>
                <th>
                  <span className="visually-hidden">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {tokens.data.tokens.map((t) => {
                const expired = new Date(t.expires_at).getTime() < Date.now();
                return (
                  <tr key={t.id}>
                    <td>{t.name}</td>
                    <td className="mono">{t.prefix}…</td>
                    <td>{t.environments.map(envName).join(", ")}</td>
                    <td>{t.permission === "read_write" ? "Read and write" : "Read"}</td>
                    <td className="nowrap">{formatDate(t.expires_at)}</td>
                    <td className="nowrap">{relativeTime(t.last_used_at)}</td>
                    <td className="actions">
                      {t.revoked_at ? (
                        <Badge>Revoked</Badge>
                      ) : expired ? (
                        <Badge tone="brass">Expired</Badge>
                      ) : (
                        <Button size="sm" variant="ghost" onClick={() => setRevoke(t)} aria-label={`Revoke ${t.name}`}>
                          Revoke
                        </Button>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      <Modal
        open={creating}
        onOpenChange={(o) => {
          if (!o) resetForm();
          setCreating(o);
        }}
        title={created ? `Token ${created.name}` : "Create service token"}
        footer={
          created ? (
            <Button variant="primary" onClick={() => (resetForm(), setCreating(false))}>
              Done
            </Button>
          ) : (
            <>
              <Button onClick={() => setCreating(false)}>Cancel</Button>
              <Button type="submit" form="token-form" variant="primary" busy={busy} disabled={envs.length === 0 || !name.trim()}>
                Create token
              </Button>
            </>
          )
        }
      >
        {created ? (
          <div className="stack-sm">
            <CopyField label="Token" value={created.secret} copiedMessage="Copied the token." />
            <Notice tone="brass">This token is shown once.</Notice>
          </div>
        ) : (
          <form
            id="token-form"
            className="stack"
            onSubmit={async (e) => {
              e.preventDefault();
              setBusy(true);
              setError(null);
              try {
                const res = await call(
                  api.POST("/api/v1/tenants/{tenant}/projects/{project}/tokens", {
                    params: { path: { tenant, project: project.slug } },
                    body: { name: name.trim(), environments: envs, permission, expires_at: new Date(`${expires}T23:59:59`).toISOString() },
                  }),
                );
                setCreated({ name: res.token.name, secret: res.secret });
                toast.show(`Created token ${res.token.name}.`);
                await qc.invalidateQueries({ queryKey: qk.tokens(tenant, project.slug) });
              } catch (err) {
                setError(err);
              } finally {
                setBusy(false);
              }
            }}
          >
            <TextField label="Label" hint="For example, the CI job or server that uses it." value={name} onChange={(e) => setName(e.target.value)} required maxLength={64} />
            <fieldset>
              <legend>Environments</legend>
              {project.environments.map((env) => (
                <label key={env.id} className="check">
                  <input
                    type="checkbox"
                    checked={envs.includes(env.slug)}
                    onChange={(e) => setEnvs((xs) => (e.target.checked ? [...xs, env.slug] : xs.filter((x) => x !== env.slug)))}
                  />
                  {env.name}
                </label>
              ))}
            </fieldset>
            <fieldset>
              <legend>Permission</legend>
              <label className="check">
                <input type="radio" name="perm" checked={permission === "read"} onChange={() => setPermission("read")} /> Read
              </label>
              <label className="check">
                <input type="radio" name="perm" checked={permission === "read_write"} onChange={() => setPermission("read_write")} /> Read and write
              </label>
            </fieldset>
            <TextField
              label="Expires on"
              type="date"
              value={expires}
              min={defaultExpiry(1)}
              max={defaultExpiry(364)}
              onChange={(e) => setExpires(e.target.value)}
              required
            />
            <ErrorNotice error={error} />
          </form>
        )}
      </Modal>
      <ConfirmByName
        open={!!revoke}
        onOpenChange={(o) => !o && setRevoke(null)}
        title="Revoke token"
        description={`Anything using ${revoke?.name} loses access at once.`}
        name={revoke?.name ?? ""}
        action="Revoke token"
        onConfirm={async () => {
          await call(api.DELETE("/api/v1/tenants/{tenant}/projects/{project}/tokens/{id}", { params: { path: { tenant, project: project.slug, id: revoke!.id } } }));
          toast.show(`Revoked token ${revoke!.name}.`);
          await qc.invalidateQueries({ queryKey: qk.tokens(tenant, project.slug) });
        }}
      />
    </section>
  );
}

function KeyModeSection() {
  const { tenant, project, role } = useProjectContext();
  const me = useCurrentMe();
  const isAdmin = !!me.user?.is_instance_admin;
  const qc = useQueryClient();
  const toast = useToast();
  const keys = useInstanceKeys(isAdmin);
  const costs = keys.data?.mode_costs?.length ? keys.data.mode_costs : STATIC_MODE_COSTS;
  const [target, setTarget] = useState<Schemas["KeyMode"] | "">("");
  const [estimate, setEstimate] = useState<Schemas["MigrationEstimate"] | null>(null);
  const [confirm, setConfirm] = useState(false);
  const [migration, setMigration] = useState<Schemas["KeyMigration"] | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const polled = useMigration(migration?.id ?? null, isAdmin);
  const live = polled.data ?? migration;
  const canChange = can(role, "project.key_mode");

  const run = async (dryRun: boolean) => {
    if (!target) return;
    setBusy(true);
    setError(null);
    try {
      const res = await call(
        api.POST("/api/v1/tenants/{tenant}/projects/{project}/key-mode", { params: { path: { tenant, project: project.slug } }, body: { key_mode: target, dry_run: dryRun } }),
      );
      if ("total_ops" in res) {
        setEstimate(res);
      } else {
        setMigration(res);
        setEstimate(null);
        toast.show(`Started changing ${project.name} to key mode ${target}.`);
      }
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="panel stack-sm" aria-labelledby="mode-h">
      <h2 id="mode-h">Key mode</h2>
      <p>
        This project uses key mode <span className="mono">{project.key_mode}</span>. Every secret value is encrypted under its own data key; the mode
        sets which keys wrap it, and so how many rypt.dev operations reads and writes cost.
      </p>
      <div className="table-wrap">
        <table className="table dense">
          <thead>
            <tr>
              <th>Mode</th>
              <th>Chain</th>
              <th>Read cost</th>
              <th>Write cost</th>
            </tr>
          </thead>
          <tbody>
            {costs.map((c) => (
              <tr key={c.mode} className={c.mode === project.key_mode ? "highlight" : undefined}>
                <td className="mono">
                  {c.mode}
                  {c.mode === project.key_mode && <span className="visually-hidden"> (current)</span>}
                </td>
                <td className="small">{c.chain}</td>
                <td className="small">{c.read_cost}</td>
                <td className="small">{c.write_cost}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="small muted">Under the local provider no mode costs anything external; the mode still applies after a move to rypt.dev.</p>

      {canChange && (
        <div className="stack-sm">
          <div className="row" style={{ alignItems: "flex-end" }}>
            <div style={{ minWidth: 200 }}>
              <SelectField
                label="Change to"
                value={target}
                onChange={(e) => {
                  setTarget(e.target.value as Schemas["KeyMode"] | "");
                  setEstimate(null);
                }}
              >
                <option value="">Choose a mode</option>
                {(["A", "B", "C"] as const)
                  .filter((m) => m !== project.key_mode)
                  .map((m) => (
                    <option key={m} value={m}>
                      Mode {m}
                    </option>
                  ))}
              </SelectField>
            </div>
            <Button busy={busy && !estimate} disabled={!target} onClick={() => run(true)}>
              Estimate cost
            </Button>
          </div>
          {estimate && (
            <Notice tone="seal" role="status">
              Changing to mode {target} re-wraps keys without re-encrypting values. It will spend <strong>{estimate.total_ops}</strong> key provider operation
              {estimate.total_ops === 1 ? "" : "s"}.{" "}
              <Button variant="link" onClick={() => setConfirm(true)}>
                Change key mode
              </Button>
            </Notice>
          )}
          <ErrorNotice error={error} />
        </div>
      )}
      {live && (
        <div className="stack-sm" aria-live="polite">
          <div className="row">
            <strong>Migration</strong> <span className="mono small">{live.id}</span> <Badge tone={live.state === "failed" ? "crit" : live.state === "succeeded" ? "seal" : undefined}>{live.state}</Badge>
          </div>
          <Progress done={live.projects_done} total={live.projects_total} label="Key mode migration progress" />
          {live.error && <Notice tone="crit">{live.error}</Notice>}
          {live.state === "succeeded" && (
            <Button size="sm" onClick={() => qc.invalidateQueries({ queryKey: projectPrefix(tenant, project.slug) })}>
              Refresh project
            </Button>
          )}
          {!isAdmin && (live.state === "queued" || live.state === "running") && <span className="small muted">Updated {formatDateTime(live.updated_at)}.</span>}
        </div>
      )}
      <ConfirmByName
        open={confirm}
        onOpenChange={setConfirm}
        title="Change key mode"
        description={`${project.name} moves from mode ${project.key_mode} to mode ${target}. Secret values are not re-encrypted; only key wraps change.`}
        name={project.name}
        action="Change key mode"
        danger={false}
        onConfirm={() => run(false)}
      />
    </section>
  );
}

function DangerSection() {
  const { tenant, project } = useProjectContext();
  const qc = useQueryClient();
  const toast = useToast();
  const navigate = useNavigate();
  const [open, setOpen] = useState(false);
  return (
    <section className="panel stack-sm" aria-labelledby="danger-h">
      <h2 id="danger-h">Delete project</h2>
      <p className="muted">Deleting a project removes it with its environments and secrets, and revokes its service tokens.</p>
      <div>
        <Button variant="danger" onClick={() => setOpen(true)}>
          Delete project
        </Button>
      </div>
      <ConfirmByName
        open={open}
        onOpenChange={setOpen}
        title="Delete project"
        description={`Delete ${project.name} and everything in it.`}
        name={project.name}
        action="Delete project"
        onConfirm={async () => {
          await call(api.DELETE("/api/v1/tenants/{tenant}/projects/{project}", { params: { path: { tenant, project: project.slug } } }));
          toast.show(`Deleted project ${project.name}.`);
          await qc.invalidateQueries({ queryKey: qk.projects(tenant) });
          navigate(`/t/${tenant}`, { replace: true });
        }}
      />
    </section>
  );
}
