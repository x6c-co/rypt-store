import { useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link, Navigate } from "react-router";
import { api, call, type Schemas } from "../api/client";
import { errorMessage } from "../api/errors";
import { qk, useAllTenants, useInstanceKeys, useInstanceSettings, useInstanceUsers, useMigrations } from "../api/queries";
import { AuditView } from "../components/AuditView";
import { Modal } from "../components/Dialog";
import { LocalProviderText } from "../components/Layout";
import { useToast } from "../components/Toast";
import { Badge, Button, CopyField, ErrorNotice, KeyValue, Loading, Notice, Progress, SelectField, TextField } from "../components/ui";
import { formatDate, formatDateTime, slugify } from "../lib/format";
import { useCurrentMe } from "../session";

/** Instance settings for instance admins (core 14.3). */
export function InstanceSettingsPage() {
  const me = useCurrentMe();
  if (!me.user?.is_instance_admin) return <Navigate to="/" replace />;
  return (
    <>
      <div className="page-header">
        <h1>Settings</h1>
      </div>
      <KeysSection />
      <MigrationsSection />
      <GeneralSection />
      <TenantsSection />
      <UsersSection />
      <section className="stack-sm" aria-labelledby="iaudit-h">
        <h2 id="iaudit-h">Instance audit log</h2>
        <AuditView scope={{ kind: "instance" }} />
      </section>
    </>
  );
}

function KeysSection() {
  const keys = useInstanceKeys();
  if (keys.isPending) return <Loading />;
  if (keys.isError) return <ErrorNotice error={keys.error} />;
  const k = keys.data;
  const local = k.provider === "local";
  const opsByProvider = new Map<string, Schemas["OpCount"][]>();
  for (const c of k.op_counts) opsByProvider.set(c.provider, [...(opsByProvider.get(c.provider) ?? []), c]);
  const ryptOps = (opsByProvider.get("rypt") ?? []).reduce((n, c) => n + c.count, 0);
  return (
    <section className="panel stack" aria-labelledby="keys-h">
      <h2 id="keys-h">Keys</h2>
      {local && (
        <Notice tone="brass" role="note">
          <LocalProviderText />
        </Notice>
      )}
      {k.quota && (
        <Notice tone="crit" role="alert">
          The rypt.dev quota was reached{k.quota.cap ? ` (cap ${k.quota.cap.toLocaleString()} operations)` : ""}
          {k.quota.resets_at ? `; it resets on ${formatDateTime(k.quota.resets_at)}` : ""}.
        </Notice>
      )}
      <KeyValue
        items={[
          ["Provider for new wraps", <span className="mono">{k.provider}</span>],
          ["Default key mode", <span className="mono">{k.default_key_mode}</span>],
          ["Unwrapped keys cached", k.cache_entries.toLocaleString()],
          [`rypt.dev operations in ${k.month} (UTC)`, <span className="mono">{ryptOps.toLocaleString()}</span>],
        ]}
      />
      <div className="table-wrap">
        <table className="table dense">
          <thead>
            <tr>
              <th>Provider</th>
              <th>Loaded</th>
              <th>Status</th>
              <th>Wraps referencing it</th>
            </tr>
          </thead>
          <tbody>
            {k.providers.map((p) => (
              <tr key={p.name}>
                <td className="mono">{p.name}</td>
                <td>{p.loaded ? "Yes" : "No"}</td>
                <td>{p.unavailable ? <Badge tone="crit">unreachable</Badge> : p.loaded ? <Badge>ok</Badge> : "—"}</td>
                <td>{p.wraps.toLocaleString()}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {k.op_counts.length > 0 && (
        <div className="table-wrap">
          <table className="table dense">
            <caption className="visually-hidden">Provider operations this month, counted locally</caption>
            <thead>
              <tr>
                <th>Provider</th>
                <th>Operation</th>
                <th>Count this month</th>
              </tr>
            </thead>
            <tbody>
              {k.op_counts.map((c) => (
                <tr key={`${c.provider}/${c.op}`}>
                  <td className="mono">{c.provider}</td>
                  <td className="mono">{c.op}</td>
                  <td>{c.count.toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <p className="small muted">Operation counts are kept by this server for the current UTC month.</p>
    </section>
  );
}

function MigrationsSection() {
  const qc = useQueryClient();
  const toast = useToast();
  const keys = useInstanceKeys();
  const migrations = useMigrations();
  const [open, setOpen] = useState(false);
  const [kind, setKind] = useState<"provider" | "rotate">("provider");
  const [to, setTo] = useState("rypt");
  const [estimate, setEstimate] = useState<Schemas["MigrationEstimate"] | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const loaded = keys.data?.providers.filter((p) => p.loaded).map((p) => p.name) ?? [];

  const start = async (dryRun: boolean) => {
    setBusy(true);
    setError(null);
    try {
      const res = await call(api.POST("/api/v1/instance/keys/migrations", { body: { kind, params: kind === "provider" ? { to } : {}, dry_run: dryRun } }));
      if ("total_ops" in res) setEstimate(res);
      else {
        toast.show(kind === "provider" ? `Started moving keys to ${to}.` : "Started rotating rypt wraps.");
        setOpen(false);
        setEstimate(null);
        await qc.invalidateQueries({ queryKey: qk.migrations });
      }
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="panel stack-sm" aria-labelledby="mig-h">
      <div className="row-between">
        <h2 id="mig-h">Key migrations</h2>
        <Button
          size="sm"
          onClick={() => {
            setEstimate(null);
            setError(null);
            setOpen(true);
          }}
        >
          Start migration
        </Button>
      </div>
      <p className="small muted">
        Migrations re-wrap keys without re-encrypting values. The CLI equivalent is <code>rypt-store keys migrate --to rypt</code>.
      </p>
      {migrations.isPending ? (
        <Loading />
      ) : migrations.isError ? (
        <ErrorNotice error={migrations.error} />
      ) : migrations.data.migrations.length === 0 ? (
        <p className="muted">No migrations have run.</p>
      ) : (
        <div className="table-wrap">
          <table className="table dense">
            <thead>
              <tr>
                <th>Started</th>
                <th>Kind</th>
                <th>Parameters</th>
                <th>State</th>
                <th>Progress</th>
              </tr>
            </thead>
            <tbody>
              {migrations.data.migrations.map((m) => (
                <tr key={m.id}>
                  <td className="nowrap">{formatDateTime(m.created_at)}</td>
                  <td className="mono">{m.kind}</td>
                  <td className="mono small">{JSON.stringify(m.params)}</td>
                  <td>
                    <Badge tone={m.state === "failed" ? "crit" : m.state === "succeeded" ? "seal" : undefined}>{m.state}</Badge>
                    {m.error && <div className="small" style={{ color: "var(--crit)" }}>{m.error}</div>}
                  </td>
                  <td style={{ minWidth: 160 }}>
                    <Progress done={m.projects_done} total={m.projects_total} label={`Progress of migration ${m.id}`} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <Modal
        open={open}
        onOpenChange={setOpen}
        title="Start key migration"
        description="Estimate first: the dry run reports how many key provider operations the migration spends."
        footer={
          <>
            <Button onClick={() => setOpen(false)}>Cancel</Button>
            <Button busy={busy && !estimate} onClick={() => start(true)}>
              Estimate cost
            </Button>
            <Button variant="primary" busy={busy && !!estimate} disabled={!estimate} onClick={() => start(false)}>
              Start migration
            </Button>
          </>
        }
      >
        <div className="stack">
          <SelectField
            label="Kind"
            value={kind}
            onChange={(e) => {
              setKind(e.target.value as "provider" | "rotate");
              setEstimate(null);
            }}
          >
            <option value="provider">Move every top-level wrap to another provider</option>
            <option value="rotate">Rewrap every rypt wrap to the current rypt key version</option>
          </SelectField>
          {kind === "provider" && (
            <SelectField
              label="Target provider"
              value={to}
              onChange={(e) => {
                setTo(e.target.value);
                setEstimate(null);
              }}
              hint="The target provider must be configured before the migration starts."
            >
              {(loaded.length ? loaded : ["rypt", "local"]).map((p) => (
                <option key={p} value={p}>
                  {p}
                </option>
              ))}
            </SelectField>
          )}
          {estimate && (
            <Notice tone="seal" role="status">
              This migration spends <strong>{estimate.total_ops}</strong> operations
              {estimate.instance_ops ? ` (${estimate.instance_ops} on the instance and root keys)` : ""} across {estimate.projects.length} project
              {estimate.projects.length === 1 ? "" : "s"}.
            </Notice>
          )}
          <ErrorNotice error={error} />
        </div>
      </Modal>
    </section>
  );
}

function GeneralSection() {
  const settings = useInstanceSettings();
  if (settings.isPending) return <Loading />;
  if (settings.isError) return <ErrorNotice error={settings.error} />;
  const s = settings.data;
  return (
    <section className="panel stack-sm" aria-labelledby="gen-h">
      <h2 id="gen-h">Instance</h2>
      {s.tls_mode === "self_signed" && (
        <Notice tone="brass" role="note">
          TLS uses a self-signed certificate. Browsers warn on every visit; configure ACME or certificate files for production.
        </Notice>
      )}
      <KeyValue
        items={[
          ["Instance ID", <span className="mono">{s.instance_id}</span>],
          ["Public URL", s.public_url || "—"],
          ["TLS mode", <span className="mono">{s.tls_mode}</span>],
          ["TLS domains", s.tls_domains?.length ? s.tls_domains.join(", ") : "—"],
          ["Key provider", <span className="mono">{s.provider}</span>],
          ["Providers loaded", s.providers.join(", ")],
          ["rypt.dev key", s.rypt_key_id ? <span className="mono">{s.rypt_key_id}</span> : "—"],
          ["Default key mode", <span className="mono">{s.default_key_mode}</span>],
          ["Outage policy", <span className="mono">{s.outage_policy}</span>],
          ["Two-factor sign-in", s.require_mfa ? "Required" : "Optional"],
          ["Versions kept per secret", s.versions_kept],
          ["Audit retention", s.audit_retention_days === 0 ? "Forever" : `${s.audit_retention_days} days`],
        ]}
      />
      <p className="small muted">These settings come from the config file and environment variables.</p>
    </section>
  );
}

function TenantsSection() {
  const qc = useQueryClient();
  const toast = useToast();
  const tenants = useAllTenants();
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [slug, setSlug] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  return (
    <section className="panel stack-sm" aria-labelledby="tenants-h">
      <div className="row-between">
        <h2 id="tenants-h">Tenants</h2>
        <Button size="sm" onClick={() => setOpen(true)}>
          Create tenant
        </Button>
      </div>
      {tenants.isPending ? (
        <Loading />
      ) : tenants.isError ? (
        <ErrorNotice error={tenants.error} />
      ) : (
        <div className="table-wrap">
          <table className="table dense">
            <thead>
              <tr>
                <th>Name</th>
                <th>Slug</th>
                <th>Your role</th>
                <th>Created</th>
              </tr>
            </thead>
            <tbody>
              {tenants.data.tenants.map((t) => (
                <tr key={t.id}>
                  <td>{t.role ? <Link to={`/t/${t.slug}`}>{t.name}</Link> : t.name}</td>
                  <td className="mono">{t.slug}</td>
                  <td>{t.role ?? "—"}</td>
                  <td className="nowrap">{formatDate(t.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <Modal
        open={open}
        onOpenChange={(o) => {
          if (!o) {
            setName("");
            setSlug("");
            setError(null);
          }
          setOpen(o);
        }}
        title="Create tenant"
        description="You become the tenant's owner and can invite others."
        footer={
          <>
            <Button onClick={() => setOpen(false)}>Cancel</Button>
            <Button type="submit" form="tenant-form" variant="primary" busy={busy}>
              Create tenant
            </Button>
          </>
        }
      >
        <form
          id="tenant-form"
          className="stack"
          onSubmit={async (e) => {
            e.preventDefault();
            setBusy(true);
            setError(null);
            try {
              const t = await call(api.POST("/api/v1/tenants", { body: { name: name.trim(), slug: slug || slugify(name) || undefined } }));
              toast.show(`Created tenant ${t.name}.`);
              await qc.invalidateQueries({ queryKey: qk.allTenants });
              await qc.invalidateQueries({ queryKey: qk.me });
              setOpen(false);
            } catch (err) {
              setError(err);
            } finally {
              setBusy(false);
            }
          }}
        >
          <TextField label="Name" value={name} onChange={(e) => setName(e.target.value)} required maxLength={128} autoFocus />
          <TextField label="Slug" value={slug || slugify(name)} onChange={(e) => setSlug(e.target.value)} mono />
          <ErrorNotice error={error} />
        </form>
      </Modal>
    </section>
  );
}

function UsersSection() {
  const users = useInstanceUsers();
  const toast = useToast();
  const [link, setLink] = useState<{ who: string; link: Schemas["OneTimeLink"] } | null>(null);
  return (
    <section className="panel stack-sm" aria-labelledby="users-h">
      <h2 id="users-h">Users</h2>
      {users.isPending ? (
        <Loading />
      ) : users.isError ? (
        <ErrorNotice error={users.error} />
      ) : (
        <div className="table-wrap">
          <table className="table dense">
            <thead>
              <tr>
                <th>Name</th>
                <th>Email</th>
                <th>Instance admin</th>
                <th>Created</th>
                <th>
                  <span className="visually-hidden">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {users.data.users.map((u) => (
                <tr key={u.id}>
                  <td>
                    {u.display_name} {u.disabled && <Badge tone="brass">disabled</Badge>}
                  </td>
                  <td>{u.email}</td>
                  <td>{u.is_instance_admin ? "Yes" : "No"}</td>
                  <td className="nowrap">{formatDate(u.created_at)}</td>
                  <td className="actions">
                    <Button
                      size="sm"
                      onClick={async () => {
                        try {
                          const l = await call(api.POST("/api/v1/instance/users/{user}/password-reset", { params: { path: { user: u.id } } }));
                          setLink({ who: u.display_name, link: l });
                        } catch (err) {
                          toast.error(errorMessage(err));
                        }
                      }}
                    >
                      Create reset link
                    </Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <Modal
        open={!!link}
        onOpenChange={(o) => !o && setLink(null)}
        title={`Password reset link for ${link?.who}`}
        footer={
          <Button variant="primary" onClick={() => setLink(null)}>
            Done
          </Button>
        }
      >
        {link && (
          <div className="stack-sm">
            <CopyField label="Reset link" value={link.link.url} copiedMessage="Copied the reset link." />
            <Notice tone="brass">This link is shown once and works until {formatDateTime(link.link.expires_at)}. Deliver it yourself.</Notice>
          </div>
        )}
      </Modal>
    </section>
  );
}
