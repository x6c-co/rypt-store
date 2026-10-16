import { useQueryClient } from "@tanstack/react-query";
import { useEffect, useMemo, useState } from "react";
import { api, call, callWithResponse, envPath, etagFor, rawFetch, versionFromETag, type Schemas } from "../api/client";
import { ApiError } from "../api/errors";
import { projectPrefix, useDeletedSecrets, useVersions } from "../api/queries";
import { parseDotenv } from "../lib/dotenv";
import { formatDateTime } from "../lib/format";
import { useReveal } from "../lib/useReveal";
import { Confirm, Modal } from "./Dialog";
import { useToast } from "./Toast";
import { Button, ErrorNotice, Loading, Notice, SelectField, TextAreaField, TextField } from "./ui";

export const MAX_VALUE_BYTES = 65536;

export function actorName(a: Schemas["Actor"] | undefined): string {
  if (!a) return "—";
  return a.display || (a.kind === "system" ? "system" : a.id);
}

function byteLength(s: string): number {
  return new TextEncoder().encode(s).length;
}

interface EditorTarget {
  mode: "create" | "edit";
  environment: string;
  name?: string;
}

/**
 * The secret editor dialog (feature 01 §6): a monospace multi-line value and
 * a comment. Edits send If-Match; a 409 means someone else saved first.
 */
export function SecretEditor({
  tenant,
  project,
  environments,
  target,
  onClose,
}: {
  tenant: string;
  project: string;
  environments: Schemas["Environment"][];
  target: EditorTarget | null;
  onClose(): void;
}) {
  const qc = useQueryClient();
  const toast = useToast();
  const [env, setEnv] = useState("");
  const [name, setName] = useState("");
  const [value, setValue] = useState("");
  const [comment, setComment] = useState("");
  const [version, setVersion] = useState<number | null>(null);
  const [loading, setLoading] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [stale, setStale] = useState(false);

  const load = async (t: EditorTarget) => {
    setLoading(true);
    setError(null);
    setStale(false);
    try {
      const { data, response } = await callWithResponse(
        api.GET("/api/v1/tenants/{tenant}/projects/{project}/environments/{environment}/secrets/{name}", {
          params: { path: { tenant, project, environment: t.environment, name: t.name! } },
        }),
      );
      setValue(data.value);
      setComment(data.comment);
      setVersion(versionFromETag(response.headers.get("ETag")) ?? data.version);
    } catch (err) {
      setError(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (!target) return;
    setEnv(target.environment);
    setName(target.name ?? "");
    setValue("");
    setComment("");
    setVersion(null);
    setError(null);
    setStale(false);
    if (target.mode === "edit") void load(target);
    // load reads only stable props; the dialog reloads when its target changes.
  }, [target]);

  const tooLong = byteLength(value) > MAX_VALUE_BYTES;
  const envName = environments.find((e) => e.slug === env)?.name ?? env;

  const save = async () => {
    if (!target) return;
    setBusy(true);
    setError(null);
    try {
      if (target.mode === "create") {
        await call(
          api.POST("/api/v1/tenants/{tenant}/projects/{project}/environments/{environment}/secrets", {
            params: { path: { tenant, project, environment: env } },
            body: { name: name.trim(), value, comment },
          }),
        );
        toast.show(`Added ${name.trim()} to ${envName}.`);
      } else {
        await call(
          api.PUT("/api/v1/tenants/{tenant}/projects/{project}/environments/{environment}/secrets/{name}", {
            params: { path: { tenant, project, environment: env, name: target.name! }, header: { "If-Match": etagFor(version ?? 0) } },
            body: { value, comment },
          }),
        );
        toast.show(`Saved ${target.name}.`);
      }
      await qc.invalidateQueries({ queryKey: projectPrefix(tenant, project) });
      onClose();
    } catch (err) {
      if (target.mode === "edit" && err instanceof ApiError && err.status === 409) setStale(true);
      else setError(err);
    } finally {
      setBusy(false);
    }
  };

  const fieldErr = (f: string) => (error instanceof ApiError ? error.fieldError(f) : undefined);

  return (
    <Modal
      open={!!target}
      onOpenChange={(o) => !o && onClose()}
      wide
      title={target?.mode === "edit" ? `Edit ${target.name}` : "Add secret"}
      description={target?.mode === "edit" ? `In ${envName}. Saving creates a new version.` : undefined}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" form="secret-editor" variant="primary" busy={busy} disabled={loading || tooLong || stale}>
            {target?.mode === "edit" ? "Save" : "Add secret"}
          </Button>
        </>
      }
    >
      {loading ? (
        <Loading />
      ) : (
        <form
          id="secret-editor"
          className="stack"
          onSubmit={(e) => {
            e.preventDefault();
            void save();
          }}
        >
          {target?.mode === "create" && (
            <div className="row" style={{ alignItems: "flex-start" }}>
              <div style={{ flex: 2, minWidth: 200 }}>
                <TextField
                  label="Name"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  required
                  mono
                  pattern="[A-Za-z_][A-Za-z0-9_]{0,255}"
                  title="Letters, digits and underscores; not starting with a digit."
                  autoComplete="off"
                  spellCheck={false}
                  autoFocus={!target.name}
                  error={fieldErr("name")}
                />
              </div>
              <div style={{ flex: 1, minWidth: 140 }}>
                <SelectField label="Environment" value={env} onChange={(e) => setEnv(e.target.value)}>
                  {environments.map((e) => (
                    <option key={e.id} value={e.slug}>
                      {e.name}
                    </option>
                  ))}
                </SelectField>
              </div>
            </div>
          )}
          <TextAreaField
            label="Value"
            value={value}
            onChange={(e) => setValue(e.target.value)}
            mono
            rows={6}
            spellCheck={false}
            autoComplete="off"
            autoFocus={target?.mode === "edit" || !!target?.name}
            error={tooLong ? "Values are at most 64 KiB." : fieldErr("value")}
          />
          <TextField label="Comment" hint="Comments are not encrypted." value={comment} onChange={(e) => setComment(e.target.value)} maxLength={1024} error={fieldErr("comment")} />
          {stale && (
            <Notice tone="brass" role="alert">
              Someone else saved a newer version of {target?.name} while you were editing.{" "}
              <Button variant="link" onClick={() => target && load(target)}>
                Reload the newest version
              </Button>{" "}
              to edit it; your changes here will be replaced.
            </Notice>
          )}
          <ErrorNotice error={error} />
        </form>
      )}
    </Modal>
  );
}

/** Version history with per-version Reveal and Restore (feature 01 §6). */
export function HistoryDrawer({
  tenant,
  project,
  environment,
  name,
  canWrite,
  onClose,
}: {
  tenant: string;
  project: string;
  environment: string;
  name: string | null;
  canWrite: boolean;
  onClose(): void;
}) {
  const qc = useQueryClient();
  const toast = useToast();
  const versions = useVersions(tenant, project, environment, name);
  const { revealed, reveal, hide, hideAll } = useReveal();
  const [restore, setRestore] = useState<number | null>(null);
  const [error, setError] = useState<unknown>(null);

  useEffect(() => hideAll(), [name, hideAll]);

  const revealVersion = async (v: number) => {
    setError(null);
    try {
      const res = await call(
        api.GET("/api/v1/tenants/{tenant}/projects/{project}/environments/{environment}/secrets/{name}/versions/{version}", {
          params: { path: { tenant, project, environment, name: name!, version: v } },
        }),
      );
      reveal(String(v), res.value);
    } catch (err) {
      setError(err);
    }
  };

  return (
    <Modal drawer open={!!name} onOpenChange={(o) => !o && onClose()} title={`History of ${name ?? ""}`} description="Versions are listed newest first. Values are fetched only when revealed.">
      <ErrorNotice error={error} />
      {versions.isPending ? (
        <Loading />
      ) : versions.isError ? (
        <ErrorNotice error={versions.error} />
      ) : (
        <ol className="stack-sm" style={{ listStyle: "none", padding: 0, margin: 0 }}>
          {versions.data.versions.map((v, idx) => {
            const key = String(v.version);
            const isCurrent = v.current ?? idx === 0;
            return (
              <li key={v.version} className="panel stack-sm" style={{ padding: 12 }}>
                <div className="row-between">
                  <strong>
                    Version {v.version}
                    {isCurrent && <span className="badge badge-seal" style={{ marginLeft: 8 }}>current</span>}
                  </strong>
                  <span className="small muted">{formatDateTime(v.created_at)}</span>
                </div>
                <span className="small muted">
                  By {actorName(v.created_by)}
                  {v.restored_from ? ` · restored from version ${v.restored_from}` : ""}
                </span>
                {key in revealed ? (
                  <pre className="json value-revealed" aria-label={`Value of version ${v.version}`}>
                    {revealed[key]}
                  </pre>
                ) : null}
                <div className="row">
                  {key in revealed ? (
                    <Button size="sm" onClick={() => hide(key)}>
                      Hide
                    </Button>
                  ) : (
                    <Button size="sm" onClick={() => revealVersion(v.version)} aria-label={`Reveal version ${v.version}`}>
                      Reveal
                    </Button>
                  )}
                  {canWrite && !isCurrent && (
                    <Button size="sm" onClick={() => setRestore(v.version)}>
                      Restore version {v.version}
                    </Button>
                  )}
                </div>
              </li>
            );
          })}
        </ol>
      )}
      <Confirm
        open={restore !== null}
        onOpenChange={(o) => !o && setRestore(null)}
        title={`Restore version ${restore}?`}
        description={`This writes the value of version ${restore} as a new version of ${name}. Version ${restore} stays in the history.`}
        action={`Restore version ${restore}`}
        onConfirm={async () => {
          await call(
            api.POST("/api/v1/tenants/{tenant}/projects/{project}/environments/{environment}/secrets/{name}/versions/{version}/restore", {
              params: { path: { tenant, project, environment, name: name!, version: restore! } },
            }),
          );
          toast.show(`Restored version ${restore} of ${name}.`);
          await qc.invalidateQueries({ queryKey: projectPrefix(tenant, project) });
        }}
      />
    </Modal>
  );
}

/** Imports a .env file (feature 01 3.7). */
export function ImportDialog({
  tenant,
  project,
  environment,
  envName,
  open,
  onOpenChange,
}: {
  tenant: string;
  project: string;
  environment: string;
  envName: string;
  open: boolean;
  onOpenChange(o: boolean): void;
}) {
  const qc = useQueryClient();
  const toast = useToast();
  const [text, setText] = useState("");
  const [mode, setMode] = useState<"skip_existing" | "overwrite">("skip_existing");
  const [result, setResult] = useState<Schemas["ImportResult"] | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const preview = useMemo(() => (text ? parseDotenv(text) : null), [text]);

  const reset = () => {
    setText("");
    setResult(null);
    setError(null);
    setMode("skip_existing");
  };

  const submit = async () => {
    setBusy(true);
    setError(null);
    try {
      const res = await rawFetch(`${envPath(tenant, project, environment)}/secrets/import?mode=${mode}`, {
        method: "POST",
        headers: { "Content-Type": "text/plain; charset=utf-8" },
        body: text,
      });
      const r = (await res.json()) as Schemas["ImportResult"];
      setResult(r);
      const changed = r.created.length + r.updated.length;
      toast.show(`Imported ${changed} secret${changed === 1 ? "" : "s"} into ${envName}.`);
      await qc.invalidateQueries({ queryKey: projectPrefix(tenant, project) });
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal
      open={open}
      onOpenChange={(o) => {
        if (!o) reset();
        onOpenChange(o);
      }}
      wide
      title={`Import .env into ${envName}`}
      footer={
        result ? (
          <Button variant="primary" onClick={() => (reset(), onOpenChange(false))}>
            Done
          </Button>
        ) : (
          <>
            <Button onClick={() => onOpenChange(false)}>Cancel</Button>
            <Button variant="primary" busy={busy} disabled={!text.trim()} onClick={submit}>
              Import
            </Button>
          </>
        )
      }
    >
      {result ? (
        <div className="stack-sm" aria-live="polite">
          <ImportList title="Created" names={result.created} />
          <ImportList title="Updated" names={result.updated} />
          <ImportList title="Skipped (already set)" names={result.skipped} />
          {result.rejected.length > 0 && (
            <div>
              <strong>Rejected</strong>
              <ul className="small">
                {result.rejected.map((r, i) => (
                  <li key={i}>
                    Line {r.line}
                    {r.name ? (
                      <>
                        {" "}
                        (<span className="mono">{r.name}</span>)
                      </>
                    ) : null}
                    : {r.reason}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      ) : (
        <div className="stack">
          <div className="field">
            <label htmlFor="env-file">.env file</label>
            <input
              id="env-file"
              type="file"
              accept=".env,text/plain"
              onChange={async (e) => {
                const f = e.target.files?.[0];
                if (f) setText(await f.text());
              }}
            />
          </div>
          <TextAreaField label="Or paste the contents" value={text} onChange={(e) => setText(e.target.value)} mono rows={8} spellCheck={false} />
          <fieldset>
            <legend>Names that already exist</legend>
            <label className="check">
              <input type="radio" name="import-mode" checked={mode === "skip_existing"} onChange={() => setMode("skip_existing")} /> Skip them
            </label>
            <label className="check">
              <input type="radio" name="import-mode" checked={mode === "overwrite"} onChange={() => setMode("overwrite")} /> Overwrite them with a new version
            </label>
          </fieldset>
          {preview && (
            <p className="small muted" aria-live="polite">
              {preview.entries.length} secret{preview.entries.length === 1 ? "" : "s"} found
              {preview.problems.length > 0 ? `, ${preview.problems.length} line${preview.problems.length === 1 ? "" : "s"} will be rejected` : ""}.
            </p>
          )}
          <ErrorNotice error={error} />
        </div>
      )}
    </Modal>
  );
}

function ImportList({ title, names }: { title: string; names: string[] }) {
  if (names.length === 0) return null;
  return (
    <div>
      <strong>
        {title} ({names.length})
      </strong>
      <p className="mono small" style={{ overflowWrap: "anywhere" }}>
        {names.join(", ")}
      </p>
    </div>
  );
}

/** Soft-deleted secrets with Restore (feature 01 3.5). */
export function RecentlyDeletedDialog({
  tenant,
  project,
  environment,
  envName,
  open,
  onOpenChange,
  canWrite,
}: {
  tenant: string;
  project: string;
  environment: string;
  envName: string;
  open: boolean;
  onOpenChange(o: boolean): void;
  canWrite: boolean;
}) {
  const qc = useQueryClient();
  const toast = useToast();
  const deleted = useDeletedSecrets(tenant, project, environment, open);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [error, setError] = useState<unknown>(null);

  return (
    <Modal open={open} onOpenChange={onOpenChange} wide title={`Recently deleted in ${envName}`} description="Deleted secrets can be restored until they are purged.">
      <ErrorNotice error={error} />
      {deleted.isPending ? (
        <Loading />
      ) : deleted.isError ? (
        <ErrorNotice error={deleted.error} />
      ) : deleted.data.secrets.length === 0 ? (
        <p className="muted">Nothing was deleted in {envName} recently.</p>
      ) : (
        <div className="table-wrap">
          <table className="table dense">
            <thead>
              <tr>
                <th>Name</th>
                <th>Deleted</th>
                <th>Purged</th>
                <th>
                  <span className="visually-hidden">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {deleted.data.secrets.map((s) => (
                <tr key={s.id}>
                  <td className="mono">{s.name}</td>
                  <td className="nowrap">{formatDateTime(s.deleted_at)}</td>
                  <td className="nowrap">{formatDateTime(s.purge_at)}</td>
                  <td className="actions">
                    {s.name_in_use ? (
                      <span className="small muted">Name in use</span>
                    ) : (
                      canWrite && (
                        <Button
                          size="sm"
                          busy={busyId === s.id}
                          onClick={async () => {
                            setBusyId(s.id);
                            setError(null);
                            try {
                              await call(
                                api.POST("/api/v1/tenants/{tenant}/projects/{project}/environments/{environment}/secrets/deleted/{id}/restore", {
                                  params: { path: { tenant, project, environment, id: s.id } },
                                }),
                              );
                              toast.show(`Restored ${s.name}.`);
                              await qc.invalidateQueries({ queryKey: projectPrefix(tenant, project) });
                            } catch (err) {
                              setError(err);
                            } finally {
                              setBusyId(null);
                            }
                          }}
                        >
                          Restore
                        </Button>
                      )
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Modal>
  );
}

