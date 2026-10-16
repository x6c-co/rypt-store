import { useInfiniteQuery } from "@tanstack/react-query";
import { Fragment, useState } from "react";
import { api, call, enc, type Schemas } from "../api/client";
import { qk, useMembers, useProjects } from "../api/queries";
import { formatDateTime, localInputToISO, shortHash } from "../lib/format";
import { Badge, Button, EmptyState, ErrorNotice, Loading, Notice, SelectField, TextField } from "./ui";

type Scope = { kind: "tenant"; tenant: string } | { kind: "instance" };

interface Filters {
  actor?: string;
  action?: string;
  project?: string;
  from?: string;
  to?: string;
}

const PAGE = 100;

/**
 * The audit log (core 14.3): a dense table with filters, the chain head at
 * the top, a Verify button, and an export link.
 */
export function AuditView({ scope }: { scope: Scope }) {
  const tenant = scope.kind === "tenant" ? scope.tenant : "";
  const [filters, setFilters] = useState<Filters>({});
  const [draft, setDraft] = useState({ actor: "", action: "", project: "", from: "", to: "" });
  const [verify, setVerify] = useState<Schemas["AuditVerify"] | null>(null);
  const [verifyBusy, setVerifyBusy] = useState(false);
  const [verifyError, setVerifyError] = useState<unknown>(null);
  const [open, setOpen] = useState<string | null>(null);
  const members = useMembers(tenant);
  const projects = useProjects(scope.kind === "tenant" ? tenant : undefined);

  const key = scope.kind === "tenant" ? qk.tenantAudit(tenant) : qk.instanceAudit;
  const q = useInfiniteQuery({
    queryKey: [...key, filters],
    initialPageParam: undefined as string | undefined,
    queryFn: ({ pageParam }) =>
      scope.kind === "tenant"
        ? call(api.GET("/api/v1/tenants/{tenant}/audit", { params: { path: { tenant }, query: { limit: PAGE, cursor: pageParam, ...filters } } }))
        : call(
            api.GET("/api/v1/instance/audit", {
              params: { query: { limit: PAGE, cursor: pageParam, actor: filters.actor, action: filters.action, from: filters.from, to: filters.to } },
            }),
          ),
    getNextPageParam: (last) => last.next_cursor ?? undefined,
  });

  const head = q.data?.pages[0]?.head;
  const events = q.data?.pages.flatMap((p) => p.events) ?? [];
  const projectName = (id: string | null | undefined) => (id ? (projects.data?.projects.find((p) => p.id === id)?.name ?? id) : "—");
  const exportURL = (() => {
    const base = scope.kind === "tenant" ? `/api/v1/tenants/${enc(tenant)}/audit/export` : "/api/v1/instance/audit/export";
    const qs = new URLSearchParams();
    if (filters.from) qs.set("from", filters.from);
    if (filters.to) qs.set("to", filters.to);
    const s = qs.toString();
    return s ? `${base}?${s}` : base;
  })();

  const runVerify = async () => {
    setVerifyBusy(true);
    setVerifyError(null);
    try {
      setVerify(
        scope.kind === "tenant"
          ? await call(api.GET("/api/v1/tenants/{tenant}/audit/verify", { params: { path: { tenant } } }))
          : await call(api.GET("/api/v1/instance/audit/verify")),
      );
    } catch (err) {
      setVerifyError(err);
    } finally {
      setVerifyBusy(false);
    }
  };

  return (
    <div className="stack">
      <div className="panel stack-sm">
        <div className="row-between">
          <div className="stack-sm" style={{ gap: 2 }}>
            <span className="small muted">Chain head</span>
            {head ? (
              <span>
                seq <span className="mono">{head.seq}</span> · <span className="mono" title={head.hash}>{shortHash(head.hash)}</span>
                {head.anchor_seq > 0 && (
                  <span className="small muted">
                    {" "}
                    · anchored at seq <span className="mono">{head.anchor_seq}</span>
                  </span>
                )}
              </span>
            ) : (
              <span className="muted">—</span>
            )}
          </div>
          <div className="row">
            <Button onClick={runVerify} busy={verifyBusy}>
              Verify
            </Button>
            <a className="btn" href={exportURL} download>
              Export
            </a>
          </div>
        </div>
        {verify && (
          <Notice tone={verify.ok ? "seal" : "crit"} role="status">
            {verify.ok ? (
              <>
                OK <span className="mono">{verify.seq}</span> <span className="mono" style={{ overflowWrap: "anywhere" }}>{verify.hash}</span> — {verify.checked} events
                checked.
              </>
            ) : (
              <>
                The chain is broken at seq <span className="mono">{verify.seq}</span>: {verify.reason}
              </>
            )}
          </Notice>
        )}
        <ErrorNotice error={verifyError} />
      </div>

      <form
        className="row"
        style={{ alignItems: "flex-end" }}
        onSubmit={(e) => {
          e.preventDefault();
          setFilters({
            actor: draft.actor || undefined,
            action: draft.action.trim() || undefined,
            project: draft.project || undefined,
            from: localInputToISO(draft.from),
            to: localInputToISO(draft.to),
          });
        }}
        aria-label="Filter events"
      >
        {scope.kind === "tenant" && members.data ? (
          <div style={{ minWidth: 160 }}>
            <SelectField label="Actor" value={draft.actor} onChange={(e) => setDraft((d) => ({ ...d, actor: e.target.value }))}>
              <option value="">Anyone</option>
              {members.data.members.map((m) => (
                <option key={m.user_id} value={m.user_id}>
                  {m.display_name}
                </option>
              ))}
            </SelectField>
          </div>
        ) : (
          <div style={{ minWidth: 160 }}>
            <TextField label="Actor ID" value={draft.actor} onChange={(e) => setDraft((d) => ({ ...d, actor: e.target.value }))} mono />
          </div>
        )}
        <div style={{ minWidth: 160 }}>
          <TextField label="Action" placeholder="secret." value={draft.action} onChange={(e) => setDraft((d) => ({ ...d, action: e.target.value }))} mono />
        </div>
        {scope.kind === "tenant" && (
          <div style={{ minWidth: 160 }}>
            <SelectField label="Project" value={draft.project} onChange={(e) => setDraft((d) => ({ ...d, project: e.target.value }))}>
              <option value="">Any project</option>
              {projects.data?.projects.map((p) => (
                <option key={p.id} value={p.slug}>
                  {p.name}
                </option>
              ))}
            </SelectField>
          </div>
        )}
        <div>
          <TextField label="From" type="datetime-local" value={draft.from} onChange={(e) => setDraft((d) => ({ ...d, from: e.target.value }))} />
        </div>
        <div>
          <TextField label="To" type="datetime-local" value={draft.to} onChange={(e) => setDraft((d) => ({ ...d, to: e.target.value }))} />
        </div>
        <Button type="submit">Filter</Button>
        <Button
          variant="ghost"
          onClick={() => {
            setDraft({ actor: "", action: "", project: "", from: "", to: "" });
            setFilters({});
          }}
        >
          Clear
        </Button>
      </form>

      {q.isPending ? (
        <Loading />
      ) : q.isError ? (
        <ErrorNotice error={q.error} />
      ) : events.length === 0 ? (
        <EmptyState>No events match these filters.</EmptyState>
      ) : (
        <div className="table-wrap">
          <table className="table dense">
            <caption className="visually-hidden">Audit events, newest first</caption>
            <thead>
              <tr>
                <th>Seq</th>
                <th>Time</th>
                <th>Actor</th>
                <th>Action</th>
                <th>Target</th>
                {scope.kind === "tenant" && <th>Project</th>}
                <th>Result</th>
                <th>IP</th>
                <th>
                  <span className="visually-hidden">Details</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {events.map((e) => (
                <Fragment key={e.id}>
                  <tr>
                    <td className="mono">{e.seq}</td>
                    <td className="nowrap">{formatDateTime(e.ts)}</td>
                    <td>
                      {e.actor_display ?? (e.actor_kind === "system" ? "system" : <span className="mono">{e.actor_id ?? "—"}</span>)}
                      {e.actor_kind === "service_token" && <span className="small muted"> (token)</span>}
                    </td>
                    <td className="mono">{e.action}</td>
                    <td className="small">
                      {e.target_kind ? (
                        <>
                          {e.target_kind} <span className="mono">{e.target_id ? shortHash(e.target_id, 6) : ""}</span>
                        </>
                      ) : (
                        "—"
                      )}
                    </td>
                    {scope.kind === "tenant" && <td>{projectName(e.project_id)}</td>}
                    <td>
                      <Badge tone={e.result === "success" ? undefined : e.result === "denied" ? "brass" : "crit"}>{e.result}</Badge>
                    </td>
                    <td className="mono small">{e.ip ?? "—"}</td>
                    <td className="actions">
                      <Button size="sm" variant="ghost" aria-expanded={open === e.id} onClick={() => setOpen(open === e.id ? null : e.id)}>
                        {open === e.id ? "Hide details" : "Details"}
                      </Button>
                    </td>
                  </tr>
                  {open === e.id && (
                    <tr>
                      <td colSpan={scope.kind === "tenant" ? 9 : 8}>
                        <pre className="json">
                          {JSON.stringify(
                            {
                              id: e.id,
                              metadata: e.metadata,
                              target_id: e.target_id,
                              environment_id: e.environment_id,
                              user_agent: e.user_agent,
                              request_id: e.request_id,
                              provider_request_id: e.provider_request_id,
                              prev_hash: e.prev_hash,
                              hash: e.hash,
                            },
                            null,
                            2,
                          )}
                        </pre>
                      </td>
                    </tr>
                  )}
                </Fragment>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {q.hasNextPage && (
        <div>
          <Button onClick={() => q.fetchNextPage()} busy={q.isFetchingNextPage}>
            Load older events
          </Button>
        </div>
      )}
    </div>
  );
}
