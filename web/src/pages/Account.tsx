import { useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { useParams } from "react-router";
import { api, call } from "../api/client";
import { qk, usePasskeys, useSessions } from "../api/queries";
import { AuditView } from "../components/AuditView";
import { Confirm, Modal } from "../components/Dialog";
import { PasskeyRegister, TotpEnroll } from "../components/MfaEnroll";
import { RecoveryCodes } from "../components/RecoveryCodes";
import { useToast } from "../components/Toast";
import { Badge, Button, ErrorNotice, KeyValue, Loading, TextField } from "../components/ui";
import { formatDateTime, relativeTime } from "../lib/format";
import { useCurrentMe } from "../session";
import { passwordProblem } from "./Setup";

export function TenantAuditPage() {
  const { tenant = "" } = useParams();
  const me = useCurrentMe();
  const name = me.tenants?.find((t) => t.slug === tenant)?.name ?? tenant;
  return (
    <>
      <div className="page-header">
        <h1>Audit log of {name}</h1>
      </div>
      <AuditView scope={{ kind: "tenant", tenant }} />
    </>
  );
}

export function AccountPage() {
  const me = useCurrentMe();
  return (
    <>
      <div className="page-header">
        <h1>Account</h1>
      </div>
      <section className="panel" aria-labelledby="profile-h">
        <h2 id="profile-h">Profile</h2>
        <KeyValue
          items={[
            ["Name", me.user?.display_name],
            ["Email", me.user?.email],
            ["Instance admin", me.user?.is_instance_admin ? "Yes" : "No"],
            ["User ID", <span className="mono">{me.user?.id}</span>],
          ]}
        />
      </section>
      <PasswordSection />
      <MfaSection />
      <SessionsSection />
    </>
  );
}

function PasswordSection() {
  const toast = useToast();
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [touched, setTouched] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  return (
    <section className="panel" aria-labelledby="pw-h">
      <h2 id="pw-h">Password</h2>
      <form
        className="stack"
        style={{ maxWidth: 420 }}
        onSubmit={async (e) => {
          e.preventDefault();
          setTouched(true);
          if (passwordProblem(next) || next !== confirm) return;
          setBusy(true);
          setError(null);
          try {
            await call(api.PUT("/api/v1/me/password", { body: { current_password: current, new_password: next } }));
            toast.show("Changed your password.");
            setCurrent("");
            setNext("");
            setConfirm("");
            setTouched(false);
          } catch (err) {
            setError(err);
          } finally {
            setBusy(false);
          }
        }}
      >
        <TextField label="Current password" type="password" value={current} onChange={(e) => setCurrent(e.target.value)} required autoComplete="current-password" />
        <TextField
          label="New password"
          type="password"
          hint="At least 12 characters."
          value={next}
          onChange={(e) => setNext(e.target.value)}
          required
          autoComplete="new-password"
          error={touched ? passwordProblem(next) : undefined}
        />
        <TextField
          label="Confirm new password"
          type="password"
          value={confirm}
          onChange={(e) => setConfirm(e.target.value)}
          required
          autoComplete="new-password"
          error={touched && confirm !== next ? "The passwords do not match." : undefined}
        />
        <ErrorNotice error={error} />
        <div>
          <Button type="submit" busy={busy}>
            Change password
          </Button>
        </div>
      </form>
    </section>
  );
}

function MfaSection() {
  const me = useCurrentMe();
  const qc = useQueryClient();
  const toast = useToast();
  const passkeys = usePasskeys();
  const [adding, setAdding] = useState<"totp" | "passkey" | null>(null);
  const [codes, setCodes] = useState<string[] | null>(null);
  const [removeTotp, setRemoveTotp] = useState(false);
  const [removeKey, setRemoveKey] = useState<{ id: string; name: string } | null>(null);
  const [regen, setRegen] = useState(false);
  const mfa = me.mfa;
  const factors = (mfa?.totp ? 1 : 0) + (mfa?.passkeys ?? 0);
  const lastFactor = !!mfa?.required && factors <= 1;
  const refresh = async () => {
    await qc.invalidateQueries({ queryKey: qk.me });
    await qc.invalidateQueries({ queryKey: qk.passkeys });
  };
  const enrolled = async (c: string[]) => {
    setAdding(null);
    if (c.length > 0) setCodes(c);
    toast.show("Added a second factor.");
    await refresh();
  };

  return (
    <section className="panel stack" aria-labelledby="mfa-h">
      <div className="row-between">
        <h2 id="mfa-h">Two-factor sign-in</h2>
        {mfa?.required && <Badge tone="seal">Required on this server</Badge>}
      </div>

      <div className="row-between">
        <div>
          <strong>Authenticator app</strong>
          <div className="small muted">{mfa?.totp ? "Enrolled." : "Not set up."}</div>
        </div>
        {mfa?.totp ? (
          <Button size="sm" variant="ghost" disabled={lastFactor} title={lastFactor ? "Add another factor before removing your only one." : undefined} onClick={() => setRemoveTotp(true)}>
            Remove authenticator app
          </Button>
        ) : (
          <Button size="sm" onClick={() => setAdding("totp")}>
            Set up authenticator app
          </Button>
        )}
      </div>

      <div className="stack-sm">
        <div className="row-between">
          <strong>Passkeys</strong>
          <Button size="sm" onClick={() => setAdding("passkey")}>
            Add passkey
          </Button>
        </div>
        {passkeys.isPending ? (
          <Loading />
        ) : passkeys.isError ? (
          <ErrorNotice error={passkeys.error} />
        ) : passkeys.data.passkeys.length === 0 ? (
          <span className="small muted">No passkeys.</span>
        ) : (
          <div className="table-wrap">
            <table className="table dense">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Added</th>
                  <th>Last used</th>
                  <th>
                    <span className="visually-hidden">Actions</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {passkeys.data.passkeys.map((p) => (
                  <tr key={p.id}>
                    <td>{p.name}</td>
                    <td className="nowrap">{formatDateTime(p.created_at)}</td>
                    <td className="nowrap">{relativeTime(p.last_used_at)}</td>
                    <td className="actions">
                      <Button size="sm" variant="ghost" disabled={lastFactor} onClick={() => setRemoveKey({ id: p.id, name: p.name })} aria-label={`Remove passkey ${p.name}`}>
                        Remove
                      </Button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <div className="row-between">
        <div>
          <strong>Recovery codes</strong>
          <div className="small muted">{mfa?.recovery_codes_remaining ?? 0} unused.</div>
        </div>
        {factors > 0 && (
          <Button size="sm" onClick={() => setRegen(true)}>
            Regenerate recovery codes
          </Button>
        )}
      </div>

      <Modal open={adding !== null} onOpenChange={(o) => !o && setAdding(null)} title={adding === "totp" ? "Set up authenticator app" : "Add passkey"}>
        {adding === "totp" ? <TotpEnroll onEnrolled={enrolled} /> : <PasskeyRegister onRegistered={enrolled} />}
      </Modal>
      <Modal
        open={!!codes}
        onOpenChange={(o) => !o && setCodes(null)}
        title="Recovery codes"
        footer={
          <Button variant="primary" onClick={() => setCodes(null)}>
            Done
          </Button>
        }
      >
        <RecoveryCodes codes={codes ?? []} />
      </Modal>
      <Confirm
        open={removeTotp}
        onOpenChange={setRemoveTotp}
        title="Remove authenticator app?"
        description="Codes from the app will no longer sign you in."
        action="Remove authenticator app"
        onConfirm={async () => {
          await call(api.DELETE("/api/v1/me/mfa/totp"));
          toast.show("Removed the authenticator app.");
          await refresh();
        }}
      />
      <Confirm
        open={!!removeKey}
        onOpenChange={(o) => !o && setRemoveKey(null)}
        title={`Remove passkey ${removeKey?.name}?`}
        description="This passkey will no longer sign you in."
        action="Remove passkey"
        onConfirm={async () => {
          await call(api.DELETE("/api/v1/me/mfa/webauthn/{id}", { params: { path: { id: removeKey!.id } } }));
          toast.show(`Removed passkey ${removeKey!.name}.`);
          await refresh();
        }}
      />
      <Confirm
        open={regen}
        onOpenChange={setRegen}
        title="Regenerate recovery codes?"
        description="Your current recovery codes stop working."
        action="Regenerate recovery codes"
        onConfirm={async () => {
          const res = await call(api.POST("/api/v1/me/mfa/recovery-codes"));
          setCodes(res.recovery_codes);
          toast.show("Regenerated your recovery codes.");
          await refresh();
        }}
      />
    </section>
  );
}

function SessionsSection() {
  const qc = useQueryClient();
  const toast = useToast();
  const sessions = useSessions();
  const [revoke, setRevoke] = useState<string | null>(null);
  return (
    <section className="panel stack-sm" aria-labelledby="sessions-h">
      <h2 id="sessions-h">Sessions</h2>
      {sessions.isPending ? (
        <Loading />
      ) : sessions.isError ? (
        <ErrorNotice error={sessions.error} />
      ) : (
        <div className="table-wrap">
          <table className="table dense">
            <thead>
              <tr>
                <th>Kind</th>
                <th>Last seen</th>
                <th>Started</th>
                <th>Expires</th>
                <th>IP</th>
                <th>Browser or client</th>
                <th>
                  <span className="visually-hidden">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {sessions.data.sessions.map((s) => (
                <tr key={s.id}>
                  <td>
                    {s.kind === "cli" ? "CLI" : "Web"} {s.current && <Badge tone="seal">this session</Badge>}
                  </td>
                  <td className="nowrap">{relativeTime(s.last_seen_at)}</td>
                  <td className="nowrap">{formatDateTime(s.created_at)}</td>
                  <td className="nowrap">{formatDateTime(s.expires_at)}</td>
                  <td className="mono small">{s.ip ?? "—"}</td>
                  <td className="small" style={{ maxWidth: 260, overflowWrap: "anywhere" }}>
                    {s.user_agent ?? "—"}
                  </td>
                  <td className="actions">
                    {!s.current && (
                      <Button size="sm" variant="ghost" onClick={() => setRevoke(s.id)}>
                        Revoke
                      </Button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <Confirm
        open={!!revoke}
        onOpenChange={(o) => !o && setRevoke(null)}
        title="Revoke session?"
        description="That browser or CLI is signed out at once."
        action="Revoke session"
        onConfirm={async () => {
          await call(api.DELETE("/api/v1/me/sessions/{id}", { params: { path: { id: revoke! } } }));
          toast.show("Revoked the session.");
          await qc.invalidateQueries({ queryKey: qk.sessions });
        }}
      />
    </section>
  );
}
