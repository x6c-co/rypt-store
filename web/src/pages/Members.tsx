import { useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { useParams } from "react-router";
import { api, call, type Schemas } from "../api/client";
import { qk, useInvitations, useMembers } from "../api/queries";
import { Confirm, Modal } from "../components/Dialog";
import { useToast } from "../components/Toast";
import { Badge, Button, CopyField, ErrorNotice, Loading, Notice, SelectField, TextField } from "../components/ui";
import { assignableRoles, can, canManageMember, type Role } from "../lib/authz";
import { formatDate, formatDateTime } from "../lib/format";
import { useCurrentMe, useRole } from "../session";
import { errorMessage } from "../api/errors";

const ROLE_HELP: Record<Role, string> = {
  owner: "Everything, including owner changes and deleting the tenant.",
  admin: "Manage projects, environments, tokens, members, and the audit log.",
  member: "Read and change secrets.",
  viewer: "Read secrets.",
};

export function MembersPage() {
  const { tenant = "" } = useParams();
  const me = useCurrentMe();
  const role = useRole(tenant);
  const qc = useQueryClient();
  const toast = useToast();
  const members = useMembers(tenant);
  const manage = can(role, "member.manage");
  const invitations = useInvitations(tenant, manage);
  const [inviting, setInviting] = useState(false);
  const [remove, setRemove] = useState<Schemas["Member"] | null>(null);
  const [resetLink, setResetLink] = useState<{ who: string; link: Schemas["OneTimeLink"] } | null>(null);
  const tenantName = me.tenants?.find((t) => t.slug === tenant)?.name ?? tenant;

  const changeRole = async (m: Schemas["Member"], newRole: Role) => {
    try {
      await call(api.PATCH("/api/v1/tenants/{tenant}/members/{user}", { params: { path: { tenant, user: m.user_id } }, body: { role: newRole } }));
      toast.show(`Changed ${m.display_name}'s role to ${newRole}.`);
      await qc.invalidateQueries({ queryKey: qk.members(tenant) });
    } catch (err) {
      toast.error(errorMessage(err));
    }
  };

  const createReset = async (m: Schemas["Member"]) => {
    try {
      const link = await call(api.POST("/api/v1/tenants/{tenant}/members/{user}/password-reset", { params: { path: { tenant, user: m.user_id } } }));
      setResetLink({ who: m.display_name, link });
    } catch (err) {
      toast.error(errorMessage(err));
    }
  };

  return (
    <>
      <div className="page-header">
        <h1>Members of {tenantName}</h1>
        {manage && (
          <Button variant="primary" onClick={() => setInviting(true)}>
            Invite member
          </Button>
        )}
      </div>
      {members.isPending ? (
        <Loading />
      ) : members.isError ? (
        <ErrorNotice error={members.error} />
      ) : (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Email</th>
                <th>Role</th>
                <th>Joined</th>
                <th>
                  <span className="visually-hidden">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {members.data.members.map((m) => {
                const self = m.user_id === me.user?.id;
                const editable = !self && canManageMember(role, m.role as Role);
                const options = assignableRoles(role);
                return (
                  <tr key={m.user_id}>
                    <td>
                      {m.display_name} {self && <Badge>you</Badge>}
                    </td>
                    <td>{m.email}</td>
                    <td>
                      {editable && options.length > 0 ? (
                        <select
                          className="select"
                          style={{ width: "auto" }}
                          aria-label={`Role of ${m.display_name}`}
                          value={m.role}
                          onChange={(e) => void changeRole(m, e.target.value as Role)}
                        >
                          {[m.role as Role, ...options.filter((r) => r !== m.role)].map((r) => (
                            <option key={r} value={r}>
                              {r}
                            </option>
                          ))}
                        </select>
                      ) : (
                        m.role
                      )}
                    </td>
                    <td className="nowrap">{formatDate(m.created_at)}</td>
                    <td className="actions">
                      {can(role, "tenant.own") && !self && (
                        <Button size="sm" onClick={() => createReset(m)}>
                          Create reset link
                        </Button>
                      )}{" "}
                      {editable && (
                        <Button size="sm" variant="ghost" onClick={() => setRemove(m)} aria-label={`Remove ${m.display_name}`}>
                          Remove
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

      {manage && invitations.data && invitations.data.invitations.some((i) => !i.accepted_at) && (
        <section className="stack-sm" aria-labelledby="inv-h">
          <h2 id="inv-h">Pending invitations</h2>
          <div className="table-wrap">
            <table className="table dense">
              <thead>
                <tr>
                  <th>Email</th>
                  <th>Role</th>
                  <th>Expires</th>
                </tr>
              </thead>
              <tbody>
                {invitations.data.invitations
                  .filter((i) => !i.accepted_at)
                  .map((i) => (
                    <tr key={i.id}>
                      <td>{i.email}</td>
                      <td>{i.role}</td>
                      <td className="nowrap">
                        {new Date(i.expires_at).getTime() < Date.now() ? <Badge tone="brass">Expired</Badge> : formatDateTime(i.expires_at)}
                      </td>
                    </tr>
                  ))}
              </tbody>
            </table>
          </div>
        </section>
      )}

      <InviteDialog tenant={tenant} open={inviting} onOpenChange={setInviting} roles={assignableRoles(role)} />
      <Confirm
        open={!!remove}
        onOpenChange={(o) => !o && setRemove(null)}
        title={`Remove ${remove?.display_name}?`}
        description={`${remove?.email} loses access to ${tenantName} at once.`}
        action="Remove member"
        onConfirm={async () => {
          await call(api.DELETE("/api/v1/tenants/{tenant}/members/{user}", { params: { path: { tenant, user: remove!.user_id } } }));
          toast.show(`Removed ${remove!.display_name}.`);
          await qc.invalidateQueries({ queryKey: qk.members(tenant) });
        }}
      />
      <Modal
        open={!!resetLink}
        onOpenChange={(o) => !o && setResetLink(null)}
        title={`Password reset link for ${resetLink?.who}`}
        footer={
          <Button variant="primary" onClick={() => setResetLink(null)}>
            Done
          </Button>
        }
      >
        {resetLink && (
          <div className="stack-sm">
            <CopyField label="Reset link" value={resetLink.link.url} copiedMessage="Copied the reset link." />
            <Notice tone="brass">
              This link is shown once and works until {formatDateTime(resetLink.link.expires_at)}. rypt-store sends no email; deliver it yourself.
            </Notice>
          </div>
        )}
      </Modal>
    </>
  );
}

function InviteDialog({ tenant, open, onOpenChange, roles }: { tenant: string; open: boolean; onOpenChange(o: boolean): void; roles: Role[] }) {
  const qc = useQueryClient();
  const toast = useToast();
  const [email, setEmail] = useState("");
  const [role, setRole] = useState<Role>("member");
  const [link, setLink] = useState<Schemas["OneTimeLink"] | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const reset = () => {
    setEmail("");
    setRole("member");
    setLink(null);
    setError(null);
  };
  return (
    <Modal
      open={open}
      onOpenChange={(o) => {
        if (!o) reset();
        onOpenChange(o);
      }}
      title="Invite member"
      footer={
        link ? (
          <Button variant="primary" onClick={() => (reset(), onOpenChange(false))}>
            Done
          </Button>
        ) : (
          <>
            <Button onClick={() => onOpenChange(false)}>Cancel</Button>
            <Button type="submit" form="invite-form" variant="primary" busy={busy}>
              Invite member
            </Button>
          </>
        )
      }
    >
      {link ? (
        <div className="stack-sm">
          <CopyField label="Invitation link" value={link.url} copiedMessage="Copied the invitation link." />
          <Notice tone="brass">
            This link is shown once and works until {formatDateTime(link.expires_at)}. rypt-store sends no email; send it to {email} yourself.
          </Notice>
        </div>
      ) : (
        <form
          id="invite-form"
          className="stack"
          onSubmit={async (e) => {
            e.preventDefault();
            setBusy(true);
            setError(null);
            try {
              const res = await call(api.POST("/api/v1/tenants/{tenant}/invitations", { params: { path: { tenant } }, body: { email: email.trim(), role } }));
              setLink(res.link);
              toast.show(`Invited ${email.trim()}.`);
              await qc.invalidateQueries({ queryKey: qk.invitations(tenant) });
            } catch (err) {
              setError(err);
            } finally {
              setBusy(false);
            }
          }}
        >
          <TextField label="Email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} required autoFocus />
          <SelectField label="Role" value={role} onChange={(e) => setRole(e.target.value as Role)} hint={ROLE_HELP[role]}>
            {roles.map((r) => (
              <option key={r} value={r}>
                {r}
              </option>
            ))}
          </SelectField>
          <ErrorNotice error={error} />
        </form>
      )}
    </Modal>
  );
}
