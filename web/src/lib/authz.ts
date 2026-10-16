// Mirrors the role table of core 7.5 so the UI hides actions a role cannot
// take. The server decides; this only avoids offering refused actions.

export type Role = "owner" | "admin" | "member" | "viewer";

export type Action =
  | "secret.read"
  | "secret.write"
  | "project.manage"
  | "project.key_mode"
  | "token.manage"
  | "member.manage"
  | "audit.read"
  | "tenant.own";

const allowed: Record<Action, Role[]> = {
  "secret.read": ["owner", "admin", "member", "viewer"],
  "secret.write": ["owner", "admin", "member"],
  "project.manage": ["owner", "admin"],
  "project.key_mode": ["owner", "admin"],
  "token.manage": ["owner", "admin"],
  "member.manage": ["owner", "admin"],
  "audit.read": ["owner", "admin"],
  "tenant.own": ["owner"],
};

export function can(role: Role | undefined | null, action: Action): boolean {
  return !!role && allowed[action].includes(role);
}

const rank: Record<Role, number> = { viewer: 0, member: 1, admin: 2, owner: 3 };

/** Roles an actor may assign: below their own, or any role for an owner. */
export function assignableRoles(actor: Role | undefined | null): Role[] {
  if (actor === "owner") return ["owner", "admin", "member", "viewer"];
  if (actor === "admin") return ["member", "viewer"];
  return [];
}

/** Whether actor may change or remove a member holding role target. */
export function canManageMember(actor: Role | undefined | null, target: Role): boolean {
  if (!actor || !can(actor, "member.manage")) return false;
  if (actor === "owner") return true;
  return rank[target] < rank[actor];
}
