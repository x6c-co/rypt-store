import { describe, expect, it } from "vitest";
import { assignableRoles, can, canManageMember, type Action, type Role } from "./authz";

// The role table of core 7.5.
const table: Record<Action, Role[]> = {
  "secret.read": ["owner", "admin", "member", "viewer"],
  "secret.write": ["owner", "admin", "member"],
  "project.manage": ["owner", "admin"],
  "project.key_mode": ["owner", "admin"],
  "token.manage": ["owner", "admin"],
  "member.manage": ["owner", "admin"],
  "audit.read": ["owner", "admin"],
  "tenant.own": ["owner"],
};

describe("can", () => {
  for (const [action, roles] of Object.entries(table) as [Action, Role[]][]) {
    for (const role of ["owner", "admin", "member", "viewer"] as Role[]) {
      it(`${role} ${roles.includes(role) ? "may" : "may not"} ${action}`, () => {
        expect(can(role, action)).toBe(roles.includes(role));
      });
    }
  }
  it("denies without a role", () => {
    expect(can(undefined, "secret.read")).toBe(false);
  });
});

describe("member management", () => {
  it("lets admins manage roles below their own", () => {
    expect(assignableRoles("admin")).toEqual(["member", "viewer"]);
    expect(canManageMember("admin", "member")).toBe(true);
    expect(canManageMember("admin", "admin")).toBe(false);
    expect(canManageMember("admin", "owner")).toBe(false);
    expect(canManageMember("owner", "owner")).toBe(true);
    expect(canManageMember("member", "viewer")).toBe(false);
    expect(assignableRoles("viewer")).toEqual([]);
  });
});
