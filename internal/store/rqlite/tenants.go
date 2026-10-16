package rqlite

import (
	"context"
	"time"

	"github.com/x6c-co/rypt-store/internal/store"
)

// ---- tenants ----

const tenantCols = "id, name, slug, created_at, deleted_at"

func insertTenantStmts(t store.Tenant) []stmt {
	return []stmt{
		st("INSERT INTO tenants ("+tenantCols+") VALUES (?, ?, ?, ?, ?)", t.ID, t.Name, t.Slug, t.CreatedAt, t.DeletedAt),
		st("INSERT INTO audit_chains (chain_id, head_seq, head_hash, anchor_seq, anchor_hash, updated_at) VALUES (?, 0, ?, 0, ?, ?)",
			t.ID, zeroHash, zeroHash, t.CreatedAt),
	}
}

func (s *Store) CreateTenant(ctx context.Context, t store.Tenant, owner *store.Membership, ev *store.AuditEvent) error {
	var b batch
	b.audit(ev)
	b.addAll(insertTenantStmts(t)...)
	if owner != nil {
		b.add("INSERT INTO tenant_memberships (tenant_id, user_id, role, created_at) VALUES (?, ?, ?, ?)",
			owner.TenantID, owner.UserID, owner.Role, owner.CreatedAt)
	}
	return s.execBatch(ctx, b)
}

func (s *Store) getTenant(ctx context.Context, where string, arg any) (*store.Tenant, error) {
	var t store.Tenant
	err := s.queryOne(ctx, store.Strong, "SELECT "+tenantCols+" FROM tenants WHERE deleted_at IS NULL AND "+where, []any{arg},
		&t.ID, &t.Name, &t.Slug, &t.CreatedAt, &t.DeletedAt)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

func (s *Store) GetTenant(ctx context.Context, id string) (*store.Tenant, error) {
	return s.getTenant(ctx, "id = ?", id)
}

func (s *Store) GetTenantBySlug(ctx context.Context, slug string) (*store.Tenant, error) {
	return s.getTenant(ctx, "slug = ?", slug)
}

func (s *Store) ListAllTenants(ctx context.Context) ([]store.Tenant, error) {
	r, err := s.query(ctx, store.Weak, "SELECT "+tenantCols+" FROM tenants WHERE deleted_at IS NULL ORDER BY name")
	if err != nil {
		return nil, err
	}
	var out []store.Tenant
	for r.next() {
		var t store.Tenant
		if err := r.scan(&t.ID, &t.Name, &t.Slug, &t.CreatedAt, &t.DeletedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, nil
}

func (s *Store) ListTenantsForUser(ctx context.Context, userID string) ([]store.TenantWithRole, error) {
	r, err := s.query(ctx, store.Strong, `SELECT t.id, t.name, t.slug, t.created_at, t.deleted_at, m.role
		FROM tenants t JOIN tenant_memberships m ON m.tenant_id = t.id
		WHERE m.user_id = ? AND t.deleted_at IS NULL ORDER BY t.name`, userID)
	if err != nil {
		return nil, err
	}
	var out []store.TenantWithRole
	for r.next() {
		var t store.TenantWithRole
		if err := r.scan(&t.ID, &t.Name, &t.Slug, &t.CreatedAt, &t.DeletedAt, &t.Role); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, nil
}

// ---- memberships ----

func (s *Store) GetMembership(ctx context.Context, tenantID, userID string) (*store.Membership, error) {
	var m store.Membership
	err := s.queryOne(ctx, store.Strong, "SELECT tenant_id, user_id, role, created_at FROM tenant_memberships WHERE tenant_id = ? AND user_id = ?",
		[]any{tenantID, userID}, &m.TenantID, &m.UserID, &m.Role, &m.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &m, nil
}

func (s *Store) ListMembers(ctx context.Context, tenantID string) ([]store.Member, error) {
	r, err := s.query(ctx, store.Weak, `SELECT m.tenant_id, m.user_id, m.role, m.created_at, u.email, u.display_name
		FROM tenant_memberships m JOIN users u ON u.id = m.user_id WHERE m.tenant_id = ? ORDER BY u.email`, tenantID)
	if err != nil {
		return nil, err
	}
	var out []store.Member
	for r.next() {
		var m store.Member
		if err := r.scan(&m.TenantID, &m.UserID, &m.Role, &m.CreatedAt, &m.Email, &m.DisplayName); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, nil
}

const ownerGuard = "SELECT CASE WHEN COUNT(*) >= 1 THEN 1 ELSE 0 END FROM tenant_memberships WHERE tenant_id = ? AND role = 'owner'"

func (s *Store) UpdateMemberRole(ctx context.Context, tenantID, userID, role string, ev *store.AuditEvent) error {
	var b batch
	b.audit(ev)
	b.guard(store.ErrNotFound, "SELECT COUNT(*) FROM tenant_memberships WHERE tenant_id = ? AND user_id = ?", tenantID, userID)
	b.add("UPDATE tenant_memberships SET role = ? WHERE tenant_id = ? AND user_id = ?", role, tenantID, userID)
	b.guard(store.Conflict("a tenant needs at least one owner"), ownerGuard, tenantID)
	return s.execBatch(ctx, b)
}

func (s *Store) DeleteMember(ctx context.Context, tenantID, userID string, ev *store.AuditEvent) error {
	var b batch
	b.audit(ev)
	b.guard(store.ErrNotFound, "SELECT COUNT(*) FROM tenant_memberships WHERE tenant_id = ? AND user_id = ?", tenantID, userID)
	b.add("DELETE FROM tenant_memberships WHERE tenant_id = ? AND user_id = ?", tenantID, userID)
	b.guard(store.Conflict("a tenant needs at least one owner"), ownerGuard, tenantID)
	return s.execBatch(ctx, b)
}

// ---- invitations ----

const invitationCols = "id, tenant_id, email, role, token_hash, expires_at, accepted_at, created_by, created_at"

func scanInvitation(r *rows) (store.Invitation, error) {
	var i store.Invitation
	err := r.scan(&i.ID, &i.TenantID, &i.Email, &i.Role, &i.TokenHash, &i.ExpiresAt, &i.AcceptedAt, &i.CreatedBy, &i.CreatedAt)
	return i, err
}

func (s *Store) CreateInvitation(ctx context.Context, inv store.Invitation, ev *store.AuditEvent) error {
	var b batch
	b.audit(ev)
	b.add("INSERT INTO invitations ("+invitationCols+") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
		inv.ID, inv.TenantID, inv.Email, inv.Role, inv.TokenHash, inv.ExpiresAt, inv.AcceptedAt, inv.CreatedBy, inv.CreatedAt)
	return s.execBatch(ctx, b)
}

func (s *Store) GetInvitationByHash(ctx context.Context, tokenHash string) (*store.Invitation, error) {
	r, err := s.query(ctx, store.Strong, "SELECT "+invitationCols+" FROM invitations WHERE token_hash = ?", tokenHash)
	if err != nil {
		return nil, err
	}
	if !r.next() {
		return nil, store.ErrNotFound
	}
	i, err := scanInvitation(r)
	return &i, err
}

func (s *Store) ListInvitations(ctx context.Context, tenantID string) ([]store.Invitation, error) {
	r, err := s.query(ctx, store.Weak, "SELECT "+invitationCols+" FROM invitations WHERE tenant_id = ? ORDER BY created_at DESC", tenantID)
	if err != nil {
		return nil, err
	}
	var out []store.Invitation
	for r.next() {
		i, err := scanInvitation(r)
		if err != nil {
			return nil, err
		}
		out = append(out, i)
	}
	return out, nil
}

func (s *Store) AcceptInvitation(ctx context.Context, inv store.Invitation, newUser *store.User, m store.Membership, at time.Time, ev *store.AuditEvent) error {
	var b batch
	b.audit(ev)
	b.guard(store.Conflict("invitation already accepted"), "SELECT COUNT(*) FROM invitations WHERE id = ? AND accepted_at IS NULL", inv.ID)
	b.add("UPDATE invitations SET accepted_at = ? WHERE id = ?", at, inv.ID)
	if newUser != nil {
		b.addAll(insertUserStmt(*newUser))
	}
	b.add("INSERT INTO tenant_memberships (tenant_id, user_id, role, created_at) VALUES (?, ?, ?, ?)", m.TenantID, m.UserID, m.Role, m.CreatedAt)
	return s.execBatch(ctx, b)
}

// ---- projects ----

const projectCols = "id, tenant_id, name, slug, key_mode, created_at, deleted_at"

func scanProject(r *rows) (store.Project, error) {
	var p store.Project
	err := r.scan(&p.ID, &p.TenantID, &p.Name, &p.Slug, &p.KeyMode, &p.CreatedAt, &p.DeletedAt)
	return p, err
}

func (s *Store) CreateProject(ctx context.Context, p store.Project, envs []store.Environment, wraps []store.KeyWrap, ev *store.AuditEvent) error {
	var b batch
	b.audit(ev)
	b.add("INSERT INTO projects ("+projectCols+") VALUES (?, ?, ?, ?, ?, ?, ?)", p.ID, p.TenantID, p.Name, p.Slug, p.KeyMode, p.CreatedAt, p.DeletedAt)
	for _, e := range envs {
		b.addAll(insertEnvStmt(e))
	}
	for _, w := range wraps {
		b.addAll(insertWrapStmt(w))
	}
	return s.execBatch(ctx, b)
}

func (s *Store) getProject(ctx context.Context, tenantID, where string, arg any) (*store.Project, error) {
	r, err := s.query(ctx, store.Strong, "SELECT "+projectCols+" FROM projects WHERE tenant_id = ? AND deleted_at IS NULL AND "+where, tenantID, arg)
	if err != nil {
		return nil, err
	}
	if !r.next() {
		return nil, store.ErrNotFound
	}
	p, err := scanProject(r)
	return &p, err
}

func (s *Store) GetProject(ctx context.Context, tenantID, id string) (*store.Project, error) {
	return s.getProject(ctx, tenantID, "id = ?", id)
}

func (s *Store) GetProjectBySlug(ctx context.Context, tenantID, slug string) (*store.Project, error) {
	return s.getProject(ctx, tenantID, "slug = ?", slug)
}

func (s *Store) listProjects(ctx context.Context, sql string, args ...any) ([]store.Project, error) {
	r, err := s.query(ctx, store.Strong, sql, args...)
	if err != nil {
		return nil, err
	}
	var out []store.Project
	for r.next() {
		p, err := scanProject(r)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

func (s *Store) ListProjects(ctx context.Context, tenantID string) ([]store.Project, error) {
	return s.listProjects(ctx, "SELECT "+projectCols+" FROM projects WHERE tenant_id = ? AND deleted_at IS NULL ORDER BY name", tenantID)
}

func (s *Store) ListAllProjects(ctx context.Context, afterID string) ([]store.Project, error) {
	return s.listProjects(ctx, "SELECT "+projectCols+" FROM projects WHERE deleted_at IS NULL AND id > ? ORDER BY id", afterID)
}

func (s *Store) UpdateProject(ctx context.Context, tenantID, id, name, slug string, ev *store.AuditEvent) error {
	var b batch
	b.audit(ev)
	b.guard(store.ErrNotFound, "SELECT COUNT(*) FROM projects WHERE id = ? AND tenant_id = ? AND deleted_at IS NULL", id, tenantID)
	b.add("UPDATE projects SET name = ?, slug = ? WHERE id = ? AND tenant_id = ?", name, slug, id, tenantID)
	return s.execBatch(ctx, b)
}

func (s *Store) DeleteProject(ctx context.Context, tenantID, id string, at time.Time, ev *store.AuditEvent) error {
	var b batch
	b.audit(ev)
	b.guard(store.ErrNotFound, "SELECT COUNT(*) FROM projects WHERE id = ? AND tenant_id = ? AND deleted_at IS NULL", id, tenantID)
	b.add("UPDATE projects SET deleted_at = ? WHERE id = ? AND tenant_id = ?", at, id, tenantID)
	// A deleted project's tokens stop working at once.
	b.add("UPDATE service_tokens SET revoked_at = ? WHERE project_id = ? AND tenant_id = ? AND revoked_at IS NULL", at, id, tenantID)
	return s.execBatch(ctx, b)
}

// ---- environments ----

const envCols = "id, tenant_id, project_id, name, slug, position, created_at"

func insertEnvStmt(e store.Environment) stmt {
	return st("INSERT INTO environments ("+envCols+") VALUES (?, ?, ?, ?, ?, ?, ?)",
		e.ID, e.TenantID, e.ProjectID, e.Name, e.Slug, e.Position, e.CreatedAt)
}

func scanEnv(r *rows) (store.Environment, error) {
	var e store.Environment
	err := r.scan(&e.ID, &e.TenantID, &e.ProjectID, &e.Name, &e.Slug, &e.Position, &e.CreatedAt)
	return e, err
}

func (s *Store) CreateEnvironment(ctx context.Context, e store.Environment, ev *store.AuditEvent) error {
	var b batch
	b.audit(ev)
	b.addAll(insertEnvStmt(e))
	return s.execBatch(ctx, b)
}

func (s *Store) getEnv(ctx context.Context, sql string, args ...any) (*store.Environment, error) {
	r, err := s.query(ctx, store.Strong, "SELECT "+envCols+" FROM environments WHERE "+sql, args...)
	if err != nil {
		return nil, err
	}
	if !r.next() {
		return nil, store.ErrNotFound
	}
	e, err := scanEnv(r)
	return &e, err
}

func (s *Store) GetEnvironment(ctx context.Context, tenantID, id string) (*store.Environment, error) {
	return s.getEnv(ctx, "tenant_id = ? AND id = ?", tenantID, id)
}

func (s *Store) GetEnvironmentBySlug(ctx context.Context, tenantID, projectID, slug string) (*store.Environment, error) {
	return s.getEnv(ctx, "tenant_id = ? AND project_id = ? AND slug = ?", tenantID, projectID, slug)
}

func (s *Store) ListEnvironments(ctx context.Context, tenantID, projectID string) ([]store.Environment, error) {
	r, err := s.query(ctx, store.Strong, "SELECT "+envCols+" FROM environments WHERE tenant_id = ? AND project_id = ? ORDER BY position, name", tenantID, projectID)
	if err != nil {
		return nil, err
	}
	var out []store.Environment
	for r.next() {
		e, err := scanEnv(r)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, nil
}

func (s *Store) UpdateEnvironment(ctx context.Context, tenantID, id, name, slug string, position int, ev *store.AuditEvent) error {
	var b batch
	b.audit(ev)
	b.guard(store.ErrNotFound, "SELECT COUNT(*) FROM environments WHERE id = ? AND tenant_id = ?", id, tenantID)
	b.add("UPDATE environments SET name = ?, slug = ?, position = ? WHERE id = ? AND tenant_id = ?", name, slug, position, id, tenantID)
	return s.execBatch(ctx, b)
}

func (s *Store) DeleteEnvironment(ctx context.Context, tenantID, id string, ev *store.AuditEvent) error {
	var b batch
	b.audit(ev)
	b.guard(store.ErrNotFound, "SELECT COUNT(*) FROM environments WHERE id = ? AND tenant_id = ?", id, tenantID)
	b.add(`DELETE FROM key_wraps WHERE key_kind = 'dek' AND key_id IN (
		SELECT v.dek_id FROM secret_versions v JOIN secrets s ON s.id = v.secret_id
		WHERE s.environment_id = ? AND s.tenant_id = ?)`, id, tenantID)
	b.add("DELETE FROM secret_versions WHERE secret_id IN (SELECT id FROM secrets WHERE environment_id = ? AND tenant_id = ?)", id, tenantID)
	b.add("DELETE FROM secrets WHERE environment_id = ? AND tenant_id = ?", id, tenantID)
	b.add("DELETE FROM service_token_environments WHERE environment_id = ?", id)
	b.add("DELETE FROM environments WHERE id = ? AND tenant_id = ?", id, tenantID)
	return s.execBatch(ctx, b)
}
