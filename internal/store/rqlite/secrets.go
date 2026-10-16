package rqlite

import (
	"context"
	"strings"
	"time"

	"github.com/x6c-co/rypt-store/internal/store"
)

// secretSelect joins each secret with its current version's author.
const secretSelect = `SELECT s.id, s.tenant_id, s.project_id, s.environment_id, s.name, s.comment, s.current_version,
	s.created_at, s.updated_at, s.deleted_at, v.created_by_kind, v.created_by_id
	FROM secrets s LEFT JOIN secret_versions v ON v.secret_id = s.id AND v.version = s.current_version`

func scanSecret(r *rows) (store.Secret, error) {
	var x store.Secret
	err := r.scan(&x.ID, &x.TenantID, &x.ProjectID, &x.EnvironmentID, &x.Name, &x.Comment, &x.CurrentVersion,
		&x.CreatedAt, &x.UpdatedAt, &x.DeletedAt, &x.UpdatedByKind, &x.UpdatedByID)
	return x, err
}

func (s *Store) listSecrets(ctx context.Context, c store.Consistency, where string, args ...any) ([]store.Secret, error) {
	r, err := s.query(ctx, c, secretSelect+" WHERE "+where, args...)
	if err != nil {
		return nil, err
	}
	var out []store.Secret
	for r.next() {
		x, err := scanSecret(r)
		if err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, nil
}

func (s *Store) ListSecrets(ctx context.Context, tenantID, envID string) ([]store.Secret, error) {
	return s.listSecrets(ctx, store.Weak, "s.tenant_id = ? AND s.environment_id = ? AND s.deleted_at IS NULL ORDER BY s.name", tenantID, envID)
}

func (s *Store) ListDeletedSecrets(ctx context.Context, tenantID, envID string) ([]store.Secret, error) {
	return s.listSecrets(ctx, store.Weak, "s.tenant_id = ? AND s.environment_id = ? AND s.deleted_at IS NOT NULL ORDER BY s.deleted_at DESC", tenantID, envID)
}

func (s *Store) one(xs []store.Secret, err error) (*store.Secret, error) {
	if err != nil {
		return nil, err
	}
	if len(xs) == 0 {
		return nil, store.ErrNotFound
	}
	return &xs[0], nil
}

func (s *Store) GetSecretByName(ctx context.Context, tenantID, envID, name string) (*store.Secret, error) {
	return s.one(s.listSecrets(ctx, store.Strong, "s.tenant_id = ? AND s.environment_id = ? AND s.name = ? AND s.deleted_at IS NULL", tenantID, envID, name))
}

func (s *Store) GetSecret(ctx context.Context, tenantID, id string) (*store.Secret, error) {
	return s.one(s.listSecrets(ctx, store.Strong, "s.tenant_id = ? AND s.id = ?", tenantID, id))
}

const versionCols = "id, tenant_id, secret_id, version, dek_id, ciphertext, value_mac, created_by_kind, created_by_id, created_at, restored_from"

func scanVersion(r *rows, dest *store.SecretVersion) error {
	return r.scan(&dest.ID, &dest.TenantID, &dest.SecretID, &dest.Version, &dest.DEKID, &dest.Ciphertext, &dest.ValueMAC,
		&dest.CreatedByKind, &dest.CreatedByID, &dest.CreatedAt, &dest.RestoredFrom)
}

func insertVersionStmt(v store.SecretVersion) stmt {
	return st("INSERT INTO secret_versions ("+versionCols+") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
		v.ID, v.TenantID, v.SecretID, v.Version, v.DEKID, v.Ciphertext, v.ValueMAC, v.CreatedByKind, v.CreatedByID, v.CreatedAt, v.RestoredFrom)
}

func (s *Store) GetSecretVersion(ctx context.Context, tenantID, secretID string, version int) (*store.SecretVersion, error) {
	r, err := s.query(ctx, store.Strong, "SELECT "+versionCols+" FROM secret_versions WHERE tenant_id = ? AND secret_id = ? AND version = ?", tenantID, secretID, version)
	if err != nil {
		return nil, err
	}
	if !r.next() {
		return nil, store.ErrNotFound
	}
	var v store.SecretVersion
	return &v, scanVersion(r, &v)
}

func (s *Store) ListSecretVersions(ctx context.Context, tenantID, secretID string) ([]store.SecretVersion, error) {
	r, err := s.query(ctx, store.Weak, "SELECT "+versionCols+" FROM secret_versions WHERE tenant_id = ? AND secret_id = ? ORDER BY version DESC", tenantID, secretID)
	if err != nil {
		return nil, err
	}
	var out []store.SecretVersion
	for r.next() {
		var v store.SecretVersion
		if err := scanVersion(r, &v); err != nil {
			return nil, err
		}
		// History never carries values.
		v.Ciphertext, v.ValueMAC = nil, nil
		out = append(out, v)
	}
	return out, nil
}

func (s *Store) CreateSecret(ctx context.Context, x store.Secret, v store.SecretVersion, dek store.KeyWrap, ev *store.AuditEvent) error {
	var b batch
	b.audit(ev)
	b.guard(store.ErrNotFound, "SELECT COUNT(*) FROM environments WHERE id = ? AND tenant_id = ? AND project_id = ?", x.EnvironmentID, x.TenantID, x.ProjectID)
	b.add(`INSERT INTO secrets (id, tenant_id, project_id, environment_id, name, comment, current_version, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)`, x.ID, x.TenantID, x.ProjectID, x.EnvironmentID, x.Name, x.Comment, x.CreatedAt, x.UpdatedAt)
	b.addAll(insertWrapStmt(dek), insertVersionStmt(v))
	return s.execBatch(ctx, b)
}

func (s *Store) WriteSecretVersion(ctx context.Context, x store.Secret, expected int, comment *string, v store.SecretVersion, dek store.KeyWrap, ev *store.AuditEvent) error {
	var b batch
	b.audit(ev)
	// The guard and UNIQUE (secret_id, version) both make a stale writer fail.
	b.guard(store.Conflict("the secret has a newer version"),
		"SELECT COUNT(*) FROM secrets WHERE id = ? AND tenant_id = ? AND current_version = ? AND deleted_at IS NULL", x.ID, x.TenantID, expected)
	if comment != nil {
		b.add("UPDATE secrets SET current_version = ?, comment = ?, updated_at = ? WHERE id = ? AND current_version = ?", v.Version, *comment, v.CreatedAt, x.ID, expected)
	} else {
		b.add("UPDATE secrets SET current_version = ?, updated_at = ? WHERE id = ? AND current_version = ?", v.Version, v.CreatedAt, x.ID, expected)
	}
	b.addAll(insertWrapStmt(dek), insertVersionStmt(v))
	return s.execBatch(ctx, b)
}

func (s *Store) SoftDeleteSecret(ctx context.Context, tenantID, id string, at time.Time, ev *store.AuditEvent) error {
	var b batch
	b.audit(ev)
	b.guard(store.ErrNotFound, "SELECT COUNT(*) FROM secrets WHERE id = ? AND tenant_id = ? AND deleted_at IS NULL", id, tenantID)
	b.add("UPDATE secrets SET deleted_at = ? WHERE id = ? AND tenant_id = ?", at, id, tenantID)
	return s.execBatch(ctx, b)
}

func (s *Store) RestoreDeletedSecret(ctx context.Context, tenantID, id string, at time.Time, ev *store.AuditEvent) error {
	var b batch
	b.audit(ev)
	b.guard(store.ErrNotFound, "SELECT COUNT(*) FROM secrets WHERE id = ? AND tenant_id = ? AND deleted_at IS NOT NULL", id, tenantID)
	// The partial unique index on live names fails this when the name is taken.
	b.add("UPDATE secrets SET deleted_at = NULL, updated_at = ? WHERE id = ? AND tenant_id = ?", at, id, tenantID)
	return s.execBatch(ctx, b)
}

func (s *Store) PruneSecretVersions(ctx context.Context, tenantID, secretID string, keep int) (int, error) {
	var current int
	if err := s.queryOne(ctx, store.Strong, "SELECT current_version FROM secrets WHERE id = ? AND tenant_id = ?", []any{secretID, tenantID}, &current); err != nil {
		return 0, err
	}
	cutoff := current - keep // versions <= cutoff go
	if cutoff < 1 {
		return 0, nil
	}
	n, err := s.exec(ctx,
		st("DELETE FROM key_wraps WHERE key_kind = 'dek' AND key_id IN (SELECT dek_id FROM secret_versions WHERE secret_id = ? AND tenant_id = ? AND version <= ?)", secretID, tenantID, cutoff),
		st("DELETE FROM secret_versions WHERE secret_id = ? AND tenant_id = ? AND version <= ?", secretID, tenantID, cutoff),
	)
	if err != nil {
		return 0, err
	}
	return int(n[1]), nil
}

func (s *Store) ListPurgeableSecrets(ctx context.Context, before time.Time, limit int) ([]store.Secret, error) {
	return s.listSecrets(ctx, store.Strong, "s.deleted_at IS NOT NULL AND s.deleted_at < ? ORDER BY s.deleted_at LIMIT ?", before, limit)
}

func (s *Store) PurgeSecret(ctx context.Context, tenantID, id string, ev *store.AuditEvent) error {
	var b batch
	b.audit(ev)
	b.guard(store.ErrNotFound, "SELECT COUNT(*) FROM secrets WHERE id = ? AND tenant_id = ? AND deleted_at IS NOT NULL", id, tenantID)
	b.add("DELETE FROM key_wraps WHERE key_kind = 'dek' AND key_id IN (SELECT dek_id FROM secret_versions WHERE secret_id = ? AND tenant_id = ?)", id, tenantID)
	b.add("DELETE FROM secret_versions WHERE secret_id = ? AND tenant_id = ?", id, tenantID)
	b.add("DELETE FROM secrets WHERE id = ? AND tenant_id = ?", id, tenantID)
	return s.execBatch(ctx, b)
}

func (s *Store) ListCurrentValues(ctx context.Context, tenantID, envID string) ([]store.CurrentValue, error) {
	r, err := s.query(ctx, store.Strong, `SELECT s.id, s.name, s.current_version, s.project_id, `+prefixed("v.", versionCols)+`
		FROM secrets s JOIN secret_versions v ON v.secret_id = s.id AND v.version = s.current_version
		WHERE s.tenant_id = ? AND s.environment_id = ? AND s.deleted_at IS NULL ORDER BY s.name`, tenantID, envID)
	if err != nil {
		return nil, err
	}
	var out []store.CurrentValue
	for r.next() {
		var c store.CurrentValue
		v := &c.Version
		if err := r.scan(&c.Secret.ID, &c.Secret.Name, &c.Secret.CurrentVersion, &c.Secret.ProjectID,
			&v.ID, &v.TenantID, &v.SecretID, &v.Version, &v.DEKID, &v.Ciphertext, &v.ValueMAC,
			&v.CreatedByKind, &v.CreatedByID, &v.CreatedAt, &v.RestoredFrom); err != nil {
			return nil, err
		}
		c.Secret.TenantID, c.Secret.EnvironmentID = tenantID, envID
		out = append(out, c)
	}
	return out, nil
}

func (s *Store) ListCompareCells(ctx context.Context, tenantID, projectID string) ([]store.CompareCell, error) {
	r, err := s.query(ctx, store.Weak, `SELECT s.environment_id, s.name, v.value_mac
		FROM secrets s JOIN secret_versions v ON v.secret_id = s.id AND v.version = s.current_version
		WHERE s.tenant_id = ? AND s.project_id = ? AND s.deleted_at IS NULL ORDER BY s.name`, tenantID, projectID)
	if err != nil {
		return nil, err
	}
	var out []store.CompareCell
	for r.next() {
		var c store.CompareCell
		if err := r.scan(&c.EnvironmentID, &c.Name, &c.ValueMAC); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

func (s *Store) ListSecretsOverVersionLimit(ctx context.Context, keep int, limit int) ([]store.Secret, error) {
	return s.listSecrets(ctx, store.Weak, `s.id IN (SELECT secret_id FROM secret_versions GROUP BY secret_id HAVING COUNT(*) > ?) LIMIT ?`, keep, limit)
}

func prefixed(p, cols string) string {
	parts := strings.Split(cols, ",")
	for i, c := range parts {
		parts[i] = p + strings.TrimSpace(c)
	}
	return strings.Join(parts, ", ")
}

// ---- service tokens ----

const tokenCols = "id, tenant_id, project_id, name, token_hash, token_prefix, permission, expires_at, created_by, created_at, last_used_at, revoked_at"

func (s *Store) CreateServiceToken(ctx context.Context, t store.ServiceToken, ev *store.AuditEvent) error {
	var b batch
	b.audit(ev)
	b.add("INSERT INTO service_tokens ("+tokenCols+") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
		t.ID, t.TenantID, t.ProjectID, t.Name, t.TokenHash, t.TokenPrefix, t.Permission, t.ExpiresAt, t.CreatedBy, t.CreatedAt, t.LastUsedAt, t.RevokedAt)
	for _, e := range t.EnvironmentIDs {
		b.guard(store.ErrNotFound, "SELECT COUNT(*) FROM environments WHERE id = ? AND project_id = ? AND tenant_id = ?", e, t.ProjectID, t.TenantID)
		b.add("INSERT INTO service_token_environments (token_id, environment_id) VALUES (?, ?)", t.ID, e)
	}
	return s.execBatch(ctx, b)
}

func (s *Store) listTokens(ctx context.Context, c store.Consistency, where string, args ...any) ([]store.ServiceToken, error) {
	r, err := s.query(ctx, c, "SELECT "+tokenCols+` FROM service_tokens WHERE `+where, args...)
	if err != nil {
		return nil, err
	}
	var out []store.ServiceToken
	idx := map[string]int{}
	for r.next() {
		var t store.ServiceToken
		if err := r.scan(&t.ID, &t.TenantID, &t.ProjectID, &t.Name, &t.TokenHash, &t.TokenPrefix, &t.Permission, &t.ExpiresAt,
			&t.CreatedBy, &t.CreatedAt, &t.LastUsedAt, &t.RevokedAt); err != nil {
			return nil, err
		}
		idx[t.ID] = len(out)
		out = append(out, t)
	}
	if len(out) == 0 {
		return out, nil
	}
	tokIDs := make([]string, 0, len(out))
	for _, t := range out {
		tokIDs = append(tokIDs, t.ID)
	}
	for _, chunk := range chunks(tokIDs, 500) {
		er, err := s.query(ctx, c, "SELECT token_id, environment_id FROM service_token_environments WHERE token_id IN ("+placeholders(len(chunk))+") ORDER BY environment_id", anys(chunk)...)
		if err != nil {
			return nil, err
		}
		for er.next() {
			var tid, eid string
			if err := er.scan(&tid, &eid); err != nil {
				return nil, err
			}
			i := idx[tid]
			out[i].EnvironmentIDs = append(out[i].EnvironmentIDs, eid)
		}
	}
	return out, nil
}

func (s *Store) GetServiceToken(ctx context.Context, id string) (*store.ServiceToken, error) {
	ts, err := s.listTokens(ctx, store.Strong, "id = ?", id)
	if err != nil {
		return nil, err
	}
	if len(ts) == 0 {
		return nil, store.ErrNotFound
	}
	return &ts[0], nil
}

func (s *Store) ListServiceTokens(ctx context.Context, tenantID, projectID string) ([]store.ServiceToken, error) {
	return s.listTokens(ctx, store.Weak, "tenant_id = ? AND project_id = ? ORDER BY created_at DESC", tenantID, projectID)
}

func (s *Store) RevokeServiceToken(ctx context.Context, tenantID, projectID, id string, at time.Time, ev *store.AuditEvent) error {
	var b batch
	b.audit(ev)
	b.guard(store.ErrNotFound, "SELECT COUNT(*) FROM service_tokens WHERE id = ? AND tenant_id = ? AND project_id = ? AND revoked_at IS NULL", id, tenantID, projectID)
	b.add("UPDATE service_tokens SET revoked_at = ? WHERE id = ? AND tenant_id = ?", at, id, tenantID)
	return s.execBatch(ctx, b)
}

func (s *Store) TouchServiceToken(ctx context.Context, id string, at time.Time) error {
	_, err := s.exec(ctx, st("UPDATE service_tokens SET last_used_at = ? WHERE id = ? AND (last_used_at IS NULL OR last_used_at < ?)",
		at, id, at.Add(-time.Minute)))
	return err
}
