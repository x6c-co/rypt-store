package rqlite

import (
	"context"
	"strings"
	"time"

	"github.com/x6c-co/rypt-store/internal/store"
)

const wrapCols = "id, key_id, key_kind, tenant_id, project_id, wrapper_kind, wrapper_ref, key_version, ciphertext, state, created_at"

func insertWrapStmt(w store.KeyWrap) stmt {
	return st("INSERT INTO key_wraps ("+wrapCols+") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
		w.ID, w.KeyID, w.KeyKind, null(w.TenantID), null(w.ProjectID), w.WrapperKind, w.WrapperRef, null(w.KeyVersion),
		w.Ciphertext, w.State, w.CreatedAt)
}

func (s *Store) listWraps(ctx context.Context, where string, args ...any) ([]store.KeyWrap, error) {
	r, err := s.query(ctx, store.Strong, "SELECT "+wrapCols+" FROM key_wraps WHERE "+where+" ORDER BY id", args...)
	if err != nil {
		return nil, err
	}
	var out []store.KeyWrap
	for r.next() {
		var w store.KeyWrap
		if err := r.scan(&w.ID, &w.KeyID, &w.KeyKind, &w.TenantID, &w.ProjectID, &w.WrapperKind, &w.WrapperRef,
			&w.KeyVersion, &w.Ciphertext, &w.State, &w.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, nil
}

func (s *Store) GetActiveWrap(ctx context.Context, keyID string) (*store.KeyWrap, error) {
	ws, err := s.listWraps(ctx, "key_id = ? AND state = 'active'", keyID)
	if err != nil {
		return nil, err
	}
	if len(ws) == 0 {
		return nil, store.ErrNotFound
	}
	return &ws[0], nil
}

func (s *Store) GetActiveWrapsByKind(ctx context.Context, kind string) ([]store.KeyWrap, error) {
	return s.listWraps(ctx, "key_kind = ? AND state = 'active'", kind)
}

func (s *Store) ListProjectWraps(ctx context.Context, projectID string, states ...string) ([]store.KeyWrap, error) {
	if len(states) == 0 {
		return s.listWraps(ctx, "project_id = ?", projectID)
	}
	return s.listWraps(ctx, "project_id = ? AND state IN ("+placeholders(len(states))+")", append([]any{projectID}, anys(states)...)...)
}

func (s *Store) CreateRootKey(ctx context.Context, w store.KeyWrap) error {
	_, err := s.exec(ctx, insertWrapStmt(w))
	return err
}

func (s *Store) InsertWraps(ctx context.Context, wraps []store.KeyWrap) error {
	var b batch
	for _, w := range wraps {
		b.addAll(insertWrapStmt(w))
	}
	return s.execBatch(ctx, b)
}

func (s *Store) DeleteWraps(ctx context.Context, wrapIDs []string) error {
	var b batch
	for _, chunk := range chunks(wrapIDs, 500) {
		b.add("DELETE FROM key_wraps WHERE id IN ("+placeholders(len(chunk))+")", anys(chunk)...)
	}
	return s.execBatch(ctx, b)
}

func (s *Store) FlipWraps(ctx context.Context, retireIDs, activateIDs []string, projectID, newMode string, at time.Time, ev *store.AuditEvent) error {
	var b batch
	b.audit(ev)
	for _, chunk := range chunks(retireIDs, 500) {
		b.guard(store.Conflict("a wrap to retire is no longer active"),
			"SELECT CASE WHEN COUNT(*) = "+itoa(len(chunk))+" THEN 1 ELSE 0 END FROM key_wraps WHERE state = 'active' AND id IN ("+placeholders(len(chunk))+")",
			anys(chunk)...)
		b.add("UPDATE key_wraps SET state = 'retired', retired_at = ? WHERE state = 'active' AND id IN ("+placeholders(len(chunk))+")", append([]any{at}, anys(chunk)...)...)
	}
	for _, chunk := range chunks(activateIDs, 500) {
		b.guard(store.Conflict("a wrap to activate is no longer pending"),
			"SELECT CASE WHEN COUNT(*) = "+itoa(len(chunk))+" THEN 1 ELSE 0 END FROM key_wraps WHERE state = 'pending' AND id IN ("+placeholders(len(chunk))+")",
			anys(chunk)...)
		b.add("UPDATE key_wraps SET state = 'active' WHERE state = 'pending' AND id IN ("+placeholders(len(chunk))+")", anys(chunk)...)
	}
	if newMode != "" {
		b.add("UPDATE projects SET key_mode = ? WHERE id = ?", newMode, projectID)
	}
	return s.execBatch(ctx, b)
}

func (s *Store) CountWrapsByProvider(ctx context.Context) (map[string]int, error) {
	r, err := s.query(ctx, store.Strong, "SELECT wrapper_ref, COUNT(*) FROM key_wraps WHERE wrapper_kind = 'provider' AND state IN ('active', 'retired') GROUP BY wrapper_ref")
	if err != nil {
		return nil, err
	}
	out := map[string]int{}
	for r.next() {
		var ref string
		var n int
		if err := r.scan(&ref, &n); err != nil {
			return nil, err
		}
		provider, _, _ := strings.Cut(ref, ":")
		out[provider] += n
	}
	return out, nil
}

func (s *Store) DeleteRetiredWraps(ctx context.Context, before time.Time) (int, error) {
	n, err := s.exec(ctx, st("DELETE FROM key_wraps WHERE state = 'retired' AND retired_at < ?", before))
	if err != nil {
		return 0, err
	}
	return int(n[0]), nil
}

func (s *Store) CountProjectDEKs(ctx context.Context, projectID string) (int, error) {
	return s.count(ctx, store.Strong, "SELECT COUNT(*) FROM key_wraps WHERE project_id = ? AND key_kind = 'dek' AND state = 'active'", projectID)
}

// ---- key migrations ----

const migrationCols = "id, kind, params, state, projects_total, projects_done, cursor, error, started_by, created_at, updated_at, finished_at"

func scanMigration(r *rows) (store.KeyMigration, error) {
	var m store.KeyMigration
	err := r.scan(&m.ID, &m.Kind, &m.Params, &m.State, &m.ProjectsTotal, &m.ProjectsDone, &m.Cursor, &m.Error, &m.StartedBy,
		&m.CreatedAt, &m.UpdatedAt, &m.FinishedAt)
	return m, err
}

func (s *Store) CreateKeyMigration(ctx context.Context, m store.KeyMigration, ev *store.AuditEvent) error {
	var b batch
	b.audit(ev)
	b.guard(store.Conflict("another key migration is running"),
		"SELECT CASE WHEN COUNT(*) = 0 THEN 1 ELSE 0 END FROM key_migrations WHERE state IN ('queued', 'running')")
	b.add("INSERT INTO key_migrations ("+migrationCols+") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
		m.ID, m.Kind, m.Params, m.State, m.ProjectsTotal, m.ProjectsDone, null(m.Cursor), null(m.Error), m.StartedBy,
		m.CreatedAt, m.UpdatedAt, m.FinishedAt)
	return s.execBatch(ctx, b)
}

func (s *Store) GetKeyMigration(ctx context.Context, id string) (*store.KeyMigration, error) {
	r, err := s.query(ctx, store.Strong, "SELECT "+migrationCols+" FROM key_migrations WHERE id = ?", id)
	if err != nil {
		return nil, err
	}
	if !r.next() {
		return nil, store.ErrNotFound
	}
	m, err := scanMigration(r)
	return &m, err
}

func (s *Store) listMigrations(ctx context.Context, sql string, args ...any) ([]store.KeyMigration, error) {
	r, err := s.query(ctx, store.Strong, sql, args...)
	if err != nil {
		return nil, err
	}
	var out []store.KeyMigration
	for r.next() {
		m, err := scanMigration(r)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, nil
}

func (s *Store) ListKeyMigrations(ctx context.Context, limit int) ([]store.KeyMigration, error) {
	return s.listMigrations(ctx, "SELECT "+migrationCols+" FROM key_migrations ORDER BY id DESC LIMIT ?", limit)
}

func (s *Store) ListUnfinishedKeyMigrations(ctx context.Context) ([]store.KeyMigration, error) {
	return s.listMigrations(ctx, "SELECT "+migrationCols+" FROM key_migrations WHERE state IN ('queued', 'running') ORDER BY id")
}

func (s *Store) UpdateKeyMigration(ctx context.Context, m store.KeyMigration, ev *store.AuditEvent) error {
	var b batch
	b.audit(ev)
	b.add("UPDATE key_migrations SET state = ?, projects_total = ?, projects_done = ?, cursor = ?, error = ?, updated_at = ?, finished_at = ? WHERE id = ?",
		m.State, m.ProjectsTotal, m.ProjectsDone, null(m.Cursor), null(m.Error), m.UpdatedAt, m.FinishedAt, m.ID)
	return s.execBatch(ctx, b)
}

// ---- provider operation counts ----

func (s *Store) AddProviderOpCounts(ctx context.Context, counts []store.ProviderOpCount) error {
	var b batch
	for _, c := range counts {
		b.add(`INSERT INTO provider_op_counts (month, provider, op, count) VALUES (?, ?, ?, ?)
			ON CONFLICT (month, provider, op) DO UPDATE SET count = provider_op_counts.count + excluded.count`,
			c.Month, c.Provider, c.Op, c.Count)
	}
	return s.execBatch(ctx, b)
}

func (s *Store) ListProviderOpCounts(ctx context.Context, month string) ([]store.ProviderOpCount, error) {
	r, err := s.query(ctx, store.Weak, "SELECT month, provider, op, count FROM provider_op_counts WHERE month = ? ORDER BY provider, op", month)
	if err != nil {
		return nil, err
	}
	var out []store.ProviderOpCount
	for r.next() {
		var c store.ProviderOpCount
		if err := r.scan(&c.Month, &c.Provider, &c.Op, &c.Count); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

func chunks(xs []string, n int) [][]string {
	var out [][]string
	for len(xs) > n {
		out = append(out, xs[:n])
		xs = xs[n:]
	}
	if len(xs) > 0 {
		out = append(out, xs)
	}
	return out
}
