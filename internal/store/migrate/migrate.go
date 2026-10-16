// Package migrate holds the numbered schema migrations, embedded in the
// binary and applied at start-up (core 4.3). Applied versions are recorded
// in schema_migrations.
package migrate

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

//go:embed sql/*.sql
var files embed.FS

// Migration is one numbered SQL file split into statements.
type Migration struct {
	Version    int
	Name       string
	Statements []string
}

// Executor is what a storage implementation provides to the runner.
type Executor interface {
	// EnsureMigrationTable creates schema_migrations if absent.
	EnsureMigrationTable(ctx context.Context) error
	// AppliedVersions returns the versions already applied.
	AppliedVersions(ctx context.Context) (map[int]bool, error)
	// ApplyMigration runs the statements and records the version in one
	// atomic batch.
	ApplyMigration(ctx context.Context, m Migration) error
}

// MigrationTableSQL creates the bookkeeping table.
const MigrationTableSQL = `CREATE TABLE IF NOT EXISTS schema_migrations (
    version    INTEGER PRIMARY KEY,
    name       TEXT NOT NULL,
    applied_at TEXT NOT NULL
)`

var fileName = regexp.MustCompile(`^(\d{4})_([a-z0-9_]+)\.sql$`)

// All returns the embedded migrations in version order.
func All() ([]Migration, error) {
	entries, err := fs.ReadDir(files, "sql")
	if err != nil {
		return nil, err
	}
	var out []Migration
	seen := map[int]bool{}
	for _, e := range entries {
		m := fileName.FindStringSubmatch(e.Name())
		if m == nil {
			return nil, fmt.Errorf("migration file %q does not match NNNN_name.sql", e.Name())
		}
		v, _ := strconv.Atoi(m[1])
		if seen[v] {
			return nil, fmt.Errorf("duplicate migration version %d", v)
		}
		seen[v] = true
		b, err := files.ReadFile("sql/" + e.Name())
		if err != nil {
			return nil, err
		}
		out = append(out, Migration{Version: v, Name: m[2], Statements: Split(string(b))})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version < out[j].Version })
	return out, nil
}

// Split splits a SQL file into statements on semicolons that end a line,
// dropping "--" comment lines. Migration files must not put a semicolon at
// the end of a line inside a statement.
func Split(src string) []string {
	var stmts []string
	var cur strings.Builder
	for _, line := range strings.Split(src, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "--") {
			continue
		}
		cur.WriteString(line)
		cur.WriteString("\n")
		if strings.HasSuffix(trimmed, ";") {
			s := strings.TrimSuffix(strings.TrimSpace(cur.String()), ";")
			stmts = append(stmts, s)
			cur.Reset()
		}
	}
	if s := strings.TrimSpace(cur.String()); s != "" {
		stmts = append(stmts, s)
	}
	return stmts
}

// Run applies every migration not yet applied, in order.
func Run(ctx context.Context, ex Executor) error {
	all, err := All()
	if err != nil {
		return err
	}
	if err := ex.EnsureMigrationTable(ctx); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}
	applied, err := ex.AppliedVersions(ctx)
	if err != nil {
		return err
	}
	for _, m := range all {
		if applied[m.Version] {
			continue
		}
		if err := ex.ApplyMigration(ctx, m); err != nil {
			return fmt.Errorf("apply migration %04d_%s: %w", m.Version, m.Name, err)
		}
	}
	return nil
}
