// Package rqlite implements the storage interface on rqlite through its
// HTTP API. Each atomic unit of the interface is one transactional batch
// (core 4.3); preconditions inside a batch are expressed as UNIQUE
// constraints, conditional UPDATEs, and batch_guards rows.
package rqlite

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	rqhttp "github.com/rqlite/rqlite-go-http"

	"github.com/x6c-co/rypt-store/internal/ids"
	"github.com/x6c-co/rypt-store/internal/store"
	"github.com/x6c-co/rypt-store/internal/store/migrate"
)

// Store is the rqlite storage implementation.
type Store struct {
	c *rqhttp.Client
}

var _ store.Store = (*Store)(nil)

// Open returns a Store for the rqlite node at url. It makes no request.
func Open(url, username, password string) (*Store, error) {
	c, err := rqhttp.NewClient(url, nil)
	if err != nil {
		return nil, fmt.Errorf("rqlite client: %w", err)
	}
	if username != "" {
		c.SetBasicAuth(username, password)
	}
	return &Store{c: c}, nil
}

func (s *Store) Close() error { return s.c.Close() }

func (s *Store) Ping(ctx context.Context) error {
	_, err := s.query(ctx, store.Strong, "SELECT 1")
	return err
}

func (s *Store) Migrate(ctx context.Context) error { return migrate.Run(ctx, s) }

func (s *Store) EnsureMigrationTable(ctx context.Context) error {
	_, err := s.exec(ctx, st(migrate.MigrationTableSQL))
	return err
}

func (s *Store) AppliedVersions(ctx context.Context) (map[int]bool, error) {
	r, err := s.query(ctx, store.Strong, "SELECT version FROM schema_migrations")
	if err != nil {
		return nil, err
	}
	out := map[int]bool{}
	for r.next() {
		var v int
		if err := r.scan(&v); err != nil {
			return nil, err
		}
		out[v] = true
	}
	return out, nil
}

func (s *Store) ApplyMigration(ctx context.Context, m migrate.Migration) error {
	stmts := make([]stmt, 0, len(m.Statements)+1)
	for _, q := range m.Statements {
		stmts = append(stmts, st(q))
	}
	stmts = append(stmts, st("INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)",
		m.Version, m.Name, time.Now()))
	_, err := s.exec(ctx, stmts...)
	return err
}

// stmt is one statement of a batch. When onFail is set and the statement
// fails, exec returns onFail instead of the database error.
type stmt struct {
	sql    string
	args   []any
	onFail error
}

func st(sql string, args ...any) stmt { return stmt{sql: sql, args: args} }

// guard returns statements that fail the batch with onFail unless cond, a
// scalar query, evaluates to 1.
func guard(onFail error, cond string, args ...any) []stmt {
	k := ids.New()
	return []stmt{
		{sql: "INSERT INTO batch_guards (k, ok) VALUES (?, (" + cond + "))", args: append([]any{k}, args...), onFail: onFail},
		st("DELETE FROM batch_guards WHERE k = ?", k),
	}
}

// batch accumulates statements.
type batch []stmt

func (b *batch) add(sql string, args ...any) { *b = append(*b, st(sql, args...)) }
func (b *batch) addAll(s ...stmt)            { *b = append(*b, s...) }
func (b *batch) guard(onFail error, cond string, args ...any) {
	*b = append(*b, guard(onFail, cond, args...)...)
}

// audit appends the chain-head guard and the event insert (core 8.3).
func (b *batch) audit(ev *store.AuditEvent) {
	if ev == nil {
		return
	}
	b.add("UPDATE audit_chains SET head_seq = ?, head_hash = ?, updated_at = ? WHERE chain_id = ? AND head_seq = ?",
		ev.Seq, ev.Hash, ev.TS, ev.ChainID, ev.Seq-1)
	b.guard(store.ErrAuditConflict,
		"SELECT COUNT(*) FROM audit_chains WHERE chain_id = ? AND head_seq = ? AND head_hash = ?",
		ev.ChainID, ev.Seq, ev.Hash)
	b.add(`INSERT INTO audit_events (id, chain_id, seq, ts, actor_kind, actor_id, action, target_kind, target_id,
		project_id, environment_id, result, ip, user_agent, request_id, provider_request_id, metadata, prev_hash, hash)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		ev.ID, ev.ChainID, ev.Seq, ev.TS, ev.ActorKind, null(ev.ActorID), ev.Action, null(ev.TargetKind), null(ev.TargetID),
		null(ev.ProjectID), null(ev.EnvironmentID), ev.Result, null(ev.IP), null(ev.UserAgent), null(ev.RequestID),
		null(ev.ProviderRequestID), ev.Metadata, ev.PrevHash, ev.Hash)
}

// nullString marks a string to be sent as NULL when empty.
type nullString string

func null(s string) nullString { return nullString(s) }

func convertArg(a any) any {
	switch v := a.(type) {
	case nullString:
		if v == "" {
			return nil
		}
		return string(v)
	case []byte:
		// rqlite stores a JSON array of byte values as a BLOB.
		if v == nil {
			return nil
		}
		arr := make([]int, len(v))
		for i, b := range v {
			arr[i] = int(b)
		}
		return arr
	case time.Time:
		return ids.FormatTime(v)
	case *time.Time:
		if v == nil {
			return nil
		}
		return ids.FormatTime(*v)
	case bool:
		if v {
			return 1
		}
		return 0
	case *int:
		if v == nil {
			return nil
		}
		return *v
	}
	return a
}

func toStatements(stmts []stmt) rqhttp.SQLStatements {
	out := make(rqhttp.SQLStatements, len(stmts))
	for i, x := range stmts {
		var params []any
		if len(x.args) > 0 {
			params = make([]any, len(x.args))
			for j, a := range x.args {
				params[j] = convertArg(a)
			}
		}
		out[i] = &rqhttp.SQLStatement{SQL: x.sql, PositionalParams: params}
	}
	return out
}

// exec runs the statements as one transactional batch and returns the rows
// affected by each.
func (s *Store) exec(ctx context.Context, stmts ...stmt) ([]int64, error) {
	if len(stmts) == 0 {
		return nil, nil
	}
	resp, err := s.c.Execute(ctx, toStatements(stmts), &rqhttp.ExecuteOptions{Transaction: len(stmts) > 1})
	if err != nil {
		return nil, fmt.Errorf("rqlite execute: %w", err)
	}
	if resp.Error != "" {
		return nil, fmt.Errorf("rqlite execute: %s", resp.Error)
	}
	affected := make([]int64, len(stmts))
	for i, r := range resp.Results {
		if r.Error != nil {
			return nil, mapStatementError(stmts, i, r.Error)
		}
		if i < len(affected) {
			affected[i] = r.RowsAffected
		}
	}
	if len(resp.Results) < len(stmts) {
		return nil, fmt.Errorf("rqlite execute: %d results for %d statements", len(resp.Results), len(stmts))
	}
	return affected, nil
}

func (s *Store) execBatch(ctx context.Context, b batch) error {
	_, err := s.exec(ctx, b...)
	return err
}

const (
	sqliteConstraintUnique     = 2067
	sqliteConstraintPrimaryKey = 1555
)

func mapStatementError(stmts []stmt, i int, e *rqhttp.StatementError) error {
	if i < len(stmts) && stmts[i].onFail != nil {
		return stmts[i].onFail
	}
	unique := strings.Contains(e.Message, "UNIQUE constraint failed")
	if e.SQLite != nil && (e.SQLite.ExtendedCode == sqliteConstraintUnique || e.SQLite.ExtendedCode == sqliteConstraintPrimaryKey) {
		unique = true
	}
	if unique {
		if strings.Contains(e.Message, "audit_events.") {
			return store.ErrAuditConflict
		}
		return store.Conflict("%s", strings.TrimPrefix(e.Message, "UNIQUE constraint failed: "))
	}
	return fmt.Errorf("rqlite statement %d: %w", i, e)
}

// rows iterates one query result.
type rows struct {
	cols  []string
	types []string
	vals  [][]any
	i     int
}

func (s *Store) query(ctx context.Context, c store.Consistency, sql string, args ...any) (*rows, error) {
	level := rqhttp.ReadConsistencyLevelWeak
	if c == store.Strong {
		level = rqhttp.ReadConsistencyLevelStrong
	}
	resp, err := s.c.Query(ctx, toStatements([]stmt{st(sql, args...)}), &rqhttp.QueryOptions{Level: level})
	if err != nil {
		return nil, fmt.Errorf("rqlite query: %w", err)
	}
	if err := resp.Err(); err != nil {
		return nil, fmt.Errorf("rqlite query: %w", err)
	}
	results, ok := resp.Results.([]rqhttp.QueryResult)
	if !ok || len(results) != 1 {
		return nil, errors.New("rqlite query: unexpected result shape")
	}
	r := results[0]
	return &rows{cols: r.Columns, types: r.Types, vals: r.Values}, nil
}

func (r *rows) next() bool {
	if r.i >= len(r.vals) {
		return false
	}
	r.i++
	return true
}

func (r *rows) len() int { return len(r.vals) }

func (r *rows) scan(dest ...any) error {
	row := r.vals[r.i-1]
	if len(dest) > len(row) {
		return fmt.Errorf("scan: %d destinations for %d columns", len(dest), len(row))
	}
	for i, d := range dest {
		if err := scanValue(row[i], d); err != nil {
			name := ""
			if i < len(r.cols) {
				name = r.cols[i]
			}
			return fmt.Errorf("scan column %d (%s): %w", i, name, err)
		}
	}
	return nil
}

func scanValue(v any, dest any) error {
	switch p := dest.(type) {
	case *string:
		if v == nil {
			*p = ""
			return nil
		}
		switch x := v.(type) {
		case string:
			*p = x
		case json.Number:
			*p = x.String()
		default:
			return fmt.Errorf("cannot scan %T into string", v)
		}
	case *int64:
		n, err := toInt(v)
		if err != nil {
			return err
		}
		*p = n
	case *int:
		n, err := toInt(v)
		if err != nil {
			return err
		}
		*p = int(n)
	case **int:
		if v == nil {
			*p = nil
			return nil
		}
		n, err := toInt(v)
		if err != nil {
			return err
		}
		x := int(n)
		*p = &x
	case *bool:
		n, err := toInt(v)
		if err != nil {
			return err
		}
		*p = n != 0
	case *[]byte:
		if v == nil {
			*p = nil
			return nil
		}
		str, ok := v.(string)
		if !ok {
			return fmt.Errorf("cannot scan %T into []byte", v)
		}
		b, err := base64.StdEncoding.DecodeString(str)
		if err != nil {
			return fmt.Errorf("blob is not base64: %w", err)
		}
		*p = b
	case *time.Time:
		str, ok := v.(string)
		if !ok {
			return fmt.Errorf("cannot scan %T into time", v)
		}
		t, err := ids.ParseTime(str)
		if err != nil {
			return err
		}
		*p = t
	case **time.Time:
		if v == nil {
			*p = nil
			return nil
		}
		str, ok := v.(string)
		if !ok {
			return fmt.Errorf("cannot scan %T into time", v)
		}
		t, err := ids.ParseTime(str)
		if err != nil {
			return err
		}
		*p = &t
	default:
		return fmt.Errorf("unsupported scan destination %T", dest)
	}
	return nil
}

func toInt(v any) (int64, error) {
	switch x := v.(type) {
	case nil:
		return 0, nil
	case json.Number:
		return x.Int64()
	case float64:
		return int64(x), nil
	case string:
		return strconv.ParseInt(x, 10, 64)
	}
	return 0, fmt.Errorf("cannot scan %T into integer", v)
}

// queryOne runs a query expected to return at most one row and scans it;
// it returns store.ErrNotFound when there is none.
func (s *Store) queryOne(ctx context.Context, c store.Consistency, sql string, args []any, dest ...any) error {
	r, err := s.query(ctx, c, sql, args...)
	if err != nil {
		return err
	}
	if !r.next() {
		return store.ErrNotFound
	}
	return r.scan(dest...)
}

// count runs a scalar integer query.
func (s *Store) count(ctx context.Context, c store.Consistency, sql string, args ...any) (int, error) {
	var n int
	err := s.queryOne(ctx, c, sql, args, &n)
	return n, err
}

// placeholders returns "?, ?, ..." for n arguments.
func placeholders(n int) string {
	if n == 0 {
		return ""
	}
	return strings.TrimSuffix(strings.Repeat("?, ", n), ", ")
}

func anys[T any](xs []T) []any {
	out := make([]any, len(xs))
	for i, x := range xs {
		out[i] = x
	}
	return out
}
