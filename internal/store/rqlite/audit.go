package rqlite

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/x6c-co/rypt-store/internal/store"
)

func itoa(n int) string { return strconv.Itoa(n) }

const auditCols = `id, chain_id, seq, ts, actor_kind, actor_id, action, target_kind, target_id, project_id, environment_id,
	result, ip, user_agent, request_id, provider_request_id, metadata, prev_hash, hash`

func scanAudit(r *rows) (store.AuditEvent, error) {
	var e store.AuditEvent
	err := r.scan(&e.ID, &e.ChainID, &e.Seq, &e.TS, &e.ActorKind, &e.ActorID, &e.Action, &e.TargetKind, &e.TargetID,
		&e.ProjectID, &e.EnvironmentID, &e.Result, &e.IP, &e.UserAgent, &e.RequestID, &e.ProviderRequestID,
		&e.Metadata, &e.PrevHash, &e.Hash)
	return e, err
}

const headCols = "chain_id, head_seq, head_hash, anchor_seq, anchor_hash, updated_at"

func scanHead(r *rows) (store.AuditHead, error) {
	var h store.AuditHead
	err := r.scan(&h.ChainID, &h.HeadSeq, &h.HeadHash, &h.AnchorSeq, &h.AnchorHash, &h.UpdatedAt)
	return h, err
}

func (s *Store) GetAuditHead(ctx context.Context, chainID string) (*store.AuditHead, error) {
	r, err := s.query(ctx, store.Strong, "SELECT "+headCols+" FROM audit_chains WHERE chain_id = ?", chainID)
	if err != nil {
		return nil, err
	}
	if !r.next() {
		return nil, store.ErrNotFound
	}
	h, err := scanHead(r)
	return &h, err
}

func (s *Store) ListAuditChains(ctx context.Context) ([]store.AuditHead, error) {
	r, err := s.query(ctx, store.Strong, "SELECT "+headCols+" FROM audit_chains ORDER BY chain_id")
	if err != nil {
		return nil, err
	}
	var out []store.AuditHead
	for r.next() {
		h, err := scanHead(r)
		if err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, nil
}

func (s *Store) EnsureAuditChain(ctx context.Context, chainID string) error {
	_, err := s.exec(ctx, st(`INSERT INTO audit_chains (chain_id, head_seq, head_hash, anchor_seq, anchor_hash, updated_at)
		VALUES (?, 0, ?, 0, ?, ?) ON CONFLICT (chain_id) DO NOTHING`, chainID, zeroHash, zeroHash, time.Now()))
	return err
}

func (s *Store) AppendAudit(ctx context.Context, ev *store.AuditEvent) error {
	var b batch
	b.audit(ev)
	return s.execBatch(ctx, b)
}

func (s *Store) ListAuditEvents(ctx context.Context, chainID string, f store.AuditFilter, page store.Page) ([]store.AuditEvent, string, error) {
	where := []string{"chain_id = ?"}
	args := []any{chainID}
	if f.ActorID != "" {
		where = append(where, "actor_id = ?")
		args = append(args, f.ActorID)
	}
	if f.Action != "" {
		where = append(where, "action LIKE ? ESCAPE '\\'")
		args = append(args, escapeLike(f.Action)+"%")
	}
	if f.ProjectID != "" {
		where = append(where, "project_id = ?")
		args = append(args, f.ProjectID)
	}
	if f.From != nil {
		where = append(where, "ts >= ?")
		args = append(args, *f.From)
	}
	if f.To != nil {
		where = append(where, "ts < ?")
		args = append(args, *f.To)
	}
	if page.Cursor != "" {
		seq, err := strconv.ParseInt(page.Cursor, 10, 64)
		if err != nil {
			return nil, "", store.Conflict("invalid cursor")
		}
		where = append(where, "seq < ?")
		args = append(args, seq)
	}
	args = append(args, page.Limit+1)
	r, err := s.query(ctx, store.Weak, "SELECT "+auditCols+" FROM audit_events WHERE "+strings.Join(where, " AND ")+" ORDER BY seq DESC LIMIT ?", args...)
	if err != nil {
		return nil, "", err
	}
	var out []store.AuditEvent
	for r.next() {
		e, err := scanAudit(r)
		if err != nil {
			return nil, "", err
		}
		out = append(out, e)
	}
	next := ""
	if len(out) > page.Limit {
		out = out[:page.Limit]
		next = strconv.FormatInt(out[len(out)-1].Seq, 10)
	}
	return out, next, nil
}

func escapeLike(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(s)
}

const auditScanPage = 1000

func (s *Store) ScanAuditEvents(ctx context.Context, chainID string, afterSeq int64, from, to *time.Time, fn func(store.AuditEvent) error) error {
	for {
		where := "chain_id = ? AND seq > ?"
		args := []any{chainID, afterSeq}
		if from != nil {
			where += " AND ts >= ?"
			args = append(args, *from)
		}
		if to != nil {
			where += " AND ts < ?"
			args = append(args, *to)
		}
		args = append(args, auditScanPage)
		r, err := s.query(ctx, store.Strong, "SELECT "+auditCols+" FROM audit_events WHERE "+where+" ORDER BY seq LIMIT ?", args...)
		if err != nil {
			return err
		}
		n := 0
		for r.next() {
			e, err := scanAudit(r)
			if err != nil {
				return err
			}
			if err := fn(e); err != nil {
				return err
			}
			afterSeq = e.Seq
			n++
		}
		if n < auditScanPage {
			return nil
		}
	}
}

func (s *Store) GetAuditEventBySeq(ctx context.Context, chainID string, seq int64) (*store.AuditEvent, error) {
	r, err := s.query(ctx, store.Strong, "SELECT "+auditCols+" FROM audit_events WHERE chain_id = ? AND seq = ?", chainID, seq)
	if err != nil {
		return nil, err
	}
	if !r.next() {
		return nil, store.ErrNotFound
	}
	e, err := scanAudit(r)
	return &e, err
}

func (s *Store) PruneAudit(ctx context.Context, chainID string, anchorSeq int64, anchorHash string, ev *store.AuditEvent) error {
	var b batch
	b.audit(ev)
	b.add("DELETE FROM audit_events WHERE chain_id = ? AND seq <= ?", chainID, anchorSeq)
	b.add("UPDATE audit_chains SET anchor_seq = ?, anchor_hash = ? WHERE chain_id = ?", anchorSeq, anchorHash, chainID)
	return s.execBatch(ctx, b)
}

func (s *Store) LastAuditSeqBefore(ctx context.Context, chainID string, before time.Time) (int64, error) {
	var n int64
	err := s.queryOne(ctx, store.Strong, "SELECT COALESCE(MAX(seq), 0) FROM audit_events WHERE chain_id = ? AND ts < ?",
		[]any{chainID, before}, &n)
	return n, err
}

// ---- jobs ----

const jobCols = "id, kind, state, run_after, attempts, last_error, payload, dedupe_key, created_at, updated_at"

func (s *Store) EnqueueJob(ctx context.Context, j store.Job) error {
	q := "INSERT INTO jobs (" + jobCols + ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
	if j.DedupeKey != "" {
		q += " ON CONFLICT DO NOTHING"
	}
	_, err := s.exec(ctx, st(q, j.ID, j.Kind, store.JobPending, j.RunAfter, 0, nil, j.Payload, null(j.DedupeKey), j.CreatedAt, j.CreatedAt))
	return err
}

func (s *Store) ClaimJob(ctx context.Context, now time.Time) (*store.Job, error) {
	for range 5 {
		r, err := s.query(ctx, store.Strong, "SELECT "+jobCols+" FROM jobs WHERE state = 'pending' AND run_after <= ? ORDER BY run_after LIMIT 1", now)
		if err != nil {
			return nil, err
		}
		if !r.next() {
			return nil, store.ErrNotFound
		}
		var j store.Job
		if err := r.scan(&j.ID, &j.Kind, &j.State, &j.RunAfter, &j.Attempts, &j.LastError, &j.Payload, &j.DedupeKey, &j.CreatedAt, &j.UpdatedAt); err != nil {
			return nil, err
		}
		n, err := s.exec(ctx, st("UPDATE jobs SET state = 'running', attempts = attempts + 1, updated_at = ? WHERE id = ? AND state = 'pending'", now, j.ID))
		if err != nil {
			return nil, err
		}
		if n[0] == 1 {
			j.State = store.JobRunning
			j.Attempts++
			return &j, nil
		}
	}
	return nil, store.ErrNotFound
}

func (s *Store) FinishJob(ctx context.Context, id string, at time.Time) error {
	_, err := s.exec(ctx, st("UPDATE jobs SET state = 'done', updated_at = ? WHERE id = ?", at, id))
	return err
}

func (s *Store) RetryJob(ctx context.Context, id, lastError string, runAfter time.Time, final bool) error {
	state := store.JobPending
	if final {
		state = store.JobFailed
	}
	// A retried job keeps its dedupe key only while no newer pending job
	// with the same key exists; a failed one drops it.
	_, err := s.exec(ctx, st(`UPDATE jobs SET state = ?, last_error = ?, run_after = ?, updated_at = ?,
		dedupe_key = CASE WHEN ? = 'failed' OR EXISTS (SELECT 1 FROM jobs j2 WHERE j2.dedupe_key = jobs.dedupe_key AND j2.state = 'pending')
			THEN NULL ELSE dedupe_key END
		WHERE id = ?`, state, lastError, runAfter, time.Now(), state, id))
	return err
}

func (s *Store) ResetRunningJobs(ctx context.Context) error {
	_, err := s.exec(ctx, st(`UPDATE jobs SET state = 'pending',
		dedupe_key = CASE WHEN EXISTS (SELECT 1 FROM jobs j2 WHERE j2.dedupe_key = jobs.dedupe_key AND j2.state = 'pending')
			THEN NULL ELSE dedupe_key END
		WHERE state = 'running'`))
	return err
}

func (s *Store) DeleteFinishedJobs(ctx context.Context, before time.Time) error {
	_, err := s.exec(ctx, st("DELETE FROM jobs WHERE state IN ('done', 'failed') AND updated_at < ?", before))
	return err
}
