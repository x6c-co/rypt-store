// Package jobs runs background work (core 4.1): queued jobs stored in the
// jobs table, retried with backoff, and periodic sweeps such as version
// pruning, purging, session expiry, and audit retention.
package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/x6c-co/rypt-store/internal/ids"
	"github.com/x6c-co/rypt-store/internal/store"
)

// MaxAttempts bounds retries of a queued job.
const MaxAttempts = 5

// Func runs one queued job with its JSON payload.
type Func func(ctx context.Context, payload json.RawMessage) error

type periodic struct {
	name     string
	interval time.Duration
	fn       func(context.Context) error
	next     time.Time
}

// Runner executes queued and periodic jobs in one goroutine.
type Runner struct {
	st   store.JobStore
	log  *slog.Logger
	now  func() time.Time
	poll time.Duration

	mu       sync.Mutex
	handlers map[string]Func
	periodic []*periodic
	wake     chan struct{}
}

func New(st store.JobStore, log *slog.Logger, now func() time.Time) *Runner {
	if now == nil {
		now = time.Now
	}
	return &Runner{st: st, log: log, now: now, poll: 2 * time.Second, handlers: map[string]Func{}, wake: make(chan struct{}, 1)}
}

// Handle registers the function for a job kind.
func (r *Runner) Handle(kind string, fn Func) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.handlers[kind] = fn
}

// Every registers a periodic task; the first run is after one interval
// unless runNow is set.
func (r *Runner) Every(name string, interval time.Duration, runNow bool, fn func(context.Context) error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	next := r.now().Add(interval)
	if runNow {
		next = r.now()
	}
	r.periodic = append(r.periodic, &periodic{name: name, interval: interval, fn: fn, next: next})
}

// Enqueue stores a job. A non-empty dedupeKey skips the job when a pending
// one with the same key exists.
func (r *Runner) Enqueue(ctx context.Context, kind string, payload any, dedupeKey string, runAfter time.Time) error {
	b, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	now := r.now().UTC()
	if runAfter.IsZero() {
		runAfter = now
	}
	err = r.st.EnqueueJob(ctx, store.Job{ID: ids.New(), Kind: kind, RunAfter: runAfter.UTC(), Payload: string(b), DedupeKey: dedupeKey, CreatedAt: now})
	if err != nil {
		return err
	}
	select {
	case r.wake <- struct{}{}:
	default:
	}
	return nil
}

// Run processes jobs until ctx ends.
func (r *Runner) Run(ctx context.Context) {
	if err := r.st.ResetRunningJobs(ctx); err != nil {
		r.log.Error("reset running jobs", "error", err.Error())
	}
	t := time.NewTicker(r.poll)
	defer t.Stop()
	for {
		r.RunOnce(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-r.wake:
		}
	}
}

// RunOnce runs due periodic tasks and every due queued job.
func (r *Runner) RunOnce(ctx context.Context) {
	r.mu.Lock()
	var due []*periodic
	now := r.now()
	for _, p := range r.periodic {
		if !now.Before(p.next) {
			p.next = now.Add(p.interval)
			due = append(due, p)
		}
	}
	r.mu.Unlock()
	for _, p := range due {
		if err := p.fn(ctx); err != nil && ctx.Err() == nil {
			r.log.Error("periodic job failed", "job", p.name, "error", err.Error())
		}
	}
	for ctx.Err() == nil {
		j, err := r.st.ClaimJob(ctx, r.now().UTC())
		if errors.Is(err, store.ErrNotFound) {
			return
		}
		if err != nil {
			r.log.Error("claim job", "error", err.Error())
			return
		}
		r.execute(ctx, j)
	}
}

func (r *Runner) execute(ctx context.Context, j *store.Job) {
	r.mu.Lock()
	fn := r.handlers[j.Kind]
	r.mu.Unlock()
	var err error
	if fn == nil {
		err = fmt.Errorf("no handler for job kind %q", j.Kind)
	} else {
		err = safeRun(ctx, fn, json.RawMessage(j.Payload))
	}
	now := r.now().UTC()
	if err == nil {
		if ferr := r.st.FinishJob(ctx, j.ID, now); ferr != nil {
			r.log.Error("finish job", "job", j.ID, "error", ferr.Error())
		}
		return
	}
	final := j.Attempts >= MaxAttempts
	backoff := time.Duration(1<<min(j.Attempts, 10)) * 5 * time.Second
	r.log.Warn("job failed", "job", j.ID, "kind", j.Kind, "attempt", j.Attempts, "final", final, "error", err.Error())
	if rerr := r.st.RetryJob(ctx, j.ID, err.Error(), now.Add(backoff), final); rerr != nil {
		r.log.Error("retry job", "job", j.ID, "error", rerr.Error())
	}
}

func safeRun(ctx context.Context, fn Func, payload json.RawMessage) (err error) {
	defer func() {
		if v := recover(); v != nil {
			err = fmt.Errorf("panic: %v", v)
		}
	}()
	return fn(ctx, payload)
}
