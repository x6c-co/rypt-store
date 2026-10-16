// Package providertest provides a fake key provider that counts calls and
// can inject outages, quota errors, and timeouts (core 16).
package providertest

import (
	"context"
	"sync"
	"time"

	"github.com/x6c-co/rypt-store/internal/keys/provider"
)

// Fake behaves like a provider with an in-memory key. By default it
// reports its name as "rypt" so that it stands in for rypt.dev.
type Fake struct {
	inner *provider.Local
	name  string

	mu     sync.Mutex
	calls  map[string]int
	fail   func(op string) error
	delay  time.Duration
	keyRef string
}

// New returns a fake named name ("rypt" when empty).
func New(name string) *Fake {
	if name == "" {
		name = "rypt"
	}
	kek := make([]byte, 32)
	for i := range kek {
		kek[i] = byte(i + 7)
	}
	inner, _ := provider.NewLocal(kek)
	return &Fake{inner: inner, name: name, calls: map[string]int{}, keyRef: "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0"}
}

func (f *Fake) Name() string   { return f.name }
func (f *Fake) KeyRef() string { return f.keyRef }
func (f *Fake) RewrapOps() int { return 2 }

// SetKeyRef changes the key new wraps are made under, like a rotation.
func (f *Fake) SetKeyRef(ref string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.keyRef = ref
}

// Fail makes every call return the error that fn returns for its op
// ("wrap", "unwrap", "rewrap"); fn returning nil lets the call through.
// Fail(nil) clears the injection.
func (f *Fake) Fail(fn func(op string) error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fail = fn
}

// Delay makes every call wait d or until its context ends.
func (f *Fake) Delay(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.delay = d
}

// Calls returns how many times op was called (including failed calls).
func (f *Fake) Calls(op string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[op]
}

// Total returns the number of metered calls.
func (f *Fake) Total() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls["wrap"] + f.calls["unwrap"] + 2*f.calls["rewrap"]
}

// Reset zeroes the counters.
func (f *Fake) Reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = map[string]int{}
}

// OutageError, QuotaError and FatalError build injected errors.
func (f *Fake) OutageError(op string) error {
	return &provider.Error{Provider: f.name, Op: op, Kind: provider.Outage, RequestID: "req_outage", Err: context.DeadlineExceeded}
}

func (f *Fake) QuotaError(op string) error {
	return &provider.Error{Provider: f.name, Op: op, Kind: provider.Quota, Code: "ops_cap_reached", RequestID: "req_quota",
		Cap: 10000, ResetsAt: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC), Err: context.Canceled}
}

func (f *Fake) FatalError(op string) error {
	return &provider.Error{Provider: f.name, Op: op, Kind: provider.Fatal, Code: "unauthorized", RequestID: "req_fatal", Err: context.Canceled}
}

func (f *Fake) before(ctx context.Context, op string) error {
	f.mu.Lock()
	f.calls[op]++
	fail, delay := f.fail, f.delay
	f.mu.Unlock()
	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return &provider.Error{Provider: f.name, Op: op, Kind: provider.Outage, Err: ctx.Err()}
		}
	}
	if fail != nil {
		return fail(op)
	}
	return nil
}

func (f *Fake) Wrap(ctx context.Context, key, aad []byte) (provider.WrappedKey, error) {
	if err := f.before(ctx, "wrap"); err != nil {
		return provider.WrappedKey{}, err
	}
	w, err := f.inner.Wrap(ctx, key, aad)
	f.mu.Lock()
	w.Provider, w.KeyRef = f.name, f.keyRef
	f.mu.Unlock()
	return w, err
}

func (f *Fake) Unwrap(ctx context.Context, w provider.WrappedKey, aad []byte) ([]byte, error) {
	if err := f.before(ctx, "unwrap"); err != nil {
		return nil, err
	}
	w.Provider, w.KeyRef = "local", f.inner.KeyRef()
	return f.inner.Unwrap(ctx, w, aad)
}

func (f *Fake) Rewrap(ctx context.Context, w provider.WrappedKey, aad []byte) (provider.WrappedKey, error) {
	if err := f.before(ctx, "rewrap"); err != nil {
		return provider.WrappedKey{}, err
	}
	w.Provider, w.KeyRef = "local", f.inner.KeyRef()
	out, err := f.inner.Rewrap(ctx, w, aad)
	f.mu.Lock()
	out.Provider, out.KeyRef = f.name, f.keyRef
	f.mu.Unlock()
	return out, err
}
