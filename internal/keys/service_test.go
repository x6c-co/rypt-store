package keys

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/x6c-co/rypt-store/internal/ids"
	"github.com/x6c-co/rypt-store/internal/keys/provider"
	"github.com/x6c-co/rypt-store/internal/keys/provider/providertest"
	"github.com/x6c-co/rypt-store/internal/metrics"
	"github.com/x6c-co/rypt-store/internal/store"
	"github.com/x6c-co/rypt-store/internal/store/storetest"
)

var ctx = context.Background()

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type env struct {
	st     store.Store
	local  *provider.Local
	rypt   *providertest.Fake
	clock  *clock
	tenant store.Tenant
}

func newEnv(t *testing.T) *env {
	t.Helper()
	local, err := provider.NewLocal(bytes.Repeat([]byte{3}, 32))
	if err != nil {
		t.Fatal(err)
	}
	e := &env{st: storetest.New(t), local: local, rypt: providertest.New("rypt"),
		clock: &clock{t: time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)}}
	return e
}

func (e *env) service(t *testing.T, current string, mut func(*Options)) *Service {
	t.Helper()
	o := Options{Store: e.st, Providers: []provider.Provider{e.local, e.rypt}, Current: current,
		CacheTTL: 15 * time.Minute, CacheMax: 1000, MaxStale: 24 * time.Hour, Metrics: metrics.New(),
		Now: e.clock.now, Logger: slog.New(slog.DiscardHandler)}
	if mut != nil {
		mut(&o)
	}
	s, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Init(ctx); err != nil {
		t.Fatal(err)
	}
	if e.tenant.ID == "" {
		e.tenant = store.Tenant{ID: ids.New(), Name: "T", Slug: "t", CreatedAt: e.clock.now()}
		if err := e.st.CreateTenant(ctx, e.tenant, nil, nil); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

func (e *env) project(t *testing.T, s *Service, mode string) (store.Project, store.Environment) {
	t.Helper()
	p := store.Project{ID: ids.New(), TenantID: e.tenant.ID, Name: "p", Slug: "p-" + ids.New()[24:], KeyMode: mode, CreatedAt: e.clock.now()}
	en := store.Environment{ID: ids.New(), TenantID: e.tenant.ID, ProjectID: p.ID, Name: "dev", Slug: "dev", CreatedAt: e.clock.now()}
	wraps, err := s.NewProjectWraps(ctx, p.TenantID, p.ID, mode)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.st.CreateProject(ctx, p, []store.Environment{en}, wraps, nil); err != nil {
		t.Fatal(err)
	}
	return p, en
}

// writeSecret seals and stores one version and returns it.
func (e *env) writeSecret(t *testing.T, s *Service, p store.Project, en store.Environment, name, value string) store.SecretVersion {
	t.Helper()
	sec := store.Secret{ID: ids.New(), TenantID: p.TenantID, ProjectID: p.ID, EnvironmentID: en.ID, Name: name, CreatedAt: e.clock.now(), UpdatedAt: e.clock.now()}
	var v store.SecretVersion
	err := s.WithProjectWrite(p.ID, func() error {
		sealed, err := s.SealValue(ctx, p, en.ID, sec.ID, 1, []byte(value))
		if err != nil {
			return err
		}
		v = store.SecretVersion{ID: ids.New(), TenantID: p.TenantID, SecretID: sec.ID, Version: 1, DEKID: sealed.DEK.KeyID,
			Ciphertext: sealed.Ciphertext, ValueMAC: sealed.MAC, CreatedByKind: "user", CreatedByID: "u", CreatedAt: e.clock.now()}
		return e.st.CreateSecret(ctx, sec, v, sealed.DEK, nil)
	})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestEveryProviderAndMode(t *testing.T) {
	e := newEnv(t)
	for _, prov := range []string{"local", "rypt"} {
		s := e.service(t, prov, nil)
		for _, mode := range []string{ModeA, ModeB, ModeC} {
			t.Run(prov+"/"+mode, func(t *testing.T) {
				p, en := e.project(t, s, mode)
				v := e.writeSecret(t, s, p, en, "K", "value-"+prov+mode)
				// A fresh service has a cold cache and must unwrap through the chain.
				cold := e.service(t, prov, nil)
				got, err := cold.OpenValue(ctx, p.TenantID, en.ID, v)
				if err != nil || string(got) != "value-"+prov+mode {
					t.Fatalf("open = %q %v", got, err)
				}
				dek, err := e.st.GetActiveWrap(ctx, v.DEKID)
				if err != nil {
					t.Fatal(err)
				}
				switch mode {
				case ModeC:
					if dek.WrapperKind != store.WrapperProvider || !strings.HasPrefix(dek.WrapperRef, prov+":") {
						t.Fatalf("mode C DEK wrap = %s %s", dek.WrapperKind, dek.WrapperRef)
					}
				default:
					if dek.WrapperKind != store.WrapperProject {
						t.Fatalf("mode %s DEK wrapper = %s", mode, dek.WrapperKind)
					}
					pk, err := e.st.GetActiveWrap(ctx, dek.WrapperRef)
					if err != nil {
						t.Fatal(err)
					}
					want := store.WrapperProvider
					if mode == ModeA {
						want = store.WrapperRoot
					}
					if pk.WrapperKind != want {
						t.Fatalf("mode %s PK wrapper = %s", mode, pk.WrapperKind)
					}
				}
			})
		}
	}
}

func TestValueAADBinding(t *testing.T) {
	e := newEnv(t)
	s := e.service(t, "local", nil)
	p, en := e.project(t, s, ModeB)
	v1 := e.writeSecret(t, s, p, en, "A", "alpha")
	v2 := e.writeSecret(t, s, p, en, "B", "beta")
	// Copy A's ciphertext into B's row: same DEK, but the AAD names B.
	moved := v2
	moved.Ciphertext, moved.DEKID = v1.Ciphertext, v1.DEKID
	if _, err := s.OpenValue(ctx, p.TenantID, en.ID, moved); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("copied ciphertext: %v", err)
	}
	// Wrong version number also fails.
	wrongVer := v1
	wrongVer.Version = 2
	if _, err := s.OpenValue(ctx, p.TenantID, en.ID, wrongVer); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("wrong version: %v", err)
	}
	// A DEK wrap copied to another key ID fails too.
	w, _ := e.st.GetActiveWrap(ctx, v1.DEKID)
	w.KeyID = v2.DEKID
	if _, err := s.unwrap(ctx, *w); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("copied DEK wrap: %v", err)
	}
}

func TestModeCProviderCalls(t *testing.T) {
	e := newEnv(t)
	s := e.service(t, "rypt", nil)
	p, en := e.project(t, s, ModeC)
	var vs []store.SecretVersion
	e.rypt.Reset()
	for i := range 5 {
		vs = append(vs, e.writeSecret(t, s, p, en, fmt.Sprintf("K%d", i), "v"))
	}
	if n := e.rypt.Calls("wrap"); n != 5 {
		t.Fatalf("mode C writes made %d wraps, want 5", n)
	}
	// Cold cache bulk read: one unwrap per secret.
	cold := e.service(t, "rypt", nil)
	e.rypt.Reset()
	for _, v := range vs {
		if _, err := cold.OpenValue(ctx, p.TenantID, en.ID, v); err != nil {
			t.Fatal(err)
		}
	}
	// Opening values needs only the DEKs, not the IK.
	if n := e.rypt.Calls("unwrap"); n != 5 {
		t.Fatalf("cold bulk read made %d unwraps, want 5", n)
	}
	// Warm cache: no provider calls.
	e.rypt.Reset()
	for _, v := range vs {
		if _, err := cold.OpenValue(ctx, p.TenantID, en.ID, v); err != nil {
			t.Fatal(err)
		}
	}
	if n := e.rypt.Total(); n != 0 {
		t.Fatalf("warm bulk read made %d provider calls", n)
	}
	// Mode B: one unwrap per project on a cold cache.
	pb, enb := e.project(t, s, ModeB)
	var bvs []store.SecretVersion
	for i := range 5 {
		bvs = append(bvs, e.writeSecret(t, s, pb, enb, fmt.Sprintf("K%d", i), "v"))
	}
	coldB := e.service(t, "rypt", nil)
	e.rypt.Reset()
	for _, v := range bvs {
		if _, err := coldB.OpenValue(ctx, pb.TenantID, enb.ID, v); err != nil {
			t.Fatal(err)
		}
	}
	if n := e.rypt.Calls("unwrap"); n != 1 {
		t.Fatalf("mode B cold read made %d unwraps, want 1", n)
	}
}

func TestOutagePolicies(t *testing.T) {
	e := newEnv(t)
	var transitions []bool
	onOutage := func(o *Options) {
		o.OnOutage = func(_ context.Context, _ string, down bool, _ error) { transitions = append(transitions, down) }
	}
	s := e.service(t, "rypt", onOutage)
	p, en := e.project(t, s, ModeC)
	v := e.writeSecret(t, s, p, en, "K", "v")

	// fail_closed: an expired entry is not used during an outage.
	closed := e.service(t, "rypt", onOutage)
	if _, err := closed.OpenValue(ctx, p.TenantID, en.ID, v); err != nil {
		t.Fatal(err)
	}
	e.clock.add(16 * time.Minute)
	e.rypt.Fail(e.rypt.OutageError)
	_, err := closed.OpenValue(ctx, p.TenantID, en.ID, v)
	if provider.KindOf(err) != provider.Outage {
		t.Fatalf("fail_closed: %v", err)
	}
	e.rypt.Fail(nil)

	// serve_cached: the expired entry serves within max_stale and is counted.
	cached := e.service(t, "rypt", func(o *Options) { onOutage(o); o.ServeCached = true })
	if _, err := cached.OpenValue(ctx, p.TenantID, en.ID, v); err != nil {
		t.Fatal(err)
	}
	e.clock.add(16 * time.Minute)
	e.rypt.Fail(e.rypt.OutageError)
	got, err := cached.OpenValue(ctx, p.TenantID, en.ID, v)
	if err != nil || string(got) != "v" {
		t.Fatalf("serve_cached: %q %v", got, err)
	}
	if n := testutil.ToFloat64(cached.m.StaleKeyUses); n != 1 {
		t.Fatalf("stale uses = %v", n)
	}
	// Writes that need a provider wrap still fail.
	err = cached.WithProjectWrite(p.ID, func() error {
		_, err := cached.SealValue(ctx, p, en.ID, ids.New(), 1, []byte("x"))
		return err
	})
	if provider.KindOf(err) != provider.Outage {
		t.Fatalf("mode C write during outage: %v", err)
	}
	// Past max_stale the entry is gone.
	e.clock.add(25 * time.Hour)
	if _, err := cached.OpenValue(ctx, p.TenantID, en.ID, v); provider.KindOf(err) != provider.Outage {
		t.Fatalf("past max_stale: %v", err)
	}
	e.rypt.Fail(nil)
	if _, err := cached.OpenValue(ctx, p.TenantID, en.ID, v); err != nil {
		t.Fatalf("after recovery: %v", err)
	}
	if len(transitions) < 2 || !transitions[0] || transitions[len(transitions)-1] {
		t.Fatalf("outage transitions = %v", transitions)
	}

	// A quota error is not an outage: stale entries are not served.
	cached2 := e.service(t, "rypt", func(o *Options) { o.ServeCached = true })
	if _, err := cached2.OpenValue(ctx, p.TenantID, en.ID, v); err != nil {
		t.Fatal(err)
	}
	e.clock.add(16 * time.Minute)
	e.rypt.Fail(e.rypt.QuotaError)
	if _, err := cached2.OpenValue(ctx, p.TenantID, en.ID, v); provider.KindOf(err) != provider.Quota {
		t.Fatalf("quota: %v", err)
	}
	if st := cached2.Status(); st.QuotaExceeded == nil || st.QuotaExceeded.Cap != 10000 {
		t.Fatalf("status after quota = %+v", st)
	}
	e.rypt.Fail(nil)
}

func TestCheckProviders(t *testing.T) {
	e := newEnv(t)
	s := e.service(t, "rypt", nil)
	p, en := e.project(t, s, ModeC)
	e.writeSecret(t, s, p, en, "K", "v")
	// A server without the rypt provider refuses to start.
	only, err := New(Options{Store: e.st, Providers: []provider.Provider{e.local}, Current: "local", Now: e.clock.now})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := only.Init(ctx); err != nil {
		t.Fatal(err)
	}
	err = only.CheckProviders(ctx)
	if err == nil || !strings.Contains(err.Error(), `provider "rypt"`) {
		t.Fatalf("missing provider: %v", err)
	}
	// A wrong local KEK is detected.
	e2 := newEnv(t)
	s2 := e2.service(t, "local", nil)
	if err := s2.CheckProviders(ctx); err != nil {
		t.Fatal(err)
	}
	wrong, _ := provider.NewLocal(bytes.Repeat([]byte{4}, 32))
	bad, _ := New(Options{Store: e2.st, Providers: []provider.Provider{wrong}, Current: "local", Now: e2.clock.now})
	if _, _, err := bad.Init(ctx); err != nil {
		t.Fatal(err)
	}
	if err := bad.CheckProviders(ctx); err == nil || !strings.Contains(err.Error(), "KEK") {
		t.Fatalf("wrong KEK: %v", err)
	}
}

func TestComparisonMACAndTOTP(t *testing.T) {
	e := newEnv(t)
	s := e.service(t, "local", nil)
	a1, _ := s.ValueMAC(ctx, "proj-1", []byte("same"))
	a2, _ := s.ValueMAC(ctx, "proj-1", []byte("same"))
	b, _ := s.ValueMAC(ctx, "proj-2", []byte("same"))
	c, _ := s.ValueMAC(ctx, "proj-1", []byte("different"))
	if !bytes.Equal(a1, a2) || bytes.Equal(a1, b) || bytes.Equal(a1, c) {
		t.Fatal("MAC must be deterministic per project and differ across projects and values")
	}
	ct, err := s.EncryptTOTP(ctx, "user-1", []byte("JBSWY3DPEHPK3PXP"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DecryptTOTP(ctx, "user-2", ct); !errors.Is(err, ErrDecrypt) {
		t.Fatal("TOTP ciphertext opened for another user")
	}
	pt, err := s.DecryptTOTP(ctx, "user-1", ct)
	if err != nil || string(pt) != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("totp = %q %v", pt, err)
	}
}

func TestMaterialRedaction(t *testing.T) {
	m := Material{b: []byte("super-secret-key-bytes-000000000")}
	for _, s := range []string{fmt.Sprint(m), fmt.Sprintf("%v %+v %#v %s %x %q", m, m, m, m, m, m), fmt.Sprintf("%v", struct{ K Material }{m})} {
		if strings.Contains(s, "super-secret") || strings.Contains(s, "7375706572") {
			t.Fatalf("material leaked: %s", s)
		}
	}
	c := newCache(time.Minute, 0, 2, time.Now)
	c.put("a", "", []byte("aaaa"))
	el := c.items["a"]
	entry := el.Value.(*cacheEntry)
	if strings.Contains(fmt.Sprintf("%+v", *entry), "aaaa") {
		t.Fatal("cache entry printed key bytes")
	}
	inner := entry.m.b
	c.put("b", "", []byte("bbbb"))
	c.put("c", "", []byte("cccc")) // evicts "a"
	if !bytes.Equal(inner, make([]byte, 4)) {
		t.Fatalf("evicted key not cleared: %v", inner)
	}
	if _, ok := c.get("a"); ok {
		t.Fatal("evicted key still served")
	}
}

func TestOpCounts(t *testing.T) {
	e := newEnv(t)
	s := e.service(t, "rypt", nil)
	p, en := e.project(t, s, ModeC)
	e.writeSecret(t, s, p, en, "K", "v")
	if got := testutil.ToFloat64(s.m.ProviderOps.WithLabelValues("rypt", "wrap", "success")); got < 1 {
		t.Fatalf("wrap counter = %v", got)
	}
	if err := s.FlushOpCounts(ctx); err != nil {
		t.Fatal(err)
	}
	rows, err := e.st.ListProviderOpCounts(ctx, "2026-10")
	if err != nil || len(rows) == 0 {
		t.Fatalf("op counts = %v %v", rows, err)
	}
}
