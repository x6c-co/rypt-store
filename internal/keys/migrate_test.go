package keys

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/x6c-co/rypt-store/internal/audit"
	"github.com/x6c-co/rypt-store/internal/ids"
	"github.com/x6c-co/rypt-store/internal/keys/provider"
	"github.com/x6c-co/rypt-store/internal/store"
)

func (e *env) migrator(s *Service) *Migrator {
	return NewMigrator(s, e.st, audit.NewWriter(e.st, nil, e.clock.now), slog.New(slog.DiscardHandler))
}

// seeded is a project with secrets and their expected values.
type seeded struct {
	p      store.Project
	en     store.Environment
	values map[string]store.SecretVersion
}

func (e *env) seed(t *testing.T, s *Service, mode string, n int) seeded {
	t.Helper()
	p, en := e.project(t, s, mode)
	sd := seeded{p: p, en: en, values: map[string]store.SecretVersion{}}
	for i := range n {
		name := fmt.Sprintf("S%d", i)
		sd.values["value-"+name+"-"+p.ID] = e.writeSecret(t, s, p, en, name, "value-"+name+"-"+p.ID)
	}
	return sd
}

// checkReadable opens every value with a cold-cache service.
func (e *env) checkReadable(t *testing.T, s *Service, sd seeded) {
	t.Helper()
	for want, v := range sd.values {
		got, err := s.OpenValue(ctx, sd.p.TenantID, sd.en.ID, v)
		if err != nil || string(got) != want {
			t.Fatalf("project %s: read %q = %q, %v", sd.p.KeyMode, want, got, err)
		}
	}
}

func (e *env) noPending(t *testing.T, projectID string) {
	t.Helper()
	ws, err := e.st.ListProjectWraps(ctx, projectID, store.WrapPending)
	if err != nil || len(ws) != 0 {
		t.Fatalf("pending wraps left: %d %v", len(ws), err)
	}
}

func waitMigration(t *testing.T, m *Migrator, st store.Store, id string) *store.KeyMigration {
	t.Helper()
	m.Wait()
	mig, err := st.GetKeyMigration(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	return mig
}

// TestModeTransitions covers A<->B, B<->C, A<->C, and checks that the
// dry-run estimate equals the provider operations spent (core 16).
func TestModeTransitions(t *testing.T) {
	e := newEnv(t)
	s := e.service(t, "rypt", nil)
	// B->A runs first, so it also covers creating the root key.
	for _, tr := range []string{"BA", "AB", "BC", "CB", "AC", "CA"} {
		t.Run(tr, func(t *testing.T) {
			from, to := tr[:1], tr[1:]
			sd := e.seed(t, s, from, 3)
			m := e.migrator(s)
			req := MigrationRequest{Kind: MigrateMode, TenantID: sd.p.TenantID, ProjectID: sd.p.ID, Mode: to}
			est, err := m.Estimate(ctx, req)
			if err != nil {
				t.Fatal(err)
			}
			e.rypt.Reset()
			mig, err := m.Start(ctx, req, "admin")
			if err != nil {
				t.Fatal(err)
			}
			got := waitMigration(t, m, e.st, mig.ID)
			if got.State != store.MigrationSucceeded || got.ProjectsDone != 1 {
				t.Fatalf("migration = %+v", got)
			}
			if spent := e.rypt.Total(); spent != est.TotalOps {
				t.Fatalf("estimate %d, spent %d", est.TotalOps, spent)
			}
			p, _ := e.st.GetProject(ctx, sd.p.TenantID, sd.p.ID)
			if p.KeyMode != to {
				t.Fatalf("mode = %s", p.KeyMode)
			}
			e.noPending(t, p.ID)
			sd.p = *p
			e.checkReadable(t, e.service(t, "rypt", nil), sd)
			// Writes after the flip use the new mode.
			e.writeSecret(t, s, *p, sd.en, "AFTER", "after")
			// The PK is retired leaving modes A and B, and exists entering them.
			ws, _ := e.st.ListProjectWraps(ctx, p.ID, store.WrapActive)
			hasPK := false
			for _, w := range ws {
				hasPK = hasPK || w.KeyKind == store.KeyKindProject
			}
			if hasPK == (to == ModeC) {
				t.Fatalf("mode %s: active PK = %v", to, hasPK)
			}
		})
	}
	// Moving to the current mode is refused.
	sd := e.seed(t, s, ModeB, 1)
	if _, err := e.migrator(s).Start(ctx, MigrationRequest{Kind: MigrateMode, TenantID: sd.p.TenantID, ProjectID: sd.p.ID, Mode: ModeB}, "a"); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("same mode: %v", err)
	}
}

// TestProviderMigration moves a local-only instance to rypt (core 5.7).
func TestProviderMigration(t *testing.T) {
	e := newEnv(t)
	local := e.service(t, "local", nil)
	projects := []seeded{e.seed(t, local, ModeA, 2), e.seed(t, local, ModeB, 2), e.seed(t, local, ModeC, 3)}
	// A deleted project's wraps must move too, or local could never be removed.
	gone := e.seed(t, local, ModeC, 1)
	if err := e.st.DeleteProject(ctx, gone.p.TenantID, gone.p.ID, time.Now(), nil); err != nil {
		t.Fatal(err)
	}
	totp, err := local.EncryptTOTP(ctx, "u1", []byte("SECRET"))
	if err != nil {
		t.Fatal(err)
	}
	// Migrating to a provider that is not keys.provider is refused.
	if _, err := e.migrator(local).Estimate(ctx, MigrationRequest{Kind: MigrateProvider, To: "rypt"}); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("to a non-current provider: %v", err)
	}
	// The operator sets keys.provider: rypt and restarts.
	s := e.service(t, "rypt", nil)
	m := e.migrator(s)
	req := MigrationRequest{Kind: MigrateProvider, To: "rypt"}
	est, err := m.Estimate(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	// IK + RK, and per project: A nothing, B its PK, C its 3 DEKs; each
	// costs a wrap and a verifying unwrap on rypt.
	if est.InstanceOps != 4 || est.TotalOps != 4+2+6+2 || len(est.Projects) != 3 {
		t.Fatalf("estimate = %+v", est)
	}
	e.rypt.Reset()
	mig, err := m.Start(ctx, req, "admin")
	if err != nil {
		t.Fatal(err)
	}
	got := waitMigration(t, m, e.st, mig.ID)
	if got.State != store.MigrationSucceeded || got.ProjectsDone != 4 {
		t.Fatalf("migration = %+v", got)
	}
	if spent := e.rypt.Total(); spent != est.TotalOps {
		t.Fatalf("estimate %d, spent %d", est.TotalOps, spent)
	}
	// Every active wrap is now on rypt: a server with only rypt reads all.
	only, err := New(Options{Store: e.st, Providers: []provider.Provider{e.rypt}, Current: "rypt", Now: e.clock.now})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := only.Init(ctx); err != nil {
		t.Fatal(err)
	}
	for _, sd := range projects {
		e.checkReadable(t, only, sd)
	}
	if pt, err := only.DecryptTOTP(ctx, "u1", totp); err != nil || string(pt) != "SECRET" {
		t.Fatalf("TOTP after migration: %q %v", pt, err)
	}
	// Retired local wraps still need the KEK until retention deletes them.
	if err := only.CheckProviders(ctx); err == nil || !strings.Contains(err.Error(), `"local"`) {
		t.Fatalf("check with retired local wraps: %v", err)
	}
	if _, err := e.st.DeleteRetiredWraps(ctx, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := only.CheckProviders(ctx); err != nil {
		t.Fatalf("check after retention: %v", err)
	}
	// Running it again moves nothing.
	if est, _ := m.Estimate(ctx, req); est.TotalOps != 0 {
		t.Fatalf("second estimate = %+v", est)
	}
}

func TestRotate(t *testing.T) {
	e := newEnv(t)
	s := e.service(t, "rypt", nil)
	sd := []seeded{e.seed(t, s, ModeB, 1), e.seed(t, s, ModeC, 2)}
	const newRef = "11111111-2222-3333-4444-555555555555"
	e.rypt.SetKeyRef(newRef)
	m := e.migrator(s)
	req := MigrationRequest{Kind: MigrateRotate}
	est, err := m.Estimate(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	// IK + PK + 2 DEKs, each: unwrap, rewrap (2), verify.
	if est.TotalOps != 4*4 {
		t.Fatalf("estimate = %+v", est)
	}
	e.rypt.Reset()
	mig, _ := m.Start(ctx, req, "admin")
	if got := waitMigration(t, m, e.st, mig.ID); got.State != store.MigrationSucceeded {
		t.Fatalf("rotate = %+v", got)
	}
	if spent := e.rypt.Total(); spent != est.TotalOps {
		t.Fatalf("estimate %d, spent %d", est.TotalOps, spent)
	}
	for _, x := range sd {
		ws, _ := e.st.ListProjectWraps(ctx, x.p.ID, store.WrapActive)
		for _, w := range ws {
			if w.WrapperKind == store.WrapperProvider && w.WrapperRef != "rypt:"+newRef {
				t.Fatalf("wrap still on the old key: %s", w.WrapperRef)
			}
		}
		e.checkReadable(t, e.service(t, "rypt", nil), x)
	}
}

// TestFailureInjection fails each stage of the second project's unit and
// checks that finished projects keep their new state and the failed one
// keeps its old wraps (core 5.7, 16).
func TestFailureInjection(t *testing.T) {
	for _, stage := range []string{"compute", "insert", "verify", "flip", "provider"} {
		t.Run(stage, func(t *testing.T) {
			e := newEnv(t)
			local := e.service(t, "local", nil)
			p1, p2, p3 := e.seed(t, local, ModeC, 2), e.seed(t, local, ModeC, 2), e.seed(t, local, ModeB, 1)
			before, _ := e.st.ListProjectWraps(ctx, p2.p.ID, store.WrapActive)
			s := e.service(t, "rypt", nil)
			m := e.migrator(s)
			injected := errors.New("injected failure")
			if stage == "provider" {
				calls := 0
				e.rypt.Fail(func(op string) error {
					// Fail during the second project, after the instance unit
					// (2 calls) and the first project (4 calls).
					if calls++; calls == 8 {
						return e.rypt.OutageError(op)
					}
					return nil
				})
			} else {
				m.hook = func(_ context.Context, st, unit string) error {
					if st == stage && unit == p2.p.ID {
						return injected
					}
					return nil
				}
			}
			mig, err := m.Start(ctx, MigrationRequest{Kind: MigrateProvider, To: "rypt"}, "admin")
			if err != nil {
				t.Fatal(err)
			}
			got := waitMigration(t, m, e.st, mig.ID)
			e.rypt.Fail(nil)
			if got.State != store.MigrationFailed || got.ProjectsDone != 1 || got.Error == "" {
				t.Fatalf("migration = %+v", got)
			}
			// Project 1 moved; project 2 has its original wraps and no pending
			// rows; project 3 was not touched.
			for _, w := range mustWraps(t, e, p1.p.ID) {
				if w.WrapperKind == store.WrapperProvider && !strings.HasPrefix(w.WrapperRef, "rypt:") {
					t.Fatalf("project 1 not migrated: %s", w.WrapperRef)
				}
			}
			after := mustWraps(t, e, p2.p.ID)
			if len(after) != len(before) {
				t.Fatalf("project 2 wraps changed: %d -> %d", len(before), len(after))
			}
			for i := range after {
				if after[i].ID != before[i].ID {
					t.Fatalf("project 2 active wrap replaced")
				}
			}
			e.noPending(t, p2.p.ID)
			for _, w := range mustWraps(t, e, p3.p.ID) {
				if strings.HasPrefix(w.WrapperRef, "rypt:") {
					t.Fatal("project 3 touched")
				}
			}
			cold := e.service(t, "rypt", nil)
			for _, sd := range []seeded{p1, p2, p3} {
				e.checkReadable(t, cold, sd)
			}
		})
	}
}

func mustWraps(t *testing.T, e *env, projectID string) []store.KeyWrap {
	t.Helper()
	ws, err := e.st.ListProjectWraps(ctx, projectID, store.WrapActive)
	if err != nil {
		t.Fatal(err)
	}
	return ws
}

// TestVerifyMismatch: a pending wrap that does not open to the original key
// aborts the unit and deletes the pending rows (core 5.7 step 4).
func TestVerifyMismatch(t *testing.T) {
	e := newEnv(t)
	s := e.service(t, "rypt", nil)
	sd := e.seed(t, s, ModeC, 1)
	m := e.migrator(s)
	ws := mustWraps(t, e, sd.p.ID)
	dek := ws[0]
	wrong := newKey()
	nw, err := s.wrapUnderProvider(ctx, store.KeyKindDEK, dek.KeyID, dek.TenantID, dek.ProjectID, newKey())
	if err != nil {
		t.Fatal(err)
	}
	nw.ID = ids.New()
	u := &unit{name: sd.p.ID, chain: sd.p.TenantID, project: &sd.p, changes: []change{{old: &dek, new: nw, key: wrong}}}
	err = m.apply(ctx, "m1", MigrateProvider, u)
	if err == nil || !strings.Contains(err.Error(), "does not open to the original key") {
		t.Fatalf("apply = %v", err)
	}
	e.noPending(t, sd.p.ID)
	e.checkReadable(t, e.service(t, "rypt", nil), sd)
}

// TestRestartMidMigration stops a migration after its first project,
// leaves stray pending rows as a crash would, and resumes it with a new
// process (core 5.7, 16).
func TestRestartMidMigration(t *testing.T) {
	e := newEnv(t)
	local := e.service(t, "local", nil)
	ps := []seeded{e.seed(t, local, ModeC, 2), e.seed(t, local, ModeB, 1), e.seed(t, local, ModeC, 1)}
	s := e.service(t, "rypt", nil)
	m := e.migrator(s)
	stopped := make(chan struct{})
	m.hook = func(ctx context.Context, stage, unit string) error {
		if stage == "compute" && unit == ps[1].p.ID {
			go func() { m.Stop(); close(stopped) }()
			<-ctx.Done()
			return ctx.Err()
		}
		return nil
	}
	mig, err := m.Start(ctx, MigrationRequest{Kind: MigrateProvider, To: "rypt"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	<-stopped
	mid, _ := e.st.GetKeyMigration(ctx, mig.ID)
	if mid.State != store.MigrationRunning || mid.ProjectsDone != 1 || mid.Cursor != ps[0].p.ID {
		t.Fatalf("after stop = %+v", mid)
	}
	// A crash between insert and flip leaves pending rows behind.
	ws := mustWraps(t, e, ps[1].p.ID)
	stray := ws[0]
	stray.ID, stray.State = ids.New(), store.WrapPending
	if err := e.st.InsertWraps(ctx, []store.KeyWrap{stray}); err != nil {
		t.Fatal(err)
	}
	// Restart: a new service and migrator resume from the cursor.
	s2 := e.service(t, "rypt", nil)
	m2 := e.migrator(s2)
	if err := m2.Resume(ctx); err != nil {
		t.Fatal(err)
	}
	got := waitMigration(t, m2, e.st, mig.ID)
	if got.State != store.MigrationSucceeded || got.ProjectsDone != 3 {
		t.Fatalf("resumed = %+v", got)
	}
	for _, sd := range ps {
		e.noPending(t, sd.p.ID)
		e.checkReadable(t, e.service(t, "rypt", nil), sd)
	}
	// The audit log records start, flips and completion.
	var actions []string
	_ = e.st.ScanAuditEvents(ctx, store.InstanceChain, 0, nil, nil, func(ev store.AuditEvent) error {
		actions = append(actions, ev.Action)
		return nil
	})
	joined := strings.Join(actions, ",")
	for _, a := range []string{"keys.migration.start", "keys.migration.flip", "keys.migration.complete"} {
		if !strings.Contains(joined, a) {
			t.Fatalf("instance chain lacks %s: %v", a, actions)
		}
	}
}
