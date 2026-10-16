package rqlite_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/x6c-co/rypt-store/internal/ids"
	"github.com/x6c-co/rypt-store/internal/store"
	"github.com/x6c-co/rypt-store/internal/store/rqlite"
	"github.com/x6c-co/rypt-store/internal/store/storetest"
)

var ctx = context.Background()

// chain hands out sequential events; store tests do not check hashes.
type chain struct {
	id   string
	seq  int64
	prev string
}

func newChain(id string) *chain { return &chain{id: id, prev: zero} }

const zero = "0000000000000000000000000000000000000000000000000000000000000000"

func (c *chain) next(action string) *store.AuditEvent {
	c.seq++
	h := fmt.Sprintf("%064x", c.seq)
	ev := &store.AuditEvent{
		ID: ids.New(), ChainID: c.id, Seq: c.seq, TS: ids.FormatTime(time.Now()), ActorKind: "system",
		Action: action, Result: "success", Metadata: "{}", PrevHash: c.prev, Hash: h,
	}
	c.prev = h
	return ev
}

// rollback undoes the last next() after a batch that failed.
func (c *chain) rollback() {
	c.seq--
	if c.seq == 0 {
		c.prev = zero
	} else {
		c.prev = fmt.Sprintf("%064x", c.seq)
	}
}

type fixture struct {
	s       *rqlite.Store
	inst    *chain
	tenant  store.Tenant
	tchain  *chain
	user    store.User
	project store.Project
	envs    []store.Environment
	now     time.Time
}

func setup(t *testing.T) *fixture {
	t.Helper()
	s := storetest.New(t)
	now := time.Now().UTC().Truncate(time.Millisecond)
	f := &fixture{s: s, inst: newChain(store.InstanceChain), now: now}
	ik := store.KeyWrap{ID: ids.New(), KeyID: ids.New(), KeyKind: store.KeyKindInstance, WrapperKind: store.WrapperProvider,
		WrapperRef: "local:abcd", Ciphertext: []byte{0, 1, 2, 255}, State: store.WrapActive, CreatedAt: now}
	if err := s.CreateInstance(ctx, store.Instance{ID: ids.New(), CreatedAt: now}, ik); err != nil {
		t.Fatal(err)
	}
	f.user = store.User{ID: ids.New(), Email: "admin@example.com", DisplayName: "Admin", PasswordHash: "x", IsInstanceAdmin: true, CreatedAt: now, UpdatedAt: now}
	f.tenant = store.Tenant{ID: ids.New(), Name: "Acme", Slug: "acme", CreatedAt: now}
	f.tchain = newChain(f.tenant.ID)
	err := s.CompleteSetup(ctx, store.CompleteSetupParams{Admin: f.user, Tenant: f.tenant, CompletedAt: now}, f.inst.next("setup.complete"))
	if err != nil {
		t.Fatal(err)
	}
	f.project = store.Project{ID: ids.New(), TenantID: f.tenant.ID, Name: "API", Slug: "api", KeyMode: "B", CreatedAt: now}
	for i, slug := range []string{"dev", "staging", "prod"} {
		f.envs = append(f.envs, store.Environment{ID: ids.New(), TenantID: f.tenant.ID, ProjectID: f.project.ID, Name: slug, Slug: slug, Position: i, CreatedAt: now})
	}
	pk := store.KeyWrap{ID: ids.New(), KeyID: ids.New(), KeyKind: store.KeyKindProject, TenantID: f.tenant.ID, ProjectID: f.project.ID,
		WrapperKind: store.WrapperProvider, WrapperRef: "local:abcd", Ciphertext: []byte("pk"), State: store.WrapActive, CreatedAt: now}
	if err := s.CreateProject(ctx, f.project, f.envs, []store.KeyWrap{pk}, f.tchain.next("project.create")); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestMigrateIsIdempotent(t *testing.T) {
	s := storetest.New(t)
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
}

func TestInstanceAndSetup(t *testing.T) {
	f := setup(t)
	inst, err := f.s.GetInstance(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if inst.SetupCompletedAt == nil {
		t.Fatal("setup not marked complete")
	}
	err = f.s.CompleteSetup(ctx, store.CompleteSetupParams{
		Admin:  store.User{ID: ids.New(), Email: "b@example.com", DisplayName: "B", PasswordHash: "x", CreatedAt: f.now, UpdatedAt: f.now},
		Tenant: store.Tenant{ID: ids.New(), Name: "B", Slug: "b", CreatedAt: f.now}, CompletedAt: f.now,
	}, f.inst.next("setup.complete"))
	if !errors.Is(err, store.ErrConflict) {
		t.Fatalf("second setup: got %v, want conflict", err)
	}
	f.inst.rollback()
	if _, err := f.s.GetUserByEmail(ctx, "b@example.com"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("rolled-back user exists: %v", err)
	}
	// A second instance row is refused.
	err = f.s.CreateInstance(ctx, store.Instance{ID: ids.New(), CreatedAt: f.now}, store.KeyWrap{ID: ids.New(), KeyID: ids.New(),
		KeyKind: store.KeyKindInstance, WrapperKind: store.WrapperProvider, WrapperRef: "local:x", Ciphertext: []byte{1}, State: store.WrapActive, CreatedAt: f.now})
	if !errors.Is(err, store.ErrConflict) {
		t.Fatalf("second instance: got %v, want conflict", err)
	}
}

func TestAuditHeadGuard(t *testing.T) {
	f := setup(t)
	ev := f.inst.next("test.one")
	if err := f.s.AppendAudit(ctx, ev); err != nil {
		t.Fatal(err)
	}
	// Replaying the same seq fails as an audit conflict.
	dup := *ev
	dup.ID = ids.New()
	if err := f.s.AppendAudit(ctx, &dup); !errors.Is(err, store.ErrAuditConflict) {
		t.Fatalf("duplicate seq: got %v", err)
	}
	// Skipping ahead also fails: the head guard requires seq = head + 1.
	skip := *ev
	skip.ID, skip.Seq = ids.New(), ev.Seq+5
	if err := f.s.AppendAudit(ctx, &skip); !errors.Is(err, store.ErrAuditConflict) {
		t.Fatalf("skipped seq: got %v", err)
	}
	head, err := f.s.GetAuditHead(ctx, store.InstanceChain)
	if err != nil {
		t.Fatal(err)
	}
	if head.HeadSeq != ev.Seq || head.HeadHash != ev.Hash {
		t.Fatalf("head = %d %s, want %d %s", head.HeadSeq, head.HeadHash, ev.Seq, ev.Hash)
	}
	// A domain change rolls back with its audit event when the head is stale.
	stale := &store.AuditEvent{ID: ids.New(), ChainID: f.tenant.ID, Seq: 1, TS: ids.FormatTime(f.now), ActorKind: "system",
		Action: "project.update", Result: "success", Metadata: "{}", PrevHash: zero, Hash: fmt.Sprintf("%064x", 99)}
	if err := f.s.UpdateProject(ctx, f.tenant.ID, f.project.ID, "Renamed", "api", stale); !errors.Is(err, store.ErrAuditConflict) {
		t.Fatalf("stale head: got %v", err)
	}
	p, _ := f.s.GetProject(ctx, f.tenant.ID, f.project.ID)
	if p.Name != "API" {
		t.Fatalf("project renamed despite audit conflict: %q", p.Name)
	}
	var seen []int64
	err = f.s.ScanAuditEvents(ctx, store.InstanceChain, 0, nil, nil, func(e store.AuditEvent) error {
		seen = append(seen, e.Seq)
		return nil
	})
	if err != nil || len(seen) != 2 || seen[0] != 1 || seen[1] != 2 {
		t.Fatalf("scan = %v, %v", seen, err)
	}
}

func TestTenantIsolation(t *testing.T) {
	f := setup(t)
	other := store.Tenant{ID: ids.New(), Name: "Other", Slug: "other", CreatedAt: f.now}
	if err := f.s.CreateTenant(ctx, other, nil, f.inst.next("tenant.create")); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.GetProject(ctx, other.ID, f.project.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("cross-tenant project: %v", err)
	}
	if _, err := f.s.GetEnvironment(ctx, other.ID, f.envs[0].ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("cross-tenant env: %v", err)
	}
	oc := newChain(other.ID)
	if err := f.s.DeleteProject(ctx, other.ID, f.project.ID, f.now, oc.next("project.delete")); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("cross-tenant delete: %v", err)
	}
}

func newVersion(f *fixture, secretID string, v int, value byte) (store.SecretVersion, store.KeyWrap) {
	dek := store.KeyWrap{ID: ids.New(), KeyID: ids.New(), KeyKind: store.KeyKindDEK, TenantID: f.tenant.ID, ProjectID: f.project.ID,
		WrapperKind: store.WrapperProject, WrapperRef: "pk", Ciphertext: []byte{value, 0}, State: store.WrapActive, CreatedAt: f.now}
	return store.SecretVersion{ID: ids.New(), TenantID: f.tenant.ID, SecretID: secretID, Version: v, DEKID: dek.KeyID,
		Ciphertext: []byte{value, 1, 2}, ValueMAC: []byte{value}, CreatedByKind: "user", CreatedByID: f.user.ID, CreatedAt: f.now}, dek
}

func TestSecretLifecycle(t *testing.T) {
	f := setup(t)
	env := f.envs[0]
	sec := store.Secret{ID: ids.New(), TenantID: f.tenant.ID, ProjectID: f.project.ID, EnvironmentID: env.ID, Name: "DATABASE_URL", CreatedAt: f.now, UpdatedAt: f.now}
	v1, d1 := newVersion(f, sec.ID, 1, 10)
	if err := f.s.CreateSecret(ctx, sec, v1, d1, f.tchain.next("secret.create")); err != nil {
		t.Fatal(err)
	}
	// Same name again is a conflict.
	dupSec := sec
	dupSec.ID = ids.New()
	dv, dd := newVersion(f, dupSec.ID, 1, 11)
	if err := f.s.CreateSecret(ctx, dupSec, dv, dd, f.tchain.next("secret.create")); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("duplicate name: %v", err)
	}
	f.tchain.rollback()

	// Update with the right expected version, then a stale one.
	v2, d2 := newVersion(f, sec.ID, 2, 20)
	comment := "primary db"
	if err := f.s.WriteSecretVersion(ctx, sec, 1, &comment, v2, d2, f.tchain.next("secret.update")); err != nil {
		t.Fatal(err)
	}
	v2b, d2b := newVersion(f, sec.ID, 2, 21)
	if err := f.s.WriteSecretVersion(ctx, sec, 1, nil, v2b, d2b, f.tchain.next("secret.update")); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("stale write: %v", err)
	}
	f.tchain.rollback()

	got, err := f.s.GetSecretByName(ctx, f.tenant.ID, env.ID, "DATABASE_URL")
	if err != nil {
		t.Fatal(err)
	}
	if got.CurrentVersion != 2 || got.Comment != comment || got.UpdatedByID != f.user.ID {
		t.Fatalf("secret = %+v", got)
	}
	ver, err := f.s.GetSecretVersion(ctx, f.tenant.ID, sec.ID, 2)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ver.Ciphertext, []byte{20, 1, 2}) || ver.DEKID != d2.KeyID {
		t.Fatalf("version blob round trip: %v", ver.Ciphertext)
	}
	if w, err := f.s.GetActiveWrap(ctx, d2.KeyID); err != nil || !bytes.Equal(w.Ciphertext, []byte{20, 0}) {
		t.Fatalf("dek wrap: %v %v", w, err)
	}

	// Compare cells and bulk values.
	cells, err := f.s.ListCompareCells(ctx, f.tenant.ID, f.project.ID)
	if err != nil || len(cells) != 1 || !bytes.Equal(cells[0].ValueMAC, []byte{20}) {
		t.Fatalf("compare cells = %v %v", cells, err)
	}
	vals, err := f.s.ListCurrentValues(ctx, f.tenant.ID, env.ID)
	if err != nil || len(vals) != 1 || vals[0].Version.Version != 2 {
		t.Fatalf("current values = %v %v", vals, err)
	}

	// Prune to one version: version 1 and its DEK wrap go.
	n, err := f.s.PruneSecretVersions(ctx, f.tenant.ID, sec.ID, 1)
	if err != nil || n != 1 {
		t.Fatalf("prune = %d %v", n, err)
	}
	if _, err := f.s.GetSecretVersion(ctx, f.tenant.ID, sec.ID, 1); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("pruned version: %v", err)
	}
	if _, err := f.s.GetActiveWrap(ctx, d1.KeyID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("pruned dek wrap: %v", err)
	}

	// Soft delete, reuse the name, then restoring the original conflicts.
	if err := f.s.SoftDeleteSecret(ctx, f.tenant.ID, sec.ID, f.now, f.tchain.next("secret.delete")); err != nil {
		t.Fatal(err)
	}
	reuse := sec
	reuse.ID = ids.New()
	rv, rd := newVersion(f, reuse.ID, 1, 30)
	if err := f.s.CreateSecret(ctx, reuse, rv, rd, f.tchain.next("secret.create")); err != nil {
		t.Fatalf("name reuse after delete: %v", err)
	}
	if err := f.s.RestoreDeletedSecret(ctx, f.tenant.ID, sec.ID, f.now, f.tchain.next("secret.restore")); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("restore over live name: %v", err)
	}
	f.tchain.rollback()
	deleted, err := f.s.ListDeletedSecrets(ctx, f.tenant.ID, env.ID)
	if err != nil || len(deleted) != 1 || deleted[0].ID != sec.ID {
		t.Fatalf("deleted = %v %v", deleted, err)
	}
	// Purge removes versions and wraps.
	if err := f.s.PurgeSecret(ctx, f.tenant.ID, sec.ID, f.tchain.next("secret.purge")); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.GetActiveWrap(ctx, d2.KeyID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("purged dek wrap: %v", err)
	}
}

func TestKeyWrapRules(t *testing.T) {
	f := setup(t)
	rk := store.KeyWrap{ID: ids.New(), KeyID: ids.New(), KeyKind: store.KeyKindRoot, WrapperKind: store.WrapperProvider,
		WrapperRef: "local:abcd", Ciphertext: []byte{1}, State: store.WrapActive, CreatedAt: f.now}
	if err := f.s.CreateRootKey(ctx, rk); err != nil {
		t.Fatal(err)
	}
	rk2 := rk
	rk2.ID, rk2.KeyID = ids.New(), ids.New()
	if err := f.s.CreateRootKey(ctx, rk2); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("second root key: %v", err)
	}
	wraps, err := f.s.ListProjectWraps(ctx, f.project.ID, store.WrapActive)
	if err != nil || len(wraps) != 1 {
		t.Fatalf("project wraps = %v %v", wraps, err)
	}
	pk := wraps[0]
	pending := pk
	pending.ID, pending.State, pending.WrapperRef = ids.New(), store.WrapPending, "rypt:key"
	if err := f.s.InsertWraps(ctx, []store.KeyWrap{pending}); err != nil {
		t.Fatal(err)
	}
	// Activating a second wrap for the key without retiring the first fails.
	if err := f.s.FlipWraps(ctx, nil, []string{pending.ID}, "", "", f.now, nil); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("double active: %v", err)
	}
	if err := f.s.FlipWraps(ctx, []string{pk.ID}, []string{pending.ID}, f.project.ID, "C", f.now, f.tchain.next("keys.migration.flip")); err != nil {
		t.Fatal(err)
	}
	active, err := f.s.GetActiveWrap(ctx, pk.KeyID)
	if err != nil || active.ID != pending.ID {
		t.Fatalf("active after flip = %v %v", active, err)
	}
	p, _ := f.s.GetProject(ctx, f.tenant.ID, f.project.ID)
	if p.KeyMode != "C" {
		t.Fatalf("mode = %s", p.KeyMode)
	}
	counts, err := f.s.CountWrapsByProvider(ctx)
	if err != nil || counts["rypt"] != 1 || counts["local"] != 3 {
		t.Fatalf("counts = %v %v", counts, err)
	}
	n, err := f.s.DeleteRetiredWraps(ctx, f.now.Add(time.Second))
	if err != nil || n != 1 {
		t.Fatalf("delete retired = %d %v", n, err)
	}
}

func TestServiceTokens(t *testing.T) {
	f := setup(t)
	tok := store.ServiceToken{ID: ids.New(), TenantID: f.tenant.ID, ProjectID: f.project.ID, Name: "ci", TokenHash: "h", TokenPrefix: "abcdefgh",
		Permission: store.TokenRead, ExpiresAt: f.now.Add(time.Hour), CreatedBy: f.user.ID, CreatedAt: f.now,
		EnvironmentIDs: []string{f.envs[2].ID, f.envs[0].ID}}
	if err := f.s.CreateServiceToken(ctx, tok, f.tchain.next("token.create")); err != nil {
		t.Fatal(err)
	}
	got, err := f.s.GetServiceToken(ctx, tok.ID)
	if err != nil || len(got.EnvironmentIDs) != 2 {
		t.Fatalf("token = %+v %v", got, err)
	}
	// An environment of another project is refused.
	bad := tok
	bad.ID, bad.Name, bad.EnvironmentIDs = ids.New(), "bad", []string{ids.New()}
	if err := f.s.CreateServiceToken(ctx, bad, f.tchain.next("token.create")); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("foreign env: %v", err)
	}
	f.tchain.rollback()
	if err := f.s.TouchServiceToken(ctx, tok.ID, f.now); err != nil {
		t.Fatal(err)
	}
	if err := f.s.RevokeServiceToken(ctx, f.tenant.ID, f.project.ID, tok.ID, f.now, f.tchain.next("token.revoke")); err != nil {
		t.Fatal(err)
	}
	got, _ = f.s.GetServiceToken(ctx, tok.ID)
	if got.RevokedAt == nil || got.LastUsedAt == nil {
		t.Fatalf("revoked token = %+v", got)
	}
}

func TestMembersKeepAnOwner(t *testing.T) {
	f := setup(t)
	if err := f.s.UpdateMemberRole(ctx, f.tenant.ID, f.user.ID, "admin", f.tchain.next("member.role")); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("demote last owner: %v", err)
	}
	f.tchain.rollback()
	m, err := f.s.GetMembership(ctx, f.tenant.ID, f.user.ID)
	if err != nil || m.Role != "owner" {
		t.Fatalf("membership = %v %v", m, err)
	}
}

func TestJobs(t *testing.T) {
	f := setup(t)
	j := store.Job{ID: ids.New(), Kind: "prune", RunAfter: f.now, Payload: "{}", DedupeKey: "prune:1", CreatedAt: f.now}
	if err := f.s.EnqueueJob(ctx, j); err != nil {
		t.Fatal(err)
	}
	j2 := j
	j2.ID = ids.New()
	if err := f.s.EnqueueJob(ctx, j2); err != nil {
		t.Fatalf("dedupe enqueue: %v", err)
	}
	got, err := f.s.ClaimJob(ctx, f.now.Add(time.Second))
	if err != nil || got.ID != j.ID || got.Attempts != 1 {
		t.Fatalf("claim = %v %v", got, err)
	}
	if _, err := f.s.ClaimJob(ctx, f.now.Add(time.Second)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("second claim (deduped): %v", err)
	}
	if err := f.s.FinishJob(ctx, got.ID, f.now); err != nil {
		t.Fatal(err)
	}
}
