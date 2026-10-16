package keys

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/x6c-co/rypt-store/internal/audit"
	"github.com/x6c-co/rypt-store/internal/ids"
	"github.com/x6c-co/rypt-store/internal/keys/provider"
	"github.com/x6c-co/rypt-store/internal/store"
)

// instanceCursor marks the instance unit (IK and RK) as done; it sorts
// before every UUIDv7 project ID.
const instanceCursor = "00000000-0000-0000-0000-000000000000"

// Migrator runs re-wrap migrations (core 5.7). A migration changes wraps,
// never secret values. Each unit of work (the instance keys, or one
// project) inserts its new wraps as pending, verifies them, and flips them
// to active in one batch; a failure leaves the unit untouched.
type Migrator struct {
	k     *Service
	st    store.Store
	audit *audit.Writer
	log   *slog.Logger
	now   func() time.Time

	mu      sync.Mutex
	running map[string]context.CancelFunc
	wg      sync.WaitGroup

	// hook, when set by tests, runs before each stage of a unit and can
	// inject a failure.
	hook func(ctx context.Context, stage, unit string) error
}

func NewMigrator(k *Service, st store.Store, aw *audit.Writer, log *slog.Logger) *Migrator {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Migrator{k: k, st: st, audit: aw, log: log, now: k.now, running: map[string]context.CancelFunc{}}
}

// metered reports whether a provider's operations count against a quota.
func metered(name string) int {
	if name == "local" {
		return 0
	}
	return 1
}

func wrapProvider(w store.KeyWrap) string {
	name, _, _ := strings.Cut(w.WrapperRef, ":")
	return name
}

// ---- validation ----

func (m *Migrator) validate(ctx context.Context, req MigrationRequest) (*store.Project, error) {
	switch req.Kind {
	case MigrateProvider:
		if _, ok := m.k.providers[req.To]; !ok {
			return nil, store.Conflict("provider %q is not configured; add its settings and restart first", req.To)
		}
		if req.To != m.k.current {
			return nil, store.Conflict("set keys.provider to %q and restart before migrating to it, so new keys are wrapped there too", req.To)
		}
		return nil, nil
	case MigrateRotate:
		if _, ok := m.k.providers["rypt"]; !ok {
			return nil, store.Conflict("rotation applies to rypt wraps, and the rypt provider is not configured")
		}
		return nil, nil
	case MigrateMode:
		if !ValidMode(req.Mode) {
			return nil, store.Conflict("unknown key mode %q", req.Mode)
		}
		p, err := m.st.GetProject(ctx, req.TenantID, req.ProjectID)
		if err != nil {
			return nil, err
		}
		if p.KeyMode == req.Mode {
			return nil, store.Conflict("the project already uses mode %s", req.Mode)
		}
		return p, nil
	}
	return nil, store.Conflict("unknown migration kind %q", req.Kind)
}

// ---- estimate ----

// Estimate reports the metered provider operations a migration will spend
// (core 5.7 --dry-run). It follows the same steps as the migration: every
// moved wrap is unwrapped from its source, wrapped for its target, and
// verified by unwrapping the new wrap.
func (m *Migrator) Estimate(ctx context.Context, req MigrationRequest) (Estimate, error) {
	p, err := m.validate(ctx, req)
	if err != nil {
		return Estimate{}, err
	}
	est := Estimate{Kind: req.Kind}
	if req.Kind == MigrateMode {
		n, err := m.estimateMode(ctx, p, req.Mode)
		if err != nil {
			return est, err
		}
		est.Projects = []ProjectEstimate{{TenantID: p.TenantID, ProjectID: p.ID, Ops: n}}
		est.TotalOps = n
		return est, nil
	}
	inst, err := m.instanceWraps(ctx, req)
	if err != nil {
		return est, err
	}
	for _, w := range inst {
		est.InstanceOps += m.wrapCost(req, w)
	}
	est.TotalOps = est.InstanceOps
	projects, err := m.st.ListAllProjects(ctx, "")
	if err != nil {
		return est, err
	}
	for _, p := range projects {
		ws, err := m.projectProviderWraps(ctx, req, p.ID)
		if err != nil {
			return est, err
		}
		n := 0
		for _, w := range ws {
			n += m.wrapCost(req, w)
		}
		if n > 0 {
			est.Projects = append(est.Projects, ProjectEstimate{TenantID: p.TenantID, ProjectID: p.ID, Ops: n})
			est.TotalOps += n
		}
	}
	return est, nil
}

// wrapCost is the metered cost of moving one provider wrap.
func (m *Migrator) wrapCost(req MigrationRequest, w store.KeyWrap) int {
	src := wrapProvider(w)
	if req.Kind == MigrateRotate {
		// unwrap the original, Rewrap, unwrap the result to verify
		return metered(src) + m.k.providers[src].RewrapOps() + metered(src)
	}
	return metered(src) + 2*metered(req.To)
}

// instanceWraps are the IK and RK wraps a provider or rotate migration moves.
func (m *Migrator) instanceWraps(ctx context.Context, req MigrationRequest) ([]store.KeyWrap, error) {
	var out []store.KeyWrap
	for _, kind := range []string{store.KeyKindInstance, store.KeyKindRoot} {
		ws, err := m.st.GetActiveWrapsByKind(ctx, kind)
		if err != nil {
			return nil, err
		}
		for _, w := range ws {
			if m.moves(req, w) {
				out = append(out, w)
			}
		}
	}
	return out, nil
}

// projectProviderWraps are a project's active provider wraps that move:
// the PK in mode B, the DEKs in mode C.
func (m *Migrator) projectProviderWraps(ctx context.Context, req MigrationRequest, projectID string) ([]store.KeyWrap, error) {
	ws, err := m.st.ListProjectWraps(ctx, projectID, store.WrapActive)
	if err != nil {
		return nil, err
	}
	var out []store.KeyWrap
	for _, w := range ws {
		if m.moves(req, w) {
			out = append(out, w)
		}
	}
	return out, nil
}

func (m *Migrator) moves(req MigrationRequest, w store.KeyWrap) bool {
	if w.WrapperKind != store.WrapperProvider {
		return false
	}
	switch req.Kind {
	case MigrateProvider:
		return wrapProvider(w) != req.To
	case MigrateRotate:
		return wrapProvider(w) == "rypt"
	}
	return false
}

// modeState is what a mode change needs to know about a project.
type modeState struct {
	pk   *store.KeyWrap  // active PK wrap, modes A and B
	deks []store.KeyWrap // active DEK wraps
	rk   *store.KeyWrap  // active RK wrap, if any
}

func (m *Migrator) loadModeState(ctx context.Context, p *store.Project) (modeState, error) {
	var s modeState
	ws, err := m.st.ListProjectWraps(ctx, p.ID, store.WrapActive)
	if err != nil {
		return s, err
	}
	for i := range ws {
		switch ws[i].KeyKind {
		case store.KeyKindProject:
			s.pk = &ws[i]
		case store.KeyKindDEK:
			s.deks = append(s.deks, ws[i])
		}
	}
	rks, err := m.st.GetActiveWrapsByKind(ctx, store.KeyKindRoot)
	if err != nil {
		return s, err
	}
	if len(rks) > 0 {
		s.rk = &rks[0]
	}
	return s, nil
}

func (m *Migrator) estimateMode(ctx context.Context, p *store.Project, to string) (int, error) {
	s, err := m.loadModeState(ctx, p)
	if err != nil {
		return 0, err
	}
	t := metered(m.k.current)
	rkCost := t // creating the RK wraps it under the current provider
	if s.rk != nil {
		rkCost = metered(wrapProvider(*s.rk))
	}
	pkCost := 0
	if s.pk != nil && s.pk.WrapperKind == store.WrapperProvider {
		pkCost = metered(wrapProvider(*s.pk))
	}
	n := len(s.deks)
	dekUnwraps := 0
	for _, d := range s.deks {
		if d.WrapperKind == store.WrapperProvider {
			dekUnwraps += metered(wrapProvider(d))
		}
	}
	switch p.KeyMode + to {
	case "AB": // PK: unwrap RK, wrap under provider, verify
		return rkCost + 2*t, nil
	case "BA": // PK: unwrap, wrap under RK (local), verify (local)
		return pkCost + rkCost, nil
	case "BC": // unwrap PK; each DEK: wrap under provider, verify
		return pkCost + 2*t*n, nil
	case "AC": // unwrap RK to open PK; each DEK: wrap under provider, verify
		return rkCost + 2*t*n, nil
	case "CB": // new PK: wrap, verify; each DEK: unwrap
		return 2*t + dekUnwraps, nil
	case "CA": // RK; new PK under RK (local); each DEK: unwrap
		return rkCost + dekUnwraps, nil
	}
	return 0, fmt.Errorf("unsupported transition %s to %s", p.KeyMode, to)
}

// ---- start, run, resume ----

func (m *Migrator) migrationChain(req MigrationRequest) string {
	if req.Kind == MigrateMode {
		return req.TenantID
	}
	return store.InstanceChain
}

// Start records a migration and runs it in the background.
func (m *Migrator) Start(ctx context.Context, req MigrationRequest, startedBy string) (*store.KeyMigration, error) {
	p, err := m.validate(ctx, req)
	if err != nil {
		return nil, err
	}
	total := 1
	if req.Kind != MigrateMode {
		ps, err := m.st.ListAllProjects(ctx, "")
		if err != nil {
			return nil, err
		}
		total = len(ps)
	}
	params := map[string]any{}
	switch req.Kind {
	case MigrateProvider:
		params["to"] = req.To
	case MigrateMode:
		params["tenant_id"], params["project_id"], params["mode"], params["from"] = req.TenantID, req.ProjectID, req.Mode, p.KeyMode
	}
	raw, _ := json.Marshal(params)
	now := m.now().UTC()
	mig := store.KeyMigration{ID: ids.New(), Kind: req.Kind, Params: string(raw), State: store.MigrationQueued,
		ProjectsTotal: total, StartedBy: startedBy, CreatedAt: now, UpdatedAt: now}
	ev := audit.Event{ChainID: m.migrationChain(req), ActorKind: audit.ActorUser, ActorID: startedBy, Action: "keys.migration.start",
		TargetKind: "key_migration", TargetID: mig.ID, ProjectID: req.ProjectID, Metadata: map[string]any{"kind": req.Kind, "params": params}}
	err = m.audit.Record(ctx, ev, func(e *store.AuditEvent) error { return m.st.CreateKeyMigration(ctx, mig, e) })
	if err != nil {
		return nil, err
	}
	m.launch(mig)
	return &mig, nil
}

// Resume restarts unfinished migrations after a restart; each continues
// from the first unfinished project.
func (m *Migrator) Resume(ctx context.Context) error {
	ms, err := m.st.ListUnfinishedKeyMigrations(ctx)
	if err != nil {
		return err
	}
	for _, mig := range ms {
		m.log.Info("resuming key migration", "id", mig.ID, "kind", mig.Kind, "done", mig.ProjectsDone, "total", mig.ProjectsTotal)
		m.launch(mig)
	}
	return nil
}

func (m *Migrator) launch(mig store.KeyMigration) {
	ctx, cancel := context.WithCancel(context.Background())
	m.mu.Lock()
	m.running[mig.ID] = cancel
	m.mu.Unlock()
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		defer cancel()
		m.run(ctx, mig)
		m.mu.Lock()
		delete(m.running, mig.ID)
		m.mu.Unlock()
	}()
}

// Stop cancels running migrations and waits for them; they resume on the
// next start.
func (m *Migrator) Stop() {
	m.mu.Lock()
	for _, c := range m.running {
		c()
	}
	m.mu.Unlock()
	m.wg.Wait()
}

// Wait blocks until running migrations finish (tests).
func (m *Migrator) Wait() { m.wg.Wait() }

func requestOf(mig store.KeyMigration) MigrationRequest {
	var p struct {
		To        string `json:"to"`
		TenantID  string `json:"tenant_id"`
		ProjectID string `json:"project_id"`
		Mode      string `json:"mode"`
	}
	_ = json.Unmarshal([]byte(mig.Params), &p)
	return MigrationRequest{Kind: mig.Kind, To: p.To, TenantID: p.TenantID, ProjectID: p.ProjectID, Mode: p.Mode}
}

func (m *Migrator) run(ctx context.Context, mig store.KeyMigration) {
	req := requestOf(mig)
	mig.State, mig.UpdatedAt = store.MigrationRunning, m.now().UTC()
	if err := m.st.UpdateKeyMigration(ctx, mig, nil); err != nil {
		m.log.Error("key migration", "id", mig.ID, "error", err.Error())
		return
	}
	err := m.runUnits(ctx, &mig, req)
	if ctx.Err() != nil {
		// Shutting down: leave the migration running so it resumes.
		return
	}
	mig.UpdatedAt = m.now().UTC()
	mig.FinishedAt = &mig.UpdatedAt
	ev := audit.Event{ChainID: m.migrationChain(req), ActorKind: audit.ActorSystem, Action: "keys.migration.complete",
		TargetKind: "key_migration", TargetID: mig.ID, ProjectID: req.ProjectID,
		Metadata: map[string]any{"kind": mig.Kind, "projects_done": mig.ProjectsDone, "projects_total": mig.ProjectsTotal}}
	if err != nil {
		mig.State, mig.Error = store.MigrationFailed, err.Error()
		ev.Result = audit.Error
		ev.ProviderRequestID = provider.RequestIDOf(err)
		ev.Metadata["error"] = err.Error()
		m.log.Error("key migration failed", "id", mig.ID, "error", err.Error())
	} else {
		mig.State = store.MigrationSucceeded
		m.log.Info("key migration finished", "id", mig.ID, "kind", mig.Kind)
	}
	bg := context.WithoutCancel(ctx)
	if uerr := m.audit.Record(bg, ev, func(e *store.AuditEvent) error { return m.st.UpdateKeyMigration(bg, mig, e) }); uerr != nil {
		m.log.Error("key migration", "id", mig.ID, "error", uerr.Error())
	}
}

func (m *Migrator) runUnits(ctx context.Context, mig *store.KeyMigration, req MigrationRequest) error {
	if req.Kind == MigrateMode {
		if mig.ProjectsDone > 0 {
			return nil
		}
		if err := m.modeUnit(ctx, mig.ID, req); err != nil {
			return err
		}
		mig.ProjectsDone, mig.Cursor = 1, req.ProjectID
		mig.UpdatedAt = m.now().UTC()
		return m.st.UpdateKeyMigration(ctx, *mig, nil)
	}
	if mig.Cursor == "" {
		if err := m.instanceUnit(ctx, mig.ID, req); err != nil {
			return err
		}
		mig.Cursor, mig.UpdatedAt = instanceCursor, m.now().UTC()
		if err := m.st.UpdateKeyMigration(ctx, *mig, nil); err != nil {
			return err
		}
	}
	projects, err := m.st.ListAllProjects(ctx, mig.Cursor)
	if err != nil {
		return err
	}
	for _, p := range projects {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := m.projectUnit(ctx, mig.ID, req, p); err != nil {
			return fmt.Errorf("project %s: %w", p.Slug, err)
		}
		mig.ProjectsDone++
		mig.Cursor, mig.UpdatedAt = p.ID, m.now().UTC()
		if mig.ProjectsDone > mig.ProjectsTotal {
			mig.ProjectsTotal = mig.ProjectsDone
		}
		if err := m.st.UpdateKeyMigration(ctx, *mig, nil); err != nil {
			return err
		}
	}
	return nil
}

// ---- units of work ----

// change is one new wrap with the key it must open to.
type change struct {
	old *store.KeyWrap // the active wrap it replaces, if any
	new store.KeyWrap  // inserted as pending
	key []byte
	// parent opens a wrap under a root or project key during verification.
	parent []byte
}

type unit struct {
	name    string // for errors and hooks
	chain   string // audit chain of the flip
	project *store.Project
	changes []change
	retire  []string // active wraps retired without replacement
	newMode string
	parents [][]byte // key bytes to clear afterwards
}

func (u *unit) clear() {
	for _, c := range u.changes {
		clear(c.key)
	}
	for _, p := range u.parents {
		clear(p)
	}
}

func (m *Migrator) step(ctx context.Context, stage, name string) error {
	if m.hook != nil {
		return m.hook(ctx, stage, name)
	}
	return nil
}

// clearStale deletes pending wraps an interrupted run left in a unit.
func (m *Migrator) clearStale(ctx context.Context, projectID string) error {
	n, err := m.st.DeletePendingWraps(ctx, projectID)
	if n > 0 {
		m.log.Warn("deleted pending wraps from an interrupted migration", "project", projectID, "count", n)
	}
	return err
}

// apply runs steps 3 to 6 of core 5.7 for a planned unit.
func (m *Migrator) apply(ctx context.Context, migID, kind string, u *unit) error {
	defer u.clear()
	if len(u.changes) == 0 && len(u.retire) == 0 && u.newMode == "" {
		return nil
	}
	pending := make([]store.KeyWrap, len(u.changes))
	pendingIDs := make([]string, len(u.changes))
	for i, c := range u.changes {
		c.new.State = store.WrapPending
		pending[i], pendingIDs[i] = c.new, c.new.ID
	}
	if err := m.step(ctx, "insert", u.name); err != nil {
		return err
	}
	if err := m.st.InsertWraps(ctx, pending); err != nil {
		return fmt.Errorf("insert pending wraps: %w", err)
	}
	abort := func(err error) error {
		if derr := m.st.DeleteWraps(context.WithoutCancel(ctx), pendingIDs); derr != nil {
			m.log.Error("delete pending wraps", "unit", u.name, "error", derr.Error())
		}
		return err
	}
	if err := m.step(ctx, "verify", u.name); err != nil {
		return abort(err)
	}
	for _, c := range u.changes {
		var got []byte
		var err error
		if c.parent != nil {
			got, err = open(c.parent, c.new.Ciphertext, WrapAAD(m.k.instanceID, c.new))
		} else {
			got, err = m.k.unwrap(ctx, c.new)
		}
		if err != nil {
			return abort(fmt.Errorf("verify %s %s: %w", c.new.KeyKind, c.new.KeyID, err))
		}
		ok := subtle.ConstantTimeCompare(got, c.key) == 1
		clear(got)
		if !ok {
			return abort(fmt.Errorf("verify %s %s: the new wrap does not open to the original key", c.new.KeyKind, c.new.KeyID))
		}
	}
	if err := m.step(ctx, "flip", u.name); err != nil {
		return abort(err)
	}
	retire := append([]string(nil), u.retire...)
	for _, c := range u.changes {
		if c.old != nil {
			retire = append(retire, c.old.ID)
		}
	}
	meta := map[string]any{"migration_id": migID, "kind": kind, "activated": len(pendingIDs), "retired": len(retire)}
	projectID := ""
	if u.project != nil {
		projectID = u.project.ID
		if u.newMode != "" {
			meta["from"], meta["to"] = u.project.KeyMode, u.newMode
		}
	}
	ev := audit.Event{ChainID: u.chain, ActorKind: audit.ActorSystem, Action: "keys.migration.flip", TargetKind: "key_migration",
		TargetID: migID, ProjectID: projectID, Metadata: meta}
	err := m.audit.Record(ctx, ev, func(e *store.AuditEvent) error {
		return m.st.FlipWraps(ctx, retire, pendingIDs, projectID, u.newMode, m.now().UTC(), e)
	})
	if err != nil {
		return abort(fmt.Errorf("flip: %w", err))
	}
	if err := m.step(ctx, "evict", u.name); err != nil {
		return err
	}
	if u.project != nil {
		m.k.EvictProject(u.project.ID)
	} else {
		m.k.cache.evictAll()
	}
	return nil
}

// moveWraps plans provider or rotate changes for provider wraps.
func (m *Migrator) moveWraps(ctx context.Context, req MigrationRequest, ws []store.KeyWrap, u *unit) error {
	for i := range ws {
		w := ws[i]
		key, err := m.k.unwrap(ctx, w)
		if err != nil {
			return fmt.Errorf("unwrap %s %s: %w", w.KeyKind, w.KeyID, err)
		}
		nw := w
		nw.ID, nw.State, nw.CreatedAt = ids.New(), store.WrapPending, m.now().UTC()
		if req.Kind == MigrateRotate {
			p := m.k.providers[wrapProvider(w)]
			_, ref, _ := strings.Cut(w.WrapperRef, ":")
			pw, err := p.Rewrap(ctx, provider.WrappedKey{Provider: wrapProvider(w), KeyRef: ref, KeyVersion: w.KeyVersion, Ciphertext: w.Ciphertext},
				WrapAAD(m.k.instanceID, w))
			if err != nil {
				clear(key)
				return fmt.Errorf("rewrap %s %s: %w", w.KeyKind, w.KeyID, err)
			}
			nw.WrapperRef, nw.KeyVersion, nw.Ciphertext = provider.Ref(pw), pw.KeyVersion, pw.Ciphertext
		} else {
			pw, err := m.k.wrapUnderNamedProvider(ctx, req.To, w.KeyKind, w.KeyID, w.TenantID, w.ProjectID, key)
			if err != nil {
				clear(key)
				return fmt.Errorf("wrap %s %s: %w", w.KeyKind, w.KeyID, err)
			}
			nw.WrapperRef, nw.KeyVersion, nw.Ciphertext = pw.WrapperRef, pw.KeyVersion, pw.Ciphertext
		}
		u.changes = append(u.changes, change{old: &ws[i], new: nw, key: key})
	}
	return nil
}

// instanceUnit moves the IK first, as its own unit, with the RK (core 5.7).
func (m *Migrator) instanceUnit(ctx context.Context, migID string, req MigrationRequest) error {
	m.k.rkMu.Lock()
	defer m.k.rkMu.Unlock()
	if err := m.clearStale(ctx, ""); err != nil {
		return err
	}
	ws, err := m.instanceWraps(ctx, req)
	if err != nil {
		return err
	}
	u := &unit{name: "instance", chain: store.InstanceChain}
	if err := m.step(ctx, "compute", u.name); err != nil {
		return err
	}
	if err := m.moveWraps(ctx, req, ws, u); err != nil {
		u.clear()
		return err
	}
	return m.apply(ctx, migID, req.Kind, u)
}

// projectUnit moves one project's provider wraps under its write lock.
func (m *Migrator) projectUnit(ctx context.Context, migID string, req MigrationRequest, p store.Project) error {
	l := m.k.projectLock(p.ID)
	l.Lock()
	defer l.Unlock()
	if err := m.clearStale(ctx, p.ID); err != nil {
		return err
	}
	ws, err := m.projectProviderWraps(ctx, req, p.ID)
	if err != nil {
		return err
	}
	u := &unit{name: p.ID, chain: p.TenantID, project: &p}
	if err := m.step(ctx, "compute", u.name); err != nil {
		return err
	}
	if err := m.moveWraps(ctx, req, ws, u); err != nil {
		u.clear()
		return err
	}
	return m.apply(ctx, migID, req.Kind, u)
}

// rootKey returns the RK's ID and bytes, unwrapping its active wrap
// directly or creating the RK.
func (m *Migrator) rootKey(ctx context.Context, s modeState) (string, []byte, error) {
	if s.rk != nil {
		b, err := m.k.unwrap(ctx, *s.rk)
		return s.rk.KeyID, b, err
	}
	id, err := m.k.ensureRootKey(ctx)
	if err != nil {
		return "", nil, err
	}
	b, ok := m.k.cache.get(id)
	if !ok {
		w, err := m.st.GetActiveWrap(ctx, id)
		if err != nil {
			return "", nil, err
		}
		b, err = m.k.unwrap(ctx, *w)
		if err != nil {
			return "", nil, err
		}
	}
	return id, b, nil
}

// modeUnit changes one project's key mode (core 5.7 step 2).
func (m *Migrator) modeUnit(ctx context.Context, migID string, req MigrationRequest) error {
	l := m.k.projectLock(req.ProjectID)
	l.Lock()
	defer l.Unlock()
	if err := m.clearStale(ctx, req.ProjectID); err != nil {
		return err
	}
	p, err := m.st.GetProject(ctx, req.TenantID, req.ProjectID)
	if err != nil {
		return err
	}
	if p.KeyMode == req.Mode {
		return nil
	}
	s, err := m.loadModeState(ctx, p)
	if err != nil {
		return err
	}
	u := &unit{name: p.ID, chain: p.TenantID, project: p, newMode: req.Mode}
	if err := m.step(ctx, "compute", u.name); err != nil {
		return err
	}
	if err := m.planMode(ctx, p, s, req.Mode, u); err != nil {
		u.clear()
		return err
	}
	return m.apply(ctx, migID, MigrateMode, u)
}

func (m *Migrator) planMode(ctx context.Context, p *store.Project, s modeState, to string, u *unit) error {
	now := m.now().UTC()
	from := p.KeyMode
	// The current PK bytes, for modes A and B.
	var pk []byte
	if from == ModeA || from == ModeB {
		if s.pk == nil {
			return errors.New("the project has no active project key")
		}
		if from == ModeA {
			if s.rk == nil {
				return errors.New("the project is in mode A but there is no root key")
			}
			rk, err := m.k.unwrap(ctx, *s.rk)
			if err != nil {
				return fmt.Errorf("unwrap root key: %w", err)
			}
			u.parents = append(u.parents, rk)
			if pk, err = open(rk, s.pk.Ciphertext, WrapAAD(m.k.instanceID, *s.pk)); err != nil {
				return fmt.Errorf("open project key: %w", err)
			}
		} else {
			var err error
			if pk, err = m.k.unwrap(ctx, *s.pk); err != nil {
				return fmt.Errorf("unwrap project key: %w", err)
			}
		}
		u.parents = append(u.parents, pk)
	}
	pending := func(w store.KeyWrap) store.KeyWrap {
		w.ID, w.State, w.CreatedAt = ids.New(), store.WrapPending, now
		return w
	}
	switch from + to {
	case "AB": // PK moves from under the RK to under the provider
		w, err := m.k.wrapUnderProvider(ctx, store.KeyKindProject, s.pk.KeyID, p.TenantID, p.ID, pk)
		if err != nil {
			return err
		}
		u.changes = append(u.changes, change{old: s.pk, new: pending(w), key: append([]byte(nil), pk...)})
	case "BA": // PK moves from under the provider to under the RK
		rkID, rk, err := m.rootKey(ctx, s)
		if err != nil {
			return err
		}
		u.parents = append(u.parents, rk)
		w, err := m.k.wrapUnderParent(store.KeyKindProject, s.pk.KeyID, p.TenantID, p.ID, store.WrapperRoot, rkID, rk, pk)
		if err != nil {
			return err
		}
		u.changes = append(u.changes, change{old: s.pk, new: pending(w), key: append([]byte(nil), pk...), parent: rk})
	case "BC", "AC": // each DEK moves under the provider; the PK retires
		for i := range s.deks {
			d := s.deks[i]
			dek, err := open(pk, d.Ciphertext, WrapAAD(m.k.instanceID, d))
			if err != nil {
				return fmt.Errorf("open DEK %s: %w", d.KeyID, err)
			}
			w, err := m.k.wrapUnderProvider(ctx, store.KeyKindDEK, d.KeyID, p.TenantID, p.ID, dek)
			if err != nil {
				clear(dek)
				return err
			}
			u.changes = append(u.changes, change{old: &s.deks[i], new: pending(w), key: dek})
		}
		u.retire = append(u.retire, s.pk.ID)
	case "CB", "CA": // a new PK; each DEK moves under it
		newPK := newKey()
		pkID := ids.New()
		var pkWrap store.KeyWrap
		var parent []byte
		var err error
		if to == ModeB {
			pkWrap, err = m.k.wrapUnderProvider(ctx, store.KeyKindProject, pkID, p.TenantID, p.ID, newPK)
		} else {
			rkID, rk, rerr := m.rootKey(ctx, s)
			if rerr != nil {
				clear(newPK)
				return rerr
			}
			u.parents = append(u.parents, rk)
			parent = rk
			pkWrap, err = m.k.wrapUnderParent(store.KeyKindProject, pkID, p.TenantID, p.ID, store.WrapperRoot, rkID, rk, newPK)
		}
		if err != nil {
			clear(newPK)
			return err
		}
		u.changes = append(u.changes, change{new: pending(pkWrap), key: newPK, parent: parent})
		for i := range s.deks {
			d := s.deks[i]
			dek, err := m.k.unwrap(ctx, d)
			if err != nil {
				return fmt.Errorf("unwrap DEK %s: %w", d.KeyID, err)
			}
			w, err := m.k.wrapUnderParent(store.KeyKindDEK, d.KeyID, p.TenantID, p.ID, store.WrapperProject, pkID, newPK, dek)
			if err != nil {
				clear(dek)
				return err
			}
			u.changes = append(u.changes, change{old: &s.deks[i], new: pending(w), key: dek, parent: newPK})
		}
	default:
		return fmt.Errorf("unsupported transition %s to %s", from, to)
	}
	return nil
}
