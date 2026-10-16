package keys

import (
	"context"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/x6c-co/rypt-store/internal/ids"
	"github.com/x6c-co/rypt-store/internal/keys/provider"
	"github.com/x6c-co/rypt-store/internal/metrics"
	"github.com/x6c-co/rypt-store/internal/store"
)

// Modes (core 5.2).
const (
	ModeA = "A" // provider -> RK -> PK -> DEK
	ModeB = "B" // provider -> PK -> DEK
	ModeC = "C" // provider -> DEK
)

// ValidMode reports whether m is A, B, or C.
func ValidMode(m string) bool { return m == ModeA || m == ModeB || m == ModeC }

// Options configures a Service.
type Options struct {
	Store store.Store
	// Providers are every provider whose configuration is present (core 5.7).
	Providers []provider.Provider
	// Current names the provider used for new wraps (keys.provider).
	Current     string
	CacheTTL    time.Duration
	CacheMax    int
	ServeCached bool
	MaxStale    time.Duration
	Metrics     *metrics.Metrics
	Logger      *slog.Logger
	Now         func() time.Time
	// OnOutage is called when a provider becomes unreachable or reachable
	// again, so that the transition can be audited (core 8.1).
	OnOutage func(ctx context.Context, providerName string, down bool, cause error)
}

// Service owns the key hierarchy.
type Service struct {
	st         store.Store
	providers  map[string]provider.Provider
	current    string
	cache      *cache
	serveStale bool
	m          *metrics.Metrics
	log        *slog.Logger
	now        func() time.Time
	onOutage   func(ctx context.Context, providerName string, down bool, cause error)
	flight     singleflight.Group

	instanceID string
	ikID       string

	rkMu sync.Mutex

	projMu    sync.Mutex
	projLocks map[string]*sync.RWMutex

	stateMu   sync.Mutex
	down      map[string]bool
	lastQuota *provider.Error
	quotaAt   time.Time
	opDeltas  map[store.ProviderOpCount]int64
}

func New(o Options) (*Service, error) {
	s := &Service{
		st: o.Store, providers: map[string]provider.Provider{}, current: o.Current,
		serveStale: o.ServeCached, m: o.Metrics, log: o.Logger, now: o.Now, onOutage: o.OnOutage,
		projLocks: map[string]*sync.RWMutex{}, down: map[string]bool{}, opDeltas: map[store.ProviderOpCount]int64{},
	}
	if s.now == nil {
		s.now = time.Now
	}
	if s.log == nil {
		s.log = slog.New(slog.DiscardHandler)
	}
	if s.m == nil {
		s.m = metrics.New()
	}
	maxStale := time.Duration(0)
	if o.ServeCached {
		maxStale = o.MaxStale
	}
	if o.CacheMax <= 0 {
		o.CacheMax = 10000
	}
	if o.CacheTTL <= 0 {
		o.CacheTTL = 15 * time.Minute
	}
	s.cache = newCache(o.CacheTTL, maxStale, o.CacheMax, s.now)
	for _, p := range o.Providers {
		s.providers[p.Name()] = &counting{Provider: p, s: s}
	}
	if _, ok := s.providers[o.Current]; !ok {
		return nil, fmt.Errorf("keys.provider is %q but that provider is not configured", o.Current)
	}
	return s, nil
}

// InstanceID returns the instance ID loaded by Init.
func (s *Service) InstanceID() string { return s.instanceID }

// CurrentProvider names the provider for new wraps.
func (s *Service) CurrentProvider() string { return s.current }

// ProviderNames lists the loaded providers.
func (s *Service) ProviderNames() []string {
	var out []string
	for n := range s.providers {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Provider returns a loaded provider by name.
func (s *Service) Provider(name string) (provider.Provider, bool) {
	p, ok := s.providers[name]
	return p, ok
}

// Init loads the instance and its IK, creating both on first start. created
// reports whether this call created the instance.
func (s *Service) Init(ctx context.Context) (inst *store.Instance, created bool, err error) {
	inst, err = s.st.GetInstance(ctx)
	if errors.Is(err, store.ErrNotFound) {
		now := s.now().UTC()
		newInst := store.Instance{ID: ids.New(), CreatedAt: now}
		ik := newKey()
		defer clear(ik)
		ikID := ids.New()
		s.instanceID = newInst.ID
		w, werr := s.wrapUnderProvider(ctx, store.KeyKindInstance, ikID, "", "", ik)
		if werr != nil {
			return nil, false, fmt.Errorf("wrap instance key: %w", werr)
		}
		if err := s.st.CreateInstance(ctx, newInst, w); err != nil && !errors.Is(err, store.ErrConflict) {
			return nil, false, err
		} else if err == nil {
			created = true
			s.cache.put(ikID, "", ik)
		}
		inst, err = s.st.GetInstance(ctx)
	}
	if err != nil {
		return nil, false, err
	}
	s.instanceID = inst.ID
	iks, err := s.st.GetActiveWrapsByKind(ctx, store.KeyKindInstance)
	if err != nil {
		return nil, false, err
	}
	if len(iks) != 1 {
		return nil, false, fmt.Errorf("found %d active instance keys, want 1", len(iks))
	}
	s.ikID = iks[0].KeyID
	return inst, created, nil
}

// CheckProviders refuses a configuration that cannot read existing wraps
// (core 5.7): every provider referenced by an active or retired wrap must be
// loaded. It then unwraps the IK, which detects a wrong local KEK. A
// provider outage at this point is logged, not fatal.
func (s *Service) CheckProviders(ctx context.Context) error {
	counts, err := s.st.CountWrapsByProvider(ctx)
	if err != nil {
		return err
	}
	var missing []string
	for name, n := range counts {
		if _, ok := s.providers[name]; !ok && n > 0 {
			missing = append(missing, fmt.Sprintf("%d key wraps reference provider %q, which is not configured", n, name))
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return errors.New(strings.Join(missing, "; "))
	}
	ik, err := s.key(ctx, s.ikID)
	if err != nil {
		if provider.KindOf(err) == provider.Outage {
			s.log.Warn("key provider unreachable at start-up", "error", err.Error())
			return nil
		}
		return fmt.Errorf("unwrap instance key: %w", err)
	}
	clear(ik)
	return nil
}

// ---- AAD (core 5.5) ----

// WrapAAD returns the AAD that binds a wrap to its position in the hierarchy.
func WrapAAD(instanceID string, w store.KeyWrap) []byte {
	switch w.KeyKind {
	case store.KeyKindInstance:
		return []byte("rypt-store/v1/ik/" + instanceID + "/" + w.KeyID)
	case store.KeyKindRoot:
		return []byte("rypt-store/v1/rk/" + instanceID + "/" + w.KeyID)
	case store.KeyKindProject:
		return []byte("rypt-store/v1/pk/" + w.TenantID + "/" + w.ProjectID + "/" + w.KeyID)
	default:
		return []byte("rypt-store/v1/dek/" + w.TenantID + "/" + w.ProjectID + "/" + w.KeyID)
	}
}

// ValueAAD binds a secret value to its version (core 5.5).
func ValueAAD(tenantID, environmentID, secretID string, version int) []byte {
	return fmt.Appendf(nil, "rypt-store/v1/val/%s/%s/%s/%d", tenantID, environmentID, secretID, version)
}

func totpAAD(userID string) []byte { return []byte("rypt-store/v1/totp/" + userID) }

// ---- unwrapping ----

// key returns a copy of a logical key's bytes, from the cache or by
// unwrapping its active wrap. The caller clears the copy.
func (s *Service) key(ctx context.Context, keyID string) ([]byte, error) {
	if b, ok := s.cache.get(keyID); ok {
		s.m.KeyCacheHits.Inc()
		return b, nil
	}
	s.m.KeyCacheMisses.Inc()
	v, err, _ := s.flight.Do(keyID, func() (any, error) {
		w, err := s.st.GetActiveWrap(ctx, keyID)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return nil, fmt.Errorf("key %s has no active wrap: %w", keyID, err)
			}
			return nil, err
		}
		b, err := s.unwrap(ctx, *w)
		if err != nil {
			return nil, err
		}
		s.cache.put(keyID, w.ProjectID, b)
		return b, nil
	})
	if err != nil {
		if s.serveStale && provider.KindOf(err) == provider.Outage {
			if b, ok := s.cache.getStale(keyID); ok {
				s.m.StaleKeyUses.Inc()
				return b, nil
			}
		}
		return nil, err
	}
	return append([]byte(nil), v.([]byte)...), nil
}

// unwrap opens one wrap, without the cache.
func (s *Service) unwrap(ctx context.Context, w store.KeyWrap) ([]byte, error) {
	aad := WrapAAD(s.instanceID, w)
	switch w.WrapperKind {
	case store.WrapperProvider:
		name, ref, _ := strings.Cut(w.WrapperRef, ":")
		p, ok := s.providers[name]
		if !ok {
			return nil, fmt.Errorf("wrap %s needs provider %q, which is not configured", w.ID, name)
		}
		return p.Unwrap(ctx, provider.WrappedKey{Provider: name, KeyRef: ref, KeyVersion: w.KeyVersion, Ciphertext: w.Ciphertext}, aad)
	case store.WrapperRoot, store.WrapperProject:
		parent, err := s.key(ctx, w.WrapperRef)
		if err != nil {
			return nil, err
		}
		defer clear(parent)
		b, err := open(parent, w.Ciphertext, aad)
		if err != nil {
			return nil, fmt.Errorf("unwrap %s %s: %w", w.KeyKind, w.KeyID, err)
		}
		return b, nil
	}
	return nil, fmt.Errorf("wrap %s has unknown wrapper kind %q", w.ID, w.WrapperKind)
}

// ---- wrapping ----

func (s *Service) wrapUnderProvider(ctx context.Context, kind, keyID, tenantID, projectID string, key []byte) (store.KeyWrap, error) {
	return s.wrapUnderNamedProvider(ctx, s.current, kind, keyID, tenantID, projectID, key)
}

func (s *Service) wrapUnderNamedProvider(ctx context.Context, name, kind, keyID, tenantID, projectID string, key []byte) (store.KeyWrap, error) {
	p, ok := s.providers[name]
	if !ok {
		return store.KeyWrap{}, fmt.Errorf("provider %q is not configured", name)
	}
	w := store.KeyWrap{ID: ids.New(), KeyID: keyID, KeyKind: kind, TenantID: tenantID, ProjectID: projectID,
		WrapperKind: store.WrapperProvider, State: store.WrapActive, CreatedAt: s.now().UTC()}
	pw, err := p.Wrap(ctx, key, WrapAAD(s.instanceID, w))
	if err != nil {
		return store.KeyWrap{}, err
	}
	w.WrapperRef, w.KeyVersion, w.Ciphertext = provider.Ref(pw), pw.KeyVersion, pw.Ciphertext
	return w, nil
}

func (s *Service) wrapUnderParent(kind, keyID, tenantID, projectID, wrapperKind, parentID string, parent, key []byte) (store.KeyWrap, error) {
	w := store.KeyWrap{ID: ids.New(), KeyID: keyID, KeyKind: kind, TenantID: tenantID, ProjectID: projectID,
		WrapperKind: wrapperKind, WrapperRef: parentID, State: store.WrapActive, CreatedAt: s.now().UTC()}
	ct, err := seal(parent, key, WrapAAD(s.instanceID, w))
	if err != nil {
		return store.KeyWrap{}, err
	}
	w.Ciphertext = ct
	return w, nil
}

// ensureRootKey returns the RK's key ID, creating the RK when no project has
// needed it yet.
func (s *Service) ensureRootKey(ctx context.Context) (string, error) {
	s.rkMu.Lock()
	defer s.rkMu.Unlock()
	for range 2 {
		rks, err := s.st.GetActiveWrapsByKind(ctx, store.KeyKindRoot)
		if err != nil {
			return "", err
		}
		if len(rks) > 0 {
			return rks[0].KeyID, nil
		}
		rk := newKey()
		rkID := ids.New()
		w, err := s.wrapUnderProvider(ctx, store.KeyKindRoot, rkID, "", "", rk)
		if err != nil {
			clear(rk)
			return "", err
		}
		err = s.st.CreateRootKey(ctx, w)
		if err == nil {
			s.cache.put(rkID, "", rk)
			clear(rk)
			return rkID, nil
		}
		clear(rk)
		if !errors.Is(err, store.ErrConflict) {
			return "", err
		}
	}
	return "", errors.New("could not create the root key")
}

// NewProjectWraps creates a project's key wraps for its mode: the PK wrapped
// under the RK in mode A or under the provider in mode B, nothing in mode C.
func (s *Service) NewProjectWraps(ctx context.Context, tenantID, projectID, mode string) ([]store.KeyWrap, error) {
	switch mode {
	case ModeA, ModeB:
		pk := newKey()
		defer clear(pk)
		pkID := ids.New()
		var w store.KeyWrap
		var err error
		if mode == ModeA {
			rkID, rerr := s.ensureRootKey(ctx)
			if rerr != nil {
				return nil, rerr
			}
			rk, rerr := s.key(ctx, rkID)
			if rerr != nil {
				return nil, rerr
			}
			defer clear(rk)
			w, err = s.wrapUnderParent(store.KeyKindProject, pkID, tenantID, projectID, store.WrapperRoot, rkID, rk, pk)
		} else {
			w, err = s.wrapUnderProvider(ctx, store.KeyKindProject, pkID, tenantID, projectID, pk)
		}
		if err != nil {
			return nil, err
		}
		s.cache.put(pkID, projectID, pk)
		return []store.KeyWrap{w}, nil
	case ModeC:
		return nil, nil
	}
	return nil, fmt.Errorf("unknown key mode %q", mode)
}

// projectKeyID finds the project's active PK.
func (s *Service) projectKeyID(ctx context.Context, projectID string) (string, error) {
	ws, err := s.st.ListProjectWraps(ctx, projectID, store.WrapActive)
	if err != nil {
		return "", err
	}
	for _, w := range ws {
		if w.KeyKind == store.KeyKindProject {
			return w.KeyID, nil
		}
	}
	return "", fmt.Errorf("project %s has no active project key", projectID)
}

// ---- project write lock ----

func (s *Service) projectLock(projectID string) *sync.RWMutex {
	s.projMu.Lock()
	defer s.projMu.Unlock()
	l, ok := s.projLocks[projectID]
	if !ok {
		l = &sync.RWMutex{}
		s.projLocks[projectID] = l
	}
	return l
}

// WithProjectWrite runs fn, which seals values and stores them, while no
// re-wrap migration of the project is in its unit of work. A secret write
// must hold this across both sealing and storing, so that a DEK is never
// wrapped under a PK that a concurrent migration retires.
func (s *Service) WithProjectWrite(projectID string, fn func() error) error {
	l := s.projectLock(projectID)
	l.RLock()
	defer l.RUnlock()
	return fn()
}

// ---- values ----

// Sealed is an encrypted secret value ready to store.
type Sealed struct {
	Ciphertext []byte
	DEK        store.KeyWrap
	MAC        []byte
}

// SealValue encrypts a value under a fresh DEK and wraps the DEK for the
// project's key mode (feature 01 3.1 steps 2-5). The caller holds
// WithProjectWrite and passes the project as just read from the store.
func (s *Service) SealValue(ctx context.Context, p store.Project, environmentID, secretID string, version int, value []byte) (Sealed, error) {
	dek := newKey()
	defer clear(dek)
	dekID := ids.New()
	ct, err := seal(dek, value, ValueAAD(p.TenantID, environmentID, secretID, version))
	if err != nil {
		return Sealed{}, err
	}
	var w store.KeyWrap
	switch p.KeyMode {
	case ModeC:
		w, err = s.wrapUnderProvider(ctx, store.KeyKindDEK, dekID, p.TenantID, p.ID, dek)
	case ModeA, ModeB:
		pkID, perr := s.projectKeyID(ctx, p.ID)
		if perr != nil {
			return Sealed{}, perr
		}
		pk, perr := s.key(ctx, pkID)
		if perr != nil {
			return Sealed{}, perr
		}
		w, err = s.wrapUnderParent(store.KeyKindDEK, dekID, p.TenantID, p.ID, store.WrapperProject, pkID, pk, dek)
		clear(pk)
	default:
		err = fmt.Errorf("project %s has unknown key mode %q", p.ID, p.KeyMode)
	}
	if err != nil {
		return Sealed{}, err
	}
	mac, err := s.ValueMAC(ctx, p.ID, value)
	if err != nil {
		return Sealed{}, err
	}
	s.cache.put(dekID, p.ID, dek)
	return Sealed{Ciphertext: ct, DEK: w, MAC: mac}, nil
}

// OpenValue decrypts a stored secret version.
func (s *Service) OpenValue(ctx context.Context, tenantID, environmentID string, v store.SecretVersion) ([]byte, error) {
	dek, err := s.key(ctx, v.DEKID)
	if err != nil {
		return nil, err
	}
	defer clear(dek)
	return open(dek, v.Ciphertext, ValueAAD(tenantID, environmentID, v.SecretID, v.Version))
}

// compareInfo is the HKDF info of project comparison keys (feature 01 2.3).
const compareInfo = "rypt-store/v1/compare"

// ValueMAC returns HMAC-SHA256 of value under the project comparison key
// HKDF-SHA256(IK, salt = project_id, info = "rypt-store/v1/compare").
func (s *Service) ValueMAC(ctx context.Context, projectID string, value []byte) ([]byte, error) {
	ik, err := s.key(ctx, s.ikID)
	if err != nil {
		return nil, err
	}
	defer clear(ik)
	ck, err := hkdf.Key(sha256.New, ik, []byte(projectID), compareInfo, KeySize)
	if err != nil {
		return nil, err
	}
	defer clear(ck)
	h := hmac.New(sha256.New, ck)
	h.Write(value)
	return h.Sum(nil), nil
}

// EncryptTOTP encrypts a TOTP secret under the IK (core 6.2).
func (s *Service) EncryptTOTP(ctx context.Context, userID string, secret []byte) ([]byte, error) {
	ik, err := s.key(ctx, s.ikID)
	if err != nil {
		return nil, err
	}
	defer clear(ik)
	return seal(ik, secret, totpAAD(userID))
}

// DecryptTOTP reverses EncryptTOTP.
func (s *Service) DecryptTOTP(ctx context.Context, userID string, ct []byte) ([]byte, error) {
	ik, err := s.key(ctx, s.ikID)
	if err != nil {
		return nil, err
	}
	defer clear(ik)
	return open(ik, ct, totpAAD(userID))
}

// EvictProject drops a project's cached keys.
func (s *Service) EvictProject(projectID string) { s.cache.evictProject(projectID) }

// ---- provider status and operation counts ----

// counting instruments a provider: Prometheus counts, the local monthly
// counts, and outage transitions.
type counting struct {
	provider.Provider
	s *Service
}

func (c *counting) Wrap(ctx context.Context, key, aad []byte) (provider.WrappedKey, error) {
	w, err := c.Provider.Wrap(ctx, key, aad)
	c.s.record(ctx, c.Name(), "wrap", 1, err)
	return w, err
}

func (c *counting) Unwrap(ctx context.Context, w provider.WrappedKey, aad []byte) ([]byte, error) {
	b, err := c.Provider.Unwrap(ctx, w, aad)
	c.s.record(ctx, c.Name(), "unwrap", 1, err)
	return b, err
}

func (c *counting) Rewrap(ctx context.Context, w provider.WrappedKey, aad []byte) (provider.WrappedKey, error) {
	out, err := c.Provider.Rewrap(ctx, w, aad)
	c.s.record(ctx, c.Name(), "rewrap", max(1, c.RewrapOps()), err)
	return out, err
}

func (s *Service) record(ctx context.Context, name, op string, n int, err error) {
	result := "success"
	if err != nil {
		result = provider.KindOf(err).String()
	}
	s.m.ProviderOps.WithLabelValues(name, op, result).Add(float64(n))

	s.stateMu.Lock()
	month := s.now().UTC().Format("2006-01")
	s.opDeltas[store.ProviderOpCount{Month: month, Provider: name, Op: op}] += int64(n)
	var transition *bool
	kind := provider.KindOf(err)
	// Any answer other than an outage, including an error, means the
	// provider is reachable.
	if outage := err != nil && kind == provider.Outage; outage != s.down[name] {
		s.down[name] = outage
		transition = &outage
	}
	var pe *provider.Error
	if err != nil && kind == provider.Quota && errors.As(err, &pe) {
		s.lastQuota, s.quotaAt = pe, s.now()
	}
	s.stateMu.Unlock()
	if transition != nil {
		if *transition {
			s.log.Warn("key provider unreachable", "provider", name, "error", err.Error())
		} else {
			s.log.Info("key provider reachable again", "provider", name)
		}
		if s.onOutage != nil {
			s.onOutage(context.WithoutCancel(ctx), name, *transition, err)
		}
	}
}

// FlushOpCounts adds the operation counts gathered since the last flush to
// the store, for the Settings page's monthly totals.
func (s *Service) FlushOpCounts(ctx context.Context) error {
	s.stateMu.Lock()
	deltas := s.opDeltas
	s.opDeltas = map[store.ProviderOpCount]int64{}
	s.stateMu.Unlock()
	if len(deltas) == 0 {
		return nil
	}
	rows := make([]store.ProviderOpCount, 0, len(deltas))
	for k, n := range deltas {
		k.Count = n
		rows = append(rows, k)
	}
	if err := s.st.AddProviderOpCounts(ctx, rows); err != nil {
		// Put the counts back so the next flush retries them.
		s.stateMu.Lock()
		for _, r := range rows {
			k := r
			k.Count = 0
			s.opDeltas[k] += r.Count
		}
		s.stateMu.Unlock()
		return err
	}
	return nil
}

// Status describes the key service for the instance settings API.
type Status struct {
	Current       string
	Providers     []string
	ProviderDown  map[string]bool
	QuotaExceeded *provider.Error
	QuotaAt       time.Time
	CacheEntries  int
}

func (s *Service) Status() Status {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	down := map[string]bool{}
	for k, v := range s.down {
		down[k] = v
	}
	st := Status{Current: s.current, Providers: s.ProviderNames(), ProviderDown: down, CacheEntries: s.cache.len()}
	// A quota error is reported for an hour after it was last seen.
	if s.lastQuota != nil && s.now().Sub(s.quotaAt) < time.Hour {
		st.QuotaExceeded, st.QuotaAt = s.lastQuota, s.quotaAt
	}
	return st
}
