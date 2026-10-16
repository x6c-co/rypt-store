// Package secrets holds the domain logic of feature 01: versioned,
// encrypted key/value secrets per environment, with history, restore, soft
// delete, import and export, bulk reads, and the Compare grid.
package secrets

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/x6c-co/rypt-store/internal/audit"
	"github.com/x6c-co/rypt-store/internal/ids"
	"github.com/x6c-co/rypt-store/internal/keys"
	"github.com/x6c-co/rypt-store/internal/keys/provider"
	"github.com/x6c-co/rypt-store/internal/store"
)

// Limits (feature 01 2.1, 2.2).
const (
	MaxValueBytes   = 64 * 1024
	MaxCommentChars = 1024
)

var namePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,255}$`)

// reservedNames collide with fixed paths under .../secrets/ (feature 01 4).
var reservedNames = map[string]bool{"deleted": true, "export": true, "import": true, "values": true}

// Validation errors.
var (
	ErrInvalidName = errors.New("names start with a letter or underscore and contain only letters, digits and underscores (at most 256)")
	ErrReserved    = errors.New("deleted, export, import and values are reserved names")
)

// ValidateName checks a secret name.
func ValidateName(name string) error {
	if !namePattern.MatchString(name) {
		return ErrInvalidName
	}
	if reservedNames[name] {
		return ErrReserved
	}
	return nil
}

// ValidateValue checks a secret value: UTF-8 text of at most 64 KiB.
func ValidateValue(v string) error {
	if len(v) > MaxValueBytes {
		return fmt.Errorf("values are at most %d bytes", MaxValueBytes)
	}
	if !utf8.ValidString(v) {
		return errors.New("values must be UTF-8 text")
	}
	return nil
}

// ValidateComment checks a comment.
func ValidateComment(c string) error {
	if utf8.RuneCountInString(c) > MaxCommentChars {
		return fmt.Errorf("comments are at most %d characters", MaxCommentChars)
	}
	return nil
}

// ErrVersionConflict means the expected version is stale (feature 01 3.1).
var ErrVersionConflict = store.Conflict("someone else saved a newer version of this secret")

// Jobs enqueues background work.
type Jobs interface {
	Enqueue(ctx context.Context, kind string, payload any, dedupeKey string, runAfter time.Time) error
}

// JobPrune is the job kind that prunes one secret's old versions.
const JobPrune = "secrets.prune"

// Service implements the operations of feature 01 section 3.
type Service struct {
	st           store.Store
	keys         *keys.Service
	audit        *audit.Writer
	jobs         Jobs
	versionsKept int
	retention    time.Duration
	now          func() time.Time
}

type Options struct {
	Store            store.Store
	Keys             *keys.Service
	Audit            *audit.Writer
	Jobs             Jobs
	VersionsKept     int
	DeletedRetention time.Duration
	Now              func() time.Time
}

func New(o Options) *Service {
	if o.Now == nil {
		o.Now = time.Now
	}
	return &Service{st: o.Store, keys: o.Keys, audit: o.Audit, jobs: o.Jobs, versionsKept: o.VersionsKept,
		retention: o.DeletedRetention, now: o.Now}
}

// Target is the environment an operation applies to.
type Target struct {
	Tenant  *store.Tenant
	Project *store.Project
	Env     *store.Environment
}

// Actor is who performs an operation.
type Actor struct {
	Kind string // audit.ActorUser or audit.ActorServiceToken
	ID   string
}

func (s *Service) event(t Target, a Actor, action, secretID string, meta map[string]any) audit.Event {
	return audit.Event{ChainID: t.Tenant.ID, ActorKind: a.Kind, ActorID: a.ID, Action: action, TargetKind: "secret",
		TargetID: secretID, ProjectID: t.Project.ID, EnvironmentID: t.Env.ID, Metadata: meta}
}

// Get returns a live secret by name.
func (s *Service) Get(ctx context.Context, t Target, name string) (*store.Secret, error) {
	return s.st.GetSecretByName(ctx, t.Tenant.ID, t.Env.ID, name)
}

// write seals value as the next version of a secret and stores it. With
// existing nil it creates the secret.
func (s *Service) write(ctx context.Context, t Target, a Actor, existing *store.Secret, name, value string, comment *string,
	expected int, restoredFrom *int, action string, meta map[string]any) (*store.Secret, error) {
	var out store.Secret
	err := s.keys.WithProjectWrite(t.Project.ID, func() error {
		// Re-read the project under the lock: a migration may have changed
		// its key mode since the request resolved it.
		p, err := s.st.GetProject(ctx, t.Tenant.ID, t.Project.ID)
		if err != nil {
			return err
		}
		now := s.now().UTC()
		sec := store.Secret{ID: ids.New(), TenantID: t.Tenant.ID, ProjectID: p.ID, EnvironmentID: t.Env.ID, Name: name,
			Comment: deref(comment), CreatedAt: now, UpdatedAt: now}
		version := 1
		if existing != nil {
			sec = *existing
			version = expected + 1
			if comment != nil {
				sec.Comment = *comment
			}
			sec.UpdatedAt = now
		}
		sealed, err := s.keys.SealValue(ctx, *p, t.Env.ID, sec.ID, version, []byte(value))
		if err != nil {
			return err
		}
		v := store.SecretVersion{ID: ids.New(), TenantID: sec.TenantID, SecretID: sec.ID, Version: version,
			DEKID: sealed.DEK.KeyID, Ciphertext: sealed.Ciphertext, ValueMAC: sealed.MAC, CreatedByKind: a.Kind,
			CreatedByID: a.ID, CreatedAt: now, RestoredFrom: restoredFrom}
		if meta == nil {
			meta = map[string]any{}
		}
		meta["name"], meta["version"] = name, version
		err = s.audit.Record(ctx, s.event(t, a, action, sec.ID, meta), func(ev *store.AuditEvent) error {
			if existing == nil {
				return s.st.CreateSecret(ctx, sec, v, sealed.DEK, ev)
			}
			return s.st.WriteSecretVersion(ctx, sec, expected, comment, v, sealed.DEK, ev)
		})
		if err != nil {
			return err
		}
		sec.CurrentVersion, sec.UpdatedByKind, sec.UpdatedByID = version, a.Kind, a.ID
		out = sec
		return nil
	})
	if err != nil {
		var ce *store.ConflictError
		if existing != nil && errors.As(err, &ce) {
			return nil, ErrVersionConflict
		}
		return nil, err
	}
	if out.CurrentVersion > s.versionsKept && s.jobs != nil {
		_ = s.jobs.Enqueue(ctx, JobPrune, prunePayload{TenantID: out.TenantID, SecretID: out.ID}, "prune:"+out.ID, time.Time{})
	}
	return &out, nil
}

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// Create adds a secret at version 1.
func (s *Service) Create(ctx context.Context, t Target, a Actor, name, value, comment string) (*store.Secret, error) {
	return s.write(ctx, t, a, nil, name, value, &comment, 0, nil, "secret.create", nil)
}

// Update writes a new version when the current version is expected.
func (s *Service) Update(ctx context.Context, t Target, a Actor, name, value string, comment *string, expected int) (*store.Secret, error) {
	cur, err := s.Get(ctx, t, name)
	if err != nil {
		return nil, err
	}
	if cur.CurrentVersion != expected {
		return nil, ErrVersionConflict
	}
	return s.write(ctx, t, a, cur, name, value, comment, expected, nil, "secret.update", nil)
}

// open decrypts one version.
func (s *Service) open(ctx context.Context, t Target, v *store.SecretVersion) (string, error) {
	b, err := s.keys.OpenValue(ctx, t.Tenant.ID, t.Env.ID, *v)
	if err != nil {
		return "", err
	}
	defer clear(b)
	return string(b), nil
}

// failedRead audits a read that could not decrypt, with the provider's
// request ID when there is one.
func (s *Service) failedRead(ctx context.Context, t Target, a Actor, action, secretID string, meta map[string]any, cause error) {
	ev := s.event(t, a, action, secretID, meta)
	ev.Result = audit.Error
	ev.ProviderRequestID = provider.RequestIDOf(cause)
	_ = s.audit.Record(ctx, ev, nil)
}

// Read returns a secret's current value and audits the read (feature 01 3.2).
func (s *Service) Read(ctx context.Context, t Target, a Actor, name string) (*store.Secret, string, error) {
	sec, err := s.Get(ctx, t, name)
	if err != nil {
		return nil, "", err
	}
	v, err := s.st.GetSecretVersion(ctx, t.Tenant.ID, sec.ID, sec.CurrentVersion)
	if err != nil {
		return nil, "", err
	}
	meta := map[string]any{"name": name, "version": v.Version}
	value, err := s.open(ctx, t, v)
	if err != nil {
		s.failedRead(ctx, t, a, "secret.read", sec.ID, meta, err)
		return nil, "", err
	}
	// The value goes out only once its read is on the audit chain.
	if err := s.audit.Record(ctx, s.event(t, a, "secret.read", sec.ID, meta), nil); err != nil {
		return nil, "", err
	}
	return sec, value, nil
}

// ReadVersion returns one version's value; the read is a secret.read with
// the version in the metadata (feature 01 3.3).
func (s *Service) ReadVersion(ctx context.Context, t Target, a Actor, name string, version int) (*store.SecretVersion, string, error) {
	sec, err := s.Get(ctx, t, name)
	if err != nil {
		return nil, "", err
	}
	v, err := s.st.GetSecretVersion(ctx, t.Tenant.ID, sec.ID, version)
	if err != nil {
		return nil, "", err
	}
	meta := map[string]any{"name": name, "version": version, "current": version == sec.CurrentVersion}
	value, err := s.open(ctx, t, v)
	if err != nil {
		s.failedRead(ctx, t, a, "secret.read", sec.ID, meta, err)
		return nil, "", err
	}
	if err := s.audit.Record(ctx, s.event(t, a, "secret.read", sec.ID, meta), nil); err != nil {
		return nil, "", err
	}
	return v, value, nil
}

// History lists versions without values.
func (s *Service) History(ctx context.Context, t Target, name string) (*store.Secret, []store.SecretVersion, error) {
	sec, err := s.Get(ctx, t, name)
	if err != nil {
		return nil, nil, err
	}
	vs, err := s.st.ListSecretVersions(ctx, t.Tenant.ID, sec.ID)
	return sec, vs, err
}

// RestoreVersion writes an old version's value as a new version under a
// fresh DEK (feature 01 3.3).
func (s *Service) RestoreVersion(ctx context.Context, t Target, a Actor, name string, version int) (*store.Secret, error) {
	sec, err := s.Get(ctx, t, name)
	if err != nil {
		return nil, err
	}
	old, err := s.st.GetSecretVersion(ctx, t.Tenant.ID, sec.ID, version)
	if err != nil {
		return nil, err
	}
	value, err := s.open(ctx, t, old)
	if err != nil {
		return nil, err
	}
	return s.write(ctx, t, a, sec, name, value, nil, sec.CurrentVersion, &version, "secret.version.restore",
		map[string]any{"restored_from": version})
}

// Delete soft-deletes a secret (feature 01 3.5).
func (s *Service) Delete(ctx context.Context, t Target, a Actor, name string) error {
	sec, err := s.Get(ctx, t, name)
	if err != nil {
		return err
	}
	return s.audit.Record(ctx, s.event(t, a, "secret.delete", sec.ID, map[string]any{"name": name, "version": sec.CurrentVersion}),
		func(ev *store.AuditEvent) error {
			return s.st.SoftDeleteSecret(ctx, t.Tenant.ID, sec.ID, s.now().UTC(), ev)
		})
}

// Deleted lists recently deleted secrets with their purge time.
func (s *Service) Deleted(ctx context.Context, t Target) ([]store.Secret, time.Duration, error) {
	xs, err := s.st.ListDeletedSecrets(ctx, t.Tenant.ID, t.Env.ID)
	return xs, s.retention, err
}

// RestoreDeleted clears deleted_at; 409 when a live secret uses the name.
func (s *Service) RestoreDeleted(ctx context.Context, t Target, a Actor, id string) (*store.Secret, error) {
	sec, err := s.st.GetSecret(ctx, t.Tenant.ID, id)
	if err != nil {
		return nil, err
	}
	if sec.EnvironmentID != t.Env.ID || sec.DeletedAt == nil {
		return nil, store.ErrNotFound
	}
	err = s.audit.Record(ctx, s.event(t, a, "secret.restore", sec.ID, map[string]any{"name": sec.Name}),
		func(ev *store.AuditEvent) error {
			return s.st.RestoreDeletedSecret(ctx, t.Tenant.ID, sec.ID, s.now().UTC(), ev)
		})
	if err != nil {
		var ce *store.ConflictError
		if errors.As(err, &ce) {
			return nil, store.Conflict("a secret named %s already exists; delete or rename it first", sec.Name)
		}
		return nil, err
	}
	return s.st.GetSecret(ctx, t.Tenant.ID, sec.ID)
}

// Values decrypts every current value of an environment as one bulk read,
// audited as a single secret.read.bulk event (feature 01 3.2).
func (s *Service) Values(ctx context.Context, t Target, a Actor, purpose string) (map[string]string, error) {
	cur, err := s.st.ListCurrentValues(ctx, t.Tenant.ID, t.Env.ID)
	if err != nil {
		return nil, err
	}
	values := make(map[string]string, len(cur))
	secretIDs := make([]string, 0, len(cur))
	for _, c := range cur {
		v, err := s.open(ctx, t, &c.Version)
		if err != nil {
			s.failedRead(ctx, t, a, "secret.read.bulk", "", map[string]any{"purpose": purpose, "failed_secret_id": c.Secret.ID}, err)
			return nil, err
		}
		values[c.Secret.Name] = v
		secretIDs = append(secretIDs, c.Secret.ID)
	}
	ev := s.event(t, a, "secret.read.bulk", "", map[string]any{"purpose": purpose, "count": len(secretIDs), "secret_ids": secretIDs})
	ev.TargetKind, ev.TargetID = "environment", t.Env.ID
	if err := s.audit.Record(ctx, ev, nil); err != nil {
		return nil, err
	}
	return values, nil
}

// ImportResult reports what an import changed (feature 01 3.7).
type ImportResult struct {
	Created  []string
	Updated  []string
	Skipped  []string
	Rejected []Rejection
}

// Import writes the assignments of a .env file. Existing secrets are
// skipped, or overwritten when overwrite is set; an unchanged value is
// skipped. Each changed secret gets a version and a write event, and the
// import itself one secret.import event.
func (s *Service) Import(ctx context.Context, t Target, a Actor, src string, overwrite bool) (ImportResult, error) {
	entries, rejected := ParseDotenv(src)
	res := ImportResult{Created: []string{}, Updated: []string{}, Skipped: []string{}, Rejected: rejected}
	if res.Rejected == nil {
		res.Rejected = []Rejection{}
	}
	for _, e := range entries {
		cur, err := s.Get(ctx, t, e.Name)
		switch {
		case errors.Is(err, store.ErrNotFound):
			if _, err := s.write(ctx, t, a, nil, e.Name, e.Value, ptr(""), 0, nil, "secret.create", map[string]any{"via": "import"}); err != nil {
				return res, fmt.Errorf("import %s (line %d): %w", e.Name, e.Line, err)
			}
			res.Created = append(res.Created, e.Name)
		case err != nil:
			return res, err
		case !overwrite:
			res.Skipped = append(res.Skipped, e.Name)
		default:
			same, err := s.sameValue(ctx, t, cur, e.Value)
			if err != nil {
				return res, err
			}
			if same {
				res.Skipped = append(res.Skipped, e.Name)
				continue
			}
			if _, err := s.write(ctx, t, a, cur, e.Name, e.Value, nil, cur.CurrentVersion, nil, "secret.update", map[string]any{"via": "import"}); err != nil {
				return res, fmt.Errorf("import %s (line %d): %w", e.Name, e.Line, err)
			}
			res.Updated = append(res.Updated, e.Name)
		}
	}
	ev := s.event(t, a, "secret.import", "", map[string]any{"mode": map[bool]string{true: "overwrite", false: "skip_existing"}[overwrite],
		"created": res.Created, "updated": res.Updated, "skipped": len(res.Skipped), "rejected": len(res.Rejected)})
	ev.TargetKind, ev.TargetID = "environment", t.Env.ID
	return res, s.audit.Record(ctx, ev, nil)
}

func ptr[T any](v T) *T { return &v }

// sameValue compares a value with a secret's current value by MAC, without
// decrypting.
func (s *Service) sameValue(ctx context.Context, t Target, sec *store.Secret, value string) (bool, error) {
	v, err := s.st.GetSecretVersion(ctx, t.Tenant.ID, sec.ID, sec.CurrentVersion)
	if err != nil {
		return false, err
	}
	mac, err := s.keys.ValueMAC(ctx, t.Project.ID, []byte(value))
	if err != nil {
		return false, err
	}
	return bytes.Equal(mac, v.ValueMAC), nil
}

// CompareRow is one secret name across environments; Groups maps an
// environment ID to the row-local label of its value, absent when missing.
type CompareRow struct {
	Name   string
	Groups map[string]int
}

// Compare builds the Compare grid (feature 01 3.6). Environments whose
// current values share a MAC within a row share a label; labels are small
// integers assigned per row in environment order.
func (s *Service) Compare(ctx context.Context, tenantID, projectID string, envs []store.Environment) ([]CompareRow, error) {
	cells, err := s.st.ListCompareCells(ctx, tenantID, projectID)
	if err != nil {
		return nil, err
	}
	byName := map[string]map[string][]byte{}
	var names []string
	for _, c := range cells {
		if byName[c.Name] == nil {
			byName[c.Name] = map[string][]byte{}
			names = append(names, c.Name)
		}
		byName[c.Name][c.EnvironmentID] = c.ValueMAC
	}
	rows := make([]CompareRow, 0, len(names))
	for _, n := range names {
		row := CompareRow{Name: n, Groups: map[string]int{}}
		var seen [][]byte
		for _, e := range envs {
			mac, ok := byName[n][e.ID]
			if !ok {
				continue
			}
			label := 0
			for i, m := range seen {
				if bytes.Equal(m, mac) {
					label = i + 1
					break
				}
			}
			if label == 0 {
				seen = append(seen, mac)
				label = len(seen)
			}
			row.Groups[e.ID] = label
		}
		rows = append(rows, row)
	}
	return rows, nil
}

// ---- background jobs ----

type prunePayload struct {
	TenantID string `json:"tenant_id"`
	SecretID string `json:"secret_id"`
}

// PruneJob prunes one secret's old versions (feature 01 3.4).
func (s *Service) PruneJob(ctx context.Context, payload json.RawMessage) error {
	var p prunePayload
	if err := json.Unmarshal(payload, &p); err != nil {
		return err
	}
	return s.prune(ctx, p.TenantID, []string{p.SecretID})
}

// prune deletes versions beyond versions_kept with their DEK wraps and
// writes one secret.versions.pruned event with per-secret counts.
func (s *Service) prune(ctx context.Context, tenantID string, secretIDs []string) error {
	counts := map[string]any{}
	total := 0
	for _, id := range secretIDs {
		n, err := s.st.PruneSecretVersions(ctx, tenantID, id, s.versionsKept)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return err
		}
		if n > 0 {
			counts[id] = n
			total += n
		}
	}
	if total == 0 {
		return nil
	}
	return s.audit.Record(ctx, audit.Event{ChainID: tenantID, ActorKind: audit.ActorSystem, Action: "secret.versions.pruned",
		Metadata: map[string]any{"versions_kept": s.versionsKept, "deleted": total, "secrets": counts}}, nil)
}

// PruneSweep prunes every secret over the limit, for example after
// versions_kept was lowered.
func (s *Service) PruneSweep(ctx context.Context) error {
	xs, err := s.st.ListSecretsOverVersionLimit(ctx, s.versionsKept, 1000)
	if err != nil {
		return err
	}
	byTenant := map[string][]string{}
	for _, x := range xs {
		byTenant[x.TenantID] = append(byTenant[x.TenantID], x.ID)
	}
	for tenant, idsList := range byTenant {
		if err := s.prune(ctx, tenant, idsList); err != nil {
			return err
		}
	}
	return nil
}

// PurgeSweep deletes soft-deleted secrets past deleted_retention, with
// their versions and DEK wraps (feature 01 3.5).
func (s *Service) PurgeSweep(ctx context.Context) error {
	xs, err := s.st.ListPurgeableSecrets(ctx, s.now().UTC().Add(-s.retention), 500)
	if err != nil {
		return err
	}
	for _, x := range xs {
		err := s.audit.Record(ctx, audit.Event{ChainID: x.TenantID, ActorKind: audit.ActorSystem, Action: "secret.purge",
			TargetKind: "secret", TargetID: x.ID, ProjectID: x.ProjectID, EnvironmentID: x.EnvironmentID,
			Metadata: map[string]any{"name": x.Name, "deleted_at": x.DeletedAt.UTC().Format(time.RFC3339)}},
			func(ev *store.AuditEvent) error { return s.st.PurgeSecret(ctx, x.TenantID, x.ID, ev) })
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
	}
	return nil
}

// ParseETag reads a version from an If-Match value such as "3" or W/"3".
func ParseETag(v string) (int, bool) {
	if len(v) >= 2 && v[:2] == "W/" {
		v = v[2:]
	}
	if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
		v = v[1 : len(v)-1]
	}
	n, err := strconv.Atoi(v)
	return n, err == nil && n >= 0
}

// ETag formats a version as an ETag.
func ETag(version int) string { return `"` + strconv.Itoa(version) + `"` }
