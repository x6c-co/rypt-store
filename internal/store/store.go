// Package store defines the storage interface (core 4.3). The interface
// exposes domain operations, not generic transactions: each method that
// changes data is one atomic unit, sent by the rqlite implementation as one
// transactional batch. A method that takes an *AuditEvent writes that event
// in the same batch as the change it records (core 8.1); the event must
// already carry its seq, prev_hash and hash (see internal/audit).
//
// Every tenant-scoped method takes the tenant ID explicitly and filters by
// it, so that an object in another tenant is ErrNotFound (core 6.2).
package store

import (
	"context"
	"errors"
	"fmt"
	"time"
)

var (
	// ErrNotFound means the object does not exist or is not in the tenant.
	ErrNotFound = errors.New("not found")
	// ErrConflict means a uniqueness rule or a guarded precondition failed.
	ErrConflict = errors.New("conflict")
	// ErrAuditConflict means another writer advanced the audit chain head
	// first. The audit writer re-reads the head and retries.
	ErrAuditConflict = errors.New("audit chain head moved")
)

// ConflictError carries the detail of an ErrConflict.
type ConflictError struct{ Detail string }

func (e *ConflictError) Error() string { return "conflict: " + e.Detail }
func (e *ConflictError) Unwrap() error { return ErrConflict }

// Conflict returns an ErrConflict with detail.
func Conflict(format string, a ...any) error {
	return &ConflictError{Detail: fmt.Sprintf(format, a...)}
}

// Consistency selects the read level (core 4.3): Strong for reads that feed
// security decisions, Weak for listings.
type Consistency int

const (
	Weak Consistency = iota
	Strong
)

type Store interface {
	Ping(ctx context.Context) error
	Migrate(ctx context.Context) error
	Close() error

	InstanceStore
	UserStore
	SessionStore
	TenantStore
	ProjectStore
	KeyStore
	AuditStore
	JobStore
	SecretStore
	TokenStore
}

type InstanceStore interface {
	// GetInstance returns ErrNotFound before first start.
	GetInstance(ctx context.Context) (*Instance, error)
	// CreateInstance inserts the instance row, the IK wrap, and the instance
	// audit chain head. ErrConflict if an instance already exists.
	CreateInstance(ctx context.Context, inst Instance, ikWrap KeyWrap) error
	SetSetupToken(ctx context.Context, hash string, expiresAt time.Time) error
	// CompleteSetup creates the admin, the first tenant with its chain head,
	// the owner membership, and the admin's confirmed TOTP and recovery codes
	// (when given), marks setup complete and clears the setup token.
	// ErrConflict when setup already completed.
	CompleteSetup(ctx context.Context, p CompleteSetupParams, ev *AuditEvent) error
}

type CompleteSetupParams struct {
	Admin         User
	Tenant        Tenant
	TOTP          *TOTP
	RecoveryCodes []RecoveryCode
	Session       *Session
	CompletedAt   time.Time
}

type UserStore interface {
	GetUser(ctx context.Context, id string) (*User, error)
	GetUserByEmail(ctx context.Context, email string) (*User, error)
	ListUsers(ctx context.Context) ([]User, error)
	UpdateUserPassword(ctx context.Context, userID, hash string, at time.Time, ev *AuditEvent) error

	GetTOTP(ctx context.Context, userID string) (*TOTP, error)
	// PutPendingTOTP stores an unconfirmed TOTP secret, replacing an
	// unconfirmed one. ErrConflict when a confirmed TOTP exists.
	PutPendingTOTP(ctx context.Context, t TOTP) error
	// ConfirmTOTP confirms the pending secret and, when codes is not nil,
	// replaces the user's recovery codes.
	ConfirmTOTP(ctx context.Context, userID string, at time.Time, codes []RecoveryCode, ev *AuditEvent) error
	DeleteTOTP(ctx context.Context, userID string, ev *AuditEvent) error

	ListUnusedRecoveryCodes(ctx context.Context, userID string) ([]RecoveryCode, error)
	CountRecoveryCodes(ctx context.Context, userID string) (unused int, err error)
	// UseRecoveryCode marks a code used. ErrConflict if already used.
	UseRecoveryCode(ctx context.Context, id string, at time.Time, ev *AuditEvent) error
	ReplaceRecoveryCodes(ctx context.Context, userID string, codes []RecoveryCode, ev *AuditEvent) error

	ListWebAuthnCredentials(ctx context.Context, userID string) ([]WebAuthnCredential, error)
	CreateWebAuthnCredential(ctx context.Context, c WebAuthnCredential, codes []RecoveryCode, ev *AuditEvent) error
	UpdateWebAuthnCredentialUse(ctx context.Context, id string, signCount int64, data string, at time.Time) error
	DeleteWebAuthnCredential(ctx context.Context, userID, id string, ev *AuditEvent) error

	CreatePasswordReset(ctx context.Context, r PasswordReset, ev *AuditEvent) error
	GetPasswordResetByHash(ctx context.Context, tokenHash string) (*PasswordReset, error)
	// UsePasswordReset sets the password, marks the reset used, and revokes
	// every session of the user. ErrConflict when already used.
	UsePasswordReset(ctx context.Context, resetID, userID, passwordHash string, at time.Time, ev *AuditEvent) error
}

type SessionStore interface {
	CreateSession(ctx context.Context, s Session, ev *AuditEvent) error
	GetSession(ctx context.Context, idHash string) (*Session, error)
	TouchSession(ctx context.Context, idHash string, at time.Time) error
	// SatisfySessionMFA marks a session MFA-satisfied and sets its expiry.
	SatisfySessionMFA(ctx context.Context, idHash string, expiresAt time.Time, ev *AuditEvent) error
	ListSessions(ctx context.Context, userID string) ([]Session, error)
	// DeleteSession deletes the user's session by public ID.
	DeleteSession(ctx context.Context, userID, publicID string, ev *AuditEvent) error
	DeleteSessionByHash(ctx context.Context, idHash string, ev *AuditEvent) error
	DeleteExpiredSessions(ctx context.Context, now time.Time, idleBefore time.Time) (int, error)

	CreateDeviceAuth(ctx context.Context, r DeviceAuthRequest) error
	GetDeviceAuthByUserCode(ctx context.Context, userCode string) (*DeviceAuthRequest, error)
	GetDeviceAuthByDeviceHash(ctx context.Context, deviceCodeHash string) (*DeviceAuthRequest, error)
	// DecideDeviceAuth moves a pending request to approved or denied.
	DecideDeviceAuth(ctx context.Context, userCode, userID, state string, ev *AuditEvent) error
	// ConsumeDeviceAuth moves an approved request to consumed and creates
	// the CLI session. ErrConflict unless the request was approved.
	ConsumeDeviceAuth(ctx context.Context, deviceCodeHash string, s Session, ev *AuditEvent) error
	DeleteExpiredDeviceAuth(ctx context.Context, now time.Time) error
}

type TenantStore interface {
	// CreateTenant inserts the tenant, its chain head, and the owner
	// membership when owner is not nil.
	CreateTenant(ctx context.Context, t Tenant, owner *Membership, ev *AuditEvent) error
	GetTenant(ctx context.Context, id string) (*Tenant, error)
	GetTenantBySlug(ctx context.Context, slug string) (*Tenant, error)
	ListAllTenants(ctx context.Context) ([]Tenant, error)
	ListTenantsForUser(ctx context.Context, userID string) ([]TenantWithRole, error)

	GetMembership(ctx context.Context, tenantID, userID string) (*Membership, error)
	ListMembers(ctx context.Context, tenantID string) ([]Member, error)
	// UpdateMemberRole changes a role. ErrConflict if it would leave the
	// tenant without an owner.
	UpdateMemberRole(ctx context.Context, tenantID, userID, role string, ev *AuditEvent) error
	// DeleteMember removes a membership. ErrConflict if it would leave the
	// tenant without an owner.
	DeleteMember(ctx context.Context, tenantID, userID string, ev *AuditEvent) error

	CreateInvitation(ctx context.Context, inv Invitation, ev *AuditEvent) error
	GetInvitationByHash(ctx context.Context, tokenHash string) (*Invitation, error)
	ListInvitations(ctx context.Context, tenantID string) ([]Invitation, error)
	// AcceptInvitation marks the invitation accepted, creates newUser when
	// not nil, and adds the membership. ErrConflict when already accepted
	// or when the user is already a member.
	AcceptInvitation(ctx context.Context, inv Invitation, newUser *User, m Membership, at time.Time, ev *AuditEvent) error
}

type ProjectStore interface {
	// CreateProject inserts the project, its environments, and its key
	// wraps (the PK wrap in modes A and B).
	CreateProject(ctx context.Context, p Project, envs []Environment, wraps []KeyWrap, ev *AuditEvent) error
	GetProject(ctx context.Context, tenantID, id string) (*Project, error)
	GetProjectBySlug(ctx context.Context, tenantID, slug string) (*Project, error)
	ListProjects(ctx context.Context, tenantID string) ([]Project, error)
	// ListAllProjects lists live projects of every tenant in ID order, after
	// the cursor ID when it is not empty.
	ListAllProjects(ctx context.Context, afterID string) ([]Project, error)
	UpdateProject(ctx context.Context, tenantID, id, name, slug string, ev *AuditEvent) error
	DeleteProject(ctx context.Context, tenantID, id string, at time.Time, ev *AuditEvent) error

	CreateEnvironment(ctx context.Context, e Environment, ev *AuditEvent) error
	GetEnvironment(ctx context.Context, tenantID, id string) (*Environment, error)
	GetEnvironmentBySlug(ctx context.Context, tenantID, projectID, slug string) (*Environment, error)
	ListEnvironments(ctx context.Context, tenantID, projectID string) ([]Environment, error)
	UpdateEnvironment(ctx context.Context, tenantID, id, name, slug string, position int, ev *AuditEvent) error
	// DeleteEnvironment deletes the environment with its secrets, versions,
	// DEK wraps, and service-token bindings.
	DeleteEnvironment(ctx context.Context, tenantID, id string, ev *AuditEvent) error
}

type KeyStore interface {
	// GetActiveWrap returns the active wrap of a logical key (strong read).
	GetActiveWrap(ctx context.Context, keyID string) (*KeyWrap, error)
	// GetActiveWrapsByKind lists active wraps of one kind (instance, root).
	GetActiveWrapsByKind(ctx context.Context, kind string) ([]KeyWrap, error)
	// ListProjectWraps lists a project's wraps in the given states (PK and
	// DEK wraps).
	ListProjectWraps(ctx context.Context, projectID string, states ...string) ([]KeyWrap, error)
	// CreateRootKey inserts the RK's active wrap. ErrConflict if an active
	// RK already exists.
	CreateRootKey(ctx context.Context, w KeyWrap) error
	InsertWraps(ctx context.Context, wraps []KeyWrap) error
	DeleteWraps(ctx context.Context, ids []string) error
	// FlipWraps, in one batch, retires the given active wraps, activates the
	// given pending wraps, and sets the project's key mode when newMode is
	// not empty (core 5.7 step 5).
	FlipWraps(ctx context.Context, retireIDs, activateIDs []string, projectID, newMode string, at time.Time, ev *AuditEvent) error
	// CountWrapsByProvider counts active and retired provider wraps by
	// provider name.
	CountWrapsByProvider(ctx context.Context) (map[string]int, error)
	DeleteRetiredWraps(ctx context.Context, before time.Time) (int, error)
	// CountProjectDEKs counts DEK wraps that are active for a project.
	CountProjectDEKs(ctx context.Context, projectID string) (int, error)

	CreateKeyMigration(ctx context.Context, m KeyMigration, ev *AuditEvent) error
	GetKeyMigration(ctx context.Context, id string) (*KeyMigration, error)
	ListKeyMigrations(ctx context.Context, limit int) ([]KeyMigration, error)
	ListUnfinishedKeyMigrations(ctx context.Context) ([]KeyMigration, error)
	UpdateKeyMigration(ctx context.Context, m KeyMigration, ev *AuditEvent) error

	AddProviderOpCounts(ctx context.Context, counts []ProviderOpCount) error
	ListProviderOpCounts(ctx context.Context, month string) ([]ProviderOpCount, error)
}

type AuditStore interface {
	// GetAuditHead reads a chain head (strong). ErrNotFound if absent.
	GetAuditHead(ctx context.Context, chainID string) (*AuditHead, error)
	// EnsureAuditChain creates a chain head at seq 0 if absent.
	EnsureAuditChain(ctx context.Context, chainID string) error
	AppendAudit(ctx context.Context, ev *AuditEvent) error
	// ListAuditEvents lists events newest first. The cursor is a seq.
	ListAuditEvents(ctx context.Context, chainID string, f AuditFilter, page Page) ([]AuditEvent, string, error)
	// ScanAuditEvents calls fn for events with seq > afterSeq in seq order,
	// optionally bounded by time, in pages.
	ScanAuditEvents(ctx context.Context, chainID string, afterSeq int64, from, to *time.Time, fn func(AuditEvent) error) error
	// GetAuditEventBySeq returns one event.
	GetAuditEventBySeq(ctx context.Context, chainID string, seq int64) (*AuditEvent, error)
	// PruneAudit deletes events with seq <= anchorSeq and records the anchor,
	// together with the audit.pruned event.
	PruneAudit(ctx context.Context, chainID string, anchorSeq int64, anchorHash string, ev *AuditEvent) error
	// LastAuditSeqBefore returns the highest seq with ts < before, or 0.
	LastAuditSeqBefore(ctx context.Context, chainID string, before time.Time) (int64, error)
	ListAuditChains(ctx context.Context) ([]AuditHead, error)
}

type JobStore interface {
	// EnqueueJob inserts a job. When DedupeKey is set and a pending job with
	// that key exists, EnqueueJob does nothing.
	EnqueueJob(ctx context.Context, j Job) error
	// ClaimJob moves a due pending job to running. ErrNotFound when none.
	ClaimJob(ctx context.Context, now time.Time) (*Job, error)
	FinishJob(ctx context.Context, id string, at time.Time) error
	// RetryJob returns a running job to pending, or marks it failed when
	// final is true.
	RetryJob(ctx context.Context, id, lastError string, runAfter time.Time, final bool) error
	// ResetRunningJobs returns jobs left running by a crash to pending.
	ResetRunningJobs(ctx context.Context) error
	DeleteFinishedJobs(ctx context.Context, before time.Time) error
}

type SecretStore interface {
	ListSecrets(ctx context.Context, tenantID, environmentID string) ([]Secret, error)
	ListDeletedSecrets(ctx context.Context, tenantID, environmentID string) ([]Secret, error)
	// GetSecretByName returns the live secret with the name.
	GetSecretByName(ctx context.Context, tenantID, environmentID, name string) (*Secret, error)
	GetSecret(ctx context.Context, tenantID, id string) (*Secret, error)
	GetSecretVersion(ctx context.Context, tenantID, secretID string, version int) (*SecretVersion, error)
	ListSecretVersions(ctx context.Context, tenantID, secretID string) ([]SecretVersion, error)
	// CreateSecret inserts the secret, its first version and the version's
	// DEK wrap. ErrConflict if a live secret has the name.
	CreateSecret(ctx context.Context, s Secret, v SecretVersion, dek KeyWrap, ev *AuditEvent) error
	// WriteSecretVersion adds a version when the secret's current version is
	// expectedVersion, and updates its comment when comment is not nil.
	// ErrConflict otherwise.
	WriteSecretVersion(ctx context.Context, s Secret, expectedVersion int, comment *string, v SecretVersion, dek KeyWrap, ev *AuditEvent) error
	SoftDeleteSecret(ctx context.Context, tenantID, id string, at time.Time, ev *AuditEvent) error
	// RestoreDeletedSecret clears deleted_at. ErrConflict if a live secret
	// now uses the name.
	RestoreDeletedSecret(ctx context.Context, tenantID, id string, at time.Time, ev *AuditEvent) error
	// PruneSecretVersions deletes versions older than the newest keep, with
	// their DEK wraps, and returns how many were deleted.
	PruneSecretVersions(ctx context.Context, tenantID, secretID string, keep int) (int, error)
	// ListPurgeableSecrets lists soft-deleted secrets deleted before t.
	ListPurgeableSecrets(ctx context.Context, before time.Time, limit int) ([]Secret, error)
	// PurgeSecret deletes a soft-deleted secret with its versions and wraps.
	PurgeSecret(ctx context.Context, tenantID, id string, ev *AuditEvent) error
	// ListCurrentValues lists live secrets of an environment with their
	// current versions.
	ListCurrentValues(ctx context.Context, tenantID, environmentID string) ([]CurrentValue, error)
	// ListCompareCells lists the current MAC of every live secret in a project.
	ListCompareCells(ctx context.Context, tenantID, projectID string) ([]CompareCell, error)
	// ListSecretsOverVersionLimit lists secrets with more than keep
	// versions, for the prune sweep.
	ListSecretsOverVersionLimit(ctx context.Context, keep int, limit int) ([]Secret, error)
}

type TokenStore interface {
	CreateServiceToken(ctx context.Context, t ServiceToken, ev *AuditEvent) error
	// GetServiceToken is a strong read, including revoked tokens.
	GetServiceToken(ctx context.Context, id string) (*ServiceToken, error)
	ListServiceTokens(ctx context.Context, tenantID, projectID string) ([]ServiceToken, error)
	RevokeServiceToken(ctx context.Context, tenantID, projectID, id string, at time.Time, ev *AuditEvent) error
	// TouchServiceToken sets last_used_at when it is older than a minute.
	TouchServiceToken(ctx context.Context, id string, at time.Time) error
}
