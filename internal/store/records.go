package store

import "time"

// Record types mirror the tables in internal/store/migrate. Empty strings
// stand for NULL in nullable text columns; nil pointers for NULL timestamps.

type Instance struct {
	ID                  string
	CreatedAt           time.Time
	SetupCompletedAt    *time.Time
	SetupTokenHash      string
	SetupTokenExpiresAt *time.Time
}

type User struct {
	ID              string
	Email           string
	DisplayName     string
	PasswordHash    string
	IsInstanceAdmin bool
	DisabledAt      *time.Time
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

type TOTP struct {
	UserID           string
	SecretCiphertext []byte
	ConfirmedAt      *time.Time
}

type RecoveryCode struct {
	ID       string
	UserID   string
	CodeHash string
	UsedAt   *time.Time
}

type WebAuthnCredential struct {
	ID           string
	UserID       string
	CredentialID []byte
	PublicKey    []byte
	SignCount    int64
	Transports   string
	Name         string
	// Data is the JSON of the library's credential record, which carries
	// flags and attestation fields beyond the columns above.
	Data       string
	CreatedAt  time.Time
	LastUsedAt *time.Time
}

const (
	SessionWeb = "web"
	SessionCLI = "cli"
)

type Session struct {
	IDHash       string
	PublicID     string
	UserID       string
	Kind         string
	MFASatisfied bool
	CreatedAt    time.Time
	ExpiresAt    time.Time
	LastSeenAt   time.Time
	IP           string
	UserAgent    string
}

const (
	DeviceAuthPending  = "pending"
	DeviceAuthApproved = "approved"
	DeviceAuthDenied   = "denied"
	DeviceAuthConsumed = "consumed"
)

type DeviceAuthRequest struct {
	DeviceCodeHash string
	UserCode       string
	UserID         string
	State          string
	ExpiresAt      time.Time
	CreatedAt      time.Time
	ClientName     string
}

type Tenant struct {
	ID        string
	Name      string
	Slug      string
	CreatedAt time.Time
	DeletedAt *time.Time
}

// TenantWithRole is a tenant as seen by one user.
type TenantWithRole struct {
	Tenant
	Role string
}

type Membership struct {
	TenantID  string
	UserID    string
	Role      string
	CreatedAt time.Time
}

// Member is a membership joined with its user.
type Member struct {
	Membership
	Email       string
	DisplayName string
}

type Invitation struct {
	ID         string
	TenantID   string
	Email      string
	Role       string
	TokenHash  string
	ExpiresAt  time.Time
	AcceptedAt *time.Time
	CreatedBy  string
	CreatedAt  time.Time
}

type PasswordReset struct {
	ID        string
	UserID    string
	TokenHash string
	ExpiresAt time.Time
	UsedAt    *time.Time
	CreatedBy string
	CreatedAt time.Time
}

type Project struct {
	ID        string
	TenantID  string
	Name      string
	Slug      string
	KeyMode   string
	CreatedAt time.Time
	DeletedAt *time.Time
}

type Environment struct {
	ID        string
	TenantID  string
	ProjectID string
	Name      string
	Slug      string
	Position  int
	CreatedAt time.Time
}

// Key kinds, wrapper kinds and wrap states (core 5.4).
const (
	KeyKindInstance = "instance"
	KeyKindRoot     = "root"
	KeyKindProject  = "project"
	KeyKindDEK      = "dek"

	WrapperProvider = "provider"
	WrapperRoot     = "root"
	WrapperProject  = "project"

	WrapPending = "pending"
	WrapActive  = "active"
	WrapRetired = "retired"
)

type KeyWrap struct {
	ID          string
	KeyID       string
	KeyKind     string
	TenantID    string
	ProjectID   string
	WrapperKind string
	// WrapperRef is "<provider>:<KeyRef>" for provider wraps, or the
	// wrapping key's key_id for root and project wraps.
	WrapperRef string
	KeyVersion string
	Ciphertext []byte
	State      string
	CreatedAt  time.Time
}

const (
	MigrationQueued    = "queued"
	MigrationRunning   = "running"
	MigrationSucceeded = "succeeded"
	MigrationFailed    = "failed"
)

type KeyMigration struct {
	ID            string
	Kind          string
	Params        string
	State         string
	ProjectsTotal int
	ProjectsDone  int
	// Cursor is the ID of the last project finished; projects run in ID order.
	Cursor     string
	Error      string
	StartedBy  string
	CreatedAt  time.Time
	UpdatedAt  time.Time
	FinishedAt *time.Time
}

// ProviderOpCount is one row of the locally kept monthly operation counts.
type ProviderOpCount struct {
	Month    string
	Provider string
	Op       string
	Count    int64
}

// AuditEvent is one row of audit_events (core 8.1). TS is stored exactly as
// hashed. Optional strings are empty when absent and hash as null.
type AuditEvent struct {
	ID                string
	ChainID           string
	Seq               int64
	TS                string
	ActorKind         string
	ActorID           string
	Action            string
	TargetKind        string
	TargetID          string
	ProjectID         string
	EnvironmentID     string
	Result            string
	IP                string
	UserAgent         string
	RequestID         string
	ProviderRequestID string
	// Metadata is canonical JSON text, "{}" when empty.
	Metadata string
	PrevHash string
	Hash     string
}

// InstanceChain is the chain ID of instance-level events.
const InstanceChain = "instance"

type AuditHead struct {
	ChainID    string
	HeadSeq    int64
	HeadHash   string
	AnchorSeq  int64
	AnchorHash string
	UpdatedAt  time.Time
}

type AuditFilter struct {
	ActorID   string
	Action    string // prefix match
	ProjectID string
	From, To  *time.Time
}

const (
	JobPending = "pending"
	JobRunning = "running"
	JobDone    = "done"
	JobFailed  = "failed"
)

type Job struct {
	ID        string
	Kind      string
	State     string
	RunAfter  time.Time
	Attempts  int
	LastError string
	Payload   string
	DedupeKey string
	CreatedAt time.Time
	UpdatedAt time.Time
}

type Secret struct {
	ID             string
	TenantID       string
	ProjectID      string
	EnvironmentID  string
	Name           string
	Comment        string
	CurrentVersion int
	CreatedAt      time.Time
	UpdatedAt      time.Time
	DeletedAt      *time.Time
	// UpdatedByKind and UpdatedByID come from the current version.
	UpdatedByKind string
	UpdatedByID   string
}

type SecretVersion struct {
	ID            string
	TenantID      string
	SecretID      string
	Version       int
	DEKID         string
	Ciphertext    []byte
	ValueMAC      []byte
	CreatedByKind string
	CreatedByID   string
	CreatedAt     time.Time
	RestoredFrom  *int
}

// CurrentValue is a secret with its current version, for bulk reads.
type CurrentValue struct {
	Secret  Secret
	Version SecretVersion
}

// CompareCell is one environment's current MAC for one secret name.
type CompareCell struct {
	SecretID      string
	EnvironmentID string
	Name          string
	ValueMAC      []byte
}

const (
	TokenRead      = "read"
	TokenReadWrite = "read_write"
)

type ServiceToken struct {
	ID             string
	TenantID       string
	ProjectID      string
	Name           string
	TokenHash      string
	TokenPrefix    string
	Permission     string
	ExpiresAt      time.Time
	CreatedBy      string
	CreatedAt      time.Time
	LastUsedAt     *time.Time
	RevokedAt      *time.Time
	EnvironmentIDs []string
}

// Page is a cursor page request (core 9).
type Page struct {
	Limit  int
	Cursor string
}
