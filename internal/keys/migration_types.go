package keys

// Migration kinds (core 5.7).
const (
	MigrateProvider = "provider"
	MigrateMode     = "mode"
	MigrateRotate   = "rotate"
)

// MigrationRequest describes a re-wrap migration.
type MigrationRequest struct {
	Kind string
	// To is the target provider (kind provider).
	To string
	// TenantID, ProjectID and Mode select the project and target mode
	// (kind mode).
	TenantID  string
	ProjectID string
	Mode      string
}

// Estimate is the --dry-run report: provider operations a migration will
// spend, by project.
type Estimate struct {
	Kind        string
	InstanceOps int
	Projects    []ProjectEstimate
	TotalOps    int
}

// ProjectEstimate is one project's share of an Estimate.
type ProjectEstimate struct {
	TenantID  string
	ProjectID string
	Ops       int
}
