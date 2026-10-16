// Package authz decides what a principal may do (core 7.5). Every handler
// calls Can before acting. Can is the single entry point so that a policy
// engine such as Cerbos can replace the implementation later (core X7).
package authz

import (
	"slices"

	"github.com/x6c-co/rypt-store/internal/store"
)

// Role is a fixed tenant-level role (core D11).
type Role string

const (
	Owner  Role = "owner"
	Admin  Role = "admin"
	Member Role = "member"
	Viewer Role = "viewer"
)

// ValidRole reports whether r is one of the four roles.
func ValidRole(r string) bool {
	switch Role(r) {
	case Owner, Admin, Member, Viewer:
		return true
	}
	return false
}

// Rank orders roles: owner 4 > admin 3 > member 2 > viewer 1.
func (r Role) Rank() int {
	switch r {
	case Owner:
		return 4
	case Admin:
		return 3
	case Member:
		return 2
	case Viewer:
		return 1
	}
	return 0
}

// Action is a permission name.
type Action string

const (
	SecretRead     Action = "secret.read"
	SecretWrite    Action = "secret.write"
	ProjectManage  Action = "project.manage"
	ProjectKeyMode Action = "project.key_mode"
	TokenManage    Action = "token.manage"
	MemberManage   Action = "member.manage"
	AuditRead      Action = "audit.read"
	TenantOwn      Action = "tenant.own"
	// ProjectRead covers listing projects, environments and secret names.
	ProjectRead Action = "project.read"
	// InstanceManage covers tenants, instance settings, provider migrations
	// and the instance audit chain (instance admins only).
	InstanceManage Action = "instance.manage"
)

// Actions lists every action, for the table-driven tests.
var Actions = []Action{SecretRead, SecretWrite, ProjectManage, ProjectKeyMode, TokenManage, MemberManage, AuditRead, TenantOwn, ProjectRead, InstanceManage}

// grants is the role table of core 7.5.
var grants = map[Action][]Role{
	ProjectRead:    {Owner, Admin, Member, Viewer},
	SecretRead:     {Owner, Admin, Member, Viewer},
	SecretWrite:    {Owner, Admin, Member},
	ProjectManage:  {Owner, Admin},
	ProjectKeyMode: {Owner, Admin},
	TokenManage:    {Owner, Admin},
	MemberManage:   {Owner, Admin},
	AuditRead:      {Owner, Admin},
	TenantOwn:      {Owner},
}

// PrincipalKind distinguishes users from machine credentials.
type PrincipalKind string

const (
	KindUser         PrincipalKind = "user"
	KindServiceToken PrincipalKind = "service_token"
)

// TokenScope is a service token's reach (feature 01 2.4).
type TokenScope struct {
	TenantID       string
	ProjectID      string
	EnvironmentIDs []string
	Permission     string
	Token          *store.ServiceToken
}

// Principal is the authenticated caller (core 7.1).
type Principal struct {
	Kind PrincipalKind
	ID   string
	// TenantID is the tenant in scope for this request; Role is the user's
	// role in it. Both are empty until a tenant is resolved.
	TenantID string
	Role     Role
	Scope    *TokenScope // service tokens only

	IsInstanceAdmin bool
	User            *store.User    // users only
	Session         *store.Session // users only
}

// WithTenant returns a copy of p scoped to a tenant with the given role.
func (p *Principal) WithTenant(tenantID string, role Role) *Principal {
	c := *p
	c.TenantID, c.Role = tenantID, role
	return &c
}

// Resource is what an action applies to. Empty fields are not checked.
type Resource struct {
	TenantID      string
	ProjectID     string
	EnvironmentID string
}

// Can reports whether p may perform action on res.
func Can(p *Principal, action Action, res Resource) bool {
	if p == nil {
		return false
	}
	if action == InstanceManage {
		return p.Kind == KindUser && p.IsInstanceAdmin
	}
	switch p.Kind {
	case KindUser:
		// Instance admin status grants nothing inside a tenant (core 7.5).
		if res.TenantID == "" || p.TenantID != res.TenantID {
			return false
		}
		return slices.Contains(grants[action], p.Role)
	case KindServiceToken:
		s := p.Scope
		if s == nil || res.TenantID != s.TenantID || res.ProjectID != s.ProjectID || res.EnvironmentID == "" {
			return false
		}
		if !slices.Contains(s.EnvironmentIDs, res.EnvironmentID) {
			return false
		}
		switch action {
		case SecretRead:
			return true
		case SecretWrite:
			return s.Permission == store.TokenReadWrite
		}
	}
	return false
}

// CanAssignRole reports whether a member manager with role actor may move
// a member from role from to role to (core 7.5: "change roles below own";
// only owners touch the owner role).
func CanAssignRole(actor, from, to Role) bool {
	if actor == Owner {
		return true
	}
	if actor != Admin {
		return false
	}
	return from.Rank() < Admin.Rank() && to.Rank() < Admin.Rank()
}
