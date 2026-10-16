package api

import (
	"context"
	"errors"

	"github.com/x6c-co/rypt-store/internal/api/gen"
	"github.com/x6c-co/rypt-store/internal/authz"
	"github.com/x6c-co/rypt-store/internal/keys"
	"github.com/x6c-co/rypt-store/internal/store"
)

// scope is a resolved tenant, project and environment with the principal
// narrowed to the tenant.
type scope struct {
	p      *authz.Principal
	tenant *store.Tenant
	proj   *store.Project
	env    *store.Environment
}

func (s scope) resource() authz.Resource {
	r := authz.Resource{TenantID: s.tenant.ID}
	if s.proj != nil {
		r.ProjectID = s.proj.ID
	}
	if s.env != nil {
		r.EnvironmentID = s.env.ID
	}
	return r
}

// can checks an action on the scope.
func (s scope) can(a authz.Action) bool { return authz.Can(s.p, a, s.resource()) }

// require returns 403 when the principal lacks the action. Service tokens
// see 404 instead (feature 01 3.8).
func (s scope) require(a authz.Action) error {
	if s.can(a) {
		return nil
	}
	if s.p.Kind == authz.KindServiceToken {
		return errNotFound("resource")
	}
	return errForbidden("your role does not allow " + string(a))
}

// tenantScope resolves a tenant slug. A tenant the principal cannot see is
// 404, never 403, so tenants do not learn of each other (core 6.2).
func (h *Handlers) tenantScope(ctx context.Context, slug string) (scope, error) {
	p := PrincipalFrom(ctx)
	if p == nil {
		return scope{}, errUnauthorized()
	}
	t, err := h.d.Store.GetTenantBySlug(ctx, slug)
	if errors.Is(err, store.ErrNotFound) {
		return scope{}, errNotFound("tenant")
	}
	if err != nil {
		return scope{}, err
	}
	switch p.Kind {
	case authz.KindServiceToken:
		if p.Scope.TenantID != t.ID {
			return scope{}, errNotFound("tenant")
		}
		return scope{p: p.WithTenant(t.ID, ""), tenant: t}, nil
	default:
		m, err := h.d.Store.GetMembership(ctx, t.ID, p.ID)
		if errors.Is(err, store.ErrNotFound) {
			return scope{}, errNotFound("tenant")
		}
		if err != nil {
			return scope{}, err
		}
		return scope{p: p.WithTenant(t.ID, authz.Role(m.Role)), tenant: t}, nil
	}
}

func (h *Handlers) projectScope(ctx context.Context, tenantSlug, projectSlug string) (scope, error) {
	s, err := h.tenantScope(ctx, tenantSlug)
	if err != nil {
		return s, err
	}
	pr, err := h.d.Store.GetProjectBySlug(ctx, s.tenant.ID, projectSlug)
	if errors.Is(err, store.ErrNotFound) {
		return s, errNotFound("project")
	}
	if err != nil {
		return s, err
	}
	if s.p.Kind == authz.KindServiceToken && s.p.Scope.ProjectID != pr.ID {
		return s, errNotFound("project")
	}
	s.proj = pr
	return s, nil
}

func (h *Handlers) envScope(ctx context.Context, tenantSlug, projectSlug, envSlug string) (scope, error) {
	s, err := h.projectScope(ctx, tenantSlug, projectSlug)
	if err != nil {
		return s, err
	}
	e, err := h.d.Store.GetEnvironmentBySlug(ctx, s.tenant.ID, s.proj.ID, envSlug)
	if errors.Is(err, store.ErrNotFound) {
		return s, errNotFound("environment")
	}
	if err != nil {
		return s, err
	}
	s.env = e
	if s.p.Kind == authz.KindServiceToken && !authz.Can(s.p, authz.SecretRead, s.resource()) {
		return s, errNotFound("environment")
	}
	return s, nil
}

// ---- JSON conversions ----

func tenantJSON(t store.Tenant, role string) gen.Tenant {
	out := gen.Tenant{Id: t.ID, Name: t.Name, Slug: t.Slug, CreatedAt: t.CreatedAt}
	if role != "" {
		out.Role = ptr(gen.Role(role))
	}
	return out
}

func envJSON(e store.Environment) gen.Environment {
	return gen.Environment{Id: e.ID, Name: e.Name, Slug: e.Slug, Position: e.Position, CreatedAt: e.CreatedAt}
}

func projectJSON(p store.Project, envs []store.Environment) gen.Project {
	out := gen.Project{Id: p.ID, Name: p.Name, Slug: p.Slug, KeyMode: gen.KeyMode(p.KeyMode), CreatedAt: p.CreatedAt,
		Environments: make([]gen.Environment, 0, len(envs))}
	for _, e := range envs {
		out.Environments = append(out.Environments, envJSON(e))
	}
	return out
}

func quotaJSON(st keys.Status) *gen.ProviderQuota {
	q := st.QuotaExceeded
	if q == nil {
		return nil
	}
	out := &gen.ProviderQuota{Provider: q.Provider, Code: strPtr(q.Code), SeenAt: ptr(st.QuotaAt.UTC())}
	if q.Cap > 0 {
		out.Cap = ptr(q.Cap)
	}
	if !q.ResetsAt.IsZero() {
		out.ResetsAt = ptr(q.ResetsAt.UTC())
	}
	return out
}
