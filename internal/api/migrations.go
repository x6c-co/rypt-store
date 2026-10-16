package api

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/x6c-co/rypt-store/internal/api/gen"
	"github.com/x6c-co/rypt-store/internal/keys"
	"github.com/x6c-co/rypt-store/internal/store"
)

func migrationJSON(m store.KeyMigration) gen.KeyMigration {
	var params map[string]any
	_ = json.Unmarshal([]byte(m.Params), &params)
	if params == nil {
		params = map[string]any{}
	}
	return gen.KeyMigration{Id: m.ID, Kind: gen.KeyMigrationKind(m.Kind), Params: params, State: gen.KeyMigrationState(m.State),
		ProjectsTotal: m.ProjectsTotal, ProjectsDone: m.ProjectsDone, Error: strPtr(m.Error), StartedBy: m.StartedBy,
		CreatedAt: m.CreatedAt, UpdatedAt: m.UpdatedAt, FinishedAt: m.FinishedAt}
}

// estimateJSON names projects by tenant and project slug.
func (h *Handlers) estimateJSON(ctx context.Context, e keys.Estimate) gen.MigrationEstimate {
	out := gen.MigrationEstimate{Kind: e.Kind, TotalOps: e.TotalOps, InstanceOps: ptr(e.InstanceOps),
		Projects: make([]gen.ProjectEstimate, 0, len(e.Projects))}
	tenants := map[string]string{}
	for _, p := range e.Projects {
		ts, ok := tenants[p.TenantID]
		if !ok {
			if t, err := h.d.Store.GetTenant(ctx, p.TenantID); err == nil {
				ts = t.Slug
			}
			tenants[p.TenantID] = ts
		}
		ps := p.ProjectID
		if pr, err := h.d.Store.GetProject(ctx, p.TenantID, p.ProjectID); err == nil {
			ps = pr.Slug
		}
		out.Projects = append(out.Projects, gen.ProjectEstimate{Tenant: ts, Project: ps, Ops: p.Ops})
	}
	return out
}

func (h *Handlers) ListKeyMigrations(ctx context.Context, _ gen.ListKeyMigrationsRequestObject) (gen.ListKeyMigrationsResponseObject, error) {
	if _, err := instanceAdmin(ctx); err != nil {
		return nil, err
	}
	ms, err := h.d.Store.ListKeyMigrations(ctx, 50)
	if err != nil {
		return nil, err
	}
	out := make([]gen.KeyMigration, 0, len(ms))
	for _, m := range ms {
		out = append(out, migrationJSON(m))
	}
	return gen.ListKeyMigrations200JSONResponse{Migrations: out}, nil
}

func (h *Handlers) GetKeyMigration(ctx context.Context, req gen.GetKeyMigrationRequestObject) (gen.GetKeyMigrationResponseObject, error) {
	if _, err := instanceAdmin(ctx); err != nil {
		return nil, err
	}
	m, err := h.d.Store.GetKeyMigration(ctx, req.Id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, errNotFound("migration")
	}
	if err != nil {
		return nil, err
	}
	return gen.GetKeyMigration200JSONResponse(migrationJSON(*m)), nil
}

// StartKeyMigration starts, or estimates with dry_run, a provider, rotate,
// or mode migration (core 5.7). Instance admins only.
func (h *Handlers) StartKeyMigration(ctx context.Context, req gen.StartKeyMigrationRequestObject) (gen.StartKeyMigrationResponseObject, error) {
	p, err := instanceAdmin(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, errInvalid("kind", "kind is required")
	}
	mreq := keys.MigrationRequest{Kind: string(req.Body.Kind)}
	params := req.Body.Params
	switch req.Body.Kind {
	case gen.KeyMigrationRequestKindProvider:
		if params == nil || deref(params.To) == "" {
			return nil, errInvalid("params.to", "name the target provider")
		}
		mreq.To = *params.To
	case gen.KeyMigrationRequestKindRotate:
	case gen.KeyMigrationRequestKindMode:
		if params == nil || deref(params.Tenant) == "" || deref(params.Project) == "" || params.Mode == nil {
			return nil, errInvalid("params", "a mode migration needs tenant, project and mode")
		}
		t, err := h.d.Store.GetTenantBySlug(ctx, *params.Tenant)
		if errors.Is(err, store.ErrNotFound) {
			return nil, errNotFound("tenant")
		}
		if err != nil {
			return nil, err
		}
		pr, err := h.d.Store.GetProjectBySlug(ctx, t.ID, *params.Project)
		if errors.Is(err, store.ErrNotFound) {
			return nil, errNotFound("project")
		}
		if err != nil {
			return nil, err
		}
		mreq.TenantID, mreq.ProjectID, mreq.Mode = t.ID, pr.ID, string(*params.Mode)
	default:
		return nil, errInvalid("kind", "kind must be provider, mode, or rotate")
	}
	if req.Body.DryRun != nil && *req.Body.DryRun {
		est, err := h.d.Migrations.Estimate(ctx, mreq)
		if err != nil {
			return nil, err
		}
		return gen.StartKeyMigration200JSONResponse(h.estimateJSON(ctx, est)), nil
	}
	m, err := h.d.Migrations.Start(ctx, mreq, p.ID)
	if err != nil {
		return nil, err
	}
	return gen.StartKeyMigration202JSONResponse(migrationJSON(*m)), nil
}
