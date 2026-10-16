package api

import (
	"context"
	"encoding/json"

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
