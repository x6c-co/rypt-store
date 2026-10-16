package api

import (
	"context"
	"strconv"
	"strings"

	"github.com/x6c-co/rypt-store/internal/api/gen"
	"github.com/x6c-co/rypt-store/internal/audit"
	"github.com/x6c-co/rypt-store/internal/authz"
	"github.com/x6c-co/rypt-store/internal/ids"
	"github.com/x6c-co/rypt-store/internal/keys"
	"github.com/x6c-co/rypt-store/internal/store"
)

// defaultEnvironments start every new project (core 6.1).
var defaultEnvironments = []string{"dev", "staging", "prod"}

func (h *Handlers) projectWithEnvs(ctx context.Context, p store.Project) (gen.Project, error) {
	envs, err := h.d.Store.ListEnvironments(ctx, p.TenantID, p.ID)
	if err != nil {
		return gen.Project{}, err
	}
	return projectJSON(p, envs), nil
}

func (h *Handlers) ListProjects(ctx context.Context, req gen.ListProjectsRequestObject) (gen.ListProjectsResponseObject, error) {
	s, err := h.tenantScope(ctx, req.Tenant)
	if err != nil {
		return nil, err
	}
	if err := s.require(authz.ProjectRead); err != nil {
		return nil, err
	}
	ps, err := h.d.Store.ListProjects(ctx, s.tenant.ID)
	if err != nil {
		return nil, err
	}
	out := make([]gen.Project, 0, len(ps))
	for _, p := range ps {
		pj, err := h.projectWithEnvs(ctx, p)
		if err != nil {
			return nil, err
		}
		out = append(out, pj)
	}
	return gen.ListProjects200JSONResponse{Projects: out}, nil
}

func cleanName(field, v string, max int) (string, error) {
	v = strings.TrimSpace(v)
	if v == "" || len(v) > max {
		return "", errInvalid(field, "enter a name of at most "+strconv.Itoa(max)+" characters")
	}
	return v, nil
}

func slugOrDefault(given *string, name string) (string, error) {
	if given == nil || *given == "" {
		return Slugify(name), nil
	}
	if !validSlug(*given) {
		return "", errInvalid("slug", "use lowercase letters, digits and dashes (at most 64)")
	}
	return *given, nil
}

func (h *Handlers) CreateProject(ctx context.Context, req gen.CreateProjectRequestObject) (gen.CreateProjectResponseObject, error) {
	s, err := h.tenantScope(ctx, req.Tenant)
	if err != nil {
		return nil, err
	}
	if err := s.require(authz.ProjectManage); err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, errInvalid("name", "name is required")
	}
	name, err := cleanName("name", req.Body.Name, 128)
	if err != nil {
		return nil, err
	}
	slug, err := slugOrDefault(req.Body.Slug, name)
	if err != nil {
		return nil, err
	}
	mode := h.d.Config.Keys.DefaultMode
	if req.Body.KeyMode != nil {
		mode = string(*req.Body.KeyMode)
	}
	if !keys.ValidMode(mode) {
		return nil, errInvalid("key_mode", "key_mode must be A, B, or C")
	}
	now := h.now()
	p := store.Project{ID: ids.New(), TenantID: s.tenant.ID, Name: name, Slug: slug, KeyMode: mode, CreatedAt: now}
	envs := make([]store.Environment, len(defaultEnvironments))
	for i, e := range defaultEnvironments {
		envs[i] = store.Environment{ID: ids.New(), TenantID: p.TenantID, ProjectID: p.ID, Name: e, Slug: e, Position: i, CreatedAt: now}
	}
	wraps, err := h.d.Keys.NewProjectWraps(ctx, p.TenantID, p.ID, mode)
	if err != nil {
		return nil, err
	}
	err = h.record(ctx, audit.Event{ChainID: s.tenant.ID, ActorKind: audit.ActorUser, ActorID: s.p.ID, Action: "project.create",
		TargetKind: "project", TargetID: p.ID, ProjectID: p.ID, Metadata: map[string]any{"name": name, "slug": slug, "key_mode": mode}},
		func(ev *store.AuditEvent) error { return h.d.Store.CreateProject(ctx, p, envs, wraps, ev) })
	if err != nil {
		h.d.Keys.EvictProject(p.ID)
		return nil, err
	}
	return gen.CreateProject201JSONResponse(projectJSON(p, envs)), nil
}

func (h *Handlers) GetProject(ctx context.Context, req gen.GetProjectRequestObject) (gen.GetProjectResponseObject, error) {
	s, err := h.projectScope(ctx, req.Tenant, req.Project)
	if err != nil {
		return nil, err
	}
	if err := s.require(authz.ProjectRead); err != nil {
		return nil, err
	}
	pj, err := h.projectWithEnvs(ctx, *s.proj)
	if err != nil {
		return nil, err
	}
	return gen.GetProject200JSONResponse(pj), nil
}

func (h *Handlers) UpdateProject(ctx context.Context, req gen.UpdateProjectRequestObject) (gen.UpdateProjectResponseObject, error) {
	s, err := h.projectScope(ctx, req.Tenant, req.Project)
	if err != nil {
		return nil, err
	}
	if err := s.require(authz.ProjectManage); err != nil {
		return nil, err
	}
	p := *s.proj
	if req.Body != nil && req.Body.Name != nil {
		if p.Name, err = cleanName("name", *req.Body.Name, 128); err != nil {
			return nil, err
		}
	}
	if req.Body != nil && req.Body.Slug != nil {
		if !validSlug(*req.Body.Slug) {
			return nil, errInvalid("slug", "use lowercase letters, digits and dashes (at most 64)")
		}
		p.Slug = *req.Body.Slug
	}
	err = h.record(ctx, audit.Event{ChainID: s.tenant.ID, ActorKind: audit.ActorUser, ActorID: s.p.ID, Action: "project.update",
		TargetKind: "project", TargetID: p.ID, ProjectID: p.ID,
		Metadata: map[string]any{"name": p.Name, "slug": p.Slug, "old_name": s.proj.Name, "old_slug": s.proj.Slug}},
		func(ev *store.AuditEvent) error {
			return h.d.Store.UpdateProject(ctx, s.tenant.ID, p.ID, p.Name, p.Slug, ev)
		})
	if err != nil {
		return nil, err
	}
	pj, err := h.projectWithEnvs(ctx, p)
	if err != nil {
		return nil, err
	}
	return gen.UpdateProject200JSONResponse(pj), nil
}

func (h *Handlers) DeleteProject(ctx context.Context, req gen.DeleteProjectRequestObject) (gen.DeleteProjectResponseObject, error) {
	s, err := h.projectScope(ctx, req.Tenant, req.Project)
	if err != nil {
		return nil, err
	}
	if err := s.require(authz.ProjectManage); err != nil {
		return nil, err
	}
	err = h.record(ctx, audit.Event{ChainID: s.tenant.ID, ActorKind: audit.ActorUser, ActorID: s.p.ID, Action: "project.delete",
		TargetKind: "project", TargetID: s.proj.ID, ProjectID: s.proj.ID, Metadata: map[string]any{"slug": s.proj.Slug}},
		func(ev *store.AuditEvent) error {
			return h.d.Store.DeleteProject(ctx, s.tenant.ID, s.proj.ID, h.now(), ev)
		})
	if err != nil {
		return nil, err
	}
	h.d.Keys.EvictProject(s.proj.ID)
	return gen.DeleteProject204Response{}, nil
}

// ---- environments ----

func (h *Handlers) ListEnvironments(ctx context.Context, req gen.ListEnvironmentsRequestObject) (gen.ListEnvironmentsResponseObject, error) {
	s, err := h.projectScope(ctx, req.Tenant, req.Project)
	if err != nil {
		return nil, err
	}
	if err := s.require(authz.ProjectRead); err != nil {
		return nil, err
	}
	envs, err := h.d.Store.ListEnvironments(ctx, s.tenant.ID, s.proj.ID)
	if err != nil {
		return nil, err
	}
	out := make([]gen.Environment, 0, len(envs))
	for _, e := range envs {
		out = append(out, envJSON(e))
	}
	return gen.ListEnvironments200JSONResponse{Environments: out}, nil
}

func (h *Handlers) CreateEnvironment(ctx context.Context, req gen.CreateEnvironmentRequestObject) (gen.CreateEnvironmentResponseObject, error) {
	s, err := h.projectScope(ctx, req.Tenant, req.Project)
	if err != nil {
		return nil, err
	}
	if err := s.require(authz.ProjectManage); err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, errInvalid("name", "name is required")
	}
	name, err := cleanName("name", req.Body.Name, 64)
	if err != nil {
		return nil, err
	}
	slug, err := slugOrDefault(req.Body.Slug, name)
	if err != nil {
		return nil, err
	}
	pos := 0
	if req.Body.Position != nil {
		pos = *req.Body.Position
	} else {
		envs, err := h.d.Store.ListEnvironments(ctx, s.tenant.ID, s.proj.ID)
		if err != nil {
			return nil, err
		}
		for _, e := range envs {
			pos = max(pos, e.Position+1)
		}
	}
	e := store.Environment{ID: ids.New(), TenantID: s.tenant.ID, ProjectID: s.proj.ID, Name: name, Slug: slug, Position: pos, CreatedAt: h.now()}
	err = h.record(ctx, audit.Event{ChainID: s.tenant.ID, ActorKind: audit.ActorUser, ActorID: s.p.ID, Action: "environment.create",
		TargetKind: "environment", TargetID: e.ID, ProjectID: s.proj.ID, EnvironmentID: e.ID, Metadata: map[string]any{"slug": slug}},
		func(ev *store.AuditEvent) error { return h.d.Store.CreateEnvironment(ctx, e, ev) })
	if err != nil {
		return nil, err
	}
	return gen.CreateEnvironment201JSONResponse(envJSON(e)), nil
}

func (h *Handlers) UpdateEnvironment(ctx context.Context, req gen.UpdateEnvironmentRequestObject) (gen.UpdateEnvironmentResponseObject, error) {
	s, err := h.envScope(ctx, req.Tenant, req.Project, req.Environment)
	if err != nil {
		return nil, err
	}
	if err := s.require(authz.ProjectManage); err != nil {
		return nil, err
	}
	e := *s.env
	if req.Body != nil {
		if req.Body.Name != nil {
			if e.Name, err = cleanName("name", *req.Body.Name, 64); err != nil {
				return nil, err
			}
		}
		if req.Body.Slug != nil {
			if !validSlug(*req.Body.Slug) {
				return nil, errInvalid("slug", "use lowercase letters, digits and dashes (at most 64)")
			}
			e.Slug = *req.Body.Slug
		}
		if req.Body.Position != nil {
			e.Position = *req.Body.Position
		}
	}
	err = h.record(ctx, audit.Event{ChainID: s.tenant.ID, ActorKind: audit.ActorUser, ActorID: s.p.ID, Action: "environment.update",
		TargetKind: "environment", TargetID: e.ID, ProjectID: s.proj.ID, EnvironmentID: e.ID,
		Metadata: map[string]any{"name": e.Name, "slug": e.Slug, "position": e.Position}},
		func(ev *store.AuditEvent) error {
			return h.d.Store.UpdateEnvironment(ctx, s.tenant.ID, e.ID, e.Name, e.Slug, e.Position, ev)
		})
	if err != nil {
		return nil, err
	}
	return gen.UpdateEnvironment200JSONResponse(envJSON(e)), nil
}

func (h *Handlers) DeleteEnvironment(ctx context.Context, req gen.DeleteEnvironmentRequestObject) (gen.DeleteEnvironmentResponseObject, error) {
	s, err := h.envScope(ctx, req.Tenant, req.Project, req.Environment)
	if err != nil {
		return nil, err
	}
	if err := s.require(authz.ProjectManage); err != nil {
		return nil, err
	}
	err = h.d.Keys.WithProjectWrite(s.proj.ID, func() error {
		return h.record(ctx, audit.Event{ChainID: s.tenant.ID, ActorKind: audit.ActorUser, ActorID: s.p.ID, Action: "environment.delete",
			TargetKind: "environment", TargetID: s.env.ID, ProjectID: s.proj.ID, EnvironmentID: s.env.ID,
			Metadata: map[string]any{"slug": s.env.Slug}},
			func(ev *store.AuditEvent) error { return h.d.Store.DeleteEnvironment(ctx, s.tenant.ID, s.env.ID, ev) })
	})
	if err != nil {
		return nil, err
	}
	return gen.DeleteEnvironment204Response{}, nil
}
