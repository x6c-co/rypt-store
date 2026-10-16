package api

import (
	"context"
	"errors"
	"net/http"
	"sort"
	"strings"

	"github.com/x6c-co/rypt-store/internal/api/gen"
	"github.com/x6c-co/rypt-store/internal/audit"
	"github.com/x6c-co/rypt-store/internal/authz"
	"github.com/x6c-co/rypt-store/internal/secrets"
	"github.com/x6c-co/rypt-store/internal/store"
)

func (s scope) target() secrets.Target {
	return secrets.Target{Tenant: s.tenant, Project: s.proj, Env: s.env}
}

func (s scope) actor() secrets.Actor {
	k, id := actorOf(s.p)
	return secrets.Actor{Kind: k, ID: id}
}

// secretScope resolves the environment and checks an action, auditing a
// denied secret operation.
func (h *Handlers) secretScope(ctx context.Context, tenant, project, env string, a authz.Action) (scope, error) {
	s, err := h.envScope(ctx, tenant, project, env)
	if err != nil {
		return s, err
	}
	if !s.can(a) {
		k, id := actorOf(s.p)
		h.recordQuiet(ctx, audit.Event{ChainID: s.tenant.ID, ActorKind: k, ActorID: id, Action: string(a), Result: audit.Denied,
			TargetKind: "environment", TargetID: s.env.ID, ProjectID: s.proj.ID, EnvironmentID: s.env.ID})
		return s, s.require(a)
	}
	return s, nil
}

func noStore(ctx context.Context) { header(ctx).Set("Cache-Control", "no-store") }

func (h *Handlers) actorJSON(ctx context.Context, names *actorNames, kind, id string) *gen.Actor {
	if id == "" {
		return nil
	}
	return &gen.Actor{Kind: gen.ActorKind(kind), Id: id, Display: strPtr(names.name(ctx, kind, id))}
}

func (h *Handlers) secretJSON(ctx context.Context, names *actorNames, x *store.Secret) gen.Secret {
	return gen.Secret{Id: x.ID, Name: x.Name, Comment: x.Comment, Version: x.CurrentVersion, CreatedAt: x.CreatedAt,
		UpdatedAt: x.UpdatedAt, UpdatedBy: h.actorJSON(ctx, names, x.UpdatedByKind, x.UpdatedByID)}
}

// secretErr maps a missing secret to 404 with a clear noun.
func secretErr(err error) error {
	if errors.Is(err, store.ErrNotFound) {
		return errNotFound("secret")
	}
	return err
}

func (h *Handlers) CompareSecrets(ctx context.Context, req gen.CompareSecretsRequestObject) (gen.CompareSecretsResponseObject, error) {
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
	rows, err := h.d.Secrets.Compare(ctx, s.tenant.ID, s.proj.ID, envs)
	if err != nil {
		return nil, err
	}
	out := gen.CompareGrid{Environments: make([]gen.Environment, 0, len(envs)), Rows: make([]gen.CompareRow, 0, len(rows))}
	for _, e := range envs {
		out.Environments = append(out.Environments, envJSON(e))
	}
	for _, r := range rows {
		row := gen.CompareRow{Name: r.Name, Cells: make([]gen.CompareCell, 0, len(envs))}
		for _, e := range envs {
			c := gen.CompareCell{Environment: e.Slug, Missing: true}
			if g, ok := r.Groups[e.ID]; ok {
				c.Missing, c.Group = false, ptr(g)
			}
			row.Cells = append(row.Cells, c)
		}
		out.Rows = append(out.Rows, row)
	}
	return gen.CompareSecrets200JSONResponse(out), nil
}

func (h *Handlers) ListSecrets(ctx context.Context, req gen.ListSecretsRequestObject) (gen.ListSecretsResponseObject, error) {
	s, err := h.envScope(ctx, req.Tenant, req.Project, req.Environment)
	if err != nil {
		return nil, err
	}
	// Service tokens list the names in their environments too.
	if !s.can(authz.ProjectRead) && !s.can(authz.SecretRead) {
		return nil, s.require(authz.ProjectRead)
	}
	xs, err := h.d.Store.ListSecrets(ctx, s.tenant.ID, s.env.ID)
	if err != nil {
		return nil, err
	}
	// Cursor pagination by name (core 9).
	limit := pageLimit(req.Params.Limit)
	cursor := deref(req.Params.Cursor)
	start := sort.Search(len(xs), func(i int) bool { return xs[i].Name > cursor })
	if cursor == "" {
		start = 0
	}
	end := min(start+limit, len(xs))
	names := h.names()
	out := make([]gen.Secret, 0, end-start)
	for i := start; i < end; i++ {
		out = append(out, h.secretJSON(ctx, names, &xs[i]))
	}
	var next *string
	if end < len(xs) {
		next = ptr(xs[end-1].Name)
	}
	return gen.ListSecrets200JSONResponse{Secrets: out, NextCursor: next}, nil
}

func validateSecretInput(name *string, value string, comment *string) error {
	var fe fieldErrors
	if name != nil {
		if err := secrets.ValidateName(*name); err != nil {
			fe.add("name", err.Error())
		}
	}
	if err := secrets.ValidateValue(value); err != nil {
		fe.add("value", err.Error())
	}
	if comment != nil {
		if err := secrets.ValidateComment(*comment); err != nil {
			fe.add("comment", err.Error())
		}
	}
	return fe.err()
}

func (h *Handlers) CreateSecret(ctx context.Context, req gen.CreateSecretRequestObject) (gen.CreateSecretResponseObject, error) {
	s, err := h.secretScope(ctx, req.Tenant, req.Project, req.Environment, authz.SecretWrite)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, errInvalid("name", "name and value are required")
	}
	if err := validateSecretInput(&req.Body.Name, req.Body.Value, req.Body.Comment); err != nil {
		return nil, err
	}
	x, err := h.d.Secrets.Create(ctx, s.target(), s.actor(), req.Body.Name, req.Body.Value, deref(req.Body.Comment))
	if err != nil {
		return nil, err
	}
	return gen.CreateSecret201JSONResponse{Body: h.secretJSON(ctx, h.names(), x),
		Headers: gen.CreateSecret201ResponseHeaders{ETag: ptr(secrets.ETag(x.CurrentVersion))}}, nil
}

func (h *Handlers) GetSecret(ctx context.Context, req gen.GetSecretRequestObject) (gen.GetSecretResponseObject, error) {
	s, err := h.secretScope(ctx, req.Tenant, req.Project, req.Environment, authz.SecretRead)
	if err != nil {
		return nil, err
	}
	x, value, err := h.d.Secrets.Read(ctx, s.target(), s.actor(), req.Name)
	if err != nil {
		return nil, secretErr(err)
	}
	noStore(ctx)
	sj := h.secretJSON(ctx, h.names(), x)
	return gen.GetSecret200JSONResponse{
		Body: gen.SecretWithValue{Id: sj.Id, Name: sj.Name, Comment: sj.Comment, Version: sj.Version, CreatedAt: sj.CreatedAt,
			UpdatedAt: sj.UpdatedAt, UpdatedBy: sj.UpdatedBy, Value: value},
		Headers: gen.GetSecret200ResponseHeaders{ETag: ptr(secrets.ETag(x.CurrentVersion))},
	}, nil
}

func (h *Handlers) UpdateSecret(ctx context.Context, req gen.UpdateSecretRequestObject) (gen.UpdateSecretResponseObject, error) {
	s, err := h.secretScope(ctx, req.Tenant, req.Project, req.Environment, authz.SecretWrite)
	if err != nil {
		return nil, err
	}
	expected, ok := secrets.ParseETag(strings.TrimSpace(req.Params.IfMatch))
	if !ok {
		return nil, errInvalid("If-Match", `If-Match must hold the current version, e.g. "3"`)
	}
	if req.Body == nil {
		return nil, errInvalid("value", "value is required")
	}
	if err := validateSecretInput(nil, req.Body.Value, req.Body.Comment); err != nil {
		return nil, err
	}
	x, err := h.d.Secrets.Update(ctx, s.target(), s.actor(), req.Name, req.Body.Value, req.Body.Comment, expected)
	if err != nil {
		return nil, secretErr(err)
	}
	return gen.UpdateSecret200JSONResponse{Body: h.secretJSON(ctx, h.names(), x),
		Headers: gen.UpdateSecret200ResponseHeaders{ETag: ptr(secrets.ETag(x.CurrentVersion))}}, nil
}

func (h *Handlers) DeleteSecret(ctx context.Context, req gen.DeleteSecretRequestObject) (gen.DeleteSecretResponseObject, error) {
	s, err := h.secretScope(ctx, req.Tenant, req.Project, req.Environment, authz.SecretWrite)
	if err != nil {
		return nil, err
	}
	if err := h.d.Secrets.Delete(ctx, s.target(), s.actor(), req.Name); err != nil {
		return nil, secretErr(err)
	}
	return gen.DeleteSecret204Response{}, nil
}

func (h *Handlers) versionJSON(ctx context.Context, names *actorNames, v store.SecretVersion, current int) gen.SecretVersion {
	return gen.SecretVersion{Version: v.Version, CreatedAt: v.CreatedAt, RestoredFrom: v.RestoredFrom, Current: ptr(v.Version == current),
		CreatedBy: deref(h.actorJSON(ctx, names, v.CreatedByKind, v.CreatedByID))}
}

func (h *Handlers) ListSecretVersions(ctx context.Context, req gen.ListSecretVersionsRequestObject) (gen.ListSecretVersionsResponseObject, error) {
	s, err := h.secretScope(ctx, req.Tenant, req.Project, req.Environment, authz.SecretRead)
	if err != nil {
		return nil, err
	}
	x, vs, err := h.d.Secrets.History(ctx, s.target(), req.Name)
	if err != nil {
		return nil, secretErr(err)
	}
	names := h.names()
	out := make([]gen.SecretVersion, 0, len(vs))
	for _, v := range vs {
		out = append(out, h.versionJSON(ctx, names, v, x.CurrentVersion))
	}
	return gen.ListSecretVersions200JSONResponse{Versions: out}, nil
}

func (h *Handlers) GetSecretVersion(ctx context.Context, req gen.GetSecretVersionRequestObject) (gen.GetSecretVersionResponseObject, error) {
	s, err := h.secretScope(ctx, req.Tenant, req.Project, req.Environment, authz.SecretRead)
	if err != nil {
		return nil, err
	}
	v, value, err := h.d.Secrets.ReadVersion(ctx, s.target(), s.actor(), req.Name, req.Version)
	if errors.Is(err, store.ErrNotFound) {
		return nil, errNotFound("secret version")
	}
	if err != nil {
		return nil, err
	}
	noStore(ctx)
	x, err := h.d.Secrets.Get(ctx, s.target(), req.Name)
	if err != nil {
		return nil, secretErr(err)
	}
	vj := h.versionJSON(ctx, h.names(), *v, x.CurrentVersion)
	return gen.GetSecretVersion200JSONResponse{Version: vj.Version, CreatedAt: vj.CreatedAt, CreatedBy: vj.CreatedBy,
		RestoredFrom: vj.RestoredFrom, Current: vj.Current, Value: value}, nil
}

func (h *Handlers) RestoreSecretVersion(ctx context.Context, req gen.RestoreSecretVersionRequestObject) (gen.RestoreSecretVersionResponseObject, error) {
	s, err := h.secretScope(ctx, req.Tenant, req.Project, req.Environment, authz.SecretWrite)
	if err != nil {
		return nil, err
	}
	x, err := h.d.Secrets.RestoreVersion(ctx, s.target(), s.actor(), req.Name, req.Version)
	if errors.Is(err, store.ErrNotFound) {
		return nil, errNotFound("secret version")
	}
	if err != nil {
		return nil, err
	}
	return gen.RestoreSecretVersion200JSONResponse{Body: h.secretJSON(ctx, h.names(), x),
		Headers: gen.RestoreSecretVersion200ResponseHeaders{ETag: ptr(secrets.ETag(x.CurrentVersion))}}, nil
}

func (h *Handlers) ListDeletedSecrets(ctx context.Context, req gen.ListDeletedSecretsRequestObject) (gen.ListDeletedSecretsResponseObject, error) {
	s, err := h.secretScope(ctx, req.Tenant, req.Project, req.Environment, authz.SecretRead)
	if err != nil {
		return nil, err
	}
	xs, retention, err := h.d.Secrets.Deleted(ctx, s.target())
	if err != nil {
		return nil, err
	}
	live, err := h.d.Store.ListSecrets(ctx, s.tenant.ID, s.env.ID)
	if err != nil {
		return nil, err
	}
	inUse := map[string]bool{}
	for _, l := range live {
		inUse[l.Name] = true
	}
	out := make([]gen.DeletedSecret, 0, len(xs))
	for _, x := range xs {
		out = append(out, gen.DeletedSecret{Id: x.ID, Name: x.Name, Version: x.CurrentVersion, DeletedAt: *x.DeletedAt,
			PurgeAt: x.DeletedAt.Add(retention), NameInUse: ptr(inUse[x.Name])})
	}
	return gen.ListDeletedSecrets200JSONResponse{Secrets: out}, nil
}

func (h *Handlers) RestoreDeletedSecret(ctx context.Context, req gen.RestoreDeletedSecretRequestObject) (gen.RestoreDeletedSecretResponseObject, error) {
	s, err := h.secretScope(ctx, req.Tenant, req.Project, req.Environment, authz.SecretWrite)
	if err != nil {
		return nil, err
	}
	x, err := h.d.Secrets.RestoreDeleted(ctx, s.target(), s.actor(), req.Id)
	if err != nil {
		return nil, secretErr(err)
	}
	return gen.RestoreDeletedSecret200JSONResponse(h.secretJSON(ctx, h.names(), x)), nil
}

func (h *Handlers) ImportSecrets(ctx context.Context, req gen.ImportSecretsRequestObject) (gen.ImportSecretsResponseObject, error) {
	s, err := h.secretScope(ctx, req.Tenant, req.Project, req.Environment, authz.SecretWrite)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, errInvalid("body", "send the .env file as the text/plain body")
	}
	if len(*req.Body) > 4<<20 {
		return nil, problem(http.StatusRequestEntityTooLarge, "validation_failed", "the file is larger than 4 MiB")
	}
	overwrite := req.Params.Mode != nil && *req.Params.Mode == gen.Overwrite
	res, err := h.d.Secrets.Import(ctx, s.target(), s.actor(), string(*req.Body), overwrite)
	if err != nil {
		return nil, err
	}
	rej := make([]gen.ImportRejection, 0, len(res.Rejected))
	for _, r := range res.Rejected {
		rej = append(rej, gen.ImportRejection{Name: strPtr(r.Name), Line: r.Line, Reason: r.Reason})
	}
	return gen.ImportSecrets200JSONResponse{Created: res.Created, Updated: res.Updated, Skipped: res.Skipped, Rejected: rej}, nil
}

func (h *Handlers) ExportSecrets(ctx context.Context, req gen.ExportSecretsRequestObject) (gen.ExportSecretsResponseObject, error) {
	s, err := h.secretScope(ctx, req.Tenant, req.Project, req.Environment, authz.SecretRead)
	if err != nil {
		return nil, err
	}
	format := "dotenv"
	if req.Params.Format != nil {
		format = string(*req.Params.Format)
	}
	values, err := h.d.Secrets.Values(ctx, s.target(), s.actor(), "export")
	if err != nil {
		return nil, err
	}
	noStore(ctx)
	if format == "json" {
		return gen.ExportSecrets200JSONResponse(values), nil
	}
	header(ctx).Set("Content-Disposition", `attachment; filename="`+s.proj.Slug+`.`+s.env.Slug+`.env"`)
	return gen.ExportSecrets200TextResponse(secrets.FormatDotenv(values)), nil
}

func (h *Handlers) GetSecretValues(ctx context.Context, req gen.GetSecretValuesRequestObject) (gen.GetSecretValuesResponseObject, error) {
	s, err := h.secretScope(ctx, req.Tenant, req.Project, req.Environment, authz.SecretRead)
	if err != nil {
		return nil, err
	}
	values, err := h.d.Secrets.Values(ctx, s.target(), s.actor(), "values")
	if err != nil {
		return nil, err
	}
	noStore(ctx)
	return gen.GetSecretValues200JSONResponse{Values: values}, nil
}
