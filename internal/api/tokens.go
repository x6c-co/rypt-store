package api

import (
	"context"
	"errors"
	"slices"
	"strings"

	"github.com/x6c-co/rypt-store/internal/api/gen"
	"github.com/x6c-co/rypt-store/internal/audit"
	"github.com/x6c-co/rypt-store/internal/authn"
	"github.com/x6c-co/rypt-store/internal/authz"
	"github.com/x6c-co/rypt-store/internal/ids"
	"github.com/x6c-co/rypt-store/internal/store"
)

func tokenJSON(t store.ServiceToken, envSlugs map[string]string) gen.ServiceToken {
	envs := make([]string, 0, len(t.EnvironmentIDs))
	for _, id := range t.EnvironmentIDs {
		if s, ok := envSlugs[id]; ok {
			envs = append(envs, s)
		}
	}
	slices.Sort(envs)
	return gen.ServiceToken{Id: t.ID, Name: t.Name, Prefix: t.TokenPrefix, Permission: gen.TokenPermission(t.Permission),
		Environments: envs, ExpiresAt: t.ExpiresAt, CreatedAt: t.CreatedAt, CreatedBy: t.CreatedBy, LastUsedAt: t.LastUsedAt,
		RevokedAt: t.RevokedAt}
}

func (h *Handlers) envSlugs(ctx context.Context, s scope) (map[string]string, []store.Environment, error) {
	envs, err := h.d.Store.ListEnvironments(ctx, s.tenant.ID, s.proj.ID)
	if err != nil {
		return nil, nil, err
	}
	m := make(map[string]string, len(envs))
	for _, e := range envs {
		m[e.ID] = e.Slug
	}
	return m, envs, nil
}

func (h *Handlers) ListServiceTokens(ctx context.Context, req gen.ListServiceTokensRequestObject) (gen.ListServiceTokensResponseObject, error) {
	s, err := h.projectScope(ctx, req.Tenant, req.Project)
	if err != nil {
		return nil, err
	}
	if err := s.require(authz.TokenManage); err != nil {
		return nil, err
	}
	slugs, _, err := h.envSlugs(ctx, s)
	if err != nil {
		return nil, err
	}
	ts, err := h.d.Store.ListServiceTokens(ctx, s.tenant.ID, s.proj.ID)
	if err != nil {
		return nil, err
	}
	out := make([]gen.ServiceToken, 0, len(ts))
	for _, t := range ts {
		out = append(out, tokenJSON(t, slugs))
	}
	return gen.ListServiceTokens200JSONResponse{Tokens: out}, nil
}

func (h *Handlers) CreateServiceToken(ctx context.Context, req gen.CreateServiceTokenRequestObject) (gen.CreateServiceTokenResponseObject, error) {
	s, err := h.projectScope(ctx, req.Tenant, req.Project)
	if err != nil {
		return nil, err
	}
	if err := s.require(authz.TokenManage); err != nil {
		return nil, err
	}
	b := req.Body
	if b == nil {
		return nil, errInvalid("name", "name, environments, permission and expires_at are required")
	}
	var fe fieldErrors
	name := strings.TrimSpace(b.Name)
	if name == "" || len(name) > 64 {
		fe.add("name", "enter a label of at most 64 characters")
	}
	if b.Permission != gen.Read && b.Permission != gen.ReadWrite {
		fe.add("permission", "permission must be read or read_write")
	}
	now := h.now()
	maxTTL := h.d.Config.Tokens.MaxTTL.D()
	switch {
	case !b.ExpiresAt.After(now):
		fe.add("expires_at", "the expiry must be in the future")
	case b.ExpiresAt.Sub(now) > maxTTL:
		fe.add("expires_at", "the expiry is beyond tokens.max_ttl ("+maxTTL.String()+")")
	}
	slugs, envs, err := h.envSlugs(ctx, s)
	if err != nil {
		return nil, err
	}
	var envIDs []string
	for _, want := range b.Environments {
		found := false
		for _, e := range envs {
			if e.Slug == want {
				if !slices.Contains(envIDs, e.ID) {
					envIDs = append(envIDs, e.ID)
				}
				found = true
			}
		}
		if !found {
			fe.add("environments", "no environment "+want+" in this project")
		}
	}
	if len(envIDs) == 0 {
		fe.add("environments", "choose at least one environment")
	}
	if err := fe.err(); err != nil {
		return nil, err
	}
	t := store.ServiceToken{ID: ids.New(), TenantID: s.tenant.ID, ProjectID: s.proj.ID, Name: name, Permission: string(b.Permission),
		ExpiresAt: b.ExpiresAt.UTC(), CreatedBy: s.p.ID, CreatedAt: now, EnvironmentIDs: envIDs}
	parsed, full, err := authn.NewServiceToken(t.ID)
	if err != nil {
		return nil, err
	}
	t.TokenHash, t.TokenPrefix = parsed.SecretHash(), parsed.Prefix()
	err = h.record(ctx, audit.Event{ChainID: s.tenant.ID, ActorKind: audit.ActorUser, ActorID: s.p.ID, Action: "token.create",
		TargetKind: "service_token", TargetID: t.ID, ProjectID: s.proj.ID,
		Metadata: map[string]any{"name": name, "permission": t.Permission, "environments": b.Environments, "expires_at": t.ExpiresAt.Format("2006-01-02T15:04:05Z")}},
		func(ev *store.AuditEvent) error { return h.d.Store.CreateServiceToken(ctx, t, ev) })
	if err != nil {
		return nil, err
	}
	noStore(ctx)
	return gen.CreateServiceToken201JSONResponse{Token: tokenJSON(t, slugs), Secret: full}, nil
}

func (h *Handlers) RevokeServiceToken(ctx context.Context, req gen.RevokeServiceTokenRequestObject) (gen.RevokeServiceTokenResponseObject, error) {
	s, err := h.projectScope(ctx, req.Tenant, req.Project)
	if err != nil {
		return nil, err
	}
	if err := s.require(authz.TokenManage); err != nil {
		return nil, err
	}
	err = h.record(ctx, audit.Event{ChainID: s.tenant.ID, ActorKind: audit.ActorUser, ActorID: s.p.ID, Action: "token.revoke",
		TargetKind: "service_token", TargetID: req.Id, ProjectID: s.proj.ID},
		func(ev *store.AuditEvent) error {
			return h.d.Store.RevokeServiceToken(ctx, s.tenant.ID, s.proj.ID, req.Id, h.now(), ev)
		})
	if errors.Is(err, store.ErrNotFound) {
		return nil, errNotFound("token")
	}
	if err != nil {
		return nil, err
	}
	return gen.RevokeServiceToken204Response{}, nil
}
