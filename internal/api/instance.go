package api

import (
	"context"
	"errors"
	"sort"

	"github.com/x6c-co/rypt-store/internal/api/gen"
	"github.com/x6c-co/rypt-store/internal/store"
)

func (h *Handlers) GetInstanceSettings(ctx context.Context, _ gen.GetInstanceSettingsRequestObject) (gen.GetInstanceSettingsResponseObject, error) {
	if _, err := instanceAdmin(ctx); err != nil {
		return nil, err
	}
	c := h.d.Config
	domains := c.TLS.Domains
	if domains == nil {
		domains = []string{}
	}
	return gen.GetInstanceSettings200JSONResponse{
		InstanceId: h.d.Keys.InstanceID(), Provider: c.Keys.Provider, Providers: h.d.Keys.ProviderNames(),
		DefaultKeyMode: gen.KeyMode(c.Keys.DefaultMode), OutagePolicy: gen.InstanceSettingsOutagePolicy(c.Rypt.OutagePolicy),
		RequireMfa: c.Auth.RequireMFA, TlsMode: gen.InstanceSettingsTlsMode(c.EffectiveTLSMode()), TlsDomains: &domains,
		VersionsKept: c.Secrets.VersionsKept, AuditRetentionDays: c.Audit.RetentionDays, PublicUrl: h.baseURL(ctx),
		RyptKeyId: strPtr(c.Rypt.KeyID),
	}, nil
}

func (h *Handlers) ListInstanceUsers(ctx context.Context, _ gen.ListInstanceUsersRequestObject) (gen.ListInstanceUsersResponseObject, error) {
	if _, err := instanceAdmin(ctx); err != nil {
		return nil, err
	}
	us, err := h.d.Store.ListUsers(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]gen.User, 0, len(us))
	for i := range us {
		out = append(out, userJSON(&us[i]))
	}
	return gen.ListInstanceUsers200JSONResponse{Users: out}, nil
}

func (h *Handlers) CreateUserPasswordReset(ctx context.Context, req gen.CreateUserPasswordResetRequestObject) (gen.CreateUserPasswordResetResponseObject, error) {
	p, err := instanceAdmin(ctx)
	if err != nil {
		return nil, err
	}
	u, err := h.d.Store.GetUser(ctx, req.User)
	if errors.Is(err, store.ErrNotFound) {
		return nil, errNotFound("user")
	}
	if err != nil {
		return nil, err
	}
	link, err := h.createResetLink(ctx, p, store.InstanceChain, u)
	if err != nil {
		return nil, err
	}
	return gen.CreateUserPasswordReset201JSONResponse(link), nil
}

// modeCosts states the provider operations of each mode (core 5.2,
// feature 01 3.2).
var modeCosts = []gen.ModeCost{
	{Mode: gen.A, Chain: "provider → RK → PK → DEK → value", ReadCost: "One unwrap per root-key cache miss.",
		WriteCost: "None beyond reads."},
	{Mode: gen.B, Chain: "provider → PK → DEK → value", ReadCost: "One unwrap per project per project-key cache miss.",
		WriteCost: "None beyond reads."},
	{Mode: gen.C, Chain: "provider → DEK → value", ReadCost: "One unwrap per secret version per cache miss; a cold bulk read of N secrets costs N.",
		WriteCost: "One wrap per secret write."},
}

func (h *Handlers) GetInstanceKeys(ctx context.Context, _ gen.GetInstanceKeysRequestObject) (gen.GetInstanceKeysResponseObject, error) {
	if _, err := instanceAdmin(ctx); err != nil {
		return nil, err
	}
	st := h.d.Keys.Status()
	wraps, err := h.d.Store.CountWrapsByProvider(ctx)
	if err != nil {
		return nil, err
	}
	names := map[string]bool{}
	for _, n := range st.Providers {
		names[n] = true
	}
	for n := range wraps {
		names[n] = true
	}
	var providers []gen.ProviderInfo
	for n := range names {
		loaded := false
		for _, l := range st.Providers {
			loaded = loaded || l == n
		}
		providers = append(providers, gen.ProviderInfo{Name: n, Loaded: loaded, Unavailable: st.ProviderDown[n], Wraps: wraps[n]})
	}
	sort.Slice(providers, func(i, j int) bool { return providers[i].Name < providers[j].Name })
	month := h.now().Format("2006-01")
	// Count what this process has not flushed yet too.
	_ = h.d.Keys.FlushOpCounts(ctx)
	counts, err := h.d.Store.ListProviderOpCounts(ctx, month)
	if err != nil {
		return nil, err
	}
	ops := make([]gen.OpCount, 0, len(counts))
	for _, c := range counts {
		ops = append(ops, gen.OpCount{Provider: c.Provider, Op: c.Op, Count: c.Count})
	}
	return gen.GetInstanceKeys200JSONResponse{
		Provider: st.Current, DefaultKeyMode: gen.KeyMode(h.d.Config.Keys.DefaultMode), Providers: providers,
		Month: month, OpCounts: ops, CacheEntries: st.CacheEntries, Quota: quotaJSON(st), ModeCosts: modeCosts,
	}, nil
}
