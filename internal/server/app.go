package server

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"time"

	"github.com/x6c-co/rypt-store/internal/api"
	"github.com/x6c-co/rypt-store/internal/audit"
	"github.com/x6c-co/rypt-store/internal/authn"
	"github.com/x6c-co/rypt-store/internal/config"
	"github.com/x6c-co/rypt-store/internal/jobs"
	"github.com/x6c-co/rypt-store/internal/keys"
	"github.com/x6c-co/rypt-store/internal/keys/provider"
	"github.com/x6c-co/rypt-store/internal/metrics"
	"github.com/x6c-co/rypt-store/internal/secrets"
	"github.com/x6c-co/rypt-store/internal/store"
	"github.com/x6c-co/rypt-store/internal/version"
)

// App is the assembled server process (core 4.1).
type App struct {
	Config   *config.Config
	Store    store.Store
	Keys     *keys.Service
	Audit    *audit.Writer
	API      *api.Handlers
	Jobs     *jobs.Runner
	Secrets  *secrets.Service
	Metrics  *metrics.Metrics
	Log      *slog.Logger
	Handler  http.Handler
	Instance *store.Instance
}

// AppOptions configures NewApp.
type AppOptions struct {
	Config *config.Config
	Store  store.Store
	// Providers overrides the providers built from the config (tests).
	Providers []provider.Provider
	SPA       fs.FS
	Logger    *slog.Logger
	Now       func() time.Time
}

// BuildProviders loads every provider whose configuration is present
// (core 5.7): local when a KEK is available or can be created, rypt when a
// token and key ID are set.
func BuildProviders(cfg *config.Config, log *slog.Logger) ([]provider.Provider, error) {
	var out []provider.Provider
	kek, created, err := provider.LoadOrCreateKEK(cfg.Keys.Local.KEKFile, cfg.Keys.Local.KEK)
	if err != nil {
		return nil, err
	}
	if created {
		log.Warn("generated a new local key-encryption key; back it up: losing it makes every secret unrecoverable",
			"path", cfg.Keys.Local.KEKFile)
	}
	local, err := provider.NewLocal(kek)
	clear(kek)
	if err != nil {
		return nil, err
	}
	out = append(out, local)
	if cfg.RyptConfigured() {
		r, err := provider.NewRypt(provider.RyptOptions{Token: cfg.Rypt.Token, KeyID: cfg.Rypt.KeyID, BaseURL: cfg.Rypt.BaseURL,
			UserAgent: "rypt-store/" + version.String()})
		if err != nil {
			return nil, fmt.Errorf("rypt provider: %w", err)
		}
		out = append(out, r)
	}
	return out, nil
}

// NewApp wires the components and loads or creates the instance.
func NewApp(ctx context.Context, o AppOptions) (*App, error) {
	cfg := o.Config
	log := o.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	now := o.Now
	if now == nil {
		now = time.Now
	}
	m := metrics.New()
	providers := o.Providers
	if providers == nil {
		var err error
		if providers, err = BuildProviders(cfg, log); err != nil {
			return nil, err
		}
	}
	aw := audit.NewWriter(o.Store, m, now)
	ks, err := keys.New(keys.Options{
		Store: o.Store, Providers: providers, Current: cfg.Keys.Provider, CacheTTL: cfg.Keys.CacheTTL.D(),
		CacheMax: cfg.Keys.CacheMaxEntries, ServeCached: cfg.Rypt.OutagePolicy == "serve_cached", MaxStale: cfg.Rypt.MaxStale.D(),
		Metrics: m, Logger: log, Now: now,
		OnOutage: func(ctx context.Context, name string, down bool, cause error) {
			action, meta := "keys.provider.recovered", map[string]any{"provider": name}
			ev := audit.Event{ChainID: store.InstanceChain, ActorKind: audit.ActorSystem, Action: action, Metadata: meta}
			if down {
				ev.Action, ev.Result = "keys.provider.outage", audit.Error
				ev.ProviderRequestID = provider.RequestIDOf(cause)
				meta["error"] = cause.Error()
			}
			if err := aw.Record(ctx, ev, nil); err != nil {
				log.Error("audit write failed", "action", ev.Action, "error", err.Error())
			}
		},
	})
	if err != nil {
		return nil, err
	}
	inst, _, err := ks.Init(ctx)
	if err != nil {
		return nil, fmt.Errorf("initialize instance: %w", err)
	}
	if err := ks.CheckProviders(ctx); err != nil {
		return nil, err
	}
	wa, err := authn.NewWebAuthn(cfg.Server.PublicURL, now)
	if err != nil {
		return nil, err
	}
	policy := authn.SessionPolicy{Idle: cfg.Auth.SessionIdle.D(), Max: cfg.Auth.SessionMax.D(), CLIMax: cfg.Auth.CLISessionMax.D(), Now: now}
	runner := jobs.New(o.Store, log, now)
	sec := secrets.New(secrets.Options{Store: o.Store, Keys: ks, Audit: aw, Jobs: runner, VersionsKept: cfg.Secrets.VersionsKept,
		DeletedRetention: cfg.Secrets.DeletedRetention.D(), Now: now})
	runner.Handle(secrets.JobPrune, sec.PruneJob)
	h := api.New(api.Deps{
		Store: o.Store, Keys: ks, Audit: aw, Config: cfg, WebAuthn: wa, TOTP: authn.NewTOTPVerifier(now), Secrets: sec,
		Limiter: authn.NewLoginLimiter(now), Sessions: policy, Jobs: runner, Metrics: m, Logger: log, Now: now,
	})
	h.SetSetupDone(inst.SetupCompletedAt != nil)
	mode := cfg.EffectiveTLSMode()
	handler := NewHandler(HandlerOptions{
		API: h, Store: o.Store, Audit: aw, SPA: o.SPA, Metrics: m, Logger: log, HSTS: mode == "acme" || mode == "files",
		Authenticator: authn.Chain{
			authn.CookieAuthenticator{Store: o.Store, Policy: policy},
			authn.ServiceTokenAuthenticator{Store: o.Store, Now: now},
			authn.CLISessionAuthenticator{Store: o.Store, Policy: policy},
		},
	})
	app := &App{Config: cfg, Store: o.Store, Keys: ks, Audit: aw, API: h, Jobs: runner, Secrets: sec, Metrics: m, Log: log,
		Handler: handler, Instance: inst}
	app.registerJobs()
	return app, nil
}

// registerJobs adds the periodic maintenance tasks.
func (a *App) registerJobs() {
	a.Jobs.Every("provider-op-counts", time.Minute, false, a.Keys.FlushOpCounts)
	a.Jobs.Every("session-expiry", 10*time.Minute, true, func(ctx context.Context) error {
		now := time.Now().UTC()
		if _, err := a.Store.DeleteExpiredSessions(ctx, now, now.Add(-a.Config.Auth.SessionIdle.D())); err != nil {
			return err
		}
		return a.Store.DeleteExpiredDeviceAuth(ctx, now)
	})
	a.Jobs.Every("audit-retention", 6*time.Hour, true, a.pruneAudit)
	a.Jobs.Every("secret-purge", time.Hour, true, a.Secrets.PurgeSweep)
	a.Jobs.Every("secret-prune-sweep", 6*time.Hour, true, a.Secrets.PruneSweep)
	a.Jobs.Every("retired-wraps", time.Hour, false, func(ctx context.Context) error {
		_, err := a.Store.DeleteRetiredWraps(ctx, time.Now().UTC().Add(-a.Config.Keys.RetiredWrapRetention.D()))
		return err
	})
	a.Jobs.Every("job-cleanup", time.Hour, false, func(ctx context.Context) error {
		return a.Store.DeleteFinishedJobs(ctx, time.Now().UTC().Add(-7*24*time.Hour))
	})
}

// pruneAudit applies audit.retention_days to every chain (core 8.5).
func (a *App) pruneAudit(ctx context.Context) error {
	days := a.Config.Audit.RetentionDays
	if days <= 0 {
		return nil
	}
	chains, err := a.Store.ListAuditChains(ctx)
	if err != nil {
		return err
	}
	before := time.Now().UTC().Add(-time.Duration(days) * 24 * time.Hour)
	for _, c := range chains {
		if n, err := a.Audit.Prune(ctx, c.ChainID, before); err != nil {
			return fmt.Errorf("prune chain %s: %w", c.ChainID, err)
		} else if n > 0 {
			a.Log.Info("pruned audit events", "chain", c.ChainID, "deleted", n)
		}
	}
	return nil
}
