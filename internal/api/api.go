// Package api implements the handlers of the strict server generated from
// api/openapi.yaml (core 9).
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/x6c-co/rypt-store/internal/api/gen"
	"github.com/x6c-co/rypt-store/internal/audit"
	"github.com/x6c-co/rypt-store/internal/authn"
	"github.com/x6c-co/rypt-store/internal/authz"
	"github.com/x6c-co/rypt-store/internal/config"
	"github.com/x6c-co/rypt-store/internal/keys"
	"github.com/x6c-co/rypt-store/internal/keys/provider"
	"github.com/x6c-co/rypt-store/internal/metrics"
	"github.com/x6c-co/rypt-store/internal/store"
)

// Jobs enqueues background work.
type Jobs interface {
	Enqueue(ctx context.Context, kind string, payload any, dedupeKey string, runAfter time.Time) error
}

// Migrations runs re-wrap migrations (core 5.7).
type Migrations interface {
	Estimate(ctx context.Context, req keys.MigrationRequest) (keys.Estimate, error)
	Start(ctx context.Context, req keys.MigrationRequest, startedBy string) (*store.KeyMigration, error)
}

// Deps are the handlers' collaborators.
type Deps struct {
	Store      store.Store
	Keys       *keys.Service
	Audit      *audit.Writer
	Config     *config.Config
	WebAuthn   *authn.WebAuthn
	TOTP       *authn.TOTPVerifier
	Limiter    *authn.LoginLimiter
	Sessions   authn.SessionPolicy
	Jobs       Jobs
	Migrations Migrations
	Metrics    *metrics.Metrics
	Logger     *slog.Logger
	Now        func() time.Time
}

// Handlers implements gen.StrictServerInterface.
type Handlers struct {
	unimplemented

	d Deps

	setupDone   atomic.Bool
	devicePolls *pollTracker
}

var _ gen.StrictServerInterface = (*Handlers)(nil)

func New(d Deps) *Handlers {
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.Logger == nil {
		d.Logger = slog.New(slog.DiscardHandler)
	}
	return &Handlers{d: d, devicePolls: newPollTracker()}
}

// SetSetupDone records that first-run setup has completed.
func (h *Handlers) SetSetupDone(done bool) { h.setupDone.Store(done) }

// SetupDone reports whether first-run setup has completed.
func (h *Handlers) SetupDone() bool { return h.setupDone.Load() }

func (h *Handlers) now() time.Time { return h.d.Now().UTC() }

// ---- request context ----

type ctxKey int

const (
	principalKey ctxKey = iota
	metaKey
	writerKey
)

// RequestMeta is request data the strict handlers need beyond their typed
// inputs.
type RequestMeta struct {
	IP           string
	UserAgent    string
	Origin       string
	Host         string
	SessionToken string // web cookie or CLI bearer token, when present
	TLS          bool
}

func WithPrincipal(ctx context.Context, p *authz.Principal) context.Context {
	return context.WithValue(ctx, principalKey, p)
}

func PrincipalFrom(ctx context.Context) *authz.Principal {
	p, _ := ctx.Value(principalKey).(*authz.Principal)
	return p
}

func WithMeta(ctx context.Context, m RequestMeta) context.Context {
	return context.WithValue(ctx, metaKey, m)
}

func MetaFrom(ctx context.Context) RequestMeta {
	m, _ := ctx.Value(metaKey).(RequestMeta)
	return m
}

// WithWriter lets handlers set cookies and headers before the strict
// server writes the response.
func WithWriter(ctx context.Context, w http.ResponseWriter) context.Context {
	return context.WithValue(ctx, writerKey, w)
}

func header(ctx context.Context) http.Header {
	if w, ok := ctx.Value(writerKey).(http.ResponseWriter); ok {
		return w.Header()
	}
	return http.Header{}
}

func setCookie(ctx context.Context, c *http.Cookie) {
	if w, ok := ctx.Value(writerKey).(http.ResponseWriter); ok {
		http.SetCookie(w, c)
	}
}

// ---- problems (RFC 9457) ----

// Problem is an API error with a stable code.
type Problem struct {
	Status int
	Code   string
	Title  string
	Detail string
	Fields []gen.FieldError
	// Header is added to the response, for example Retry-After.
	Header http.Header
}

func (p *Problem) Error() string { return p.Code + ": " + p.Detail }

func problem(status int, code, detail string) *Problem {
	return &Problem{Status: status, Code: code, Title: http.StatusText(status), Detail: detail}
}

func errNotFound(what string) *Problem {
	return problem(http.StatusNotFound, "not_found", what+" not found")
}

func errForbidden(detail string) *Problem {
	return problem(http.StatusForbidden, "forbidden", detail)
}

func errUnauthorized() *Problem {
	return problem(http.StatusUnauthorized, "unauthorized", "sign in first")
}

func errConflict(detail string) *Problem {
	return problem(http.StatusConflict, "conflict", detail)
}

// errInvalid is a validation failure on one field.
func errInvalid(field, msg string) *Problem {
	p := problem(http.StatusBadRequest, "validation_failed", msg)
	p.Fields = []gen.FieldError{{Field: field, Message: msg}}
	return p
}

// fieldErrors collects validation failures.
type fieldErrors []gen.FieldError

func (f *fieldErrors) add(field, msg string) {
	*f = append(*f, gen.FieldError{Field: field, Message: msg})
}

func (f fieldErrors) err() error {
	if len(f) == 0 {
		return nil
	}
	p := problem(http.StatusBadRequest, "validation_failed", f[0].Message)
	p.Fields = f
	return p
}

// ToProblem maps any error onto a problem.
func ToProblem(err error) *Problem {
	var p *Problem
	if errors.As(err, &p) {
		return p
	}
	var ce *store.ConflictError
	switch {
	case errors.As(err, &ce):
		return errConflict(conflictDetail(ce.Detail))
	case errors.Is(err, store.ErrConflict):
		return errConflict("the change conflicts with the current state")
	case errors.Is(err, store.ErrNotFound):
		return errNotFound("resource")
	}
	var pe *provider.Error
	if errors.As(err, &pe) {
		switch pe.Kind {
		case provider.Outage:
			return problem(http.StatusServiceUnavailable, "key_provider_unavailable",
				"the key provider ("+pe.Provider+") is unreachable; try again later")
		case provider.Quota:
			d := "the rypt.dev operation quota is exhausted"
			if pe.Cap > 0 {
				d = fmt.Sprintf("the rypt.dev monthly operation cap of %d is reached", pe.Cap)
				if !pe.ResetsAt.IsZero() {
					d += "; it resets at " + pe.ResetsAt.UTC().Format(time.RFC3339)
				}
			}
			return problem(http.StatusServiceUnavailable, "key_provider_quota", d)
		}
	}
	return problem(http.StatusInternalServerError, "internal", "internal error")
}

// conflictDetail turns a constraint name into a sentence.
func conflictDetail(d string) string {
	switch {
	case strings.Contains(d, "users.email"):
		return "a user with this email already exists"
	case strings.Contains(d, "tenants.slug"):
		return "a tenant with this slug already exists"
	case strings.Contains(d, "projects.tenant_id, projects.slug"):
		return "a project with this slug already exists"
	case strings.Contains(d, "environments.project_id, environments.slug"):
		return "an environment with this slug already exists"
	case strings.Contains(d, "secrets.environment_id, secrets.name"):
		return "a secret with this name already exists in the environment"
	case strings.Contains(d, "service_tokens.project_id, service_tokens.name"):
		return "a token with this name already exists in the project"
	case strings.Contains(d, "tenant_memberships"):
		return "the user is already a member"
	}
	return d
}

// WriteProblem writes err as application/problem+json.
func WriteProblem(w http.ResponseWriter, r *http.Request, err error, log *slog.Logger) {
	p := ToProblem(err)
	reqID := w.Header().Get("X-Request-Id")
	if p.Status >= 500 && p.Code == "internal" && log != nil {
		log.Error("request failed", "request_id", reqID, "method", r.Method, "path", r.URL.Path, "error", err.Error())
	}
	for k, vs := range p.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	body := gen.Problem{Type: "https://rypt.dev/problems/" + p.Code, Title: p.Title, Status: p.Status, Code: p.Code}
	if p.Detail != "" {
		body.Detail = &p.Detail
	}
	if reqID != "" {
		body.RequestId = &reqID
	}
	if len(p.Fields) > 0 {
		body.Errors = &p.Fields
	}
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(p.Status)
	_ = json.NewEncoder(w).Encode(body)
}

// ---- small helpers ----

func ptr[T any](v T) *T { return &v }

func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func deref[T any](p *T) T {
	var zero T
	if p == nil {
		return zero
	}
	return *p
}

// baseURL is the public URL of the server, from server.public_url or the
// request's host.
func (h *Handlers) baseURL(ctx context.Context) string {
	if u := h.d.Config.Server.PublicURL; u != "" {
		return strings.TrimRight(u, "/")
	}
	m := MetaFrom(ctx)
	host := m.Host
	if host == "" {
		host = "localhost"
	}
	return (&url.URL{Scheme: "https", Host: host}).String()
}

// userJSON converts a user record.
func userJSON(u *store.User) gen.User {
	out := gen.User{Id: u.ID, Email: u.Email, DisplayName: u.DisplayName, IsInstanceAdmin: u.IsInstanceAdmin, CreatedAt: u.CreatedAt}
	if u.DisabledAt != nil {
		out.Disabled = ptr(true)
	}
	return out
}

// record writes an audit event; apply nil writes the event alone.
func (h *Handlers) record(ctx context.Context, ev audit.Event, apply func(*store.AuditEvent) error) error {
	return h.d.Audit.Record(ctx, ev, apply)
}

// recordQuiet writes an audit event that must not fail the request, such
// as a denial; failures are logged.
func (h *Handlers) recordQuiet(ctx context.Context, ev audit.Event) {
	if err := h.d.Audit.Record(ctx, ev, nil); err != nil {
		h.d.Logger.Error("audit write failed", "action", ev.Action, "error", err.Error())
	}
}

// actorOf describes the principal for audit events.
func actorOf(p *authz.Principal) (kind, id string) {
	if p == nil {
		return audit.ActorSystem, ""
	}
	if p.Kind == authz.KindServiceToken {
		return audit.ActorServiceToken, p.ID
	}
	return audit.ActorUser, p.ID
}
