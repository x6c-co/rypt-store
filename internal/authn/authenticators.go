package authn

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/x6c-co/rypt-store/internal/authz"
	"github.com/x6c-co/rypt-store/internal/ids"
	"github.com/x6c-co/rypt-store/internal/store"
)

// Authenticator turns a request credential into a principal (core 7.1).
type Authenticator interface {
	// Authenticate returns (nil, nil) when the request carries no
	// credential of this kind, and a *DeniedError when it carries one that
	// is refused.
	Authenticate(r *http.Request) (*authz.Principal, error)
}

// DeniedError is a presented credential that was refused. TenantID is set
// when the credential could be tied to a tenant, so that the denial is
// audited on that tenant's chain (token.denied).
type DeniedError struct {
	Kind     string // "service_token" or "cli_session"
	TokenID  string
	TenantID string
	Reason   string
}

func (e *DeniedError) Error() string { return e.Kind + " refused: " + e.Reason }

// Chain runs authenticators in order; the first principal wins.
type Chain []Authenticator

func (c Chain) Authenticate(r *http.Request) (*authz.Principal, error) {
	for _, a := range c {
		p, err := a.Authenticate(r)
		if err != nil || p != nil {
			return p, err
		}
	}
	return nil, nil
}

// SessionPolicy holds session lifetimes (core 7.3, 7.4).
type SessionPolicy struct {
	Idle   time.Duration
	Max    time.Duration
	CLIMax time.Duration
	Now    func() time.Time
}

// Valid reports whether a stored session is still usable.
func (p SessionPolicy) Valid(s *store.Session) bool {
	now := p.Now()
	if !now.Before(s.ExpiresAt) {
		return false
	}
	if s.Kind == store.SessionWeb && now.Sub(s.LastSeenAt) >= p.Idle {
		return false
	}
	return true
}

// touchInterval limits last_seen_at writes.
const touchInterval = time.Minute

func loadSessionPrincipal(ctx context.Context, st store.Store, pol SessionPolicy, token, kind string) (*authz.Principal, error) {
	s, err := st.GetSession(ctx, ids.HashToken(token))
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if s.Kind != kind || !pol.Valid(s) {
		return nil, nil
	}
	u, err := st.GetUser(ctx, s.UserID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if u.DisabledAt != nil {
		return nil, nil
	}
	if now := pol.Now(); now.Sub(s.LastSeenAt) >= touchInterval {
		_ = st.TouchSession(ctx, s.IDHash, now)
		s.LastSeenAt = now
	}
	return &authz.Principal{Kind: authz.KindUser, ID: u.ID, IsInstanceAdmin: u.IsInstanceAdmin, User: u, Session: s}, nil
}

// CookieAuthenticator reads the web session cookie. A stale or unknown
// cookie counts as no credential.
type CookieAuthenticator struct {
	Store  store.Store
	Policy SessionPolicy
}

func (a CookieAuthenticator) Authenticate(r *http.Request) (*authz.Principal, error) {
	c, err := r.Cookie(SessionCookie)
	if err != nil || c.Value == "" {
		return nil, nil
	}
	return loadSessionPrincipal(r.Context(), a.Store, a.Policy, c.Value, store.SessionWeb)
}

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) > 7 && strings.EqualFold(h[:7], "bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}

// ServiceTokenAuthenticator reads "Authorization: Bearer rst_..." (feature 01 3.8).
type ServiceTokenAuthenticator struct {
	Store store.Store
	Now   func() time.Time
}

func (a ServiceTokenAuthenticator) Authenticate(r *http.Request) (*authz.Principal, error) {
	raw := bearer(r)
	if !strings.HasPrefix(raw, ServiceTokenPrefix) {
		return nil, nil
	}
	ctx := r.Context()
	parsed, err := ParseServiceToken(raw)
	if err != nil {
		return nil, &DeniedError{Kind: "service_token", Reason: "malformed"}
	}
	t, err := a.Store.GetServiceToken(ctx, parsed.ID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, &DeniedError{Kind: "service_token", TokenID: parsed.ID, Reason: "unknown"}
	}
	if err != nil {
		return nil, err
	}
	deny := func(reason string) error {
		return &DeniedError{Kind: "service_token", TokenID: t.ID, TenantID: t.TenantID, Reason: reason}
	}
	if !EqualConstantTime(parsed.SecretHash(), t.TokenHash) {
		return nil, deny("wrong secret")
	}
	now := a.Now()
	switch {
	case t.RevokedAt != nil:
		return nil, deny("revoked")
	case !now.Before(t.ExpiresAt):
		return nil, deny("expired")
	case len(t.EnvironmentIDs) == 0:
		return nil, deny("no environments")
	}
	if t.LastUsedAt == nil || now.Sub(*t.LastUsedAt) >= time.Minute {
		_ = a.Store.TouchServiceToken(ctx, t.ID, now)
	}
	return &authz.Principal{
		Kind: authz.KindServiceToken, ID: t.ID, TenantID: t.TenantID,
		Scope: &authz.TokenScope{TenantID: t.TenantID, ProjectID: t.ProjectID, EnvironmentIDs: slices.Clone(t.EnvironmentIDs),
			Permission: t.Permission, Token: t},
	}, nil
}

// CLISessionAuthenticator reads "Authorization: Bearer rsc_..." (core 7.4).
type CLISessionAuthenticator struct {
	Store  store.Store
	Policy SessionPolicy
}

func (a CLISessionAuthenticator) Authenticate(r *http.Request) (*authz.Principal, error) {
	raw := bearer(r)
	if !strings.HasPrefix(raw, CLISessionPrefix) {
		if raw != "" && !strings.HasPrefix(raw, ServiceTokenPrefix) {
			return nil, &DeniedError{Kind: "bearer", Reason: "unrecognized token format"}
		}
		return nil, nil
	}
	p, err := loadSessionPrincipal(r.Context(), a.Store, a.Policy, raw, store.SessionCLI)
	if err != nil {
		return nil, err
	}
	if p == nil {
		return nil, &DeniedError{Kind: "cli_session", Reason: "unknown or expired"}
	}
	return p, nil
}
