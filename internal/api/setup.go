package api

import (
	"context"
	"errors"
	"net/http"
	"net/mail"
	"regexp"
	"strings"
	"time"

	"github.com/x6c-co/rypt-store/internal/api/gen"
	"github.com/x6c-co/rypt-store/internal/audit"
	"github.com/x6c-co/rypt-store/internal/authn"
	"github.com/x6c-co/rypt-store/internal/ids"
	"github.com/x6c-co/rypt-store/internal/store"
)

// SetupTokenTTL is how long the first-start token stays valid (core 10).
const SetupTokenTTL = 24 * time.Hour

// IssueSetupToken generates the one-time setup token, stores its hash, and
// returns it for printing.
func (h *Handlers) IssueSetupToken(ctx context.Context) (string, error) {
	tok := ids.RandomToken(32)
	if err := h.d.Store.SetSetupToken(ctx, ids.HashToken(tok), h.now().Add(SetupTokenTTL)); err != nil {
		return "", err
	}
	return tok, nil
}

func (h *Handlers) GetSetupStatus(ctx context.Context, _ gen.GetSetupStatusRequestObject) (gen.GetSetupStatusResponseObject, error) {
	c := h.d.Config
	return gen.GetSetupStatus200JSONResponse{
		SetupRequired:  !h.SetupDone(),
		Provider:       c.Keys.Provider,
		DefaultKeyMode: gen.KeyMode(c.Keys.DefaultMode),
		RequireMfa:     c.Auth.RequireMFA,
		TlsMode:        c.EffectiveTLSMode(),
	}, nil
}

// checkSetupToken validates the setup token in constant time and rate
// limits guesses per source IP.
func (h *Handlers) checkSetupToken(ctx context.Context, token string) error {
	if h.SetupDone() {
		return errConflict("setup is already complete")
	}
	ip := MetaFrom(ctx).IP
	if h.d.Limiter.IP.Blocked("setup:" + ip) {
		return tooManyAttempts()
	}
	inst, err := h.d.Store.GetInstance(ctx)
	if err != nil {
		return err
	}
	if inst.SetupCompletedAt != nil {
		return errConflict("setup is already complete")
	}
	valid := inst.SetupTokenHash != "" && authn.EqualConstantTime(ids.HashToken(strings.TrimSpace(token)), inst.SetupTokenHash)
	if !valid || inst.SetupTokenExpiresAt == nil || !h.now().Before(*inst.SetupTokenExpiresAt) {
		h.d.Limiter.IP.Fail("setup:" + ip)
		return problem(http.StatusUnauthorized, "invalid_setup_token",
			"the setup token is wrong or expired; restart the server to print a new one")
	}
	return nil
}

func tooManyAttempts() *Problem {
	p := problem(http.StatusTooManyRequests, "rate_limited", "too many failed attempts; wait 15 minutes")
	p.Header = http.Header{"Retry-After": {"900"}}
	return p
}

func (h *Handlers) BeginSetupTotp(ctx context.Context, req gen.BeginSetupTotpRequestObject) (gen.BeginSetupTotpResponseObject, error) {
	if req.Body == nil {
		return nil, errInvalid("body", "a JSON body is required")
	}
	if err := h.checkSetupToken(ctx, req.Body.SetupToken); err != nil {
		return nil, err
	}
	email, err := normalizeEmail(string(req.Body.Email))
	if err != nil {
		return nil, errInvalid("email", err.Error())
	}
	secret, url, err := authn.NewTOTPSecret("rypt-store", email)
	if err != nil {
		return nil, err
	}
	return gen.BeginSetupTotp200JSONResponse{Secret: secret, OtpauthUrl: url}, nil
}

func normalizeEmail(s string) (string, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	a, err := mail.ParseAddress(s)
	if err != nil || a.Address != s || len(s) > 254 {
		return "", errors.New("enter a valid email address")
	}
	return s, nil
}

var slugInvalid = regexp.MustCompile(`[^a-z0-9]+`)

// Slugify derives a slug from a name.
func Slugify(name string) string {
	s := strings.Trim(slugInvalid.ReplaceAllString(strings.ToLower(name), "-"), "-")
	if len(s) > 64 {
		s = strings.Trim(s[:64], "-")
	}
	if s == "" {
		s = "default"
	}
	return s
}

var slugPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?$`)

func validSlug(s string) bool { return slugPattern.MatchString(s) }

func (h *Handlers) CompleteSetup(ctx context.Context, req gen.CompleteSetupRequestObject) (gen.CompleteSetupResponseObject, error) {
	b := req.Body
	if b == nil {
		return nil, errInvalid("body", "a JSON body is required")
	}
	if err := h.checkSetupToken(ctx, b.SetupToken); err != nil {
		return nil, err
	}
	var fe fieldErrors
	email, err := normalizeEmail(string(b.Email))
	if err != nil {
		fe.add("email", err.Error())
	}
	if err := authn.ValidatePassword(b.Password); err != nil {
		fe.add("password", err.Error())
	}
	name := strings.TrimSpace(b.DisplayName)
	if name == "" || len(name) > 128 {
		fe.add("display_name", "enter a name of at most 128 characters")
	}
	org := strings.TrimSpace(b.Organization)
	if org == "" || len(org) > 128 {
		fe.add("organization", "enter an organization name of at most 128 characters")
	}
	requireMFA := h.d.Config.Auth.RequireMFA
	secret, code := strings.TrimSpace(deref(b.TotpSecret)), strings.TrimSpace(deref(b.TotpCode))
	if requireMFA && (secret == "" || code == "") {
		fe.add("totp_code", "set up an authenticator app first: MFA is required")
	}
	if err := fe.err(); err != nil {
		return nil, err
	}

	now := h.now()
	admin := store.User{ID: ids.New(), Email: email, DisplayName: name, IsInstanceAdmin: true, CreatedAt: now, UpdatedAt: now}
	if admin.PasswordHash, err = authn.HashPassword(b.Password); err != nil {
		return nil, err
	}
	params := store.CompleteSetupParams{
		Admin:       admin,
		Tenant:      store.Tenant{ID: ids.New(), Name: org, Slug: Slugify(org), CreatedAt: now},
		CompletedAt: now,
	}
	var codes []string
	if secret != "" {
		if !h.d.TOTP.Verify(admin.ID, secret, code) {
			return nil, errInvalid("totp_code", "the code does not match; check the authenticator app's clock and try again")
		}
		ct, err := h.d.Keys.EncryptTOTP(ctx, admin.ID, []byte(secret))
		if err != nil {
			return nil, err
		}
		params.TOTP = &store.TOTP{UserID: admin.ID, SecretCiphertext: ct, ConfirmedAt: &now}
		var recs []store.RecoveryCode
		codes, recs, err = newRecoveryCodes(admin.ID)
		if err != nil {
			return nil, err
		}
		params.RecoveryCodes = recs
	}
	token := authn.NewWebSessionToken()
	sess := h.newSession(ctx, admin.ID, token, store.SessionWeb, true)
	params.Session = &sess

	err = h.record(ctx, audit.Event{
		ChainID: store.InstanceChain, ActorKind: audit.ActorUser, ActorID: admin.ID, Action: "setup.complete",
		TargetKind: "tenant", TargetID: params.Tenant.ID,
		Metadata: map[string]any{"email": email, "tenant": params.Tenant.Slug, "mfa": secret != ""},
	}, func(ev *store.AuditEvent) error { return h.d.Store.CompleteSetup(ctx, params, ev) })
	if err != nil {
		return nil, err
	}
	h.SetSetupDone(true)
	h.setSessionCookie(ctx, token, sess.ExpiresAt)
	if codes == nil {
		codes = []string{}
	}
	return gen.CompleteSetup201JSONResponse{
		User:          userJSON(&admin),
		Tenant:        tenantJSON(params.Tenant, "owner"),
		RecoveryCodes: codes,
	}, nil
}

// newRecoveryCodes returns ten codes and their hashed records (core 7.2).
func newRecoveryCodes(userID string) ([]string, []store.RecoveryCode, error) {
	codes := authn.NewRecoveryCodes(10)
	recs := make([]store.RecoveryCode, len(codes))
	for i, c := range codes {
		hsh, err := authn.HashRecoveryCode(c)
		if err != nil {
			return nil, nil, err
		}
		recs[i] = store.RecoveryCode{ID: ids.New(), UserID: userID, CodeHash: hsh}
	}
	return codes, recs, nil
}
