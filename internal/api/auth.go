package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/x6c-co/rypt-store/internal/api/gen"
	"github.com/x6c-co/rypt-store/internal/audit"
	"github.com/x6c-co/rypt-store/internal/authn"
	"github.com/x6c-co/rypt-store/internal/authz"
	"github.com/x6c-co/rypt-store/internal/ids"
	"github.com/x6c-co/rypt-store/internal/store"
)

// preMFASession bounds a session that still owes its second factor.
const preMFASession = 10 * time.Minute

// newSession builds a session record for a fresh token.
func (h *Handlers) newSession(ctx context.Context, userID, token, kind string, mfaSatisfied bool) store.Session {
	now := h.now()
	m := MetaFrom(ctx)
	life := h.d.Sessions.Max
	switch {
	case kind == store.SessionCLI:
		life = h.d.Sessions.CLIMax
	case !mfaSatisfied:
		life = preMFASession
	}
	return store.Session{
		IDHash: ids.HashToken(token), PublicID: ids.New(), UserID: userID, Kind: kind, MFASatisfied: mfaSatisfied,
		CreatedAt: now, ExpiresAt: now.Add(life), LastSeenAt: now, IP: m.IP, UserAgent: truncate(m.UserAgent, 512),
	}
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func (h *Handlers) setSessionCookie(ctx context.Context, token string, expires time.Time) {
	setCookie(ctx, &http.Cookie{
		Name: authn.SessionCookie, Value: token, Path: "/", Secure: true, HttpOnly: true,
		SameSite: http.SameSiteStrictMode, Expires: expires,
	})
}

func (h *Handlers) clearSessionCookie(ctx context.Context) {
	setCookie(ctx, &http.Cookie{
		Name: authn.SessionCookie, Value: "", Path: "/", Secure: true, HttpOnly: true,
		SameSite: http.SameSiteStrictMode, MaxAge: -1,
	})
}

// MFAStatus reports which second factors a user has.
type MFAStatus struct {
	TOTP     bool
	Passkeys int
	Codes    int
}

// Any reports whether the user has a second factor.
func (m MFAStatus) Any() bool { return m.TOTP || m.Passkeys > 0 }

func (m MFAStatus) methods() []gen.LoginResultMfaMethods {
	var out []gen.LoginResultMfaMethods
	if m.TOTP {
		out = append(out, gen.Totp)
	}
	if m.Passkeys > 0 {
		out = append(out, gen.Webauthn)
	}
	if m.Codes > 0 {
		out = append(out, gen.RecoveryCode)
	}
	return out
}

// MFAState loads a user's second factors.
func (h *Handlers) MFAState(ctx context.Context, userID string) (MFAStatus, error) {
	var s MFAStatus
	t, err := h.d.Store.GetTOTP(ctx, userID)
	switch {
	case err == nil:
		s.TOTP = t.ConfirmedAt != nil
	case !errors.Is(err, store.ErrNotFound):
		return s, err
	}
	pk, err := h.d.Store.ListWebAuthnCredentials(ctx, userID)
	if err != nil {
		return s, err
	}
	s.Passkeys = len(pk)
	if s.Codes, err = h.d.Store.CountRecoveryCodes(ctx, userID); err != nil {
		return s, err
	}
	return s, nil
}

func invalidCredentials() *Problem {
	return problem(http.StatusUnauthorized, "invalid_credentials", "the email or password is wrong")
}

func (h *Handlers) Login(ctx context.Context, req gen.LoginRequestObject) (gen.LoginResponseObject, error) {
	if req.Body == nil {
		return nil, errInvalid("body", "a JSON body is required")
	}
	email := strings.ToLower(strings.TrimSpace(req.Body.Email))
	ip := MetaFrom(ctx).IP
	fail := func(userID, reason string, result string) {
		h.recordQuiet(ctx, audit.Event{ChainID: store.InstanceChain, ActorKind: audit.ActorUser, ActorID: userID,
			Action: "auth.login.failed", Result: result, TargetKind: "user", TargetID: userID,
			Metadata: map[string]any{"email": email, "reason": reason}})
	}
	if h.d.Limiter.Blocked(email, ip) {
		fail("", "rate_limited", audit.Denied)
		return nil, tooManyAttempts()
	}
	u, err := h.d.Store.GetUserByEmail(ctx, email)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	hash := ""
	if u != nil {
		hash = u.PasswordHash
	}
	if !authn.VerifyPassword(req.Body.Password, hash) || u.DisabledAt != nil {
		h.d.Limiter.Fail(email, ip)
		id := ""
		if u != nil {
			id = u.ID
		}
		fail(id, "invalid_credentials", audit.Denied)
		return nil, invalidCredentials()
	}
	mfa, err := h.MFAState(ctx, u.ID)
	if err != nil {
		return nil, err
	}
	satisfied := !mfa.Any() && !h.d.Config.Auth.RequireMFA
	token := authn.NewWebSessionToken()
	sess := h.newSession(ctx, u.ID, token, store.SessionWeb, satisfied)
	status := gen.LoginResultStatusOk
	switch {
	case mfa.Any():
		status = gen.LoginResultStatusMfaRequired
	case !satisfied:
		status = gen.LoginResultStatusMfaEnrollmentRequired
	}
	err = h.record(ctx, audit.Event{ChainID: store.InstanceChain, ActorKind: audit.ActorUser, ActorID: u.ID,
		Action: "auth.login", TargetKind: "user", TargetID: u.ID, Metadata: map[string]any{"session": sess.PublicID, "status": string(status)}},
		func(ev *store.AuditEvent) error { return h.d.Store.CreateSession(ctx, sess, ev) })
	if err != nil {
		return nil, err
	}
	h.setSessionCookie(ctx, token, sess.ExpiresAt)
	res := gen.LoginResult{Status: status, User: ptr(userJSON(u))}
	if status == gen.LoginResultStatusMfaRequired {
		res.MfaMethods = ptr(mfa.methods())
	}
	return gen.Login200JSONResponse(res), nil
}

// pendingUser returns the user of a session that still owes a second
// factor; an already satisfied session is returned with done = true.
func (h *Handlers) pendingUser(ctx context.Context) (p *authz.Principal, done bool, err error) {
	p = PrincipalFrom(ctx)
	if p == nil || p.Kind != authz.KindUser || p.Session == nil {
		return nil, false, errUnauthorized()
	}
	if h.d.Limiter.Account.Blocked("mfa:" + p.ID) {
		return nil, false, tooManyAttempts()
	}
	return p, p.Session.MFASatisfied, nil
}

func (h *Handlers) loginOK(p *authz.Principal) gen.LoginResult {
	return gen.LoginResult{Status: gen.LoginResultStatusOk, User: ptr(userJSON(p.User))}
}

// satisfy marks the current session MFA-satisfied with its full lifetime
// and re-issues the web cookie to match.
func (h *Handlers) satisfy(ctx context.Context, p *authz.Principal, method string) error {
	expires := p.Session.CreatedAt.Add(h.d.Sessions.Max)
	err := h.record(ctx, audit.Event{ChainID: store.InstanceChain, ActorKind: audit.ActorUser, ActorID: p.ID,
		Action: "auth.mfa.verify", TargetKind: "user", TargetID: p.ID, Metadata: map[string]any{"method": method, "session": p.Session.PublicID}},
		func(ev *store.AuditEvent) error {
			return h.d.Store.SatisfySessionMFA(ctx, p.Session.IDHash, expires, ev)
		})
	if err != nil {
		return err
	}
	// The cookie was set with the short pre-MFA expiry; re-issue it with the
	// session's full lifetime.
	if tok := MetaFrom(ctx).SessionToken; p.Session.Kind == store.SessionWeb && tok != "" {
		h.setSessionCookie(ctx, tok, expires)
	}
	return nil
}

func (h *Handlers) mfaFailed(ctx context.Context, p *authz.Principal, method string) error {
	h.d.Limiter.Account.Fail("mfa:" + p.ID)
	h.recordQuiet(ctx, audit.Event{ChainID: store.InstanceChain, ActorKind: audit.ActorUser, ActorID: p.ID,
		Action: "auth.mfa.failed", Result: audit.Denied, TargetKind: "user", TargetID: p.ID, Metadata: map[string]any{"method": method}})
	return problem(http.StatusUnauthorized, "invalid_credentials", "the code is wrong")
}

func (h *Handlers) VerifyTotp(ctx context.Context, req gen.VerifyTotpRequestObject) (gen.VerifyTotpResponseObject, error) {
	p, done, err := h.pendingUser(ctx)
	if err != nil {
		return nil, err
	}
	if done {
		return gen.VerifyTotp200JSONResponse(h.loginOK(p)), nil
	}
	if req.Body == nil {
		return nil, errInvalid("code", "enter the code")
	}
	t, err := h.d.Store.GetTOTP(ctx, p.ID)
	if errors.Is(err, store.ErrNotFound) || (err == nil && t.ConfirmedAt == nil) {
		return nil, errConflict("no authenticator app is enrolled")
	}
	if err != nil {
		return nil, err
	}
	secret, err := h.d.Keys.DecryptTOTP(ctx, p.ID, t.SecretCiphertext)
	if err != nil {
		return nil, err
	}
	ok := h.d.TOTP.Verify(p.ID, string(secret), req.Body.Code)
	clear(secret)
	if !ok {
		return nil, h.mfaFailed(ctx, p, "totp")
	}
	if err := h.satisfy(ctx, p, "totp"); err != nil {
		return nil, err
	}
	return gen.VerifyTotp200JSONResponse(h.loginOK(p)), nil
}

func (h *Handlers) VerifyRecoveryCode(ctx context.Context, req gen.VerifyRecoveryCodeRequestObject) (gen.VerifyRecoveryCodeResponseObject, error) {
	p, done, err := h.pendingUser(ctx)
	if err != nil {
		return nil, err
	}
	if done {
		return gen.VerifyRecoveryCode200JSONResponse(h.loginOK(p)), nil
	}
	if req.Body == nil {
		return nil, errInvalid("code", "enter a recovery code")
	}
	codes, err := h.d.Store.ListUnusedRecoveryCodes(ctx, p.ID)
	if err != nil {
		return nil, err
	}
	norm := authn.NormalizeRecoveryCode(req.Body.Code)
	for _, c := range codes {
		if ok, _ := authn.VerifyHash(norm, c.CodeHash); !ok {
			continue
		}
		err := h.record(ctx, audit.Event{ChainID: store.InstanceChain, ActorKind: audit.ActorUser, ActorID: p.ID,
			Action: "auth.recovery_code.used", TargetKind: "user", TargetID: p.ID, Metadata: map[string]any{"remaining": len(codes) - 1}},
			func(ev *store.AuditEvent) error { return h.d.Store.UseRecoveryCode(ctx, c.ID, h.now(), ev) })
		if err != nil {
			return nil, err
		}
		if err := h.satisfy(ctx, p, "recovery_code"); err != nil {
			return nil, err
		}
		return gen.VerifyRecoveryCode200JSONResponse(h.loginOK(p)), nil
	}
	return nil, h.mfaFailed(ctx, p, "recovery_code")
}

func webauthnOrigin(ctx context.Context) authn.Origin {
	m := MetaFrom(ctx)
	return authn.Origin{Origin: m.Origin, Host: m.Host}
}

func (h *Handlers) BeginWebauthnLogin(ctx context.Context, _ gen.BeginWebauthnLoginRequestObject) (gen.BeginWebauthnLoginResponseObject, error) {
	p, _, err := h.pendingUser(ctx)
	if err != nil {
		return nil, err
	}
	creds, err := h.d.Store.ListWebAuthnCredentials(ctx, p.ID)
	if err != nil {
		return nil, err
	}
	opts, err := h.d.WebAuthn.BeginLogin(webauthnOrigin(ctx), p.Session.IDHash, p.User, creds)
	if err != nil {
		return nil, errConflict(err.Error())
	}
	return gen.BeginWebauthnLogin200JSONResponse{Options: toJSONObject(opts)}, nil
}

func toJSONObject(v any) gen.JsonObject {
	b, _ := json.Marshal(v)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	return m
}

func (h *Handlers) FinishWebauthnLogin(ctx context.Context, req gen.FinishWebauthnLoginRequestObject) (gen.FinishWebauthnLoginResponseObject, error) {
	p, done, err := h.pendingUser(ctx)
	if err != nil {
		return nil, err
	}
	if done {
		return gen.FinishWebauthnLogin200JSONResponse(h.loginOK(p)), nil
	}
	if req.Body == nil {
		return nil, errInvalid("credential", "the passkey response is missing")
	}
	creds, err := h.d.Store.ListWebAuthnCredentials(ctx, p.ID)
	if err != nil {
		return nil, err
	}
	raw, _ := json.Marshal(req.Body.Credential)
	cred, err := h.d.WebAuthn.FinishLogin(webauthnOrigin(ctx), p.Session.IDHash, p.User, creds, raw)
	if err != nil {
		return nil, h.mfaFailed(ctx, p, "webauthn")
	}
	for _, c := range creds {
		if string(c.CredentialID) == string(cred.ID) {
			sc, _ := authn.StoredCredential(cred)
			_ = h.d.Store.UpdateWebAuthnCredentialUse(ctx, c.ID, sc.SignCount, sc.Data, h.now())
		}
	}
	if err := h.satisfy(ctx, p, "webauthn"); err != nil {
		return nil, err
	}
	return gen.FinishWebauthnLogin200JSONResponse(h.loginOK(p)), nil
}

func (h *Handlers) Logout(ctx context.Context, _ gen.LogoutRequestObject) (gen.LogoutResponseObject, error) {
	p := PrincipalFrom(ctx)
	h.clearSessionCookie(ctx)
	if p == nil || p.Session == nil {
		return gen.Logout204Response{}, nil
	}
	err := h.record(ctx, audit.Event{ChainID: store.InstanceChain, ActorKind: audit.ActorUser, ActorID: p.ID,
		Action: "auth.logout", TargetKind: "session", TargetID: p.Session.PublicID},
		func(ev *store.AuditEvent) error { return h.d.Store.DeleteSessionByHash(ctx, p.Session.IDHash, ev) })
	if err != nil {
		return nil, err
	}
	return gen.Logout204Response{}, nil
}

// ---- password reset (core 7.2) ----

// ResetLinkTTL is how long a password reset link works.
const ResetLinkTTL = time.Hour

func (h *Handlers) createResetLink(ctx context.Context, actor *authz.Principal, chainID string, target *store.User) (gen.OneTimeLink, error) {
	tok := ids.RandomToken(32)
	now := h.now()
	r := store.PasswordReset{ID: ids.New(), UserID: target.ID, TokenHash: ids.HashToken(tok), ExpiresAt: now.Add(ResetLinkTTL),
		CreatedBy: actor.ID, CreatedAt: now}
	err := h.record(ctx, audit.Event{ChainID: chainID, ActorKind: audit.ActorUser, ActorID: actor.ID,
		Action: "user.password_reset.create", TargetKind: "user", TargetID: target.ID, Metadata: map[string]any{"email": target.Email}},
		func(ev *store.AuditEvent) error { return h.d.Store.CreatePasswordReset(ctx, r, ev) })
	if err != nil {
		return gen.OneTimeLink{}, err
	}
	return gen.OneTimeLink{Token: tok, Url: h.baseURL(ctx) + "/reset-password/" + tok, ExpiresAt: r.ExpiresAt}, nil
}

func (h *Handlers) ResetPassword(ctx context.Context, req gen.ResetPasswordRequestObject) (gen.ResetPasswordResponseObject, error) {
	if req.Body == nil {
		return nil, errInvalid("body", "a JSON body is required")
	}
	ip := MetaFrom(ctx).IP
	if h.d.Limiter.IP.Blocked("reset:" + ip) {
		return nil, tooManyAttempts()
	}
	r, err := h.d.Store.GetPasswordResetByHash(ctx, ids.HashToken(req.Body.Token))
	if errors.Is(err, store.ErrNotFound) || (err == nil && (r.UsedAt != nil || !h.now().Before(r.ExpiresAt))) {
		h.d.Limiter.IP.Fail("reset:" + ip)
		return nil, problem(http.StatusBadRequest, "invalid_token", "the reset link is invalid, used, or expired; ask for a new one")
	}
	if err != nil {
		return nil, err
	}
	if err := authn.ValidatePassword(req.Body.NewPassword); err != nil {
		return nil, errInvalid("new_password", err.Error())
	}
	hash, err := authn.HashPassword(req.Body.NewPassword)
	if err != nil {
		return nil, err
	}
	err = h.record(ctx, audit.Event{ChainID: store.InstanceChain, ActorKind: audit.ActorUser, ActorID: r.UserID,
		Action: "user.password_reset.use", TargetKind: "user", TargetID: r.UserID},
		func(ev *store.AuditEvent) error {
			return h.d.Store.UsePasswordReset(ctx, r.ID, r.UserID, hash, h.now(), ev)
		})
	if err != nil {
		return nil, err
	}
	return gen.ResetPassword204Response{}, nil
}
