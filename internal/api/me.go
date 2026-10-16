package api

import (
	"context"
	"encoding/json"
	"errors"
	"slices"

	"github.com/x6c-co/rypt-store/internal/api/gen"
	"github.com/x6c-co/rypt-store/internal/audit"
	"github.com/x6c-co/rypt-store/internal/authn"
	"github.com/x6c-co/rypt-store/internal/authz"
	"github.com/x6c-co/rypt-store/internal/ids"
	"github.com/x6c-co/rypt-store/internal/store"
)

func (h *Handlers) GetMe(ctx context.Context, _ gen.GetMeRequestObject) (gen.GetMeResponseObject, error) {
	p := PrincipalFrom(ctx)
	if p == nil {
		return nil, errUnauthorized()
	}
	notices := h.notices()
	if p.Kind == authz.KindServiceToken {
		t := p.Scope.Token
		ten, err := h.d.Store.GetTenant(ctx, t.TenantID)
		if err != nil {
			return nil, err
		}
		proj, err := h.d.Store.GetProject(ctx, t.TenantID, t.ProjectID)
		if err != nil {
			return nil, err
		}
		envs, err := h.d.Store.ListEnvironments(ctx, t.TenantID, t.ProjectID)
		if err != nil {
			return nil, err
		}
		var slugs []string
		for _, e := range envs {
			if slices.Contains(t.EnvironmentIDs, e.ID) {
				slugs = append(slugs, e.Slug)
			}
		}
		return gen.GetMe200JSONResponse{PrincipalKind: gen.MePrincipalKindServiceToken, Notices: &notices,
			Token: &gen.TokenScope{Id: t.ID, Name: t.Name, Tenant: ten.Slug, Project: proj.Slug, Environments: slugs,
				Permission: gen.TokenPermission(t.Permission), ExpiresAt: t.ExpiresAt}}, nil
	}
	tenants, err := h.d.Store.ListTenantsForUser(ctx, p.ID)
	if err != nil {
		return nil, err
	}
	ts := make([]gen.Tenant, 0, len(tenants))
	for _, t := range tenants {
		ts = append(ts, tenantJSON(t.Tenant, t.Role))
	}
	mfa, err := h.MFAState(ctx, p.ID)
	if err != nil {
		return nil, err
	}
	sess := sessionJSON(*p.Session, p.Session.IDHash)
	return gen.GetMe200JSONResponse{
		PrincipalKind: gen.MePrincipalKindUser, User: ptr(userJSON(p.User)), Tenants: &ts, Session: &sess, Notices: &notices,
		Mfa: &gen.MfaStatus{Totp: mfa.TOTP, Passkeys: mfa.Passkeys, RecoveryCodesRemaining: mfa.Codes, Required: h.d.Config.Auth.RequireMFA},
	}, nil
}

func (h *Handlers) notices() gen.Notices {
	st := h.d.Keys.Status()
	n := gen.Notices{LocalProvider: st.Current == "local", SelfSignedTls: h.d.Config.EffectiveTLSMode() == "self_signed"}
	if st.ProviderDown[st.Current] {
		n.ProviderUnavailable = ptr(true)
	}
	if q := st.QuotaExceeded; q != nil {
		n.ProviderQuota = quotaJSON(st)
	}
	return n
}

func sessionJSON(s store.Session, currentHash string) gen.SessionInfo {
	return gen.SessionInfo{Id: s.PublicID, Kind: gen.SessionInfoKind(s.Kind), CreatedAt: s.CreatedAt, LastSeenAt: s.LastSeenAt,
		ExpiresAt: s.ExpiresAt, Ip: strPtr(s.IP), UserAgent: strPtr(s.UserAgent), Current: s.IDHash == currentHash, MfaSatisfied: s.MFASatisfied}
}

func (h *Handlers) ChangePassword(ctx context.Context, req gen.ChangePasswordRequestObject) (gen.ChangePasswordResponseObject, error) {
	p, err := signedInUser(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, errInvalid("body", "a JSON body is required")
	}
	if h.d.Limiter.Account.Blocked("pw:" + p.ID) {
		return nil, tooManyAttempts()
	}
	if !authn.VerifyPassword(req.Body.CurrentPassword, p.User.PasswordHash) {
		h.d.Limiter.Account.Fail("pw:" + p.ID)
		return nil, errInvalid("current_password", "the current password is wrong")
	}
	if err := authn.ValidatePassword(req.Body.NewPassword); err != nil {
		return nil, errInvalid("new_password", err.Error())
	}
	hash, err := authn.HashPassword(req.Body.NewPassword)
	if err != nil {
		return nil, err
	}
	err = h.record(ctx, audit.Event{ChainID: store.InstanceChain, ActorKind: audit.ActorUser, ActorID: p.ID,
		Action: "user.password.change", TargetKind: "user", TargetID: p.ID},
		func(ev *store.AuditEvent) error { return h.d.Store.UpdateUserPassword(ctx, p.ID, hash, h.now(), ev) })
	if err != nil {
		return nil, err
	}
	return gen.ChangePassword204Response{}, nil
}

func (h *Handlers) ListMySessions(ctx context.Context, _ gen.ListMySessionsRequestObject) (gen.ListMySessionsResponseObject, error) {
	p, err := signedInUser(ctx)
	if err != nil {
		return nil, err
	}
	ss, err := h.d.Store.ListSessions(ctx, p.ID)
	if err != nil {
		return nil, err
	}
	out := make([]gen.SessionInfo, 0, len(ss))
	for _, s := range ss {
		if h.d.Sessions.Valid(&s) {
			out = append(out, sessionJSON(s, p.Session.IDHash))
		}
	}
	return gen.ListMySessions200JSONResponse{Sessions: out}, nil
}

func (h *Handlers) RevokeMySession(ctx context.Context, req gen.RevokeMySessionRequestObject) (gen.RevokeMySessionResponseObject, error) {
	p, err := signedInUser(ctx)
	if err != nil {
		return nil, err
	}
	err = h.record(ctx, audit.Event{ChainID: store.InstanceChain, ActorKind: audit.ActorUser, ActorID: p.ID,
		Action: "session.revoke", TargetKind: "session", TargetID: req.Id},
		func(ev *store.AuditEvent) error { return h.d.Store.DeleteSession(ctx, p.ID, req.Id, ev) })
	if errors.Is(err, store.ErrNotFound) {
		return nil, errNotFound("session")
	}
	if err != nil {
		return nil, err
	}
	if req.Id == p.Session.PublicID {
		h.clearSessionCookie(ctx)
	}
	return gen.RevokeMySession204Response{}, nil
}

// ---- MFA enrollment ----

// enrollingUser returns the user for an enrollment endpoint. A session that
// still owes a second factor may enroll only when the user has none, so a
// stolen password cannot add a factor to an account that has one.
func (h *Handlers) enrollingUser(ctx context.Context) (*authz.Principal, MFAStatus, error) {
	p, err := signedInUser(ctx)
	if err != nil {
		return nil, MFAStatus{}, err
	}
	mfa, err := h.MFAState(ctx, p.ID)
	if err != nil {
		return nil, mfa, err
	}
	if !p.Session.MFASatisfied && mfa.Any() {
		return nil, mfa, problem(403, "mfa_required", "verify your second factor first")
	}
	return p, mfa, nil
}

// afterEnrollment satisfies a pending session: enrolling proved possession.
func (h *Handlers) afterEnrollment(ctx context.Context, p *authz.Principal, method string) error {
	if p.Session.MFASatisfied {
		return nil
	}
	return h.satisfy(ctx, p, method+"_enrollment")
}

func (h *Handlers) BeginTotpEnrollment(ctx context.Context, _ gen.BeginTotpEnrollmentRequestObject) (gen.BeginTotpEnrollmentResponseObject, error) {
	p, mfa, err := h.enrollingUser(ctx)
	if err != nil {
		return nil, err
	}
	if mfa.TOTP {
		return nil, errConflict("an authenticator app is already enrolled; remove it first")
	}
	secret, url, err := authn.NewTOTPSecret("rypt-store", p.User.Email)
	if err != nil {
		return nil, err
	}
	ct, err := h.d.Keys.EncryptTOTP(ctx, p.ID, []byte(secret))
	if err != nil {
		return nil, err
	}
	if err := h.d.Store.PutPendingTOTP(ctx, store.TOTP{UserID: p.ID, SecretCiphertext: ct}); err != nil {
		return nil, err
	}
	return gen.BeginTotpEnrollment200JSONResponse{Secret: secret, OtpauthUrl: url}, nil
}

func (h *Handlers) ConfirmTotpEnrollment(ctx context.Context, req gen.ConfirmTotpEnrollmentRequestObject) (gen.ConfirmTotpEnrollmentResponseObject, error) {
	p, mfa, err := h.enrollingUser(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, errInvalid("code", "enter the code")
	}
	t, err := h.d.Store.GetTOTP(ctx, p.ID)
	if errors.Is(err, store.ErrNotFound) || (err == nil && t.ConfirmedAt != nil) {
		return nil, errConflict("start enrollment first")
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
		return nil, errInvalid("code", "the code does not match; check the app's clock and try again")
	}
	// Recovery codes are issued at the first MFA enrollment (core 7.2).
	var codes []string
	var recs []store.RecoveryCode
	if !mfa.Any() {
		if codes, recs, err = newRecoveryCodes(p.ID); err != nil {
			return nil, err
		}
	}
	err = h.record(ctx, audit.Event{ChainID: store.InstanceChain, ActorKind: audit.ActorUser, ActorID: p.ID,
		Action: "mfa.TOTP.enroll", TargetKind: "user", TargetID: p.ID},
		func(ev *store.AuditEvent) error { return h.d.Store.ConfirmTOTP(ctx, p.ID, h.now(), recs, ev) })
	if err != nil {
		return nil, err
	}
	if err := h.afterEnrollment(ctx, p, "totp"); err != nil {
		return nil, err
	}
	if codes == nil {
		codes = []string{}
	}
	return gen.ConfirmTotpEnrollment200JSONResponse{RecoveryCodes: codes}, nil
}

// requireSatisfied refuses a session that owes its second factor.
func requireSatisfied(p *authz.Principal) error {
	if !p.Session.MFASatisfied {
		return problem(403, "mfa_required", "verify your second factor first")
	}
	return nil
}

func (h *Handlers) RemoveTotp(ctx context.Context, _ gen.RemoveTotpRequestObject) (gen.RemoveTotpResponseObject, error) {
	p, err := signedInUser(ctx)
	if err != nil {
		return nil, err
	}
	if err := requireSatisfied(p); err != nil {
		return nil, err
	}
	mfa, err := h.MFAState(ctx, p.ID)
	if err != nil {
		return nil, err
	}
	if h.d.Config.Auth.RequireMFA && mfa.Passkeys == 0 && mfa.TOTP {
		return nil, errConflict("MFA is required: add a passkey before removing the authenticator app")
	}
	err = h.record(ctx, audit.Event{ChainID: store.InstanceChain, ActorKind: audit.ActorUser, ActorID: p.ID,
		Action: "mfa.TOTP.remove", TargetKind: "user", TargetID: p.ID},
		func(ev *store.AuditEvent) error { return h.d.Store.DeleteTOTP(ctx, p.ID, ev) })
	if errors.Is(err, store.ErrNotFound) {
		return nil, errNotFound("authenticator app")
	}
	if err != nil {
		return nil, err
	}
	return gen.RemoveTotp204Response{}, nil
}

func (h *Handlers) ListPasskeys(ctx context.Context, _ gen.ListPasskeysRequestObject) (gen.ListPasskeysResponseObject, error) {
	p, err := signedInUser(ctx)
	if err != nil {
		return nil, err
	}
	creds, err := h.d.Store.ListWebAuthnCredentials(ctx, p.ID)
	if err != nil {
		return nil, err
	}
	out := make([]gen.Passkey, 0, len(creds))
	for _, c := range creds {
		out = append(out, gen.Passkey{Id: c.ID, Name: c.Name, CreatedAt: c.CreatedAt, LastUsedAt: c.LastUsedAt})
	}
	return gen.ListPasskeys200JSONResponse{Passkeys: out}, nil
}

func (h *Handlers) BeginPasskeyRegistration(ctx context.Context, _ gen.BeginPasskeyRegistrationRequestObject) (gen.BeginPasskeyRegistrationResponseObject, error) {
	p, _, err := h.enrollingUser(ctx)
	if err != nil {
		return nil, err
	}
	creds, err := h.d.Store.ListWebAuthnCredentials(ctx, p.ID)
	if err != nil {
		return nil, err
	}
	opts, err := h.d.WebAuthn.BeginRegistration(webauthnOrigin(ctx), p.Session.IDHash, p.User, creds)
	if err != nil {
		return nil, errConflict(err.Error())
	}
	return gen.BeginPasskeyRegistration200JSONResponse{Options: toJSONObject(opts)}, nil
}

func (h *Handlers) FinishPasskeyRegistration(ctx context.Context, req gen.FinishPasskeyRegistrationRequestObject) (gen.FinishPasskeyRegistrationResponseObject, error) {
	p, mfa, err := h.enrollingUser(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil || req.Body.Name == "" || len(req.Body.Name) > 64 {
		return nil, errInvalid("name", "name the passkey (at most 64 characters)")
	}
	creds, err := h.d.Store.ListWebAuthnCredentials(ctx, p.ID)
	if err != nil {
		return nil, err
	}
	raw, _ := json.Marshal(req.Body.Credential)
	cred, err := h.d.WebAuthn.FinishRegistration(webauthnOrigin(ctx), p.Session.IDHash, p.User, creds, raw)
	if err != nil {
		return nil, errInvalid("credential", "the passkey could not be verified: "+err.Error())
	}
	sc, err := authn.StoredCredential(cred)
	if err != nil {
		return nil, err
	}
	sc.ID, sc.UserID, sc.Name, sc.CreatedAt = ids.New(), p.ID, req.Body.Name, h.now()
	var codes []string
	var recs []store.RecoveryCode
	if !mfa.Any() {
		if codes, recs, err = newRecoveryCodes(p.ID); err != nil {
			return nil, err
		}
	}
	err = h.record(ctx, audit.Event{ChainID: store.InstanceChain, ActorKind: audit.ActorUser, ActorID: p.ID,
		Action: "mfa.webauthn.enroll", TargetKind: "passkey", TargetID: sc.ID, Metadata: map[string]any{"name": sc.Name}},
		func(ev *store.AuditEvent) error { return h.d.Store.CreateWebAuthnCredential(ctx, sc, recs, ev) })
	if err != nil {
		return nil, err
	}
	if err := h.afterEnrollment(ctx, p, "webauthn"); err != nil {
		return nil, err
	}
	if codes == nil {
		codes = []string{}
	}
	return gen.FinishPasskeyRegistration200JSONResponse{RecoveryCodes: codes}, nil
}

func (h *Handlers) RemovePasskey(ctx context.Context, req gen.RemovePasskeyRequestObject) (gen.RemovePasskeyResponseObject, error) {
	p, err := signedInUser(ctx)
	if err != nil {
		return nil, err
	}
	if err := requireSatisfied(p); err != nil {
		return nil, err
	}
	mfa, err := h.MFAState(ctx, p.ID)
	if err != nil {
		return nil, err
	}
	if h.d.Config.Auth.RequireMFA && !mfa.TOTP && mfa.Passkeys <= 1 {
		return nil, errConflict("MFA is required: keep at least one second factor")
	}
	err = h.record(ctx, audit.Event{ChainID: store.InstanceChain, ActorKind: audit.ActorUser, ActorID: p.ID,
		Action: "mfa.webauthn.remove", TargetKind: "passkey", TargetID: req.Id},
		func(ev *store.AuditEvent) error { return h.d.Store.DeleteWebAuthnCredential(ctx, p.ID, req.Id, ev) })
	if errors.Is(err, store.ErrNotFound) {
		return nil, errNotFound("passkey")
	}
	if err != nil {
		return nil, err
	}
	return gen.RemovePasskey204Response{}, nil
}

func (h *Handlers) RegenerateRecoveryCodes(ctx context.Context, _ gen.RegenerateRecoveryCodesRequestObject) (gen.RegenerateRecoveryCodesResponseObject, error) {
	p, err := signedInUser(ctx)
	if err != nil {
		return nil, err
	}
	if err := requireSatisfied(p); err != nil {
		return nil, err
	}
	mfa, err := h.MFAState(ctx, p.ID)
	if err != nil {
		return nil, err
	}
	if !mfa.Any() {
		return nil, errConflict("enroll an authenticator app or a passkey first")
	}
	codes, recs, err := newRecoveryCodes(p.ID)
	if err != nil {
		return nil, err
	}
	err = h.record(ctx, audit.Event{ChainID: store.InstanceChain, ActorKind: audit.ActorUser, ActorID: p.ID,
		Action: "mfa.recovery_codes.regenerate", TargetKind: "user", TargetID: p.ID},
		func(ev *store.AuditEvent) error { return h.d.Store.ReplaceRecoveryCodes(ctx, p.ID, recs, ev) })
	if err != nil {
		return nil, err
	}
	return gen.RegenerateRecoveryCodes200JSONResponse{RecoveryCodes: codes}, nil
}
