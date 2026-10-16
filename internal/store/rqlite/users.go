package rqlite

import (
	"context"
	"time"

	"github.com/x6c-co/rypt-store/internal/store"
)

// ---- instance ----

func (s *Store) GetInstance(ctx context.Context) (*store.Instance, error) {
	var i store.Instance
	err := s.queryOne(ctx, store.Strong,
		"SELECT id, created_at, setup_completed_at, setup_token_hash, setup_token_expires_at FROM instance", nil,
		&i.ID, &i.CreatedAt, &i.SetupCompletedAt, &i.SetupTokenHash, &i.SetupTokenExpiresAt)
	if err != nil {
		return nil, err
	}
	return &i, nil
}

func (s *Store) CreateInstance(ctx context.Context, inst store.Instance, ik store.KeyWrap) error {
	var b batch
	b.add("INSERT INTO instance (id, created_at) VALUES (?, ?)", inst.ID, inst.CreatedAt)
	b.addAll(insertWrapStmt(ik))
	b.add("INSERT INTO audit_chains (chain_id, head_seq, head_hash, anchor_seq, anchor_hash, updated_at) VALUES (?, 0, ?, 0, ?, ?)",
		store.InstanceChain, zeroHash, zeroHash, inst.CreatedAt)
	return s.execBatch(ctx, b)
}

// zeroHash is prev_hash for seq 1 (core 8.1).
const zeroHash = "0000000000000000000000000000000000000000000000000000000000000000"

func (s *Store) SetSetupToken(ctx context.Context, hash string, expiresAt time.Time) error {
	_, err := s.exec(ctx, st("UPDATE instance SET setup_token_hash = ?, setup_token_expires_at = ? WHERE setup_completed_at IS NULL", hash, expiresAt))
	return err
}

func (s *Store) CompleteSetup(ctx context.Context, p store.CompleteSetupParams, ev *store.AuditEvent) error {
	var b batch
	b.audit(ev)
	b.guard(store.Conflict("setup already completed"), "SELECT COUNT(*) FROM instance WHERE setup_completed_at IS NULL")
	b.add("UPDATE instance SET setup_completed_at = ?, setup_token_hash = NULL, setup_token_expires_at = NULL", p.CompletedAt)
	b.addAll(insertUserStmt(p.Admin))
	b.addAll(insertTenantStmts(p.Tenant)...)
	b.add("INSERT INTO tenant_memberships (tenant_id, user_id, role, created_at) VALUES (?, ?, 'owner', ?)",
		p.Tenant.ID, p.Admin.ID, p.CompletedAt)
	if p.TOTP != nil {
		b.add("INSERT INTO user_totp (user_id, secret_ciphertext, confirmed_at) VALUES (?, ?, ?)",
			p.TOTP.UserID, p.TOTP.SecretCiphertext, p.TOTP.ConfirmedAt)
	}
	for _, c := range p.RecoveryCodes {
		b.add("INSERT INTO user_recovery_codes (id, user_id, code_hash) VALUES (?, ?, ?)", c.ID, c.UserID, c.CodeHash)
	}
	if p.Session != nil {
		b.addAll(insertSessionStmt(*p.Session))
	}
	return s.execBatch(ctx, b)
}

// ---- users ----

const userCols = "id, email, display_name, password_hash, is_instance_admin, disabled_at, created_at, updated_at"

func scanUser(r *rows) (*store.User, error) {
	var u store.User
	err := r.scan(&u.ID, &u.Email, &u.DisplayName, &u.PasswordHash, &u.IsInstanceAdmin, &u.DisabledAt, &u.CreatedAt, &u.UpdatedAt)
	return &u, err
}

func insertUserStmt(u store.User) stmt {
	return st("INSERT INTO users ("+userCols+") VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
		u.ID, u.Email, u.DisplayName, u.PasswordHash, u.IsInstanceAdmin, u.DisabledAt, u.CreatedAt, u.UpdatedAt)
}

func (s *Store) getUser(ctx context.Context, where string, arg any) (*store.User, error) {
	r, err := s.query(ctx, store.Strong, "SELECT "+userCols+" FROM users WHERE "+where, arg)
	if err != nil {
		return nil, err
	}
	if !r.next() {
		return nil, store.ErrNotFound
	}
	return scanUser(r)
}

func (s *Store) GetUser(ctx context.Context, id string) (*store.User, error) {
	return s.getUser(ctx, "id = ?", id)
}

func (s *Store) GetUserByEmail(ctx context.Context, email string) (*store.User, error) {
	return s.getUser(ctx, "email = ?", email)
}

func (s *Store) UpdateUserPassword(ctx context.Context, userID, hash string, at time.Time, ev *store.AuditEvent) error {
	var b batch
	b.audit(ev)
	b.guard(store.ErrNotFound, "SELECT COUNT(*) FROM users WHERE id = ?", userID)
	b.add("UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?", hash, at, userID)
	return s.execBatch(ctx, b)
}

// ---- TOTP and recovery codes ----

func (s *Store) GetTOTP(ctx context.Context, userID string) (*store.TOTP, error) {
	var t store.TOTP
	err := s.queryOne(ctx, store.Strong, "SELECT user_id, secret_ciphertext, confirmed_at FROM user_totp WHERE user_id = ?",
		[]any{userID}, &t.UserID, &t.SecretCiphertext, &t.ConfirmedAt)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

func (s *Store) PutPendingTOTP(ctx context.Context, t store.TOTP) error {
	var b batch
	b.guard(store.Conflict("TOTP is already enrolled"),
		"SELECT CASE WHEN COUNT(*) = 0 THEN 1 ELSE 0 END FROM user_totp WHERE user_id = ? AND confirmed_at IS NOT NULL", t.UserID)
	b.add("DELETE FROM user_totp WHERE user_id = ?", t.UserID)
	b.add("INSERT INTO user_totp (user_id, secret_ciphertext, confirmed_at) VALUES (?, ?, NULL)", t.UserID, t.SecretCiphertext)
	return s.execBatch(ctx, b)
}

func (s *Store) ConfirmTOTP(ctx context.Context, userID string, at time.Time, codes []store.RecoveryCode, ev *store.AuditEvent) error {
	var b batch
	b.audit(ev)
	b.guard(store.Conflict("no pending TOTP enrollment"),
		"SELECT COUNT(*) FROM user_totp WHERE user_id = ? AND confirmed_at IS NULL", userID)
	b.add("UPDATE user_totp SET confirmed_at = ? WHERE user_id = ?", at, userID)
	if codes != nil {
		b.addAll(replaceCodesStmts(userID, codes)...)
	}
	return s.execBatch(ctx, b)
}

func (s *Store) DeleteTOTP(ctx context.Context, userID string, ev *store.AuditEvent) error {
	var b batch
	b.audit(ev)
	b.guard(store.ErrNotFound, "SELECT COUNT(*) FROM user_totp WHERE user_id = ?", userID)
	b.add("DELETE FROM user_totp WHERE user_id = ?", userID)
	return s.execBatch(ctx, b)
}

func replaceCodesStmts(userID string, codes []store.RecoveryCode) []stmt {
	out := []stmt{st("DELETE FROM user_recovery_codes WHERE user_id = ?", userID)}
	for _, c := range codes {
		out = append(out, st("INSERT INTO user_recovery_codes (id, user_id, code_hash) VALUES (?, ?, ?)", c.ID, userID, c.CodeHash))
	}
	return out
}

func (s *Store) ListUnusedRecoveryCodes(ctx context.Context, userID string) ([]store.RecoveryCode, error) {
	r, err := s.query(ctx, store.Strong, "SELECT id, user_id, code_hash, used_at FROM user_recovery_codes WHERE user_id = ? AND used_at IS NULL", userID)
	if err != nil {
		return nil, err
	}
	var out []store.RecoveryCode
	for r.next() {
		var c store.RecoveryCode
		if err := r.scan(&c.ID, &c.UserID, &c.CodeHash, &c.UsedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

func (s *Store) CountRecoveryCodes(ctx context.Context, userID string) (int, error) {
	return s.count(ctx, store.Weak, "SELECT COUNT(*) FROM user_recovery_codes WHERE user_id = ? AND used_at IS NULL", userID)
}

func (s *Store) UseRecoveryCode(ctx context.Context, id string, at time.Time, ev *store.AuditEvent) error {
	var b batch
	b.audit(ev)
	b.guard(store.Conflict("recovery code already used"), "SELECT COUNT(*) FROM user_recovery_codes WHERE id = ? AND used_at IS NULL", id)
	b.add("UPDATE user_recovery_codes SET used_at = ? WHERE id = ?", at, id)
	return s.execBatch(ctx, b)
}

func (s *Store) ReplaceRecoveryCodes(ctx context.Context, userID string, codes []store.RecoveryCode, ev *store.AuditEvent) error {
	var b batch
	b.audit(ev)
	b.addAll(replaceCodesStmts(userID, codes)...)
	return s.execBatch(ctx, b)
}

// ---- WebAuthn ----

const webauthnCols = "id, user_id, credential_id, public_key, sign_count, transports, name, data, created_at, last_used_at"

func (s *Store) ListWebAuthnCredentials(ctx context.Context, userID string) ([]store.WebAuthnCredential, error) {
	r, err := s.query(ctx, store.Strong, "SELECT "+webauthnCols+" FROM webauthn_credentials WHERE user_id = ? ORDER BY created_at", userID)
	if err != nil {
		return nil, err
	}
	var out []store.WebAuthnCredential
	for r.next() {
		var c store.WebAuthnCredential
		if err := r.scan(&c.ID, &c.UserID, &c.CredentialID, &c.PublicKey, &c.SignCount, &c.Transports, &c.Name, &c.Data, &c.CreatedAt, &c.LastUsedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

func (s *Store) CreateWebAuthnCredential(ctx context.Context, c store.WebAuthnCredential, codes []store.RecoveryCode, ev *store.AuditEvent) error {
	var b batch
	b.audit(ev)
	b.add("INSERT INTO webauthn_credentials ("+webauthnCols+") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
		c.ID, c.UserID, c.CredentialID, c.PublicKey, c.SignCount, c.Transports, c.Name, c.Data, c.CreatedAt, c.LastUsedAt)
	if codes != nil {
		b.addAll(replaceCodesStmts(c.UserID, codes)...)
	}
	return s.execBatch(ctx, b)
}

func (s *Store) UpdateWebAuthnCredentialUse(ctx context.Context, id string, signCount int64, data string, at time.Time) error {
	_, err := s.exec(ctx, st("UPDATE webauthn_credentials SET sign_count = ?, data = ?, last_used_at = ? WHERE id = ?", signCount, data, at, id))
	return err
}

func (s *Store) DeleteWebAuthnCredential(ctx context.Context, userID, id string, ev *store.AuditEvent) error {
	var b batch
	b.audit(ev)
	b.guard(store.ErrNotFound, "SELECT COUNT(*) FROM webauthn_credentials WHERE id = ? AND user_id = ?", id, userID)
	b.add("DELETE FROM webauthn_credentials WHERE id = ? AND user_id = ?", id, userID)
	return s.execBatch(ctx, b)
}

// ---- password resets ----

func (s *Store) CreatePasswordReset(ctx context.Context, r store.PasswordReset, ev *store.AuditEvent) error {
	var b batch
	b.audit(ev)
	b.add("INSERT INTO password_resets (id, user_id, token_hash, expires_at, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		r.ID, r.UserID, r.TokenHash, r.ExpiresAt, r.CreatedBy, r.CreatedAt)
	return s.execBatch(ctx, b)
}

func (s *Store) GetPasswordResetByHash(ctx context.Context, tokenHash string) (*store.PasswordReset, error) {
	var r store.PasswordReset
	err := s.queryOne(ctx, store.Strong,
		"SELECT id, user_id, token_hash, expires_at, used_at, created_by, created_at FROM password_resets WHERE token_hash = ?",
		[]any{tokenHash}, &r.ID, &r.UserID, &r.TokenHash, &r.ExpiresAt, &r.UsedAt, &r.CreatedBy, &r.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func (s *Store) UsePasswordReset(ctx context.Context, resetID, userID, passwordHash string, at time.Time, ev *store.AuditEvent) error {
	var b batch
	b.audit(ev)
	b.guard(store.Conflict("reset link already used"), "SELECT COUNT(*) FROM password_resets WHERE id = ? AND used_at IS NULL", resetID)
	b.add("UPDATE password_resets SET used_at = ? WHERE id = ?", at, resetID)
	b.add("UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?", passwordHash, at, userID)
	b.add("DELETE FROM sessions WHERE user_id = ?", userID)
	return s.execBatch(ctx, b)
}

// ---- sessions ----

const sessionCols = "id_hash, public_id, user_id, kind, mfa_satisfied, created_at, expires_at, last_seen_at, ip, user_agent"

func insertSessionStmt(x store.Session) stmt {
	return st("INSERT INTO sessions ("+sessionCols+") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
		x.IDHash, x.PublicID, x.UserID, x.Kind, x.MFASatisfied, x.CreatedAt, x.ExpiresAt, x.LastSeenAt, null(x.IP), null(x.UserAgent))
}

func scanSession(r *rows) (store.Session, error) {
	var x store.Session
	err := r.scan(&x.IDHash, &x.PublicID, &x.UserID, &x.Kind, &x.MFASatisfied, &x.CreatedAt, &x.ExpiresAt, &x.LastSeenAt, &x.IP, &x.UserAgent)
	return x, err
}

func (s *Store) CreateSession(ctx context.Context, x store.Session, ev *store.AuditEvent) error {
	var b batch
	b.audit(ev)
	b.addAll(insertSessionStmt(x))
	return s.execBatch(ctx, b)
}

func (s *Store) GetSession(ctx context.Context, idHash string) (*store.Session, error) {
	r, err := s.query(ctx, store.Strong, "SELECT "+sessionCols+" FROM sessions WHERE id_hash = ?", idHash)
	if err != nil {
		return nil, err
	}
	if !r.next() {
		return nil, store.ErrNotFound
	}
	x, err := scanSession(r)
	return &x, err
}

func (s *Store) TouchSession(ctx context.Context, idHash string, at time.Time) error {
	_, err := s.exec(ctx, st("UPDATE sessions SET last_seen_at = ? WHERE id_hash = ?", at, idHash))
	return err
}

func (s *Store) SatisfySessionMFA(ctx context.Context, idHash string, expiresAt time.Time, ev *store.AuditEvent) error {
	var b batch
	b.audit(ev)
	b.guard(store.ErrNotFound, "SELECT COUNT(*) FROM sessions WHERE id_hash = ?", idHash)
	b.add("UPDATE sessions SET mfa_satisfied = 1, expires_at = ? WHERE id_hash = ?", expiresAt, idHash)
	return s.execBatch(ctx, b)
}

func (s *Store) ListSessions(ctx context.Context, userID string) ([]store.Session, error) {
	r, err := s.query(ctx, store.Weak, "SELECT "+sessionCols+" FROM sessions WHERE user_id = ? ORDER BY last_seen_at DESC", userID)
	if err != nil {
		return nil, err
	}
	var out []store.Session
	for r.next() {
		x, err := scanSession(r)
		if err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, nil
}

func (s *Store) DeleteSession(ctx context.Context, userID, publicID string, ev *store.AuditEvent) error {
	var b batch
	b.audit(ev)
	b.guard(store.ErrNotFound, "SELECT COUNT(*) FROM sessions WHERE public_id = ? AND user_id = ?", publicID, userID)
	b.add("DELETE FROM sessions WHERE public_id = ? AND user_id = ?", publicID, userID)
	return s.execBatch(ctx, b)
}

func (s *Store) DeleteSessionByHash(ctx context.Context, idHash string, ev *store.AuditEvent) error {
	var b batch
	b.audit(ev)
	b.add("DELETE FROM sessions WHERE id_hash = ?", idHash)
	return s.execBatch(ctx, b)
}

func (s *Store) DeleteExpiredSessions(ctx context.Context, now time.Time, idleBefore time.Time) (int, error) {
	n, err := s.exec(ctx, st("DELETE FROM sessions WHERE expires_at <= ? OR (kind = 'web' AND last_seen_at < ?)", now, idleBefore))
	if err != nil {
		return 0, err
	}
	return int(n[0]), nil
}

// ---- device authorization ----

const deviceCols = "device_code_hash, user_code, user_id, state, expires_at, created_at, client_name"

func (s *Store) CreateDeviceAuth(ctx context.Context, r store.DeviceAuthRequest) error {
	_, err := s.exec(ctx, st("INSERT INTO device_auth_requests ("+deviceCols+") VALUES (?, ?, ?, ?, ?, ?, ?)",
		r.DeviceCodeHash, r.UserCode, null(r.UserID), r.State, r.ExpiresAt, r.CreatedAt, null(r.ClientName)))
	return err
}

func (s *Store) getDeviceAuth(ctx context.Context, where string, arg any) (*store.DeviceAuthRequest, error) {
	var r store.DeviceAuthRequest
	err := s.queryOne(ctx, store.Strong, "SELECT "+deviceCols+" FROM device_auth_requests WHERE "+where, []any{arg},
		&r.DeviceCodeHash, &r.UserCode, &r.UserID, &r.State, &r.ExpiresAt, &r.CreatedAt, &r.ClientName)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func (s *Store) GetDeviceAuthByUserCode(ctx context.Context, userCode string) (*store.DeviceAuthRequest, error) {
	return s.getDeviceAuth(ctx, "user_code = ?", userCode)
}

func (s *Store) GetDeviceAuthByDeviceHash(ctx context.Context, h string) (*store.DeviceAuthRequest, error) {
	return s.getDeviceAuth(ctx, "device_code_hash = ?", h)
}

func (s *Store) DecideDeviceAuth(ctx context.Context, userCode, userID, state string, ev *store.AuditEvent) error {
	var b batch
	b.audit(ev)
	b.guard(store.Conflict("request is not pending"), "SELECT COUNT(*) FROM device_auth_requests WHERE user_code = ? AND state = 'pending'", userCode)
	b.add("UPDATE device_auth_requests SET state = ?, user_id = ? WHERE user_code = ?", state, userID, userCode)
	return s.execBatch(ctx, b)
}

func (s *Store) ConsumeDeviceAuth(ctx context.Context, h string, x store.Session, ev *store.AuditEvent) error {
	var b batch
	b.audit(ev)
	b.guard(store.Conflict("request is not approved"), "SELECT COUNT(*) FROM device_auth_requests WHERE device_code_hash = ? AND state = 'approved'", h)
	b.add("UPDATE device_auth_requests SET state = 'consumed' WHERE device_code_hash = ?", h)
	b.addAll(insertSessionStmt(x))
	return s.execBatch(ctx, b)
}

func (s *Store) DeleteExpiredDeviceAuth(ctx context.Context, now time.Time) error {
	_, err := s.exec(ctx, st("DELETE FROM device_auth_requests WHERE expires_at <= ?", now))
	return err
}
