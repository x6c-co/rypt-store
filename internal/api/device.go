package api

import (
	"context"
	"crypto/rand"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/x6c-co/rypt-store/internal/api/gen"
	"github.com/x6c-co/rypt-store/internal/audit"
	"github.com/x6c-co/rypt-store/internal/authn"
	"github.com/x6c-co/rypt-store/internal/authz"
	"github.com/x6c-co/rypt-store/internal/ids"
	"github.com/x6c-co/rypt-store/internal/store"
)

// Device flow timing (core X8, RFC 8628).
const (
	deviceCodeTTL  = 10 * time.Minute
	devicePollWait = 5 * time.Second
)

// userCodeAlphabet is RFC 8628's suggested set: consonants only, so codes
// spell no words, with no look-alike characters.
const userCodeAlphabet = "BCDFGHJKLMNPQRSTVWXZ"

func newUserCode() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	out := make([]byte, 0, 9)
	for i, c := range b {
		if i == 4 {
			out = append(out, '-')
		}
		out = append(out, userCodeAlphabet[int(c)%len(userCodeAlphabet)])
	}
	return string(out)
}

// NormalizeUserCode upper-cases and re-inserts the dash.
func NormalizeUserCode(s string) string {
	s = strings.ToUpper(strings.NewReplacer("-", "", " ", "").Replace(s))
	if len(s) != 8 {
		return s
	}
	return s[:4] + "-" + s[4:]
}

// pollTracker enforces the polling interval per device code (slow_down).
type pollTracker struct {
	mu   sync.Mutex
	last map[string]time.Time
}

func newPollTracker() *pollTracker { return &pollTracker{last: map[string]time.Time{}} }

func (t *pollTracker) tooSoon(key string, now time.Time) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	for k, at := range t.last {
		if now.Sub(at) > deviceCodeTTL {
			delete(t.last, k)
		}
	}
	prev, ok := t.last[key]
	t.last[key] = now
	// Allow a little jitter in the client's timer.
	return ok && now.Sub(prev) < devicePollWait-500*time.Millisecond
}

func (h *Handlers) StartDeviceAuth(ctx context.Context, req gen.StartDeviceAuthRequestObject) (gen.StartDeviceAuthResponseObject, error) {
	client := ""
	if req.Body != nil {
		client = truncate(strings.TrimSpace(deref(req.Body.ClientName)), 128)
	}
	device := ids.RandomToken(32)
	now := h.now()
	r := store.DeviceAuthRequest{DeviceCodeHash: ids.HashToken(device), UserCode: newUserCode(), State: store.DeviceAuthPending,
		ExpiresAt: now.Add(deviceCodeTTL), CreatedAt: now, ClientName: client}
	if err := h.d.Store.CreateDeviceAuth(ctx, r); err != nil {
		return nil, err
	}
	base := h.baseURL(ctx) + "/device"
	return gen.StartDeviceAuth200JSONResponse{
		DeviceCode: device, UserCode: r.UserCode, VerificationUri: base,
		VerificationUriComplete: base + "?code=" + r.UserCode,
		ExpiresIn:               int(deviceCodeTTL.Seconds()), Interval: int(devicePollWait.Seconds()),
	}, nil
}

func deviceError(code, detail string) *Problem {
	return problem(http.StatusBadRequest, code, detail)
}

func (h *Handlers) PollDeviceToken(ctx context.Context, req gen.PollDeviceTokenRequestObject) (gen.PollDeviceTokenResponseObject, error) {
	if req.Body == nil {
		return nil, errInvalid("device_code", "device_code is required")
	}
	hash := ids.HashToken(req.Body.DeviceCode)
	r, err := h.d.Store.GetDeviceAuthByDeviceHash(ctx, hash)
	if errors.Is(err, store.ErrNotFound) {
		return nil, deviceError("expired_token", "the device code is unknown or expired; run login again")
	}
	if err != nil {
		return nil, err
	}
	now := h.now()
	if !now.Before(r.ExpiresAt) || r.State == store.DeviceAuthConsumed {
		return nil, deviceError("expired_token", "the device code is expired; run login again")
	}
	switch r.State {
	case store.DeviceAuthDenied:
		return nil, deviceError("access_denied", "the request was denied in the browser")
	case store.DeviceAuthPending:
		if h.devicePolls.tooSoon(hash, now) {
			return nil, deviceError("slow_down", "polling too fast")
		}
		return nil, deviceError("authorization_pending", "waiting for approval in the browser")
	}
	token := authn.NewCLISessionToken()
	sess := h.newSession(ctx, r.UserID, token, store.SessionCLI, true)
	err = h.record(ctx, audit.Event{ChainID: store.InstanceChain, ActorKind: audit.ActorUser, ActorID: r.UserID,
		Action: "auth.cli_session.create", TargetKind: "session", TargetID: sess.PublicID, Metadata: map[string]any{"client": r.ClientName}},
		func(ev *store.AuditEvent) error { return h.d.Store.ConsumeDeviceAuth(ctx, hash, sess, ev) })
	if errors.Is(err, store.ErrConflict) {
		return nil, deviceError("expired_token", "the device code was already used")
	}
	if err != nil {
		return nil, err
	}
	return gen.PollDeviceToken200JSONResponse{AccessToken: token, TokenType: gen.Bearer, ExpiresAt: sess.ExpiresAt}, nil
}

// signedInUser returns the signed-in, MFA-satisfied user.
func signedInUser(ctx context.Context) (*authz.Principal, error) {
	p := PrincipalFrom(ctx)
	if p == nil || p.Kind != authz.KindUser {
		return nil, errUnauthorized()
	}
	return p, nil
}

func (h *Handlers) GetDeviceAuth(ctx context.Context, req gen.GetDeviceAuthRequestObject) (gen.GetDeviceAuthResponseObject, error) {
	if _, err := signedInUser(ctx); err != nil {
		return nil, err
	}
	r, err := h.d.Store.GetDeviceAuthByUserCode(ctx, NormalizeUserCode(req.UserCode))
	if errors.Is(err, store.ErrNotFound) || (err == nil && !h.now().Before(r.ExpiresAt)) {
		return nil, errNotFound("device request")
	}
	if err != nil {
		return nil, err
	}
	return gen.GetDeviceAuth200JSONResponse{UserCode: r.UserCode, ClientName: strPtr(r.ClientName),
		State: gen.DeviceAuthRequestState(r.State), CreatedAt: r.CreatedAt, ExpiresAt: r.ExpiresAt}, nil
}

func (h *Handlers) ApproveDeviceAuth(ctx context.Context, req gen.ApproveDeviceAuthRequestObject) (gen.ApproveDeviceAuthResponseObject, error) {
	p, err := signedInUser(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, errInvalid("user_code", "user_code is required")
	}
	code := NormalizeUserCode(req.Body.UserCode)
	r, err := h.d.Store.GetDeviceAuthByUserCode(ctx, code)
	if errors.Is(err, store.ErrNotFound) || (err == nil && !h.now().Before(r.ExpiresAt)) {
		return nil, errNotFound("device request")
	}
	if err != nil {
		return nil, err
	}
	state, action := store.DeviceAuthDenied, "auth.device.deny"
	if req.Body.Approve {
		state, action = store.DeviceAuthApproved, "auth.device.approve"
	}
	err = h.record(ctx, audit.Event{ChainID: store.InstanceChain, ActorKind: audit.ActorUser, ActorID: p.ID, Action: action,
		TargetKind: "device_request", TargetID: code, Metadata: map[string]any{"client": r.ClientName}},
		func(ev *store.AuditEvent) error { return h.d.Store.DecideDeviceAuth(ctx, code, p.ID, state, ev) })
	if err != nil {
		return nil, err
	}
	return gen.ApproveDeviceAuth204Response{}, nil
}
