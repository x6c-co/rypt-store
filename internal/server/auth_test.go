package server_test

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/x6c-co/rypt-store/internal/config"
	"github.com/x6c-co/rypt-store/internal/server/servertest"
)

func TestSetupFlow(t *testing.T) {
	e := servertest.Start(t, servertest.Options{})
	c := e.Client()

	r := c.Get("/api/v1/setup/status").Must(t, 200)
	if r.Map()["setup_required"] != true || r.Map()["provider"] != "local" || r.Map()["default_key_mode"] != "B" {
		t.Fatalf("status = %s", r.Body)
	}
	// Everything else is gated until setup completes (core 10).
	if r := c.Get("/api/v1/tenants"); r.Status != 403 || r.Code() != "setup_required" {
		t.Fatalf("gated route: %d %s", r.Status, r.Body)
	}
	c.Get("/healthz").Must(t, 200)
	if r := c.Get("/some/spa/route"); r.Status != 200 || !strings.Contains(string(r.Body), "rypt-store") {
		t.Fatalf("spa route: %d", r.Status)
	}
	// A wrong setup token is refused.
	if r := c.Post("/api/v1/setup/totp", map[string]any{"setup_token": "nope", "email": "a@example.com"}); r.Status != 401 {
		t.Fatalf("wrong token: %d %s", r.Status, r.Body)
	}
	// MFA is required by default: setup without TOTP fails validation.
	r = c.Post("/api/v1/setup", map[string]any{"setup_token": e.Setup, "email": "a@example.com", "display_name": "A",
		"password": "correct horse battery", "organization": "Acme"})
	if r.Status != 400 || r.Code() != "validation_failed" {
		t.Fatalf("setup without mfa: %d %s", r.Status, r.Body)
	}
	a := e.SetupAdmin()
	if len(a.RecoveryCodes) != 10 || a.Tenant != "acme-corp" {
		t.Fatalf("admin = %+v", a)
	}
	// The setup token is single use.
	if r := c.Post("/api/v1/setup/totp", map[string]any{"setup_token": e.Setup, "email": "a@example.com"}); r.Status != 409 {
		t.Fatalf("reused setup token: %d %s", r.Status, r.Body)
	}
	me := a.Client.Get("/api/v1/me").Must(t, 200).Map()
	if me["principal_kind"] != "user" || me["user"].(map[string]any)["is_instance_admin"] != true {
		t.Fatalf("me = %v", me)
	}
	if notices := me["notices"].(map[string]any); notices["local_provider"] != true || notices["self_signed_tls"] != true {
		t.Fatalf("notices = %v", notices)
	}
	// Security headers on every response (core 15).
	r = a.Client.Get("/api/v1/me")
	if r.Header.Get("Content-Security-Policy") != "default-src 'self'; frame-ancestors 'none'" ||
		r.Header.Get("X-Content-Type-Options") != "nosniff" || r.Header.Get("Referrer-Policy") != "no-referrer" ||
		r.Header.Get("X-Request-Id") == "" || r.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("headers = %v", r.Header)
	}
}

func TestLoginMFAAndSessions(t *testing.T) {
	e := servertest.Start(t, servertest.Options{})
	a := e.SetupAdmin()

	c := e.Client()
	r := c.Post("/api/v1/auth/login", map[string]any{"email": "ADMIN@example.com", "password": a.Password}).Must(t, 200)
	if r.Map()["status"] != "mfa_required" {
		t.Fatalf("login = %s", r.Body)
	}
	// Until the second factor, the session reaches only the MFA endpoints.
	if r := c.Get("/api/v1/tenants"); r.Status != 403 || r.Code() != "mfa_required" {
		t.Fatalf("pre-mfa access: %d %s", r.Status, r.Body)
	}
	c.Get("/api/v1/me").Must(t, 200)
	if r := c.Post("/api/v1/auth/mfa/totp", map[string]any{"code": "000000"}); r.Status != 401 {
		t.Fatalf("wrong code: %d", r.Status)
	}
	// A pending session cannot enroll a new factor on an account that has one.
	if r := c.Post("/api/v1/me/mfa/totp", nil); r.Status != 403 {
		t.Fatalf("enroll while pending: %d %s", r.Status, r.Body)
	}
	r = c.Post("/api/v1/auth/mfa/totp", map[string]any{"code": e.TOTPCode(a.TOTPSecret)}).Must(t, 200)
	// The cookie set at the password step expires with the 10-minute pre-MFA
	// session; passing MFA re-issues it with the full session lifetime.
	var cookie *http.Cookie
	for _, ck := range (&http.Response{Header: r.Header}).Cookies() {
		if ck.Name == "__Host-rypt_store_session" {
			cookie = ck
		}
	}
	if cookie == nil || time.Until(cookie.Expires) < 6*24*time.Hour {
		t.Fatalf("session cookie after MFA = %+v", cookie)
	}
	if r := c.Get("/api/v1/me").Map(); r["session"].(map[string]any)["mfa_satisfied"] != true {
		t.Fatalf("session after mfa = %v", r["session"])
	}

	// Mutations without the CSRF header are refused (core 7.3).
	c.NoCSRF = true
	if r := c.Post("/api/v1/auth/logout", nil); r.Status != 403 || r.Code() != "csrf_header_required" {
		t.Fatalf("csrf: %d %s", r.Status, r.Body)
	}
	c.NoCSRF = false

	// Sessions: list, revoke another.
	r = a.Client.Get("/api/v1/me/sessions").Must(t, 200)
	var list struct {
		Sessions []struct {
			ID      string `json:"id"`
			Current bool
		}
	}
	r.JSON(&list)
	if len(list.Sessions) != 2 {
		t.Fatalf("sessions = %s", r.Body)
	}
	var other string
	for _, s := range list.Sessions {
		if !s.Current {
			other = s.ID
		}
	}
	a.Client.Delete("/api/v1/me/sessions/"+other).Must(t, 204)
	if r := c.Get("/api/v1/me"); r.Status != 401 {
		t.Fatalf("revoked session still works: %d", r.Status)
	}

	// Recovery codes work once.
	c2 := e.Client()
	c2.Post("/api/v1/auth/login", map[string]any{"email": a.Email, "password": a.Password}).Must(t, 200)
	c2.Post("/api/v1/auth/mfa/recovery", map[string]any{"code": strings.ToUpper(a.RecoveryCodes[0])}).Must(t, 200)
	c3 := e.Client()
	c3.Post("/api/v1/auth/login", map[string]any{"email": a.Email, "password": a.Password}).Must(t, 200)
	if r := c3.Post("/api/v1/auth/mfa/recovery", map[string]any{"code": a.RecoveryCodes[0]}); r.Status != 401 {
		t.Fatalf("reused recovery code: %d", r.Status)
	}
	if n := c2.Get("/api/v1/me").Map()["mfa"].(map[string]any)["recovery_codes_remaining"]; n != float64(9) {
		t.Fatalf("remaining codes = %v", n)
	}

	// Logout ends the session.
	c2.Post("/api/v1/auth/logout", nil).Must(t, 204)
	if r := c2.Get("/api/v1/me"); r.Status != 401 {
		t.Fatalf("after logout: %d", r.Status)
	}
}

func TestLoginRateLimit(t *testing.T) {
	e := servertest.Start(t, servertest.Options{})
	a := e.SetupAdmin()
	c := e.Client()
	for i := 0; i < 10; i++ {
		if r := c.Post("/api/v1/auth/login", map[string]any{"email": a.Email, "password": "wrong password!"}); r.Status != 401 {
			t.Fatalf("attempt %d: %d", i, r.Status)
		}
	}
	r := c.Post("/api/v1/auth/login", map[string]any{"email": a.Email, "password": a.Password})
	if r.Status != http.StatusTooManyRequests || r.Code() != "rate_limited" {
		t.Fatalf("11th attempt: %d %s", r.Status, r.Body)
	}
	// Unknown users get the same answer as wrong passwords.
	if r := e.Client().Post("/api/v1/auth/login", map[string]any{"email": "nobody@example.com", "password": "whatever-password"}); r.Code() != "invalid_credentials" {
		t.Fatalf("unknown user: %s", r.Body)
	}
}

func TestMFAEnrollmentRequired(t *testing.T) {
	e := servertest.Start(t, servertest.Options{Config: func(c *config.Config) { c.Auth.RequireMFA = false }})
	c := e.Client()
	c.Post("/api/v1/setup", map[string]any{"setup_token": e.Setup, "email": "a@example.com", "display_name": "A",
		"password": "correct horse battery", "organization": "Acme"}).Must(t, 201)
	c.Get("/api/v1/me/sessions").Must(t, 200)
	// With MFA optional and none enrolled, login is complete at the password.
	c2 := e.Client()
	if r := c2.Post("/api/v1/auth/login", map[string]any{"email": "a@example.com", "password": "correct horse battery"}); r.Map()["status"] != "ok" {
		t.Fatalf("login = %s", r.Body)
	}
	// Enroll TOTP; recovery codes come with the first factor.
	r := c2.Post("/api/v1/me/mfa/totp", nil).Must(t, 200)
	secret := r.Map()["secret"].(string)
	r = c2.Post("/api/v1/me/mfa/totp/confirm", map[string]any{"code": e.TOTPCode(secret)}).Must(t, 200)
	if codes := r.Map()["recovery_codes"].([]any); len(codes) != 10 {
		t.Fatalf("codes = %v", codes)
	}
	// Now login asks for the second factor.
	if r := e.Client().Post("/api/v1/auth/login", map[string]any{"email": "a@example.com", "password": "correct horse battery"}); r.Map()["status"] != "mfa_required" {
		t.Fatalf("login after enroll = %s", r.Body)
	}
}

func TestDeviceFlow(t *testing.T) {
	e := servertest.Start(t, servertest.Options{})
	a := e.SetupAdmin()
	cli := e.Client()
	r := cli.Post("/api/v1/auth/device", map[string]any{"client_name": "laptop"}).Must(t, 200)
	var start struct {
		DeviceCode string `json:"device_code"`
		UserCode   string `json:"user_code"`
		URI        string `json:"verification_uri_complete"`
	}
	r.JSON(&start)
	if !strings.Contains(start.URI, "/device?code="+start.UserCode) {
		t.Fatalf("uri = %s", start.URI)
	}
	if r := cli.Post("/api/v1/auth/device/token", map[string]any{"device_code": start.DeviceCode}); r.Code() != "authorization_pending" {
		t.Fatalf("pending: %s", r.Body)
	}
	if r := cli.Post("/api/v1/auth/device/token", map[string]any{"device_code": start.DeviceCode}); r.Code() != "slow_down" {
		t.Fatalf("slow down: %s", r.Body)
	}
	lower := strings.ToLower(strings.ReplaceAll(start.UserCode, "-", ""))
	a.Client.Get("/api/v1/auth/device/requests/"+lower).Must(t, 200)
	a.Client.Post("/api/v1/auth/device/approve", map[string]any{"user_code": lower, "approve": true}).Must(t, 204)
	r = cli.Post("/api/v1/auth/device/token", map[string]any{"device_code": start.DeviceCode}).Must(t, 200)
	tok := r.Map()["access_token"].(string)
	if !strings.HasPrefix(tok, "rsc_") {
		t.Fatalf("token = %s", tok)
	}
	// The code is single use.
	if r := cli.Post("/api/v1/auth/device/token", map[string]any{"device_code": start.DeviceCode}); r.Code() != "expired_token" {
		t.Fatalf("reuse: %s", r.Body)
	}
	bc := e.BearerClient(tok)
	if kind := bc.Get("/api/v1/me").Must(t, 200).Map()["session"].(map[string]any)["kind"]; kind != "cli" {
		t.Fatalf("cli session kind = %v", kind)
	}
	// Bearer requests need no CSRF header.
	bc.NoCSRF = true
	bc.Post("/api/v1/auth/logout", nil).Must(t, 204)
	if r := bc.Get("/api/v1/me"); r.Status != 401 {
		t.Fatalf("after cli logout: %d", r.Status)
	}
	if r := e.BearerClient("garbage").Get("/api/v1/me"); r.Status != 401 {
		t.Fatalf("garbage bearer: %d", r.Status)
	}
}
