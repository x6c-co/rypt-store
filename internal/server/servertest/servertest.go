// Package servertest runs a full rypt-store HTTP server against a
// throwaway rqlite for integration tests.
package servertest

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"github.com/x6c-co/rypt-store/internal/config"
	"github.com/x6c-co/rypt-store/internal/keys/provider"
	"github.com/x6c-co/rypt-store/internal/keys/provider/providertest"
	"github.com/x6c-co/rypt-store/internal/server"
	"github.com/x6c-co/rypt-store/internal/store/rqlite"
	"github.com/x6c-co/rypt-store/internal/store/storetest"
)

// Clock is a settable clock shared by the server under test.
type Clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *Clock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *Clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// Env is a running server.
type Env struct {
	T      testing.TB
	App    *server.App
	Server *httptest.Server
	Store  *rqlite.Store
	Clock  *Clock
	Rypt   *providertest.Fake
	Setup  string // the setup token
}

// Options adjusts the config before start.
type Options struct {
	Config func(*config.Config)
	Store  *rqlite.Store // reuse a store (restart tests)
	Rypt   *providertest.Fake
	Clock  *Clock
}

// Start runs a server. The local provider is always loaded, and a fake
// "rypt" provider stands in for rypt.dev.
func Start(t testing.TB, o Options) *Env {
	t.Helper()
	cfg, err := config.Load("", nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg.DataDir = t.TempDir()
	if o.Config != nil {
		o.Config(cfg)
	}
	st := o.Store
	if st == nil {
		st = storetest.New(t)
	}
	clock := o.Clock
	if clock == nil {
		clock = &Clock{t: time.Now().UTC()}
	}
	rypt := o.Rypt
	if rypt == nil {
		rypt = providertest.New("rypt")
	}
	local, err := provider.NewLocal(bytes.Repeat([]byte{42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	app, err := server.NewApp(context.Background(), server.AppOptions{
		Config: cfg, Store: st, Providers: []provider.Provider{local, rypt}, Now: clock.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	e := &Env{T: t, App: app, Store: st, Clock: clock, Rypt: rypt}
	if !app.API.SetupDone() {
		if e.Setup, err = app.API.IssueSetupToken(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	e.Server = httptest.NewTLSServer(app.Handler)
	t.Cleanup(e.Server.Close)
	return e
}

// Client is a cookie-holding API client.
type Client struct {
	e      *Env
	hc     *http.Client
	Bearer string
	// NoCSRF omits the X-Rypt-Store-Request header.
	NoCSRF bool
}

func (e *Env) Client() *Client {
	jar, _ := cookiejar.New(nil)
	return &Client{e: e, hc: e.httpClient(jar)}
}

// httpClient returns a client of its own; Server.Client() is shared.
func (e *Env) httpClient(jar http.CookieJar) *http.Client {
	return &http.Client{Transport: e.Server.Client().Transport, Jar: jar}
}

// BearerClient authenticates with a token instead of cookies.
func (e *Env) BearerClient(token string) *Client {
	return &Client{e: e, hc: e.httpClient(nil), Bearer: token}
}

// Response is a decoded response.
type Response struct {
	Status int
	Header http.Header
	Body   []byte
}

// JSON decodes the body into v.
func (r *Response) JSON(v any) {
	if err := json.Unmarshal(r.Body, v); err != nil {
		panic(fmt.Sprintf("decode %s: %v", r.Body, err))
	}
}

// Code returns the problem code of an error response.
func (r *Response) Code() string {
	var p struct{ Code string }
	_ = json.Unmarshal(r.Body, &p)
	return p.Code
}

// Map decodes the body as an object.
func (r *Response) Map() map[string]any {
	var m map[string]any
	_ = json.Unmarshal(r.Body, &m)
	return m
}

// Do sends a request; body may be nil, a string (sent as text/plain), or a
// value encoded as JSON.
func (c *Client) Do(method, path string, body any, headers ...string) *Response {
	c.e.T.Helper()
	var rd io.Reader
	ct := ""
	switch b := body.(type) {
	case nil:
	case string:
		rd, ct = strings.NewReader(b), "text/plain"
	default:
		raw, err := json.Marshal(b)
		if err != nil {
			c.e.T.Fatal(err)
		}
		rd, ct = bytes.NewReader(raw), "application/json"
	}
	req, err := http.NewRequest(method, c.e.Server.URL+path, rd)
	if err != nil {
		c.e.T.Fatal(err)
	}
	if ct != "" {
		req.Header.Set("Content-Type", ct)
	}
	if !c.NoCSRF {
		req.Header.Set("X-Rypt-Store-Request", "1")
	}
	if c.Bearer != "" {
		req.Header.Set("Authorization", "Bearer "+c.Bearer)
	}
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		c.e.T.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return &Response{Status: resp.StatusCode, Header: resp.Header, Body: b}
}

func (c *Client) Get(path string) *Response             { return c.Do(http.MethodGet, path, nil) }
func (c *Client) Post(path string, body any) *Response  { return c.Do(http.MethodPost, path, body) }
func (c *Client) Patch(path string, body any) *Response { return c.Do(http.MethodPatch, path, body) }
func (c *Client) Delete(path string) *Response          { return c.Do(http.MethodDelete, path, nil) }

// Must fails the test unless the response has the status.
func (r *Response) Must(t testing.TB, status int) *Response {
	t.Helper()
	if r.Status != status {
		t.Fatalf("status %d, want %d: %s", r.Status, status, r.Body)
	}
	return r
}

// Admin is the account created by Setup.
type Admin struct {
	Email, Password, TOTPSecret, Tenant string
	RecoveryCodes                       []string
	Client                              *Client
}

// TOTPCode returns a code for the current clock, advancing the clock one
// step first so that a code is never replayed.
func (e *Env) TOTPCode(secret string) string {
	e.Clock.Advance(30 * time.Second)
	code, err := totp.GenerateCode(secret, e.Clock.Now())
	if err != nil {
		e.T.Fatal(err)
	}
	return code
}

// SetupAdmin completes first-run setup and returns a signed-in client.
func (e *Env) SetupAdmin() *Admin {
	e.T.Helper()
	c := e.Client()
	a := &Admin{Email: "admin@example.com", Password: "correct horse battery staple", Client: c}
	r := c.Post("/api/v1/setup/totp", map[string]any{"setup_token": e.Setup, "email": a.Email}).Must(e.T, 200)
	a.TOTPSecret = r.Map()["secret"].(string)
	r = c.Post("/api/v1/setup", map[string]any{
		"setup_token": e.Setup, "email": a.Email, "display_name": "Ada Admin", "password": a.Password,
		"organization": "Acme Corp", "totp_secret": a.TOTPSecret, "totp_code": e.TOTPCode(a.TOTPSecret),
	}).Must(e.T, 201)
	var res struct {
		Tenant        struct{ Slug string }
		RecoveryCodes []string `json:"recovery_codes"`
	}
	r.JSON(&res)
	a.Tenant, a.RecoveryCodes = res.Tenant.Slug, res.RecoveryCodes
	return a
}

// Login signs in a user with password and TOTP.
func (e *Env) Login(email, password, totpSecret string) *Client {
	e.T.Helper()
	c := e.Client()
	r := c.Post("/api/v1/auth/login", map[string]any{"email": email, "password": password}).Must(e.T, 200)
	switch r.Map()["status"] {
	case "ok":
	case "mfa_required":
		c.Post("/api/v1/auth/mfa/totp", map[string]any{"code": e.TOTPCode(totpSecret)}).Must(e.T, 200)
	default:
		e.T.Fatalf("login status %v", r.Map()["status"])
	}
	return c
}
