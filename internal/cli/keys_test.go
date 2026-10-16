package cli

import (
	"encoding/json"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/x6c-co/rypt-store/internal/config"
	"github.com/x6c-co/rypt-store/internal/metrics"
	"github.com/x6c-co/rypt-store/internal/server/servertest"
)

// cliToken signs a CLI session in through the device flow API.
func cliToken(t *testing.T, e *servertest.Env, admin *servertest.Client) string {
	t.Helper()
	anon := e.Client()
	r := anon.Post("/api/v1/auth/device", map[string]any{}).Must(t, 200)
	start := r.Map()
	admin.Post("/api/v1/auth/device/approve", map[string]any{"user_code": start["user_code"], "approve": true}).Must(t, 204)
	return anon.Post("/api/v1/auth/device/token", map[string]any{"device_code": start["device_code"]}).Must(t, 200).Map()["access_token"].(string)
}

// ryptOps sums rypt_store_provider_ops_total for the rypt provider.
func ryptOps(t *testing.T, m *metrics.Metrics) int {
	t.Helper()
	mfs, err := m.Registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	total := 0.0
	for _, mf := range mfs {
		if mf.GetName() != "rypt_store_provider_ops_total" {
			continue
		}
		for _, mt := range mf.GetMetric() {
			for _, l := range mt.GetLabel() {
				if l.GetName() == "provider" && l.GetValue() == "rypt" {
					total += mt.GetCounter().GetValue()
				}
			}
		}
	}
	return int(total)
}

// TestKeyMigrationAcceptance is feature 01 acceptance criterion 5: after
// `keys migrate --to rypt` and a project mode change from B to C, every
// secret reads back unchanged, and the provider-op counter matches each
// dry-run estimate.
func TestKeyMigrationAcceptance(t *testing.T) {
	// A local-only instance with secrets in two environments.
	e1 := servertest.Start(t, servertest.Options{})
	a := e1.SetupAdmin()
	proj := "/api/v1/tenants/" + a.Tenant + "/projects"
	a.Client.Post(proj, map[string]any{"name": "API", "key_mode": "B"}).Must(t, 201)
	want := map[string]map[string]string{
		"dev":  {"DB_URL": "postgres://dev", "MULTI": "line one\nline two", "EMPTY": ""},
		"prod": {"DB_URL": "postgres://prod", "API_KEY": "sk_live_123"},
	}
	for env, kv := range want {
		for k, v := range kv {
			a.Client.Post(proj+"/api/environments/"+env+"/secrets", map[string]any{"name": k, "value": v}).Must(t, 201)
		}
	}

	// The operator adds rypt credentials, sets keys.provider: rypt, restarts.
	rypt := func(c *config.Config) {
		c.Keys.Provider = "rypt"
		c.Rypt.Token, c.Rypt.KeyID = "ry_test", "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0"
	}
	e := servertest.Start(t, servertest.Options{Store: e1.Store, Rypt: e1.Rypt, Clock: e1.Clock, Config: rypt})
	admin := e.Login(a.Email, a.Password, a.TOTPSecret)
	c := &cliRunner{t: t, server: e.Server.URL, cfg: filepath.Join(t.TempDir(), "cli.yaml"), dir: t.TempDir(),
		vars: map[string]string{"RYPT_STORE_SERVER": e.Server.URL}}
	if err := saveUserConfig(c.cfg, &UserConfig{Server: e.Server.URL, Token: cliToken(t, e, admin), Tenant: a.Tenant}); err != nil {
		t.Fatal(err)
	}

	migrate := func(args ...string) {
		t.Helper()
		var est struct {
			TotalOps int `json:"total_ops"`
		}
		out := c.ok("", append(append([]string{"keys", "migrate"}, args...), "--dry-run", "--output", "json")...)
		if err := json.Unmarshal([]byte(out), &est); err != nil {
			t.Fatalf("dry run output %q: %v", out, err)
		}
		if est.TotalOps == 0 {
			t.Fatalf("dry run estimated no operations: %s", out)
		}
		before := ryptOps(t, e.App.Metrics)
		if res := c.ok("", append([]string{"keys", "migrate"}, args...)...); !strings.Contains(res, "succeeded") {
			t.Fatalf("migrate %v: %q", args, res)
		}
		if spent := ryptOps(t, e.App.Metrics) - before; spent != est.TotalOps {
			t.Fatalf("migrate %v: dry run estimated %d operations, the counter shows %d", args, est.TotalOps, spent)
		}
	}
	migrate("--to", "rypt")
	status := c.ok("", "keys", "status", "--output", "json")
	if !strings.Contains(status, `"provider": "rypt"`) {
		t.Fatalf("status = %s", status)
	}
	migrate("--tenant", a.Tenant, "--project", "api", "--mode", "C")

	// Every secret reads back unchanged, from a cold cache.
	e3 := servertest.Start(t, servertest.Options{Store: e1.Store, Rypt: e1.Rypt, Clock: e1.Clock, Config: rypt})
	c.server = e3.Server.URL
	c.vars["RYPT_STORE_SERVER"] = e3.Server.URL
	if err := saveUserConfig(c.cfg, &UserConfig{Server: e3.Server.URL, Token: cliToken(t, e3, e3.Login(a.Email, a.Password, a.TOTPSecret)), Tenant: a.Tenant}); err != nil {
		t.Fatal(err)
	}
	for env, kv := range want {
		var got map[string]string
		out := c.ok("", "export", "--format", "json", "--tenant", a.Tenant, "--project", "api", "--env", env)
		if err := json.Unmarshal([]byte(out), &got); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, kv) {
			t.Fatalf("%s after migrations = %v, want %v", env, got, kv)
		}
	}
	if v := c.ok("", "audit", "verify", "--instance"); !strings.HasPrefix(v, "OK ") {
		t.Fatalf("instance chain = %q", v)
	}
	if v := c.ok("", "audit", "verify", "--tenant", a.Tenant); !strings.HasPrefix(v, "OK ") {
		t.Fatalf("tenant chain = %q", v)
	}
}
