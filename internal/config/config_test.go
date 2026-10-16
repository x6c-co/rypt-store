package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func write(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDefaults(t *testing.T) {
	c, err := Load("", nil)
	if err != nil {
		t.Fatal(err)
	}
	// Shipped defaults (core X15).
	if c.Keys.Provider != "local" || c.Keys.DefaultMode != "B" || c.Rypt.OutagePolicy != "fail_closed" ||
		!c.Auth.RequireMFA || c.Secrets.VersionsKept != 20 {
		t.Fatalf("unexpected defaults: %+v", c)
	}
	if c.Secrets.DeletedRetention.D() != 720*time.Hour || c.Tokens.MaxTTL.D() != 8760*time.Hour {
		t.Fatalf("feature 01 defaults: %v %v", c.Secrets.DeletedRetention, c.Tokens.MaxTTL)
	}
	if c.Keys.Local.KEKFile != "/data/local.kek" {
		t.Fatalf("kek file = %s", c.Keys.Local.KEKFile)
	}
	if c.EffectiveTLSMode() != "self_signed" {
		t.Fatalf("tls mode = %s", c.EffectiveTLSMode())
	}
}

func TestFileAndEnvOverride(t *testing.T) {
	p := write(t, `
data_dir: /srv
keys:
  provider: local
  default_mode: A
  cache_ttl: 5m
tls:
  domains: ["a.example.com"]
  acme:
    email: ops@example.com
`)
	c, err := Load(p, []string{
		"RYPT_STORE_KEYS_DEFAULT_MODE=C",
		"RYPT_STORE_TLS_DOMAINS=x.example.com, y.example.com",
		"RYPT_STORE_AUTH_REQUIRE_MFA=false",
		"RYPT_STORE_SECRETS_VERSIONS_KEPT=5",
		"RYPT_STORE_RYPT_MAX_STALE=2h",
		"UNRELATED=1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if c.DataDir != "/srv" || c.Keys.DefaultMode != "C" || c.Keys.CacheTTL.D() != 5*time.Minute {
		t.Fatalf("file/env merge: %+v", c.Keys)
	}
	if strings.Join(c.TLS.Domains, ",") != "x.example.com,y.example.com" {
		t.Fatalf("domains = %v", c.TLS.Domains)
	}
	if c.Auth.RequireMFA || c.Secrets.VersionsKept != 5 || c.Rypt.MaxStale.D() != 2*time.Hour {
		t.Fatalf("env overrides not applied: %+v %+v", c.Auth, c.Secrets)
	}
	if c.EffectiveTLSMode() != "acme" {
		t.Fatalf("tls mode = %s", c.EffectiveTLSMode())
	}
	if c.Keys.Local.KEKFile != "/srv/local.kek" {
		t.Fatalf("kek file follows data_dir: %s", c.Keys.Local.KEKFile)
	}
}

func TestValidation(t *testing.T) {
	cases := map[string][]string{
		"bad provider":       {"RYPT_STORE_KEYS_PROVIDER=vault"},
		"bad mode":           {"RYPT_STORE_KEYS_DEFAULT_MODE=D"},
		"rypt without token": {"RYPT_STORE_KEYS_PROVIDER=rypt"},
		"bad policy":         {"RYPT_STORE_RYPT_OUTAGE_POLICY=maybe"},
		"bad kek":            {"RYPT_STORE_LOCAL_KEK=c2hvcnQ="},
		"files without cert": {"RYPT_STORE_TLS_MODE=files"},
		"bad duration":       {"RYPT_STORE_KEYS_CACHE_TTL=soon"},
	}
	for name, env := range cases {
		if _, err := Load("", env); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	if _, err := Load(write(t, "keys:\n  nonsense: 1\n"), nil); err == nil {
		t.Error("unknown field: expected an error")
	}
	c, err := Load("", []string{"RYPT_STORE_KEYS_PROVIDER=rypt", "RYPT_STORE_RYPT_TOKEN=ry_x", "RYPT_STORE_RYPT_KEY_ID=0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0"})
	if err != nil || !c.RyptConfigured() {
		t.Fatalf("rypt config: %v", err)
	}
}

func TestEmptyFile(t *testing.T) {
	if _, err := Load(write(t, ""), nil); err != nil {
		t.Fatalf("empty file: %v", err)
	}
}

// TestExampleConfig keeps deploy/config.example.yaml loadable.
func TestExampleConfig(t *testing.T) {
	c, err := Load(filepath.Join("..", "..", "deploy", "config.example.yaml"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.Keys.Provider != "local" || c.Secrets.DeletedRetention.D() != 720*time.Hour || c.TLS.Domains[0] != "secrets.example.com" {
		t.Fatalf("example config = %+v", c)
	}
}
