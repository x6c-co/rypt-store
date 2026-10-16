// Package config loads the rypt-store configuration: one YAML file whose
// values can be overridden by RYPT_STORE_-prefixed environment variables.
package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

// EnvPrefix prefixes every environment variable that overrides a config value.
const EnvPrefix = "RYPT_STORE_"

// Duration is a time.Duration that reads Go duration strings ("15m", "168h")
// from YAML and environment variables.
type Duration time.Duration

// D returns the value as a time.Duration.
func (d Duration) D() time.Duration { return time.Duration(d) }

func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	var s string
	if err := n.Decode(&s); err != nil {
		return err
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	*d = Duration(v)
	return nil
}

func (d Duration) MarshalYAML() (any, error) { return time.Duration(d).String(), nil }

type Config struct {
	DataDir  string         `yaml:"data_dir"`
	Server   ServerConfig   `yaml:"server"`
	Database DatabaseConfig `yaml:"database"`
	TLS      TLSConfig      `yaml:"tls"`
	Keys     KeysConfig     `yaml:"keys"`
	Rypt     RyptConfig     `yaml:"rypt"`
	Auth     AuthConfig     `yaml:"auth"`
	Secrets  SecretsConfig  `yaml:"secrets"`
	Tokens   TokensConfig   `yaml:"tokens"`
	Audit    AuditConfig    `yaml:"audit"`
	Metrics  MetricsConfig  `yaml:"metrics"`
}

type ServerConfig struct {
	HTTPSListen string `yaml:"https_listen"`
	HTTPListen  string `yaml:"http_listen"`
	PublicURL   string `yaml:"public_url"`
}

type DatabaseConfig struct {
	Driver   string `yaml:"driver"`
	URL      string `yaml:"url"`
	Username string `yaml:"username"`
	Password string `yaml:"password" secret:"true"`
}

type TLSConfig struct {
	Mode     string     `yaml:"mode"`
	Domains  []string   `yaml:"domains"`
	ACME     ACMEConfig `yaml:"acme"`
	CertFile string     `yaml:"cert_file"`
	KeyFile  string     `yaml:"key_file"`
}

type ACMEConfig struct {
	Email     string        `yaml:"email"`
	CA        string        `yaml:"ca"`
	Challenge string        `yaml:"challenge"`
	DNS       ACMEDNSConfig `yaml:"dns"`
}

type ACMEDNSConfig struct {
	Provider string `yaml:"provider"`
}

type KeysConfig struct {
	Provider             string         `yaml:"provider"`
	DefaultMode          string         `yaml:"default_mode"`
	CacheTTL             Duration       `yaml:"cache_ttl"`
	CacheMaxEntries      int            `yaml:"cache_max_entries"`
	RetiredWrapRetention Duration       `yaml:"retired_wrap_retention"`
	Local                LocalKeyConfig `yaml:"local"`
}

type LocalKeyConfig struct {
	KEKFile string `yaml:"kek_file"`
	// KEK is the base64 KEK from RYPT_STORE_LOCAL_KEK (core 5.3). It is not
	// read from the file.
	KEK string `yaml:"-" secret:"true"`
}

type RyptConfig struct {
	Token        string   `yaml:"token" secret:"true"`
	KeyID        string   `yaml:"key_id"`
	BaseURL      string   `yaml:"base_url"`
	OutagePolicy string   `yaml:"outage_policy"`
	MaxStale     Duration `yaml:"max_stale"`
}

type AuthConfig struct {
	RequireMFA    bool     `yaml:"require_mfa"`
	SessionIdle   Duration `yaml:"session_idle"`
	SessionMax    Duration `yaml:"session_max"`
	CLISessionMax Duration `yaml:"cli_session_max"`
}

type SecretsConfig struct {
	VersionsKept     int      `yaml:"versions_kept"`
	DeletedRetention Duration `yaml:"deleted_retention"`
}

type TokensConfig struct {
	MaxTTL Duration `yaml:"max_ttl"`
}

type AuditConfig struct {
	RetentionDays int `yaml:"retention_days"`
}

type MetricsConfig struct {
	Listen string `yaml:"listen"`
}

// Default returns the shipped defaults (core X15, section 12, feature 01 2.5).
func Default() *Config {
	return &Config{
		DataDir: "/data",
		Server: ServerConfig{
			HTTPSListen: ":8443",
			HTTPListen:  ":8080",
		},
		Database: DatabaseConfig{
			Driver: "rqlite",
			URL:    "http://127.0.0.1:4001",
		},
		TLS: TLSConfig{
			ACME: ACMEConfig{Challenge: "http"},
		},
		Keys: KeysConfig{
			Provider:             "local",
			DefaultMode:          "B",
			CacheTTL:             Duration(15 * time.Minute),
			CacheMaxEntries:      10000,
			RetiredWrapRetention: Duration(7 * 24 * time.Hour),
		},
		Rypt: RyptConfig{
			OutagePolicy: "fail_closed",
			MaxStale:     Duration(24 * time.Hour),
		},
		Auth: AuthConfig{
			RequireMFA:    true,
			SessionIdle:   Duration(12 * time.Hour),
			SessionMax:    Duration(7 * 24 * time.Hour),
			CLISessionMax: Duration(30 * 24 * time.Hour),
		},
		Secrets: SecretsConfig{
			VersionsKept:     20,
			DeletedRetention: Duration(30 * 24 * time.Hour),
		},
		Tokens:  TokensConfig{MaxTTL: Duration(365 * 24 * time.Hour)},
		Metrics: MetricsConfig{Listen: "127.0.0.1:9090"},
	}
}

// Load reads the YAML file at path (skipped when path is empty), applies
// environment overrides from environ, fills derived defaults, and validates.
func Load(path string, environ []string) (*Config, error) {
	c := Default()
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read config: %w", err)
		}
		dec := yaml.NewDecoder(strings.NewReader(string(b)))
		dec.KnownFields(true)
		if err := dec.Decode(c); err != nil && !errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("parse config %s: %w", path, err)
		}
	}
	env := envMap(environ)
	if err := applyEnv(reflect.ValueOf(c).Elem(), EnvPrefix, env); err != nil {
		return nil, err
	}
	c.Keys.Local.KEK = env[EnvPrefix+"LOCAL_KEK"]
	if c.Keys.Local.KEKFile == "" {
		c.Keys.Local.KEKFile = filepath.Join(c.DataDir, "local.kek")
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

func envMap(environ []string) map[string]string {
	m := make(map[string]string, len(environ))
	for _, kv := range environ {
		k, v, ok := strings.Cut(kv, "=")
		if ok && strings.HasPrefix(k, EnvPrefix) {
			m[k] = v
		}
	}
	return m
}

// applyEnv overrides each field from the variable named after its YAML path:
// keys.provider becomes RYPT_STORE_KEYS_PROVIDER.
func applyEnv(v reflect.Value, prefix string, env map[string]string) error {
	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		tag := strings.Split(f.Tag.Get("yaml"), ",")[0]
		if tag == "" || tag == "-" {
			continue
		}
		name := prefix + strings.ToUpper(tag)
		fv := v.Field(i)
		if fv.Kind() == reflect.Struct {
			if err := applyEnv(fv, name+"_", env); err != nil {
				return err
			}
			continue
		}
		raw, ok := env[name]
		if !ok {
			continue
		}
		if err := setFromString(fv, raw); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	return nil
}

func setFromString(fv reflect.Value, raw string) error {
	switch fv.Interface().(type) {
	case Duration:
		d, err := time.ParseDuration(raw)
		if err != nil {
			return err
		}
		fv.Set(reflect.ValueOf(Duration(d)))
		return nil
	case []string:
		var parts []string
		for _, p := range strings.Split(raw, ",") {
			if p = strings.TrimSpace(p); p != "" {
				parts = append(parts, p)
			}
		}
		fv.Set(reflect.ValueOf(parts))
		return nil
	}
	switch fv.Kind() {
	case reflect.String:
		fv.SetString(raw)
	case reflect.Bool:
		b, err := strconv.ParseBool(raw)
		if err != nil {
			return err
		}
		fv.SetBool(b)
	case reflect.Int:
		n, err := strconv.Atoi(raw)
		if err != nil {
			return err
		}
		fv.SetInt(int64(n))
	default:
		return fmt.Errorf("unsupported field kind %s", fv.Kind())
	}
	return nil
}

// Validate checks enumerations and ranges.
func (c *Config) Validate() error {
	var errs []error
	bad := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }

	if c.DataDir == "" {
		bad("data_dir is required")
	}
	if c.Database.Driver != "rqlite" {
		bad("database.driver: %q is not supported (only rqlite)", c.Database.Driver)
	}
	if c.Database.URL == "" {
		bad("database.url is required")
	}
	switch c.TLS.Mode {
	case "", "acme", "files", "self_signed":
	default:
		bad("tls.mode: %q is not one of acme, files, self_signed", c.TLS.Mode)
	}
	switch c.TLS.ACME.Challenge {
	case "http", "tls-alpn", "dns":
	default:
		bad("tls.acme.challenge: %q is not one of http, tls-alpn, dns", c.TLS.ACME.Challenge)
	}
	if c.EffectiveTLSMode() == "acme" {
		if len(c.TLS.Domains) == 0 {
			bad("tls.domains is required in acme mode")
		}
		if c.TLS.ACME.Email == "" {
			bad("tls.acme.email is required in acme mode")
		}
		if c.TLS.ACME.Challenge == "dns" && c.TLS.ACME.DNS.Provider == "" {
			bad("tls.acme.dns.provider is required for the dns challenge")
		}
	}
	if c.EffectiveTLSMode() == "files" && (c.TLS.CertFile == "" || c.TLS.KeyFile == "") {
		bad("tls.cert_file and tls.key_file are required in files mode")
	}
	switch c.Keys.Provider {
	case "local", "rypt":
	default:
		bad("keys.provider: %q is not one of local, rypt", c.Keys.Provider)
	}
	switch c.Keys.DefaultMode {
	case "A", "B", "C":
	default:
		bad("keys.default_mode: %q is not one of A, B, C", c.Keys.DefaultMode)
	}
	if c.Keys.CacheTTL <= 0 {
		bad("keys.cache_ttl must be positive")
	}
	if c.Keys.CacheMaxEntries < 16 {
		bad("keys.cache_max_entries must be at least 16")
	}
	if c.Keys.Local.KEK != "" {
		if b, err := base64.StdEncoding.DecodeString(c.Keys.Local.KEK); err != nil || len(b) != 32 {
			bad("RYPT_STORE_LOCAL_KEK must be 32 bytes of standard base64")
		}
	}
	if c.Keys.Provider == "rypt" && (c.Rypt.Token == "" || c.Rypt.KeyID == "") {
		bad("keys.provider is rypt but rypt.token or rypt.key_id is not set")
	}
	switch c.Rypt.OutagePolicy {
	case "fail_closed", "serve_cached":
	default:
		bad("rypt.outage_policy: %q is not one of fail_closed, serve_cached", c.Rypt.OutagePolicy)
	}
	if c.Auth.SessionIdle <= 0 || c.Auth.SessionMax <= 0 || c.Auth.CLISessionMax <= 0 {
		bad("auth session lifetimes must be positive")
	}
	if c.Secrets.VersionsKept < 1 {
		bad("secrets.versions_kept must be at least 1")
	}
	if c.Tokens.MaxTTL <= 0 {
		bad("tokens.max_ttl must be positive")
	}
	if c.Audit.RetentionDays < 0 {
		bad("audit.retention_days must not be negative")
	}
	if c.Server.PublicURL != "" {
		if u, err := url.Parse(c.Server.PublicURL); err != nil || u.Scheme == "" || u.Host == "" {
			bad("server.public_url must be an absolute URL")
		}
	}
	return errors.Join(errs...)
}

// EffectiveTLSMode resolves an empty tls.mode (core 11): acme when domains and
// an ACME email are set, otherwise self_signed.
func (c *Config) EffectiveTLSMode() string {
	if c.TLS.Mode != "" {
		return c.TLS.Mode
	}
	if len(c.TLS.Domains) > 0 && c.TLS.ACME.Email != "" {
		return "acme"
	}
	return "self_signed"
}

// RyptConfigured reports whether a rypt token and key ID are present.
func (c *Config) RyptConfigured() bool { return c.Rypt.Token != "" && c.Rypt.KeyID != "" }
