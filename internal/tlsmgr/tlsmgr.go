// Package tlsmgr provides the server's certificates (core 11): ACME through
// CertMagic, operator-supplied certificate files with reload, or a
// generated self-signed certificate.
package tlsmgr

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"strconv"

	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"

	"github.com/x6c-co/rypt-store/internal/config"
)

// Manager holds the TLS configuration for the HTTPS listener.
type Manager struct {
	Mode string
	// TLSConfig serves the HTTPS listener.
	TLSConfig *tls.Config
	// SelfSignedCert is the PEM path of the generated certificate, for
	// clients that need to trust it (self_signed mode only).
	SelfSignedCert string

	challenge func(http.Handler) http.Handler
	start     func(context.Context) error
}

// ChallengeHandler wraps the HTTP listener's handler with the ACME HTTP-01
// responder in acme mode, and returns next unchanged otherwise.
func (m *Manager) ChallengeHandler(next http.Handler) http.Handler {
	if m.challenge == nil {
		return next
	}
	return m.challenge(next)
}

// Start begins background work: certificate management in acme mode and
// file watching in files mode.
func (m *Manager) Start(ctx context.Context) error {
	if m.start == nil {
		return nil
	}
	return m.start(ctx)
}

func baseTLS() *tls.Config {
	// Go's default cipher suites; TLS 1.2 minimum (core 11).
	return &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"h2", "http/1.1"}}
}

// New builds the manager for the configured mode.
func New(cfg *config.Config, log *slog.Logger) (*Manager, error) {
	mode := cfg.EffectiveTLSMode()
	m := &Manager{Mode: mode}
	switch mode {
	case "self_signed":
		dir := filepath.Join(cfg.DataDir, "tls")
		cert, path, err := LoadOrCreateSelfSigned(dir, cfg.TLS.Domains)
		if err != nil {
			return nil, fmt.Errorf("self-signed certificate: %w", err)
		}
		tc := baseTLS()
		tc.Certificates = []tls.Certificate{*cert}
		m.TLSConfig, m.SelfSignedCert = tc, path
		log.Warn("serving a self-signed certificate; configure tls.domains and tls.acme.email, or tls.cert_file and tls.key_file",
			"certificate", path)
	case "files":
		fc, err := newFileCert(cfg.TLS.CertFile, cfg.TLS.KeyFile, log)
		if err != nil {
			return nil, err
		}
		tc := baseTLS()
		tc.GetCertificate = fc.getCertificate
		m.TLSConfig, m.start = tc, fc.watch
	case "acme":
		tc, challenge, start, err := acme(cfg, log)
		if err != nil {
			return nil, err
		}
		m.TLSConfig, m.challenge, m.start = tc, challenge, start
	default:
		return nil, fmt.Errorf("unknown tls mode %q", mode)
	}
	return m, nil
}

func listenPort(addr string, fallback int) int {
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		return fallback
	}
	n, err := strconv.Atoi(p)
	if err != nil {
		return fallback
	}
	return n
}

// acme configures CertMagic for tls.domains (core 11).
func acme(cfg *config.Config, log *slog.Logger) (*tls.Config, func(http.Handler) http.Handler, func(context.Context) error, error) {
	zl, err := zap.NewProduction()
	if err != nil {
		zl = zap.NewNop()
	}
	cm := certmagic.NewDefault()
	cm.Storage = &certmagic.FileStorage{Path: filepath.Join(cfg.DataDir, "certmagic")}
	cm.Logger = zl
	tmpl := certmagic.ACMEIssuer{
		CA:     certmagic.LetsEncryptProductionCA,
		Email:  cfg.TLS.ACME.Email,
		Agreed: true,
		Logger: zl,
		// Challenges are answered by this server's own listeners, so
		// CertMagic never tries to bind ports 80 and 443 itself.
		AltHTTPPort:    listenPort(cfg.Server.HTTPListen, 80),
		AltTLSALPNPort: listenPort(cfg.Server.HTTPSListen, 443),
	}
	if cfg.TLS.ACME.CA != "" {
		tmpl.CA = cfg.TLS.ACME.CA
	}
	switch cfg.TLS.ACME.Challenge {
	case "http":
		if cfg.Server.HTTPListen == "" {
			return nil, nil, nil, fmt.Errorf("the http challenge needs server.http_listen")
		}
		tmpl.DisableTLSALPNChallenge = true
	case "tls-alpn":
		tmpl.DisableHTTPChallenge = true
	case "dns":
		p, err := DNSProvider(cfg.TLS.ACME.DNS.Provider)
		if err != nil {
			return nil, nil, nil, err
		}
		tmpl.DisableHTTPChallenge, tmpl.DisableTLSALPNChallenge = true, true
		tmpl.DNS01Solver = &certmagic.DNS01Solver{DNSManager: certmagic.DNSManager{DNSProvider: p, Logger: zl}}
	}
	issuer := certmagic.NewACMEIssuer(cm, tmpl)
	cm.Issuers = []certmagic.Issuer{issuer}
	tc := cm.TLSConfig()
	tc.MinVersion = tls.VersionTLS12
	tc.NextProtos = append([]string{"h2", "http/1.1"}, tc.NextProtos...)
	domains := cfg.TLS.Domains
	start := func(ctx context.Context) error {
		log.Info("managing ACME certificates", "domains", domains, "ca", tmpl.CA, "challenge", cfg.TLS.ACME.Challenge)
		return cm.ManageAsync(ctx, domains)
	}
	return tc, issuer.HTTPChallengeHandler, start, nil
}
