package tlsmgr

import (
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/x6c-co/rypt-store/internal/config"
)

func TestSelfSignedCreateAndReuse(t *testing.T) {
	dir := t.TempDir()
	c1, path, err := LoadOrCreateSelfSigned(dir, []string{"secrets.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	leaf := c1.Leaf
	if !slices.Contains(leaf.DNSNames, "localhost") || !slices.Contains(leaf.DNSNames, "secrets.example.com") {
		t.Fatalf("names = %v", leaf.DNSNames)
	}
	if leaf.PublicKeyAlgorithm != x509.ECDSA || leaf.NotAfter.Sub(leaf.NotBefore) < 364*24*time.Hour {
		t.Fatalf("key %v validity %v", leaf.PublicKeyAlgorithm, leaf.NotAfter.Sub(leaf.NotBefore))
	}
	if fi, _ := os.Stat(filepath.Join(dir, "self-signed.key")); fi.Mode().Perm() != 0o600 {
		t.Fatalf("key mode = %o", fi.Mode().Perm())
	}
	c2, _, err := LoadOrCreateSelfSigned(dir, []string{"secrets.example.com"})
	if err != nil || !c2.Leaf.Equal(leaf) {
		t.Fatal("certificate not reused")
	}
	// A new name forces a new certificate.
	c3, _, err := LoadOrCreateSelfSigned(dir, []string{"other.example.com"})
	if err != nil || c3.Leaf.Equal(leaf) || !slices.Contains(c3.Leaf.DNSNames, "other.example.com") {
		t.Fatal("certificate not regenerated for a new name")
	}
	// The PEM file is a trust anchor a client can pin (rypt-store --ca-file).
	pool := x509.NewCertPool()
	pem, _ := os.ReadFile(path)
	pool.AppendCertsFromPEM(pem)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{*c3}}
	srv.StartTLS()
	defer srv.Close()
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
	url := strings.Replace(srv.URL, "127.0.0.1", "localhost", 1)
	if _, err := client.Get(url); err != nil {
		t.Fatalf("pinned client: %v", err)
	}
}

func TestFileCertReload(t *testing.T) {
	dir := t.TempDir()
	c1, src1, _ := LoadOrCreateSelfSigned(filepath.Join(dir, "a"), []string{"one.example.com"})
	_, src2, _ := LoadOrCreateSelfSigned(filepath.Join(dir, "b"), []string{"two.example.com"})
	certFile, keyFile := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	copyPair := func(src string) {
		for from, to := range map[string]string{src: certFile, strings.TrimSuffix(src, ".crt") + ".key": keyFile} {
			b, err := os.ReadFile(from)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(to, b, 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	copyPair(src1)
	f, err := newFileCert(certFile, keyFile, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	got, _ := f.getCertificate(nil)
	if !got.Leaf.Equal(c1.Leaf) {
		t.Fatal("initial certificate")
	}
	copyPair(src2)
	future := time.Now().Add(time.Minute)
	_ = os.Chtimes(certFile, future, future)
	f.tryReload("test")
	got, _ = f.getCertificate(nil)
	if !slices.Contains(got.Leaf.DNSNames, "two.example.com") {
		t.Fatal("reload did not pick up the new pair")
	}
	// A broken pair keeps the previous certificate.
	_ = os.WriteFile(certFile, []byte("garbage"), 0o600)
	f.tryReload("test")
	if got2, _ := f.getCertificate(nil); got2 != got {
		t.Fatal("broken pair replaced the certificate")
	}
}

func TestModes(t *testing.T) {
	log := slog.New(slog.DiscardHandler)
	cfg, _ := config.Load("", nil)
	cfg.DataDir = t.TempDir()
	m, err := New(cfg, log)
	if err != nil || m.Mode != "self_signed" || m.SelfSignedCert == "" || m.TLSConfig.MinVersion != tls.VersionTLS12 {
		t.Fatalf("self_signed manager = %+v %v", m, err)
	}

	cfg.TLS.Domains, cfg.TLS.ACME.Email = []string{"secrets.example.com"}, "ops@example.com"
	m, err = New(cfg, log)
	if err != nil || m.Mode != "acme" || m.TLSConfig.GetCertificate == nil {
		t.Fatalf("acme manager = %+v %v", m, err)
	}
	// The HTTP listener answers ACME challenges and redirects the rest.
	h := m.ChallengeHandler(http.NotFoundHandler())
	if h == nil {
		t.Fatal("no challenge handler")
	}
	if !slices.Contains(m.TLSConfig.NextProtos, "acme-tls/1") {
		t.Fatalf("tls-alpn not offered: %v", m.TLSConfig.NextProtos)
	}

	cfg.TLS.ACME.Challenge = "dns"
	cfg.TLS.ACME.DNS.Provider = "cloudflare"
	t.Setenv("CLOUDFLARE_API_TOKEN", "")
	if _, err := New(cfg, log); err == nil || !strings.Contains(err.Error(), "CLOUDFLARE_API_TOKEN") {
		t.Fatalf("missing dns credential: %v", err)
	}
	t.Setenv("CLOUDFLARE_API_TOKEN", "x")
	if _, err := New(cfg, log); err != nil {
		t.Fatalf("dns challenge: %v", err)
	}
	cfg.TLS.ACME.DNS.Provider = "nope"
	if _, err := New(cfg, log); err == nil || !strings.Contains(err.Error(), "porkbun") {
		t.Fatalf("unknown provider: %v", err)
	}
	for _, p := range []string{"cloudflare", "route53", "digitalocean", "hetzner", "porkbun"} {
		if _, ok := dnsProviders[p]; !ok {
			t.Errorf("%s not compiled in", p)
		}
	}
}
