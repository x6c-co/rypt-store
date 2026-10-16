package tlsmgr

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"sync"
	"syscall"
	"time"
)

// selfSignedValidity is how long a generated certificate lasts (core 11).
const selfSignedValidity = 365 * 24 * time.Hour

// selfSignedNames returns the DNS names and IPs a generated certificate
// covers: tls.domains, localhost, loopback, and the host's addresses.
func selfSignedNames(domains []string) ([]string, []net.IP) {
	names := append([]string{"localhost"}, domains...)
	ips := []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && !ipn.IP.IsLoopback() && !ipn.IP.IsLinkLocalUnicast() {
				ips = append(ips, ipn.IP)
			}
		}
	}
	return names, ips
}

// LoadOrCreateSelfSigned reuses the certificate in dir while it is valid
// for 30 more days and covers the names, and otherwise generates an ECDSA
// P-256 certificate. It returns the certificate and the PEM path.
func LoadOrCreateSelfSigned(dir string, domains []string) (*tls.Certificate, string, error) {
	certPath, keyPath := filepath.Join(dir, "self-signed.crt"), filepath.Join(dir, "self-signed.key")
	names, ips := selfSignedNames(domains)
	if c, err := tls.LoadX509KeyPair(certPath, keyPath); err == nil && c.Leaf != nil {
		covers := time.Until(c.Leaf.NotAfter) > 30*24*time.Hour
		for _, n := range names {
			covers = covers && slices.Contains(c.Leaf.DNSNames, n)
		}
		for _, ip := range ips {
			covers = covers && slices.ContainsFunc(c.Leaf.IPAddresses, ip.Equal)
		}
		if covers {
			return &c, certPath, nil
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, "", err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, "", err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: names[len(names)-1], Organization: []string{"rypt-store self-signed"}},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(selfSignedValidity), DNSNames: names, IPAddresses: ips,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true, IsCA: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, "", err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, "", err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, "", err
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return nil, "", err
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return nil, "", err
	}
	c, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, "", err
	}
	return &c, certPath, nil
}

// fileCert serves tls.cert_file and tls.key_file, reloading them on SIGHUP
// and when either file's modification time changes (core 11).
type fileCert struct {
	certFile, keyFile string
	log               *slog.Logger

	mu     sync.RWMutex
	cert   *tls.Certificate
	mtimes [2]time.Time
}

func newFileCert(certFile, keyFile string, log *slog.Logger) (*fileCert, error) {
	f := &fileCert{certFile: certFile, keyFile: keyFile, log: log}
	if err := f.reload(); err != nil {
		return nil, err
	}
	return f, nil
}

func (f *fileCert) modTimes() ([2]time.Time, error) {
	var out [2]time.Time
	for i, p := range []string{f.certFile, f.keyFile} {
		fi, err := os.Stat(p)
		if err != nil {
			return out, err
		}
		out[i] = fi.ModTime()
	}
	return out, nil
}

func (f *fileCert) reload() error {
	mt, err := f.modTimes()
	if err != nil {
		return err
	}
	c, err := tls.LoadX509KeyPair(f.certFile, f.keyFile)
	if err != nil {
		return fmt.Errorf("load certificate files: %w", err)
	}
	f.mu.Lock()
	f.cert, f.mtimes = &c, mt
	f.mu.Unlock()
	return nil
}

func (f *fileCert) getCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.cert, nil
}

// watch reloads on SIGHUP and on a changed modification time, checked
// every 60 seconds. A failed reload keeps serving the previous pair.
func (f *fileCert) watch(ctx context.Context) error {
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		defer signal.Stop(hup)
		t := time.NewTicker(60 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-hup:
				f.tryReload("SIGHUP")
			case <-t.C:
				mt, err := f.modTimes()
				f.mu.RLock()
				changed := err == nil && mt != f.mtimes
				f.mu.RUnlock()
				if changed {
					f.tryReload("file change")
				}
			}
		}
	}()
	return nil
}

func (f *fileCert) tryReload(reason string) {
	if err := f.reload(); err != nil {
		f.log.Error("certificate reload failed; keeping the previous certificate", "reason", reason, "error", err.Error())
		return
	}
	f.log.Info("reloaded certificate files", "reason", reason)
}
