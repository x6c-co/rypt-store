package tlsmgr

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"

	"github.com/caddyserver/certmagic"
)

// DNSProviderFactory builds a DNS-01 provider from environment variables.
type DNSProviderFactory func(getenv func(string) string) (certmagic.DNSProvider, error)

var (
	dnsMu        sync.Mutex
	dnsProviders = map[string]DNSProviderFactory{}
)

// RegisterDNSProvider adds a DNS-01 provider. The providers of core X14
// register themselves in dns_providers.go; others can be compiled in with a
// file behind a build tag that calls this from init.
func RegisterDNSProvider(name string, f DNSProviderFactory) {
	dnsMu.Lock()
	defer dnsMu.Unlock()
	dnsProviders[name] = f
}

// DNSProvider builds the named provider with credentials from the
// environment.
func DNSProvider(name string) (certmagic.DNSProvider, error) {
	dnsMu.Lock()
	f, ok := dnsProviders[name]
	var names []string
	for n := range dnsProviders {
		names = append(names, n)
	}
	dnsMu.Unlock()
	if !ok {
		sort.Strings(names)
		return nil, fmt.Errorf("tls.acme.dns.provider %q is not compiled in (available: %s)", name, strings.Join(names, ", "))
	}
	return f(os.Getenv)
}

// requireEnv reads environment variables and reports the missing ones.
func requireEnv(getenv func(string) string, provider string, names ...string) ([]string, error) {
	out := make([]string, len(names))
	var missing []string
	for i, n := range names {
		if out[i] = getenv(n); out[i] == "" {
			missing = append(missing, n)
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("the %s DNS provider needs %s", provider, strings.Join(missing, ", "))
	}
	return out, nil
}
