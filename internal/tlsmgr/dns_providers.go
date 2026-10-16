package tlsmgr

import (
	"github.com/caddyserver/certmagic"
	"github.com/libdns/cloudflare"
	"github.com/libdns/digitalocean"
	"github.com/libdns/hetzner"
	"github.com/libdns/porkbun"
	"github.com/libdns/route53"
)

// The DNS-01 providers compiled in by default (core X14). Credentials come
// from environment variables only, never the config file.
func init() {
	RegisterDNSProvider("cloudflare", func(getenv func(string) string) (certmagic.DNSProvider, error) {
		v, err := requireEnv(getenv, "cloudflare", "CLOUDFLARE_API_TOKEN")
		if err != nil {
			return nil, err
		}
		return &cloudflare.Provider{APIToken: v[0]}, nil
	})
	RegisterDNSProvider("route53", func(getenv func(string) string) (certmagic.DNSProvider, error) {
		// The AWS SDK's default chain supplies credentials (AWS_ACCESS_KEY_ID,
		// AWS_SECRET_ACCESS_KEY, AWS_PROFILE, instance roles).
		return &route53.Provider{Region: getenv("AWS_REGION"), HostedZoneID: getenv("AWS_HOSTED_ZONE_ID")}, nil
	})
	RegisterDNSProvider("digitalocean", func(getenv func(string) string) (certmagic.DNSProvider, error) {
		v, err := requireEnv(getenv, "digitalocean", "DIGITALOCEAN_API_TOKEN")
		if err != nil {
			return nil, err
		}
		return &digitalocean.Provider{APIToken: v[0]}, nil
	})
	RegisterDNSProvider("hetzner", func(getenv func(string) string) (certmagic.DNSProvider, error) {
		v, err := requireEnv(getenv, "hetzner", "HETZNER_API_TOKEN")
		if err != nil {
			return nil, err
		}
		return &hetzner.Provider{AuthAPIToken: v[0]}, nil
	})
	RegisterDNSProvider("porkbun", func(getenv func(string) string) (certmagic.DNSProvider, error) {
		v, err := requireEnv(getenv, "porkbun", "PORKBUN_API_KEY", "PORKBUN_API_SECRET_KEY")
		if err != nil {
			return nil, err
		}
		return &porkbun.Provider{APIKey: v[0], APISecretKey: v[1]}, nil
	})
}
