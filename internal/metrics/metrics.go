// Package metrics holds the Prometheus collectors served at /metrics (core X13).
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
)

type Metrics struct {
	Registry *prometheus.Registry

	// ProviderOps counts provider calls by provider, op, and result (core 5.3).
	ProviderOps *prometheus.CounterVec
	// StaleKeyUses counts uses of expired cache entries under serve_cached (core 5.6).
	StaleKeyUses   prometheus.Counter
	KeyCacheHits   prometheus.Counter
	KeyCacheMisses prometheus.Counter
	HTTPRequests   *prometheus.CounterVec
	AuditEvents    *prometheus.CounterVec
}

// New registers the collectors on a fresh registry.
func New() *Metrics {
	m := &Metrics{
		Registry: prometheus.NewRegistry(),
		ProviderOps: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "rypt_store_provider_ops_total",
			Help: "Key provider operations by provider, operation and result.",
		}, []string{"provider", "op", "result"}),
		StaleKeyUses: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "rypt_store_stale_key_uses_total",
			Help: "Expired key cache entries used while the provider was unreachable (serve_cached).",
		}),
		KeyCacheHits: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "rypt_store_key_cache_hits_total",
			Help: "Unwrapped-key cache hits.",
		}),
		KeyCacheMisses: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "rypt_store_key_cache_misses_total",
			Help: "Unwrapped-key cache misses.",
		}),
		HTTPRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "rypt_store_http_requests_total",
			Help: "HTTP requests by method and status class.",
		}, []string{"method", "code"}),
		AuditEvents: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "rypt_store_audit_events_total",
			Help: "Audit events written by result.",
		}, []string{"result"}),
	}
	m.Registry.MustRegister(m.ProviderOps, m.StaleKeyUses, m.KeyCacheHits, m.KeyCacheMisses, m.HTTPRequests, m.AuditEvents,
		collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	return m
}
