package dnsbl2

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

type dnsblMetrics struct {
	queries        *prometheus.CounterVec
	lookupDuration *prometheus.HistogramVec
	cacheHits      prometheus.Counter
	coalesced      prometheus.Counter
	inflight       prometheus.Gauge
	providerHealth *prometheus.GaugeVec
}

func registerDNSBLMetrics(registry *prometheus.Registry) (*dnsblMetrics, error) {
	if registry == nil {
		return nil, nil
	}
	const namespace, subsystem = "caddy", "dnsbl2"

	queries, err := registerCollector(registry, prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Subsystem: subsystem,
		Name:      "queries_total",
		Help:      "Number of DNSBL resolver queries by provider and result.",
	}, []string{"provider", "result"}))
	if err != nil {
		return nil, err
	}
	lookupDuration, err := registerCollector(registry, prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: namespace,
		Subsystem: subsystem,
		Name:      "lookup_duration_seconds",
		Help:      "Duration of DNSBL resolver queries in seconds.",
		Buckets:   prometheus.DefBuckets,
	}, []string{"provider"}))
	if err != nil {
		return nil, err
	}
	cacheHits, err := registerCollector(registry, prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: namespace,
		Subsystem: subsystem,
		Name:      "cache_hits_total",
		Help:      "Number of DNSBL responses served from the internal cache.",
	}))
	if err != nil {
		return nil, err
	}
	coalesced, err := registerCollector(registry, prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: namespace,
		Subsystem: subsystem,
		Name:      "coalesced_total",
		Help:      "Number of DNSBL lookups served by an existing in-flight query.",
	}))
	if err != nil {
		return nil, err
	}
	inflight, err := registerCollector(registry, prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: namespace,
		Subsystem: subsystem,
		Name:      "inflight",
		Help:      "Number of active DNSBL resolver queries.",
	}))
	if err != nil {
		return nil, err
	}
	providerHealth, err := registerCollector(registry, prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Subsystem: subsystem,
		Name:      "provider_healthy",
		Help:      "DNSBL provider health status: 1 healthy, 0 unhealthy, -1 unknown.",
	}, []string{"provider"}))
	if err != nil {
		return nil, err
	}

	return &dnsblMetrics{
		queries:        queries,
		lookupDuration: lookupDuration,
		cacheHits:      cacheHits,
		coalesced:      coalesced,
		inflight:       inflight,
		providerHealth: providerHealth,
	}, nil
}

func registerCollector[T prometheus.Collector](registry *prometheus.Registry, collector T) (T, error) {
	if err := registry.Register(collector); err != nil {
		var alreadyRegistered prometheus.AlreadyRegisteredError
		if errors.As(err, &alreadyRegistered) {
			if existing, ok := alreadyRegistered.ExistingCollector.(T); ok {
				return existing, nil
			}
		}
		var zero T
		return zero, fmt.Errorf("register DNSBL metrics: %w", err)
	}
	return collector, nil
}

func (m *MatchDNSBL) instrumentLookup(provider string, lookupDNS lookupDNSFunc) lookupDNSFunc {
	if m.metrics == nil {
		return lookupDNS
	}
	return func(ctx context.Context, query string) (dnsResponse, error) {
		started := time.Now()
		m.metrics.inflight.Inc()
		response, err := lookupDNS(ctx, query)
		m.metrics.inflight.Dec()
		m.metrics.lookupDuration.WithLabelValues(provider).Observe(time.Since(started).Seconds())
		m.metrics.queries.WithLabelValues(provider, lookupMetricResult(response, err)).Inc()
		return response, err
	}
}

func (m *MatchDNSBL) recordResolveMetrics(provider string, resolved resolveResult, err error) {
	if m.metrics == nil {
		return
	}
	if resolved.cacheHit {
		m.metrics.cacheHits.Inc()
	}
	if resolved.shared {
		m.metrics.coalesced.Inc()
	}
	if errors.Is(err, errLookupLimit) {
		m.metrics.queries.WithLabelValues(provider, "limited").Inc()
	}
}

func lookupMetricResult(response dnsResponse, err error) string {
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return "timeout"
		}
		if errors.Is(err, context.Canceled) {
			return "canceled"
		}
		if timeout, ok := err.(interface{ Timeout() bool }); ok && timeout.Timeout() {
			return "timeout"
		}
		return "error"
	}
	if response.rcode == dnsRcodeSuccess {
		if len(response.addresses) > 0 {
			return "answer"
		}
		return "no_answer"
	}
	name := dnsRcodeName(response.rcode)
	if name == fmt.Sprintf("%d", response.rcode) {
		return "other_rcode"
	}
	return strings.ToLower(name)
}

func (m *dnsblMetrics) setProviderHealth(provider string, status providerHealthStatus) {
	if m != nil {
		m.providerHealth.WithLabelValues(provider).Set(float64(statusMetricValue(status)))
	}
}

func statusMetricValue(status providerHealthStatus) int {
	switch status {
	case providerHealthHealthy:
		return 1
	case providerHealthUnhealthy:
		return 0
	default:
		return -1
	}
}
