package dnsbl2

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestRegisterDNSBLMetricsReusesCollectors(t *testing.T) {
	registry := prometheus.NewPedanticRegistry()
	first, err := registerDNSBLMetrics(registry)
	if err != nil {
		t.Fatalf("register metrics: %v", err)
	}
	second, err := registerDNSBLMetrics(registry)
	if err != nil {
		t.Fatalf("register metrics again: %v", err)
	}

	first.cacheHits.Inc()
	if got, want := testutil.ToFloat64(second.cacheHits), float64(1); got != want {
		t.Fatalf("cache hits = %f, want %f", got, want)
	}
}

func TestMatcherMetricsDistinguishQueriesAndCacheHits(t *testing.T) {
	metrics, err := registerDNSBLMetrics(prometheus.NewPedanticRegistry())
	if err != nil {
		t.Fatalf("register metrics: %v", err)
	}
	matcher := MatchDNSBL{
		Providers: []string{"dnsbl.example."},
		Timeout:   caddy.Duration(time.Second),
		cache:     newResponseCache(2, time.Hour),
		metrics:   metrics,
		lookupDNS: func(context.Context, string) (dnsResponse, error) {
			return dnsResponse{
				addresses: []netip.Addr{netip.MustParseAddr("127.0.0.2")},
				ttl:       time.Minute,
				rcode:     dnsRcodeSuccess,
			}, nil
		},
	}

	for range 2 {
		matched, err := matcher.MatchWithError(newRequest("192.0.2.45:1234"))
		if err != nil {
			t.Fatalf("match: %v", err)
		}
		if !matched {
			t.Fatal("expected request to match")
		}
	}

	queries := metrics.queries.WithLabelValues("dnsbl.example.", "answer")
	if got, want := testutil.ToFloat64(queries), float64(1); got != want {
		t.Fatalf("resolver queries = %f, want %f", got, want)
	}
	if got, want := testutil.ToFloat64(metrics.cacheHits), float64(1); got != want {
		t.Fatalf("cache hits = %f, want %f", got, want)
	}
	if got := testutil.ToFloat64(metrics.inflight); got != 0 {
		t.Fatalf("inflight queries = %f, want 0", got)
	}
}

func TestLookupMetricResult(t *testing.T) {
	tests := []struct {
		name     string
		response dnsResponse
		err      error
		want     string
	}{
		{name: "answer", response: dnsResponse{rcode: dnsRcodeSuccess, addresses: []netip.Addr{netip.MustParseAddr("127.0.0.2")}}, want: "answer"},
		{name: "no answer", response: dnsResponse{rcode: dnsRcodeSuccess}, want: "no_answer"},
		{name: "NXDOMAIN", response: dnsResponse{rcode: dnsRcodeNameError}, want: "nxdomain"},
		{name: "SERVFAIL", response: dnsResponse{rcode: 2}, want: "servfail"},
		{name: "unknown RCODE", response: dnsResponse{rcode: 999}, want: "other_rcode"},
		{name: "timeout", err: context.DeadlineExceeded, want: "timeout"},
		{name: "canceled", err: context.Canceled, want: "canceled"},
		{name: "error", err: errors.New("resolver failed"), want: "error"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := lookupMetricResult(test.response, test.err); got != test.want {
				t.Fatalf("result = %q, want %q", got, test.want)
			}
		})
	}
}

func TestProviderHealthMetric(t *testing.T) {
	metrics, err := registerDNSBLMetrics(prometheus.NewPedanticRegistry())
	if err != nil {
		t.Fatalf("register metrics: %v", err)
	}

	for status, want := range map[providerHealthStatus]float64{
		providerHealthUnknown:   -1,
		providerHealthHealthy:   1,
		providerHealthUnhealthy: 0,
	} {
		metrics.setProviderHealth("dnsbl.example.", status)
		gauge := metrics.providerHealth.WithLabelValues("dnsbl.example.")
		if got := testutil.ToFloat64(gauge); got != want {
			t.Fatalf("health metric for %s = %f, want %f", healthStatusName(status), got, want)
		}
	}
}
