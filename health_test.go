package dnsbl2

import (
	"context"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
)

func TestNormalizeHealthCheckDefaults(t *testing.T) {
	provider := Provider{
		Zone:        "dnsbl.example.",
		Answers:     []string{"127.0.0.38"},
		HealthCheck: &ProviderHealthCheck{},
	}
	normalizeHealthCheck(&provider)

	if got, want := provider.HealthCheck.Positive, "127.0.0.38"; got != want {
		t.Fatalf("positive address = %q, want %q", got, want)
	}
	if got, want := provider.HealthCheck.Negative, defaultHealthNegative; got != want {
		t.Fatalf("negative address = %q, want %q", got, want)
	}
	if got, want := time.Duration(provider.HealthCheck.Interval), defaultHealthInterval; got != want {
		t.Fatalf("interval = %s, want %s", got, want)
	}
}

func TestProviderHealthQueriesControlsConcurrently(t *testing.T) {
	rule := healthTestRule()
	started := make(chan string, 2)
	release := make(chan struct{})
	matcher := MatchDNSBL{
		Timeout: caddy.Duration(time.Second),
		lookupDNS: func(_ context.Context, query string) (dnsResponse, error) {
			started <- query
			<-release
			if strings.HasPrefix(query, "38.0.0.127.") {
				return dnsResponse{
					addresses: []netip.Addr{netip.MustParseAddr("127.0.0.38")},
					rcode:     dnsRcodeSuccess,
				}, nil
			}
			return dnsResponse{rcode: dnsRcodeNameError}, nil
		},
	}

	done := make(chan struct{})
	go func() {
		matcher.checkProviderHealth(context.Background(), &rule)
		close(done)
	}()
	for range 2 {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("control queries did not start concurrently")
		}
	}
	close(release)
	<-done

	if got := providerHealthStatus(rule.health.status.Load()); got != providerHealthHealthy {
		t.Fatalf("health status = %s, want healthy", healthStatusName(got))
	}
}

func TestProviderHealthDetectsControlFailures(t *testing.T) {
	tests := []struct {
		name   string
		lookup lookupDNSFunc
	}{
		{
			name: "positive SERVFAIL",
			lookup: func(_ context.Context, query string) (dnsResponse, error) {
				if strings.HasPrefix(query, "38.0.0.127.") {
					return dnsResponse{rcode: 2}, nil
				}
				return dnsResponse{rcode: dnsRcodeNameError}, nil
			},
		},
		{
			name: "negative wildcard",
			lookup: func(_ context.Context, query string) (dnsResponse, error) {
				return dnsResponse{
					addresses: []netip.Addr{netip.MustParseAddr("127.0.0.38")},
					rcode:     dnsRcodeSuccess,
				}, nil
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rule := healthTestRule()
			matcher := MatchDNSBL{
				Timeout:   caddy.Duration(time.Second),
				lookupDNS: test.lookup,
			}
			matcher.checkProviderHealth(context.Background(), &rule)
			if got := providerHealthStatus(rule.health.status.Load()); got != providerHealthUnhealthy {
				t.Fatalf("health status = %s, want unhealthy", healthStatusName(got))
			}
		})
	}
}

func TestMatcherSkipsUnhealthyProvider(t *testing.T) {
	unhealthy := healthTestRule()
	unhealthy.health.update(false)
	lookupCalls := 0
	matcher := MatchDNSBL{
		Timeout: caddy.Duration(time.Second),
		rules: []providerRule{
			unhealthy,
			{zone: "healthy.example."},
		},
		lookupDNS: func(_ context.Context, query string) (dnsResponse, error) {
			lookupCalls++
			if strings.HasSuffix(query, ".dnsbl.example.") {
				t.Fatal("unhealthy provider was queried")
			}
			return dnsResponse{rcode: dnsRcodeNameError}, nil
		},
	}

	matched, err := matcher.MatchWithError(newRequest("192.0.2.45:1234"))
	if err != nil {
		t.Fatalf("match: %v", err)
	}
	if matched {
		t.Fatal("unexpected match")
	}
	if got, want := lookupCalls, 1; got != want {
		t.Fatalf("lookups = %d, want %d", got, want)
	}
}

func TestMatcherUsesProviderWithUnknownHealth(t *testing.T) {
	rule := healthTestRule()
	matcher := MatchDNSBL{
		Timeout: caddy.Duration(time.Second),
		rules:   []providerRule{rule},
		lookupDNS: func(context.Context, string) (dnsResponse, error) {
			return dnsResponse{
				addresses: []netip.Addr{netip.MustParseAddr("127.0.0.38")},
				rcode:     dnsRcodeSuccess,
			}, nil
		},
	}

	matched, err := matcher.MatchWithError(newRequest("192.0.2.45:1234"))
	if err != nil {
		t.Fatalf("match: %v", err)
	}
	if !matched {
		t.Fatal("provider with unknown health must remain available")
	}
}

func TestCleanupCancelsHealthChecks(t *testing.T) {
	started := make(chan struct{}, 2)
	canceled := make(chan struct{}, 2)
	matcher := MatchDNSBL{
		ProviderConfigs: []Provider{{
			Zone:        "dnsbl.example.",
			HealthCheck: &ProviderHealthCheck{},
		}},
		lookupDNS: func(ctx context.Context, _ string) (dnsResponse, error) {
			started <- struct{}{}
			<-ctx.Done()
			canceled <- struct{}{}
			return dnsResponse{}, ctx.Err()
		},
	}

	if err := matcher.Provision(caddy.Context{}); err != nil {
		t.Fatalf("provision: %v", err)
	}
	for range 2 {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("health check did not start")
		}
	}
	if err := matcher.Cleanup(); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	for range 2 {
		select {
		case <-canceled:
		case <-time.After(time.Second):
			t.Fatal("health check was not canceled")
		}
	}
}

func TestProviderHealthStatusUpdate(t *testing.T) {
	health := newProviderHealth(ProviderHealthCheck{
		Positive: defaultHealthPositive,
		Negative: defaultHealthNegative,
		Interval: caddy.Duration(defaultHealthInterval),
	})
	var transitions atomic.Int32
	for _, healthy := range []bool{true, true, false, false, true} {
		if _, _, changed := health.update(healthy); changed {
			transitions.Add(1)
		}
	}
	if got, want := transitions.Load(), int32(3); got != want {
		t.Fatalf("health transitions = %d, want %d", got, want)
	}
}

func healthTestRule() providerRule {
	return providerRule{
		zone: "dnsbl.example.",
		answers: map[netip.Addr]struct{}{
			netip.MustParseAddr("127.0.0.38"): {},
		},
		health: newProviderHealth(ProviderHealthCheck{
			Positive: "127.0.0.38",
			Negative: "127.0.0.1",
			Interval: caddy.Duration(time.Minute),
		}),
	}
}
