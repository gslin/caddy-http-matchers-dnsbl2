package dnsbl2

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func TestCaddyModule(t *testing.T) {
	module := MatchDNSBL{}.CaddyModule()
	if module.ID != "http.matchers.dnsbl2" {
		t.Fatalf("unexpected module ID: %s", module.ID)
	}
	if _, ok := module.New().(*MatchDNSBL); !ok {
		t.Fatalf("module constructor returned %T", module.New())
	}
}

func TestUnmarshalCaddyfile(t *testing.T) {
	d := caddyfile.NewTestDispenser(`
		dnsbl2 {
			providers "b.barracudacentral.org." "spam.spamrats.com."
			timeout 750ms
		}
	`)

	var matcher MatchDNSBL
	if err := matcher.UnmarshalCaddyfile(d); err != nil {
		t.Fatalf("unmarshal Caddyfile: %v", err)
	}

	wantProviders := []string{"b.barracudacentral.org.", "spam.spamrats.com."}
	if len(matcher.Providers) != len(wantProviders) {
		t.Fatalf("got %d providers, want %d", len(matcher.Providers), len(wantProviders))
	}
	for i, want := range wantProviders {
		if matcher.Providers[i] != want {
			t.Errorf("provider %d = %q, want %q", i, matcher.Providers[i], want)
		}
	}
	if got, want := time.Duration(matcher.Timeout), 750*time.Millisecond; got != want {
		t.Fatalf("timeout = %s, want %s", got, want)
	}
}

func TestUnmarshalCaddyfileProviderAnswers(t *testing.T) {
	d := caddyfile.NewTestDispenser(`
		dnsbl2 {
			provider spam.spamrats.com. {
				answers 127.0.0.38
			}
		}
	`)

	var matcher MatchDNSBL
	if err := matcher.UnmarshalCaddyfile(d); err != nil {
		t.Fatalf("unmarshal Caddyfile: %v", err)
	}

	if got, want := len(matcher.ProviderConfigs), 1; got != want {
		t.Fatalf("provider configs = %d, want %d", got, want)
	}
	provider := matcher.ProviderConfigs[0]
	if got, want := provider.Zone, "spam.spamrats.com."; got != want {
		t.Fatalf("provider zone = %q, want %q", got, want)
	}
	if got, want := strings.Join(provider.Answers, ","), "127.0.0.38"; got != want {
		t.Fatalf("provider answers = %q, want %q", got, want)
	}
}

func TestUnmarshalCaddyfileHealthCheck(t *testing.T) {
	d := caddyfile.NewTestDispenser(`
		dnsbl2 {
			provider spam.spamrats.com. {
				answers 127.0.0.38
				health_check {
					positive 127.0.0.38
					negative 127.0.0.1
					interval 30s
				}
			}
		}
	`)

	var matcher MatchDNSBL
	if err := matcher.UnmarshalCaddyfile(d); err != nil {
		t.Fatalf("unmarshal Caddyfile: %v", err)
	}
	check := matcher.ProviderConfigs[0].HealthCheck
	if check == nil {
		t.Fatal("health check was not configured")
	}
	if got, want := check.Positive, "127.0.0.38"; got != want {
		t.Fatalf("positive address = %q, want %q", got, want)
	}
	if got, want := check.Negative, "127.0.0.1"; got != want {
		t.Fatalf("negative address = %q, want %q", got, want)
	}
	if got, want := time.Duration(check.Interval), 30*time.Second; got != want {
		t.Fatalf("interval = %s, want %s", got, want)
	}
}

func TestUnmarshalCaddyfileResolvers(t *testing.T) {
	d := caddyfile.NewTestDispenser(`
		dnsbl2 {
			providers dnsbl.example
			resolvers 127.0.0.1:5353 ::1
		}
	`)

	var matcher MatchDNSBL
	if err := matcher.UnmarshalCaddyfile(d); err != nil {
		t.Fatalf("unmarshal Caddyfile: %v", err)
	}
	if got, want := strings.Join(matcher.Resolvers, ","), "127.0.0.1:5353,::1"; got != want {
		t.Fatalf("resolvers = %q, want %q", got, want)
	}
}

func TestUnmarshalCaddyfileCache(t *testing.T) {
	d := caddyfile.NewTestDispenser(`
		dnsbl2 {
			providers dnsbl.example
			cache_size 512
			cache_max_ttl 15m
		}
	`)

	var matcher MatchDNSBL
	if err := matcher.UnmarshalCaddyfile(d); err != nil {
		t.Fatalf("unmarshal Caddyfile: %v", err)
	}
	if got, want := matcher.CacheSize, 512; got != want {
		t.Fatalf("cache size = %d, want %d", got, want)
	}
	if got, want := time.Duration(matcher.CacheMaxTTL), 15*time.Minute; got != want {
		t.Fatalf("cache max TTL = %s, want %s", got, want)
	}
}

func TestUnmarshalCaddyfileMaxConcurrent(t *testing.T) {
	d := caddyfile.NewTestDispenser(`
		dnsbl2 {
			providers dnsbl.example
			max_concurrent 12
		}
	`)

	var matcher MatchDNSBL
	if err := matcher.UnmarshalCaddyfile(d); err != nil {
		t.Fatalf("unmarshal Caddyfile: %v", err)
	}
	if got, want := matcher.MaxConcurrent, 12; got != want {
		t.Fatalf("max concurrent = %d, want %d", got, want)
	}
}

func TestUnmarshalCaddyfileRejectsInvalidConfiguration(t *testing.T) {
	tests := map[string]string{
		"inline arguments":  `dnsbl2 example.test`,
		"missing providers": `dnsbl2 { timeout 1s }`,
		"empty providers": `
			dnsbl2 {
				providers
			}
		`,
		"unknown option": `dnsbl2 { unknown value }`,
		"invalid timeout": `
			dnsbl2 {
				providers example.test
				timeout later
			}
		`,
		"zero timeout": `
			dnsbl2 {
				providers example.test
				timeout 0s
			}
		`,
		"duplicate": `dnsbl2 { providers example.test EXAMPLE.TEST. }`,
		"duplicate answer": `
			dnsbl2 {
				provider example.test {
					answers 127.0.0.2 127.0.0.2
				}
			}
		`,
		"invalid answer": `
			dnsbl2 {
				provider example.test {
					answers not-an-address
				}
			}
		`,
		"unknown provider option": `
			dnsbl2 {
				provider example.test {
					unknown value
				}
			}
		`,
		"invalid health positive": `
			dnsbl2 {
				provider example.test {
					health_check {
						positive invalid
					}
				}
			}
		`,
		"same health controls": `
			dnsbl2 {
				provider example.test {
					health_check {
						positive 127.0.0.2
						negative 127.0.0.2
					}
				}
			}
		`,
		"invalid health interval": `
			dnsbl2 {
				provider example.test {
					health_check {
						interval 0s
					}
				}
			}
		`,
		"unknown health option": `
			dnsbl2 {
				provider example.test {
					health_check {
						unknown value
					}
				}
			}
		`,
		"duplicate health check": `
			dnsbl2 {
				provider example.test {
					health_check
					health_check
				}
			}
		`,
		"empty resolvers": `
			dnsbl2 {
				providers example.test
				resolvers
			}
		`,
		"invalid resolver": `
			dnsbl2 {
				providers example.test
				resolvers resolver.example
			}
		`,
		"duplicate resolver": `
			dnsbl2 {
				providers example.test
				resolvers 127.0.0.1 127.0.0.1:53
			}
		`,
		"invalid cache size": `
			dnsbl2 {
				providers example.test
				cache_size 0
			}
		`,
		"invalid cache TTL": `
			dnsbl2 {
				providers example.test
				cache_max_ttl never
			}
		`,
		"invalid max concurrent": `
			dnsbl2 {
				providers example.test
				max_concurrent 0
			}
		`,
	}

	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			var matcher MatchDNSBL
			if err := matcher.UnmarshalCaddyfile(caddyfile.NewTestDispenser(input)); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestCaddyfileAdapter(t *testing.T) {
	input := []byte(`
		http://wiki.gslin.org {
			@badactors dnsbl2 {
				providers "b.barracudacentral.org." "spam.spamrats.com."
			}
			respond @badactors 403
		}
	`)
	adapter := caddyfile.Adapter{ServerType: httpcaddyfile.ServerType{}}
	output, _, err := adapter.Adapt(input, nil)
	if err != nil {
		t.Fatalf("adapt Caddyfile: %v", err)
	}
	if !strings.Contains(string(output), `"dnsbl2"`) {
		t.Fatalf("adapted JSON does not contain dnsbl2 matcher: %s", output)
	}
}

func TestProvision(t *testing.T) {
	matcher := MatchDNSBL{Providers: []string{"DNSBL.EXAMPLE"}}
	if err := matcher.Provision(caddy.Context{}); err != nil {
		t.Fatalf("provision matcher: %v", err)
	}

	if got, want := matcher.Providers[0], "dnsbl.example."; got != want {
		t.Fatalf("provider = %q, want %q", got, want)
	}
	if got, want := time.Duration(matcher.Timeout), defaultLookupTimeout; got != want {
		t.Fatalf("timeout = %s, want %s", got, want)
	}
	if matcher.lookupDNS == nil {
		t.Fatal("resolver was not configured")
	}
	if got, want := matcher.CacheSize, defaultCacheSize; got != want {
		t.Fatalf("cache size = %d, want %d", got, want)
	}
	if got, want := time.Duration(matcher.CacheMaxTTL), defaultCacheMaxTTL; got != want {
		t.Fatalf("cache max TTL = %s, want %s", got, want)
	}
	if matcher.cache == nil {
		t.Fatal("cache was not configured")
	}
	if got, want := matcher.MaxConcurrent, defaultMaxConcurrent; got != want {
		t.Fatalf("max concurrent = %d, want %d", got, want)
	}
	if matcher.coordinator == nil {
		t.Fatal("lookup coordinator was not configured")
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		matcher MatchDNSBL
	}{
		{name: "no providers", matcher: MatchDNSBL{}},
		{name: "empty provider", matcher: MatchDNSBL{Providers: []string{"."}}},
		{name: "whitespace", matcher: MatchDNSBL{Providers: []string{"bad provider.test"}}},
		{name: "negative timeout", matcher: MatchDNSBL{Providers: []string{"dnsbl.example"}, Timeout: caddy.Duration(-time.Second)}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.matcher.Validate(); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestDNSBLQuery(t *testing.T) {
	tests := []struct {
		name     string
		address  string
		provider string
		want     string
	}{
		{
			name:     "IPv4",
			address:  "192.0.2.45",
			provider: "dnsbl.example",
			want:     "45.2.0.192.dnsbl.example.",
		},
		{
			name:     "IPv6",
			address:  "2001:db8::1",
			provider: "dnsbl.example.",
			want:     "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.dnsbl.example.",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			address := netip.MustParseAddr(test.address)
			if got := dnsblQuery(address, test.provider); got != test.want {
				t.Fatalf("query = %q, want %q", got, test.want)
			}
		})
	}
}

func TestRequestClientIP(t *testing.T) {
	t.Run("remote address", func(t *testing.T) {
		request := newRequest("192.0.2.45:1234")
		address, err := requestClientIP(request)
		if err != nil {
			t.Fatalf("parse client IP: %v", err)
		}
		if got, want := address.String(), "192.0.2.45"; got != want {
			t.Fatalf("client IP = %q, want %q", got, want)
		}
	})

	t.Run("Caddy client IP", func(t *testing.T) {
		request := newRequest("192.0.2.45:1234")
		ctx := context.WithValue(request.Context(), caddyhttp.VarsCtxKey, map[string]any{
			caddyhttp.ClientIPVarKey: "2001:db8::1",
		})
		request = request.WithContext(ctx)

		address, err := requestClientIP(request)
		if err != nil {
			t.Fatalf("parse client IP: %v", err)
		}
		if got, want := address.String(), "2001:db8::1"; got != want {
			t.Fatalf("client IP = %q, want %q", got, want)
		}
	})

	t.Run("IPv4-mapped IPv6", func(t *testing.T) {
		request := newRequest("[::ffff:192.0.2.45]:1234")
		address, err := requestClientIP(request)
		if err != nil {
			t.Fatalf("parse client IP: %v", err)
		}
		if got, want := address.String(), "192.0.2.45"; got != want {
			t.Fatalf("client IP = %q, want %q", got, want)
		}
	})
}

func TestMatchWithErrorListed(t *testing.T) {
	matcher := MatchDNSBL{
		Providers: []string{"dnsbl.example."},
		Timeout:   caddy.Duration(time.Second),
		lookupIP: func(_ context.Context, network, host string) ([]net.IP, error) {
			if network != "ip4" {
				t.Errorf("network = %q, want ip4", network)
			}
			if got, want := host, "45.2.0.192.dnsbl.example."; got != want {
				t.Errorf("query = %q, want %q", got, want)
			}
			return []net.IP{net.IPv4(127, 0, 0, 2)}, nil
		},
	}

	matched, err := matcher.MatchWithError(newRequest("192.0.2.45:1234"))
	if err != nil {
		t.Fatalf("match: %v", err)
	}
	if !matched {
		t.Fatal("expected request to match")
	}
}

func TestMatchWithErrorFiltersProviderAnswers(t *testing.T) {
	tests := []struct {
		name      string
		answer    net.IP
		wantMatch bool
	}{
		{name: "accepted", answer: net.IPv4(127, 0, 0, 38), wantMatch: true},
		{name: "not accepted", answer: net.IPv4(127, 0, 0, 2), wantMatch: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matcher := MatchDNSBL{
				ProviderConfigs: []Provider{{
					Zone:    "spam.spamrats.com.",
					Answers: []string{"127.0.0.38"},
				}},
				Timeout: caddy.Duration(time.Second),
				lookupIP: func(context.Context, string, string) ([]net.IP, error) {
					return []net.IP{test.answer}, nil
				},
			}

			matched, err := matcher.MatchWithError(newRequest("192.0.2.45:1234"))
			if err != nil {
				t.Fatalf("match: %v", err)
			}
			if matched != test.wantMatch {
				t.Fatalf("matched = %t, want %t", matched, test.wantMatch)
			}
		})
	}
}

func TestMatchWithErrorFailsOpenOnDNSErrors(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{
			name: "NXDOMAIN",
			err:  &net.DNSError{Err: "no such host", IsNotFound: true},
		},
		{
			name: "SERVFAIL",
			err:  &net.DNSError{Err: "server misbehaving", IsTemporary: true},
		},
		{
			name: "other resolver error",
			err:  errors.New("resolver unavailable"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matcher := MatchDNSBL{
				Providers: []string{"dnsbl.example."},
				Timeout:   caddy.Duration(time.Second),
				lookupIP: func(context.Context, string, string) ([]net.IP, error) {
					return nil, test.err
				},
			}

			matched, err := matcher.MatchWithError(newRequest("192.0.2.45:1234"))
			if err != nil {
				t.Fatalf("match: %v", err)
			}
			if matched {
				t.Fatal("DNS error must not match")
			}
		})
	}
}

func TestMatchWithErrorFailsOpenOnUnsuccessfulRcode(t *testing.T) {
	matcher := MatchDNSBL{
		Providers: []string{"dnsbl.example."},
		Timeout:   caddy.Duration(time.Second),
		lookupDNS: func(context.Context, string) (dnsResponse, error) {
			return dnsResponse{
				addresses: []netip.Addr{netip.MustParseAddr("127.0.0.2")},
				rcode:     2,
			}, nil
		},
	}

	matched, err := matcher.MatchWithError(newRequest("192.0.2.45:1234"))
	if err != nil {
		t.Fatalf("match: %v", err)
	}
	if matched {
		t.Fatal("unsuccessful DNS response must not match")
	}
}

func TestProvidersAreQueriedConcurrently(t *testing.T) {
	const providerCount = 3

	started := make(chan struct{}, providerCount)
	release := make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() {
		releaseOnce.Do(func() { close(release) })
	}
	defer unblock()

	matcher := MatchDNSBL{
		Providers: []string{"one.example", "two.example", "three.example"},
		Timeout:   caddy.Duration(time.Second),
		lookupIP: func(context.Context, string, string) ([]net.IP, error) {
			started <- struct{}{}
			<-release
			return nil, nil
		},
	}

	done := make(chan bool, 1)
	go func() {
		matched, _ := matcher.MatchWithError(newRequest("192.0.2.45:1234"))
		done <- matched
	}()

	for i := 0; i < providerCount; i++ {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatalf("only %d of %d provider lookups started", i, providerCount)
		}
	}

	unblock()
	select {
	case matched := <-done:
		if matched {
			t.Fatal("unexpected match")
		}
	case <-time.After(time.Second):
		t.Fatal("matcher did not finish")
	}
}

func TestLookupTimeoutFailsOpen(t *testing.T) {
	matcher := MatchDNSBL{
		Providers: []string{"dnsbl.example"},
		Timeout:   caddy.Duration(20 * time.Millisecond),
		lookupIP: func(ctx context.Context, _, _ string) ([]net.IP, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		},
	}

	started := time.Now()
	matched, err := matcher.MatchWithError(newRequest("192.0.2.45:1234"))
	if err != nil {
		t.Fatalf("match: %v", err)
	}
	if matched {
		t.Fatal("timeout must not match")
	}
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("matcher took too long to fail open: %s", elapsed)
	}
}

func TestMatchCancelsRemainingLookups(t *testing.T) {
	started := make(chan struct{}, 2)
	releaseHit := make(chan struct{})
	canceled := make(chan struct{})

	matcher := MatchDNSBL{
		Providers: []string{"hit.example", "slow.example"},
		Timeout:   caddy.Duration(time.Second),
		lookupIP: func(ctx context.Context, _, host string) ([]net.IP, error) {
			started <- struct{}{}
			if strings.HasSuffix(host, ".hit.example.") {
				<-releaseHit
				return []net.IP{net.IPv4(127, 0, 0, 2)}, nil
			}
			<-ctx.Done()
			close(canceled)
			return nil, ctx.Err()
		},
	}

	done := make(chan bool, 1)
	go func() {
		matched, _ := matcher.MatchWithError(newRequest("192.0.2.45:1234"))
		done <- matched
	}()

	for i := 0; i < 2; i++ {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("provider lookup did not start")
		}
	}
	close(releaseHit)

	select {
	case matched := <-done:
		if !matched {
			t.Fatal("expected request to match")
		}
	case <-time.After(time.Second):
		t.Fatal("matcher did not return after a hit")
	}

	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("remaining lookup was not canceled")
	}
}

func TestMalformedClientAddressFailsOpen(t *testing.T) {
	lookupCalled := false
	matcher := MatchDNSBL{
		Providers: []string{"dnsbl.example"},
		lookupIP: func(context.Context, string, string) ([]net.IP, error) {
			lookupCalled = true
			return nil, nil
		},
	}

	matched, err := matcher.MatchWithError(newRequest("not-an-address"))
	if err != nil {
		t.Fatalf("match: %v", err)
	}
	if matched {
		t.Fatal("malformed address must not match")
	}
	if lookupCalled {
		t.Fatal("DNS lookup was called for malformed address")
	}
}

func newRequest(remoteAddress string) *http.Request {
	request := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	request.RemoteAddr = remoteAddress
	return request
}
