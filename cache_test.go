package dnsbl2

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
)

func TestResponseCacheExpiresAtDNSResponseTTL(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	cache := newResponseCache(2, time.Hour)
	cache.now = func() time.Time { return now }
	response := dnsResponse{rcode: dnsRcodeSuccess, ttl: time.Minute}

	cache.put("listed.example.", response)
	if _, ok := cache.get("listed.example."); !ok {
		t.Fatal("expected cache hit")
	}

	now = now.Add(time.Minute)
	if _, ok := cache.get("listed.example."); ok {
		t.Fatal("expired response must not be returned")
	}
}

func TestResponseCacheCapsTTL(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	cache := newResponseCache(2, time.Minute)
	cache.now = func() time.Time { return now }
	cache.put("listed.example.", dnsResponse{rcode: dnsRcodeSuccess, ttl: time.Hour})

	now = now.Add(time.Minute)
	if _, ok := cache.get("listed.example."); ok {
		t.Fatal("response exceeded configured maximum TTL")
	}
}

func TestResponseCacheEvictsLeastRecentlyUsed(t *testing.T) {
	cache := newResponseCache(2, time.Hour)
	response := dnsResponse{rcode: dnsRcodeSuccess, ttl: time.Minute}
	cache.put("one.example.", response)
	cache.put("two.example.", response)
	if _, ok := cache.get("one.example."); !ok {
		t.Fatal("expected cache hit")
	}
	cache.put("three.example.", response)

	if _, ok := cache.get("two.example."); ok {
		t.Fatal("least recently used response was not evicted")
	}
	if _, ok := cache.get("one.example."); !ok {
		t.Fatal("recent response was evicted")
	}
}

func TestResponseCacheSkipsUncacheableResponses(t *testing.T) {
	tests := []struct {
		name     string
		response dnsResponse
	}{
		{name: "zero TTL", response: dnsResponse{rcode: dnsRcodeSuccess}},
		{name: "SERVFAIL", response: dnsResponse{rcode: 2, ttl: time.Minute}},
		{name: "REFUSED", response: dnsResponse{rcode: 5, ttl: time.Minute}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cache := newResponseCache(2, time.Hour)
			cache.put("listed.example.", test.response)
			if _, ok := cache.get("listed.example."); ok {
				t.Fatal("response must not be cached")
			}
		})
	}
}

func TestResponseCacheStoresNXDOMAIN(t *testing.T) {
	cache := newResponseCache(2, time.Hour)
	cache.put("clean.example.", dnsResponse{rcode: dnsRcodeNameError, ttl: time.Minute})
	if response, ok := cache.get("clean.example."); !ok {
		t.Fatal("expected negative cache hit")
	} else if response.rcode != dnsRcodeNameError {
		t.Fatalf("rcode = %d, want %d", response.rcode, dnsRcodeNameError)
	}
}

func TestMatcherUsesResponseCache(t *testing.T) {
	lookups := 0
	matcher := MatchDNSBL{
		Providers: []string{"dnsbl.example."},
		Timeout:   caddy.Duration(time.Second),
		cache:     newResponseCache(2, time.Hour),
		lookupDNS: func(context.Context, string) (dnsResponse, error) {
			lookups++
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
	if got, want := lookups, 1; got != want {
		t.Fatalf("DNS lookups = %d, want %d", got, want)
	}
}
