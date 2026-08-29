# caddy-http-matchers-dnsbl2

`caddy-http-matchers-dnsbl2` is a Caddy HTTP request matcher that checks a
client IP address against one or more DNS blocklists (DNSBLs). The matcher is
true when any eligible provider returns an accepted A record.

## Features

- Queries configured providers concurrently with a per-request timeout.
- Coalesces identical in-flight queries and limits active DNS I/O.
- Caches positive and negative responses in a bounded LRU cache while
  respecting DNS TTLs.
- Supports provider-specific A record values, IPv4, and IPv6 DNSBL queries.
- Optionally checks [RFC 5782](https://www.rfc-editor.org/rfc/rfc5782.html)
  positive and negative control entries in the background.
- Supports explicit local DNS resolvers and UDP-to-TCP fallback for truncated
  responses.
- Fails open on NXDOMAIN, SERVFAIL, REFUSED, timeouts, resolver errors,
  concurrency saturation, and unhealthy providers.
- Uses Caddy's resolved client IP, including its trusted proxy configuration.
- Exposes Prometheus metrics, structured debug logs, and request placeholders.

Each HTTP request waits only for its own DNSBL decision, up to `timeout`.
Resolver I/O runs concurrently and does not hold a global request lock. When
the DNS concurrency limit is full, additional lookups fail open immediately.

## Build

Build Caddy with this module using
[xcaddy](https://github.com/caddyserver/xcaddy):

```sh
xcaddy build --with github.com/gslin/caddy-http-matchers-dnsbl2
```

## Basic Caddyfile configuration

The `providers` shorthand treats any returned A record as a match:

```caddyfile
wiki.gslin.org {
        @badactors dnsbl2 {
                providers "b.barracudacentral.org." "spam.spamrats.com."
        }
        respond @badactors 403
}
```

At least one `providers` or `provider` entry is required. Provider names may
be written with or without a trailing dot.

## Provider-specific answers

Some DNSBLs use particular A records for list categories or resolver errors.
Use a `provider` block when only specific answers should match:

```caddyfile
@badactors dnsbl2 {
        providers "b.barracudacentral.org."

        provider "spam.spamrats.com." {
                answers "127.0.0.38"
        }
}
```

When `answers` is omitted, any A record is accepted. A provider zone cannot
appear more than once across `providers` and `provider` blocks.

## Health checks

Health checks are opt-in per provider:

```caddyfile
@badactors dnsbl2 {
        provider "spam.spamrats.com." {
                answers "127.0.0.38"
                health_check {
                        positive "127.0.0.38"
                        negative "127.0.0.1"
                        interval 5m
                }
        }
}
```

The positive and negative control queries run concurrently, immediately after
provisioning and then once per interval. Before the first result, provider
health is `unknown` and normal lookups remain enabled. A failed control check
marks the provider unhealthy and normal requests skip it until a later check
succeeds. Skipping is fail-open.

Defaults follow RFC 5782:

- `positive` is the first configured `answers` value, or `127.0.0.2` when any
  A record is accepted.
- `negative` is `127.0.0.1`.
- `interval` is `5m`.

Providers with nonstandard control entries should configure both addresses
explicitly.

## Lookup and cache controls

```caddyfile
@badactors dnsbl2 {
        providers "b.barracudacentral.org." "spam.spamrats.com."
        timeout 2s
        resolvers "127.0.0.1:53" "[::1]:53"
        cache_size 4096
        cache_max_ttl 1h
        max_concurrent 64
}
```

| Option | Default | Description |
| --- | ---: | --- |
| `timeout` | `2s` | Maximum time for all provider checks for one request. |
| `resolvers` | system configuration | Resolver IP addresses with optional ports. |
| `cache_size` | `4096` | Maximum number of cached DNS responses. |
| `cache_max_ttl` | `1h` | Upper bound applied to each response TTL. |
| `max_concurrent` | `64` | Maximum number of active resolver queries. |

Identical queries share one in-flight resolver request. The cache stores
NOERROR and NXDOMAIN responses only when the DNS response supplies a positive
TTL. It never extends the DNS TTL, and it does not cache SERVFAIL, REFUSED,
timeouts, transport errors, or zero-TTL responses.

Without `resolvers`, the module reads the system resolver configuration from
`/etc/resolv.conf`. If that file is unavailable, it falls back to Go's default
resolver; results from that fallback are not cached because their original
DNS TTL is unavailable. Explicit resolvers must be IP addresses, optionally
with a port. A local recursive resolver is recommended because some DNSBLs
reject shared public resolvers.

## Failure behavior

DNS failures do not return an HTTP 500 response. The matcher treats the
following results as not listed:

| Result | Cached | Match |
| --- | --- | --- |
| Accepted A record | By DNS TTL | Yes |
| Unaccepted A record | By DNS TTL | No |
| NOERROR without A records | By negative DNS TTL | No |
| NXDOMAIN | By negative DNS TTL | No |
| SERVFAIL, REFUSED, or another unsuccessful RCODE | No | No |
| Timeout or resolver transport error | No | No |
| Concurrency limit reached | No | No |
| Provider marked unhealthy | No query | No |

## Request placeholders

A successful match sets these Caddy request variables:

- `{http.vars.dnsbl2.provider}`: the normalized provider zone.
- `{http.vars.dnsbl2.answer}`: the accepted A record.

Both variables are cleared at the start of each matcher evaluation.

## Metrics

The module registers the following metrics with Caddy's Prometheus registry:

- `caddy_dnsbl2_queries_total{provider,result}`
- `caddy_dnsbl2_lookup_duration_seconds{provider}`
- `caddy_dnsbl2_cache_hits_total`
- `caddy_dnsbl2_coalesced_total`
- `caddy_dnsbl2_inflight`
- `caddy_dnsbl2_provider_healthy{provider}`

Provider health uses `1` for healthy, `0` for unhealthy, and `-1` for unknown.
Caddy exposes its registry at the admin API `/metrics` endpoint. The Caddy
[`metrics` handler](https://caddyserver.com/docs/metrics) can expose it through
an HTTP route when the admin API is disabled.

## JSON configuration

The module ID is `http.matchers.dnsbl2`. A matcher in native Caddy JSON can use
both shorthand and detailed providers:

```json
{
  "dnsbl2": {
    "providers": [
      "b.barracudacentral.org."
    ],
    "provider_configs": [
      {
        "zone": "spam.spamrats.com.",
        "answers": ["127.0.0.38"],
        "health_check": {
          "positive": "127.0.0.38",
          "negative": "127.0.0.1",
          "interval": "5m"
        }
      }
    ],
    "timeout": "2s",
    "resolvers": ["127.0.0.1:53", "[::1]:53"],
    "cache_size": 4096,
    "cache_max_ttl": "1h",
    "max_concurrent": 64
  }
}
```

## Development

Run the standard checks and build:

```sh
make
```

Run the race detector separately:

```sh
make test-race
```

The test suite uses local fake resolvers and does not query public DNSBLs.

## LLM assistance

An LLM was used to assist with the design, implementation, tests, and
documentation of this project. Its output is not treated as authoritative;
changes are validated with automated checks and should be reviewed by project
maintainers before release.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE).
