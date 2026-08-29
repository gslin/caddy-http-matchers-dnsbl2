# caddy-http-matchers-dnsbl2

`caddy-http-matchers-dnsbl2` is a Caddy HTTP request matcher that checks the
client IP address against one or more DNS blocklists (DNSBLs). The matcher is
true when any configured provider returns an A record.

## Features

- Queries all configured providers concurrently.
- Applies one timeout to the whole group of lookups. The default is 2 seconds.
- Cancels outstanding lookups as soon as one provider reports a match.
- Fails open on DNS errors. NXDOMAIN, SERVFAIL, timeouts, and other resolver
  errors are treated as not listed.
- Supports IPv4 and IPv6 DNSBL query formats.
- Uses Caddy's resolved client IP, including its trusted proxy configuration.

The matcher waits for the DNSBL result for the request being evaluated, but it
does not use a global lock or block Caddy from serving other requests.

## Build

Build Caddy with this module using
[xcaddy](https://github.com/caddyserver/xcaddy):

```sh
xcaddy build --with github.com/gslin/caddy-http-matchers-dnsbl2
```

## Caddyfile

```caddyfile
wiki.gslin.org {
        @badactors dnsbl2 {
                providers "b.barracudacentral.org." "spam.spamrats.com."
        }
        respond @badactors 403
}
```

An optional timeout can be configured with a Go duration:

```caddyfile
@badactors dnsbl2 {
        providers "b.barracudacentral.org." "spam.spamrats.com."
        timeout 3s
}
```

At least one provider is required. Provider names may be written with or
without a trailing dot.

## JSON

The module ID is `http.matchers.dnsbl2`. A matcher in native Caddy JSON has the
following shape:

```json
{
  "dnsbl2": {
    "providers": [
      "b.barracudacentral.org.",
      "spam.spamrats.com."
    ],
    "timeout": "3s"
  }
}
```

## Resolver behavior

Queries use the resolver configured for the operating system. Some DNSBL
providers reject queries sent through shared public resolvers. A local
recursive resolver may be required in that case.

DNS lookup failures are fail-open by design. They are logged at debug level and
do not cause Caddy to return an HTTP 500 response.

## Development

```sh
go test ./...
```
