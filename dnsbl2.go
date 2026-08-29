// Package dnsbl2 provides a Caddy HTTP request matcher backed by DNS blocklists.
package dnsbl2

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

const defaultLookupTimeout = 2 * time.Second

type lookupIPFunc func(context.Context, string, string) ([]net.IP, error)

// Provider configures a DNSBL zone and its accepted A record answers.
type Provider struct {
	// Zone is the DNSBL zone to query.
	Zone string `json:"zone"`

	// Answers limits matches to these IPv4 answers. Any A record matches when
	// Answers is empty.
	Answers []string `json:"answers,omitempty"`
}

// MatchDNSBL matches requests whose client IP is listed by at least one DNSBL
// provider.
type MatchDNSBL struct {
	// Providers is the shorthand list of DNSBL zones where any A record matches.
	Providers []string `json:"providers,omitempty"`

	// ProviderConfigs contains DNSBL zones with provider-specific settings.
	ProviderConfigs []Provider `json:"provider_configs,omitempty"`

	// Timeout limits the total time spent checking all providers for a request.
	// The default is 2 seconds.
	Timeout caddy.Duration `json:"timeout,omitempty"`

	lookupIP lookupIPFunc
	logger   *zap.Logger
	rules    []providerRule
}

type lookupResult struct {
	provider string
	listed   bool
	answer   string
	err      error
}

type providerRule struct {
	zone    string
	answers map[netip.Addr]struct{}
}

func init() {
	caddy.RegisterModule(MatchDNSBL{})
}

// CaddyModule returns the Caddy module information.
func (MatchDNSBL) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.matchers.dnsbl2",
		New: func() caddy.Module { return new(MatchDNSBL) },
	}
}

// Provision prepares the matcher for use.
func (m *MatchDNSBL) Provision(ctx caddy.Context) error {
	if err := m.Validate(); err != nil {
		return err
	}

	for i, provider := range m.Providers {
		m.Providers[i] = normalizeProvider(provider)
	}
	for i := range m.ProviderConfigs {
		m.ProviderConfigs[i].Zone = normalizeProvider(m.ProviderConfigs[i].Zone)
		for j, answer := range m.ProviderConfigs[i].Answers {
			m.ProviderConfigs[i].Answers[j] = netip.MustParseAddr(answer).Unmap().String()
		}
	}
	m.rules = m.compileProviderRules()
	if m.Timeout == 0 {
		m.Timeout = caddy.Duration(defaultLookupTimeout)
	}
	if m.lookupIP == nil {
		m.lookupIP = net.DefaultResolver.LookupIP
	}
	m.logger = ctx.Logger()

	return nil
}

// Validate validates the matcher configuration.
func (m *MatchDNSBL) Validate() error {
	if len(m.Providers) == 0 && len(m.ProviderConfigs) == 0 {
		return fmt.Errorf("at least one DNSBL provider is required")
	}
	if m.Timeout < 0 {
		return fmt.Errorf("timeout must be greater than zero")
	}

	seen := make(map[string]struct{}, len(m.Providers)+len(m.ProviderConfigs))
	for _, provider := range m.Providers {
		if err := validateProviderZone(provider, seen); err != nil {
			return err
		}
	}
	for _, provider := range m.ProviderConfigs {
		if err := validateProviderZone(provider.Zone, seen); err != nil {
			return err
		}
		answerSeen := make(map[netip.Addr]struct{}, len(provider.Answers))
		for _, answer := range provider.Answers {
			address, err := netip.ParseAddr(answer)
			if err != nil || !address.Unmap().Is4() {
				return fmt.Errorf("invalid DNSBL answer %q for provider %q", answer, provider.Zone)
			}
			address = address.Unmap()
			if _, ok := answerSeen[address]; ok {
				return fmt.Errorf("duplicate DNSBL answer %q for provider %q", answer, provider.Zone)
			}
			answerSeen[address] = struct{}{}
		}
	}

	return nil
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler. Syntax:
//
//	dnsbl2 {
//		providers <zones...>
//		provider <zone> {
//			answers <IPv4 addresses...>
//		}
//		timeout <duration>
//	}
func (m *MatchDNSBL) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if d.NextArg() {
			return d.ArgErr()
		}

		for nesting := d.Nesting(); d.NextBlock(nesting); {
			switch d.Val() {
			case "providers":
				providers := d.RemainingArgs()
				if len(providers) == 0 {
					return d.ArgErr()
				}
				m.Providers = append(m.Providers, providers...)

			case "provider":
				if !d.NextArg() {
					return d.ArgErr()
				}
				provider := Provider{Zone: d.Val()}
				if d.NextArg() {
					return d.ArgErr()
				}
				for providerNesting := d.Nesting(); d.NextBlock(providerNesting); {
					switch d.Val() {
					case "answers":
						answers := d.RemainingArgs()
						if len(answers) == 0 {
							return d.ArgErr()
						}
						provider.Answers = append(provider.Answers, answers...)
					default:
						return d.Errf("unrecognized dnsbl2 provider option: %s", d.Val())
					}
				}
				m.ProviderConfigs = append(m.ProviderConfigs, provider)

			case "timeout":
				var value string
				if !d.AllArgs(&value) {
					return d.ArgErr()
				}
				timeout, err := caddy.ParseDuration(value)
				if err != nil {
					return d.Errf("invalid timeout duration %q: %v", value, err)
				}
				if timeout <= 0 {
					return d.Err("timeout must be greater than zero")
				}
				m.Timeout = caddy.Duration(timeout)

			default:
				return d.Errf("unrecognized dnsbl2 option: %s", d.Val())
			}
		}
	}

	return m.Validate()
}

// Match reports whether the request matches. It is retained for compatibility
// with Caddy versions that use caddyhttp.RequestMatcher.
func (m *MatchDNSBL) Match(r *http.Request) bool {
	matched, _ := m.MatchWithError(r)
	return matched
}

// MatchWithError reports whether the request's client IP is listed by any
// configured provider. DNS errors fail open and do not match.
func (m *MatchDNSBL) MatchWithError(r *http.Request) (bool, error) {
	clientIP, err := requestClientIP(r)
	if err != nil {
		m.logDebug("invalid client IP", zap.String("address", requestClientAddress(r)), zap.Error(err))
		return false, nil
	}

	timeout := time.Duration(m.Timeout)
	if timeout <= 0 {
		timeout = defaultLookupTimeout
	}
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()

	rules := m.rules
	if len(rules) == 0 {
		rules = m.compileProviderRules()
	}
	results := make(chan lookupResult, len(rules))
	lookupIP := m.lookupIP
	if lookupIP == nil {
		lookupIP = net.DefaultResolver.LookupIP
	}

	for _, rule := range rules {
		rule := rule
		query := dnsblQuery(clientIP, rule.zone)

		go func() {
			addresses, lookupErr := lookupIP(ctx, "ip4", query)
			answer, listed := matchingAnswer(addresses, rule.answers)
			results <- lookupResult{
				provider: rule.zone,
				listed:   lookupErr == nil && listed,
				answer:   answer,
				err:      lookupErr,
			}
		}()
	}

	for range rules {
		select {
		case result := <-results:
			if result.err != nil {
				m.logDebug("DNSBL lookup failed", zap.String("provider", result.provider), zap.Error(result.err))
				continue
			}
			if result.listed {
				return true, nil
			}

		case <-ctx.Done():
			m.logDebug("DNSBL lookup deadline reached", zap.Error(ctx.Err()))
			return false, nil
		}
	}

	return false, nil
}

func requestClientIP(r *http.Request) (netip.Addr, error) {
	address := requestClientAddress(r)
	if address == "" {
		return netip.Addr{}, fmt.Errorf("client address is empty")
	}

	if addrPort, err := netip.ParseAddrPort(address); err == nil {
		return addrPort.Addr().WithZone("").Unmap(), nil
	}

	address = strings.TrimPrefix(address, "[")
	address = strings.TrimSuffix(address, "]")
	addr, err := netip.ParseAddr(address)
	if err != nil {
		return netip.Addr{}, err
	}

	return addr.WithZone("").Unmap(), nil
}

func requestClientAddress(r *http.Request) string {
	if clientIP, ok := caddyhttp.GetVar(r.Context(), caddyhttp.ClientIPVarKey).(string); ok && clientIP != "" {
		return clientIP
	}
	return r.RemoteAddr
}

func dnsblQuery(address netip.Addr, provider string) string {
	return reverseAddress(address) + "." + normalizeProvider(provider)
}

func reverseAddress(address netip.Addr) string {
	address = address.Unmap()
	if address.Is4() {
		octets := address.As4()
		return fmt.Sprintf("%d.%d.%d.%d", octets[3], octets[2], octets[1], octets[0])
	}

	expanded := strings.ReplaceAll(address.StringExpanded(), ":", "")
	var reversed strings.Builder
	reversed.Grow(len(expanded)*2 - 1)
	for i := len(expanded) - 1; i >= 0; i-- {
		if reversed.Len() > 0 {
			reversed.WriteByte('.')
		}
		reversed.WriteByte(expanded[i])
	}
	return reversed.String()
}

func normalizeProvider(provider string) string {
	return strings.ToLower(strings.TrimRight(provider, ".")) + "."
}

func validateProviderZone(provider string, seen map[string]struct{}) error {
	if strings.TrimSpace(provider) != provider || strings.ContainsAny(provider, " \t\r\n") {
		return fmt.Errorf("invalid DNSBL provider %q", provider)
	}

	normalized := normalizeProvider(provider)
	if normalized == "." {
		return fmt.Errorf("DNSBL provider must not be empty")
	}
	if _, ok := seen[normalized]; ok {
		return fmt.Errorf("duplicate DNSBL provider %q", provider)
	}
	seen[normalized] = struct{}{}
	return nil
}

func (m *MatchDNSBL) compileProviderRules() []providerRule {
	rules := make([]providerRule, 0, len(m.Providers)+len(m.ProviderConfigs))
	for _, provider := range m.Providers {
		rules = append(rules, providerRule{zone: normalizeProvider(provider)})
	}
	for _, provider := range m.ProviderConfigs {
		rule := providerRule{
			zone:    normalizeProvider(provider.Zone),
			answers: make(map[netip.Addr]struct{}, len(provider.Answers)),
		}
		for _, answer := range provider.Answers {
			address, err := netip.ParseAddr(answer)
			if err == nil {
				rule.answers[address.Unmap()] = struct{}{}
			}
		}
		rules = append(rules, rule)
	}
	return rules
}

func matchingAnswer(addresses []net.IP, accepted map[netip.Addr]struct{}) (string, bool) {
	for _, address := range addresses {
		parsed, ok := netip.AddrFromSlice(address)
		if !ok || !parsed.Unmap().Is4() {
			continue
		}
		parsed = parsed.Unmap()
		if len(accepted) == 0 {
			return parsed.String(), true
		}
		if _, ok := accepted[parsed]; ok {
			return parsed.String(), true
		}
	}
	return "", false
}

func (m *MatchDNSBL) logDebug(message string, fields ...zap.Field) {
	if m.logger != nil {
		m.logger.Debug(message, fields...)
	}
}

var (
	_ caddy.Module                      = (*MatchDNSBL)(nil)
	_ caddy.Provisioner                 = (*MatchDNSBL)(nil)
	_ caddy.Validator                   = (*MatchDNSBL)(nil)
	_ caddyfile.Unmarshaler             = (*MatchDNSBL)(nil)
	_ caddyhttp.RequestMatcher          = (*MatchDNSBL)(nil)
	_ caddyhttp.RequestMatcherWithError = (*MatchDNSBL)(nil)
)
