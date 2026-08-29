package dnsbl2

import (
	"context"
	"fmt"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"go.uber.org/zap"
)

const (
	defaultHealthPositive = "127.0.0.2"
	defaultHealthNegative = "127.0.0.1"
	defaultHealthInterval = 5 * time.Minute
)

type providerHealthStatus int32

const (
	providerHealthUnknown providerHealthStatus = iota
	providerHealthHealthy
	providerHealthUnhealthy
)

type providerHealth struct {
	positive netip.Addr
	negative netip.Addr
	interval time.Duration
	status   atomic.Int32
}

type healthControlResult struct {
	positive bool
	response dnsResponse
	err      error
}

func newProviderHealth(config ProviderHealthCheck) *providerHealth {
	positive, _ := netip.ParseAddr(config.Positive)
	negative, _ := netip.ParseAddr(config.Negative)
	return &providerHealth{
		positive: positive.Unmap(),
		negative: negative.Unmap(),
		interval: time.Duration(config.Interval),
	}
}

func (h *providerHealth) available() bool {
	return providerHealthStatus(h.status.Load()) != providerHealthUnhealthy
}

func (h *providerHealth) update(healthy bool) (providerHealthStatus, providerHealthStatus, bool) {
	next := providerHealthUnhealthy
	if healthy {
		next = providerHealthHealthy
	}
	previous := providerHealthStatus(h.status.Swap(int32(next)))
	return previous, next, previous != next
}

func normalizeHealthCheck(provider *Provider) {
	if provider.HealthCheck == nil {
		return
	}
	check := provider.HealthCheck
	if check.Positive == "" {
		check.Positive = defaultHealthPositive
		if len(provider.Answers) > 0 {
			check.Positive = provider.Answers[0]
		}
	}
	if check.Negative == "" {
		check.Negative = defaultHealthNegative
	}
	if check.Interval == 0 {
		check.Interval = caddy.Duration(defaultHealthInterval)
	}
	if address, err := netip.ParseAddr(check.Positive); err == nil {
		check.Positive = address.Unmap().String()
	}
	if address, err := netip.ParseAddr(check.Negative); err == nil {
		check.Negative = address.Unmap().String()
	}
}

func validateHealthCheck(provider Provider) error {
	if provider.HealthCheck == nil {
		return nil
	}
	if provider.HealthCheck.Interval < 0 {
		return fmt.Errorf("health check interval for provider %q must be greater than zero", provider.Zone)
	}

	checkCopy := *provider.HealthCheck
	provider.HealthCheck = &checkCopy
	normalizeHealthCheck(&provider)
	positive, err := netip.ParseAddr(provider.HealthCheck.Positive)
	if err != nil {
		return fmt.Errorf("invalid positive health check address %q for provider %q", provider.HealthCheck.Positive, provider.Zone)
	}
	negative, err := netip.ParseAddr(provider.HealthCheck.Negative)
	if err != nil {
		return fmt.Errorf("invalid negative health check address %q for provider %q", provider.HealthCheck.Negative, provider.Zone)
	}
	if positive.Unmap() == negative.Unmap() {
		return fmt.Errorf("health check addresses for provider %q must differ", provider.Zone)
	}
	return nil
}

func unmarshalHealthCheck(d *caddyfile.Dispenser) (*ProviderHealthCheck, error) {
	if d.NextArg() {
		return nil, d.ArgErr()
	}
	check := new(ProviderHealthCheck)
	for nesting := d.Nesting(); d.NextBlock(nesting); {
		switch d.Val() {
		case "positive":
			if !d.AllArgs(&check.Positive) {
				return nil, d.ArgErr()
			}
		case "negative":
			if !d.AllArgs(&check.Negative) {
				return nil, d.ArgErr()
			}
		case "interval":
			var value string
			if !d.AllArgs(&value) {
				return nil, d.ArgErr()
			}
			interval, err := caddy.ParseDuration(value)
			if err != nil || interval <= 0 {
				return nil, d.Errf("invalid health check interval %q", value)
			}
			check.Interval = caddy.Duration(interval)
		default:
			return nil, d.Errf("unrecognized health_check option: %s", d.Val())
		}
	}
	return check, nil
}

func (m *MatchDNSBL) startHealthChecks(ctx context.Context) {
	for i := range m.rules {
		rule := &m.rules[i]
		if rule.health != nil {
			m.metrics.setProviderHealth(rule.zone, providerHealthUnknown)
			go m.monitorProviderHealth(ctx, rule)
		}
	}
}

func (m *MatchDNSBL) monitorProviderHealth(ctx context.Context, rule *providerRule) {
	m.checkProviderHealth(ctx, rule)
	ticker := time.NewTicker(rule.health.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			m.checkProviderHealth(ctx, rule)
		case <-ctx.Done():
			return
		}
	}
}

func (m *MatchDNSBL) checkProviderHealth(ctx context.Context, rule *providerRule) {
	timeout := time.Duration(m.Timeout)
	if timeout <= 0 {
		timeout = defaultLookupTimeout
	}
	checkCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	results := make(chan healthControlResult, 2)
	controls := []struct {
		positive bool
		address  netip.Addr
	}{
		{positive: true, address: rule.health.positive},
		{positive: false, address: rule.health.negative},
	}
	for _, control := range controls {
		control := control
		go func() {
			resolved, err := m.resolveFresh(checkCtx, dnsblQuery(control.address, rule.zone), m.instrumentLookup(rule.zone, m.lookupDNS))
			m.recordResolveMetrics(rule.zone, resolved, err)
			results <- healthControlResult{
				positive: control.positive,
				response: resolved.response,
				err:      err,
			}
		}()
	}

	var positive, negative healthControlResult
	var positiveSeen, negativeSeen bool
healthResults:
	for received := 0; received < 2; received++ {
		select {
		case result := <-results:
			if result.positive {
				positive = result
				positiveSeen = true
			} else {
				negative = result
				negativeSeen = true
			}
		case <-checkCtx.Done():
			if ctx.Err() != nil {
				return
			}
			if !positiveSeen {
				positive.err = checkCtx.Err()
			}
			if !negativeSeen {
				negative.err = checkCtx.Err()
			}
			break healthResults
		}
	}
	if ctx.Err() != nil {
		return
	}

	_, positiveListed := matchingAnswer(positive.response.addresses, rule.answers)
	positiveOK := positive.err == nil && positive.response.rcode == dnsRcodeSuccess && positiveListed
	negativeOK := negative.err == nil && (negative.response.rcode == dnsRcodeNameError ||
		(negative.response.rcode == dnsRcodeSuccess && len(negative.response.addresses) == 0))
	healthy := positiveOK && negativeOK
	previous, current, changed := rule.health.update(healthy)
	m.metrics.setProviderHealth(rule.zone, current)
	if !changed {
		return
	}

	fields := []zap.Field{
		zap.String("provider", rule.zone),
		zap.String("positive_rcode", dnsRcodeName(positive.response.rcode)),
		zap.Strings("positive_answers", addressStrings(positive.response.addresses)),
		zap.String("negative_rcode", dnsRcodeName(negative.response.rcode)),
		zap.Strings("negative_answers", addressStrings(negative.response.addresses)),
	}
	if positive.err != nil {
		fields = append(fields, zap.NamedError("positive_error", positive.err))
	}
	if negative.err != nil {
		fields = append(fields, zap.NamedError("negative_error", negative.err))
	}
	if current == providerHealthUnhealthy {
		if m.logger != nil {
			m.logger.Warn("DNSBL provider health check failed", fields...)
		}
		return
	}
	if previous == providerHealthUnhealthy && m.logger != nil {
		m.logger.Info("DNSBL provider health restored", fields...)
	} else {
		m.logDebug("DNSBL provider health check passed", fields...)
	}
}

func addressStrings(addresses []netip.Addr) []string {
	values := make([]string, 0, len(addresses))
	for _, address := range addresses {
		values = append(values, address.String())
	}
	return values
}

func healthStatusName(status providerHealthStatus) string {
	switch status {
	case providerHealthHealthy:
		return "healthy"
	case providerHealthUnhealthy:
		return "unhealthy"
	default:
		return "unknown"
	}
}
