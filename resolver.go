package dnsbl2

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"time"

	"github.com/miekg/dns"
)

const dnsRcodeSuccess = dns.RcodeSuccess

type dnsResponse struct {
	addresses []netip.Addr
	ttl       time.Duration
	rcode     int
}

type lookupDNSFunc func(context.Context, string) (dnsResponse, error)

type dnsResolver struct {
	servers   []string
	udpClient *dns.Client
	tcpClient *dns.Client
}

func newLookupDNS(configuredServers []string, timeout time.Duration) (lookupDNSFunc, error) {
	servers := configuredServers
	port := "53"
	if len(servers) == 0 {
		config, err := dns.ClientConfigFromFile("/etc/resolv.conf")
		if err != nil || len(config.Servers) == 0 {
			return lookupWithDefaultResolver, nil
		}
		servers = config.Servers
		port = config.Port
	}

	normalized := make([]string, 0, len(servers))
	for _, server := range servers {
		address, err := normalizeResolverAddress(server, port)
		if err != nil {
			return nil, err
		}
		normalized = append(normalized, address)
	}

	resolver := &dnsResolver{
		servers:   normalized,
		udpClient: &dns.Client{Net: "udp", Timeout: timeout},
		tcpClient: &dns.Client{Net: "tcp", Timeout: timeout},
	}
	return resolver.lookup, nil
}

func (r *dnsResolver) lookup(ctx context.Context, name string) (dnsResponse, error) {
	query := new(dns.Msg).SetQuestion(dns.Fqdn(name), dns.TypeA)
	query.RecursionDesired = true

	var lastErr error
	for _, server := range r.servers {
		response, _, err := r.udpClient.ExchangeContext(ctx, query.Copy(), server)
		if err != nil {
			lastErr = err
			if ctx.Err() != nil {
				break
			}
			continue
		}
		if response == nil {
			lastErr = fmt.Errorf("DNS resolver %s returned an empty response", server)
			continue
		}
		if response.Truncated {
			response, _, err = r.tcpClient.ExchangeContext(ctx, query.Copy(), server)
			if err != nil {
				lastErr = err
				if ctx.Err() != nil {
					break
				}
				continue
			}
			if response == nil {
				lastErr = fmt.Errorf("DNS resolver %s returned an empty TCP response", server)
				continue
			}
		}
		return parseDNSResponse(response), nil
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("no DNS resolvers are available")
	}
	return dnsResponse{}, lastErr
}

func lookupWithDefaultResolver(ctx context.Context, name string) (dnsResponse, error) {
	addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", name)
	if err != nil {
		return dnsResponse{}, err
	}
	return dnsResponse{addresses: addresses, rcode: dns.RcodeSuccess}, nil
}

func parseDNSResponse(message *dns.Msg) dnsResponse {
	response := dnsResponse{rcode: message.Rcode}
	var ttl uint32
	var ttlSet bool
	for _, record := range message.Answer {
		a, ok := record.(*dns.A)
		if !ok {
			continue
		}
		address, ok := netip.AddrFromSlice(a.A)
		if !ok {
			continue
		}
		response.addresses = append(response.addresses, address.Unmap())
		if !ttlSet || a.Hdr.Ttl < ttl {
			ttl = a.Hdr.Ttl
			ttlSet = true
		}
	}
	if len(response.addresses) == 0 {
		ttl = negativeTTL(message.Ns)
	}
	response.ttl = time.Duration(ttl) * time.Second
	return response
}

func negativeTTL(records []dns.RR) uint32 {
	var ttl uint32
	var ttlSet bool
	for _, record := range records {
		soa, ok := record.(*dns.SOA)
		if !ok {
			continue
		}
		candidate := min(soa.Hdr.Ttl, soa.Minttl)
		if !ttlSet || candidate < ttl {
			ttl = candidate
			ttlSet = true
		}
	}
	return ttl
}

func normalizeResolverAddress(value, defaultPort string) (string, error) {
	if addressPort, err := netip.ParseAddrPort(value); err == nil {
		return addressPort.String(), nil
	}
	if address, err := netip.ParseAddr(value); err == nil {
		port, err := strconv.ParseUint(defaultPort, 10, 16)
		if err != nil || port == 0 {
			return "", fmt.Errorf("invalid DNS resolver port %q", defaultPort)
		}
		return netip.AddrPortFrom(address, uint16(port)).String(), nil
	}
	return "", fmt.Errorf("invalid DNS resolver address %q", value)
}

func dnsRcodeName(rcode int) string {
	if name, ok := dns.RcodeToString[rcode]; ok {
		return name
	}
	return strconv.Itoa(rcode)
}
