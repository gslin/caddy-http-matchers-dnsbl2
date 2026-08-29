package dnsbl2

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestNormalizeResolverAddress(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{input: "127.0.0.1", want: "127.0.0.1:53"},
		{input: "127.0.0.1:5353", want: "127.0.0.1:5353"},
		{input: "::1", want: "[::1]:53"},
		{input: "[::1]:5353", want: "[::1]:5353"},
	}

	for _, test := range tests {
		if got, err := normalizeResolverAddress(test.input, "53"); err != nil {
			t.Errorf("normalize %q: %v", test.input, err)
		} else if got != test.want {
			t.Errorf("normalize %q = %q, want %q", test.input, got, test.want)
		}
	}
}

func TestParseDNSResponse(t *testing.T) {
	message := new(dns.Msg)
	message.Rcode = dns.RcodeSuccess
	message.Answer = []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{Name: "listed.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 120},
			A:   net.IPv4(127, 0, 0, 2),
		},
		&dns.A{
			Hdr: dns.RR_Header{Name: "listed.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.IPv4(127, 0, 0, 3),
		},
	}

	response := parseDNSResponse(message)
	if got, want := response.rcode, dns.RcodeSuccess; got != want {
		t.Fatalf("rcode = %d, want %d", got, want)
	}
	if got, want := response.ttl, time.Minute; got != want {
		t.Fatalf("TTL = %s, want %s", got, want)
	}
	if got, want := response.addresses[0], netip.MustParseAddr("127.0.0.2"); got != want {
		t.Fatalf("address = %s, want %s", got, want)
	}
}

func TestParseDNSResponseNegativeTTL(t *testing.T) {
	message := new(dns.Msg)
	message.Rcode = dns.RcodeNameError
	message.Ns = []dns.RR{&dns.SOA{
		Hdr:    dns.RR_Header{Name: "example.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300},
		Minttl: 120,
	}}

	response := parseDNSResponse(message)
	if got, want := response.ttl, 2*time.Minute; got != want {
		t.Fatalf("TTL = %s, want %s", got, want)
	}
}

func TestParseDNSResponsePreservesZeroTTL(t *testing.T) {
	message := new(dns.Msg)
	message.Answer = []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{Name: "listed.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 0},
			A:   net.IPv4(127, 0, 0, 2),
		},
		&dns.A{
			Hdr: dns.RR_Header{Name: "listed.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.IPv4(127, 0, 0, 3),
		},
	}

	if got := parseDNSResponse(message).ttl; got != 0 {
		t.Fatalf("TTL = %s, want 0s", got)
	}
}

func TestCustomResolver(t *testing.T) {
	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	server := &dns.Server{
		PacketConn: packetConn,
		Handler: dns.HandlerFunc(func(writer dns.ResponseWriter, request *dns.Msg) {
			response := new(dns.Msg).SetReply(request)
			response.Answer = []dns.RR{&dns.A{
				Hdr: dns.RR_Header{
					Name:   request.Question[0].Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    30,
				},
				A: net.IPv4(127, 0, 0, 38),
			}}
			_ = writer.WriteMsg(response)
		}),
	}
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.ActivateAndServe() }()
	t.Cleanup(func() {
		if err := server.Shutdown(); err != nil {
			t.Errorf("shut down DNS server: %v", err)
		}
		<-serveDone
	})

	lookup, err := newLookupDNS([]string{packetConn.LocalAddr().String()}, time.Second)
	if err != nil {
		t.Fatalf("configure resolver: %v", err)
	}
	response, err := lookup(context.Background(), "45.2.0.192.dnsbl.example.")
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if got, want := response.addresses[0], netip.MustParseAddr("127.0.0.38"); got != want {
		t.Fatalf("answer = %s, want %s", got, want)
	}
	if got, want := response.ttl, 30*time.Second; got != want {
		t.Fatalf("TTL = %s, want %s", got, want)
	}
}
