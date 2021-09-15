package main

import (
	"net"
	"strings"

	"github.com/miekg/dns"
)

// just to shorten things
var eq = strings.EqualFold

func ServeDNS() {
	// attach request handler func
	dns.HandleFunc(DNSZone, handleDnsRequest)

	// start server
	server := &dns.Server{
		Addr: ":53",
		Net:  "udp",
	}
	err := server.ListenAndServe()
	panic(err)
}

func handleDnsRequest(resp dns.ResponseWriter, req *dns.Msg) {
	m := new(dns.Msg).SetReply(req)
	m.Authoritative = true

	switch req.Opcode {
	case dns.OpcodeQuery:
		for _, q := range m.Question {
			host := strings.SplitN(q.Name, ".", 2)[0]
			host = strings.ReplaceAll(host, "-", ":")
			ip := parseIPv6(host)
			if ip == nil {
				if strings.ContainsAny(host, ":") {
					// the user probably mis-formatted an IP
					m.SetRcode(req, dns.RcodeNameError)
				} else if eq(host, "ns1") || eq(host, "ns2") {
					// respond with our own IPs
					answer(m, q,
						parseIPv4OrPanic(PublicIPv4Addr),
						parseIPv6OrPanic(PublicIPv6Addr),
						false,
					)
				} else {
					// assume this is a domain root
					// answer as ourselves and include SOA and NS records
					answer(m, q,
						parseIPv4OrPanic(PublicIPv4Addr),
						parseIPv6OrPanic(PublicIPv6Addr),
						true,
					)
				}
			} else {
				// we got a valid IPv6 address as the hostname
				answer(m, q, parseIPv4OrPanic(PublicIPv4Addr), ip, false)
			}
		}
	}

	resp.WriteMsg(m)
}

func answer(
	out *dns.Msg,
	question dns.Question,
	ipv4, ipv6 net.IP,
	isRoot bool,
) {
	switch question.Qtype {
	case dns.TypeA:
		out.Answer = append(out.Answer, &dns.A{
			Hdr: dns.RR_Header{
				Name:   question.Name,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    DNSTTL,
			},
			A: ipv4,
		})
	case dns.TypeAAAA:
		out.Answer = append(out.Answer, &dns.AAAA{
			Hdr: dns.RR_Header{
				Name:   question.Name,
				Rrtype: dns.TypeAAAA,
				Class:  dns.ClassINET,
				Ttl:    DNSTTL,
			},
			AAAA: ipv6,
		})
	case dns.TypeNS:
		if !isRoot {
			break
		}
		out.Answer = append(out.Answer, &dns.NS{
			Hdr: dns.RR_Header{
				Name:   question.Name,
				Rrtype: dns.TypeNS,
				Class:  dns.ClassINET,
				Ttl:    DNSTTL,
			},
			Ns: "ns1." + question.Name,
		})
		out.Answer = append(out.Answer, &dns.NS{
			Hdr: dns.RR_Header{
				Name:   question.Name,
				Rrtype: dns.TypeNS,
				Class:  dns.ClassINET,
				Ttl:    DNSTTL,
			},
			Ns: "ns2." + question.Name,
		})
		// and this is where this domain is
		out.Extra = append(out.Extra, &dns.A{
			Hdr: dns.RR_Header{
				Name:   "ns1." + question.Name,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    DNSTTL,
			},
			A: ipv4,
		})
		out.Extra = append(out.Extra, &dns.AAAA{
			Hdr: dns.RR_Header{
				Name:   "ns1." + question.Name,
				Rrtype: dns.TypeAAAA,
				Class:  dns.ClassINET,
				Ttl:    DNSTTL,
			},
			AAAA: ipv6,
		})
		out.Extra = append(out.Extra, &dns.A{
			Hdr: dns.RR_Header{
				Name:   "ns2." + question.Name,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    DNSTTL,
			},
			A: ipv4,
		})
		out.Extra = append(out.Extra, &dns.AAAA{
			Hdr: dns.RR_Header{
				Name:   "ns2." + question.Name,
				Rrtype: dns.TypeAAAA,
				Class:  dns.ClassINET,
				Ttl:    DNSTTL,
			},
			AAAA: ipv6,
		})
	case dns.TypeSOA:
		if !isRoot {
			break
		}
		out.Answer = append(out.Answer, &dns.SOA{
			Hdr: dns.RR_Header{
				Name:   question.Name,
				Rrtype: dns.TypeSOA,
				Class:  dns.ClassINET,
				Ttl:    DNSTTL,
			},
			Ns:      "ns1." + question.Name,
			Mbox:    strings.ReplaceAll(DNSAdminEmail, "@", ".") + ".",
			Serial:  2000010101, // bogus, but format confrming serial
			Refresh: 1200,       // min recomended value (not used)
			Retry:   DNSTTL,     // (not used)
			Expire:  1209600,    // min recomended value (not used)
			Minttl:  DNSTTL,
		})
	}
}

func parseIPv6(s string) net.IP {
	ip := net.ParseIP(s)
	if ip.To4() != nil {
		return nil
	}
	return ip
}

func parseIPv6OrPanic(s string) net.IP {
	ip := net.ParseIP(s)
	if ip == nil {
		panic("failed to parse IPv6 address")
	}
	if ip.To4() != nil {
		panic("expected IPv6 address, got IPv4 address")
	}
	return ip
}

func parseIPv4OrPanic(s string) net.IP {
	ip := net.ParseIP(s).To4()
	if ip == nil {
		panic("failed to parse IPv4 address")
	}
	return ip
}
