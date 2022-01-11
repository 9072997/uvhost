package main

import (
	"net"
	"regexp"
	"strings"

	"github.com/miekg/dns"
)

// just to shorten things
var eq = strings.EqualFold

func StartDNS() {
	mux := dns.NewServeMux()

	// attach request handler func
	mux.HandleFunc(DNSZone, handleDnsRequest)

	go func() {
		err := (&dns.Server{
			Addr:    net.JoinHostPort(PublicIPv6Addr, "53"),
			Net:     "udp",
			Handler: mux,
		}).ListenAndServe()
		panic(err)
	}()
	go func() {
		err := (&dns.Server{
			Addr:    net.JoinHostPort(PublicIPv6Addr, "53"),
			Net:     "tcp",
			Handler: mux,
		}).ListenAndServe()
		panic(err)
	}()
}

func handleDnsRequest(resp dns.ResponseWriter, req *dns.Msg) {
	m := new(dns.Msg).SetReply(req)
	m.Authoritative = true

	switch req.Opcode {
	case dns.OpcodeQuery:
		for _, q := range m.Question {
			ip := ipV6Extract(q.Name)
			if ip == nil {
				if eq(q.Name, "ns1."+DNSZone) || eq(q.Name, "ns2."+DNSZone) {
					// respond with our IPv6 address
					answer(m, q,
						nil,
						parseIPv6OrPanic(PublicIPv6Addr),
						false,
					)
				} else if eq(q.Name, DNSZone) {
					// answer as ourselves and include SOA and NS records
					answer(m, q,
						parseIPv4OrPanic(PublicIPv4Addr),
						parseIPv6OrPanic(PublicIPv6Addr),
						true,
					)
				} else {
					m.SetRcode(req, dns.RcodeNameError)
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
	case dns.TypeMX:
		// loopback MX records
		out.Answer = append(out.Answer, &dns.MX{
			Hdr: dns.RR_Header{
				Name:   question.Name,
				Rrtype: dns.TypeMX,
				Class:  dns.ClassINET,
				Ttl:    DNSTTL,
			},
			Mx:         question.Name,
			Preference: 10,
		})
	case dns.TypeA:
		if ipv4 == nil {
			break
		}
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
		if ipv6 == nil {
			break
		}
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
		// and this is where that domain is
		out.Extra = append(out.Extra, &dns.AAAA{
			Hdr: dns.RR_Header{
				Name:   "ns1." + question.Name,
				Rrtype: dns.TypeAAAA,
				Class:  dns.ClassINET,
				Ttl:    DNSTTL,
			},
			AAAA: ipv6,
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

var rIPv6Subdomain = regexp.MustCompile(`(?i)^(?:[0-9a-f]{4}-){7}[0-9a-f]{4}$`)

// extract an ipv6 address from a DNS query name
func ipV6Extract(q string) net.IP {
	if !strings.HasSuffix(q, "."+DNSZone) {
		return nil
	}
	q = strings.TrimSuffix(q, "."+DNSZone)

	parts := strings.Split(q, ".")
	if len(parts) == 0 {
		return nil
	}

	ipPart := parts[len(parts)-1]
	if !rIPv6Subdomain.MatchString(ipPart) {
		return nil
	}

	ip := net.ParseIP(strings.ReplaceAll(ipPart, "-", ":"))
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
