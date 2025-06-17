package main

import (
	"context"
	"fmt"
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
	mux.HandleFunc(Conf.DNSZone, HandleMainZone)

	go func() {
		err := (&dns.Server{
			Addr:    net.JoinHostPort(Conf.PublicIPv6Addr, "53"),
			Net:     "udp",
			Handler: mux,
		}).ListenAndServe()
		panic(err)
	}()
	go func() {
		err := (&dns.Server{
			Addr:    net.JoinHostPort(Conf.PublicIPv6Addr, "53"),
			Net:     "tcp",
			Handler: mux,
		}).ListenAndServe()
		panic(err)
	}()
}

func HandleMainZone(resp dns.ResponseWriter, req *dns.Msg) {
	m := new(dns.Msg).SetReply(req)
	m.Authoritative = true

	if req.Opcode == dns.OpcodeQuery {
		for _, q := range m.Question {
			ip := IPv6Extract(q.Name)
			if ip == nil {
				if eq(q.Name, "ns1."+Conf.DNSZone) || eq(q.Name, "ns2."+Conf.DNSZone) {
					// respond with our addresses
					answer(m, q,
						parseIPv4OrPanic(Conf.PublicIPv4Addr),
						parseIPv6OrPanic(Conf.PublicIPv6Addr),
						false,
					)
				} else if eq(q.Name, Conf.DNSZone) {
					// answer as ourselves and include SOA and NS records
					answer(m, q,
						parseIPv4OrPanic(Conf.PublicIPv4Addr),
						parseIPv6OrPanic(Conf.PublicIPv6Addr),
						true,
					)
				} else {
					m.SetRcode(req, dns.RcodeNameError)
				}
			} else {
				// we got a valid IPv6 address as the hostname
				answer(m, q, parseIPv4OrPanic(Conf.PublicIPv4Addr), ip, false)
			}
		}
	} else {
		m.SetRcode(req, dns.RcodeServerFailure)
	}

	Log(FormatDNS(*m))
	resp.WriteMsg(m)
}

func answer(
	out *dns.Msg,
	question dns.Question,
	ipv4, ipv6 net.IP,
	isRoot bool,
) {
	// for servers other than ourselves
	if !parseIPv6OrPanic(Conf.PublicIPv6Addr).Equal(ipv6) {
		// MX, A, AAAA, and TXT records may be overridden by the backend
		pr := proxyRecords(ipv6, question)
		if pr != nil {
			out.Answer = append(out.Answer, pr...)
			return
		}
	}

	switch question.Qtype {
	case dns.TypeMX:
		// loopback MX records
		out.Answer = append(out.Answer, &dns.MX{
			Hdr: dns.RR_Header{
				Name:   question.Name,
				Rrtype: dns.TypeMX,
				Class:  dns.ClassINET,
				Ttl:    Conf.DNSTTL,
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
				Ttl:    Conf.DNSTTL,
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
				Ttl:    Conf.DNSTTL,
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
				Ttl:    Conf.DNSTTL,
			},
			Ns: "ns1." + question.Name,
		})
		out.Answer = append(out.Answer, &dns.NS{
			Hdr: dns.RR_Header{
				Name:   question.Name,
				Rrtype: dns.TypeNS,
				Class:  dns.ClassINET,
				Ttl:    Conf.DNSTTL,
			},
			Ns: "ns2." + question.Name,
		})
		// and this is where that domain is
		if ipv4 != nil {
			out.Extra = append(out.Extra, &dns.A{
				Hdr: dns.RR_Header{
					Name:   "ns1." + question.Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    Conf.DNSTTL,
				},
				A: ipv4,
			})
			out.Extra = append(out.Extra, &dns.A{
				Hdr: dns.RR_Header{
					Name:   "ns2." + question.Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    Conf.DNSTTL,
				},
				A: ipv4,
			})
		}
		if ipv6 != nil {
			out.Extra = append(out.Extra, &dns.AAAA{
				Hdr: dns.RR_Header{
					Name:   "ns1." + question.Name,
					Rrtype: dns.TypeAAAA,
					Class:  dns.ClassINET,
					Ttl:    Conf.DNSTTL,
				},
				AAAA: ipv6,
			})
			out.Extra = append(out.Extra, &dns.AAAA{
				Hdr: dns.RR_Header{
					Name:   "ns2." + question.Name,
					Rrtype: dns.TypeAAAA,
					Class:  dns.ClassINET,
					Ttl:    Conf.DNSTTL,
				},
				AAAA: ipv6,
			})
		}
	case dns.TypeSOA:
		if !isRoot {
			break
		}
		out.Answer = append(out.Answer, &dns.SOA{
			Hdr: dns.RR_Header{
				Name:   question.Name,
				Rrtype: dns.TypeSOA,
				Class:  dns.ClassINET,
				Ttl:    Conf.DNSTTL,
			},
			Ns:      "ns1." + question.Name,
			Mbox:    strings.ReplaceAll(Conf.DNSAdminEmail, "@", ".") + ".",
			Serial:  2000010101,  // bogus, but format conforming serial
			Refresh: 1200,        // min recommended value (not used)
			Retry:   Conf.DNSTTL, // (not used)
			Expire:  1209600,     // min recommended value (not used)
			Minttl:  Conf.DNSTTL,
		})
	}
}

var rIPv6Subdomain = regexp.MustCompile(`(?i)^(?:[0-9a-f]{4}-){7}[0-9a-f]{4}$`)

// extract an ipv6 address from a DNS query name
func IPv6Extract(q string) net.IP {
	q = strings.ToLower(q)
	suffix := "." + strings.ToLower(Conf.DNSZone)

	if !strings.HasSuffix(q, suffix) {
		return nil
	}
	q = strings.TrimSuffix(q, suffix)

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

// BUG(jon): re-use proxy logic from recurse
func proxyRecords(dnsServer net.IP, question dns.Question) (r []dns.RR) {
	ctx, cancel := context.WithTimeout(
		context.Background(),
		Conf.DNSPassthroughTimeout.Duration,
	)
	defer cancel()

	backend := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: Conf.DNSPassthroughTimeout.Duration,
			}
			return d.DialContext(
				ctx,
				network,
				fmt.Sprintf("[%s]:53", dnsServer),
			)
		},
	}

	switch question.Qtype {
	case dns.TypeMX:
		backendRecords, _ := backend.LookupMX(ctx, question.Name)
		for _, backendRecord := range backendRecords {
			r = append(r, &dns.MX{
				Hdr: dns.RR_Header{
					Name:   question.Name,
					Rrtype: dns.TypeMX,
					Class:  dns.ClassINET,
					Ttl:    Conf.DNSTTL,
				},
				Mx:         backendRecord.Host,
				Preference: backendRecord.Pref,
			})
		}
	case dns.TypeA:
		backendRecords, _ := backend.LookupIP(ctx, "ip4", question.Name)
		for _, backendRecord := range backendRecords {
			r = append(r, &dns.A{
				Hdr: dns.RR_Header{
					Name:   question.Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    Conf.DNSTTL,
				},
				A: backendRecord,
			})
		}
	case dns.TypeAAAA:
		backendRecords, _ := backend.LookupIP(ctx, "ip6", question.Name)
		for _, backendRecord := range backendRecords {
			r = append(r, &dns.AAAA{
				Hdr: dns.RR_Header{
					Name:   question.Name,
					Rrtype: dns.TypeAAAA,
					Class:  dns.ClassINET,
					Ttl:    Conf.DNSTTL,
				},
				AAAA: backendRecord,
			})
		}
	case dns.TypeTXT:
		backendRecords, _ := backend.LookupTXT(ctx, question.Name)
		if len(backendRecords) == 0 {
			return nil
		}
		r = []dns.RR{
			&dns.TXT{
				Hdr: dns.RR_Header{
					Name:   question.Name,
					Rrtype: dns.TypeTXT,
					Class:  dns.ClassINET,
					Ttl:    Conf.DNSTTL,
				},
				Txt: backendRecords,
			},
		}
	}

	return r
}
