package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	expiremap "github.com/nursik/go-expire-map"
	"github.com/vburenin/nsync"
	"golang.org/x/net/publicsuffix"
)

var ErrETLD1ConcurrencyLimit = errors.New("eTLD+1 is already at its query concurrency limit")
var ErrNoETLDNS = errors.New("could not find eTLD nameserver")
var ErrMaxDepthExceeded = errors.New("exceeded maximum recursion depth")
var ErrNoNS = errors.New("no name servers found")
var nsCache = expiremap.New() // used by lookupNS()
var recursionLimiter sync.Map // used by authority()

type nsResp struct {
	ns            []string
	authoritative bool
}

func StartRecurse(tf *TableFlip) {
	go serveRecurseMode("udp", tf)
	go serveRecurseMode("tcp", tf)
}

func serveRecurseMode(mode string, tf *TableFlip) {
	mux := dns.NewServeMux()

	// attach request handler func
	mux.HandleFunc(".", recurseMode(mode).handle)

	// also answer requests for the main zone
	mux.HandleFunc(Conf.DNSZone, HandleMainZone)

	listenAddr := net.JoinHostPort(Conf.PublicIPv4Addr, "53")
	var s dns.Server
	switch mode {
	case "udp":
		l, err := tf.ListenPacket(mode, listenAddr)
		if err != nil {
			panic(fmt.Sprintf("failed to listen on UDP: %v", err))
		}
		s = dns.Server{
			PacketConn: l,
			Handler:    mux,
			UDPSize:    int(Conf.DNSBufferSize),
		}
	case "tcp":
		l, err := tf.Listen("tcp", listenAddr)
		if err != nil {
			panic(fmt.Sprintf("failed to listen on TCP: %v", err))
		}
		s = dns.Server{
			Listener: l,
			Handler:  mux,
		}
	}

	err := s.ActivateAndServe()
	panic(err)
}

func lookupNS(
	ctx context.Context,
	host string,
	dnsServer string,
	mode string,
	log func(...interface{}),
) (nameServers []string, authoritative bool, err error) {
	// short-circuit DNS resolution of the nameserver for *.withfallback.com
	ip := IPv6Extract(dnsServer)
	if ip != nil {
		dnsServer = "[" + ip.String() + "]"
	}

	// check if response is in cache
	cacheKey := [2]string{host, dnsServer}
	cacheEntry, inCache := nsCache.Get(cacheKey)
	if inCache {
		cacheEntry := cacheEntry.(nsResp)
		log(dnsServer+"[cache]>", host)
		// there is a race condition here, but this is only used for logging
		// so I don't care
		ttl := nsCache.GetTTL(cacheKey) / int64(time.Second)
		for _, nameServer := range cacheEntry.ns {
			log(fmt.Sprintf("NS: %s TTL=%d", nameServer, ttl))
		}
		if cacheEntry.authoritative {
			log("authoritative")
		}

		return cacheEntry.ns, cacheEntry.authoritative, nil
	} else {
		log(dnsServer+"["+mode+"]>", host)
	}

	client := &dns.Client{
		Net: mode,
	}
	query := new(dns.Msg)
	query.SetQuestion(host, dns.TypeNS)

	if dnsServer == Conf.RecurseServer {
		query.RecursionDesired = true
	}

	resp, _, err := client.ExchangeContext(ctx, query, dnsServer+":53")
	if err != nil {
		return nil, false, err
	}

	// if response was truncated, retry over TCP
	if resp.Truncated && mode != "tcp" {
		return lookupNS(ctx, host, dnsServer, "tcp", log)
	}

	if resp.Rcode != dns.RcodeSuccess {
		return nil, false, fmt.Errorf("unexpected rcode: %v", resp.Rcode)
	}

	// prefer NS section, fall back to Answer, fall back to Extra
	ttl := uint32(Conf.RecurseMaxTTL)
	for _, section := range [][]dns.RR{resp.Ns, resp.Answer, resp.Extra} {
		for _, record := range section {
			if nsRecord, isNS := record.(*dns.NS); isNS {
				log(fmt.Sprintf("NS: %s TTL=%d", nsRecord.Ns, nsRecord.Hdr.Ttl))
				nameServers = append(nameServers, nsRecord.Ns)
				if nsRecord.Hdr.Ttl < ttl {
					ttl = nsRecord.Hdr.Ttl
				}
			}
		}
		if len(nameServers) > 0 {
			// if we got some servers in this section, don't fallback
			break
		}
	}
	if resp.Authoritative {
		log("authoritative")
	}

	// save to cache
	if ttl < Conf.RecurseMinTTL {
		ttl = Conf.RecurseMinTTL
	}
	cacheEntry = nsResp{nameServers, resp.Authoritative}
	nsCache.Set(cacheKey, cacheEntry, time.Second*time.Duration(ttl))

	return nameServers, resp.Authoritative, nil
}

// return the hostname of the authoritative name servers for a domain
func authority(
	ctx context.Context,
	host string,
	log func(...interface{}),
) (string, error) {
	// acquire semaphore for eTLD+1. This prevents infinite recursion and
	// limits DoS opportunities. errors share the "" semaphore.
	etld1, _ := publicsuffix.EffectiveTLDPlusOne(
		strings.Trim(dns.CanonicalName(host), "."),
	)
	semaphore, _ := recursionLimiter.LoadOrStore(
		etld1,
		nsync.NewSemaphore(Conf.RecurseConcurrencyLimit),
	)
	// if we spend too much time waiting on the lock, timeout
	ctxDeadline, ctxHasDeadline := ctx.Deadline()
	var maxWaitTime time.Duration
	if ctxHasDeadline {
		maxWaitTime = time.Until(ctxDeadline)
	} else {
		maxWaitTime = Conf.MaxLookupTime.Duration
	}
	gotLock := semaphore.(*nsync.Semaphore).TryAcquireTimeout(maxWaitTime)
	if !gotLock {
		return "", ErrETLD1ConcurrencyLimit
	}
	defer semaphore.(*nsync.Semaphore).Release()

	// bootstrap things by querying a recursive server for the eTLD server
	suffix, _ := publicsuffix.PublicSuffix(strings.Trim(host, "."))
	tldNS, _, err := lookupNS(
		ctx,
		suffix+".",
		Conf.RecurseServer,
		"udp",
		log,
	)
	if err != nil {
		return "", err
	}
	if len(tldNS) == 0 {
		return "", ErrNoETLDNS
	}
	// BUG(jon): we don't try multiple nameservers
	responsibleNameServer := tldNS[0]
	eTLD1, _ := publicsuffix.EffectiveTLDPlusOne(strings.Trim(host, "."))
	eTLD1 += "."

	i := 0
	for {
		i++
		if i > Conf.RecurseMaxDepth {
			return "", ErrMaxDepthExceeded
		}

		// do DNS lookup
		var nameServers []string
		var authoritative bool
		if i == 1 && host != eTLD1 {
			// trigger special cache-friendly behavior at the eTLD+1 level
			// so as not to hammer the TLD servers.
			nameServers, _, err = lookupNS(
				ctx,
				eTLD1,
				responsibleNameServer,
				"udp",
				log,
			)
		} else {
			nameServers, authoritative, err = lookupNS(
				ctx,
				host,
				responsibleNameServer,
				"udp",
				log,
			)
		}
		if err != nil {
			return "", err
		}

		next := nextNameServer(nameServers)
		if next == "" {
			if authoritative {
				// if this server has the authority to tell us there are no
				// name servers at this level, then it is the name server
				// for this level
				break
			} else {
				return "", ErrNoNS
			}
		}
		responsibleNameServer = next
		log("switching to nameserver", responsibleNameServer)

		if authoritative {
			break
		}
	}

	// at this point responsibleNameServer should either be nil (if the
	// domain is delegated to a "normal" nameserver) or the authoritative
	// name server in charge of the specified domain.
	return responsibleNameServer, nil
}

// BUG(jon): we don't try multiple nameservers
func nextNameServer(nameServers []string) string {
	// look for "*.withfallback.com" name servers
	for _, nameServer := range nameServers {
		ip := IPv6Extract(nameServer)
		// if we found one, do all future queries using it
		if ip != nil {
			return nameServer
		}
	}
	// if we got here, we didn't find a *.withfallback.com nameserver
	// at this level. That might be because this is not the start of a
	// new zone, or because it was delegated to a non-withfallback
	// server
	if len(nameServers) > 0 {
		return nameServers[0]
	}

	return ""
}

type recurseMode string // "tcp" or "udp"

func (mode recurseMode) handle(resp dns.ResponseWriter, req *dns.Msg) {
	log, printLog := NewLog()
	defer printLog()
	log(FormatDNS(*req))

	ctx, cancel := context.WithTimeout(context.Background(), Conf.MaxLookupTime.Duration)
	defer cancel()

	// this is overwritten for successfully proxied requests
	m := new(dns.Msg).SetReply(req)

	// normal DNS query packets only ever contain a single question, and
	// "who should we forward to" would get complex anr risky if those
	// questions should go to different servers, so we reject packets with
	// multiple questions.
	if req.Opcode == dns.OpcodeQuery && len(req.Question) == 1 {
		q := req.Question[0]
		nameServer, err := authority(ctx, q.Name, log)
		if err == nil {
			ip := IPv6Extract(nameServer)
			if ip == nil {
				// the authority for this query is not *.withfallback.com
				log("refusing query for zone owner:", nameServer)
				m.Authoritative = false
				m.SetRcode(req, dns.RcodeNotAuth)
			} else {
				// proxy the request
				dialAddr := fmt.Sprintf("[%s]:53", ip)
				mFromBackend, _, err := (&dns.Client{
					Net:     string(mode),
					UDPSize: Conf.DNSBufferSize,
				}).ExchangeContext(ctx, req, dialAddr)
				if err == nil {
					m = mFromBackend
				} else {
					log("error while proxying request", err)
					m.SetRcode(req, dns.RcodeServerFailure)
				}
			}
		} else {
			log("error identifying authority", err)
			m.SetRcode(req, dns.RcodeServerFailure)
		}
	} else {
		log("invalid opcode or number of queries")
		m.SetRcode(req, dns.RcodeServerFailure)
	}

	log(FormatDNS(*m))
	resp.WriteMsg(m)
}
