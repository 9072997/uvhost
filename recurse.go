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

var ErrETLD1ConcurencyLimit = errors.New("eTLD+1 is already at its query concurency limit")
var nsCache = expiremap.New() // used by lookupNS()
var recursionLimiter sync.Map // used by authority()

func StartRecurse() {
	go serveRecurseMode("udp")
	go serveRecurseMode("tcp")
}

func serveRecurseMode(mode string) {
	mux := dns.NewServeMux()

	// attach request handler func
	mux.HandleFunc(".", recurseMode(mode).handle)

	// also answer requests for the main zone
	mux.HandleFunc(DNSZone, HandleMainZone)

	func() {
		err := (&dns.Server{
			Addr:    net.JoinHostPort(PublicIPv4Addr, "53"),
			Net:     mode,
			Handler: mux,
		}).ListenAndServe()
		panic(err)
	}()
}

func lookupNS(
	ctx context.Context,
	host string,
	dnsServer string,
	mode string,
	log func(...interface{}),
) (nameServers []string, err error) {
	// short-circuit DNS resolution of the nameserver for *.withfallback.com
	ip := IPv6Extract(dnsServer)
	if ip != nil {
		dnsServer = "[" + ip.String() + "]"
	}

	// check if response is in cache
	cacheKey := [2]string{host, dnsServer}
	cacheEntry, inCache := nsCache.Get(cacheKey)
	if inCache {
		cacheEntry := cacheEntry.([]string)
		log(dnsServer+"[cache]>", host)
		// there is a race condition here, but this is only used for logging
		// so I don't care
		ttl := nsCache.GetTTL(cacheKey) / int64(time.Second)
		for _, nameServer := range cacheEntry {
			log(fmt.Sprintf("NS: %s TTL=%d", nameServer, ttl))
		}

		return cacheEntry, nil
	} else {
		log(dnsServer+"["+mode+"]>", host)
	}

	client := &dns.Client{
		Net: mode,
	}
	query := new(dns.Msg)
	query.SetQuestion(host, dns.TypeNS)

	if dnsServer == RecurseServer {
		query.RecursionDesired = true
	}

	resp, _, err := client.ExchangeContext(ctx, query, dnsServer+":53")
	if err != nil {
		return nil, err
	}

	// if response was truncated, retry over TCP
	if resp.Truncated && mode != "tcp" {
		return lookupNS(ctx, host, dnsServer, "tcp", log)
	}

	if resp.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("unexpected rcode: %v", resp.Rcode)
	}

	// prefer NS section, fall back to Answer, fall back to Extra
	ttl := uint32(RecurseMaxTTL)
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

	// save to cache
	if ttl < RecurseMinTTL {
		ttl = RecurseMinTTL
	}
	nsCache.Set(cacheKey, nameServers, time.Second*time.Duration(ttl))

	return nameServers, nil
}

// return the hostname of the authoritative name servers for a domain
func authority(
	ctx context.Context,
	host string,
	log func(...interface{}),
) (string, error) {
	// aquire semaphore for eTLD+1. This prevents infinite recursion and
	// limits DoS oppertunities. errors share the "" semaphore.
	etld1, _ := publicsuffix.EffectiveTLDPlusOne(
		strings.Trim(dns.CanonicalName(host), "."),
	)
	semaphore, _ := recursionLimiter.LoadOrStore(
		etld1,
		nsync.NewSemaphore(RecurseConcurencyLimit),
	)
	// if we spend too much time waiting on the lock, timeout
	ctxDeadline, ctxHasDeadline := ctx.Deadline()
	var maxWaitTime time.Duration
	if ctxHasDeadline {
		maxWaitTime = time.Until(ctxDeadline)
	} else {
		maxWaitTime = MaxLookupTime
	}
	gotLock := semaphore.(*nsync.Semaphore).TryAcquireTimeout(maxWaitTime)
	if !gotLock {
		return "", ErrETLD1ConcurencyLimit
	}
	defer semaphore.(*nsync.Semaphore).Release()

	var responsibleNameServer string
	parts := strings.Split(strings.Trim(host, "."), ".")

domainLevels:
	for i := len(parts) - 1; i >= 0; i-- {
		currentHost := strings.Join(parts[i:], ".")
		suffix, _ := publicsuffix.PublicSuffix(currentHost)
		if currentHost == suffix {
			responsibleNameServer = RecurseServer
		}
		currentHost += "."

		// do DNS lookup
		nameServers, err := lookupNS(
			ctx,
			currentHost,
			responsibleNameServer,
			"udp",
			log,
		)
		if err != nil {
			return "", err
		}

		// look for "*.withfallback.com" name servers
		for _, nameServer := range nameServers {
			ip := IPv6Extract(nameServer)
			// if we found one, do all future queries using it
			if ip != nil {
				log("switching to nameserver", nameServer)
				responsibleNameServer = nameServer
				// BUG(jon): we don't try multiple nameservers
				continue domainLevels
			}
		}
		// if we got here, we didn't find a *.withfallback.com nameserver
		// at this level. That might be because this is not the start of a
		// new zone, or because it was deligated to a non-withfallback
		// server
		for _, nameServer := range nameServers {
			log("switching to nameserver", nameServer)
			responsibleNameServer = nameServer
			// BUG(jon): we don't try multiple nameservers
			continue domainLevels
		}
	}

	// at this point responsibleNameServer should either be nil (if the
	// domain is deligated to a "normal" nameserver) or the authoritative
	// name server in charge of the specified domain.
	return responsibleNameServer, nil
}

type recurseMode string // "tcp" or "udp"

func (mode recurseMode) handle(resp dns.ResponseWriter, req *dns.Msg) {
	log, printLog := NewLog()
	defer printLog()
	log(FormatDNS(*req))

	ctx, cancel := context.WithTimeout(context.Background(), MaxLookupTime)
	defer cancel()

	// this is overwritten for successfully proxied requests
	m := new(dns.Msg).SetReply(req)

	// normal DNS query packets only ever contain a single question, and
	// "who should we forward to" would get complex anr risky if those
	// questions should go to diffrent servers, so we reject packets with
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
					UDPSize: RecurseBufferSize,
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
