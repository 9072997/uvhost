package main

import (
	"regexp"
	"strings"
)

var rHTTPIdentifier = regexp.MustCompile(`(?i)^[A-Z]{2,15} /[!-~]* HTTP/[0-9]+\.[0-9]+\r?\n`)
var rHTTPHostHeader = regexp.MustCompile(`(?i)^HOST: ?([^:]+)(?::[0-9]+)?$`)
var rTLSIdentifier = regexp.MustCompile(`^\x16\x03[\x00-\x06]`)
var rSMTPIdentifier = regexp.MustCompile(`(?i)^(?:HELO|EHLO) `)
var rSMTPRCPTCommand = regexp.MustCompile(`(?i)\nRCPT TO: *(?:<[!-~]+@([!-~]+)>|[!-~]+@([!-~]+)) *\r?\n`)
var rGenericIdentifier = regexp.MustCompile(`(?i)(?:[0-9a-f]{4}-){7}[0-9a-f]{4}\.` +
	regexp.QuoteMeta(strings.TrimSuffix(DNSZone, ".")))

// attempt to identify the host based on what we have so far. Ex:
//     HOST        FINISHED
// -------------- ----------
// "example.com"   true       The vhost is example.com. Parsing need not continue.
// nil             false      There is not enough information available to identify the vhost yet. Parsing should continue in the next round.
// nil             true       The vhost could not be identified. There is no hope of identification in future rounds. Parsing can stop.
// "example.com"   false      undefined
func Parse(b []byte, portHint uint, log func(...interface{})) (hosts []string, finished bool) {
	log("attempting to identify vhost based on", len(b), "bytes")

	if portHint == SMTPPort && rSMTPIdentifier.Match(b) {
		// SMTP based on host part of TO address
		log("protocol: smtp")

		matches := rSMTPRCPTCommand.FindStringSubmatch(string(b))
		if matches == nil {
			// we are not to the RCPT command yet
			return nil, false
		}

		var rcptDomain string
		if len(matches[1]) > 0 {
			rcptDomain = matches[1]
		} else if len(matches[2]) > 0 {
			rcptDomain = matches[2]
		} else {
			log("empty domain in RCPT command")
			return nil, true
		}

		// spec says we should prefer MX records but fall back to A/AAAA
		hosts, err := IPv6LookupMX(rcptDomain)
		if err != nil {
			log("error looking up MX records:", err)
		}
		if len(hosts) == 0 {
			log("no suitable MX records; falling back to AAAA")
			hosts = []string{rcptDomain}
		}
		return hosts, true

	} else if rHTTPIdentifier.Match(b) {
		// HTTP, based on host header
		log("protocol: http")

		headers := strings.Split(string(b), "\r\n")
		for _, header := range headers {
			// a blank line is how HTTP signals the end of headers
			if header == "" {
				log("end of http headers before HOST header")
				return nil, true
			}

			matches := rHTTPHostHeader.FindStringSubmatch(header)
			if len(matches) == 2 {
				host := matches[1]
				return []string{host}, true
			}
		}

		// need mode data
		return nil, false
	} else if rTLSIdentifier.Match(b) {
		// TLS, based on SNI
		log("protocol: tls")

		tlsInfo, err := ReadClientHello(b)
		if err == nil {
			if tlsInfo.ServerName != "" {
				host := tlsInfo.ServerName
				return []string{host}, true
			} else {
				log("no SNI information")
				return nil, true
			}
		}

		// need mode data
		return nil, false
	} else if match := rGenericIdentifier.Find(b); match != nil {
		// generic string search (does not work with cnames)
		log("protocol: generic")

		host := string(match)
		return []string{host}, true
	}

	log("protocol: no match")
	return nil, false
}
