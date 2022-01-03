package main

import (
	"regexp"
	"strings"
)

var rHTTPIdentifier = regexp.MustCompile(`(?i)^[A-Z]{2,15} /[!-~]* HTTP/[0-9]+\.[0-9]+\r\n`)
var rHTTPHostHeader = regexp.MustCompile(`(?i)^HOST: ?([^:]+)(?::[0-9]+)?$`)
var rTLSIdentifier = regexp.MustCompile(`^\x16\x03[\x00-\x06]`)
var rGenericIdentifier = regexp.MustCompile(`(?i)(?:[0-9a-f]{4}-){7}[0-9a-f]{4}\.` +
	regexp.QuoteMeta(strings.TrimSuffix(DNSZone, ".")))

// attempt to identify the host based on what we have so far. Ex:
//     HOST        FINISHED
// -------------- ----------
// "example.com"   true       The vhost is example.com. Parsing need not continue.
// ""              false      There is not enough information available to identify the vhost yet. Parsing should continue in the next round.
// ""              true       The vhost could not be identified. There is no hope of identification in future rounds. Parsing can stop.
// "example.com"   false      undefined
func Parse(b []byte, log func(...interface{})) (host string, finished bool) {
	log("attempting to identify vhost based on", len(b), "bytes")

	if rHTTPIdentifier.Match(b) {
		// HTTP, based on host header
		log("protocol: http")

		headers := strings.Split(string(b), "\r\n")
		for _, header := range headers {
			// a blank line is how HTTP signals the end of headers
			if header == "" {
				log("end of http headers before HOST header")
				return "", true
			}

			matches := rHTTPHostHeader.FindStringSubmatch(header)
			if len(matches) == 2 {
				host = matches[1]
				return host, true
			}
		}

		// need mode data
		return "", false
	} else if rTLSIdentifier.Match(b) {
		// TLS, based on SNI
		log("protocol: tls")

		tlsInfo, err := ReadClientHello(b)
		if err == nil {
			if tlsInfo.ServerName != "" {
				return tlsInfo.ServerName, true
			} else {
				log("no SNI information")
				return "", true
			}
		}

		// need mode data
		return "", false
	} else if match := rGenericIdentifier.Find(b); match != nil {
		// generic string search (does not work with cnames)
		log("protocol: generic")

		return string(match), true
	}

	log("protocol: no match")
	return "", false
}
