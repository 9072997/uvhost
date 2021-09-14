package main

import (
	"regexp"
	"strings"
)

var rHTTPIdentifier = regexp.MustCompile(`(?i)^[A-Za-z]+ /[^\r\n]* HTTP/[0-9]+\.[0-9]+\r\n`)
var rHTTPHostHeader = regexp.MustCompile(`(?i)^HOST: ?([^:]+)(?::[0-9]+)?$`)

// attempt to identify the host based on what we have so far. Ex:
//     HOST        FINISHED
// -------------- ----------
// "example.com"   true       The vhost is example.com. Parsing need not continue.
// ""              false      There is not enough information available to identify the vhost yet. Parsing should continue in the next round.
// ""              true       The vhost could not be identified. There is no hope of identification in future rounds. Parsing can stop.
// "example.com"   false      undefined
func Parse(b []byte) (host string, finished bool) {
	// HTTP, based on host header
	if rHTTPIdentifier.Match(b) {
		headers := strings.Split(string(b), "\r\n")
		for _, header := range headers {
			// a blank line is how HTTP signals the end of headers
			if header == "" {
				break
			}

			matches := rHTTPHostHeader.FindStringSubmatch(header)
			if len(matches) == 2 {
				host = matches[1]
				return host, true
			}
		}
	}

	// TLS, based on SNI
	tlsInfo, err := ReadClientHello(b)
	if err == nil {
		if tlsInfo.ServerName != "" {
			return tlsInfo.ServerName, true
		}
	}

	return "", false
}
