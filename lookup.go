package main

import (
	"context"
	"net"
)

func IPv6Lookup(host string) ([]net.IP, error) {
	ctx, cancel := context.WithTimeout(context.Background(), MaxLookupTime)
	defer cancel()

	// do DNS lookup
	ips, err := net.DefaultResolver.LookupHost(ctx, host)
	if err != nil {
		return nil, err
	}

	// return first IPv6 address
	var ipv6s []net.IP
	for _, ipStr := range ips {
		ip := net.ParseIP(ipStr)
		if ip.To4() == nil {
			ipv6s = append(ipv6s, ip)
		}
	}

	return ipv6s, nil
}

// return the hostname of the mail servers for a domain
func IPv6LookupMX(host string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), MaxLookupTime)
	defer cancel()

	// do DNS lookup
	mxRecords, err := net.DefaultResolver.LookupMX(ctx, host)
	if err != nil {
		return nil, err
	}

	// return records with an IPv6 address
	var hosts []string
	for _, r := range mxRecords {
		ips, _ := IPv6Lookup(r.Host)
		if len(ips) != 0 {
			hosts = append(hosts, r.Host)
		}
	}

	return hosts, nil
}
