package main

import (
	"context"
	"errors"
	"net"
)

var ErrUnknownHost = errors.New("an IPv6 address could not be found for the given hostname")

func IPv6Lookup(host string) (net.IP, error) {
	ctx, cancel := context.WithTimeout(context.Background(), MaxLookupTime)
	defer cancel()

	// do DNS lookup
	ips, err := new(net.Resolver).LookupHost(ctx, host)
	if err != nil {
		return net.IP{}, err
	}

	// return first IPv6 address
	for _, ipStr := range ips {
		ip := net.ParseIP(ipStr)
		if len(ip) == 16 {
			return ip, nil
		}
	}

	return net.IP{}, ErrUnknownHost
}
