package main

import (
	"net"
	"strconv"

	tproxy "github.com/LiamHaworth/go-tproxy"
)

func Proxy() {
	listenAddr := parseAddr(ProxyListenAddr)
	if listenAddr == nil {
		panic("failed to parse listen address")
	}

	listener, err := tproxy.ListenTCP("tcp", listenAddr)
	if err != nil {
		panic(err)
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			Log(err)
			continue
		}
		go handle(NewConn(conn.(*tproxy.Conn).TCPConn))
	}
}

func handle(c Conn) {
	if c.ClientIsIPv6() {
		c.Log("dropping IPv6 Client:", c.RemoteAddr().String())
		c.Close()
		return
	}

	ip := c.RemoteAddr().(*net.TCPAddr).IP
	abuseConfidence := AbuseIPDBCheck(ip, c.Log)
	c.Log("AbuseIPDB abuse confidence:", abuseConfidence)
	if abuseConfidence >= AbuseConfidenceThreshold {
		c.Log("blocking connection because of abuse score")
		Annoy(c)
		c.Close()
		return
	}

	backend, err := c.DialBackend()
	if err != nil {
		c.Close()
		return
	}

	// this will block as long as the connection is open. When it closes it
	// will close both ends of the connection.
	c.Connect(backend)
}

func parseAddr(addrStr string) *net.TCPAddr {
	ipStr, portStr, err := net.SplitHostPort(addrStr)
	if err != nil {
		return nil
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil
	}
	return &net.TCPAddr{
		IP:   ip,
		Port: port,
	}
}
