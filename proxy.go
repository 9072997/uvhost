package main

import (
	"net"
)

func Proxy(tf *TableFlip) {
	listener, err := tf.ListenTransparent("tcp", Conf.ProxyListenAddr)
	if err != nil {
		panic(err)
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			Log(err)
			continue
		}
		tcpConn := conn.(*net.TCPConn)
		go handle(NewConn(tcpConn))
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

	if abuseConfidence == ReportedByUs {
		c.Log("AbuseIPDB abuse confidence: ReportedByUs")
	} else {
		c.Log("AbuseIPDB abuse confidence:", abuseConfidence)
	}

	if abuseConfidence >= Conf.AbuseConfidenceThreshold {
		c.Log("blocking connection because of abuse score")
		RecordAbusiveOpen(c)
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
