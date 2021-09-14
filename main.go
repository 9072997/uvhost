package main

import (
	"log"
	"net"
	"time"

	"github.com/LiamHaworth/go-tproxy"
)

const ListenAddr = "127.127.127.127:127"
const MaxLookahead = 4096
const MaxIdentifyTime = time.Second
const MaxConnectTime = 5 * time.Second
const MaxLookupTime = 2 * time.Second
const MappedPrefix = "ffff::"

func main() {
	listenAddr := net.ParseIP(ListenAddr)
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
			log.Print(err)
			continue
		}
		go handle(NewConn(conn))
	}
}

func handle(c Conn) {
	if !c.ClientIsIPv4() {
		log.Print("Dropping IPv4 Client:", c.RemoteAddr().String())
		c.Close()
		return
	}

	backend, err := c.DialBackend()
	if err != nil {
		log.Print(err)
		c.Close()
		return
	}

	// this will block as long as the connection is open. When it closes it
	// will close both ends of the connection.
	c.Connect(backend)
}
