package main

import (
	"errors"
	"io"
	"log"
	"net"
	"sync"
	"time"
)

// ErrNoHost indicates that a host could not be identified
var ErrNoHost = errors.New("a hostname could not be identified")

type Conn struct {
	*net.TCPConn
	preview        [MaxLookahead]byte
	previewPointer int
}

func NewConn(c *net.TCPConn) Conn {
	return Conn{TCPConn: c}
}

func (c Conn) DialBackend() (*net.TCPConn, error) {
	host, err := c.identifyHost()
	if err != nil {
		return nil, err
	}

	backendIP, err := IPv6Lookup(host)
	if err != nil {
		return nil, err
	}

	backendConn, err := net.DialTCP(
		"tcp6",
		c.mappedAddr(),
		&net.TCPAddr{
			IP:   backendIP,
			Port: c.LocalAddr().(*net.TCPAddr).Port,
		},
	)
	if err != nil {
		return nil, err
	}

	return backendConn, nil
}

func (c *Conn) Connect(backendConn *net.TCPConn) {
	defer c.Close()
	defer backendConn.Close()
	defer func() { c.TCPConn = nil }()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		// flush preview buffer
		_, err := backendConn.Write(c.preview[:c.previewPointer])

		// connect client to backend traffic
		if err == nil {
			io.Copy(backendConn, c.TCPConn)
		} else {
			log.Print(err)
		}

		backendConn.CloseWrite()
		wg.Done()
	}()
	go func() {
		// connect backend to client traffic
		io.Copy(c.TCPConn, backendConn)

		c.CloseWrite()
		wg.Done()
	}()

	wg.Wait()
}

func (c Conn) ClientIsIPv4() bool {
	srcIP := c.RemoteAddr().(*net.TCPAddr).IP
	return len(srcIP) == 4
}

func (c *Conn) identifyHost() (host string, err error) {
	c.SetReadDeadline(time.Now().Add(MaxIdentifyTime))
	defer c.SetReadDeadline(time.Time{})

	for c.previewPointer < MaxLookahead {
		readBytes, err := c.Read(c.preview[c.previewPointer:])
		if err != nil {
			return "", err
		}
		c.previewPointer += readBytes

		host, finished := Parse(c.preview[:c.previewPointer])
		if finished {
			if host == "" {
				return "", ErrNoHost
			}
			return host, nil
		}
	}
	return "", ErrNoHost
}

func (c Conn) mappedAddr() *net.TCPAddr {
	srcIP := c.RemoteAddr().(*net.TCPAddr).IP
	srcPort := c.RemoteAddr().(*net.TCPAddr).Port
	return &net.TCPAddr{
		IP:   net.ParseIP(MappedPrefix + srcIP.String()),
		Port: srcPort,
	}
}
