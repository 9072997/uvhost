package main

import (
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

// ErrNoHost indicates that a host could not be identified
var ErrNoHost = errors.New("a hostname could not be identified")

type Conn struct {
	*net.TCPConn
	preview        [MaxLookahead]byte
	previewPointer int
	logs           []string
}

func NewConn(tcpConn *net.TCPConn) Conn {
	c := Conn{TCPConn: tcpConn}
	c.Log(
		"incoming connection:",
		c.TCPConn.RemoteAddr(),
		"->",
		c.TCPConn.LocalAddr(),
	)
	return c
}

func (c *Conn) Log(is ...interface{}) {
	var ss []string
	for _, i := range is {
		ss = append(ss, Stringify(i))
	}
	c.logs = append(c.logs, strings.Join(ss, " "))
}

func (c *Conn) Close(i ...interface{}) {
	c.Log("closing client side connection")

	// flush logs
	LogPrinter <- c.logs
	c.logs = nil

	c.TCPConn.Close()
	c.TCPConn = nil
}

func (c *Conn) DialBackend() (*net.TCPConn, error) {
	host, err := c.identifyHost()
	if err != nil {
		c.Log("failed to identify vhost in", c.previewPointer, "bytes:", err)
		c.Log(c.preview[:c.previewPointer])
		return nil, err
	}
	c.Log("vhost:", host)

	backendIP, err := IPv6Lookup(host)
	if err != nil {
		c.Log(err)
		return nil, err
	}

	backendAddr := &net.TCPAddr{
		IP:   backendIP,
		Port: c.LocalAddr().(*net.TCPAddr).Port,
	}
	c.Log("dialing backend:", c.mappedAddr(), "->", backendAddr)
	backendConn, err := net.DialTCP(
		"tcp6",
		c.mappedAddr(),
		backendAddr,
	)
	if err != nil {
		c.Log(err)
		return nil, err
	}

	c.Log("backend connection established")
	return backendConn, nil
}

func (c *Conn) Connect(backendConn *net.TCPConn) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		// flush preview buffer
		bytes, err := backendConn.Write(c.preview[:c.previewPointer])

		// connect client to backend traffic
		if err == nil {
			c.Log("flushed", bytes, "bytes from preview buffer")
			bytes, err := io.Copy(backendConn, c.TCPConn)
			c.Log("finished forwarding", bytes, "additional bytes from client")
			if err != nil {
				c.Log(err)
			}
		} else {
			c.Log("error flushing preview buffer to backend:", err)
		}

		backendConn.CloseWrite()
		wg.Done()
	}()
	go func() {
		// connect backend to client traffic
		bytes, err := io.Copy(c.TCPConn, backendConn)
		c.Log("finished forwarding", bytes, "bytes from backend")
		if err != nil {
			c.Log(err)
		}

		c.CloseWrite()
		wg.Done()
	}()

	wg.Wait()

	c.Log("closing backend connection")
	backendConn.Close()

	// this is self-logging
	c.Close()
}

func (c Conn) ClientIsIPv6() bool {
	srcIP := c.RemoteAddr().(*net.TCPAddr).IP
	return srcIP.To4() == nil
}

func (c *Conn) identifyHost() (host string, err error) {
	c.SetReadDeadline(time.Now().Add(MaxIdentifyTime))
	defer c.SetReadDeadline(time.Time{})

	for c.previewPointer < MaxLookahead {
		readBytes, err := c.Read(c.preview[c.previewPointer:])
		c.Log("got", readBytes, "bytes")
		if err != nil {
			c.Log(err)
			return "", err
		}
		c.previewPointer += readBytes

		host, finished := Parse(c.preview[:c.previewPointer], c.Log)
		if finished {
			if host == "" {
				return "", ErrNoHost
			}
			return host, nil
		}
	}
	c.Log("MaxLookahead bytes exceeded")
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
