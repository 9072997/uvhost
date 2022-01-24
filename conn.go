package main

import (
	"errors"
	"io"
	"net"
	"reflect"
	"runtime"
	"strconv"
	"sync"
	"time"
)

// ErrNoHost indicates that a host could not be identified
var ErrNoHost = errors.New("a hostname could not be identified")
var ErrNoV6Addr = errors.New("an IPv6 address could not be found for the given hostname")

type Conn struct {
	*net.TCPConn
	preview        [MaxLookahead]byte
	previewPointer int
	eater          func(io.Reader) (int, error)

	Log      func(...interface{})
	printLog func()
}

func NewConn(tcpConn *net.TCPConn) Conn {
	c := Conn{TCPConn: tcpConn}
	c.Log, c.printLog = NewLog()
	c.Log(
		"incoming connection:",
		c.TCPConn.RemoteAddr(),
		"->",
		c.TCPConn.LocalAddr(),
	)
	return c
}

func (c *Conn) Close(i ...interface{}) {
	c.Log("closing client side connection")

	c.printLog()

	c.TCPConn.Close()
	c.TCPConn = nil
}

func (c *Conn) DialBackend() (*net.TCPConn, error) {
	hosts, err := c.identifyHosts()
	if err != nil {
		c.Log("failed to identify vhost in", c.previewPointer, "bytes:", err)
		c.Log(c.preview[:c.previewPointer])
		return nil, err
	}
	c.Log("identified", len(hosts), "possible vhosts")

	var topLevelErr error
	for _, host := range hosts {
		c.Log("trying vhost:", host)

		backendIPs, err := IPv6Lookup(host)
		if err != nil {
			c.Log(err)
			topLevelErr = err
			continue
		}
		if len(backendIPs) == 0 {
			c.Log("no IPv6 addresses for", host)
			topLevelErr = ErrNoV6Addr
			continue
		}
		for _, backendIP := range backendIPs {
			backendAddr := &net.TCPAddr{
				IP:   backendIP,
				Port: c.LocalAddr().(*net.TCPAddr).Port,
			}
			c.Log("dialing backend:", c.mappedAddr(), "->", backendAddr)
			backendConn, err := (&net.Dialer{
				Timeout:   MaxConnectTime,
				LocalAddr: c.mappedAddr(),
			}).Dial(
				"tcp6",
				backendAddr.String(),
			)
			if err != nil {
				c.Log(err)
				topLevelErr = err
				continue
			}

			c.Log("backend connection established")
			return backendConn.(*net.TCPConn), nil
		}
	}

	return nil, topLevelErr
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
		// for some protocols (ex: SMTP) we have to start speeking to know
		// who to dial. If that happened, we need to "eat" the stuff the
		// server is going to send that we already sent. This serves a
		// similar function to the preview buffer.
		if c.eater != nil {
			c.Log("triggering eater:", functionName(c.eater))
			bytes, err := c.eater(backendConn)
			if err != nil {
				c.Log(err)
				c.CloseWrite()
				wg.Done()
				return
			}
			c.Log("ate", bytes, "bytes from server")
		}

		// connect backend to client traffic
		bytes, err := io.Copy(c.TCPConn, backendConn)
		c.Log("finished forwarding", bytes, "additional bytes from backend")
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

func (c *Conn) identifyHosts() (hosts []string, err error) {
	c.SetReadDeadline(time.Now().Add(MaxIdentifyTime))
	defer c.SetReadDeadline(time.Time{})

	// if there is an error, you just don't get a port hint
	_, portHintStr, _ := net.SplitHostPort(c.LocalAddr().String())
	portHint, _ := strconv.ParseUint(portHintStr, 10, 32)
	if portHint == SMTPPort {
		bytes, err := StuffSMTP(c)
		c.Log("stuffed", bytes, "bytes")
		if err != nil {
			c.Log(err)
			return nil, err
		}
		c.eater = EatSMTP
	}

	for c.previewPointer < MaxLookahead {
		readBytes, err := c.Read(c.preview[c.previewPointer:])
		c.Log("got", readBytes, "bytes")
		if err != nil {
			c.Log(err)
			return nil, err
		}
		c.previewPointer += readBytes

		hosts, finished := Parse(
			c.preview[:c.previewPointer],
			uint(portHint),
			c.Log,
		)
		if finished {
			if len(hosts) == 0 {
				return nil, ErrNoHost
			}
			return hosts, nil
		}
	}
	c.Log("MaxLookahead bytes exceeded")
	return nil, ErrNoHost
}

func (c Conn) mappedAddr() *net.TCPAddr {
	srcIP := c.RemoteAddr().(*net.TCPAddr).IP
	srcPort := c.RemoteAddr().(*net.TCPAddr).Port
	return &net.TCPAddr{
		IP:   net.ParseIP(MappedPrefix + srcIP.String()),
		Port: srcPort,
	}
}

func functionName(i interface{}) string {
	return runtime.FuncForPC(reflect.ValueOf(i).Pointer()).Name()
}
