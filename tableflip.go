package main

import (
	"context"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/cloudflare/tableflip"
)

type TableFlip struct {
	*tableflip.Upgrader
	sync.Mutex
	transparent bool
}

func SetupTableFlip() *TableFlip {
	var tf TableFlip
	var err error
	tf.Upgrader, err = tableflip.New(tableflip.Options{
		UpgradeTimeout: time.Minute,
		PIDFile:        Conf.PIDFile,
		ListenConfig: &net.ListenConfig{
			Control: func(network, address string, c syscall.RawConn) error {
				if !tf.transparent {
					return nil
				}
				// Set the IP_TRANSPARENT option on the listening socket
				var err error
				err = c.Control(func(fd uintptr) {
					err := syscall.SetsockoptInt(
						int(fd),
						syscall.IPPROTO_IP,
						syscall.IP_TRANSPARENT,
						1,
					)
					if err != nil {
						panic(err)
					}
				})
				return err
			},
		},
	})
	if err != nil {
		panic(err)
	}

	return &tf
}

func (tf *TableFlip) Run() {
	// we could use fancy logic to determine when the listeners are ready,
	// but waiting a bit is less error-prone.
	if tf.HasParent() {
		time.Sleep(5 * time.Second)
	}
	Log("Ready for traffic")

	// we haven't crashed yet, so assume we're ready for traffic
	err := tf.Ready()
	if err != nil {
		panic(err)
	}

	// wait for the parent to finish
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	tf.WaitForParent(ctx)

	// set up a signal handler to upgrade the process on SIGHUP
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGHUP)
		for range sig {
			// I frequently forget to chmod +x the binary after building it,
			// so check/do that here.
			selfPath, err := os.Executable()
			if err != nil {
				Log("Error getting executable path:", err)
			} else {
				info, err := os.Stat(selfPath)
				if err != nil {
					Log("Error getting file info:", err)
				} else if info.Mode()&0111 == 0 {
					Log("Missing executable permission for:", selfPath)
					newPerms := info.Mode() | 0111 // add executable permission
					err := os.Chmod(selfPath, newPerms)
					if err != nil {
						Log("Error setting executable permission:", err)
					}
				}
			}

			Log("Received SIGHUP, upgrading process")
			err = tf.Upgrade()
			if err != nil {
				Log("Error upgrading process:", err)
				continue
			}
		}
	}()
	Log("TableFlip is ready to upgrade")

	// block forever (or until we are signaled to upgrade)
	<-tf.Exit()
	Log("TableFlip completed upgrade")
}

func (tf *TableFlip) ListenTransparent(network, address string) (net.Listener, error) {
	tf.Lock()
	tf.transparent = true
	l, err := tf.Upgrader.Listen(network, address)
	tf.transparent = false
	tf.Unlock()
	return l, err
}

func (tf *TableFlip) AddConn(network, address string, conn tableflip.Conn) {
	tf.Lock()
	defer tf.Unlock()
	tf.Upgrader.AddConn(network, address, conn)
}

func (tf *TableFlip) AddFile(name string, file *os.File) {
	tf.Lock()
	defer tf.Unlock()
	tf.Upgrader.AddFile(name, file)
}

func (tf *TableFlip) AddListener(network, address string, ln tableflip.Listener) {
	tf.Lock()
	defer tf.Unlock()
	tf.Upgrader.AddListener(network, address, ln)
}

func (tf *TableFlip) AddPacketConn(network, address string, pc tableflip.PacketConn) {
	tf.Lock()
	defer tf.Unlock()
	tf.Upgrader.AddPacketConn(network, address, pc)
}

func (tf *TableFlip) Conn(network, address string) (net.Conn, error) {
	tf.Lock()
	defer tf.Unlock()
	return tf.Upgrader.Conn(network, address)
}

func (tf *TableFlip) File(name string) (*os.File, error) {
	tf.Lock()
	defer tf.Unlock()
	return tf.Upgrader.File(name)
}

func (tf *TableFlip) Files() ([]*os.File, error) {
	tf.Lock()
	defer tf.Unlock()
	return tf.Upgrader.Files()
}

func (tf *TableFlip) Listen(network, address string) (net.Listener, error) {
	tf.Lock()
	defer tf.Unlock()
	return tf.Upgrader.Listen(network, address)
}

func (tf *TableFlip) ListenPacket(network, address string) (net.PacketConn, error) {
	tf.Lock()
	defer tf.Unlock()
	return tf.Upgrader.ListenPacket(network, address)
}

func (tf *TableFlip) ListenPacketWithCallback(network, address string, cb func(network, addr string) (net.PacketConn, error)) (net.PacketConn, error) {
	tf.Lock()
	defer tf.Unlock()
	return tf.Upgrader.ListenPacketWithCallback(network, address, cb)
}

func (tf *TableFlip) ListenWithCallback(network, address string, cb func(network, addr string) (net.Listener, error)) (net.Listener, error) {
	tf.Lock()
	defer tf.Unlock()
	return tf.Upgrader.ListenWithCallback(network, address, cb)
}

func (tf *TableFlip) Listener(network, address string) (net.Listener, error) {
	tf.Lock()
	defer tf.Unlock()
	return tf.Upgrader.Listener(network, address)
}

func (tf *TableFlip) PacketConn(network, address string) (net.PacketConn, error) {
	tf.Lock()
	defer tf.Unlock()
	return tf.Upgrader.PacketConn(network, address)
}
