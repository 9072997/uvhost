package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// LogEntry represents a status change event.
type LogEntry struct {
	Time   time.Time
	Status string // "up" or "down"
}

// Log holds the in-memory log of status changes.
type Log struct {
	sync.Mutex
	Entries    []LogEntry
	LastStatus string
}

func (l *Log) Add(status string) {
	l.Lock()
	defer l.Unlock()
	if l.LastStatus == status {
		return
	}
	l.Entries = append(l.Entries, LogEntry{Time: time.Now(), Status: status})
	l.LastStatus = status
}

func (l *Log) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	l.Lock()
	defer l.Unlock()
	fmt.Fprintf(w, "<html><body><h1>Status Log</h1><ul>")
	for _, entry := range l.Entries {
		fmt.Fprintf(w, "<li>%s: %s</li>", entry.Time.Format(time.RFC3339), entry.Status)
	}
	fmt.Fprintf(w, "</ul></body></html>")
}

var httpIPv4 = &http.Client{
	Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// Force IPv4 by always using "tcp4"
			return (&net.Dialer{
				Timeout: 1 * time.Second,
			}).DialContext(ctx, "tcp4", addr)
		},
	},
}

// getIPv6 gets the public IPv6 address.
func getIPv6() (string, error) {
	resp, err := http.Get("http://v6.ipv6-test.com/api/myip.php")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	ip := strings.TrimSpace(string(data))
	if net.ParseIP(ip) == nil || !strings.Contains(ip, ":") {
		return "", fmt.Errorf("invalid IPv6: %q", ip)
	}
	return ip, nil
}

// expandIPv6 expands an IPv6 address to full form.
func expandIPv6(ip string) (string, error) {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return "", fmt.Errorf("invalid IPv6: %q", ip)
	}
	parsed = parsed.To16()
	if parsed == nil {
		return "", fmt.Errorf("not IPv6: %q", ip)
	}
	// Format as 8 groups of 4 hex digits
	parts := make([]string, 8)
	for i := 0; i < 8; i++ {
		parts[i] = fmt.Sprintf("%04x", big.NewInt(0).SetBytes(parsed[i*2:i*2+2]).Uint64())
	}
	return strings.Join(parts, "-"), nil
}

// trickleHandler writes 30KB over 30 seconds (1KB/s).
func trickleHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", "30000")
	flusher, _ := w.(http.Flusher)
	buf := make([]byte, 1000)
	for i := range buf {
		buf[i] = byte(i % 256)
	}
	for i := 0; i < 30; i++ {
		if _, err := w.Write(buf); err != nil {
			return
		}
		if flusher != nil {
			flusher.Flush()
		}
		time.Sleep(1 * time.Second)
	}
}

// checkTrickle checks the trickle endpoint.
func checkTrickle(url string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}
	resp, err := httpIPv4.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("bad status: %s", resp.Status)
	}
	want := 30000
	got := 0
	buf := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(buf)
		got += n
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
	}
	if got != want {
		return fmt.Errorf("expected %d bytes, got %d", want, got)
	}
	return nil
}

// monitor continuously checks the endpoint and logs status changes.
func monitor(url string, log *Log) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		err := checkTrickle(url)
		if err != nil {
			log.Add("down")
		} else {
			log.Add("up")
		}
		<-ticker.C
	}
}

func main() {
	ipv6, err := getIPv6()
	if err != nil {
		log.Fatalf("Failed to get IPv6: %v", err)
	}
	expanded, err := expandIPv6(ipv6)
	if err != nil {
		log.Fatalf("Failed to expand IPv6: %v", err)
	}
	withfallback := expanded + ".withfallback.com"
	trickleURL := fmt.Sprintf("http://%s/trickle", withfallback)
	log.Printf("Monitoring: %s", trickleURL)

	logMem := &Log{}
	go monitor(trickleURL, logMem)

	http.HandleFunc("/trickle", trickleHandler)
	http.Handle("/log", logMem)

	log.Printf("Serving trickle endpoint at %s", trickleURL)
	log.Printf("Serving log at /log")
	if err := http.ListenAndServe(":http", nil); err != nil {
		log.Fatalf("ListenAndServe: %v", err)
	}
}
