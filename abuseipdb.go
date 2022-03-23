package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"
)

var abuseIPDBCache sync.Map

type abuseIPDBResp struct {
	Data struct {
		AbuseConfidenceScore int `json:"abuseConfidenceScore"`
	} `json:"data"`
}

// this is a race condition, but this whole file is a stop-gap
func init() {
	go func() {
		for {
			// clear cache every 6 hours
			time.Sleep(6 * time.Hour)
			abuseIPDBCache = sync.Map{}
		}
	}()
}

// this is sort of a stop-gap until I write a fancier monitoring system
func AbuseIPDBCheck(ip net.IP, log func(...interface{})) int {
	ipStr := ip.String()
	confidence, inCache := abuseIPDBCache.Load(ipStr)

	if inCache {
		log("AbuseIPDB cache hit")
	} else {
		log("AbuseIPDB cache miss")

		url := fmt.Sprintf(
			"https://api.abuseipdb.com/api/v2/check?key=%s&ipAddress=%s",
			AbuseIPDBKey,
			url.QueryEscape(ipStr),
		)
		resp, err := http.Get(url)
		if err != nil {
			// fail open
			confidence = -1
			abuseIPDBCache.Store(ipStr, confidence)
			log("AbuseIPDB request error:", err)
			return -1
		}

		defer resp.Body.Close()
		var respObj abuseIPDBResp
		err = json.NewDecoder(resp.Body).Decode(&respObj)
		if err != nil {
			// fail open
			confidence = -1
			abuseIPDBCache.Store(ipStr, confidence)
			log("AbuseIPDB decode error:", err)
			return -1
		}

		confidence = respObj.Data.AbuseConfidenceScore
		abuseIPDBCache.Store(ipStr, confidence)
	}

	return confidence.(int)
}

// abusive people annoy me, so let's annoy them back
func Annoy(c Conn) {
	// maximum protocol overhead
	c.SetWriteBuffer(0)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		numBytes, _ := io.Copy(io.Discard, c)
		c.Log("bogo read", numBytes, "bytes")
		wg.Done()
	}()
	go func() {
		numBytes, _ := c.Write([]byte("This IP has been flagged by AbuseIPDB. The connection will be dropped. Reputation is updated every 6 hours."))
		// use a tiny buffer to force many SYN packets
		randBuff := make([]byte, 1000)
	randLoop:
		for {
			rand.Reader.Read(randBuff)
			for _, b := range randBuff {
				i, err := c.Write([]byte{b})
				if err != nil {
					break randLoop
				}
				numBytes += i
				time.Sleep(time.Millisecond)
			}
		}
		c.Log("bogo write", numBytes, "bytes")
		wg.Done()
	}()
	wg.Wait()
}
