package main

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"
)

var abuseIPDBCache sync.Map
var abusePatterns sync.Map

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

// record the opening bytes from abusive connections.
// BUG(jon): match against these
func RecordAbusiveOpen(c Conn) {
	// only read for 1 second
	c.SetReadDeadline(time.Now().Add(AbuseRecordTime))
	defer c.SetReadDeadline(time.Time{})

	buff := make([]byte, AbuseRecordLength)
	n, err := io.ReadFull(c, buff)
	buff = buff[:n]

	if !errors.Is(err, os.ErrDeadlineExceeded) {
		c.Log(err)
		return
	}
	if len(buff) == 0 {
		c.Log("client did not send data within AbuseRecordTime")
		return
	}

	hash := md5.Sum(buff)
	hexHash := hex.EncodeToString(hash[:])

	_, alreadyDiscovered := abusePatterns.LoadOrStore(hash, struct{}{})
	if alreadyDiscovered {
		c.Log("client sent old pattern:", hexHash)
		return
	}
	c.Log("client sent new pattern:", hexHash)

	filename := filepath.Join(AbuseRecordPath, hexHash)
	err = os.WriteFile(filename, buff, 0644)
	if err != nil {
		c.Log(err)
		return
	}
}
