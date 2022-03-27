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
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const ReportedByUs = 101 // confidence score

var abuseIPDBCache sync.Map
var abusePatterns sync.Map
var knownBadPatterns atomic.Value

type KnownAbusePattern struct {
	Hash     string
	Category string
	Comment  string
}

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

		apiURL := fmt.Sprintf(
			"https://api.abuseipdb.com/api/v2/check?key=%s&ipAddress=%s",
			Conf.AbuseIPDBKey,
			url.QueryEscape(ipStr),
		)
		resp, err := http.Get(apiURL)
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

func AbuseIPDBReport(
	ip net.IP,
	pattern KnownAbusePattern,
	log func(...interface{}),
) {
	ipStr := ip.String()

	// BUG(Jon): we should use something like Swap() to avoid a race
	// condition here, but AbuseIPDB de-bounces for us, to its ok.
	// https://github.com/golang/go/issues/51972
	confidence, inCache := abuseIPDBCache.Load(ipStr)
	// refuse future connections until cache expiry
	abuseIPDBCache.Store(ipStr, ReportedByUs)

	if inCache && confidence.(int) == ReportedByUs {
		log("this IP has already been reported")
		return
	}

	log("reporting", ipStr, "for pattern", pattern.Hash)
	apiURL := fmt.Sprintf(
		"https://api.abuseipdb.com/api/v2/report?key=%s",
		Conf.AbuseIPDBKey,
	)
	resp, err := http.PostForm(apiURL, url.Values{
		"ip":         {ipStr},
		"categories": {pattern.Category},
		"comment":    {pattern.Comment},
	})
	if err != nil {
		log("error when submitting abuse report:", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		log("error when submitting abuse report")
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			log(err)
			return
		}
		log(string(body))
	}
}

// record the opening bytes from abusive connections.
func RecordAbusiveOpen(c Conn) {
	// only read for 1 second
	c.SetReadDeadline(time.Now().Add(Conf.AbuseRecordTime.Duration))
	defer c.SetReadDeadline(time.Time{})

	buff := make([]byte, Conf.AbuseRecordLength)
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

	filename := filepath.Join(Conf.AbuseRecordPath, hexHash)
	err = os.WriteFile(filename, buff, 0644)
	if err != nil {
		c.Log(err)
		return
	}

	// if this is a known pattern, also send a report
	pattern, err := CheckAbusiveOpen(buff)
	if err != nil {
		c.Log("error checking for abuse pattern matches:", err)
		return
	}
	if pattern != nil {
		c.Log("pattern is known bad:", pattern.Comment)
		ip := c.RemoteAddr().(*net.TCPAddr).IP
		AbuseIPDBReport(ip, *pattern, c.Log)
	}
}

func CheckAbusiveOpen(buff []byte) (*KnownAbusePattern, error) {
	var patterns []KnownAbusePattern
	patternsIface := knownBadPatterns.Load()
	if patternsIface == nil {
		log, print := NewLog()
		defer print()
		log("reading AbusePatternsFile")

		// read in file as TSV
		contents, err := os.ReadFile(Conf.AbusePatternsFile)
		if err != nil {
			return nil, err
		}
		lines := strings.Split(string(contents), "\n")
		for i, line := range lines {
			fields := strings.SplitN(line, "\t", 3)
			if len(fields) != 3 {
				log("expected 3 fields on line", i, "got", len(fields))
				continue
			}
			patterns = append(patterns, KnownAbusePattern{
				Hash:     fields[0],
				Category: fields[1],
				Comment:  fields[2],
			})
		}
		knownBadPatterns.Store(patterns)
		log("loaded", len(patterns), "known abuse patterns")
	} else {
		patterns = patternsIface.([]KnownAbusePattern)
	}

	hash := md5.Sum(buff)
	hexHash := hex.EncodeToString(hash[:])
	for _, pattern := range patterns {
		if hexHash == pattern.Hash {
			return &pattern, nil
		}
	}
	return nil, nil
}
