package main

import (
	"crypto/md5"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	_ "modernc.org/sqlite"
)

const ReportedByUs = 101 // confidence score

var abuseDB *sql.DB

type AbusePatternDB struct {
	Hash      string
	Category  string
	Comment   string
	Confirmed bool
	FirstSeen int64
	LastSeen  int64
	LastIP    string
	Count     int
	ExpiresAt int64
}

type IPDB struct {
	IP              string
	FirstSeen       int64
	LastSeen        int64
	ExpiresAt       int64
	ReputationScore int
}

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

func StartAbuseDB() error {
	var err error
	abuseDB, err = sql.Open("sqlite", Conf.AbuseDBPath)
	if err != nil {
		return fmt.Errorf("failed to open abuse database: %w", err)
	}
	_, err = abuseDB.Exec(`
		CREATE TABLE IF NOT EXISTS abuseipdb_cache (
			ip TEXT PRIMARY KEY,
			confidence INTEGER,
			updated_at INTEGER
		);
		CREATE TABLE IF NOT EXISTS patterns (
			hash TEXT PRIMARY KEY,
			category TEXT,
			comment TEXT,
			confirmed INTEGER,
			first_seen INTEGER,
			last_seen INTEGER,
			last_ip TEXT,
			count INTEGER,
			expires_at INTEGER
		);
		CREATE INDEX IF NOT EXISTS idx_patterns_last_ip ON patterns(last_ip);
	`)
	if err != nil {
		return fmt.Errorf("failed to create abuse database tables: %w", err)
	}

	// Start cleanup goroutine
	go func() {
		for {
			CleanupAbuseDB()
			time.Sleep(5 * time.Minute)
		}
	}()

	return nil
}

func CleanupAbuseDB() {
	now := time.Now().Unix()
	ipExpire := now - int64(Conf.AbuseIPExpire.Duration.Seconds())
	abuseDB.Exec("DELETE FROM abuseipdb_cache WHERE updated_at < ?", ipExpire)
	abuseDB.Exec("DELETE FROM patterns WHERE confirmed = 0 AND expires_at < ?", now)
}

// AbuseIPDBCheck checks the abuse confidence score for an IP using the database cache.
func AbuseIPDBCheck(ip net.IP, log func(...interface{})) int {
	ipStr := ip.String()
	var confidence int
	var updatedAt int64

	// Check DB cache
	row := abuseDB.QueryRow("SELECT confidence, updated_at FROM abuseipdb_cache WHERE ip = ?", ipStr)
	err := row.Scan(&confidence, &updatedAt)
	now := time.Now().Unix()
	ipExpire := Conf.AbuseIPExpire.Duration.Seconds()
	cacheValid := err == nil && now-updatedAt < int64(ipExpire)

	if cacheValid {
		log("AbuseIPDB DB cache hit")
		return confidence
	}

	log("AbuseIPDB DB cache miss")
	apiURL := fmt.Sprintf(
		"https://api.abuseipdb.com/api/v2/check?key=%s&ipAddress=%s",
		Conf.AbuseIPDBKey,
		url.QueryEscape(ipStr),
	)
	resp, err := http.Get(apiURL)
	if err != nil {
		// fail open
		confidence = -1
		_, _ = abuseDB.Exec(`
			INSERT OR REPLACE INTO abuseipdb_cache (
				ip,
				confidence,
				updated_at
			) VALUES (?, ?, ?)
		`, ipStr, confidence, now)
		log("AbuseIPDB request error:", err)
		return -1
	}
	defer resp.Body.Close()

	var respObj abuseIPDBResp
	err = json.NewDecoder(resp.Body).Decode(&respObj)
	if err != nil {
		confidence = -1
		_, _ = abuseDB.Exec(`
			INSERT OR REPLACE INTO abuseipdb_cache (
				ip,
				confidence,
				updated_at
			) VALUES (?, ?, ?)
		`, ipStr, confidence, now)
		log("AbuseIPDB decode error:", err)
		return -1
	}

	confidence = respObj.Data.AbuseConfidenceScore
	_, _ = abuseDB.Exec(`
		INSERT OR REPLACE INTO abuseipdb_cache (
			ip,
			confidence,
			updated_at
		) VALUES (?, ?, ?)
	`, ipStr, confidence, now)
	return confidence
}

// AbuseIPDBReport reports an IP for abuse and updates the database cache.
func AbuseIPDBReport(
	ip net.IP,
	pattern KnownAbusePattern,
	log func(...interface{}),
) {
	ipStr := ip.String()

	// Check if already reported
	var confidence int
	row := abuseDB.QueryRow("SELECT confidence FROM abuseipdb_cache WHERE ip = ?", ipStr)
	err := row.Scan(&confidence)
	if err == nil && confidence == ReportedByUs {
		log("this IP has already been reported")
		return
	}

	// Set cache to reported
	now := time.Now().Unix()
	_, _ = abuseDB.Exec(`
		INSERT OR REPLACE INTO abuseipdb_cache (
			ip,
			confidence,
			updated_at
		) VALUES (?, ?, ?)
	`, ipStr, ReportedByUs, now)

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

	// Check if pattern is confirmed
	pattern, err := GetPatternByHash(hexHash)
	if err != nil {
		c.Log("db error:", err)
		return
	}
	if pattern != nil && pattern.Confirmed {
		c.Log("client sent confirmed bad pattern:", hexHash)
		ip := c.RemoteAddr().(*net.TCPAddr).IP
		AbuseIPDBReport(ip, KnownAbusePattern{
			Hash:     pattern.Hash,
			Category: pattern.Category,
			Comment:  pattern.Comment,
		}, c.Log)
		return
	}

	// Not confirmed, check IP reputation
	ip := c.RemoteAddr().(*net.TCPAddr).IP
	rep := AbuseIPDBCheck(ip, c.Log)
	if rep >= 90 { // bad reputation
		c.Log("bad reputation IP", ip.String(), "sent new pattern", hexHash)
		// Limit unconfirmed patterns per IP
		count, err := CountUnconfirmedPatternsByIP(ip.String())
		if err != nil {
			c.Log("db error:", err)
			return
		}
		if count >= Conf.AbusePatternsPerIP {
			c.Log("too many unconfirmed patterns from this IP")
			return
		}
		// Insert or update pattern
		if err := UpsertUnconfirmedPattern(hexHash, ip.String()); err != nil {
			c.Log("db error:", err)
		}
	}
}

func CheckAbusiveOpen(buff []byte) (*KnownAbusePattern, error) {
	hash := md5.Sum(buff)
	hexHash := hex.EncodeToString(hash[:])

	row := abuseDB.QueryRow(`
		SELECT
			hash,
			category,
			comment
		FROM patterns
		WHERE hash = ? AND confirmed = 1
	`, hexHash)
	var pattern KnownAbusePattern
	err := row.Scan(&pattern.Hash, &pattern.Category, &pattern.Comment)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &pattern, nil
}

// DB helpers for patterns
func GetPatternByHash(hash string) (*AbusePatternDB, error) {
	row := abuseDB.QueryRow(`
		SELECT
			hash,
			category,
			comment,
			confirmed,
			first_seen,
			last_seen,
			last_ip,
			count,
			expires_at
		FROM patterns
		WHERE hash = ?
	`, hash)
	var p AbusePatternDB
	var confirmed int
	err := row.Scan(
		&p.Hash,
		&p.Category,
		&p.Comment,
		&confirmed,
		&p.FirstSeen,
		&p.LastSeen,
		&p.LastIP,
		&p.Count,
		&p.ExpiresAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	p.Confirmed = confirmed != 0
	return &p, nil
}

func CountUnconfirmedPatternsByIP(ip string) (int, error) {
	row := abuseDB.QueryRow("SELECT COUNT(*) FROM patterns WHERE confirmed = 0 AND last_ip = ?", ip)
	var count int
	if err := row.Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}

func UpsertUnconfirmedPattern(hash, ip string) error {
	now := time.Now()
	exp := now.Add(Conf.AbusePatternExpire.Duration)
	_, err := abuseDB.Exec(`
		INSERT INTO patterns (
			hash, category, comment, confirmed, first_seen, last_seen, last_ip, count, expires_at
		) VALUES (
			?, '', '', 0, ?, ?, ?, 1, ?
		)
		ON CONFLICT(hash) DO UPDATE SET
			last_seen = excluded.last_seen,
			last_ip = excluded.last_ip,
			count = patterns.count + 1,
			expires_at = excluded.expires_at
	`, hash, now.Unix(), now.Unix(), ip, exp.Unix())
	return err
}
