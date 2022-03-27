package main

import (
	"os"
	"time"

	"github.com/BurntSushi/toml"
)

// this is used as an array length, so it has to be compile-time constant
const MaxLookahead = 4096

type Duration struct {
	time.Duration
}

func (d *Duration) UnmarshalText(text []byte) error {
	var err error
	d.Duration, err = time.ParseDuration(string(text))
	return err
}

var Conf struct {
	DNSAdminEmail            string
	DNSTTL                   uint32
	DNSZone                  string
	DNSPassthroughTimeout    Duration
	RecurseMaxTTL            uint32
	RecurseMinTTL            uint32
	RecurseConcurencyLimit   int
	RecurseMaxDepth          int
	RecurseServer            string
	RecurseBufferSize        uint16
	MappedPrefix             string
	MaxConnectTime           Duration
	MaxIdentifyTime          Duration
	MaxLookupTime            Duration
	ProxyListenAddr          string
	PublicIPv4Addr           string
	PublicIPv6Addr           string
	LogAsStringCutoff        float32
	AbuseIPDBKey             string
	AbuseConfidenceThreshold int
	AbuseRecordTime          Duration
	AbuseRecordLength        uint
	AbuseRecordPath          string
}

func LoadConfig(filename string) error {
	tomlData, err := os.ReadFile(filename)
	if err != nil {
		return err
	}
	return toml.Unmarshal(tomlData, &Conf)
}
