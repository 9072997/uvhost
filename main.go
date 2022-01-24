package main

import (
	"time"
)

const DNSAdminEmail = "Jon@9072997.com"
const DNSTTL = 300
const DNSZone = "withfallback.com."
const DNSPassthroughTimeout = 500 * time.Millisecond
const RecurseMaxTTL = 60 * 60 * 24 // 1 day
const RecurseMinTTL = 60           // 1 minute
const RecurseConcurencyLimit = 2   // per eTLD+1
const RecurseMaxDepth = 7
const RecurseServer = "[2600:3c00::3]"
const RecurseBufferSize = 1500
const MappedPrefix = "2600:3c00:e000:03f5::"
const MaxConnectTime = 5 * time.Second
const MaxIdentifyTime = time.Second
const MaxLookahead = 4096
const MaxLookupTime = 2 * time.Second
const ProxyListenAddr = "127.127.127.127:127"
const PublicIPv4Addr = "45.33.22.33"
const PublicIPv6Addr = "2600:3c00::f03c:92ff:fe4c:684a"
const LogAsStringCutoff = 0.80

func main() {
	StartDNS()
	StartRecurse()
	go ServeInfo()
	Proxy()
}
