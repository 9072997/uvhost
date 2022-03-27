package main

func main() {
	err := LoadConfig("/etc/uvhost.toml")
	if err != nil {
		panic(err)
	}

	StartDNS()
	StartRecurse()
	go ServeInfo()
	Proxy()
}
