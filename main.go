package main

func main() {
	err := LoadConfig("/etc/uvhost.toml")
	if err != nil {
		panic(err)
	}

	tf := SetupTableFlip()

	StartAbuseDB()
	StartDNS(tf)
	StartRecurse(tf)
	go ServeInfo(tf)
	go Proxy(tf)

	tf.Run()
}
