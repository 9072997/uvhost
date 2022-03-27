package main

import (
	_ "embed"
	"fmt"
	"net/http"

	"github.com/gomarkdown/markdown"
)

type staticHTML []byte

func (h staticHTML) ServeHTTP(resp http.ResponseWriter, req *http.Request) {
	resp.Header().Add("Content-Type", "text/html")
	resp.Write([]byte(h))
}

//go:embed README.md
var readmeMD []byte

var abuseIPDB = []byte("abuseipdb-verification-Y6KrOhDv")

func ServeInfo() {
	readmeHTML := markdown.ToHTML(readmeMD, nil, nil)
	mux := http.NewServeMux()
	mux.Handle("/", staticHTML(readmeHTML))
	mux.Handle("/abuseipdb-verification.html", staticHTML(abuseIPDB))
	listenAddr := fmt.Sprintf("[%s]:http", Conf.PublicIPv6Addr)
	http.ListenAndServe(listenAddr, mux)
}
