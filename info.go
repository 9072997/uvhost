package main

import (
	_ "embed"
	"net"
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

func ServeInfo(tf *TableFlip) {
	readmeHTML := markdown.ToHTML(readmeMD, nil, nil)
	mux := http.NewServeMux()
	mux.Handle("/", staticHTML(readmeHTML))
	mux.Handle("/abuseipdb-verification.html", staticHTML([]byte(Conf.AbuseIPDBVerification)))
	mux.Handle("/abuse", http.HandlerFunc(handleAbuseUI))
	mux.Handle("/hpd/", http.HandlerFunc(handleHPD))

	listenAddr := net.JoinHostPort(Conf.PublicIPv6Addr, "http")
	l, err := tf.Listen("tcp", listenAddr)
	if err != nil {
		panic(err)
	}
	err = http.Serve(l, mux)
	if err != nil {
		panic(err)
	}
}
