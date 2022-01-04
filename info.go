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

func ServeInfo() {
	readmeHTML := markdown.ToHTML(readmeMD, nil, nil)
	http.Handle("/", staticHTML(readmeHTML))
	listenAddr := fmt.Sprintf("[%s]:http", PublicIPv6Addr)
	http.ListenAndServe(listenAddr, nil)
}
