package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

var LogPrinter = StartLogPrinter()

// use a single thread and channels to print logs to avoid mixed up output
func StartLogPrinter() chan<- []string {
	c := make(chan []string)
	go func() {
		for batch := range c {
			for _, line := range batch {
				fmt.Println(line)
			}
			fmt.Println()
		}
	}()
	return c
}

func Log(is ...interface{}) {
	var ss []string
	for _, i := range is {
		ss = append(ss, Stringify(i))
	}
	LogPrinter <- []string{strings.Join(ss, " ")}
}

func Stringify(ii interface{}) string {
	switch i := ii.(type) {
	case []byte:
		if len(i) == 0 {
			return "STRING:"
		}
		// huristically guess if this is ascii
		printableChars := 0
		nonprintableChars := 0
		for _, c := range i {
			if 32 <= c && c <= 126 {
				printableChars++
			} else {
				nonprintableChars++
			}
		}
		if nonprintableChars == 0 {
			return "STRING:" + string(i)
		} else if float32(printableChars)/float32(len(i)) > LogAsStringCutoff {
			j, _ := json.Marshal(string(i))
			return "JSON:" + string(j)
		} else {
			return "BASE64:" + base64.StdEncoding.EncodeToString(i)
		}
	default:
		return fmt.Sprint(i)
	}
}
