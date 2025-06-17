package main

import (
	"fmt"
	"io"
	"strings"
)

const SMTPPort = 25

// read from an io.Reader up to and including the next occurrence of the
// indicated byte
func eatUntil(r io.Reader, b byte) (n int, err error) {
	buff := make([]byte, 1)
	for {
		nn, err := io.ReadFull(r, buff)
		n += nn
		if err != nil {
			return n, err
		}
		if buff[0] == b {
			break
		}
	}
	return n, nil
}

// assuming the reader is currently at the start of an SMTP reply with the
// given code, this will read until the end of that reply.
func eatSMTPReply(r io.Reader, code uint) (n int, err error) {
	codeBytes := make([]byte, 3)
	n, err = io.ReadFull(r, codeBytes)
	if err != nil {
		return n, err
	}
	if string(codeBytes) != fmt.Sprint(code) {
		return n, fmt.Errorf("unexpected SMTP reply: %s (expected %d)",
			codeBytes, code)
	}

	// space indicates this is the last line, hyphen indicates more lines
	codeSeparator := make([]byte, 1)
	nn, err := io.ReadFull(r, codeSeparator)
	n += nn
	if err != nil {
		return n, err
	}
	switch codeSeparator[0] {
	case ' ':
		nn, err := eatUntil(r, '\n')
		n += nn
		return n, err
	case '-':
		nn, err := eatUntil(r, '\n')
		n += nn
		if err != nil {
			return n, err
		}
		return eatSMTPReply(r, code)
	default:
		return n, fmt.Errorf("unexpected character after SMTP code: %s",
			codeSeparator)
	}
}

// eat 220, 250, 250, which should get us to the point where we are ready to
// connect the client to the server.
func EatSMTP(upstream io.Reader) (n int, err error) {
	// eat server welcome banner
	n, err = eatSMTPReply(upstream, 220)
	if err != nil {
		return n, err
	}
	// client sends hello
	// eat server OK
	nn, err := eatSMTPReply(upstream, 250)
	n += nn
	if err != nil {
		return n, err
	}
	// client sends FROM address
	// eat server OK
	nn, err = eatSMTPReply(upstream, 250)
	n += nn
	if err != nil {
		return n, err
	}
	// client sends TO address
	return n, nil
}

// Ideally we would actually look at what the client is sending us, but
// for simplicity we are just going to send all the replies the client
// expects from us all at once.
func StuffSMTP(client io.Writer) (n int, err error) {
	n, err = client.Write([]byte("220 " + strings.TrimSuffix(Conf.DNSZone, ".") + " this is an IPv4 to IPv6 reverse proxy\r\n" +
		"250 I'm blindly accepting that command so we can get to the part where you tell me who you want to talk to\r\n" +
		"250 Once you send me a TO address I will connect you to the real mail server\r\n",
	))
	return n, err
}
