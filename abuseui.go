package main

import (
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

// Embed templates directory
//
//go:embed templates/*
var templatesFS embed.FS

var templates = template.Must(template.ParseFS(templatesFS, "templates/*.html"))

// handleAbuseUI serves the web interface for abuse patterns.
func handleAbuseUI(w http.ResponseWriter, r *http.Request) {
	// Basic authentication
	username, password, ok := r.BasicAuth()
	usernameMatch := subtle.ConstantTimeCompare([]byte(username), []byte(Conf.AuthUsername)) == 1
	passwordMatch := subtle.ConstantTimeCompare([]byte(password), []byte(Conf.AuthPassword)) == 1
	if !ok || !usernameMatch || !passwordMatch {
		w.Header().Set("WWW-Authenticate", "Basic realm=\"Restricted\"")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if r.Method == http.MethodGet {
		serveAbusePatterns(w)
	} else if r.Method == http.MethodPost {
		editAbusePattern(w, r)
	} else {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleHPD forwards the user to https://hpd.gasmi.net/ with synthesized packet data.
func handleHPD(w http.ResponseWriter, r *http.Request) {
	// Extract hash from the URL path
	hash := strings.TrimPrefix(r.URL.Path, "/hpd/")
	if hash == "" {
		http.Error(w, "Bad Request: Missing hash", http.StatusBadRequest)
		return
	}

	// Query the database for the packet data
	var lastIP string
	var lastPort int
	var data []byte
	err := AbuseDB.QueryRow(`
		SELECT last_ip, last_port, data
		FROM patterns
		WHERE hash = ?
	`, hash).Scan(&lastIP, &lastPort, &data)
	if err != nil {
		log.Println("Error querying database:", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Synthesize the packet with Ethernet and IPv4 headers
	srcIP := net.ParseIP(lastIP)
	if srcIP == nil {
		srcIP = net.IPv4(0, 0, 0, 0)
	}
	srcIP = srcIP.To4()
	dstIP := net.ParseIP(Conf.PublicIPv4Addr)
	if dstIP == nil {
		dstIP = net.IPv4(0, 0, 0, 0)
	}
	dstIP = dstIP.To4()
	ipLen := len(data) + 20 + 20      // Data length + IPv4 header (20 bytes) + TCP header (20 bytes)
	ipl1 := byte(ipLen >> 8)          // Length high byte
	ipl2 := byte(ipLen & 0xFF)        // Length low byte
	dstPort1 := byte(lastPort >> 8)   // Destination port high byte
	dstPort2 := byte(lastPort & 0xFF) // Destination port low byte
	header := []byte{
		// ethernet header
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Destination MAC (dummy)
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Source MAC (dummy)
		0x08, 0x00, // EtherType (IPv4)

		// IPv4 header
		0x45,       // Version and IHL
		0x00,       // Differentiated Services Field
		ipl1, ipl2, // Total Length
		0x00, 0x00, // Identification
		0x00, 0x00, // Flags and Fragment Offset
		0x00,       // Time to Live
		0x06,       // Protocol (TCP)
		0x00, 0x00, // Header Checksum (dummy)
		srcIP[0], srcIP[1], srcIP[2], srcIP[3], // Source IP
		dstIP[0], dstIP[1], dstIP[2], dstIP[3], // Destination IP

		// TCP header
		0x00, 0x00, // Source Port (dummy)
		dstPort1, dstPort2, // Destination Port
		0x00, 0x00, 0x00, 0x00, // Sequence Number (dummy)
		0x00, 0x00, 0x00, 0x00, // Acknowledgment Number (dummy)
		0x50, 0x18, // Header Length and Flags
		0x00, 0x01, // Window Size (dummy)
		0x00, 0x00, // Checksum (dummy)
		0x00, 0x00, // Urgent Pointer (dummy)
	}
	packet := append(header, data...)

	// Convert packet to hex dump
	hexData := strings.ToUpper(hex.EncodeToString(packet))

	// Generate HTML for self-submitting form
	formHTML := fmt.Sprintf(`
		<!DOCTYPE html>
		<html>
		<head>
			<title>Forwarding to HPD</title>
		</head>
		<body>
			<form id="hpdForm" action="https://hpd.gasmi.net/" method="POST">
				<input type="hidden" name="data" value="%s">
			</form>
			<script>
				document.getElementById('hpdForm').submit();
			</script>
		</body>
		</html>
	`, hexData)

	// Write the HTML response
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(formHTML))
}

func serveAbusePatterns(w http.ResponseWriter) {
	rows, err := AbuseDB.Query(`
		SELECT
			hash,
			first_seen,
			last_seen,
			last_ip,
			last_port,
			count,
			category,
			comment,
			data,
			confirmed
		FROM patterns
		WHERE data IS NOT NULL
		ORDER BY count DESC, last_seen DESC
		LIMIT 1000
	`)
	if err != nil {
		log.Println("Error querying database:", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type pattern struct {
		Hash      string
		FirstSeen string
		LastSeen  string
		LastIP    string
		LastPort  int
		Count     int
		Category  string
		Comment   string
		Data      string
		HexData   string
		Confirmed bool
	}
	var patterns []pattern

	for rows.Next() {
		var hash, lastIP, category, comment string
		var firstSeenUnix, lastSeenUnix, lastPort, count int
		var data []byte
		var confirmed bool
		err := rows.Scan(
			&hash,
			&firstSeenUnix,
			&lastSeenUnix,
			&lastIP,
			&lastPort,
			&count,
			&category,
			&comment,
			&data,
			&confirmed,
		)
		if err != nil {
			log.Println("Error scanning row:", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		// format dates
		firstSeen := time.Unix(int64(firstSeenUnix), 0).Format("2006-01-02 03:04:05 PM")
		lastSeen := time.Unix(int64(lastSeenUnix), 0).Format("2006-01-02 03:04:05 PM")

		// format the hex representation of data
		hexData := hex.EncodeToString(data)
		hexData = strings.ToUpper(hexData)
		var formattedHexData string
		for i := 0; i < len(hexData); i += 2 {
			formattedHexData += hexData[i : i+2]
			if (i+2)%32 == 0 && i+2 < len(hexData) {
				formattedHexData += "\n"
			} else if (i+2)%32 == 16 && i+2 < len(hexData) {
				// extra space after every 16 characters for better readability
				formattedHexData += "   "
			} else {
				formattedHexData += " "
			}
		}

		// replace non-printable characters in data with a placeholder
		for i, b := range data {
			if b == '\r' || b == '\n' || b == '\t' {
				continue // keep these characters as they are
			}
			if b < 32 || b > 126 {
				data[i] = '?'
			}
		}

		patterns = append(patterns, pattern{
			Hash:      hash,
			FirstSeen: firstSeen,
			LastSeen:  lastSeen,
			LastIP:    lastIP,
			LastPort:  lastPort,
			Count:     count,
			Category:  category,
			Comment:   comment,
			Data:      string(data),
			HexData:   formattedHexData,
			Confirmed: confirmed,
		})
	}

	templateErr := templates.ExecuteTemplate(w, "abuse_patterns.html", patterns)
	if templateErr != nil {
		log.Println("Error executing template:", templateErr)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func editAbusePattern(w http.ResponseWriter, r *http.Request) {
	hash := r.FormValue("hash")
	category := r.FormValue("category")
	comment := r.FormValue("comment")
	confirmed := r.FormValue("confirmed") == "on"

	_, err := AbuseDB.Exec(
		"UPDATE patterns SET category = ?, comment = ?, confirmed = ? WHERE hash = ?",
		category, comment, confirmed, hash,
	)
	if err != nil {
		log.Println("Error updating database:", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/abuse", http.StatusSeeOther)
}
