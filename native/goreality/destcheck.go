// Startup sanity probe of the decoy `dest`: xtls/reality's Server() mimics the
// dest's handshake flight record-by-record and hard-caps every record at an
// unexported `size = 8192` bytes. A dest whose flight contains a longer record
// (www.microsoft.com's OCSP-stapled Certificate is ~8.3 KB today) makes every
// *authenticated* client fail mid-handshake with the opaque upstream reason
// "handshake did not complete successfully" (XTLS/Xray-core#6356), while probes
// still see a perfectly healthy decoy. Measure the dest's records once at
// server startup and warn loudly so the misconfiguration is visible before the
// first client ever connects.
package main

import (
	"fmt"
	"net"
	"os"
	"time"

	utls "github.com/refraction-networking/utls"
)

// realityRecordCap mirrors xtls/reality's unexported `size` constant (tls.go).
const realityRecordCap = 8192

const destProbeTimeout = 10 * time.Second

// recordLenScanner counts TLS record lengths (header included) flowing through
// Read, without altering the stream. Records arrive in arbitrary Read chunks,
// so it keeps a tiny header/payload cursor across calls.
type recordLenScanner struct {
	net.Conn
	hdr     [5]byte
	hdrLen  int // header bytes collected so far
	remain  int // payload bytes left in the current record
	maxSeen int // largest record (5-byte header + payload) observed
}

func (c *recordLenScanner) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	for b := p[:n]; len(b) > 0; {
		if c.remain > 0 {
			skip := min(c.remain, len(b))
			c.remain -= skip
			b = b[skip:]
			continue
		}
		take := min(len(c.hdr)-c.hdrLen, len(b))
		copy(c.hdr[c.hdrLen:], b[:take])
		c.hdrLen += take
		b = b[take:]
		if c.hdrLen == len(c.hdr) {
			c.remain = int(c.hdr[3])<<8 | int(c.hdr[4])
			c.maxSeen = max(c.maxSeen, len(c.hdr)+c.remain)
			c.hdrLen = 0
		}
	}
	return n, err
}

// maxDestHandshakeRecordLen dials dest and runs one throwaway TLS handshake
// with the same default fingerprint REALITY clients use (Chrome), returning
// the largest record dest sent during it. The fingerprint matters: what dest
// staples/compresses — and therefore its record sizes — depends on the
// ClientHello it answers.
func maxDestHandshakeRecordLen(dest, sni string) (int, error) {
	d := net.Dialer{Timeout: destProbeTimeout}
	raw, err := d.Dial("tcp", dest)
	if err != nil {
		return 0, err
	}
	defer raw.Close()
	raw.SetDeadline(time.Now().Add(destProbeTimeout))
	scan := &recordLenScanner{Conn: raw}
	tc := utls.UClient(scan, &utls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
	}, utls.HelloChrome_Auto)
	err = tc.Handshake()
	return scan.maxSeen, err
}

// warnIfDestOverRecordCap runs the probe and prints an actionable warning when
// dest can never serve authenticated clients. Best-effort: probe failures are
// noted but never fatal (a transiently unreachable dest must not block or kill
// server startup), so callers just `go warnIfDestOverRecordCap(...)`.
func warnIfDestOverRecordCap(dest, sni string) {
	defer func() { _ = recover() }()
	maxLen, err := maxDestHandshakeRecordLen(dest, sni)
	if maxLen > realityRecordCap {
		fmt.Fprintf(os.Stderr,
			"reality: WARNING: dest %s sent a %d-byte TLS handshake record; xtls/reality mimics at most %d bytes per record, so authenticated clients will fail with \"handshake did not complete successfully\" (XTLS/Xray-core#6356) — pick a different dest (e.g. www.cloudflare.com:443)\n",
			dest, maxLen, realityRecordCap)
		return
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "reality: dest record-size probe failed (non-fatal): %v\n", err)
	}
}
