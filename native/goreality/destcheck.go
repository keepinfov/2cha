// Startup self-test of the decoy `dest`. xtls/reality borrows the dest's TLS
// appearance by mimicking its handshake flight record-by-record, and that
// mimicry is fragile in several dest-dependent ways: a record over its
// unexported 8192-byte cap (www.microsoft.com's OCSP-stapled Certificate), or a
// post-handshake NewSessionTicket whose live size differs from the one reality
// measured in its one-shot startup detection (most modern CDNs — the padding
// math underflows: "payload[0]: 4, padding: -N", conn.go). Every such dest
// fails identically and opaquely: authenticated clients abort mid-handshake
// with a bare EOF while the server logs upstream's last-resort
// "handshake did not complete successfully" — and censor probes still see a
// perfectly healthy decoy, so nothing looks wrong from the outside.
//
// Rather than enumerate those failure modes, we exercise the real path once at
// startup: a loopback REALITY handshake (this package's own client against
// reality.Server, which dials the real dest and mimics it). If it can't
// complete, neither can any client, so warn loudly and name known-good dests.
package main

import (
	"context"
	"crypto/ecdh"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/xtls/reality"
)

const destSelfTestTimeout = 15 * time.Second

// destSelfTest runs one loopback REALITY handshake against cfg.Dest using a
// short id, SNI and (derived) public key that authenticate against cfg, and
// returns whatever stops an authenticated client from completing — nil means
// the dest is usable. The caller must have run DetectPostHandshakeRecordsLens
// for cfg.Dest already (gor_server_new does). Never mutates cfg.
func destSelfTest(cfg *reality.Config) error {
	sk, err := ecdh.X25519().NewPrivateKey(cfg.PrivateKey)
	if err != nil {
		return fmt.Errorf("bad reality private key: %w", err)
	}
	pub := sk.PublicKey().Bytes()

	var shortID [8]byte
	haveSID := false
	for id := range cfg.ShortIds {
		shortID, haveSID = id, true
		break
	}
	if !haveSID {
		return nil // nothing to authenticate with; not a dest problem
	}
	var sni string
	for name := range cfg.ServerNames {
		sni = name
		break
	}
	if sni == "" {
		return nil
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		// reality.Server dials the real dest and mimics it; on the loopback
		// failure path it closes conn itself. Discard the success result — the
		// client side below is what we're measuring.
		if rc, err := reality.Server(context.Background(), conn, cfg); err == nil {
			rc.Close()
		}
	}()

	tcp, err := net.DialTimeout("tcp", ln.Addr().String(), destSelfTestTimeout)
	if err != nil {
		return err
	}
	_ = tcp.SetDeadline(time.Now().Add(destSelfTestTimeout))
	ctx, cancel := context.WithTimeout(context.Background(), destSelfTestTimeout)
	defer cancel()

	rc, err := clientHandshake(ctx, tcp, sni, pub, shortID[:], "chrome")
	if err != nil {
		tcp.Close()
		return err
	}
	rc.Close()
	return nil
}

// warnIfDestUnusable runs destSelfTest and prints an actionable warning if the
// configured dest can't be mimicked. Best-effort: recovers from any panic and
// never blocks or fails server startup (call as `go warnIfDestUnusable(cfg)`).
func warnIfDestUnusable(cfg *reality.Config) {
	defer func() { _ = recover() }()
	if err := destSelfTest(cfg); err != nil {
		fmt.Fprintf(os.Stderr,
			"reality: WARNING: startup self-test against dest %s failed: %v — authenticated clients will fail the same way (xtls/reality cannot mimic this dest's handshake). Pick a different dest; known-good: www.mozilla.org:443, addons.mozilla.org:443. See docs/reality.md.\n",
			cfg.Dest, err)
	}
}
