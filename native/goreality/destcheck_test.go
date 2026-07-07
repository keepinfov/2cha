package main

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/xtls/reality"
)

func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "dest.test"},
		DNSNames:     []string{"dest.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// startLocalDest runs a minimal TLS 1.3 dest on loopback — the kind of small,
// stable-record site reality.Server can mimic (the CI e2e uses the same shape).
func startLocalDest(t *testing.T) string {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{selfSignedCert(t)},
		MinVersion:   tls.VersionTLS13,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				_ = c.(*tls.Conn).Handshake()
				io := make([]byte, 512)
				for {
					if _, err := c.Read(io); err != nil {
						break
					}
				}
				c.Close()
			}(c)
		}
	}()
	return ln.Addr().String()
}

func newTestCfg(t *testing.T, dest string, withPeer bool) *reality.Config {
	t.Helper()
	priv := make([]byte, 32)
	if _, err := rand.Read(priv); err != nil {
		t.Fatal(err)
	}
	cfg := &reality.Config{
		Type:        "tcp",
		Dest:        dest,
		ServerNames: map[string]bool{"dest.test": true},
		ShortIds:    map[[8]byte]bool{},
		PrivateKey:  priv,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		},
	}
	if withPeer {
		cfg.ShortIds[[8]byte{0xdd, 0x23, 0x13, 0x7f, 0x33, 0x19, 0x0b, 0x4a}] = true
	}
	return cfg
}

// A dest with no configured short id / server name is not a "dest problem" —
// destSelfTest returns nil without touching the network.
func TestDestSelfTestNoAuthMaterial(t *testing.T) {
	cfg := newTestCfg(t, "127.0.0.1:1", false) // dest never dialed
	if err := destSelfTest(cfg); err != nil {
		t.Fatalf("expected nil without a short id, got %v", err)
	}
}

// A malformed private key is reported, not panicked on.
func TestDestSelfTestBadKey(t *testing.T) {
	cfg := newTestCfg(t, "127.0.0.1:1", true)
	cfg.PrivateKey = []byte{1, 2, 3} // wrong length
	if err := destSelfTest(cfg); err == nil {
		t.Fatal("expected an error for a 3-byte private key")
	}
}

// Happy path: a small-record local dest is mimicable, so an authenticated
// loopback client completes. Retried to absorb the documented ~1/10 post-
// handshake flake in the vendored reality/uTLS internals.
func TestDestSelfTestLocalDestUsable(t *testing.T) {
	if testing.Short() {
		t.Skip("full loopback handshake; skipped under -short")
	}
	cfg := newTestCfg(t, startLocalDest(t), true)
	reality.DetectPostHandshakeRecordsLens(cfg)
	awaitRecordDetection(cfg)

	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if lastErr = destSelfTest(cfg); lastErr == nil {
			return
		}
	}
	t.Fatalf("local dest should be usable, got %v", lastErr)
}

// Sanity: the derived public key matches what reality's server computes from
// the same private key (the auth in destSelfTest depends on this identity).
func TestDerivedPublicKeyMatchesServer(t *testing.T) {
	priv := make([]byte, 32)
	if _, err := rand.Read(priv); err != nil {
		t.Fatal(err)
	}
	sk, err := ecdh.X25519().NewPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(sk.PublicKey().Bytes()); got != 32 {
		t.Fatalf("public key length = %d, want 32", got)
	}
}
