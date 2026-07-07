package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net"
	"testing"
	"time"
)

// selfSignedPadded builds a self-signed cert whose DER is inflated by padBytes
// of opaque extension data, so a test dest can be made to send a Certificate
// record on either side of realityRecordCap.
func selfSignedPadded(t *testing.T, padBytes int) tls.Certificate {
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
	if padBytes > 0 {
		tmpl.ExtraExtensions = []pkix.Extension{{
			Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1},
			Value: bytes.Repeat([]byte{0x5a}, padBytes),
		}}
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// startTLSDest serves one-shot TLS handshakes with the given cert on loopback.
func startTLSDest(t *testing.T, cert tls.Certificate) string {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
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
				c.(*tls.Conn).Handshake()
				c.Close()
			}(c)
		}
	}()
	return ln.Addr().String()
}

func TestDestProbeSmallCertUnderCap(t *testing.T) {
	dest := startTLSDest(t, selfSignedPadded(t, 0))
	maxLen, err := maxDestHandshakeRecordLen(dest, "dest.test")
	if err != nil {
		t.Fatalf("handshake against small-cert dest: %v", err)
	}
	if maxLen == 0 {
		t.Fatal("scanner saw no records")
	}
	if maxLen > realityRecordCap {
		t.Fatalf("small cert measured %d > cap %d", maxLen, realityRecordCap)
	}
}

func TestDestProbeInflatedCertOverCap(t *testing.T) {
	// Pad well past the cap: the Certificate message carries the whole DER,
	// so a >9 KB cert guarantees one record over realityRecordCap.
	dest := startTLSDest(t, selfSignedPadded(t, realityRecordCap+1024))
	maxLen, err := maxDestHandshakeRecordLen(dest, "dest.test")
	if err != nil {
		t.Fatalf("handshake against inflated-cert dest: %v", err)
	}
	if maxLen <= realityRecordCap {
		t.Fatalf("inflated cert measured %d, expected > cap %d", maxLen, realityRecordCap)
	}
}

// oneByteConn dribbles a canned byte stream to Read one byte per call, so the
// scanner's header/payload cursors are exercised across every possible split.
type oneByteConn struct {
	net.Conn
	buf []byte
}

func (c *oneByteConn) Read(p []byte) (int, error) {
	if len(c.buf) == 0 {
		return 0, net.ErrClosed
	}
	p[0] = c.buf[0]
	c.buf = c.buf[1:]
	return 1, nil
}

func TestRecordLenScannerSplitReads(t *testing.T) {
	// Two records: payloads of 3 and 700 bytes.
	stream := []byte{22, 3, 3, 0, 3, 1, 2, 3, 23, 3, 3, 0x02, 0xbc}
	stream = append(stream, make([]byte, 700)...)
	scan := &recordLenScanner{Conn: &oneByteConn{buf: stream}}
	tmp := make([]byte, 16)
	for {
		if _, err := scan.Read(tmp); err != nil {
			break
		}
	}
	if scan.maxSeen != 705 {
		t.Fatalf("maxSeen = %d, want 705", scan.maxSeen)
	}
}
