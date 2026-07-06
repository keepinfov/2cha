//go:build reality_test_support

// Test-only: a throwaway local TLS server to point Dest at from integration
// tests. gor_test_start_tls_dest is never called by the production transport,
// and this file (self-signed cert generation + a TLS listener) is excluded
// from production builds by the `reality_test_support` build tag above —
// build.rs only passes that tag when Cargo's `reality-test-support` feature
// is enabled (test builds).
package main

/*
#include <stdint.h>
*/
import "C"

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	gotls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"time"
)

func genSelfSigned(host string) (gotls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return gotls.Certificate{}, err
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return gotls.Certificate{}, err
	}
	return gotls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

//export gor_test_start_tls_dest
func gor_test_start_tls_dest() C.int {
	cert, err := genSelfSigned("example.com")
	if err != nil {
		return -1
	}
	ln, err := gotls.Listen("tcp", "127.0.0.1:0", &gotls.Config{Certificates: []gotls.Certificate{cert}})
	if err != nil {
		return -1
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { io.Copy(io.Discard, c); c.Close() }(c)
		}
	}()
	return C.int(ln.Addr().(*net.TCPAddr).Port)
}
