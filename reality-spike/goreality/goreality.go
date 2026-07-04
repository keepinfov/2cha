// Package main is the goreality FFI core: a thin C ABI over github.com/xtls/reality
// so Rust can run the REALITY handshake and get back a decrypted-stream fd.
//
// Server uses reality.Server (self-contained: auth + internal io.Copy fallback to
// Dest). Client ports Xray-core's UClient auth (uTLS browser ClientHello with the
// REALITY short-id/pubkey sealed into SessionId). Both hand Rust one end of a
// socketpair carrying the decrypted application stream; Rust does its own framing.
//
// Build: CGO_ENABLED=1 go build -buildmode=c-archive -o libgoreality.a .
//
// Portions of clientHandshake are ported from XTLS/Xray-core (MPL-2.0).
package main

/*
#include <stdint.h>
*/
import "C"

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	gotls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"math/big"
	"net"
	"os"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	utls "github.com/refraction-networking/utls"
	"github.com/xtls/reality"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// gorFallback is returned by gor_server_handshake when the peer failed auth and Go
// already relayed it to Dest (probe); Rust just forgets the connection.
const gorFallback = -1

// ── handle registry ─────────────────────────────────────────────────────────

type entry struct {
	reality net.Conn // the decrypted REALITY stream
	local   net.Conn // Go's end of the socketpair
}

var (
	mu      sync.Mutex
	nextID  int64 = 1
	handles       = map[int64]interface{}{} // *entry (conn) or *reality.Config (server)
)

func store(v interface{}) int64 {
	mu.Lock()
	defer mu.Unlock()
	id := nextID
	nextID++
	handles[id] = v
	return id
}

func loadHandle(id int64) interface{} {
	mu.Lock()
	defer mu.Unlock()
	return handles[id]
}

func drop(id int64) {
	mu.Lock()
	defer mu.Unlock()
	delete(handles, id)
}

func setErr(buf *C.char, buflen C.int, msg string) {
	if buf == nil || buflen <= 0 {
		return
	}
	b := []byte(msg)
	if len(b) > int(buflen)-1 {
		b = b[:int(buflen)-1]
	}
	dst := unsafe.Slice((*byte)(unsafe.Pointer(buf)), int(buflen))
	copy(dst, b)
	dst[len(b)] = 0
}

// fdToConn adopts an already-connected/accepted TCP fd (ownership transferred from
// Rust via into_raw_fd) into a pollable net.Conn.
func fdToConn(fd C.int) (net.Conn, error) {
	f := os.NewFile(uintptr(fd), "tcp")
	c, err := net.FileConn(f)
	f.Close() // FileConn dup'd into the runtime poller; drop the original.
	return c, err
}

// bridge wires the decrypted REALITY stream to a fresh socketpair and returns the
// caller-owned fd plus a handle for teardown.
func bridge(rc net.Conn) (C.int, int64, error) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		rc.Close()
		return -1, 0, err
	}
	goEnd, cEnd := fds[0], fds[1]
	f := os.NewFile(uintptr(goEnd), "goEnd")
	local, err := net.FileConn(f)
	f.Close()
	if err != nil {
		syscall.Close(cEnd)
		rc.Close()
		return -1, 0, err
	}
	id := store(&entry{reality: rc, local: local})
	// Pump both directions; first EOF tears the pair down.
	go func() { io.Copy(rc, local); rc.Close(); local.Close() }()
	go func() { io.Copy(local, rc); rc.Close(); local.Close() }()
	return C.int(cEnd), id, nil
}

func fingerprintByName(name string) utls.ClientHelloID {
	switch strings.ToLower(name) {
	case "firefox":
		return utls.HelloFirefox_Auto
	case "safari":
		return utls.HelloSafari_Auto
	case "edge":
		return utls.HelloEdge_Auto
	default: // "chrome" or unspecified
		return utls.HelloChrome_Auto
	}
}

// ── C ABI ────────────────────────────────────────────────────────────────────

// gor_x25519_keygen writes a fresh X25519 private/public keypair (REALITY key
// format). Returns 0 on success.
//
//export gor_x25519_keygen
func gor_x25519_keygen(outPriv *C.uint8_t, outPub *C.uint8_t) C.int {
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		return -1
	}
	// Clamp per X25519 and derive the public key.
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64
	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return -1
	}
	copy(unsafe.Slice((*byte)(unsafe.Pointer(outPriv)), 32), priv[:])
	copy(unsafe.Slice((*byte)(unsafe.Pointer(outPub)), 32), pub)
	return 0
}

// gor_server_new builds a reusable REALITY server config. serverNamesCSV and
// shortIdsCSV are comma-separated (short ids in hex). Returns a handle or <0.
//
//export gor_server_new
func gor_server_new(privateKey *C.uint8_t, dest *C.char, serverNamesCSV *C.char,
	shortIdsCSV *C.char, maxTimeDiffMs C.int64_t, err *C.char, errlen C.int) C.int64_t {

	cfg := &reality.Config{
		Show:        true, // TEMP: print server-side auth decision for the spike
		Type:        "tcp",
		Dest:        C.GoString(dest),
		ServerNames: map[string]bool{},
		ShortIds:    map[[8]byte]bool{},
		MaxTimeDiff: time.Duration(maxTimeDiffMs) * time.Millisecond,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		},
	}
	cfg.PrivateKey = append([]byte(nil), unsafe.Slice((*byte)(unsafe.Pointer(privateKey)), 32)...)

	for _, name := range strings.Split(C.GoString(serverNamesCSV), ",") {
		if name = strings.TrimSpace(name); name != "" {
			cfg.ServerNames[name] = true
		}
	}
	for _, sid := range strings.Split(C.GoString(shortIdsCSV), ",") {
		sid = strings.TrimSpace(sid)
		if sid == "" {
			continue
		}
		raw, e := hex.DecodeString(sid)
		if e != nil || len(raw) > 8 {
			setErr(err, errlen, "bad short id: "+sid)
			return -1
		}
		var id [8]byte
		copy(id[:], raw)
		cfg.ShortIds[id] = true
	}
	// Required when not using REALITY's own listener (per reality.Server docs).
	reality.DetectPostHandshakeRecordsLens(cfg)
	return C.int64_t(store(cfg))
}

// gor_server_handshake runs the REALITY server handshake on an accepted TCP fd.
//
//	>=0        : authenticated; *outFd = decrypted-stream fd
//	gorFallback: probe; Go already relayed tcp_fd<->Dest, nothing for Rust to do
//	< -1       : error
//
//export gor_server_handshake
func gor_server_handshake(serverHandle C.int64_t, tcpFd C.int, outFd *C.int,
	errBuf *C.char, errlen C.int) C.int64_t {

	cfg, ok := loadHandle(int64(serverHandle)).(*reality.Config)
	if !ok {
		setErr(errBuf, errlen, "invalid server handle")
		return -2
	}
	conn, err := fdToConn(tcpFd)
	if err != nil {
		setErr(errBuf, errlen, err.Error())
		return -2
	}
	rc, err := reality.Server(context.Background(), conn, cfg)
	if err != nil {
		// reality.Server already relayed probes to Dest internally.
		return gorFallback
	}
	cEnd, id, err := bridge(rc)
	if err != nil {
		setErr(errBuf, errlen, err.Error())
		return -2
	}
	*outFd = cEnd
	return C.int64_t(id)
}

// gor_client_handshake runs the REALITY client handshake on an already-connected
// TCP fd, mimicking serverName with the given uTLS fingerprint and authenticating
// with the server's public key + short id. Returns a handle >=0 and sets *outFd.
//
//export gor_client_handshake
func gor_client_handshake(tcpFd C.int, serverName *C.char, publicKey *C.uint8_t,
	shortID *C.uint8_t, fingerprint *C.char, outFd *C.int, errBuf *C.char, errlen C.int) C.int64_t {

	conn, err := fdToConn(tcpFd)
	if err != nil {
		setErr(errBuf, errlen, err.Error())
		return -2
	}
	pub := append([]byte(nil), unsafe.Slice((*byte)(unsafe.Pointer(publicKey)), 32)...)
	sid := append([]byte(nil), unsafe.Slice((*byte)(unsafe.Pointer(shortID)), 8)...)

	rc, err := clientHandshake(context.Background(), conn, C.GoString(serverName), pub, sid, C.GoString(fingerprint))
	if err != nil {
		conn.Close()
		setErr(errBuf, errlen, err.Error())
		return -2
	}
	cEnd, id, err := bridge(rc)
	if err != nil {
		setErr(errBuf, errlen, err.Error())
		return -2
	}
	*outFd = cEnd
	return C.int64_t(id)
}

// gor_close tears down a connection (or forgets a server config) by handle.
//
//export gor_close
func gor_close(handle C.int64_t) {
	v := loadHandle(int64(handle))
	drop(int64(handle))
	if e, ok := v.(*entry); ok {
		if e.reality != nil {
			e.reality.Close()
		}
		if e.local != nil {
			e.local.Close()
		}
	}
}

// gor_echo_fd (retained from the build spike): a socketpair whose Go end echoes.
// Proves the fd hand-off mechanics independent of the handshake.
//
//export gor_echo_fd
func gor_echo_fd() C.int {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		return -1
	}
	goEnd, cEnd := fds[0], fds[1]
	f := os.NewFile(uintptr(goEnd), "goEnd")
	conn, err := net.FileConn(f)
	f.Close()
	if err != nil {
		syscall.Close(cEnd)
		return -1
	}
	go func() {
		defer conn.Close()
		buf := make([]byte, 4096)
		for {
			n, rerr := conn.Read(buf)
			if n > 0 {
				if _, werr := conn.Write(buf[:n]); werr != nil {
					return
				}
			}
			if rerr != nil {
				return
			}
		}
	}()
	return C.int(cEnd)
}

// ── test support: a hermetic local TLS server to act as Dest ─────────────────

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

// gor_test_start_tls_dest starts a throwaway TLS 1.3 server on localhost for tests
// to point Dest at, and returns its port (or <0). Test-only.
//
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

// ── ported REALITY client (from XTLS/Xray-core UClient, MPL-2.0) ─────────────

type uConnWrap struct {
	*utls.UConn
	authKey  []byte
	verified bool
}

func (c *uConnWrap) verifyPeerCertificate(_ [][]byte, _ [][]*x509.Certificate) error {
	// utls does not expose peerCertificates at verify time; reach it like Xray does.
	p, _ := reflect.TypeOf(c.Conn).Elem().FieldByName("peerCertificates")
	certs := *(*[]*x509.Certificate)(unsafe.Pointer(uintptr(unsafe.Pointer(c.Conn)) + p.Offset))
	if len(certs) == 0 {
		return errors.New("REALITY: no peer certificate")
	}
	if pub, ok := certs[0].PublicKey.(ed25519.PublicKey); ok {
		h := hmac.New(sha512.New, c.authKey)
		h.Write(pub)
		if hmac.Equal(h.Sum(nil), certs[0].Signature) {
			c.verified = true
			return nil
		}
	}
	// Not our REALITY server (a real certificate / MITM / redirect).
	return errors.New("REALITY: certificate not verified")
}

func clientHandshake(ctx context.Context, conn net.Conn, serverName string,
	publicKey, shortID []byte, fingerprint string) (net.Conn, error) {

	if serverName == "" {
		return nil, errors.New("REALITY: empty server name")
	}
	wrap := &uConnWrap{}
	utlsConfig := &utls.Config{
		VerifyPeerCertificate:  wrap.verifyPeerCertificate,
		ServerName:             serverName,
		InsecureSkipVerify:     true,
		SessionTicketsDisabled: true,
	}
	wrap.UConn = utls.UClient(conn, utlsConfig, fingerprintByName(fingerprint))

	if err := wrap.BuildHandshakeState(); err != nil {
		return nil, err
	}
	hello := wrap.HandshakeState.Hello
	hello.SessionId = make([]byte, 32)
	copy(hello.Raw[39:], hello.SessionId) // fixed SessionId offset in the ClientHello
	hello.SessionId[0] = 1
	hello.SessionId[1] = 8
	hello.SessionId[2] = 2
	hello.SessionId[3] = 0
	binary.BigEndian.PutUint32(hello.SessionId[4:], uint32(time.Now().Unix()))
	copy(hello.SessionId[8:], shortID)

	serverPub, err := ecdh.X25519().NewPublicKey(publicKey)
	if err != nil {
		return nil, errors.New("REALITY: bad server public key")
	}
	ecdhe := wrap.HandshakeState.State13.KeyShareKeys.Ecdhe
	if ecdhe == nil {
		return nil, errors.New("REALITY: fingerprint lacks a TLS 1.3 X25519 key share")
	}
	authKey, err := ecdhe.ECDH(serverPub)
	if err != nil {
		return nil, err
	}
	if _, err := hkdf.New(sha256.New, authKey, hello.Random[:20], []byte("REALITY")).Read(authKey); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(authKey)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	aead.Seal(hello.SessionId[:0], hello.Random[20:], hello.SessionId[:16], hello.Raw)
	copy(hello.Raw[39:], hello.SessionId)
	wrap.authKey = authKey

	if err := wrap.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	if !wrap.verified {
		return nil, errors.New("REALITY: server not verified")
	}
	return wrap.UConn, nil
}

func main() {}
