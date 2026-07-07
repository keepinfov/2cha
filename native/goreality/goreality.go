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
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	utls "github.com/refraction-networking/utls"
	"github.com/xtls/reality"
	"golang.org/x/crypto/hkdf"
)

// gorFallback: peer failed auth and Go already relayed it to Dest (probe).
const gorFallback = -1

type entry struct {
	reality net.Conn
	local   net.Conn
}

var (
	mu      sync.Mutex
	nextID  int64 = 1
	handles       = map[int64]interface{}{}
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

// recoverInto reports a panic (from malformed input, a uTLS/reality library
// edge case, the unsafe peer-certificate reflection hack, etc.) as an error
// instead of letting it unwind across the cgo boundary — a panic escaping an
// `//export`-ed function is fatal to the whole process. Call via `defer` as
// the first statement of every exported function, passing its named return.
func recoverInto(errBuf *C.char, errlen C.int, ret *C.int64_t, failVal C.int64_t) {
	if r := recover(); r != nil {
		setErr(errBuf, errlen, fmt.Sprintf("panic: %v", r))
		*ret = failVal
	}
}

func fdToConn(fd C.int) (net.Conn, error) {
	f := os.NewFile(uintptr(fd), "tcp")
	c, err := net.FileConn(f)
	f.Close()
	return c, err
}

func bridge(rc net.Conn) (C.int, int64, error) {
	// The handshake libraries (REALITY's server auth loop, uTLS on the client)
	// may leave a deadline set on rc to bound handshake time. rc now enters a
	// long-lived bidirectional relay, so any leftover deadline must be
	// cleared first — otherwise the first post-handshake Read/Write can
	// spuriously fail as soon as (or before) that stale deadline expires.
	rc.SetDeadline(time.Time{})
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
	default:
		return utls.HelloChrome_Auto
	}
}

//export gor_server_new
func gor_server_new(privateKey *C.uint8_t, dest *C.char, serverNamesCSV *C.char,
	shortIdsCSV *C.char, maxTimeDiffMs C.int64_t, err *C.char, errlen C.int) (ret C.int64_t) {
	defer recoverInto(err, errlen, &ret, -2)

	cfg := &reality.Config{
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
	awaitRecordDetection(cfg)
	for sni := range cfg.ServerNames {
		go warnIfDestOverRecordCap(cfg.Dest, sni)
		break // one probe is enough; the record shape is a property of dest
	}
	return C.int64_t(store(cfg))
}

// detectTimeout bounds how long gor_server_new waits for
// DetectPostHandshakeRecordsLens's background probing of the decoy `dest` to
// finish before returning — long enough to cover its worst case (CCS probing
// sleeps up to ~3s, plus real network round trips), short enough that an
// unreachable or slow dest can't hang server startup.
const detectTimeout = 10 * time.Second
const detectPollInterval = 50 * time.Millisecond

// awaitRecordDetection blocks until reality's background detection of the
// decoy dest's post-handshake record shape (kicked off by
// DetectPostHandshakeRecordsLens, above) has produced a result for every
// (dest, SNI, ALPN) combination this server can see, or detectTimeout elapses.
//
// Without this, a client that authenticates before detection finishes hits
// reality.Server()'s own completion loop, which retries every 5 seconds while
// the result isn't ready — so the very first connection after startup (or
// after a config reload) can stall for several extra seconds, or fail
// outright if it races the detection unfavorably. Detection always completes
// eventually (even a failed probe stores an empty result via defer), so this
// only narrows the window instead of introducing a new failure mode.
func awaitRecordDetection(cfg *reality.Config) {
	keys := make([]string, 0, len(cfg.ServerNames)*3)
	for sni := range cfg.ServerNames {
		for alpn := 0; alpn < 3; alpn++ {
			keys = append(keys, cfg.Dest+" "+sni+" "+strconv.Itoa(alpn))
		}
	}
	deadline := time.Now().Add(detectTimeout)
	for {
		ready := true
		for _, key := range keys {
			val, ok := reality.GlobalPostHandshakeRecordsLens.Load(key)
			if !ok {
				ready = false
				break
			}
			if _, ok := val.([]int); !ok {
				ready = false
				break
			}
		}
		if ready || time.Now().After(deadline) {
			return
		}
		time.Sleep(detectPollInterval)
	}
}

//export gor_server_handshake
func gor_server_handshake(serverHandle C.int64_t, tcpFd C.int, outFd *C.int,
	errBuf *C.char, errlen C.int) (ret C.int64_t) {
	defer recoverInto(errBuf, errlen, &ret, -2)

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
		// reality.Server already relayed the probe to Dest; log why so a
		// legitimate client's rejected handshake isn't silently invisible.
		// Upstream's last-resort reason means the client *did* authenticate
		// (SNI, key and short id all matched) and the forged handshake broke
		// afterwards — in practice almost always a dest whose flight has a
		// record over realityRecordCap (see destcheck.go).
		hint := ""
		if strings.Contains(err.Error(), "handshake did not complete successfully") {
			hint = " (client auth was OK; likely dest sends a handshake record over " +
				strconv.Itoa(realityRecordCap) + " bytes — see the startup dest probe warning)"
		}
		fmt.Fprintf(os.Stderr, "reality: handshake rejected, fell back to dest: %v%s\n", err, hint)
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

//export gor_client_handshake
func gor_client_handshake(tcpFd C.int, serverName *C.char, publicKey *C.uint8_t,
	shortID *C.uint8_t, fingerprint *C.char, outFd *C.int, errBuf *C.char, errlen C.int) (ret C.int64_t) {
	defer recoverInto(errBuf, errlen, &ret, -2)

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

//export gor_close
func gor_close(handle C.int64_t) {
	defer func() { _ = recover() }()
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

// ── ported REALITY client (from XTLS/Xray-core UClient, MPL-2.0) ─────────────

type uConnWrap struct {
	*utls.UConn
	authKey  []byte
	verified bool
}

func (c *uConnWrap) verifyPeerCertificate(_ [][]byte, _ [][]*x509.Certificate) error {
	p, ok := reflect.TypeOf(c.Conn).Elem().FieldByName("peerCertificates")
	if !ok {
		// crypto/tls renamed or relaid out its private Conn struct; reading at
		// a stale/zero offset would be memory corruption, so fail closed
		// instead of dereferencing garbage.
		return errors.New("REALITY: peerCertificates field not found (crypto/tls layout changed)")
	}
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
	// The forged SessionId is written at a fixed byte offset in the serialized
	// ClientHello (legacy_version(2) + random(32) + session_id_len(1) = 35,
	// plus this fingerprint's fixed prefix before session_id starts at 39).
	// Every uTLS fingerprint this package selects (fingerprintByName) serializes
	// that fixed prefix, but fail closed instead of a slice-bounds panic or a
	// silent short copy if a future fingerprint ever doesn't.
	const sessionIDOffset = 39
	const sessionIDLen = 32
	if len(hello.Raw) < sessionIDOffset+sessionIDLen {
		return nil, errors.New("REALITY: ClientHello too short for this fingerprint")
	}
	hello.SessionId = make([]byte, sessionIDLen)
	copy(hello.Raw[sessionIDOffset:], hello.SessionId)
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
	copy(hello.Raw[sessionIDOffset:], hello.SessionId)
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
