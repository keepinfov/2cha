// Package main is the REALITY FFI build spike. It proves the integration's load-
// bearing build mechanics before we commit to the full design:
//
//  1. github.com/xtls/reality compiles and links into a cgo c-archive (go 1.24 +
//     utls + circl), and
//  2. a Go-created socketpair fd can cross the FFI boundary to Rust carrying a live
//     byte stream — the exact seam the real transport uses.
//
// Build:  CGO_ENABLED=1 go build -buildmode=c-archive -o libgoreality.a .
package main

import "C"

import (
	"net"
	"os"
	"syscall"

	"github.com/xtls/reality"
)

// gor_reality_build_check references a real xtls/reality type so the dependency is
// forced to link into the archive (not merely compile). Returns 1 on success.
//
//export gor_reality_build_check
func gor_reality_build_check() C.int {
	var c reality.Config
	c.ServerNames = map[string]bool{"example.com": true}
	if c.ServerNames["example.com"] {
		return 1
	}
	return 0
}

// gor_echo_fd creates a socketpair, keeps one end in Go with a goroutine that echoes
// everything written to it, and returns the other end's fd for the Rust caller to
// own and close. This mirrors the real seam: Go owns a connection and hands Rust a
// plaintext-stream fd it drives from its poll loop.
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
	// net.FileConn dups the fd into the runtime poller; close the original.
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

func main() {}
