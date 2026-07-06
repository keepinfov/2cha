module goreality

go 1.24

// Pinned to the versions `go mod tidy` selects under Go 1.24 so `go build`
// resolves the same 1.24-compatible graph everywhere (incl. the main CI's
// clippy --all-features), instead of pulling a newer x/crypto that demands
// a Go 1.25 toolchain. build.rs runs with GOTOOLCHAIN=auto as a safety net.
require (
	github.com/refraction-networking/utls v1.8.2
	github.com/xtls/reality v0.0.0-20260322125925-9234c772ba8f
	golang.org/x/crypto v0.48.0
)

require (
	github.com/andybalholm/brotli v1.0.6 // indirect
	github.com/cloudflare/circl v1.6.3 // indirect
	github.com/klauspost/compress v1.17.4 // indirect
	golang.org/x/sys v0.41.0 // indirect
)
