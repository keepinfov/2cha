# REALITY FFI build spike

Throwaway spike that retires the one medium-risk item in `docs/reality-go-design.md`:
the **cgo c-archive + FFI link** mechanics. It is not part of the 2cha cargo workspace
and is not built by normal `cargo build`.

It proves two things:

1. `github.com/xtls/reality` (go 1.24 + utls + circl) compiles and links into a
   `-buildmode=c-archive` static library — `goreality/goreality.go`
   (`gor_reality_build_check`).
2. A Go-created socketpair fd crosses the FFI boundary into Rust and round-trips a
   live byte stream — the exact seam the real transport will use
   (`gor_echo_fd` ↔ `rust/src/main.rs`).

Run in CI via `.github/workflows/reality-spike.yml`. Locally (needs Go 1.24+ and a C
toolchain):

```sh
cd goreality && go get github.com/xtls/reality@latest && go mod tidy
CGO_ENABLED=1 go build -buildmode=c-archive -o ../rust/libgoreality.a .
cd ../rust && cargo run
# => REALITY FFI spike OK: xtls/reality linked + socketpair round-trip works
```

A green run is the greenlight to implement the full integration.
