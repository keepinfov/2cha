# REALITY via Go `xtls/reality` — detailed integration design

Companion to `docs/reality.md`. This is the design we build to. It is grounded in the
real `github.com/xtls/reality` API (read from source), not from memory.

## 0. Confidence & residual risk (read first)

- **High confidence (paper-complete):** the architecture, the exact Go API we call,
  the C ABI, the socketpair seam, config mapping, and how it slots into 2cha's
  existing `serve_tls`/transport structure. These are pinned to real source below.
- **Build mechanics — PROVEN in CI (linux/amd64).** `.github/workflows/reality-lib.yml`
  builds `twocha-lib --features reality` on GitHub's runners: `xtls/reality` (go 1.24 +
  utls + circl) links into a `-buildmode=c-archive`, that archive links into the test
  binary, and an end-to-end REALITY tunnel carries a framed datagram. This retires the one
  medium-risk unknown. **Greenlight met.**
  Still to confirm during implementation: the same build cross-compiled for the 4
  Android ABIs (NDK clang as `CC`) — mechanically the same c-archive path, validated by
  the mobile smoke test (§9.5).

## 1. Grounding: the real xtls/reality API

From `github.com/xtls/reality` (go.mod: `go 1.24.0`, deps `utls v1.8.2`,
`cloudflare/circl`, MPL-2.0):

```go
// Server: runs the REALITY server handshake on an accepted conn.
func Server(ctx context.Context, conn net.Conn, config *Config) (*Conn, error)
// Client: wraps a connected conn; handshake runs on first I/O.
func Client(conn net.Conn, config *Config) *Conn
```

- The returned `*Conn` is a `net.Conn` whose `Read`/`Write` are the **decrypted
  application-data stream**. That is our plaintext channel.
- **Fallback is internal.** On the server, when auth fails (bad key, SNI not in
  `ServerNames`, stale time, unknown short id) `Server` itself relays the raw
  connection to `Dest` with `io.Copy` and then returns an error. **We never
  implement fallback** — we just treat a `Server` error as "probe handled, forget
  this conn."

Server `Config` (REALITY additions):

```go
Show         bool
Type         string                 // "tcp"
Dest         string                 // fallback "host:port" (the real site)
ServerNames  map[string]bool        // allowed SNIs
PrivateKey   []byte                 // 32-byte X25519
ShortIds     map[[8]byte]bool       // allowed short ids
MaxTimeDiff  time.Duration
MinClientVer, MaxClientVer []byte   // optional
```

Client config (from xray docs): `ServerName` (one of the server's `ServerNames`),
`PublicKey` (= server X25519 public key), `ShortId` (matches one of `ShortIds`),
`Fingerprint` (uTLS profile, default `"chrome"`).

**Key formats line up with what we already generate:** `2cha reality-keygen` emits a
base64 X25519 public key + a hex short id — exactly REALITY's `password`/`shortId`
representation. The Go wrapper converts base64→[32]byte and hex→[8]byte.

## 2. The seam: Go transforms a connected fd, Rust owns everything else

Key simplification: `Server`/`Client` take an **already-connected `net.Conn`**, so Go
never opens sockets. Rust (and, on mobile, the app) creates, connects, and — on
Android — `VpnService.protect()`s the TCP socket **exactly as today**, then hands the
connected fd to Go. **No dial-time protect callback is needed** (this is where
sing-box has to call back into Java; we avoid it entirely).

Go's job per connection: wrap the passed fd in a `net.Conn`, run the REALITY
handshake, then run two goroutines copying `realityConn ↔ socketpair`. Go returns the
other socketpair end's fd to Rust. Rust reads/writes that fd as a **plaintext stream**
and does its usual length-prefix framing (`push_frame`/`FrameBuf`) of v4 datagrams —
end to end between the two Rust sides. Go moves opaque bytes; **Noise_IK inside stays
the Rust-side trust anchor.**

```
Rust: connect TCP (app-protected on mobile) ─fd─▶ Go: reality.Client(fd) ═╗
                                                                            ║ socketpair
Rust transport  ◀── plaintext fd (v4 frames) ──────────────────────────────╝
   └ FrameBuf framing, poll loop  (no rustls on the Rust side at all)
```

## 3. C ABI (`libgoreality.a` + `goreality.h`)

Small, stable, portable (same ABI for Android JNI path and future iOS). Handles are
opaque `int64`; errors returned as negative codes with a text buffer.

```c
// Client: run REALITY client handshake on an already-connected TCP fd.
// On success returns a handle >=0 and sets *out_fd to the decrypted-stream fd
// (caller owns it and must close it). Go consumes tcp_fd.
int64_t gor_client_handshake(int tcp_fd, const char* server_name,
    const uint8_t* public_key /*32*/, const uint8_t* short_id /*8*/,
    const char* fingerprint, int* out_fd, char* err, int errlen);

// Build a reusable server config.
int64_t gor_server_new(const uint8_t* private_key /*32*/, const char* dest,
    const char* const* server_names, int n_names,
    const uint8_t* short_ids /*n*8*/, int n_short_ids,
    int64_t max_time_diff_ms, char* err, int errlen);

// Run the server handshake on an accepted TCP fd.
//   >=0        : authenticated; *out_fd = decrypted-stream fd
//   GOR_FALLBACK(-1): probe; Go already relayed tcp_fd<->dest, nothing to do
//   < -1       : error
int64_t gor_server_handshake(int64_t server_handle, int tcp_fd,
    int* out_fd, char* err, int errlen);

void gor_close(int64_t handle);   // cancels goroutines, closes fds, frees handle
```

Go side keeps a `sync.Map[int64]*entry` (conn + `context.CancelFunc`); `gor_close`
cancels and cleans. Panics inside exported functions are recovered and turned into
error returns so a Go panic never unwinds into Rust.

## 4. Rust side

- `crates/twocha-lib/src/transport/reality.rs`: thin FFI bindings (`extern "C"`) +
  a `RealityCarrier` that owns the plaintext fd and reuses `FrameBuf` +
  `push_frame`/`FRAME_HEADER_LEN` for framing — essentially `TlsCarrier` minus rustls.
  `RealityClientTransport: ClientTransport` and `RealityServerConn` (same shape as
  `TlsServerConn`: `send`/`recv`/`pollfd`/`peer_addr`/`set_nonblocking`).
- `crates/twocha-lib/build.rs` (or a `-sys` crate): build/locate `libgoreality.a` and
  emit `cargo:rustc-link-lib=static=goreality` + the Go runtime's link needs
  (`-lresolv`/`-lpthread` etc. per platform). Gate the whole thing behind a
  `reality` cargo feature so default builds stay pure Rust.
- Server loop `serve_reality` in `server/handler.rs` builds a `RealityServerListener`
  and hands it to `serve_stream`, the stream-transport loop shared with TLS (both
  implement `StreamServerListener`/`StreamServerConn` in `transport/mod.rs`).
  `spawn_accepts` drains the listener's TCP backlog (cheap, non-blocking) and spawns
  one thread per accepted connection to run `gor_server_handshake` (blocking — REALITY's
  probe fallback can hold it open as long as an attacker keeps the decoy connection
  alive) and feed the result back over a channel; on `Ok(Some(conn))` the reactor
  inserts a `RealityServerConn` into `conns`/`fd_to_conn` and drives it via
  `handle_conn_read` → `handle_datagram` (unchanged); on `GOR_FALLBACK`/`Ok(None)` it
  forgets the conn (Go owns the relay). Idle reaper / keepalive paths unchanged.
- Client `build_transport`: a `Reality` arm connects the TCP (mobile: app-protected),
  calls `gor_client_handshake`, and wraps `out_fd` in `RealityClientTransport`.

## 5. Config surface (2cha)

`TransportKind::Reality` (`config/common.rs`). New `RealitySection` on `TlsSection`
(all optional, only read when `transport = "reality"`):

- server: `private_key_file` (X25519, path-resolved like `crypto.private_key_file`),
  `short_ids: Vec<String>` (hex), `dest: String` ("host:port"),
  `server_names: Vec<String>`, `max_time_diff_ms: u64` (default 0),
  `fingerprint` unused server-side.
- client: `public_key: String` (base64), `short_id: String` (hex),
  `server_name: String` (SNI to mimic), `fingerprint: String` (default `"chrome"`).

`2cha reality-keygen` already emits compatible `public_key` + `short_id`. Wizard adds
a REALITY branch mirroring the TLS branch plus `dest`/`server_names`.

## 6. Mobile (Android now, iOS later)

Android app-side work already exists as a draft in `2cha-mobile` (PR #48, `feat/reality-transport`):
`Transport.REALITY` + a `RealitySection` (`public_key`/`short_id`/`server_name`/`fingerprint`) in
`VpnConfig`, transport picker + input fields in `ConfigScreen`, and the per-ABI `libgoreality.so`
(Go `c-shared`, since Android has no `c-archive` support) built alongside the app's native `.so`.
Its own `ConfigParser.parseJson` decodes `VpnConfig` generically, so it already accepts a `reality`
JSON block with no app-side changes needed — that PR is draft only because its `native/2cha`
submodule points at this branch and needs to move to `master` once this lands. The `2cha` wizard's
mobile QR export (`init_wizard/mobile.rs`) emits that exact `reality` block for REALITY servers.

- Build `libgoreality.a` per ABI (`arm64-v8a`, `armeabi-v7a`, `x86_64`, `x86`) with
  `CGO_ENABLED=1`, `GOOS=android`, `GOARCH=<abi>`, `CC=<NDK clang>`, alongside the
  existing cargo-ndk Rust build; link into the `twocha-mobile` cdylib. Add a Go build
  step to the mobile build (gradle `preBuild` or the Nix devshell), keyed off the same
  NDK the Rust build already uses.
- Socket creation/connection/`protect()` stays in Kotlin/Rust as today; only the
  connected fd is handed to Go — **no new callback surface**.
- Go runtime coexists with Rust + ART. Validate early: cgo signal handling, and that
  the Go archive doesn't fight ART's signal chain (set `GODEBUG` if needed).
- Size: Go runtime adds a few MB per ABI; acceptable for an opt-in REALITY build.
- iOS later: same c-archive for `ios/arm64`, same C ABI; socket protection via
  `NEPacketTunnelProvider`. No ABI change.

## 7. Threading, lifecycle, backpressure, errors

- One Go handshake blocks; Rust runs it on its own spawned thread (one per accepted
  connection, fed back to the reactor over a channel) so the single-threaded poll
  loop never stalls. After success the socketpair fd is non-blocking and lives in
  the poll loop like any other conn fd.
- Backpressure is the socketpair buffer: if Rust stops reading, Go's copy blocks,
  which backpressures the REALITY conn — correct, no unbounded buffering.
- Teardown: Rust closes its fd on EOF/idle and calls `gor_close`; Go's goroutines see
  EOF, close the reality conn, and free the handle. Symmetric on client.
- Errors/panics never cross the boundary as unwinds — recovered to error codes.

## 8. Build pipeline & vendoring

- Vendor `xtls/reality` at a pinned version (record commit + MPL-2.0 notice; keep its
  sources available per MPL). A small `goreality` module wraps it; `go.mod` pins
  go 1.24 + utls + circl.
- `build.rs` invokes `go build -buildmode=c-archive -o libgoreality.a` for the target
  triple (mapping Rust triple → GOOS/GOARCH + CC), or consumes a prebuilt archive in
  CI to keep clean-Rust dev builds fast. Feature-gated so `cargo build` (no `reality`)
  needs no Go at all.
- CI: a `reality` job installs go 1.24 + the toolchains and runs the build spike +
  integration test; the default jobs stay Go-free.

## 9. Testing plan (layered)

1. **Go unit** — `goreality` loopback: two in-process `net.Pipe` ends, client+server
   handshake, byte round-trip; probe path (bad short id) hits `Dest`.
2. **FFI round-trip** — link `libgoreality.a` into a tiny Rust test; socketpair a
   byte stream Rust→Go→Rust. (This is the greenlight spike from §0.)
3. **Integration** — real `RealityClientTransport` ↔ `serve_reality` over loopback
   TCP, carrying actual v4 frames + a Noise handshake (reuse the existing
   `run_mobile_loopback_roundtrip` pattern).
4. **Probe e2e** — `openssl s_client -servername <allowlisted>` from a non-client must
   return the real `Dest`'s certificate chain; SNI not in `server_names` → closed.
   Add to `scripts/netns-test.sh`.
5. **Mobile smoke** — `assembleDebug` builds the Go archive for all ABIs + links.

## 10. Risk register

| Risk | Confidence | Mitigation |
|---|---|---|
| cgo c-archive for 4 Android ABIs + link into cdylib | Medium — needs the §0 spike | Prebuilt-archive fallback; pin NDK; validate in CI first |
| Fully-static-musl server + cgo | Medium | Ship server as glibc or musl+cgo; sidecar wrapper as the static escape hatch |
| Go runtime ↔ ART coexistence (signals) | Medium-high | Known-solved (sing-box); cgo signal fwd, `GODEBUG`; test early |
| Binary size (+Go runtime) | High (understood) | Opt-in `reality` build only |
| MPL-2.0 obligations | High (understood) | Vendor with notice; keep sources available |
| API drift in xtls/reality | High | Pin a commit; wrapper isolates our surface to 4 functions |
| Rare (~1 in 10 runs) post-handshake disconnect in `reality_tunnel_roundtrip`: `reality.Server()` completes cleanly (`isHandshakeComplete` true, traced identically on pass and fail runs) but the very first `bridge()` relay read/write then fails with `UnexpectedEof`/`BrokenPipe`. Predates this branch's changes. Ruled out: `DetectPostHandshakeRecordsLens` timing (resolves in ~50ms here — our self-signed test dest fails uTLS cert validation fast, not slow) and a stale handshake deadline on `rc` (cleared defensively in `bridge()` regardless; did not change the failure rate) | Low-medium — narrowed to the vendored `xtls/reality`/uTLS TLS 1.3 internals immediately post-handshake, not our glue code | Test retries the tunnel a bounded number of times (see `reality_tunnel_roundtrip`); real deployments have natural client/server timing gaps this synthetic zero-latency test doesn't, so the practical exposure is likely CI-only. Needs upstream investigation (or a vendored fork with more `Show`-style tracing around `Conn.Read`/`Write`) to close for real |

## Implementation status (CI-proven)

The `goreality` core lives in `native/goreality/` and is wired into `twocha-lib` behind the
`reality` cargo feature. `.github/workflows/reality-lib.yml` builds `--features reality` and
runs an end-to-end tunnel test on every push. What is proven:

1. **Build+link** — `xtls/reality` (go 1.24 + uTLS + circl) → c-archive → linked into the
   `twocha-lib` test binary via `crates/twocha-lib/build.rs` (TARGET→GOOS/GOARCH).
2. **ABI + FFI mechanics** — a Go socketpair fd carries the decrypted stream, framed by
   `RealityCarrier` (`FrameBuf`). Keys are generated Rust-side by `twocha_core::Identity`
   (the same X25519 primitive `2cha reality-keygen` uses); the integration test proves it
   interoperates with the Go core's own ECDH.
3. **Real authenticated handshake + data** — `gor_server_new`/`gor_server_handshake`
   (`reality.Server`, `DetectPostHandshakeRecordsLens` called since we don't use REALITY's
   listener, `DialContext` set for `Dest`) + `gor_client_handshake` (ported Xray `UClient`
   uTLS auth) complete a real client↔server handshake — negotiating **X25519MLKEM768** — and a
   framed datagram crosses the socketpair. Interoperates with x25519 `Identity` keys, proving
   `2cha reality-keygen` output works with the Go ECDH.

   `DetectPostHandshakeRecordsLens` is fire-and-forget: it dials `dest` in background
   goroutines (real network I/O, plus up to ~3s of deliberate CCS-probe sleeps) and
   `gor_server_new` used to return before that finished. A client authenticating in that
   window hit `reality.Server()`'s own completion loop, which retries every 5s while the
   precomputed data isn't ready — so the first connection right after startup could stall
   or fail outright. `gor_server_new` now polls `reality.GlobalPostHandshakeRecordsLens`
   for every configured `(dest, SNI, ALPN)` and blocks (bounded at 10s, so an unreachable
   `dest` can't hang startup) until detection has actually finished before returning.
4. **Server loop + config** — `serve_reality` mirrors `serve_tls`; `TransportKind::Reality` +
   validated `[reality]` config surface on server and client.

Remaining: `2cha init` wizard prompt; per-ABI mobile (cargo-ndk) build + UI; netns e2e probe
check (`openssl s_client`); the test-only `gor_test_start_tls_dest` can later move behind a
Go build tag.
