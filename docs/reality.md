# REALITY-style anti-probe TLS gate (design + status)

This document describes the in-progress **REALITY mode** for 2cha's TLS transport,
records the feasibility research that shaped it, and tracks what is implemented
versus staged. It is the reference for anyone continuing the work.

## Goal

Today, with `transport = "tls"`, the server terminates TLS with its **own**
certificate and an unauthenticated connection gets silence then idle-reaping. An
active prober therefore sees a self-signed certificate for a domain that doesn't
own it, and an endpoint that never behaves like the site it claims to be — two
strong fingerprints.

REALITY mode closes this: a provisioned client proves itself **inside the TLS
ClientHello**, so the server can decide — *before presenting any certificate* —
whether to run the tunnel or hand the connection to a real decoy site named by an
allowlisted SNI. Right keys → the VPN works; wrong/no keys → the prober is spliced
to the genuine target and sees its real certificate and content.

## What REALITY provides, and the 2cha-specific angle

REALITY (from XTLS/Xray) borrows a real target site's TLS appearance as cover. Its
hardest machinery exists so a *normal* TLS client can trust a borrowed certificate
the server doesn't hold the private key for, while defeating a censor MITM.

2cha changes the calculus in two ways:

1. **Noise_IK inside the tunnel is the sole trust anchor.** The TLS layer is pure
   obfuscation; the client already accepts any server certificate (see
   `transport/tls.rs`). So the tunnel's security never depended on the TLS layer.
2. **TLS 1.3 encrypts the certificate message.** A passive on-path censor cannot
   read the server's certificate at all; it only sees the SNI (which matches an
   allowlisted real host) and otherwise-encrypted records.

Consequence: the highest-value anti-probe property — *active probes see the real
target* — is reachable **without** porting REALITY's full certificate-borrowing
handshake. That split defines the two stages below.

## Feasibility finding (spike A0)

There is **no REALITY implementation in Rust**. The only maintained one (client and
server) is Go: `github.com/xtls/reality`, a fork of Go's entire `crypto/tls`. The
Rust client-side fingerprint tooling that exists does not close the gap:

- `utls-rs` — 6 commits, reuses *rustls's own* ClientHello fingerprint (no browser
  parroting, no `session_id`/`key_share` control). Not usable.
- `craftls` — rustls fork; customizes extensions/ciphers/GREASE/ordering, but **not**
  the `session_id` or `key_share`.
- `boring` / `wreq` — BoringSSL (Chrome's TLS lib) with browser profiles, but does not
  expose the client legacy `session_id` or the key_share ephemeral private key.

REALITY-faithful auth requires a client ClientHello with (a) a controlled 32-byte
`session_id` and (b) an X25519 `key_share` whose private key the client retains (to
compute the ECDH auth key). No off-the-shelf Rust stack exposes both. Achieving it
means either forking a Rust TLS stack (craftls-style, extended) or hand-rolling the
minimal TLS 1.3 client path — a substantial, correctness-critical effort. This
matches `transport/tls.rs`'s own note that REALITY is "deferred pending a mature
uTLS-equivalent in Rust."

## Integration decision: reuse Go `xtls/reality` via c-archive (chosen)

Rather than fork or hand-roll a Rust TLS 1.3 stack, we reuse the maintained Go
implementation (`github.com/xtls/reality` + uTLS) and link it into 2cha. This
inherits the correct, up-to-date handshake surgery, browser fingerprints, and PQ
key exchange, and — unlike any pure-Rust path — gives **full certificate borrowing
(Stage B) for free**. REALITY is in scope for mobile, so integration is in-process.

**Architecture — one Go core, thin C ABI, socketpair seam:**

- A single Go module `goreality` wraps `xtls/reality`, exposing a small, stable,
  portable C ABI (cgo `//export`):
  - `gor_client_connect(cfg) -> (handle, fd, err)` — dials, runs the REALITY
    *client* handshake, returns a **socketpair fd** carrying the decrypted app-data.
  - `gor_server_new(cfg) -> handle`, `gor_server_accept(handle) -> (conn, fd, peer)`
    — accepts + runs the REALITY *server* handshake, with the probe→`dest` fallback
    handled **inside Go** (that is REALITY's job). Returns a decrypted-stream fd.
  - `gor_close(handle)`.
  - `gor_set_protect_callback(fn)` — see mobile note below.
- **Seam = socketpair.** Go owns the whole TLS+REALITY connection and pumps
  decrypted plaintext over a socketpair; Rust reads/writes the fd inside its existing
  poll loop and reassembles v4 datagrams with `FrameBuf`, exactly like the `tls`
  carrier. Go is confined to the obfuscation envelope; **Noise_IK inside stays the
  Rust-side trust anchor** (defence in depth even though REALITY now secures the
  outer TLS).

**Mobile (Android, in scope now):**

- `go build -buildmode=c-archive` → `libgoreality.a` + header, built **per ABI**
  (arm64-v8a, armeabi-v7a, x86_64, x86) with the NDK clang as `CC`, alongside the
  existing cargo-ndk Rust build; linked into the `twocha-mobile` cdylib.
- **Socket-protect callback is mandatory.** The outbound TCP now originates in Go, so
  each dial fd must be passed to the Android `VpnService.protect()` (via the
  `gor_set_protect_callback` hook) *before connect*, or the tunnel's own transport
  would route back into the tunnel. This is the trickiest mobile piece; sing-box/v2ray
  solve it exactly this way.
- Go runtime (GC/scheduler/signal handlers) coexists with Rust and Android ART —
  known-solved but validate early (cgo signal forwarding, `GODEBUG`).

**iOS/Swift (later):** the same c-archive builds for `arm64` iOS; the same C ABI and
protect callback apply (protect via `NEPacketTunnelProvider`). Designing the ABI
portable now makes the iOS path largely free.

**Server/desktop:** default to the same in-process c-archive. The **sidecar** (same
Go core wrapped in a `main()` that bridges over a unix socket instead of a socketpair)
remains the escape hatch if a fully-static-musl server binary must stay pure Rust.

**Implications (honest):**

- This **supersedes** the pure-Rust `crypto/reality.rs` auth primitive on the data
  path — Go performs the real REALITY handshake and auth. The Rust primitive is kept
  only for `reality-keygen`, documentation, and as a pure-Rust fallback; it is not
  load-bearing under this plan. (REALITY uses X25519 keys like ours, so
  `reality-keygen` output can feed the Go config.)
- `xtls/reality` / Project X is **MPL-2.0**: link-compatible with 2cha's MIT, but the
  MPL'd sources (and any modifications) must remain available and MPL-licensed.
- The Go runtime adds a few MB to every REALITY-enabled artifact; keep REALITY an
  opt-in build so the default pure-Rust static-musl binary is unaffected.

The Stage A/B split below was the *pure-Rust* framing; with Go, both land together.
It is retained for context and for the fallback path.

## Stage A — auth-in-ClientHello + probe redirection (target deliverable)

Authenticated clients get the tunnel; every non-authenticated connection is
raw-spliced to the allowlisted real target. Authenticated sessions still terminate
with the server's own certificate — but because TLS 1.3 encrypts it and Noise
authenticates the tunnel, this already defeats passive SNI inspection and active
probing.

The discriminator is REALITY's ClientHello-embedded auth (**not** the existing Noise
mac1): only a signal *in the ClientHello* lets the server fork to "splice to the real
target" before committing to a certificate, which is what makes a prober see the
target's real certificate.

### Auth construction (implemented: `crypto/reality.rs`)

Transport-agnostic core, using 2cha's in-tree primitives (BLAKE2s KDF +
ChaCha20-Poly1305) rather than REALITY's HKDF-SHA256 + AES-GCM, since 2cha owns both
ends:

- Client picks an ephemeral X25519 keypair; its public key is the TLS `key_share`.
- `shared = X25519(eph_priv, server_reality_pub)`;
  `key,nonce = BLAKE2s(ctx, shared, client_random)`.
- `session_id[32] = ChaCha20Poly1305(key, nonce).seal(short_id(8) || timestamp(8))`,
  with AAD = `key_share || server_reality_pub` (binds the blob to this hello + server).
- Server reads `key_share`, `client_random`, `session_id` from the raw ClientHello,
  recomputes the shared secret with its REALITY private key, and opens `session_id`.
  Success + allowlisted short id + fresh timestamp ⇒ tunnel; otherwise ⇒ probe.

API: `seal`, `open`, `short_id_allowed`, `timestamp_fresh`, plus
`generate_short_id`/`short_id_hex`/`parse_short_id`. Unit-tested for round-trip and
for rejection of wrong server key, wrong client_random, tampered `session_id`, and a
transplanted `key_share`.

Keys are generated with `2cha reality-keygen` (reuses the X25519 `Identity`), which
prints the server public key + a random short id for client configs.

### Remaining Stage A work

1. **Client ClientHello crafting** — the load-bearing dependency from A0. Options, in
   order of preference: extend a craftls-style rustls fork to expose `session_id` +
   the key_share ephemeral; or hand-roll the minimal TLS 1.3 client path (2cha's
   client already skips certificate verification, which removes much of the burden).
2. **Config** — `TransportKind::Reality`; a `RealitySection` on `TlsSection`
   (`config/common.rs`): server `private_key_file` / `short_ids` / `allow_dest`;
   client `public_key` / `short_id` / `target`.
3. **Transport module** `transport/reality.rs` — mirror `tls.rs`, reuse `FrameBuf`
   framing; server `accept` reads the raw ClientHello, runs `reality::open`, and on
   failure raw-splices to the allowlisted SNI target on a detached thread.
4. **Server loop** `serve_reality` — near-copy of `serve_tls`, with the probe-splice
   fork in `accept`.
5. **Wizard + e2e** — REALITY prompts; extend `scripts/netns-test.sh` with an
   `openssl s_client` probe check that must return the real target's chain.

## Stage B — full certificate borrowing (large, optional follow-up)

Make authenticated sessions *also* present the real target's certificate, defeating a
censor that can force certificate disclosure. Requires porting REALITY's TLS surgery
to Rust (server-chosen ServerHello `key_share`, copied target certificate, a
CertificateVerify the 2cha client skips, censor-MITM detection). No Rust base exists —
scope as its own project. Stage A's `reality.rs` is structured so the authenticated
branch of `accept` is the single swap-in point.

## Status

- [x] A0 spike (this document's feasibility finding)
- [x] `crypto/reality.rs` auth primitive + short-id helpers (unit-tested; now a
      fallback/keygen aid — superseded on the data path by the Go decision)
- [x] `2cha reality-keygen` CLI
- [x] Integration decision: Go `xtls/reality` c-archive, mobile in scope

Chosen path (Go c-archive):
- [x] `goreality` Go module wrapping `xtls/reality`, C ABI (`gor_x25519_keygen`,
      `gor_server_new`/`gor_server_handshake`, `gor_client_handshake`, `gor_close`)
      — `native/goreality/`
- [x] Rust FFI bindings + `build.rs` linking `libgoreality.a`; socketpair carrier in
      `transport/reality.rs` reusing `FrameBuf`; `TransportKind::Reality` + `[reality]`
      config surface (server + client) with validation
- [x] Server loop wiring `serve_reality` (probe→`dest` fallback lives in Go)
- [x] CI: `reality-lib.yml` builds `--features reality` and runs an end-to-end tunnel
      test (Go keys **and** x25519 `Identity` keys, proving keygen interop)
- [ ] Mobile: per-ABI Go archive build in the cargo-ndk pipeline; uniffi plumbing + UI
- [ ] Wizard `2cha init` prompt for REALITY
- [ ] netns e2e (`openssl s_client` probe check)
- [ ] (Later) iOS/Swift c-archive using the same C ABI

## Usage (manual)

Build with the feature (needs Go 1.24+, a C compiler; the default build is Go-free):

    cargo build -p twocha-cli --features reality --release

Generate the server keypair + a short id:

    2cha reality-keygen            # writes the private key, prints public_key + short_id

Server config:

    [server]
    transport = "reality"

    [reality]
    private_key_file = "/etc/2cha/reality.key"
    dest             = "www.microsoft.com:443"   # real site to borrow / relay probes to
    server_names     = ["www.microsoft.com"]     # accepted SNIs (others → dest)
    short_ids        = ["0123456789abcdef"]

Client config:

    [client]
    transport = "reality"

    [reality]
    public_key  = "<base64 from reality-keygen>"
    short_id    = "0123456789abcdef"
    server_name = "www.microsoft.com"            # SNI to mimic; one of the server's
    fingerprint = "chrome"                        # chrome|firefox|safari|edge

An unauthenticated probe (wrong/no keys) is transparently handed to `dest` inside the
Go core, so it completes a genuine handshake with the real site.
