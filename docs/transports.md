# Transports

2cha carries the same Noise_IK-encrypted protocol inside one of three **obfuscation
transports**. The transport only changes what the traffic *looks like* on the wire — the
cryptographic core (handshake, per-client keys, forward secrecy) is identical either way.

Set it with `transport` under `[server]` and `[client]`. **Both ends must use the same
value.** The default is `quic`.

| | `quic` (default) | `tls` | `awg` |
|---|---|---|---|
| Layer 4 | UDP | TCP | UDP |
| Looks like | QUIC v1 traffic | a real HTTPS/TLS 1.3 session | nothing — no fixed bytes |
| Handshake on the wire | QUIC-mimicry framing (no real TLS) | a genuine TLS 1.3 handshake (ServerHello, certificate) | randomized per-packet magic headers + junk/signature packets |
| DPI philosophy | *mimicry* (blend in as a known protocol) | *mimicry* (be a real protocol) | *randomization* (look like nothing) |
| Certificate a prober sees | none (silent drop) | server's own (self-signed) cert | none (silent drop) |
| Anti-DoS | MAC1 + stateless cookie; unauthenticated packets dropped with zero reply | TCP handshake + rate limiting | MAC1 + stateless cookie; unauthenticated packets dropped with zero reply |
| Best when | UDP is allowed and unthrottled | UDP is blocked/throttled, or active probing is a concern | a DPI blocks *known* protocols (incl. QUIC) but passes unclassified UDP |

## How the crypto relates to the transport

In **all** transports, Noise_IK runs *inside* and is the sole authenticator:

- With `quic`, the QUIC-looking framing is cosmetic; the Noise messages are the payload.
- With `tls`, a real TLS 1.3 tunnel is established first, and the Noise handshake then runs
  inside it. **TLS here is an envelope for blending in, not the trust anchor** — so the
  server's TLS certificate can be (and by default is) self-signed. Authentication still comes
  entirely from Noise_IK and the `[[peers]]` whitelist.
- With `awg`, the framing is stripped of every constant byte instead of imitating a protocol.
  The Noise messages are the payload, wrapped in a 4-byte random header (see below).

## `quic` vs `awg`: mimicry vs randomization

`quic` and `awg` are both UDP carriers of the same Noise messages, but take **opposite** stances
against DPI:

- **`quic` mimics.** Every datagram is shaped to look like QUIC v1 (version field, connection-ID
  length markers, length varints). This sails through a DPI that allowlists QUIC, but its fixed
  structure is itself a fingerprint a censor can learn.
- **`awg` randomizes** (the AmneziaWG 2.0 approach). There are **no constant bytes** on the wire:
  each packet's leading 4 bytes are a random value drawn from a per-message-type range (the
  "magic header", `H1`–`H4`), packets carry random padding (`S1`–`S4`), and before each handshake
  the client emits `Jc` junk datagrams of random size plus optional protocol-signature packets.
  A DPI has nothing constant to match on. The cost: `awg` does not *look* like any allowlisted
  protocol, so it only helps where unclassified UDP is permitted to pass.

Pick `awg` when a censor blocks recognised protocols (including QUIC mimicry) but still forwards
otherwise-unclassifiable UDP; pick `quic` when QUIC itself is allowed and you want the throughput
of a lean, batched UDP datapath.

## The `[tls]` section

Only consulted when `transport = "tls"`.

```toml
[tls]
sni = "www.cloudflare.com"     # SNI the client sends / the server expects
# cert_file = "/etc/2cha/tls/fullchain.pem"   # optional (server)
# key_file  = "/etc/2cha/tls/privkey.pem"     # required if cert_file is set
```

- **`sni`** — pick a plausible hostname so the ClientHello blends in with ordinary HTTPS.
  The client presents it; the server expects it. Defaults to `www.cloudflare.com`.
- **`cert_file` / `key_file`** — optional, server-side. If omitted, the server **generates a
  self-signed certificate for `sni`** at startup. Supply a real cert/key pair (e.g. from
  Let's Encrypt) if you'd rather present a CA-valid certificate. If you set `cert_file`, you
  must also set `key_file`.

Because the cert is allowed to be self-signed, a client connecting with `2cha` does not
verify it against a CA — that's deliberate and safe, since Noise inside the tunnel provides
real mutual authentication.

## The `[awg]` section

Only consulted when `transport = "awg"`. The wire-format fields (`h1`–`h4`, `header_span`,
`s1`–`s4`) are **part of the on-wire format and MUST be byte-for-byte identical on the server
and every client** — a mismatch means the two ends classify packets differently and no
handshake ever validates. The junk knobs (`jc`, `jmin`, `jmax`) and signature templates
(`i1`–`i5`) are **client-only**; the server ignores them. `2cha init` generates a matched
set automatically — you rarely need to write this by hand.

```toml
[awg]
# Magic headers: each packet's first 4 bytes are a random u32 in [hN, hN + header_span].
# The four resulting ranges MUST NOT overlap. init=h1, resp=h2, cookie=h3, data=h4.
h1 = 271896630
h2 = 1345638454
h3 = 2419380278
h4 = 3493122102
header_span = 16777215      # width of each range (0 = static 1.x-style headers)

# Random padding (max extra bytes) per message class: init / resp / cookie / data.
s1 = 24
s2 = 40
s3 = 24
s4 = 16

# Junk packets fired before each handshake (client-only). jc = 0 disables.
jc = 4
jmin = 64
jmax = 1024

# Optional CPS signature packets sent before the junk burst (client-only, i1..i5).
# Composable tags render into raw bytes so a packet can mimic another protocol's opener:
#   <b HEX>  literal bytes (whitespace in the hex is ignored)
#   <t>      current Unix time, 4-byte big-endian
#   <r N>    N cryptographically-random bytes
#   <rc N>   N random ASCII letters [A-Za-z]
#   <rd N>   N random decimal digits [0-9]
# i1 = "<b 0d0a0d0a><r 16>"
```

How it maps to AmneziaWG 2.0: `Jc`/`Jmin`/`Jmax` are the junk-packet count and size range;
`S1`–`S4` are the per-message-type padding; `H1`–`H4` are the message "magic headers"
(2.0 makes them dynamic per-packet ranges via `header_span`); `I1`–`I5` are the CPS
signature packets. The server needs no special handling for junk or signature packets —
none of them match a configured header range, so they fail to parse and the datapath drops
them silently (it never replies to unauthenticated bytes).

## Performance: prefer `quic` for throughput

Choose `tls` only when you need it (UDP blocked/throttled, active-probing concerns).
For raw throughput `quic` is the better transport:

- **TCP-in-TCP meltdown is inherent to `tls` mode.** Tunnelling TCP flows through another
  TCP connection stacks two loss-recovery/congestion-control loops: when the outer TCP
  retransmits, the inner TCP's RTT estimate inflates and both stacks back off, collapsing
  throughput on lossy paths. No amount of tuning in 2cha can remove this — it's a property
  of the encapsulation.
- The `quic` path preserves datagram semantics end to end (inner TCP sees real loss and
  reacts once) and uses batched `recvmmsg`/`sendmmsg` syscalls on Linux.

## Choosing a port

`tls` is typically run on `:443` so it's indistinguishable from a web server. Remember to open
the **TCP** port on the server's firewall (`quic` and `awg` both use **UDP**). See
[Server Setup](./server-setup.md#4-open-the-firewall).

## Verifying a TLS server

A real TLS server completes a handshake and presents a certificate; the fake-QUIC path would
silently drop the probe. You can confirm with:

```bash
openssl s_client -connect SERVER:443 -servername www.cloudflare.com -showcerts </dev/null
```

A genuine handshake returns a `BEGIN CERTIFICATE` block. The self-signed cert will fail CA
verification — that is expected and not an error for 2cha. The end-to-end
[test harness](./testing.md) automates this check in `--tls` mode.

---

← [Client Setup](./client-setup.md) · [Documentation Home](./README.md) · [Routing](./routing.md) →
