# Transports

2cha carries the same Noise_IK-encrypted protocol inside one of two **obfuscation
transports**. The transport only changes what the traffic *looks like* on the wire — the
cryptographic core (handshake, per-client keys, forward secrecy) is identical either way.

Set it with `transport` under `[server]` and `[client]`. **Both ends must use the same
value.** The default is `quic`.

| | `quic` (default) | `tls` |
|---|---|---|
| Layer 4 | UDP | TCP |
| Looks like | QUIC v1 traffic | a real HTTPS/TLS 1.3 session |
| Handshake on the wire | QUIC-mimicry framing (no real TLS) | a genuine TLS 1.3 handshake (ServerHello, certificate) |
| Certificate a prober sees | none (silent drop) | server's own (self-signed) cert |
| Anti-DoS | MAC1 + stateless cookie; unauthenticated packets dropped with zero reply | TCP handshake + rate limiting |
| Best when | UDP is allowed and unthrottled | UDP is blocked/throttled, or active probing is a concern |

## How the crypto relates to the transport

In **both** transports, Noise_IK runs *inside* and is the sole authenticator:

- With `quic`, the QUIC-looking framing is cosmetic; the Noise messages are the payload.
- With `tls`, a real TLS 1.3 tunnel is established first, and the Noise handshake then runs
  inside it. **TLS here is an envelope for blending in, not the trust anchor** — so the
  server's TLS certificate can be (and by default is) self-signed. Authentication still comes
  entirely from Noise_IK and the `[[peers]]` whitelist.

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
the **TCP** port on the server's firewall (`quic` uses **UDP**). See
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
