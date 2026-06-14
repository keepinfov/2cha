# 2cha Documentation

**2cha** is a minimalist anti-censorship VPN. Protocol v4 runs a Noise_IK handshake
(X25519 + ChaCha20-Poly1305, forward secrecy, per-client keys) inside an obfuscation
transport — either UDP with QUIC mimicry (default) or real TLS 1.3 over TCP — so a passive
or active observer sees plausible cover traffic rather than a VPN.

These guides take you from a fresh machine to a working server-and-client tunnel, then into
day-to-day operation.

## Getting started

| Guide | What it covers |
|---|---|
| [Installation](./installation.md) | Building from source, static (musl) and cross builds, Nix, platform requirements. |
| [Quick Start](./quickstart.md) | The 5-minute end-to-end path: keys → configs → run server → connect client → verify. |

## Setting up

| Guide | What it covers |
|---|---|
| [Keys & Peers](./keys-and-peers.md) | The key model, generating/exchanging keys, and live peer management. |
| [Server Setup](./server-setup.md) | First-time server config, gateway/NAT, firewall, running as a service. |
| [Client Setup](./client-setup.md) | Client config, connecting, status, running as a service. |

## Reference & tuning

| Guide | What it covers |
|---|---|
| [Configuration Reference](./configuration.md) | Every config key, type, default, and side. |
| [Transports](./transports.md) | `quic` vs `tls`, the `[tls]` section, when to use which. |
| [Routing](./routing.md) | Full vs split tunnel, pushed routes, DNS. |
| [Troubleshooting](./troubleshooting.md) | Common failures and how to fix them. |
| [Testing](./testing.md) | The end-to-end network-namespace test harness. |

## Internals

| Document | What it covers |
|---|---|
| [Protocol v4](./protocol-v4.md) | The on-the-wire protocol: handshake, anti-DoS, framing, sessions. |
| [Windows Support](./windows-support.md) | Current Windows status and remaining work. |

---

> **Platform note:** the VPN runtime is currently **Linux-only** (the event loop and routing
> use `poll(2)` and netlink). The TUN device layer is cross-platform, but the server/client
> do not yet run on Windows — see [Windows Support](./windows-support.md).
