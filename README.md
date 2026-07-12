```
  ██████╗  ██████╗██╗  ██╗ █████╗
  ╚════██╗██╔════╝██║  ██║██╔══██╗
   █████╔╝██║     ███████║███████║
  ██╔═══╝ ██║     ██╔══██║██╔══██║
  ███████╗╚██████╗██║  ██║██║  ██║
  ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝
```

# 2cha - High-Performance VPN Utility

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-1.70+-orange.svg)](https://www.rust-lang.org)

Minimalist anti-censorship VPN with IPv4/IPv6 dual-stack support. Protocol v4: a Noise_IK
handshake (X25519 + ChaCha20-Poly1305, forward secrecy, per-client keys) carried inside an
obfuscation transport — UDP with QUIC mimicry by default, or real TLS 1.3 over TCP — to
resist DPI classification and active probing.

## Features

- **DPI Resistance** — traffic mimics QUIC (no constant protocol bytes, randomized padding,
  jittered keepalives), or a real TLS 1.3 session over TCP. See [Transports](docs/transports.md).
- **Modern Crypto** — Noise_IK (X25519), ChaCha20-Poly1305 or AES-256-GCM, forward secrecy,
  automatic rekeying.
- **Per-Client Keys** — clients are authenticated against a public-key whitelist; no shared PSK.
- **Anti-DoS** — unauthenticated packets are dropped with zero reply; cookie challenges under load.
- **IPv4/IPv6 Dual-Stack**, **roaming** across client IP changes, and **full or split tunnel** routing.
- **Static Binary** — build with musl for a portable, dependency-free binary.

## Quick Start

**Server one-liner** — installs the latest release and runs the turn-key setup (config
wizard, systemd service, forwarding, firewall, QR code for the mobile app):

```bash
sudo sh -c "$(curl -fsSL https://raw.githubusercontent.com/keepinfov/2cha/master/scripts/install.sh)"
```

Manual path:

```bash
# Build & install
cargo install --path crates/twocha-cli

# Generate keypairs (private key → file at 0600; public key → stdout)
2cha genkey server.key      # on the server
2cha genkey client.key      # on each client

# Create config templates
2cha init server --template > server.toml
2cha init client --template > client.toml

# Exchange PUBLIC keys:
#   - each client's public key goes in the server's [[peers]] list
#   - the server's public key goes in the client's crypto.server_public_key
# Then edit the configs (key paths, server address) and run:

sudo 2cha server -c server.toml     # on the server
sudo 2cha up -c client.toml         # on the client
2cha status                         # check the connection
sudo 2cha down                      # disconnect
```

A step-by-step walkthrough is in the [Quick Start guide](docs/quickstart.md).

## Documentation

Full documentation lives in [`docs/`](docs/README.md):

- **[Installation](docs/installation.md)** — building, static/cross builds, Nix, platform requirements
- **[Quick Start](docs/quickstart.md)** — end-to-end in five minutes
- **[Keys & Peers](docs/keys-and-peers.md)** — the key model and live peer management
- **[Server Setup](docs/server-setup.md)** — first-time setup, gateway/NAT, running as a service
- **[Client Setup](docs/client-setup.md)** — connecting and running as a service
- **[Config CLI](docs/config-cli.md)** — inspect/edit configs with `2cha config`, validated and atomic
- **[NixOS](docs/nixos.md)** — declarative `services.twocha` server/client
- **[Configuration Reference](docs/configuration.md)** — every config key, type, and default
- **[Transports](docs/transports.md)** — `quic` vs `tls`
- **[Routing](docs/routing.md)** — full vs split tunnel, DNS
- **[Troubleshooting](docs/troubleshooting.md)** — common failures and fixes
- **[Testing](docs/testing.md)** — the end-to-end network-namespace harness
- **[Protocol v4](docs/protocol-v4.md)** — the on-the-wire protocol
- **[Windows Support](docs/windows-support.md)** — current status

## Commands

| Command | Description |
|---|---|
| `up` / `down` | Connect / disconnect |
| `status` | Show connection status |
| `toggle` | Connect if down, disconnect if up |
| `server` | Run as a VPN server |
| `genkey <file>` | Generate an X25519 keypair (private → file, public → stdout) |
| `pubkey <file>` | Print the public key for a private key file |
| `peer add/remove/list` | Manage authorized peers on a running server |
| `config validate/show/get/set/edit` | Inspect and edit a config file (validated, atomic) |
| `init [client\|server]` | Create a config (wizard; `--template` for stdout) |

Common flags: `-c/--config <FILE>`, `-d/--daemon`, `-v/--verbose`, `-q/--quiet`.

> **Platform note:** the VPN runtime is currently **Linux-only**. The TUN layer is
> cross-platform, but the server/client do not yet run on Windows — see
> [Windows Support](docs/windows-support.md).

## License

MIT
