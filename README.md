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

Minimalist anti-censorship VPN with IPv4/IPv6 dual-stack support. Protocol v4: Noise_IK handshake (X25519 + ChaCha20-Poly1305, forward secrecy, per-client keys) wrapped in QUIC mimicry to resist DPI classification.

## Table of Contents

- [Features](#features)
- [Quick Start](#quick-start)
- [Building](#building)
  - [Standard Build](#standard-build)
  - [Static Build](#static-build-portable-binary)
  - [Cross-Compilation](#cross-compilation)
- [Configuration](#configuration)
- [Commands](#commands)
- [Protocol](#protocol)
- [Routing Modes](#routing-modes)
- [Performance Tuning](#performance-tuning)
- [Nix/NixOS](#nixnixos)
- [License](#license)

## Features

- **DPI Resistance** - Traffic is indistinguishable from QUIC: no constant protocol bytes on the wire, randomized padding, jittered keepalives
- **Modern Crypto** - Noise_IK handshake (X25519), ChaCha20-Poly1305 or AES-256-GCM, forward secrecy, automatic rekeying every 2 minutes
- **Per-Client Keys** - Server authenticates clients against a public-key whitelist; no shared PSK
- **Anti-DoS** - Server silently drops unauthenticated packets (no amplification); cookie challenges under load
- **IPv4/IPv6 Dual-Stack** - Full support for both protocols
- **Roaming** - Sessions survive client IP changes
- **Flexible Routing** - Full tunnel or split tunnel modes
- **Static Binary** - Compile with musl for portable binaries

## Quick Start

```bash
# Clone
git clone https://github.com/keepinfov/2cha
cd 2cha

# Build
cargo install --path crates/twocha-cli

# Generate keypairs (private key file is created with 0600 permissions,
# the public key is printed to stdout)
2cha genkey server.key   # on the server
2cha genkey client.key   # on each client

# Exchange PUBLIC keys:
#   - put each client's public key into the server's [[peers]] list
#   - put the server's public key into the client's server_public_key
2cha pubkey client.key

# Create configs
2cha init server > server.toml
2cha init client > client.toml

# Edit configs (key paths + public keys), then:

# On server
sudo 2cha server -c server.toml

# On client
sudo 2cha up -c client.toml

# Check status
2cha status

# Disconnect
sudo 2cha down
```

## Building

### Standard Build

```bash
cargo build --release
```

### Static Build (Portable Binary)

Create a fully static binary with musl:

```bash
# x86_64 (64-bit Intel/AMD)
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl

# ARM64 (Raspberry Pi 4, modern ARM servers)
rustup target add aarch64-unknown-linux-musl
cargo build --release --target aarch64-unknown-linux-musl

# ARMv7 (Raspberry Pi 3, older ARM devices)
rustup target add armv7-unknown-linux-musleabihf
cargo build --release --target armv7-unknown-linux-musleabihf
```

### Cross-Compilation

For easier cross-compilation, use [cross](https://github.com/cross-rs/cross):

```bash
# Install cross
cargo install cross

# Build for different architectures
cross build --release --target aarch64-unknown-linux-musl
cross build --release --target armv7-unknown-linux-musleabihf
cross build --release --target x86_64-unknown-linux-musl

# 32-bit x86
cross build --release --target i686-unknown-linux-musl
```

**Supported targets:**
- `x86_64-unknown-linux-gnu` / `x86_64-unknown-linux-musl` (64-bit x86)
- `i686-unknown-linux-gnu` / `i686-unknown-linux-musl` (32-bit x86)
- `aarch64-unknown-linux-gnu` / `aarch64-unknown-linux-musl` (64-bit ARM)
- `armv7-unknown-linux-gnueabihf` / `armv7-unknown-linux-musleabihf` (ARMv7)
- `arm-unknown-linux-gnueabihf` / `arm-unknown-linux-musleabihf` (ARM)

## Configuration

### Client (`client.toml`)

```toml
[client]
server = "vpn.example.com:51820"

[tun]
name = "tun0"
mtu = 1420

[crypto]
cipher = "chacha20-poly1305"
private_key_file = "/etc/2cha/client.key"        # raw 32 bytes, must be 0600
server_public_key = "SERVER_PUBLIC_KEY_BASE64"   # from: 2cha pubkey server.key

# IPv4 settings
[ipv4]
enable = true
address = "10.0.0.2"
prefix = 24
route_all = true              # Full tunnel

# IPv6 settings
[ipv6]
enable = true
address = "fd00:2cha::2"
prefix = 64
route_all = true

# DNS
[dns]
servers_v4 = ["1.1.1.1", "8.8.8.8"]
servers_v6 = ["2606:4700:4700::1111"]
```

### Server (`server.toml`)

```toml
[server]
listen = "0.0.0.0:51820"
max_clients = 256

[tun]
name = "tun0"
mtu = 1420

[crypto]
private_key_file = "/etc/2cha/server.key"   # raw 32 bytes, must be 0600

# Authorized clients (public-key whitelist)
[[peers]]
public_key = "CLIENT_PUBLIC_KEY_BASE64"     # from: 2cha pubkey client.key
name = "laptop"

[ipv4]
enable = true
address = "10.0.0.1"
prefix = 24

[ipv6]
enable = true
address = "fd00:2cha::1"
prefix = 64

[gateway]
ip_forward = true
ip6_forward = true
masquerade_v4 = true
masquerade_v6 = true
external_interface = "eth0"
```

## Commands

| Command | Description |
|---------|-------------|
| `up` | Connect to VPN |
| `down` | Disconnect |
| `status` | Show connection status |
| `toggle` | Toggle connection on/off |
| `server` | Run as VPN server |
| `genkey <file>` | Generate X25519 keypair (private key → file, public key → stdout) |
| `pubkey <file>` | Print the public key for a private key file |
| `init` | Create config template |

## Options

```
-c, --config <FILE>   Config file path
-d, --daemon          Run in background
-v, --verbose         Detailed output
-q, --quiet           Minimal output
```

## Protocol

Protocol v4 is documented in [docs/protocol-v4.md](docs/protocol-v4.md). In short:

- **Handshake**: Noise_IK (X25519 + ChaCha20-Poly1305 + BLAKE2s). The client knows the server's public key in advance; the server authenticates clients against its `[[peers]]` whitelist. Every session gets fresh ephemeral keys (forward secrecy).
- **Anti-DoS**: every handshake message carries a MAC (keyed BLAKE2s over the receiver's public key) verified before any expensive crypto; packets failing it are dropped with zero bytes in response. Under load the server demands a stateless cookie round-trip.
- **Wire format**: all packets are framed as plausible QUIC v1 (RFC 9000) — handshakes look like Initial/Handshake long-header packets padded to ≥1200 bytes, data looks like short-header packets. No version, type, or counter fields appear in plaintext.
- **Sessions**: deterministic 64-bit nonces, sliding-window replay protection, rekey after 2 minutes, keepalives with randomized size and ±30% interval jitter.

## Routing Modes

### Split Tunnel (default)
Only VPN network traffic goes through VPN:
```toml
[ipv4]
route_all = false
routes = ["10.0.0.0/24", "192.168.100.0/24"]
```

### Full Tunnel
ALL traffic goes through VPN:
```toml
[ipv4]
route_all = true

[ipv6]
route_all = true

[dns]
servers_v4 = ["1.1.1.1"]
```

## Status Output

```
  2cha VPN Status
  ════════════════════════════════════════
  Status:     ● Connected
  Interface:  ● tun0
  IPv4:       10.0.0.2/24
  IPv6:       fd00:2cha::2/64
  Routing:    ● Full tunnel (v4+v6)
  Traffic:    ↓ 15.24 MB / ↑ 3.12 MB
  Public IP:  203.0.113.42
```

## Performance Tuning

```toml
[performance]
socket_recv_buffer = 4194304  # 4MB for high throughput
socket_send_buffer = 4194304
batch_size = 64               # Larger batches
multi_queue = true            # Multi-queue TUN
cpu_affinity = [0, 1]         # Pin to CPUs
```

## Nix/NixOS

### Using Flakes

Build and run directly from GitHub:
```bash
# Run without installing
nix run github:keepinfov/2cha -- --help

# Build dynamic version
nix build github:keepinfov/2cha

# Build static version (musl, supports x86_64 and aarch64)
nix build github:keepinfov/2cha#static

# Install to profile
nix profile install github:keepinfov/2cha
```

### Local Development

```bash
# Clone repository
git clone https://github.com/keepinfov/2cha
cd 2cha

# Enter development shell (includes Rust, cargo-watch, etc.)
nix develop

# Build with cargo
cargo build --release

# Or build with Nix
nix build          # Dynamic binary
nix build .#static # Static musl binary
```

### For Non-Flake Users

```bash
# Build with nix-build
nix-build

# Development shell
nix-shell
```

## License

MIT
