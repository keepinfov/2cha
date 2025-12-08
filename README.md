```
  ██████╗  ██████╗██╗  ██╗ █████╗ 
  ╚════██╗██╔════╝██║  ██║██╔══██╗
   █████╔╝██║     ███████║███████║
  ██╔═══╝ ██║     ██╔══██║██╔══██║
  ███████╗╚██████╗██║  ██║██║  ██║
  ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝
```

# 2cha - High-Performance VPN Utility

Minimalist VPN tool with IPv4/IPv6 dual-stack support, powered by ChaCha20-Poly1305 encryption.

## Features

- **IPv4/IPv6 Dual-Stack** - Full support for both protocols
- **High Performance** - Optimized crypto and I/O
- **Static Binary** - Compile with musl for portable binaries
- **Flexible Routing** - Full tunnel or split tunnel modes
- **Modern Crypto** - ChaCha20-Poly1305 or AES-256-GCM

## Quick Start

```bash
# Clone
git clone https://github.com/keepinfov/2cha
cd 2cha

# Build
cargo install --path .

# Generate key (save this!)
2cha genkey > vpn.key

# Create configs
2cha init server > server.toml
2cha init client > client.toml

# Edit configs, add key, then:

# On server
sudo 2cha server -c server.toml

# On client
sudo 2cha up -c client.toml

# Check status
2cha status

# Disconnect
sudo 2cha down
```

## Static Build (Portable Binary)

```bash
# Install musl target
rustup target add x86_64-unknown-linux-musl

# Build static binary
cargo build --release --target x86_64-unknown-linux-musl

# Or use build script
./build.sh static

# For ARM64 (Raspberry Pi, etc.)
rustup target add aarch64-unknown-linux-musl
./build.sh static-arm
```

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
key = "your_64_char_hex_key"

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
key = "same_key_as_clients"

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
| `genkey` | Generate encryption key |
| `init` | Create config template |

## Options

```
-c, --config <FILE>   Config file path
-d, --daemon          Run in background
-v, --verbose         Detailed output
-q, --quiet           Minimal output
```

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

## NixOS
You can build it using
```bash
# dynamic version 
nix build github:keepinfov/2cha

# static version (musl, supports aarch64 and x86_64) 
nix build github:keepinfov/2cha#static

# or if you wanna build by your own
git clone https://github.com/keepinfov/2cha
nix develop
cargo build --release
```
or you can just run it using
```bash
nix run github:keepinfov/2cha
```

## License

MIT
