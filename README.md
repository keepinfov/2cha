```
  ██████╗  ██████╗██╗  ██╗ █████╗ 
  ╚════██╗██╔════╝██║  ██║██╔══██╗
   █████╔╝██║     ███████║███████║
  ██╔═══╝ ██║     ██╔══██║██╔══██║
  ███████╗╚██████╗██║  ██║██║  ██║
  ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝
```

# 2cha - Simple VPN Utility

Minimalist VPN tool powered by ChaCha20-Poly1305 encryption.

## Quick Start

```bash
# Build
cargo build --release

# Generate key (save this!)
./2cha genkey > vpn.key

# Create configs
./2cha init server > server.toml
./2cha init client > client.toml

# Edit configs, add key, then:

# On server (e.g., Raspberry Pi)
sudo ./2cha server -c server.toml

# On client
sudo ./2cha up -c client.toml

# Check status
./2cha status

# Disconnect
sudo ./2cha down
```

## Commands

| Command | Description |
|---------|-------------|
| `up` | Connect to VPN |
| `down` | Disconnect |
| `status` | Show connection status |
| `toggle` | Toggle connection on/off |
| `server` | Run as VPN server |
| `genkey` | Generate new encryption key |
| `init` | Create config template |

## Options

```
-c, --config <FILE>   Config file path
-d, --daemon          Run in background
-v, --verbose         Detailed output
-q, --quiet           Minimal output
```

## Configuration

### Client (`client.toml`)

```toml
[client]
server = "vpn.example.com:51820"

[tun]
address = "10.0.0.2"

[crypto]
cipher = "chacha20-poly1305"
key = "your_64_char_hex_key"

[routing]
route_all_traffic = true  # Full tunnel
dns = ["1.1.1.1"]
```

### Server (`server.toml`)

```toml
[server]
listen = "0.0.0.0:51820"

[tun]
address = "10.0.0.1"

[crypto]
key = "same_key_as_clients"

[routing]
ip_forward = true        # Enable gateway mode
masquerade = true
external_interface = "eth0"
```

## Routing Modes

### Split Tunnel (default)
Only VPN network traffic goes through VPN:
```toml
[routing]
route_all_traffic = false
routes = ["10.0.0.0/24"]
```

### Full Tunnel
ALL traffic goes through VPN:
```toml
[routing]
route_all_traffic = true
dns = ["1.1.1.1", "8.8.8.8"]
```

Requires server gateway mode enabled!

## NixOS

```bash
# Enter dev shell
nix-shell

# Or with flake
nix develop

# Build
cargo build --release
```

## Status Output

```
  2cha VPN Status
  ─────────────────────────────────
  Status:    ● Connected
  VPN IP:    10.0.0.2/24
  Routing:   ● Full tunnel (all traffic via VPN)
  Public IP: 203.0.113.42
  Traffic:   ↓ 15.2 MB / ↑ 3.1 MB
```

## License

MIT
