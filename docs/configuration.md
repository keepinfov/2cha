# Configuration Reference

This is the canonical reference for every `2cha` configuration key: its type, default,
and which side (server, client, or both) it applies to. Other guides link here instead of
repeating defaults.

Configs are TOML. The server reads `server.toml`; the client reads `client.toml`. Default
paths are `/etc/2cha/server.toml` and `/etc/2cha/client.toml` on Unix
(`C:\ProgramData\2cha\*.toml` on Windows); override with `-c/--config`.

Generate a fully-commented starting point with `2cha init server --template > server.toml`
or `2cha init client --template > client.toml` (see [Quick Start](./quickstart.md)).

> Relative file paths (`private_key_file`, `tls.cert_file`, `tls.key_file`) are resolved
> against the config file's directory, not the working directory.

---

## `[server]` — server only

| Key | Type | Default | Description |
|---|---|---|---|
| `listen` | string | **required** | IPv4 listen address `IP:port`, e.g. `"0.0.0.0:51820"`. |
| `listen_v6` | string | `None` | Optional IPv6 listen address, e.g. `"[::]:51820"`. |
| `max_clients` | integer | `256` | Maximum concurrent client sessions (must be > 0). |
| `transport` | `"quic"`\|`"tls"` | `"quic"` | Obfuscation transport. **Must match the client's `transport`.** See [Transports](./transports.md). |

A server config must declare at least one `[[peers]]` entry or it fails validation at load.

## `[client]` — client only

| Key | Type | Default | Description |
|---|---|---|---|
| `server` | string | **required** | Server address: `IP:port` or `host:port` (e.g. `"vpn.example.com:51820"`). |
| `prefer_ipv6` | bool | `false` | Prefer an IPv6 address when a hostname resolves to both. |
| `dns_lookup` | `"auto"`\|`"always"`\|`"never"` | `"auto"` | Hostname resolution mode. `"true"`/`"false"` are accepted aliases for `always`/`never`. `auto` parses an IP first, then falls back to DNS. |
| `transport` | `"quic"`\|`"tls"` | `"quic"` | Obfuscation transport. **Must match the server's `transport`.** |

## `[tun]` — both

| Key | Type | Default | Description |
|---|---|---|---|
| `name` | string | `"tun0"` | TUN interface name. |
| `mtu` | integer (u16) | `1420` | Interface MTU. |
| `queue_len` | integer (u32) | `500` | TUN tx queue length. |

## `[crypto]` — both

| Key | Type | Default | Description | Side |
|---|---|---|---|---|
| `cipher` | `"chacha20-poly1305"`\|`"aes-256-gcm"` | `"chacha20-poly1305"` | AEAD cipher suite. | both |
| `private_key_file` | string | **required** | Path to this host's X25519 private key (raw 32 bytes, mode `0600`). | both |
| `server_public_key` | string (base64) | **required (client)** | The server's public key. Get it with `2cha pubkey server.key`. | client only |

See [Keys & Peers](./keys-and-peers.md) for the key model.

## `[[peers]]` — server only

An array of tables; one per authorized client. Handshakes from keys not listed here are
dropped silently.

| Key | Type | Default | Description |
|---|---|---|---|
| `public_key` | string (base64) | **required** | The client's X25519 public key (`2cha pubkey client.key`). |
| `name` | string | `None` | Human-readable label for logs and `peer list`. |

```toml
[[peers]]
public_key = "CLIENT_PUBLIC_KEY_BASE64"
name = "laptop"
```

Peers can also be added/removed at runtime without a restart — see
[Keys & Peers](./keys-and-peers.md#live-peer-management).

## `[ipv4]`

Shared keys:

| Key | Type | Default (server / client) | Description |
|---|---|---|---|
| `enable` | bool | `true` / `true` | Enable IPv4 on the tunnel. |
| `address` | string | `"10.0.0.1"` / `"10.0.0.2"` | TUN IPv4 address. |
| `prefix` | integer (u8) | `24` | CIDR prefix length (0–32). |

Server-only keys:

| Key | Type | Default | Description |
|---|---|---|---|
| `allowed_ips` | string[] | `[]` | If non-empty, only these source IPs/CIDRs are accepted from clients. |
| `blocked_ips` | string[] | `[]` | Source IPs/CIDRs to drop. |
| `push_routes` | string[] | `[]` | CIDRs advertised to clients. |

Client-only keys:

| Key | Type | Default | Description |
|---|---|---|---|
| `route_all` | bool | `false` | Full tunnel: route `0.0.0.0/0` through the VPN. See [Routing](./routing.md). |
| `routes` | string[] | `[]` | Split tunnel: specific CIDRs to route through the VPN. |
| `exclude_ips` | string[] | `[]` | CIDRs to keep off the tunnel. |

## `[ipv6]`

Same shape as `[ipv4]`. Differences: `enable` defaults to **`false`**, `address` defaults
to `None` (commonly `"fd00:2cha::1"` server / `"fd00:2cha::2"` client), `prefix` defaults to
`64` (0–128).

## `[gateway]` — server only

Controls whether the server acts as an internet gateway (NAT) for clients. All default to
off. See [Server Setup](./server-setup.md#5-gateway-mode-internet-access-for-clients).

| Key | Type | Default | Description |
|---|---|---|---|
| `ip_forward` | bool | `false` | Enable IPv4 forwarding (`net.ipv4.ip_forward=1`). |
| `ip6_forward` | bool | `false` | Enable IPv6 forwarding. |
| `masquerade_v4` | bool | `false` | Add IPv4 NAT (nftables `twocha_nat`, falling back to iptables). |
| `masquerade_v6` | bool | `false` | Add IPv6 NAT. |
| `external_interface` | string | `None` | The egress interface for NAT, e.g. `"eth0"`. |

## `[dns]` — client only

| Key | Type | Default | Description |
|---|---|---|---|
| `servers_v4` | string[] | `[]` | IPv4 DNS servers written to `/etc/resolv.conf` while connected. |
| `servers_v6` | string[] | `[]` | IPv6 DNS servers. |
| `search` | string[] | `[]` | DNS search domains. |

## `[performance]` — both

| Key | Type | Default | Description |
|---|---|---|---|
| `socket_recv_buffer` | integer | `2097152` (2 MiB) | Socket receive buffer in bytes. |
| `socket_send_buffer` | integer | `2097152` (2 MiB) | Socket send buffer in bytes. |
| `batch_size` | integer | `32` | Packets processed per batch. |
| `multi_queue` | bool | `false` | Use multi-queue TUN (Linux). |
| `cpu_affinity` | integer[] | `[]` | CPU cores to pin worker threads to. |

## `[timeouts]` — both

| Key | Type | Default | Description |
|---|---|---|---|
| `session` | integer (u64) | `180` | Drop a session after this many seconds without authenticated traffic. |

## `[logging]` — both

| Key | Type | Default | Description |
|---|---|---|---|
| `level` | string | `"info"` | `error`, `warn`, `info`, `debug`, or `trace`. `-v` forces `debug`, `-q` reduces output. |
| `file` | string | `None` | Log file path. If absent, logs go to stderr. |

## `[tls]` — both (only used when `transport = "tls"`)

| Key | Type | Default | Description | Side |
|---|---|---|---|---|
| `sni` | string | `"www.cloudflare.com"` | SNI the client presents / the server expects. Pick a plausible host. | both |
| `cert_file` | string | `None` | PEM certificate chain. If omitted, the server auto-generates a self-signed cert for `sni`. | server only |
| `key_file` | string | `None` | PEM PKCS#8 private key. Required if `cert_file` is set. | server only |

See [Transports](./transports.md) for why a self-signed cert is safe here (Noise_IK provides
the real authentication inside the TLS tunnel).

---

← [Routing](./routing.md) · [Documentation Home](./README.md) · [Transports](./transports.md) →
