# Routing

Routing decides **which traffic goes through the tunnel**. It's configured under the client's
`[ipv4]`/`[ipv6]` sections, with the server able to advertise routes and the operator
controlling NAT separately (see [Server Setup](./server-setup.md#5-gateway-mode-internet-access-for-clients)).

## Split tunnel (default)

Only the VPN subnet — plus any extra `routes` you list — goes through the tunnel; everything
else uses the normal connection. This is the default (`route_all = false`).

```toml
[ipv4]
route_all = false
routes = ["10.0.0.0/24", "192.168.100.0/24"]   # CIDRs to send through the VPN
exclude_ips = []                                # CIDRs to keep off the VPN
```

Use this for reaching private networks behind the server without sending all your traffic
through it.

## Full tunnel

All traffic goes through the server. Set `route_all = true`; you'll almost always want to set
DNS too, so lookups don't leak to your local resolver.

```toml
[ipv4]
route_all = true

[ipv6]
route_all = true       # also tunnel IPv6, or leave disabled to avoid IPv6 leaks

[dns]
servers_v4 = ["1.1.1.1", "8.8.8.8"]
servers_v6 = ["2606:4700:4700::1111"]
```

When `route_all = true`, the client:

- pins the **server's** address through your *original* default gateway (so the encrypted
  tunnel packets don't loop back into the tunnel), then
- sets the new default route to the VPN gateway, and
- backs up and rewrites `/etc/resolv.conf` with your `[dns]` servers.

All of this is reverted on `2cha down` (or when the client process exits).

For full-tunnel clients to reach the **internet** (not just the server), the server must run
in [gateway mode](./server-setup.md#5-gateway-mode-internet-access-for-clients) with NAT.

## `exclude_ips`

Keep specific destinations off the tunnel even in full-tunnel mode — e.g. a LAN printer or a
latency-sensitive service:

```toml
[ipv4]
route_all = true
exclude_ips = ["192.168.1.0/24"]
```

## Server-advertised routes and access control

On the **server**, `[ipv4]`/`[ipv6]` offer:

- `push_routes` — CIDRs advertised to clients (e.g. private networks reachable behind the
  server).
- `allowed_ips` / `blocked_ips` — a source-IP allow/deny list applied to client traffic
  (empty `allowed_ips` means "allow all").

```toml
# server.toml
[ipv4]
address = "10.0.0.1"
prefix = 24
push_routes = ["192.168.100.0/24"]
allowed_ips = []
blocked_ips = []
```

## DNS

The client's `[dns]` section controls resolver settings applied while connected:

| Key | Effect |
|---|---|
| `servers_v4` / `servers_v6` | DNS servers written to `/etc/resolv.conf` for the session. |
| `search` | DNS search domains. |

The original `/etc/resolv.conf` is restored on disconnect. Setting DNS is strongly
recommended with `route_all = true` to avoid DNS leaks.

## MTU

The tunnel `mtu` defaults to `1420` (under the typical `1500` to leave room for encapsulation
overhead). If you see large packets stalling on an unusual path, lower `tun.mtu` on both ends.

See the [Configuration Reference](./configuration.md) for exact types and defaults.

---

← [Transports](./transports.md) · [Documentation Home](./README.md) · [Configuration Reference](./configuration.md) →
