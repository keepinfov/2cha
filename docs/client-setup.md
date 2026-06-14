# Client Setup

This guide sets up a 2cha client: a minimal config, connecting, checking status, and running
it as a service. It assumes you've [installed](./installation.md) the binary and have the
server's public key (see [Keys & Peers](./keys-and-peers.md)).

The client needs **root** (or `CAP_NET_ADMIN`) to create the TUN device and change routes;
`2cha up` auto-prompts for `sudo`.

## 1. Generate the client key

```bash
sudo mkdir -p /etc/2cha
sudo 2cha genkey /etc/2cha/client.key     # give the printed public key to the server operator
```

The server operator adds that public key to the server's `[[peers]]`.

## 2. A minimal client config

```bash
2cha init client --template > /etc/2cha/client.toml
```

A minimal working `client.toml`:

```toml
[client]
server = "203.0.113.10:51820"     # server IP/host : listen port
transport = "quic"                # must match the server

[tun]
name = "tun0"
mtu = 1420

[crypto]
cipher = "chacha20-poly1305"
private_key_file = "/etc/2cha/client.key"
server_public_key = "SERVER_PUBLIC_KEY_BASE64"   # 2cha pubkey server.key (on the server)

[ipv4]
enable = true
address = "10.0.0.2"              # this client's address inside the tunnel
prefix = 24
route_all = false                 # split tunnel; see ./routing.md

[ipv6]
enable = false
```

`address` must be in the server's tunnel subnet and unique per client. Every key is described
in the [Configuration Reference](./configuration.md).

> `cipher` and `transport` must match the server. The `server` value may be a hostname; set
> `dns_lookup`/`prefer_ipv6` under `[client]` to control resolution.

## 3. Connect

```bash
sudo 2cha up -c /etc/2cha/client.toml
```

Add `-v` for verbose handshake logging, `-q` for minimal output. On success you'll see the
handshake complete and a status block with the tunnel addresses and routing mode.

`up` runs in the foreground by default. To background it:

```bash
sudo 2cha up -c /etc/2cha/client.toml --daemon
```

## 4. Status, toggle, disconnect

```bash
2cha status            # interface, addresses, routing mode, traffic, public IP
2cha toggle            # connect if down, disconnect if up (alias: t)
sudo 2cha down         # disconnect and restore original routes/DNS
```

`down` and `toggle` find the running client via its PID file (`/run/2cha.pid`, with
`$XDG_RUNTIME_DIR`/`/tmp` fallbacks). On disconnect the client restores the original default
gateway, removes routes it added, and restores `/etc/resolv.conf` if it changed it.

## 5. Routing

By default this is a **split tunnel**: only the VPN subnet (and any `routes` you add) goes
through the tunnel. To send **all** traffic through the server, set `route_all = true` and
usually configure `[dns]`. Full details, including `routes`/`exclude_ips` and DNS behavior,
are in [Routing](./routing.md).

## 6. Run as a service (systemd)

`/etc/systemd/system/2cha-client.service`:

```ini
[Unit]
Description=2cha VPN client
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/2cha up -c /etc/2cha/client.toml
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now 2cha-client
journalctl -u 2cha-client -f
```

If a connection fails or you have no internet after connecting, see
[Troubleshooting](./troubleshooting.md).

---

← [Server Setup](./server-setup.md) · [Documentation Home](./README.md) · [Transports](./transports.md) →
