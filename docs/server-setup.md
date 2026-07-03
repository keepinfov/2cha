# Server Setup

> **Turn-key alternative:** `sudo 2cha setup` (or the
> [install one-liner](./quickstart.md)) automates steps 2–8 below: config wizard, systemd
> unit, IP forwarding, firewall, start + verify — plus a QR code for the mobile app.
> `2cha init server` covers only the config/keys part (steps 2–3).

This guide walks through setting up a 2cha server for the first time: a minimal working
config, authorizing clients, giving them internet access, and running the server as a
service. It assumes you've [installed](./installation.md) the binary and read
[Keys & Peers](./keys-and-peers.md).

The server needs **root** (or `CAP_NET_ADMIN`) because it creates a TUN device and changes
routing/NAT. `2cha server` auto-prompts for `sudo` if needed.

## 1. Generate the server key

```bash
sudo mkdir -p /etc/2cha
sudo 2cha genkey /etc/2cha/server.key     # note the printed public key
```

Clients will need that public key. The private key file is created `0600`.

## 2. A minimal server config

Start from the template, then trim to the essentials:

```bash
2cha init server --template > /etc/2cha/server.toml
```

A minimal working `server.toml`:

```toml
[server]
listen = "0.0.0.0:51820"
max_clients = 256
transport = "quic"            # or "tls" — see ./transports.md (must match clients)

[tun]
name = "tun0"
mtu = 1420

[crypto]
cipher = "chacha20-poly1305"
private_key_file = "/etc/2cha/server.key"

[[peers]]
public_key = "CLIENT_PUBLIC_KEY_BASE64"   # 2cha pubkey client.key
name = "laptop"

[ipv4]
enable = true
address = "10.0.0.1"          # the server's address inside the tunnel
prefix = 24

[ipv6]
enable = false
```

The tunnel subnet here is `10.0.0.0/24`; the server is `10.0.0.1` and clients take other
addresses in that range. See the [Configuration Reference](./configuration.md) for every key.

## 3. Authorize clients

Each client needs a `[[peers]]` entry containing its public key. Add them in the config (as
above) before starting, or add them live on a running server:

```bash
2cha peer add <CLIENT_PUBLIC_KEY_BASE64> --name phone
2cha peer list
```

See [Keys & Peers: Live peer management](./keys-and-peers.md#live-peer-management).

## 4. Open the firewall

**The server does not open ports for you.** Open the `listen` port for the right protocol:

- `transport = "quic"` → **UDP**
- `transport = "tls"` → **TCP**

```bash
sudo ufw allow 51820/udp        # quic
# sudo ufw allow 443/tcp        # tls (if you listen on 443)
```

## 5. Gateway mode (internet access for clients)

By default the server only connects clients to itself and to each other inside the tunnel
subnet. To let clients reach the **internet** through the server, enable gateway mode:

```toml
[gateway]
ip_forward = true
masquerade_v4 = true
external_interface = "eth0"     # the server's internet-facing interface

# for IPv6 as well:
# ip6_forward = true
# masquerade_v6 = true
```

When these are set, the server **itself** does the following on startup and **rolls it all
back on shutdown**:

- enables IP forwarding (`sysctl net.ipv4.ip_forward=1`, falling back to writing `/proc`);
- adds a NAT/masquerade rule via **nftables** (table `twocha_nat`), falling back to **iptables**;
- adds the matching FORWARD rules between `tun0` and `external_interface`.

What you must still handle yourself:

- **Confirm `external_interface`** is the correct egress NIC (`ip route get 1.1.1.1`).
- **Persist `ip_forward`** across reboots if you want it independent of 2cha (e.g. a
  `/etc/sysctl.d/` drop-in). 2cha only restores the *previous* value on exit.
- **Firewall** rules from step 4 (and any cloud-provider security group).
- Clients still choose whether to send all traffic through the tunnel — see
  [Routing: Full vs split tunnel](./routing.md).

## 6. Choose a transport

`quic` (default) frames traffic to look like QUIC over UDP. `tls` runs a real TLS 1.3
handshake over TCP (often on `:443`) with Noise riding inside — better against active probing
and TCP-only networks. Both ends must agree. See [Transports](./transports.md).

## 7. Run the server

Foreground (good for first runs — you see the logs):

```bash
sudo 2cha server -c /etc/2cha/server.toml
```

Background daemon:

```bash
sudo 2cha server -c /etc/2cha/server.toml --daemon
```

Add `-v` for debug logging, `-q` for minimal output. A healthy startup logs the server public
key, the TUN address, `Server ready. Authorized peers: N …`, and the listen line. Stop a
foreground server with Ctrl-C; it tears down any NAT/forwarding it added.

## 8. Run as a service (systemd)

`/etc/systemd/system/2cha-server.service`:

```ini
[Unit]
Description=2cha VPN server
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/2cha server -c /etc/2cha/server.toml
Restart=on-failure
# Runs as root for TUN + routing. To drop privileges instead, grant CAP_NET_ADMIN.

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now 2cha-server
journalctl -u 2cha-server -f
```

## 9. Verify

```bash
2cha peer list                  # who's authorized / connected
journalctl -u 2cha-server -f    # live logs
```

From a connected client, `ping 10.0.0.1`. If clients connect but have no internet, revisit
[gateway mode](#5-gateway-mode-internet-access-for-clients) — see also
[Troubleshooting](./troubleshooting.md).

---

← [Keys & Peers](./keys-and-peers.md) · [Documentation Home](./README.md) · [Client Setup](./client-setup.md) →
