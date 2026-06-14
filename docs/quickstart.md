# Quick Start

This is the fastest path from nothing to a working tunnel between a **server** (a host with
a public IP) and a **client**. It uses the default `quic` transport and a single client.

If you haven't built the binary yet, see [Installation](./installation.md). For the full
explanation of each step, follow the links into the detailed guides.

## 1. Generate a keypair on each host

`genkey` writes the **private** key to the file (mode `0600`) and prints the **public** key
to stdout.

```bash
# On the server
2cha genkey server.key            # prints the server's public key

# On the client
2cha genkey client.key            # prints the client's public key
```

Keep each public key — you'll exchange them in step 3. You can reprint a public key anytime
with `2cha pubkey <keyfile>`. More detail in [Keys & Peers](./keys-and-peers.md).

## 2. Create config templates

```bash
# On the server
2cha init server --template > server.toml

# On the client
2cha init client --template > client.toml
```

These templates are fully commented and contain every section with sensible defaults.

## 3. Exchange public keys

Two facts must be wired up (this is the most common thing to get wrong):

- The **client** needs the **server's** public key in `crypto.server_public_key`.
- The **server** needs the **client's** public key in a `[[peers]]` entry.

```toml
# client.toml
[crypto]
private_key_file = "client.key"
server_public_key = "<SERVER PUBLIC KEY from step 1>"
```

```toml
# server.toml
[[peers]]
public_key = "<CLIENT PUBLIC KEY from step 1>"
name = "laptop"
```

Also set, in `client.toml`, the server's address:

```toml
[client]
server = "203.0.113.10:51820"     # your server's public IP and listen port
```

And point both `crypto.private_key_file` values at the keys from step 1.

## 4. Open the firewall (server)

The server does **not** open ports for you. With the default `quic` transport the listener is
**UDP**:

```bash
# example: ufw
sudo ufw allow 51820/udp
```

(With `transport = "tls"` it's TCP instead — see [Transports](./transports.md).)

## 5. Run the server

```bash
sudo 2cha server -c server.toml
```

You should see `Server ready. Authorized peers: 1 …` and `Listening on 0.0.0.0:51820 (udp/quic)`.

## 6. Connect the client

```bash
sudo 2cha up -c client.toml
```

On success you'll see the handshake complete and a status block showing the tunnel addresses
(e.g. `10.0.0.2` ↔ gateway `10.0.0.1`).

## 7. Verify

```bash
# from the client, ping the server's tunnel address
ping 10.0.0.1

# check status anytime
2cha status

# on the server, list peers and their connection state
2cha peer list
```

## 8. Disconnect

```bash
sudo 2cha down              # client
# Ctrl-C (or SIGTERM) stops the server and rolls back any NAT/routes it added
```

## Where to next

- Give clients **internet access** through the server → [Server Setup: Gateway mode](./server-setup.md#5-gateway-mode-internet-access-for-clients)
- **Full vs split tunnel** and DNS → [Routing](./routing.md)
- Hide the tunnel as **HTTPS** → [Transports](./transports.md)
- Run server/client as a **service** → [Server Setup](./server-setup.md#8-run-as-a-service-systemd) · [Client Setup](./client-setup.md#6-run-as-a-service-systemd)
- Something not working? → [Troubleshooting](./troubleshooting.md)

---

← [Installation](./installation.md) · [Documentation Home](./README.md) · [Keys & Peers](./keys-and-peers.md) →
