# Keys & Peers

2cha authenticates with public-key cryptography — there is no shared password. Each host
holds an X25519 private key; the other side is identified by the matching public key.

## The key model

```
   SERVER                                   CLIENT
   ------                                   ------
   server.key  (private, on server)         client.key  (private, on client)
   server pubkey ──────────────────────────►  crypto.server_public_key
   [[peers]] public_key  ◄────────────────── client pubkey
```

- Each side keeps its **private** key in a file (`crypto.private_key_file`).
- The **client** must know the **server's public key** (`crypto.server_public_key`), because
  Noise_IK requires the initiator to know the responder's static key in advance.
- The **server** authorizes clients by their **public keys**, listed under `[[peers]]`. A
  handshake from a key that isn't whitelisted is dropped silently (no error leaks to a prober).

Public keys are not secret — they're meant to be exchanged. Private keys are.

## Generating keys

`genkey` creates a private key file and prints the corresponding public key to **stdout**:

```bash
2cha genkey server.key
# stdout: <base64 public key>
```

- The private key is written as **raw 32 bytes** with file mode **`0600`**. 2cha refuses to
  load a private key whose permissions are looser than `0600` — fix with `chmod 600 <file>`.
- The public key is printed base64-encoded. That base64 string is what goes into config files.

Reprint a public key from an existing private key anytime:

```bash
2cha pubkey server.key
```

## Exchanging keys

Put each side's public key where the other side expects it:

```toml
# client.toml — the client needs the server's public key
[crypto]
private_key_file = "/etc/2cha/client.key"
server_public_key = "SERVER_PUBLIC_KEY_BASE64"   # 2cha pubkey server.key
```

```toml
# server.toml — the server whitelists each client's public key
[[peers]]
public_key = "CLIENT_PUBLIC_KEY_BASE64"          # 2cha pubkey client.key
name = "laptop"
```

Add one `[[peers]]` block per client. A server config with **no** peers fails to load.

## Live peer management

You can authorize or revoke clients on a **running** server without restarting it, using the
control socket. These commands must run on the same machine as the server:

```bash
# Authorize a new client (also persists the entry to server.toml)
2cha peer add <CLIENT_PUBLIC_KEY_BASE64> --name phone

# Revoke a client — drops its active session immediately
2cha peer remove <CLIENT_PUBLIC_KEY_BASE64>

# List authorized peers and their connection state
2cha peer list
```

The control socket lives at `/run/2cha-ctl.sock` (falling back to `$XDG_RUNTIME_DIR/2cha-ctl.sock`
or `/tmp/2cha-ctl.sock`). If the server couldn't bind it, peer management is disabled and the
server logs a warning at startup; you can still authorize peers by editing `[[peers]]` in
`server.toml` and restarting. Live peer management is **Unix-only**.

## Rotating keys

To rotate a host's key: generate a new keypair, update the **other** side with the new public
key (the client's `server_public_key`, or the server's `[[peers]]` entry), then swap the
private key file and reconnect. Because Noise_IK pins the responder's static key, a server key
change requires every client to learn the new public key before they can reconnect.

---

← [Quick Start](./quickstart.md) · [Documentation Home](./README.md) · [Server Setup](./server-setup.md) →
