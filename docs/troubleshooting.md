# Troubleshooting

Common failures and how to fix them. Run with `-v` (verbose/debug logging) to see more
detail; check `journalctl -u 2cha-server` / `-u 2cha-client` when running as a service.

## "key file has insecure permissions"

The private key must be mode `0600`. 2cha refuses to load a looser key.

```bash
chmod 600 /etc/2cha/server.key   # or client.key
```

## "no [[peers]] configured"

A server config must whitelist at least one client public key. Add a `[[peers]]` block (or
`2cha peer add <key>` on a running server). See [Keys & Peers](./keys-and-peers.md).

## "crypto.server_public_key is required" (client)

The client config is missing the server's public key. Add it under `[crypto]`:

```toml
server_public_key = "SERVER_PUBLIC_KEY_BASE64"   # 2cha pubkey server.key
```

## Client handshake times out / can't connect

Work down this list:

1. **Firewall / port.** The server doesn't open ports. Open the `listen` port for the right
   protocol — **UDP** for `quic`, **TCP** for `tls` — on the host firewall *and* any cloud
   security group. See [Server Setup](./server-setup.md#4-open-the-firewall).
2. **Transport mismatch.** `transport` must be identical on both ends (`quic` ≠ `tls`). A
   mismatch looks like a server that never responds.
3. **Wrong keys.** The client's `server_public_key` must match the server's actual public key
   (`2cha pubkey server.key`), and the client's public key must be in the server's
   `[[peers]]`. An unauthorized client is dropped silently by design.
4. **Address/port.** `client.server` must point at the server's reachable IP/host and its
   `listen` port.
5. **Cipher mismatch.** `[crypto] cipher` must match on both ends.

## Connected, but the client has no internet

A bare tunnel only connects the client to the server and the VPN subnet. For internet access:

1. The server must run in [gateway mode](./server-setup.md#5-gateway-mode-internet-access-for-clients):
   `ip_forward = true`, `masquerade_v4 = true`, and the correct `external_interface`.
2. The client must actually route its traffic out — set `route_all = true` (full tunnel) or
   add the destinations to `routes`. See [Routing](./routing.md).
3. With `route_all = true`, set `[dns]` so name resolution doesn't leak or break.

## IP forwarding doesn't persist after reboot

2cha enables `net.ipv4.ip_forward` at startup and restores the *previous* value on shutdown —
it does not make the change permanent. If you want forwarding on independently of 2cha, add a
sysctl drop-in:

```bash
echo 'net.ipv4.ip_forward = 1' | sudo tee /etc/sysctl.d/99-2cha.conf
sudo sysctl --system
```

## "control socket ... is in use" / peer commands fail

- `control socket is in use (another server running?)` — another 2cha server already holds
  `/run/2cha-ctl.sock`. Stop it first.
- `control socket not found — is the server running on this machine?` — `2cha peer …` must run
  on the same host as the server, and the server must have successfully bound the socket.
  Live peer management is **Unix-only**; otherwise edit `[[peers]]` and restart.

## TUN device name already in use

If `tun0` is held by another VPN/process, either stop that process or set a different
`[tun] name` on the 2cha side.

## The cleanup contract

Both ends undo what they changed, so a clean shutdown shouldn't leave stale state:

- **Server** (on Ctrl-C/SIGTERM or service stop): removes the `twocha_nat` nftables table (or
  the iptables rules), restores the previous `ip_forward` value, and drops sessions.
- **Client** (`2cha down` or exit): restores the original default gateway, deletes routes it
  added, and restores `/etc/resolv.conf`.

If a process was killed with `SIGKILL` it can't clean up — inspect with `ip route`,
`nft list ruleset` / `iptables -t nat -L`, and `cat /etc/resolv.conf`, and remove leftovers
manually.

## Windows

The VPN runtime does not run on Windows yet (the TUN layer exists, but the handlers are
Linux-only). See [Windows Support](./windows-support.md).

---

← [Configuration Reference](./configuration.md) · [Documentation Home](./README.md) · [Testing](./testing.md) →
