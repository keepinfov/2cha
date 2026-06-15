# Managing config with `2cha config`

The `2cha config` commands let you inspect and change a config file without hand-editing
TOML. Every mutating operation is **validated against the real schema before it is written**,
and writes are **atomic** (a temporary file is renamed into place), so a bad edit never lands
on disk and you can't end up with a half-written config.

This is the imperative counterpart to the [`init` wizard](./quickstart.md): the wizard
creates a config from scratch; these commands edit one that already exists. On NixOS the
config is owned declaratively by the module instead — see [NixOS](./nixos.md).

## Commands

```bash
# Parse and validate a config against its schema
2cha config validate -c server.toml

# Print the file plus a one-line validation summary (--raw prints the file only)
2cha config show -c server.toml

# Read one value by dotted key
2cha config get crypto.cipher -c server.toml

# Set one value (validated, then written atomically)
2cha config set crypto.cipher aes-256-gcm -c server.toml

# Open the config in $EDITOR; the edit is validated before it is saved
2cha config edit -c server.toml
```

`-c/--config` defaults to the client config path (`/etc/2cha/client.toml` on Unix). Pass
`-c server.toml` for a server config.

## Dotted keys

Keys address a single value by its TOML path, joined with dots:

| Key | Refers to |
|---|---|
| `server.listen` | `listen` under `[server]` |
| `crypto.cipher` | `cipher` under `[crypto]` |
| `ipv4.address` | `address` under `[ipv4]` |
| `dns.servers_v4` | `servers_v4` under `[dns]` |

`get` and `set` operate on a single value; they do not address `[[peers]]` entries (use
[`2cha peer add/remove`](./keys-and-peers.md) for those). Pointing a key at a whole table is
an error. See the [Configuration Reference](./configuration.md) for every key.

## Value types

`set` infers the TOML type of the value you pass:

| You type | Stored as |
|---|---|
| `true` / `false` | boolean |
| `1420` | integer |
| `1.5` | float |
| `[1.1.1.1, 8.8.8.8]` | array (each element inferred) |
| anything else | string |

So `2cha config set tun.mtu 1400` writes an integer, while
`2cha config set crypto.cipher aes-256-gcm` writes a string. Surrounding quotes you pass are
stripped, so `set crypto.cipher '"aes-256-gcm"'` and `set crypto.cipher aes-256-gcm` are
equivalent. Comments and layout in the file are preserved across edits.

## Server vs client detection

`validate`, `show`, `set`, and `edit` need to know which schema to check against. They
auto-detect it from the file: a `[server]` section means a server config, `[client]` means a
client config. If a file has neither or both, pass `--server` or `--client` to disambiguate.

## What "validated before write" means

`set` and `edit` render the *would-be* result, parse it with the detected schema, and run the
same validation the daemon runs at startup. Only if that succeeds is the file replaced. For
example:

```bash
$ 2cha config set server.transport bogus -c server.toml
 ❌ Error: ... unknown variant `bogus`, expected `quic` or `tls`
$ 2cha config get server.transport -c server.toml
quic        # unchanged
```

If the target file lives on a read-only filesystem (for example a Nix-store config on NixOS),
the atomic rename fails with a clear I/O error — that config is managed declaratively, so edit
the Nix options and rebuild instead. See [NixOS](./nixos.md).

---

← [Keys & Peers](./keys-and-peers.md) · [Documentation Home](./README.md) · [NixOS](./nixos.md) →
