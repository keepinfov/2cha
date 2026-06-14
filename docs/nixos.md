# Running 2cha on NixOS

The flake ships a NixOS module that runs 2cha as a declarative service:
`services.twocha.server` and `services.twocha.client`. The config is generated from your Nix
options, rendered to the (read-only) Nix store, and passed to the daemon. **Your Nix
configuration is the source of truth** — to change a setting or add a peer, edit the options
and rebuild.

On non-NixOS systems you don't need any of this: install the binary, run the
[`init` wizard](./quickstart.md), and manage the config imperatively with
[`2cha config`](./config-cli.md) and [`2cha peer`](./keys-and-peers.md).

## Enabling the module

Add the flake as an input and import its module:

```nix
{
  inputs.twocha.url = "github:keepinfov/2cha";

  outputs = { nixpkgs, twocha, ... }: {
    nixosConfigurations.myhost = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        twocha.nixosModules.default
        ./configuration.nix
      ];
    };
  };
}
```

## Server example

```nix
services.twocha.server = {
  enable = true;
  openFirewall = true;            # opens the listen port (UDP for quic, TCP for tls)
  privateKeyFile = "/var/lib/2cha/server.key";
  generateKey = true;             # create the key on first start if missing

  settings = {
    server = { listen = "0.0.0.0:51820"; transport = "quic"; };
    crypto.cipher = "chacha20-poly1305";
    ipv4 = { enable = true; address = "10.8.0.1"; prefix = 24; };
    gateway = {
      ip_forward = true;
      masquerade_v4 = true;
      external_interface = "eth0";
    };
    peers = [
      { public_key = "CLIENT_PUBLIC_KEY_BASE64"; name = "laptop"; }
    ];
  };
};
```

`settings` mirrors the TOML sections one-for-one (see the
[Configuration Reference](./configuration.md)) — each `[section]` becomes a Nix attrset and
`[[peers]]` becomes the `peers` list. You never set `crypto.private_key_file`; the module
fills it in from `privateKeyFile`.

## Client example

```nix
services.twocha.client = {
  enable = true;
  privateKeyFile = "/var/lib/2cha/client.key";
  generateKey = true;

  settings = {
    client = { server = "vpn.example.com:51820"; transport = "quic"; };
    crypto = {
      cipher = "chacha20-poly1305";
      server_public_key = "SERVER_PUBLIC_KEY_BASE64";
    };
    ipv4 = { enable = true; address = "10.8.0.2"; prefix = 24; route_all = true; };
    dns.servers_v4 = [ "1.1.1.1" "8.8.8.8" ];
  };
};
```

## Keys and secrets

`privateKeyFile` is a **path**, never key material — it is not placed in the Nix store. Two
ways to populate it:

- **`generateKey = true`** — a systemd pre-start step runs `2cha genkey <privateKeyFile>` to
  create the raw 32-byte key (mode 0600) the first time the service starts, if the file is
  missing. Read the printed public key from the service logs and hand it to the other side.
- **A secrets manager** — point `privateKeyFile` at a secret deployed by
  [sops-nix](https://github.com/Mic92/sops-nix) or
  [agenix](https://github.com/ryantm/agenix). Leave `generateKey = false`.

## The service unit

The module defines `2cha-server` / `2cha-client` systemd services that:

- run `2cha server -c <generated.toml>` / `2cha up -c <generated.toml>`,
- hold `CAP_NET_ADMIN` (and `CAP_NET_RAW`) for TUN creation and netlink routing,
- allow `/dev/net/tun`, restart on failure, and start after the network is online.

When `gateway` is enabled the server sets up `ip_forward` and nftables masquerade itself and
tears them down on stop, exactly as documented in [Server Setup](./server-setup.md).

## Declarative config vs. runtime `peer add`

Because the generated config lives read-only in the Nix store, runtime mutation behaves
intentionally:

- `2cha peer add <key>` against a running server still **live-authorises** the peer over the
  control socket (it connects immediately), but the server **cannot persist** it into the
  store config and replies `ok … (warning: not persisted)`. After a restart it's gone.
- To make a peer permanent, add it to `services.twocha.server.settings.peers` and rebuild.
- Likewise `2cha config set` will fail to write a store-backed config — edit the Nix options
  instead.

In short: on NixOS, Nix is the source of truth and the imperative commands are for live ops
only. On other systems, the imperative commands *are* the management interface — see
[Managing config with `2cha config`](./config-cli.md).

---

← [Configuration Reference](./configuration.md) · [Documentation Home](./README.md) · [Config CLI](./config-cli.md) →
