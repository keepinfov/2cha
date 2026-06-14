# Installation

2cha is a single Rust binary, `2cha`, built from this workspace. The runtime currently
targets **Linux** (see [Platform requirements](#platform-requirements)).

## Build from source

You need a recent Rust toolchain (1.70+).

```bash
git clone https://github.com/keepinfov/2cha
cd 2cha

# Install the 2cha binary into ~/.cargo/bin
cargo install --path crates/twocha-cli

# …or just build it in-tree
cargo build --release        # target/release/2cha
```

Verify:

```bash
2cha --help
2cha --version
```

## Static binary (musl)

A static musl build has no libc dependency and runs on any matching Linux kernel — handy for
copying a server binary to a minimal VPS.

```bash
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
# -> target/x86_64-unknown-linux-musl/release/2cha
```

## Cross-compilation

[`cross`](https://github.com/cross-rs/cross) makes building for other architectures painless:

```bash
cargo install cross
cross build --release --target aarch64-unknown-linux-musl     # 64-bit ARM (Pi 4, ARM servers)
cross build --release --target armv7-unknown-linux-musleabihf # ARMv7 (Pi 3)
cross build --release --target i686-unknown-linux-musl        # 32-bit x86
```

**Supported targets:** `x86_64`, `i686`, `aarch64`, `armv7`, and `arm` — each in both
`-gnu` and `-musl` flavors.

## Nix / NixOS

```bash
# Run without installing
nix run github:keepinfov/2cha -- --help

# Build (dynamic, then static musl)
nix build github:keepinfov/2cha
nix build github:keepinfov/2cha#static

# Install to your profile
nix profile install github:keepinfov/2cha

# Local dev shell (Rust, cargo-watch, etc.)
nix develop
```

## Platform requirements

To run the **server** or **client** (both create a TUN device and modify routing) you need:

- **Linux.** The VPN runtime is Linux-only today; the handlers use `poll(2)` and netlink.
  See [Windows Support](./windows-support.md) for the current Windows status.
- **Root or `CAP_NET_ADMIN`.** `2cha up`, `down`, `server`, and `toggle` will auto-prompt for
  `sudo` if they aren't already privileged.
- **`/dev/net/tun`** present (the TUN character device).
- For **gateway mode** (giving clients internet access): `nftables` or `iptables` installed.
  See [Server Setup](./server-setup.md#5-gateway-mode-internet-access-for-clients).

The `genkey`, `pubkey`, `init`, and `status` commands need no special privileges.

---

[Documentation Home](./README.md) · [Quick Start](./quickstart.md) →
