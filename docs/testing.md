# Testing

The repo ships an end-to-end test harness, [`scripts/netns-test.sh`](../scripts/netns-test.sh),
that stands up a real server and client in a pair of Linux **network namespaces**, runs the
tunnel, and asserts that it works. It's the quickest way to confirm a build is functional
without touching your host's networking.

## What it does

It creates two network namespaces (`2cha-srv` and `2cha-cli`) joined by a veth pair, generates
keys and configs, runs `2cha server` in one namespace and `2cha up` in the other, then checks:

1. **Tunnel carries traffic** — pings the server's tunnel address (`10.0.0.1`-style) from the
   client namespace.
2. **Transport-specific probe**:
   - `quic` mode — **anti-amplification**: sends an unauthenticated garbage UDP datagram and
     asserts the server replies with **zero** bytes.
   - `tls` mode — **anti-probing**: runs `openssl s_client` against the server and asserts a
     real TLS handshake completes (a certificate is presented). The cert is self-signed by
     design (see [Transports](./transports.md)).

Topology (defaults): wire `192.168.250.1/.2`, tunnel `10.99.0.1/.2`, port `51820`.

## Requirements

- **Root** (network namespaces + TUN): run under `sudo`.
- A built binary at `target/debug/2cha` (the script builds it if missing).
- `openssl` on `PATH` for the `--tls` probe (skipped with a warning if absent).
- `tcpdump` on `PATH` only if you use `--capture`.

## Running it

```bash
# Default (quic / UDP) transport
sudo scripts/netns-test.sh

# Real TLS-over-TCP transport
sudo scripts/netns-test.sh --tls
```

On NixOS (or anywhere `sudo` resets `PATH`), preserve the environment so `cargo`/`openssl`/
`tcpdump` stay visible:

```bash
sudo env "PATH=$PATH" scripts/netns-test.sh --tls
```

A successful run ends with `OK` and `PASS` lines for each check.

## Flags

| Flag | Effect |
|---|---|
| `--tls` | Use the TLS transport instead of QUIC (switches configs to `transport = "tls"`, the capture filter to TCP, and the probe to `openssl s_client`). |
| `--capture <file>` | Capture wire traffic to a pcap for DPI inspection. |
| `--keep` | Don't tear down the namespaces/workdir on exit (for poking around afterward). |

## Inspecting the wire

With `--capture`, open the pcap to confirm the traffic looks like what you expect:

```bash
sudo scripts/netns-test.sh --tls --capture /tmp/2cha-tls.pcap

# TLS mode: you should see a real TLS 1.3 handshake
tshark -r /tmp/2cha-tls.pcap -Y tls.handshake.type

# QUIC mode: packets should classify as QUIC
wireshark /tmp/2cha-quic.pcap
```

This is the practical demonstration of the difference between the transports: in `tls` mode a
capture shows a genuine ClientHello/ServerHello/Certificate exchange, not just QUIC-shaped
bytes.

## Unit tests

The protocol and crypto cores have their own unit tests:

```bash
cargo test
```

These cover wire framing, the sliding-window replay protection, the Noise handshake, and
config parsing.

---

← [Troubleshooting](./troubleshooting.md) · [Documentation Home](./README.md)
