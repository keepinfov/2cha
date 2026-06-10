#!/usr/bin/env bash
# End-to-end loopback test for protocol v4 in a network-namespace pair.
#
# Creates two netns (2cha-srv, 2cha-cli) connected by a veth pair, runs the
# server in one and the client in the other, then pings through the tunnel.
# Optionally captures the wire traffic for DPI inspection.
#
# Usage: sudo scripts/netns-test.sh [--capture /tmp/2cha.pcap] [--keep]
set -euo pipefail

NS_S=2cha-srv
NS_C=2cha-cli
VETH_S=veth-2cha-s
VETH_C=veth-2cha-c
WIRE_S=192.168.250.1
WIRE_C=192.168.250.2
TUN_S=10.99.0.1
TUN_C=10.99.0.2
PORT=51820

CAPTURE=""
KEEP=0
while [ $# -gt 0 ]; do
    case "$1" in
        --capture) CAPTURE="$2"; shift 2 ;;
        --keep) KEEP=1; shift ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

if [ "$(id -u)" -ne 0 ]; then
    echo "must run as root (network namespaces + TUN)" >&2
    exit 1
fi

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/target/debug/2cha"
[ -x "$BIN" ] || { echo "building..."; cargo build --workspace --manifest-path "$ROOT/Cargo.toml"; }

WORK="$(mktemp -d /tmp/2cha-netns.XXXXXX)"

cleanup() {
    set +e
    [ -n "${SRV_PID:-}" ] && kill "$SRV_PID" 2>/dev/null
    [ -n "${CLI_PID:-}" ] && kill "$CLI_PID" 2>/dev/null
    [ -n "${DUMP_PID:-}" ] && kill "$DUMP_PID" 2>/dev/null
    sleep 0.3
    if [ "$KEEP" -eq 0 ]; then
        ip netns del "$NS_S" 2>/dev/null
        ip netns del "$NS_C" 2>/dev/null
        rm -rf "$WORK"
    else
        echo "kept: netns $NS_S/$NS_C, workdir $WORK"
    fi
}
trap cleanup EXIT

# --- topology ---------------------------------------------------------------
ip netns del "$NS_S" 2>/dev/null || true
ip netns del "$NS_C" 2>/dev/null || true
ip netns add "$NS_S"
ip netns add "$NS_C"
ip link add "$VETH_S" type veth peer name "$VETH_C"
ip link set "$VETH_S" netns "$NS_S"
ip link set "$VETH_C" netns "$NS_C"
ip -n "$NS_S" addr add "$WIRE_S/24" dev "$VETH_S"
ip -n "$NS_C" addr add "$WIRE_C/24" dev "$VETH_C"
ip -n "$NS_S" link set lo up
ip -n "$NS_C" link set lo up
ip -n "$NS_S" link set "$VETH_S" up
ip -n "$NS_C" link set "$VETH_C" up

# --- keys & configs ---------------------------------------------------------
"$BIN" genkey "$WORK/server.key" >"$WORK/server.pub" 2>/dev/null
"$BIN" genkey "$WORK/client.key" >"$WORK/client.pub" 2>/dev/null

cat >"$WORK/server.toml" <<EOF
[server]
listen = "$WIRE_S:$PORT"
max_clients = 8

[tun]
name = "tun0"
mtu = 1420

[crypto]
cipher = "chacha20-poly1305"
private_key_file = "$WORK/server.key"

[[peers]]
public_key = "$(cat "$WORK/client.pub")"
name = "test-client"

[ipv4]
enable = true
address = "$TUN_S"
prefix = 24

[ipv6]
enable = false
EOF

cat >"$WORK/client.toml" <<EOF
[client]
server = "$WIRE_S:$PORT"

[tun]
name = "tun0"
mtu = 1420

[crypto]
cipher = "chacha20-poly1305"
private_key_file = "$WORK/client.key"
server_public_key = "$(cat "$WORK/server.pub")"

[ipv4]
enable = true
address = "$TUN_C"
prefix = 24
route_all = false

[ipv6]
enable = false
EOF

# --- optional wire capture ---------------------------------------------------
if [ -n "$CAPTURE" ]; then
    if ! command -v tcpdump >/dev/null 2>&1; then
        echo "WARN: tcpdump not found in PATH, skipping capture" >&2
        echo "      (NixOS hint: sudo --preserve-env=PATH, with tcpdump in a nix shell)" >&2
        CAPTURE=""
    else
        ip netns exec "$NS_S" tcpdump -i "$VETH_S" -w "$CAPTURE" "udp port $PORT" \
            >"$WORK/tcpdump.log" 2>&1 &
        DUMP_PID=$!
        sleep 0.5
        if ! kill -0 "$DUMP_PID" 2>/dev/null; then
            echo "WARN: tcpdump failed to start, skipping capture" >&2
            cat "$WORK/tcpdump.log" >&2
            CAPTURE=""
        fi
    fi
fi

# --- run ---------------------------------------------------------------------
ip netns exec "$NS_S" env RUST_LOG=info "$BIN" server -c "$WORK/server.toml" \
    >"$WORK/server.log" 2>&1 &
SRV_PID=$!
sleep 1
kill -0 "$SRV_PID" 2>/dev/null || { echo "FAIL: server died"; cat "$WORK/server.log"; exit 1; }

ip netns exec "$NS_C" env RUST_LOG=info "$BIN" up -c "$WORK/client.toml" -q \
    >"$WORK/client.log" 2>&1 &
CLI_PID=$!
sleep 2
kill -0 "$CLI_PID" 2>/dev/null || { echo "FAIL: client died"; cat "$WORK/client.log"; exit 1; }

# --- tests ---------------------------------------------------------------
echo "== ping client -> server through tunnel"
if ip netns exec "$NS_C" ping -c 3 -W 2 "$TUN_S"; then
    echo "PASS: tunnel carries traffic"
else
    echo "FAIL: ping through tunnel"
    echo "--- server.log"; tail -20 "$WORK/server.log"
    echo "--- client.log"; tail -20 "$WORK/client.log"
    exit 1
fi

echo "== anti-amplification: garbage datagram must get no reply"
REPLY=$(ip netns exec "$NS_C" python3 - "$WIRE_S" "$PORT" <<'PY'
import os, socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(2)
s.sendto(os.urandom(64), (sys.argv[1], int(sys.argv[2])))
try:
    data, _ = s.recvfrom(2048)
    print(len(data))
except socket.timeout:
    print(0)
PY
)
if [ "$REPLY" = "0" ]; then
    echo "PASS: zero response bytes to unauthenticated garbage"
else
    echo "FAIL: server replied with $REPLY bytes to garbage"
    exit 1
fi

if [ -n "$CAPTURE" ]; then
    sleep 1
    # SIGINT makes tcpdump flush and close the file cleanly
    kill -INT "$DUMP_PID" 2>/dev/null
    wait "$DUMP_PID" 2>/dev/null
    DUMP_PID=""
    if [ -s "$CAPTURE" ]; then
        echo "== capture written to $CAPTURE"
        echo "   inspect with: wireshark $CAPTURE   (packets should classify as QUIC)"
        echo "   entropy:      ent < <(tshark -r $CAPTURE -T fields -e data | xxd -r -p)"
    else
        echo "WARN: capture file is missing or empty: $CAPTURE" >&2
        cat "$WORK/tcpdump.log" >&2
    fi
fi

echo "OK"
