#!/usr/bin/env bash
# End-to-end loopback test for protocol v4 in a network-namespace pair.
#
# Creates two netns (2cha-srv, 2cha-cli) connected by a veth pair, runs the
# server in one and the client in the other, then pings through the tunnel.
# Optionally captures the wire traffic for DPI inspection.
#
# Usage: sudo scripts/netns-test.sh [--capture /tmp/2cha.pcap] [--keep]
#                                    [--tls | --awg] [--workers N]
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
MODE=quic
WORKERS=0
TLS_SNI="www.example-cdn.test"
# Minimum iperf3 throughput (Mbit/s) before the smoke test fails; debug
# builds on slow CI runners can override via env.
IPERF_MIN_MBPS="${IPERF_MIN_MBPS:-50}"
while [ $# -gt 0 ]; do
    case "$1" in
        --capture) CAPTURE="$2"; shift 2 ;;
        --keep) KEEP=1; shift ;;
        --tls) MODE=tls; shift ;;
        --awg) MODE=awg; shift ;;
        --workers) WORKERS="$2"; shift 2 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

# Wire protocol differs per transport: fake-QUIC rides UDP, the TLS transport
# rides TCP. The capture filter and the probing assertion below switch on this.
if [ "$MODE" = "tls" ]; then
    L4=tcp
else
    L4=udp
fi
echo "== transport mode: $MODE (L4: $L4, server workers: $WORKERS)"

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
    [ -n "${IPERF_PID:-}" ] && kill "$IPERF_PID" 2>/dev/null
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

# In TLS mode both ends select transport = "tls" and share an SNI. The server
# auto-generates a self-signed cert for that SNI (no cert/key files needed);
# Noise_IK still runs *inside* the TLS tunnel for authentication.
#
# In AWG mode both ends select transport = "awg" and share an *identical* [awg]
# section: the magic-header ranges (H1-H4) and padding (S1-S4) are part of the
# wire format, so a mismatch means no handshake ever validates. jc/jmin/jmax are
# client-only (junk packets), but sharing them here is harmless.
if [ "$MODE" = "tls" ]; then
    SRV_TRANSPORT=$'transport = "tls"\n\n[tls]\nsni = "'"$TLS_SNI"$'"'
    CLI_TRANSPORT=$'transport = "tls"\n\n[tls]\nsni = "'"$TLS_SNI"$'"'
elif [ "$MODE" = "awg" ]; then
    AWG_SECTION=$'[awg]\nh1 = 271896630\nh2 = 1345638454\nh3 = 2419380278\nh4 = 3493122102\nheader_span = 16777215\ns1 = 24\ns2 = 40\ns3 = 24\ns4 = 16\njc = 4\njmin = 64\njmax = 1024'
    SRV_TRANSPORT=$'transport = "awg"\n\n'"$AWG_SECTION"
    CLI_TRANSPORT=$'transport = "awg"\n\n'"$AWG_SECTION"
else
    SRV_TRANSPORT=""
    CLI_TRANSPORT=""
fi

cat >"$WORK/server.toml" <<EOF
[server]
listen = "$WIRE_S:$PORT"
max_clients = 8
$SRV_TRANSPORT

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

[performance]
# 0 = single-threaded loop; >= 2 exercises the multi-worker pool
worker_threads = $WORKERS
EOF

cat >"$WORK/client.toml" <<EOF
[client]
server = "$WIRE_S:$PORT"
$CLI_TRANSPORT

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
        ip netns exec "$NS_S" tcpdump -i "$VETH_S" -w "$CAPTURE" "$L4 port $PORT" \
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

# Padding-bug canary: 1392B ICMP payload + 8 ICMP + 20 IP = a full 1420B
# inner packet. Before the padding cap, random pad pushed ~29% of these
# past 1500B on the wire, where they were truncated and dropped — so any
# loss here is a deterministic-in-practice regression signal.
echo "== full-MTU ping through tunnel (padding-cap regression)"
FULL_MTU_OUT="$(ip netns exec "$NS_C" ping -c 20 -i 0.2 -s 1392 -W 2 "$TUN_S" || true)"
echo "$FULL_MTU_OUT" | tail -2
if echo "$FULL_MTU_OUT" | grep -q " 0% packet loss"; then
    echo "PASS: zero loss at full MTU"
else
    echo "FAIL: full-MTU packets dropped (padding overflow / truncation regression)"
    echo "--- server.log"; tail -20 "$WORK/server.log"
    echo "--- client.log"; tail -20 "$WORK/client.log"
    exit 1
fi

if command -v iperf3 >/dev/null 2>&1; then
    echo "== iperf3 throughput smoke (5s through tunnel)"
    ip netns exec "$NS_S" iperf3 -s -1 >"$WORK/iperf-srv.log" 2>&1 &
    IPERF_PID=$!
    sleep 0.5
    BPS=$(ip netns exec "$NS_C" iperf3 -c "$TUN_S" -t 5 -J 2>"$WORK/iperf-cli.log" \
        | python3 -c 'import json,sys; print(int(json.load(sys.stdin)["end"]["sum_received"]["bits_per_second"]))' \
        || echo 0)
    wait "$IPERF_PID" 2>/dev/null || true
    IPERF_PID=""
    echo "   throughput: $((BPS / 1000000)) Mbit/s"
    if [ "$BPS" -gt $((IPERF_MIN_MBPS * 1000000)) ]; then
        echo "PASS: throughput above ${IPERF_MIN_MBPS} Mbit/s floor"
    else
        echo "FAIL: throughput below ${IPERF_MIN_MBPS} Mbit/s floor"
        echo "--- iperf-srv.log"; tail -10 "$WORK/iperf-srv.log"
        echo "--- iperf-cli.log"; tail -10 "$WORK/iperf-cli.log"
        exit 1
    fi
else
    echo "SKIP: iperf3 not installed, skipping throughput smoke"
fi

if [ "$MODE" = "tls" ]; then
    echo "== anti-probing: TLS server must complete a real handshake (SNI $TLS_SNI)"
    if ! command -v openssl >/dev/null 2>&1; then
        echo "WARN: openssl not found in PATH, skipping handshake assertion" >&2
    else
        # A real TLS server returns a ServerHello + Certificate and finishes the
        # handshake. Fake-QUIC would silently drop this, so receiving a cert is
        # the discriminating signal an active prober would look for. The cert is
        # self-signed *by design* — Noise_IK inside the tunnel is the real
        # authenticator — so we must NOT pass -verify_return_error here.
        if ip netns exec "$NS_C" openssl s_client -connect "$WIRE_S:$PORT" \
            -servername "$TLS_SNI" -showcerts 2>"$WORK/openssl.log" \
            </dev/null | grep -q "BEGIN CERTIFICATE"; then
            echo "PASS: server presented a certificate and completed TLS handshake"
        else
            echo "FAIL: no TLS handshake / certificate from server"
            echo "--- openssl.log"; tail -20 "$WORK/openssl.log"
            echo "--- server.log"; tail -20 "$WORK/server.log"
            exit 1
        fi
    fi
else
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
fi

if [ -n "$CAPTURE" ]; then
    sleep 1
    # SIGINT makes tcpdump flush and close the file cleanly
    kill -INT "$DUMP_PID" 2>/dev/null
    wait "$DUMP_PID" 2>/dev/null
    DUMP_PID=""
    if [ -s "$CAPTURE" ]; then
        echo "== capture written to $CAPTURE"
        if [ "$MODE" = "tls" ]; then
            echo "   inspect with: wireshark $CAPTURE   (should show a real TLS 1.3 handshake: ClientHello/ServerHello/Certificate)"
            echo "   handshake:    tshark -r $CAPTURE -Y tls.handshake.type"
        elif [ "$MODE" = "awg" ]; then
            echo "   inspect with: wireshark $CAPTURE   (no fixed protocol bytes; junk packets precede the handshake)"
            echo "   first bytes:  tshark -r $CAPTURE -T fields -e udp.payload | cut -c1-8   (magic headers should vary per packet)"
            echo "   entropy:      ent < <(tshark -r $CAPTURE -T fields -e udp.payload | tr -d '\\n:,' | xxd -r -p)"
        else
            echo "   inspect with: wireshark $CAPTURE   (packets should classify as QUIC)"
            echo "   entropy:      ent < <(tshark -r $CAPTURE -T fields -e udp.payload | tr -d '\\n:,' | xxd -r -p)"
        fi
    else
        echo "WARN: capture file is missing or empty: $CAPTURE" >&2
        cat "$WORK/tcpdump.log" >&2
    fi
fi

echo "OK"
