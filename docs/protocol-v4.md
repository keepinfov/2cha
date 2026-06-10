# 2cha Protocol v4

Protocol v4 is a clean break from v3 (no backward compatibility). It combines
a Noise_IK handshake with QUIC v1 mimicry so that a passive observer (DPI)
sees plausible QUIC traffic, while the cryptographic core provides mutual
authentication, forward secrecy and replay protection.

Layering:

```
IP packet  →  AEAD (session keys)  →  QUIC-mimic framing  →  UDP
```

## 1. Cryptographic core

### Identities

Each side has a long-term X25519 keypair:

- private key: 32 raw bytes in a file, permissions must be `0600`
  (`2cha genkey <file>`)
- public key: base64 in config (`2cha pubkey <file>`)

The client config carries the server's public key (`server_public_key`).
The server config carries a whitelist of client public keys (`[[peers]]`).
There is no shared PSK; each client is individually authenticated and can be
revoked by removing its entry.

### Handshake: Noise_IK

Implemented with the [`snow`](https://crates.io/crates/snow) crate:

| `cipher` config value | Noise pattern |
|---|---|
| `chacha20-poly1305` | `Noise_IK_25519_ChaChaPoly_BLAKE2s` |
| `aes-256-gcm` | `Noise_IK_25519_AESGCM_SHA256` |

- The initiator (client) knows the responder's static public key in advance
  (the *IK* pattern), so the client's static key is sent encrypted — a passive
  observer never learns who is connecting.
- Both messages contribute ephemeral keys → forward secrecy: compromising a
  long-term key later does not decrypt recorded sessions.
- The server checks the decrypted client static key against its whitelist
  before completing the handshake.

Noise payloads (encrypted) carry session parameters:

- **Init payload (48 bytes)**: client session CID (8) + client obfs seed (32)
  + timestamp, unix nanos LE (8). The timestamp must strictly increase per
  client public key — replayed or reordered inits are rejected.
- **Resp payload (40 bytes)**: server session CID (8) + server obfs seed (32).

The transport keys derived by Noise become the session's send/receive keys.

### MAC1 / cookies (anti-DoS, anti-amplification)

Before any DH or AEAD work, handshake datagrams are gated by a cheap keyed
MAC (BLAKE2s-128):

- `mac1_key = BLAKE2s("2cha-v4-mac1" || receiver_static_public)`
- `mac1 = BLAKE2s-128(mac1_key, datagram_up_to_mac1)`

A datagram with a missing/invalid MAC1 is dropped **silently** — the server
never sends a single byte in response to unauthenticated input, so it cannot
be used as an amplification reflector and does not reveal its existence to
scanners that don't know its public key.

Under load (global handshake rate exceeded) the server responds statelessly
with a cookie reply (framed as QUIC Retry): a 16-byte cookie derived from a
rotating secret (rotated every 120 s) and the source address, sealed with
XChaCha20-Poly1305 under `BLAKE2s("2cha-v4-cookie-key" || receiver_public)`
using the init's MAC1 as AD. The client patches `mac2 = BLAKE2s-128(cookie,
datagram_up_to_mac2)` into its stored init and retransmits. Rate limits:
per-IP 2 handshakes/s (burst 5), global 50/s (burst 100).

### Sessions

- Keys: per-direction AEAD keys from Noise; nonce = LE64(counter) ‖ zeros.
  Counters are explicit, deterministic and never reused (no random nonces,
  no reuse-after-restart — keys live only as long as the session).
- Replay: sliding window over the received counter, bound to the session
  (not the source address), checked **after** AEAD authentication. Roaming
  does not reset the window.
- Rekey: initiator starts a fresh handshake after 120 s (`REKEY_AFTER`) or
  2⁴⁸ messages; a session is rejected outright after 180 s (`REJECT_AFTER`).
  The old session keeps decrypting until the new one is established, so
  traffic never stalls.
- Keepalive: an empty payload with 24–256 bytes of random padding, sent every
  15 s with ±30 % jitter — no fixed size, no fixed period.
- Data padding: every data packet gets 0–64 bytes of random padding
  (length byte + pad inside the AEAD).

### Session identifiers and roaming

Sessions are identified by an 8-byte connection ID (CID) chosen randomly by
the receiver and exchanged *inside* the encrypted handshake payloads — wire
CIDs in handshake packets are random throwaways. The server maintains:

- `CID → session` (data-path lookup),
- `peer pubkey → CID` (a new handshake from the same peer evicts the old
  session),
- `inner IP → CID` learned from decrypted packet source addresses
  (TUN→UDP routing; unknown destinations are dropped silently).

Because sessions are keyed by CID rather than by source address, a client may
change its IP/port (mobile roaming): the endpoint is updated from any packet
that authenticates under the session keys.

## 2. Wire format: QUIC v1 mimicry

Every UDP datagram is framed as plausible QUIC v1 (RFC 9000). Mapping:

| 2cha message | QUIC appearance |
|---|---|
| Handshake init | Initial (long header, type 00) |
| Handshake resp | Handshake (long header, type 10) |
| Cookie reply | Retry (long header, type 11) |
| Data / keepalive | 1-RTT (short header) |

Properties:

- The only structured plaintext bytes are those a real QUIC packet would
  have: fixed bit (0x40), long/short header bit, version `0x00000001`,
  CID length bytes. No 2cha version, packet type, or counter is ever visible.
- Long-header bits that QUIC encrypts (reserved/packet-number bits) are
  randomized per packet; wire DCID/SCID in handshake packets are fresh random
  values each time.
- Handshake inits are padded with random bytes to ≥ 1200-byte datagrams,
  exactly like real QUIC Initials. Since the server's response is much
  smaller, amplification factor stays well below 1×.
- Short header: `byte0 (01xxxxxx, random spin/key-phase/reserved bits)` ‖
  `DCID (8)` ‖ `masked counter (8)` ‖ ciphertext. The counter is XOR-masked
  with a keyed BLAKE2s MAC over the first 16 ciphertext bytes, where the mask
  key is `BLAKE2s("2cha-v4-hp" || seed_initiator || seed_responder ||
  direction)` (analogous to QUIC header protection), so even the
  monotonically increasing counter is not observable.
- Per-direction mask keys are derived from the obfs seeds exchanged inside
  the encrypted handshake (direction bytes `0x01` initiator→responder,
  `0x02` reverse), so CIDs/masks are stable within a session — like real
  QUIC — but unlinkable across sessions.

Anything that does not parse as one of the four shapes above is dropped
without a response.

### Threat model note

The mimicry targets **passive** classification (DPI flow analysis, entropy
and header heuristics). Active probing by a full QUIC stack (e.g. completing
a real QUIC handshake against the server) is out of scope: the server stays
silent to anything that is not a valid 2cha handshake, which is itself a
recognizable behavior under active probing, but does not leak what the
endpoint is.

## 3. Verification checklist

- `cargo test --workspace` — handshake roundtrip, replay window, framing
  roundtrips, MAC1 negative tests.
- Wire capture (`tcpdump -w`): Wireshark classifies the flow as QUIC; first
  bytes vary across packets (except legitimate QUIC fixed bits); payload
  entropy ≈ random (`ent`); keepalive sizes and intervals vary.
- Anti-amplification: garbage datagrams and inits with broken MAC1 produce
  zero response bytes.
- End-to-end: `scripts/netns-test.sh` runs server + client in a network
  namespace pair and pings through the tunnel.
