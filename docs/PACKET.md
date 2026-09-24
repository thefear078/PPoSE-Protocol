# Packet workbook (v0.5 — wire format unchanged since v0.3)

Byte-accurate layouts. If code and this file disagree, fix both in the same PR.

## Constants

| Name | Value |
|---|---|
| `MAGIC` | `4A 7F` |
| `VERSION` | `03` |
| `OUTER_LEN` | 8 |
| `FORWARD_BODY_OVERHEAD` | 6 |
| `LAYER_OVERHEAD` (PND hop) | 78 = 32+24+16+4+2 |
| `DATA_HDR_LEN` | 9 |
| `ACK_LEN` | 13 |
| `MAX_PAYLOAD` | 1024 |
| `MAX_DATAGRAM` | 1200 |

## Outer TYPE

| Value | Name |
|---|---|
| 1 | Handshake |
| 2 | Data (also cover: random body, decrypt fails) |
| 3 | Ack (unused on wire) |
| 4 | Forward (cleartext dest — not anonymous) |
| 5 | Onion (PND layer; **not Sphinx**) |
| 6 | Rendezvous |

## Outer header (8 bytes)

```
magic 2 | version 1 | type 1 | flags 1 | reserved 3
```

## Data / cover

```
[outer TYPE=Data][noise_transport OR random bytes]
```

Cover body length is drawn per packet from `CoverMode::payload_len_range`
(`Balanced` 16–512, `Stealth` 16–256), capped at the largest real sealed
DATA body on the current path. Same TYPE and random-looking content as real
traffic, but **not** size-indistinguishable against a patient statistical
observer — see `docs/SPECIFICATION.md` §8 and `examples/cover_measurement.rs`
for the measured sizes. Receiver ignores Noise open failure (and `snow` does
not advance its receive nonce on a failed open, so this can't desync).

| Packet | Wire size |
|---|---|
| ACK | 37 B (8 outer + 13 inner + 16 tag) |
| DATA carrying `n` app bytes | 33 + `n` B (8 outer + 9 header + `n` + 16 tag) |

## Forward (TYPE=4)

```
dst_ipv4 4 | dst_port u16 BE | inner full datagram
```

Relay rewrites dest to sender. Replay: BLAKE3-16 of inner, TTL 30s.

## Onion / PND (TYPE=5)

**Not Sphinx.** Domain `ppose-pnd-v1`.

Layer body:

```
eph_x25519 32 | nonce 24 | aead(ct||tag)
plain = next_ipv4 4 | next_port 2 | payload (complete datagram)
```

Key = BLAKE3(`ppose-pnd-v1` || X25519(eph, hop_static)). AAD = eph public.

Hop peels one layer, refuses a next hop equal to its own address,
replay-checks payload, raw-sends payload to next.

Each hop adds **86 bytes on the wire**: the 78-byte layer plus a fresh
8-byte outer header. The sender's ARQ fragment size shrinks to match
(`session::max_fragment_for_path`), so every sealed DATA frame still fits
`MAX_DATAGRAM`:

| Path | Max app bytes per fragment |
|---|---|
| Direct / relay / 1 hop | 1024 (`MAX_PAYLOAD`) |
| 2 hops | 995 |
| 3 hops | 909 |
| `h` hops | 1167 − 86·`h` |

Before v0.5 fragments were always 1024 B, so any message over ~995 B failed
with `TooLarge` on 2+ hops.

## Rendezvous (TYPE=6)

```
op=1 register | token 32     → store recv_from
op=2 lookup   | token 32     → reply
op=3 reply    | found u8 | ipv4 4 | port 2
```

Token helper: BLAKE3(`ppose-rs` || psk || epoch_hours). Colluding RS correlate. No GPA claim.

Server keeps at most 4096 tokens (FIFO eviction), TTL 60 s. Registration is
unauthenticated — anyone can register any token.

## Invitation (admission, not on the UDP path)

144 bytes, exchanged out of band (e.g. `ppose invite` output):

```
issuer_ed25519 32 | subject_x25519 32 | issued_at u64 BE | expires_at u64 BE | ed25519_sig 64
```

Signature covers `"ppose-invite-v1" || issuer || subject || issued_at || expires_at`.

## Inner Noise plaintext

DATA `01 | seq u32 | frag_id u16 | index u8 | total u8 | payload`

ACK `02 | base u32 | bitmap u64`
