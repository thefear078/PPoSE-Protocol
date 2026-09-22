# Packet workbook (v0.4)

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
[outer TYPE=Data][noise_transport OR random 64+ bytes]
```

Cover uses the same TYPE so a size-only observer cannot label it. Receiver ignores Noise open failure.

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

Hop peels one layer, replay-checks payload, raw-sends payload to next.

Each hop adds 78 bytes. 3 hops + 1 kB app may exceed 1200 — keep payloads small on onion paths.

## Rendezvous (TYPE=6)

```
op=1 register | token 32     → store recv_from
op=2 lookup   | token 32     → reply
op=3 reply    | found u8 | ipv4 4 | port 2
```

Token helper: BLAKE3(`ppose-rs` || psk || epoch_hours). Colluding RS correlate. No GPA claim.

## Inner Noise plaintext

DATA `01 | seq u32 | frag_id u16 | index u8 | total u8 | payload`

ACK `02 | base u32 | bitmap u64`
