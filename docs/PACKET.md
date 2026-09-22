# Packet workbook (v0.3)

Byte-accurate layouts for the reference implementation. If code and this file disagree, **fix the code or this file in the same PR**.

## Constants

| Name | Value |
|---|---|
| `MAGIC` | `4A 7F` |
| `VERSION` | `03` |
| `OUTER_LEN` | 8 |
| `FORWARD_BODY_OVERHEAD` | 6 |
| `DATA_HDR_LEN` | 9 |
| `ACK_LEN` | 13 |
| `MAX_PAYLOAD` | 1024 |
| `MAX_DATAGRAM` | 1200 |

## Outer header (cleartext)

```
offset  len  name
0       2    magic
2       1    version
3       1    type
4       1    flags
5       3    reserved
```

Sum: **8**.

TYPE:

| Value | Name | Meaning |
|---|---|---|
| 1 | Handshake | Noise XX message |
| 2 | Data | Noise transport (app DATA or inner ACK) |
| 3 | Ack | unused on the wire (inner ACK uses TYPE=2) |
| 4 | Forward | IPv4 wrap; **relay sees destination** |

## Handshake datagram

Direct:

```
[outer 8 TYPE=Handshake][noise_message …]
```

Via relay: wrap the *entire* handshake datagram as Forward (below).

## Data datagram (Noise transport)

```
[outer 8 TYPE=Data][snow_transport_message …]
```

Decrypted inner plaintext:

### DATA (kind 0x01)

```
offset  len  name
0       1    kind = 0x01
1       4    seq u32 BE
5       2    frag_id u16 BE
7       1    frag_index
8       1    frag_total (>= 1)
9       N    payload  (N ≤ 1024)
```

### ACK (kind 0x02)

```
offset  len  name
0       1    kind = 0x02
1       4    base u32 BE
5       8    bitmap u64 BE
```

Size: **13**. Bit `i` set ⇒ sequence `base+i` received.

### Size inequality (direct DATA)

```
8 + 16 + 9 + N  ≤  1200
⇒  N ≤ 1167   (code uses MAX_PAYLOAD = 1024)
```

## Forward wrapper (TYPE=4)

**Not onion routing.** Destination IPv4:port is in the clear.

```
[outer 8 TYPE=Forward]
  dst_ipv4 [4]
  dst_port u16 BE
  inner    full PPoSE datagram (has its own outer header)
```

Relay algorithm:

1. Decode dest + inner.
2. Replay-check `BLAKE3(inner)[..16]` with TTL (default 30s, cap 4096).
3. Send TYPE=Forward to dest with dest-field rewritten to the **sender** address (return path).

### Size inequality (forwarded)

```
8 + 6 + len(inner)  ≤  1200
⇒  inner ≤ 1186
```

## What must never appear in cleartext

- X25519 static public keys except inside Noise handshake messages
- BLAKE3 identity fingerprints
- Application payload
- Inner seq / ACK (those are inside Noise transport)

Cleartext that **does** appear (honest):

- MAGIC / VERSION / TYPE / FLAGS
- Packet length and timing
- Forward dest IPv4:port when using a relay

## Voided v1.2 mistakes

| Claim | Problem |
|---|---|
| Fixed header 44 bytes with two 32-byte IDs | Cleartext linkage |
| “48 bytes per hop” listing 32+32+32+16 | Sums to 112, not 48 |
| Calling format “Sphinx” | Was not Sphinx |
| Stateless relay + replay protection | Contradiction; relay now has a bounded hash cache |
