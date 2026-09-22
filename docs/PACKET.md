# Packet workbook (v0.2)

Byte-accurate layouts for the reference implementation. If code and this file disagree, **fix the code or this file in the same PR**.

## Constants

| Name | Value |
|---|---|
| `MAGIC` | `4A 7F` |
| `VERSION` | `03` |
| `OUTER_LEN` | 8 |
| `COUNTER_LEN` | 8 |
| `TAG_LEN` | 16 |
| `MAX_DATAGRAM` | 1200 |

## Outer header

```
offset  len  name
0       2    magic
2       1    version
3       1    type
4       1    flags
5       3    reserved
```

Sum: **8**.

## Handshake datagram

```
[outer 8][noise_message ...]
```

Length(noise_message) is defined by Noise/snow for that round. No padding in Phase 1.

## Data datagram (Phase 1 — Noise transport)

```
[outer 8][snow_transport_message ...]
```

Session AEAD, nonces, and tags are owned by Noise transport
(`Noise_XX_25519_ChaChaPoly_BLAKE2s` via `snow`). Application plaintext is
whatever `UdpSession::send` passes through — no extra cleartext counter.

Standalone XChaCha20-Poly1305 helpers exist in `crypto::aead` for future
non-Noise frames; they are **not** on the Phase 1 UDP path.

### Size inequality (must hold)

```
8 + len(snow_transport_message)  ≤  1200
```

## What must never appear in cleartext

- Ed25519 / X25519 public keys (except inside Noise messages as required by Noise)
- BLAKE3(identity) peer IDs
- Application payload
- Route descriptors (when onion exists)

## Voided v1.2 mistakes

| Claim | Problem |
|---|---|
| Fixed header 44 bytes with two 32-byte IDs | Cleartext linkage; also inconsistent with “zero metadata” |
| “48 bytes per hop” listing 32+32+32+16 | Sums to 112, not 48 |
| Calling format “Sphinx” | Was not Sphinx |
