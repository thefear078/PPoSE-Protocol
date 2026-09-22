# PPoSE Protocol Specification

## Version 0.2-DRAFT

```
┌─────────────────────────────────────────────────────────────┐
│  Status: DRAFT — normative only where marked NORMATIVE     │
│  Previous hype labels (FINAL / APT-grade / zero-metadata)  │
│  are revoked. See docs/THREAT_MODEL.md                     │
│  License: MIT                                              │
│  Target: Rust                                              │
│  Updated: 2026-09-22                                       │
└─────────────────────────────────────────────────────────────┘
```

**Companion docs:** [THREAT_MODEL.md](THREAT_MODEL.md) · [PACKET.md](PACKET.md)

---

## 1. Purpose and scope

PPoSE explores encrypted peer-to-peer datagrams with an optional future onion-forwarding layer.

| In scope for v0.2 code | Out of scope (DRAFT text only) |
|---|---|
| Identity keys (Ed25519 / X25519) | Multi-hop anonymity vs GPA |
| Noise XX session setup | Blind rendezvous production design |
| Session AEAD datagrams | Cover-traffic schedules |
| 8-byte cleartext outer header | Sybil-hard admission |
| UDP loopback integration tests | Bug bounty / audits |

---

## 2. Architecture (current vs planned)

```
Implemented now:
  App  →  Session (Noise XX + AEAD)  →  Outer header  →  UDP

Planned later:
  App → RDG → Session → Onion (cite Sphinx) → Obfuscation → Transport
```

### 2.1 “Stateless” clarified (NORMATIVE intent)

- **Endpoints** MAY/MUST keep reliability state (seq, ACK bitmap, reassembly).
- **Forwarders** (when they exist) MUST NOT keep long-lived circuit maps keyed by end-user identity.
- **Forwarders** MUST keep **bounded ephemeral state**: anti-replay window / bloom with TTL, optional fragment timer, optional cover scheduler. Claiming “zero memory” while also requiring replay protection is a contradiction — this draft rejects that.

---

## 3. Cryptographic primitives (NORMATIVE for Phase 1)

| Role | Algorithm | Notes |
|---|---|---|
| Identity signature | Ed25519 | Long-term |
| DH / Noise | X25519 | Via Noise XX |
| Handshake framework | Noise `XX` | [Noise spec](https://noiseprotocol.org/noise.html) |
| Session AEAD | XChaCha20-Poly1305 | 24-byte nonce |
| Hash | BLAKE3 | Transcript helpers / IDs *inside ciphertext* |
| KDF | HKDF-SHA256 | As used by Noise / explicit session KDF |

### 3.1 Why Noise XX

- Mutual authentication of static keys with forward secrecy after handshake.
- Better KCI story than IK for this use case.
- Cost: extra RTT vs IK.

### 3.2 Handshake (NORMATIVE pattern)

Noise pattern name: `Noise_XX_25519_ChaChaPoly_BLAKE2s` as provided by the `snow` crate defaults used in the reference code, **or** an explicitly documented equivalent. The reference implementation pins the exact `snow` protocol string in `src/crypto/noise.rs` — that string is authoritative for interop until a frozen versioned constant is published.

After handshake, each peer derives:

```
session_key_send / session_key_recv  (directional)
nonce management: monotonic counter per direction (never reuse)
```

---

## 4. Packet format (NORMATIVE outer header)

### 4.1 Cleartext outer header — **8 bytes**

```
 0                   1
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
+-------+-------+-------+-------+
| MAGIC 0x4A7F  | VER   | TYPE  |
+-------+-------+-------+-------+
| FLAGS |   reserved (3 bytes)  |
+-------+-----------------------+
| ciphertext / handshake blob…  |
+-------------------------------+
```

| Field | Size | Value |
|---|---|---|
| MAGIC | 2 | `0x4A 0x7F` |
| VER | 1 | `0x03` (wire v0.2) |
| TYPE | 1 | `1=Handshake`, `2=Data`, `3=Ack` |
| FLAGS | 1 | bit0 = cover candidate (unused in Phase 1) |
| reserved | 3 | MUST be zero; ignore on recv for forward-compat |

**Removed vs abandoned v1.2 draft:** cleartext sender/receiver BLAKE3 identity hashes (64 bytes). Those made “zero-metadata” false on contact and enabled trivial linkage.

### 4.2 Handshake body

Opaque Noise message bytes produced by `snow` (length varies by round). No additional cleartext fields.

### 4.3 Data body (after handshake)

Phase 1 **NORMATIVE** path uses Noise **transport** messages from the same
`snow` session (ChaCha20-Poly1305 as selected by the Noise cipher suite):

```
[outer 8][snow_transport_ciphertext]
```

Standalone XChaCha20-Poly1305 (`crypto::aead`) is available for future frames
but is not used on the Phase 1 UDP path.

Byte workbook: [PACKET.md](PACKET.md).

### 4.4 Maximum size

```
INTERNAL_MTU = 1200   // soft target for future path probing
PHASE1_MAX_UDP = 1200 // reference impl rejects larger plaintext wraps
```

### 4.5 Onion routing (DRAFT — not implemented)

Do **not** call the current code “Sphinx.”

When multi-hop is introduced, prefer:

1. Implement [Sphinx](https://cypherpunks.ca/~iang/pubs/Sphinx_Oakland09.pdf) (Danezis–Goldberg) with a cited parameter set, **or**
2. Publish a complete custom construction with a security argument.

Placeholder per-hop sizes from older drafts that did not sum to the advertised 48 bytes are **void**.

---

## 5. Reliability (DRAFT)

Selective-repeat ARQ, fragmentation, and reorder buffers are **endpoint** responsibilities. Not implemented in Phase 1 beyond optional `seq` in plaintext.

---

## 6. Blind rendezvous (DRAFT sketch)

Intent (unchanged): two rendezvous servers should not jointly learn both endpoints.

**Missing for any security claim** (open design work):

- Who publishes operator fingerprints and under what root of trust?
- How does a client *prove* RS-A and RS-B are independently operated?
- What a passive observer sees at registration (timing, size, IP)?
- Padding / delay schedule to reduce correlation?

Until those have answers + tests, rendezvous text is non-normative.

---

## 7. Trust / Sybil (DRAFT sketch)

Invitation Web-of-Trust and reputation arithmetic are **policy sketches**, not cryptographic Sybil defenses. Soft scores can be farmed. Hardcoded bootstrap nodes are an explicit cold-start centralization trade-off.

---

## 8. Cover traffic (DRAFT)

Constant-rate / stealth modes are unimplemented. Any battery percentage in older docs is **unmeasured fiction** and revoked.

---

## 9. Configuration (informative)

```json
{
  "ppose": {
    "wire_version": 3,
    "noise": "as pinned in src/crypto/noise.rs",
    "mtu": 1200,
    "transport": "udp"
  }
}
```

---

## 10. Testing requirements (Phase 1)

| Test | Required |
|---|---|
| Identity key round-trip | yes |
| Noise XX handshake Alice↔Bob | yes |
| AEAD seal/open + nonce reuse detection | yes |
| UDP loopback echo with handshake + data | yes |
| Outer header rejects wrong magic/version | yes |

---

## 11. Roadmap

See README. Spec versions: `0.2-DRAFT` (this) → `0.3` when reliability lands → `1.0` only after interop vectors + external review.

---

## 12. Prior art (cite, don’t cosplay)

| System | Borrowed idea | Difference |
|---|---|---|
| Noise | XX handshake | We are not inventing a new handshake |
| Sphinx / HORNET | Onion packet format | Not implemented |
| Loopix / Nym | Cover / mixing | Not implemented |
| Cwtch / Briar | Invitation trust | Sketch only |
| Tor | GPA discussion | We make **weaker** claims |

---

## 13. Limitations (honest)

| Issue | Status |
|---|---|
| No multi-hop network | true |
| No GPA resistance claim | true |
| Soft Sybil policy | true |
| Rendezvous underspecified | true |
| Cleartext sizes/timings leak | inherent to Phase 1 |
| Relay anti-replay needs state | acknowledged |
| Spec not FINAL | true |

---

## 14. Contact

- Issues / Discussions: GitHub
- Security: private advisories only
- No active bounty
