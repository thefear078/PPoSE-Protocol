# PPoSE Protocol Specification

## Version 0.5-DRAFT

```
┌─────────────────────────────────────────────────────────────┐
│  Status: DRAFT — normative only where marked NORMATIVE     │
│  Previous hype labels (FINAL / APT-grade / zero-metadata)  │
│  are revoked. See docs/THREAT_MODEL.md                     │
│  License: MIT                                              │
│  Target: Rust                                              │
│  Updated: 2026-09-24                                       │
└─────────────────────────────────────────────────────────────┘
```

**Companion docs:** [THREAT_MODEL.md](THREAT_MODEL.md) · [PACKET.md](PACKET.md)

---

## 1. Purpose and scope

PPoSE explores encrypted peer-to-peer datagrams with an optional future onion-forwarding layer.

| In scope for v0.5 code | Out of scope |
|---|---|
| X25519 + Noise XX + remote pin | GPA / mixnet |
| ARQ + fragments | Sphinx (we implemented PND instead) |
| IPv4 forwarder + PND onion hops | Blind RS independence proofs |
| Token rendezvous | Sybil-hard admission |
| Cover datagrams (size + interval measured/randomized, §8) | Bug bounty / audit |
| Invitation Web-of-Trust admission (Ed25519 chains) | Network-wide Sybil resistance |

---

## 2. Architecture (current vs planned)

```
Implemented now:
  App → ARQ/fragments → Noise XX transport → Outer header → UDP
                 ↘ optional TYPE=Forward IPv4 wrap (relay sees dest)
                 ↘ optional TYPE=Onion PND nested hops (XChaCha20-Poly1305, not Sphinx)
                 ↘ optional TYPE=Rendezvous token discovery (collusion not solved)
                 ↘ optional TYPE=Data cover datagrams (size/interval randomized, see §8)
  Admission: separate Ed25519 Invitation Web-of-Trust (src/admission.rs,
             not on the wire path above — a local policy gate, not a
             Sybil defense; see §7)

Not implemented:
  Sphinx/HORNET onion  ·  blind rendezvous operator-independence proofs  ·  mixing
```

### 2.1 “Stateless” clarified (NORMATIVE intent)

- **Endpoints** MAY/MUST keep reliability state (seq, ACK bitmap, reassembly).
- **Forwarders** (when they exist) MUST NOT keep long-lived circuit maps keyed by end-user identity.
- **Forwarders** MUST keep **bounded ephemeral state**: anti-replay window / bloom with TTL, optional fragment timer, optional cover scheduler. Claiming “zero memory” while also requiring replay protection is a contradiction — this draft rejects that.

---

## 3. Cryptographic primitives (NORMATIVE for Phase 1)

| Role | Algorithm | Notes |
|---|---|---|
| Core PPoSE identity | X25519 | Noise static key; authenticated via DH in the handshake, **not** a separate signature |
| DH / Noise | X25519 | Via Noise XX |
| Handshake framework | Noise `XX` | [Noise spec](https://noiseprotocol.org/noise.html) |
| Handshake/session AEAD | ChaCha20-Poly1305 | Via `snow`'s Noise cipher suite (§4.3) |
| Onion-hop AEAD | XChaCha20-Poly1305 | 24-byte nonce; used for `TYPE=Onion` PND layers only (§4.5, `src/onion.rs`) |
| Admission invitation signature | Ed25519 | Separate keypair from the core identity above; signs `Invitation`s only (§7, `src/admission.rs`) |
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

Standalone XChaCha20-Poly1305 (`crypto::aead`) is not used on the direct
endpoint-to-endpoint `TYPE=Data` path above, but it **is** used to seal each
`TYPE=Onion` PND layer (§4.5) — that construction shipped in v0.4.

Byte workbook: [PACKET.md](PACKET.md).

### 4.4 Maximum size

```
INTERNAL_MTU = 1200   // soft target for future path probing
PHASE1_MAX_UDP = 1200 // reference impl rejects larger plaintext wraps
```

### 4.5 Onion routing — PND nested hops (implemented, explicitly not Sphinx)

Do **not** call this code “Sphinx.” `TYPE=Onion` (`src/onion.rs`) wraps the
payload in one XChaCha20-Poly1305 layer per hop; each hop peels its layer
(`peel_layer`) and forwards to the next IPv4 address it learns from that
layer — **the hop sees the next hop's IP**, same as the plain IPv4
forwarder (§5.1). It provides no traffic analysis resistance and is not a
mixnet. Tested for a 2-hop path (`tests/onion_path.rs`).

Real Sphinx/HORNET-grade onion routing remains **out of scope** for this
prototype. If it is ever attempted, prefer:

1. Implement [Sphinx](https://cypherpunks.ca/~iang/pubs/Sphinx_Oakland09.pdf) (Danezis–Goldberg) with a cited parameter set, **or**
2. Publish a complete custom construction with a security argument.

Placeholder per-hop sizes from older drafts that did not sum to the advertised 48 bytes are **void**.

---

## 5. Reliability (NORMATIVE in reference crate)

Selective-repeat ARQ and fragmentation run **only on endpoints**.

| Parameter | Value |
|---|---|
| Window | 32 packets |
| ACK | inner kind 0x02 after each accepted DATA |
| Retransmit | 200 ms, 5 attempts then give up |
| Fragment payload | ≤ 1024 bytes on direct / relay / 1-hop paths, 1167 − 86·hops on longer onion paths ([PACKET.md](PACKET.md)); `frag_total` ≤ 255 |
| Pending reassemblies | ≤ 64 distinct `frag_id`s, oldest evicted first |

Inner layouts: [PACKET.md](PACKET.md).

### 5.1 IPv4 forwarder (implemented, not anonymous)

TYPE=Forward carries dest IPv4:port in the clear. The relay:

- does not decrypt
- rewrites the dest field to the sender for the return path
- drops inner datagrams whose BLAKE3-16 hash was seen inside the TTL window

This is a **proxy**, not Sphinx.

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

## 7. Trust / Sybil admission (implemented, not a Sybil defense)

`src/admission.rs` implements the Invitation Web-of-Trust as a real, tested mechanism rather than a sketch:

- A separate Ed25519 keypair (`InviteSigningKey`) — deliberately not the X25519 Noise identity — signs `Invitation`s: `issuer(32) || subject(32) || issued_at(8) || expires_at(8) || signature(64)`, 144 bytes on the wire, domain-separated with the tag `ppose-invite-v1`.
- A local `TrustStore` holds one or more trusted root verifying keys and a set of ingested invitations, and answers `is_admitted(subject, max_depth, now)` by BFS over the invitation graph, re-checking each edge's signature and expiry at query time.
- `TrustStore::set_max_invitees_per_issuer` caps how many distinct subjects one issuer can get admitted through *that local store*.
- Wired into `ppose listen` (`--admit-root`, `--admit-invite`, `--admit-depth`; `ppose keygen-invite`/`ppose invite` generate the material): the gate runs **after** the Noise XX handshake completes, using the now-authenticated `remote_static()` as the subject to check — not before, and not on an unauthenticated claim. It is not wired into token rendezvous (§6), since registration tokens there aren't tied to any authenticated identity to check in the first place.

What this still is **not**: a cryptographic Sybil defense. A signature only proves an issuer chose to vouch for a key; nothing stops an admitted issuer from minting many subject keypairs and vouching for all of them. The per-issuer cap is a local, non-networked mitigation, not consensus-enforced. Hardcoded bootstrap roots remain an explicit cold-start centralization trade-off. Reputation *scores* (as opposed to chain membership) are not implemented — deliberately, since scores are exactly the part `docs/THREAT_MODEL.md` warns is farmable.

---

## 8. Cover traffic (implemented, measured, still not mixnet-grade)

`src/cover.rs` implements two idle-time cover modes — `Balanced`
(120–280 ms jittered interval) and `Stealth` (30–70 ms jittered interval) —
that send `TYPE=Data` packets of random bytes (never Noise-sealed) when the
session is otherwise idle; the receiver drops them because they fail to
decrypt.

Measured by `examples/cover_measurement.rs` against the real encoding path
(not estimated):

| Traffic | Wire size |
|---|---|
| ACK | 37 bytes (constant) |
| DATA, 8 B app chunk | 41 bytes |
| DATA, 1024 B app chunk | 1057 bytes |
| Cover, `Balanced` | 24–520 bytes (uniform per packet) |
| Cover, `Stealth` | 24–264 bytes (uniform per packet) |

Both the payload length and the inter-packet interval are now randomized
per packet, rather than the fixed 64-byte / exactly-200ms-or-50ms cadence
earlier code used — a fixed value on either axis is a distinguishing
signal by itself (constant size vs. real traffic's variable size; constant
period vs. real traffic's irregular timing, detectable even with simple
inter-arrival-time analysis). The current ranges overlap plausible real
values but were chosen by hand, not fit to any measured application
traffic distribution — a patient observer with enough samples can likely
still separate cover's two independent uniform distributions from
whatever real traffic's actual (non-uniform, correlated) distributions
are. Battery-cost percentages from older drafts remain **unmeasured
fiction** and revoked — nothing in this project measures power draw.

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

## 10. Testing requirements

| Test | Required |
|---|---|
| Identity key round-trip | yes |
| Noise XX handshake Alice↔Bob | yes |
| AEAD seal/open + AAD mismatch | yes |
| UDP loopback + ARQ | yes |
| Loss recovery (drop one DATA) | yes |
| Fragment reassembly (~2 kB) | yes |
| Path via IPv4 forwarder | yes |
| Outer header rejects wrong magic/version | yes |
| Replay cache rejects duplicates | yes |
| Remote static pinning (accept / reject) | yes |
| Two-hop PND onion, small and multi-fragment messages | yes |
| Rendezvous register / lookup | yes |
| Invitation sign / verify / tamper / expiry / chain depth / issuer cap | yes |
| Real message survives interleaved cover traffic | yes |
| Replay cache, reassembly table, rendezvous table stay bounded | yes |
| Every wire parser: randomized input of every length 0–200 B, no panic | yes |

---

## 11. Roadmap

See README. Spec versions: `0.5-DRAFT` (this) → `1.0` only after interop vectors + external review.

---

## 12. Prior art (cite, don’t cosplay)

| System | Borrowed idea | Difference |
|---|---|---|
| Noise | XX handshake | We are not inventing a new handshake |
| Sphinx / HORNET | Onion packet format | Not implemented — we ship PND layered AEAD instead (§4.5), explicitly not Sphinx |
| Loopix / Nym | Cover / mixing | Cover datagrams implemented and measured (§8); no mixing/batching |
| Cwtch / Briar | Invitation trust | Implemented as signed Ed25519 chains (§7) — still not a cryptographic Sybil defense |
| Tor | GPA discussion | We make **weaker** claims |

---

## 13. Limitations (honest)

| Issue | Status |
|---|---|
| No Sphinx/mixnet-grade multi-hop network | true — PND onion hops exist (§4.5) but each hop sees the next IP and there is no mixing |
| No GPA resistance claim | true |
| Soft Sybil policy | true — Invitation WoT is implemented (§7) but is a local policy gate, not a cryptographic defense |
| Rendezvous underspecified | true |
| Cleartext sizes/timings leak | inherent to Phase 1 |
| Relay anti-replay needs state | acknowledged |
| Spec not FINAL | true |

---

## 14. Contact

- Issues / Discussions: GitHub
- Security: private advisories only
- No active bounty
