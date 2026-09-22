# Threat Model (v0.3-DRAFT)

**Status:** living document. If README and this file disagree, this file wins for security claims.

## 1. Assets

| Asset | Notes |
|---|---|
| Message confidentiality | Payload unreadability for parties without session keys |
| Message integrity / authenticity | AEAD + Noise handshake binding |
| Endpoint identity keys | Long-term Ed25519 / X25519 material |
| Session keys | Ephemeral; should provide FS after handshake completes |

**Not an asset we claim today:** unlinkability under a global passive adversary, contact-graph privacy at network scale, or resistance to malicious-relay correlation across hops.

## 2. Adversaries (informal)

| Adversary | Capabilities | What we claim today |
|---|---|---|
| **Eavesdropper on a single UDP path** | Sees datagrams Alice↔Bob on loopback/LAN test | Cannot read Data payloads after successful Noise XX + AEAD |
| **Active MITM on first contact** | Can drop/modify handshake bytes | Detected if Noise XX authentication fails (static keys known/out-of-band) |
| **Malicious relay** | Sees dest IP:port, can drop/delay/log sizes | **No anonymity claim.** Replay cache only reduces duplicate flooding. |
| **Global passive adversary (GPA)** | Observes all links, timing, sizes | **No claim** |
| **Sybil operator** | Spins many identities | Invitation WoT sketch is **not** a cryptographic defense |

This is **not** a UC / game-based proof. It is an engineering threat sketch so implementers know what *not* to advertise.

## 3. Explicit non-claims

1. **Zero-metadata leakage** — false for any IP/UDP system; also formerly contradicted by cleartext identity hashes (removed in v0.2).
2. **APT-grade privacy** — undefined marketing term; removed.
3. **Stateless relays imply security** — relays still need bounded anti-replay / DoS state when forwarding exists.
4. **3 hops defeat GPA** — Tor does not claim this with larger hop counts and a real network; we do not either.
5. **Reputation formulas stop Sybils** — `score = age*10 + …` can be farmed; treat as soft policy, not crypto.

## 4. Trust assumptions (v0.3)

- Demo CLI generates **ephemeral** keys per process; there is no PKI.
- Noise XX authenticates static keys **if** they were exchanged out of band. The demo does **not** pin the peer static key (PSK/remote known-key) yet — a MITM who intercepts the first handshake can impersonate. Treat demo sessions as **unauthenticated until remote static is set**.
- OS UDP stack and local machine are trusted for loopback tests.
- `snow` / `x25519-dalek` / `chacha20poly1305` / `blake3` behave as documented.

## 5. Metadata that still leaks (Phase 1)

Even with an 8-byte outer header and encrypted payload, a path observer learns:

- That two IP:ports exchange PPoSE-shaped packets (`MAGIC`)
- Packet sizes and inter-arrival times
- Approximate session length and volume
- That a Noise-sized handshake occurred at start

Reducing *these* requires cover traffic, constant-rate channels, and likely a mixnet-style design — **future work**, with measurements, not slogans.

## 6. Open problems (from external review)

Tracked honestly until solved in code + analysis:

| Problem | Direction |
|---|---|
| Replay / fragment / cover vs “stateless” | Bound per-relay ephemera; document TTLs |
| Blind rendezvous correlation | Spec §6 remains DRAFT; needs operator registry design |
| Sybil | Do not ship soft scores as security features |
| Onion routing | Either implement Sphinx (cite Danezis–Goldberg) or a fully specified custom construction |
| GPA | Out of scope until there is a network + evaluation harness |

## 7. Change control

Any README badge or one-liner that strengthens a claim above must update **this file first** and cite evidence (test, paper, or measurement).
