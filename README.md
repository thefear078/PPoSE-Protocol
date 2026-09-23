<p align="center">
  <img src="assets/logo.png" alt="PPoSE Protocol" width="160" height="160" />
</p>

<h1 align="center">PPoSE Protocol</h1>

<p align="center">
  <strong>Peer-to-Peer Obfuscated Stateless Exchange</strong><br />
  Working research prototype for encrypted P2P datagrams — <em>not</em> a finished anonymity network.
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-yellow.svg" alt="License: MIT" /></a>
  <a href="docs/SPECIFICATION.md"><img src="https://img.shields.io/badge/spec-v0.4--DRAFT-orange.svg" alt="Spec v0.4 DRAFT" /></a>
  <a href="#status"><img src="https://img.shields.io/badge/status-research%20prototype-lightgrey.svg" alt="Status" /></a>
  <a href="https://github.com/thefear078/PPoSE-Protocol/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/thefear078/PPoSE-Protocol/ci.yml?branch=main" alt="CI" /></a>
  <img src="https://img.shields.io/badge/lang-Rust-dea584.svg" alt="Rust" />
</p>

<p align="center">
  <a href="#what-this-is">What this is</a> ·
  <a href="#what-this-is-not">What this is not</a> ·
  <a href="#working-today">Working today</a> ·
  <a href="docs/THREAT_MODEL.md">Threat model</a> ·
  <a href="docs/SPECIFICATION.md">Specification</a> ·
  <a href="#roadmap">Roadmap</a>
</p>

---

## What this is

PPoSE is a **research prototype** with a running reference crate:

| Axis | Inspiration | Status |
|---|---|---|
| Session crypto | Noise XX + optional remote-static pin | **Implemented** |
| Datagram AEAD | ChaChaPoly (Noise) + XChaCha20-Poly1305 hops | **Implemented** |
| Reliability | Selective-repeat ARQ + fragmentation | **Implemented** |
| Transport | UDP | **Implemented** |
| 1-hop forwarder | Cleartext dest wrap + replay cache | **Implemented** (sees dest IP) |
| Nested hops | PND layered AEAD | **Implemented** — **not Sphinx**, hops see next IP |
| Discovery | Token rendezvous | **Implemented** — collusion not solved |
| Cover traffic | TYPE=Data random bodies | **Implemented** — unmeasured, not mixnet |
| Admission | Invitation Web-of-Trust (Ed25519 signed, chain-depth) | **Implemented** — policy layer, not a Sybil defense |

If you need production anonymity, use battle-tested systems (Tor, I2P, Nym, SimpleX, …). This repo is for a testable design, not a Tor competitor.

---

## What this is not

- **Not** “APT-grade” or “zero-metadata.”
- **Not** a mixnet. The optional forwarder is a **dumb IPv4 proxy** with a replay cache.
- **Not** a FINAL specification. See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).
- **Not** a bug-bounty program.

---

## Working today

```
X25519 identity
    → Noise XX handshake
    → inner DATA/ACK frames
    → selective-repeat ARQ + fragments
    → 8-byte cleartext outer header
    → UDP  (direct  or  via IPv4 forwarder)
```

```bash
git clone https://github.com/thefear078/PPoSE-Protocol.git
cd PPoSE-Protocol
cargo test
cargo run --example udp_chat

# two terminals
cargo run --bin ppose -- listen 127.0.0.1:9000
cargo run --bin ppose -- connect 127.0.0.1:9000

# pin the remote static key instead of trust-on-first-use
cargo run --bin ppose -- keygen                              # note "secret" and "public"
cargo run --bin ppose -- listen 127.0.0.1:9000 --key <secret hex>
cargo run --bin ppose -- connect 127.0.0.1:9000 --pin <public hex>

# optional forwarder (sees destination addresses)
cargo run --example relay_node -- 127.0.0.1:8000

# invitation web-of-trust admission walkthrough
cargo run --example admission_demo
```

Tests cover: handshake, ARQ loss recovery, 2 kB fragmentation, Alice↔Bob through a relay.

### Wire envelope (cleartext outer header = 8 bytes)

```
 offset  size  field
 0       2     MAGIC = 0x4A 0x7F
 2       1     VERSION = 0x03
 3       1     TYPE     Handshake=1 Data=2 Forward=4
 4       1     FLAGS
 5       3     reserved = 0
 8       …     body
```

No identity hashes in the clear. Byte workbook: [docs/PACKET.md](docs/PACKET.md).

---

## Design principles

1. **Endpoints hold reliability state.** Relays hold **bounded** replay hashes only — not zero memory, not a circuit table.
2. **Do not put identity in cleartext headers.**
3. **Cite constructions.** The forwarder is not Sphinx; docs say so.
4. **Goals ≠ measurements.** Latency/battery numbers are not claimed.

---

## Roadmap

| Phase | Scope | Done? |
|---|---|---|
| **0** | Honest docs, threat model, 8-byte envelope | yes |
| **1** | Keys → Noise XX → UDP loopback | yes |
| **2** | ARQ, ACK, fragment reassembly, loss test | yes |
| **3** | IPv4 forwarder + replay window | yes (not anonymous) |
| **4** | Nested hops: specified PND (explicitly not Sphinx) | yes |
| **5** | Token rendezvous (collusion documented, not solved) | yes |
| **6** | Cover datagrams (unmeasured) | yes |
| **6.5** | Invitation Web-of-Trust admission (Ed25519 chains, local per-issuer cap) | yes (not a Sybil defense) |
| **7** | External review / mixnet / GPA evaluation | no |

---

## Documentation map

| Doc | Role |
|---|---|
| [docs/SPECIFICATION.md](docs/SPECIFICATION.md) | Wire + crypto (DRAFT) |
| [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) | Claims / non-claims |
| [docs/PACKET.md](docs/PACKET.md) | Byte-level packet workbook |
| [SECURITY.md](SECURITY.md) | How to report issues |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Dev workflow |

---

## License

MIT © 2026 [The Fear](https://github.com/thefear078) — [LICENSE](LICENSE).
