<p align="center">
  <img src="assets/logo.png" alt="PPoSE Protocol" width="160" height="160" />
</p>

<h1 align="center">PPoSE Protocol</h1>

<p align="center">
  <strong>Peer-to-Peer Obfuscated Stateless Exchange</strong><br />
  Experimental design for encrypted P2P datagrams — <em>not</em> a finished anonymity network.
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-yellow.svg" alt="License: MIT" /></a>
  <a href="docs/SPECIFICATION.md"><img src="https://img.shields.io/badge/spec-v0.2--DRAFT-orange.svg" alt="Spec v0.2 DRAFT" /></a>
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

PPoSE is a **research prototype** exploring how to combine:

| Axis | Inspiration | Status in this repo |
|---|---|---|
| Session crypto | [Noise Protocol](https://noiseprotocol.org/) XX | **Implemented** (loopback) |
| Datagram AEAD | XChaCha20-Poly1305 | **Implemented** |
| Transport | UDP | **Implemented** (loopback integration test) |
| Source routing | Sphinx / HORNET *ideas* | **Not implemented** — see spec §4 |
| Discovery | Blind rendezvous | **Sketch only** |
| Cover traffic | Mixnet-style padding | **Not implemented** |
| Admission | Invitation Web-of-Trust | **Sketch only** — not cryptographic Sybil defense |

If you need production anonymity, use battle-tested systems (Tor, I2P, Nym, SimpleX, …) and read their papers and audits. This repository is for design iteration and a growing reference implementation.

---

## What this is not

- **Not** “APT-grade” or “zero-metadata.” Those phrases were removed because they were marketing, not proven properties.
- **Not** a competitor to Tor/I2P/Nym. There is no relay network, no directory, no traffic-analysis evaluation.
- **Not** a FINAL / production-ready specification. Wire formats that are normative are marked **NORMATIVE**; the rest is **DRAFT / aspirational**.
- **Not** a live bug-bounty program. Do not treat dollar figures as an active program.

Honest limitations: [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) and [docs/SPECIFICATION.md](docs/SPECIFICATION.md) §13.

---

## Working today (Phase 1 slice)

Minimal path recommended by external review — **and now coded**:

```
Ed25519 / X25519 identity
        ↓
Noise XX handshake (snow)
        ↓
XChaCha20-Poly1305 session AEAD
        ↓
UDP loopback (std::net)
        ↓
integration test: Alice ↔ Bob
```

```bash
git clone https://github.com/thefear078/PPoSE-Protocol.git
cd PPoSE-Protocol
cargo test
cargo run --example udp_chat   # optional demo
```

### Wire envelope (cleartext outer header = 8 bytes)

Observers on the path see **no identity hashes** in the clear. Identities live only inside the Noise/AEAD ciphertext after handshake.

```
 offset  size  field
 0       2     MAGIC = 0x4A 0x7F
 2       1     VERSION = 0x03   (v0.2 wire)
 3       1     TYPE            (Handshake=1, Data=2, Ack=3)
 4       1     FLAGS
 5       3     reserved = 0
 8       …     ciphertext / handshake message
```

Full byte accounting: [docs/SPECIFICATION.md](docs/SPECIFICATION.md) §4.

---

## Design principles (revised)

1. **Endpoints hold state; relays hold bounded ephemera.** “Stateless relay” means *no circuit database*, not *zero memory*. Anti-replay windows, fragment timers, and cover schedules require short-lived state — the spec now says so explicitly.
2. **Do not put routing or identity metadata in cleartext headers** unless a concrete, analyzed reason exists.
3. **Cite constructions** (Noise, Sphinx paper) instead of inventing “Sphinx-like” without a security argument.
4. **Separate goals from measurements.** Latency/battery numbers are *targets for future benchmarks*, not claims about the current crate.

---

## Aspirational targets (unmeasured)

| Quantity | Target (future) | Current evidence |
|---|---|---|
| LAN RTT (direct) | &lt; 10 ms | unmeasured |
| WAN RTT (direct) | 50–100 ms | unmeasured |
| Internal MTU | 1200 B | constant in code |
| Hop count | research open | direct path only today |
| Battery impact of cover traffic | unknown | no cover traffic yet |

---

## Roadmap (honest)

| Phase | Scope | Done? |
|---|---|---|
| **0** | Honest docs, threat model, byte-accurate envelope | **this commit** |
| **1** | Keys → Noise XX → AEAD → UDP loopback → tests | **this commit** |
| **2** | Lossy UDP, ACK/retransmit, fragment reassembly | next |
| **3** | Single intermediate forwarder + replay window | later |
| **4** | Adopt or formally specify onion routing (cite Sphinx/HORNET) | later |
| **5** | Rendezvous sketch → threat analysis → then code | later |
| **6** | Cover traffic + measurement harness | later |
| **7** | External review / audit when there is something to audit | much later |

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

## Security contact

Private reports: [GitHub Security Advisories](https://github.com/thefear078/PPoSE-Protocol/security/advisories/new).

There is **no active paid bug bounty**. If one is funded later, it will be announced in `SECURITY.md` with dates and tiers — not promised in advance.

---

## License

MIT © 2026 [The Fear](https://github.com/thefear078) — [LICENSE](LICENSE).

---

## Tags

`#PPoSE` `#research` `#NoiseProtocol` `#XChaCha20` `#UDP` `#Rust` `#draft-spec` `#P2P`
