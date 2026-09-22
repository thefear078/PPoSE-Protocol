<p align="center">
  <img src="assets/logo.png" alt="PPoSE Protocol" width="160" height="160" />
</p>

<h1 align="center">PPoSE Protocol</h1>

<p align="center">
  <strong>Peer-to-Peer Obfuscated Stateless Exchange</strong><br />
  Decentralized anonymous P2P communication with zero-metadata leakage.
</p>

<p align="center">
  <a href="https://github.com/thefear078/PPoSE-Protocol/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-yellow.svg" alt="License: MIT" /></a>
  <a href="docs/SPECIFICATION.md"><img src="https://img.shields.io/badge/spec-v1.2--FINAL-black.svg" alt="Spec v1.2" /></a>
  <a href="docs/SPECIFICATION.md"><img src="https://img.shields.io/badge/security-APT--grade-brightgreen.svg" alt="APT-grade privacy" /></a>
  <a href="#status"><img src="https://img.shields.io/badge/status-spec%20ready-orange.svg" alt="Status" /></a>
  <a href="https://github.com/thefear078/PPoSE-Protocol"><img src="https://img.shields.io/badge/lang-Rust%20%2F%20tokio-dea584.svg" alt="Rust" /></a>
</p>

<p align="center">
  <a href="#why-ppose">Why</a> ·
  <a href="#architecture">Architecture</a> ·
  <a href="#key-metrics">Metrics</a> ·
  <a href="docs/SPECIFICATION.md">Specification</a> ·
  <a href="#roadmap">Roadmap</a> ·
  <a href="#security">Security</a> ·
  <a href="#community--contact">Contact</a>
</p>

---

## Why PPoSE?

PPoSE is designed for environments where metadata is as dangerous as payload. It targets:

- **Global passive adversaries** (APT / nation-state traffic analysis)
- **Malicious or compromised relays**
- **Sybil / botnet admission attacks**

Core idea: no trusted third party ever sees a full communication path. After handshake, relays stay **stateless**. Transport is **UDP-first** with cryptographic agility and onion-style source routing.

| Principle | Meaning |
|---|---|
| No trusted third parties | No node observes the full end-to-end relationship |
| Stateless after handshake | Minimal relay memory surface |
| UDP-first transport | Precise timing control for obfuscation |
| Cryptographic agility | Algorithms swappable without protocol breakage |

---

## Key Metrics

| Metric | Target |
|---|---|
| LAN latency | &lt; 10 ms |
| WAN latency | ~50–100 ms |
| Internal MTU | Hard 1200 bytes |
| Max hops | 3 (configurable up to 5) |
| Forward secrecy | Full, per-message |
| Metadata exposure | Zero |
| Mobile battery (adaptive) | ~3–5% / hour |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                   PPoSE v1.2 Protocol Stack                 │
├─────────────────────────────────────────────────────────────┤
│  L7  Application API              Messenger / files / voice │
│  L6  Reliable Datagram (RDG)      ACK, fragment, retransmit │
│  L5  Cryptography                 Noise XX + XChaCha20-Poly │
│  L4  Source Routing               Sphinx-like onion wraps   │
│  L3  Identity + NAT               Blind rendezvous + STUN   │
│  L2  Traffic Obfuscation          Adaptive constant-rate    │
│  L1  Transport                    UDP / TCP / WS / BLE      │
└─────────────────────────────────────────────────────────────┘
```

Full technical detail lives in **[docs/SPECIFICATION.md](docs/SPECIFICATION.md)** (v1.2-FINAL).

### Cryptography (mandatory)

| Component | Algorithm |
|---|---|
| Identity | Ed25519 |
| Key exchange | X25519 |
| AEAD | XChaCha20-Poly1305 |
| Hash | BLAKE3 |
| Handshake | Noise XX |
| KDF | HKDF-SHA256 |

Noise **XX** (not IK): full forward secrecy after handshake and KCI resistance. Extra RTT is a one-time session cost.

---

## Status

**Specification-complete / implementation in progress.**

The protocol document is production-ready for implementers. The Rust reference crate is being scaffolded toward Phase 1 (crypto, packet codec, Noise XX).

See the [implementation roadmap](#roadmap) and [CHANGELOG](CHANGELOG.md).

---

## Quick start (developers)

```bash
git clone https://github.com/thefear078/PPoSE-Protocol.git
cd PPoSE-Protocol
cargo check
cargo test
```

Planned examples:

```bash
cargo run --example cli_client
cargo run --example relay_node
```

Configuration sketch:

```json
{
  "ppose": {
    "version": "1.2",
    "network": {
      "internal_mtu": 1200,
      "max_hops": 3
    },
    "traffic_mode": {
      "default": "balanced"
    }
  }
}
```

---

## Roadmap

| Phase | Focus | Window |
|---|---|---|
| **1** | Core infra — crypto, packet codec, Noise XX | Weeks 1–3 |
| **2** | Networking — UDP, STUN, blind rendezvous | Weeks 4–6 |
| **3** | Reliability & routing — ARQ, Sphinx hops, MTU | Weeks 7–9 |
| **4** | Hardening — obfuscation modes, WoT, benches | Weeks 10–14 |
| **5** | External audit, bug bounty, v1.0 release | Week 15+ |

---

## Security

Threat model: **global passive adversary + malicious relays**.

- Report vulnerabilities privately via [GitHub Security Advisories](https://github.com/thefear078/PPoSE-Protocol/security/advisories/new)
- Do **not** open public issues for unfixed security bugs
- Details: **[SECURITY.md](SECURITY.md)**

Planned bug bounty: up to **$10,000 USD** for critical findings (program TBD before v1.0).

---

## Repository layout

```
PPoSE-Protocol/
├── assets/           # Brand icon (honey / onion-layer motif)
├── docs/             # Formal specification
├── src/              # Rust reference implementation
│   ├── crypto/
│   ├── network/
│   ├── reliability/
│   └── identity/
├── tests/
├── benches/
├── examples/
├── SECURITY.md
├── CONTRIBUTING.md
└── LICENSE           # MIT
```

---

## Community & contact

| Channel | Link |
|---|---|
| Issues | [GitHub Issues](https://github.com/thefear078/PPoSE-Protocol/issues) |
| Discussions | [GitHub Discussions](https://github.com/thefear078/PPoSE-Protocol/discussions) |
| Security | [Private advisory](https://github.com/thefear078/PPoSE-Protocol/security/advisories/new) |
| Maintainer | [@thefear078](https://github.com/thefear078) |

Questions about the spec → open a Discussion. Implementation bugs → open an Issue. Crypto/privacy flaws → Security Advisories only.

---

## License

MIT © 2026 [The Fear](https://github.com/thefear078) — see [LICENSE](LICENSE).

---

## Tags

`#PPoSE` `#P2P` `#Privacy` `#Anonymity` `#ZeroMetadata` `#OnionRouting` `#NoiseProtocol` `#XChaCha20` `#Ed25519` `#BLAKE3` `#UDP` `#NATTraversal` `#BlindRendezvous` `#Rust` `#tokio` `#APTResistant` `#Stateless` `#ForwardSecrecy` `#HoneypotYellow` `#OpenSource`
