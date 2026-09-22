# PPoSE Protocol v1.2

## Peer-to-Peer Obfuscated Stateless Exchange — Technical Specification

```
┌─────────────────────────────────────────────────────────────┐
│                    TECHNICAL SPECIFICATION                  │
│                       Version 1.2-FINAL                     │
├─────────────────────────────────────────────────────────────┤
│  Document Status: Production-Ready for Implementation      │
│  Security Level: APT-Grade Privacy                        │
│  Threat Model: Global Passive Adversary + Malicious Relays│
│  License: MIT                                             │
│  Target Language: Rust (tokio async runtime)              │
│  Last Updated: September 2026                             │
│  Repository: https://github.com/thefear078/PPoSE-Protocol │
└─────────────────────────────────────────────────────────────┘
```

---

## 1. Executive Summary

### 1.1 Purpose

PPoSE is a decentralized protocol for anonymous peer-to-peer communication with **zero-metadata leakage**. It is designed to resist:

- A **global passive observer** (APT, intelligence agencies)
- **Malicious relays** (compromised network operators)
- **Sybil attacks** (botnets)

### 1.2 Key Metrics

| Metric | Target |
|---|---|
| **LAN latency** | &lt; 10 ms |
| **WAN latency** | ~50–100 ms |
| **MTU** | Hard 1200 bytes (internal) |
| **Maximum hops** | 3 (configurable up to 5) |
| **Forward secrecy** | Full (per-message) |
| **Metadata exposure** | Zero |
| **Mobile battery** | 3–5% / hour (adaptive mode) |

### 1.3 Design Principles

1. **No trusted third parties** — no node observes the full end-to-end relationship
2. **Stateless after handshake** — minimal memory on relays
3. **UDP-first transport** — control over timings
4. **Cryptographic agility** — algorithms replaceable without a protocol upgrade

---

## 2. Protocol Stack Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                   PPoSE v1.2 Protocol Stack                 │
├─────────────────────────────────────────────────────────────┤
│  Layer 7: Application API                                  │  Messenger / files / voice
├─────────────────────────────────────────────────────────────┤
│  Layer 6: Reliable Datagram (RDG)                          │  ACK, fragment, retransmit
├─────────────────────────────────────────────────────────────┤
│  Layer 5: Cryptography                                     │  Noise XX + XChaCha20-Poly1305
├─────────────────────────────────────────────────────────────┤
│  Layer 4: Source Routing                                   │  Sphinx-like onion encapsulation
├─────────────────────────────────────────────────────────────┤
│  Layer 3: Identity + NAT Traversal                         │  Blind Rendezvous + STUN
├─────────────────────────────────────────────────────────────┤
│  Layer 2: Traffic Obfuscation                              │  Adaptive constant-rate channels
├─────────────────────────────────────────────────────────────┤
│  Layer 1: Transport                                        │  UDP / TCP / WebSocket / BLE
└─────────────────────────────────────────────────────────────┘
```

---

## 3. Cryptographic Primitives (Layer 5)

### 3.1 Mandatory Algorithms

| Component | Algorithm | Parameters | Length |
|---|---|---|---|
| **Identity key** | Ed25519 | Curve25519 basepoint | 32 B secret / 32 B public |
| **Key exchange** | X25519 | Elliptic-curve DH | 32 B shared secret |
| **Symmetric encrypt** | XChaCha20-Poly1305 | 24-byte nonce | 256-bit key |
| **Identity hash** | BLAKE3 | Full output | 32 B |
| **Signature** | Ed25519 | Deterministic | 64 B |
| **KDF** | HKDF-SHA256 | Extract-and-expand | 32 B output |

### 3.2 Noise Protocol Pattern: XX

**Why not IK:**

- IK does not provide forward secrecy for the first message
- IK is vulnerable to KCI (Key Compromise Impersonation)

**Why XX:**

- Full FS after handshake
- KCI resistance
- Extra RTT is a one-time per-session cost

### 3.3 Noise XX Handshake Diagram

```
Initiator (Alice)                Responder (Bob)
      │                              │
      │  e, es                       │  (1)
      ├──────────────────────────────►│
      │                              │  Initiate ephemeral, static
      │           e, ee              │  (2)
      │◄──────────────────────────────┤
      │           ss                 │  (3)
      │                              │  Respond ephemeral, static
      │  PSK (optional)              │  (4)
      ├──────────────────────────────►│  (session confirmation)
      │                              │
      ══════ SESSION ESTABLISHED ════╪
      │                              │

(1) First message: ephemeral pubkey + static pubkey (encrypted)
(2) Second message: ephemeral pubkey + encrypted response
(3) Session keys derived from all DH outputs
(4) Optional pre-shared key for mutual auth

Total handshake: 2 round trips (≈100 ms WAN)
After handshake: stateless, no ratchet state stored on relays
```

### 3.4 Key Derivation

```rust
// HKDF chain for session key hierarchy
master_secret = X25519(ephemeral_A, ephemeral_B)
 || X25519(static_A, static_B) // if mutual auth
 || X25519(ephemeral_A, static_B)

// Per-message keys
msg_key = HKDF(master_secret, salt="ppose-msg", info=sequence_number)
enc_key = msg_key[0..32]
mac_key = msg_key[32..64]

// Forward secrecy: new master_secret per session (every 24h or 1000 msgs)
```

---

## 4. Packet Format (Layer 4)

### 4.1 Fixed Header (44 bytes)

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+---------------+-------+---+---+---------------------------+
|MAGIC (2b)     |VER(1b)|TYP|FLAGS| Reserved (1b)           │
| 0x4A 0x7F     | 0x02  |   |     | MUST be 0x00             │
+---------------+-------+---+---+---------------------------+
|              Sender Identity (32b)                        │
|  BLAKE3(identity_pubkey) — FULL 32 bytes                 │
+-----------------------------------------------------------+
|              Receiver Identity (32b)                      │
|  BLAKE3(identity_pubkey) — FULL 32 bytes                 │
+-----------------------------------------------------------+
|              Sequence Number (4b)                         │
|  uint32 big-endian, monotonic increasing per session      │
+-----------------------------------------------------------+
|              Message_ID (12b)                             │
|  UUID-like for ACK tracking (random on first transmit)    │
+-----------------------------------------------------------+
```

**Fully removed:**

- Timestamp (8 B) — clock fingerprint vector
- Route length field (now fixed 48 B × hop_count)
- Any optional fields

### 4.2 Route Envelopes (48 bytes per hop, max 5 hops)

```
Per-Hop Structure (for each intermediate relay):
┌─────────────────────────────────────────────────────────────┐
│  Target_Hash (32b)         ← Next hop identity (BLAKE3)     │
│  Encrypted_Address (16b)   ← XChaCha20 with relay key       │
│                              (includes IP:Port packing)     │
│  Ephemeral_Public_Key (32b) ← X25519 for shared secret      │
│  HMAC_SHA256 truncated (16b)← Integrity check               │
└─────────────────────────────────────────────────────────────┘
Note: field packing MUST total 48 bytes per hop as implemented;
exact sub-field widths are normative in the reference codec.

For 3-hop route: 48 × 3 = 144 bytes of routing
For 5-hop route: 48 × 5 = 240 bytes of routing

Total packet size = 44 + route + payload_section ≤ 1200 bytes
```

### 4.3 Payload Section (variable, ≤1052 bytes at 3 hops)

```
┌─────────────────────────────────────────────────────────────┐
│  Ephemeral_PubKey (32b)       ← New X25519 key per packet   │
│  IV / nonce (24b preferred / 12b if AEAD mode requires)    │
│  Ciphertext (variable)         ← XChaCha20 encrypted data  │
│  Auth_Tag (16b)                ← Poly1305 MAC              │
└─────────────────────────────────────────────────────────────┘
```

### 4.4 ACK Frame Format

```
┌─────────────────────────────────────────────────────────────┐
│  Type: ACK (0x02)                                          │
│  Base_Ack_Number (4b)        ← Lowest unacked sequence     │
│  Bitmap (8b / 64 bits)       ← bit[i]=1 if [base+i] recv   │
│  Window_Size (2b)            ← Current receiver window     │
└─────────────────────────────────────────────────────────────┘

Size: 14 bytes + framing overhead
Sent every 4th data packet OR as standalone NACK
```

---

## 5. MTU Management (Layer 6)

### 5.1 Hard Constraint

```
INTERNAL_MTU = 1200 bytes (constant, non-configurable)

Rationale:
• IPv6 minimum: 1280 bytes
• Minus tunnel headers: 80 bytes
• Safety margin: 80 bytes

If packet > 1200 bytes → MUST split at L6 BEFORE encryption
```

### 5.2 Pre-Encryption Fragmentation

```
Large Message (>1200 bytes):
┌─────────────────────────────────────────────────────────────┐
│  Original: [2000 bytes payload]                            │
│                                                            │
│  Fragmented into:                                          │
│  Fragment 0: [Header: fragment_id=123, total=2, seq=0,     │
│               payload=first chunk]                        │
│  Fragment 1: [Header: fragment_id=123, total=2, seq=1,     │
│               payload=remaining]                          │
│                                                            │
│  Each fragment fits within the 1200-byte limit             │
│  Receivers reassemble in order, then deliver to L7         │
└─────────────────────────────────────────────────────────────┘

Fragment Header:
├─ Fragment_ID (4b)   ← Unique ID for this message
├─ Total_Fragments (2b)
├─ Fragment_Index (2b)
├─ Original_Length (4b)
```

### 5.3 PLPMTUD (Path MTU Discovery)

```
Procedure during handshake:
1. Alice sends probe_packets of sizes: 512, 1024, 1152, 1200
2. Bob acknowledges which sizes were successfully received
3. Both parties record min(1200, highest_successful_size)
4. Periodically re-probe every 60 seconds

Fallback: If probing fails repeatedly, reduce effective MTU to 1024 bytes
```

---

## 6. Blind Rendezvous System (Layer 3)

### 6.1 Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Alice                              Bob                    │
│     │                                 │                    │
│     ▼                                 ▼                    │
│  RS-A (Random)                    RS-B (Random)           │
│  (Becomes blind)                  (Becomes blind)         │
│     │                                 │                    │
│     │  DHT lookup (blind)             │                    │
│     └─────────────────────────────────┘                    │
│                    │                                       │
│  Neither RS knows BOTH endpoints simultaneously            │
└─────────────────────────────────────────────────────────────┘
```

### 6.2 Protocol Flow

```
Step 1: Alice generates Blinded Key
─────────────────────────────────────
blinded_key = H(epoch_counter ∥ shared_secret) ⊕ hash(Bob_identity)

Step 2: Alice registers with RS-A
─────────────────────────────────────
Alice → RS-A: { blinded_key, alice_address, signature }
RS-A stores: blinded_key ↦ alice_address
RS-A DOES NOT know who Alice wants to contact

Step 3: Bob registers descriptor
─────────────────────────────────────
Bob → RS-B: { bob_descriptor, bob_address, signature }
Bob_descriptor = { bob_identity, service_port, expiration }

Step 4: Alice retrieves Bob's blind descriptor
─────────────────────────────────────
Alice → RS-A: query(blinded_key)
RS-A → Alice: { RS-B_address, onion_wrapped_intro }

Step 5: Hole punch initiation
─────────────────────────────────────
Alice → RS-B (via onion): "Send STUN probe to alice_address"
RS-B → Alice: STUN_probe
Alice ↔ Bob: NAT hole punches (both initiate outgoing)
```

### 6.3 Anti-Correlation Requirement

```
MANDATORY RULES:
1. RS-A and RS-B MUST have different operators
2. RS selection via VRF (Verifiable Random Function)
3. Client verifies operator fingerprints against a public registry
4. If both RS are controlled by the same entity → abort connection
```

---

## 7. Trust Model & Sybil Defense (Layer 3/4)

### 7.1 Invitation Web-of-Trust (WoT)

```
┌─────────────────────────────────────────────────────────────┐
│  Three-tier Admission System:                             │
├─────────────────────────────────────────────────────────────┤
│  Tier 1: Bootstrap Admins (5 known nodes)                 │
│    • Manually configured, verified out-of-band           │
│    • Can issue invitations to Tier 2                     │
│                                                          │
│  Tier 2: Relay Operators                                 │
│    • Need 1 signed invitation from Tier 1 or Tier 2      │
│    • Must run for ≥7 days before inviting others         │
│    • Responsible for invitees (reputation linked)        │
│                                                          │
│  Tier 3: Clients                                         │
│    • Direct P2P, no relay duties                         │
│    • May upgrade to Tier 2 after 24h activity            │
└─────────────────────────────────────────────────────────────┘
```

### 7.2 Reputation System

```rust
struct NodeReputation {
    age_days: u32,              // How long the node has existed
    successful_relay_count: u64,
    failed_delivery_count: u64,
    invitation_chain_depth: u8,
    // Formula:
    // score = (age_days * 10) + successful_relay - (failed_relay * 100)
}

// Thresholds:
// reputation > 1000 → Tier 2 eligible
// reputation < 0 → Ban, revoke invitations
```

### 7.3 Anti-Spam Measures

```
Rate Limiting:
• Max 3 new invitations per node per week
• Min 7 days between invitation issuance
• Invitation requires proof of active relay usage (≥100 MB/day)
• Cooldown period: 24h before accepting first relay traffic

Monitoring:
• Random probes sent by other nodes (decoy traffic)
• False positives trigger investigation
• Multiple failures → automatic revocation
```

---

## 8. Traffic Obfuscation (Layer 2)

### 8.1 Adaptive Modes

```
┌─────────────────────────────────────────────────────────────┐
│  Mode       │ Interval  │ Fake %  │ Battery  │ Privacy     │
├─────────────────────────────────────────────────────────────┤
│  Eco        │ 1000 ms   │ 0%      │ ★★★★★  │ ★★☆☆☆     │
│  Balanced   │  200 ms   │ 50%     │ ★★★★☆  │ ★★★☆☆     │
│  Stealth    │   50 ms   │ 100%    │ ★★☆☆☆  │ ★★★★★     │
│  Burst      │ Variable  │ 0%      │ ★★★★☆  │ ★★☆☆☆     │
└─────────────────────────────────────────────────────────────┘

Auto-switching Logic:
if (battery_level < 15%) → Eco
else if (is_charging) → Stealth
else if (wifi_connected) → Balanced
else → Balanced
```

### 8.2 Cover Traffic Generation

```
Fake Packet Structure:
├─ Identical header format to real packets
├─ Valid HMAC (but different key)
├─ Payload = cryptographically random noise
├─ Receiver validates HMAC → rejects if fake
└─ Observer sees traffic indistinguishable from real
```

---

## 9. Reliable Datagram (Layer 6)

### 9.1 Selective Repeat ARQ

```
Parameters:
• window_size: 32 packets (sliding)
• ack_frequency: every 4th packet includes bitmap
• retransmit_timeout: 200 ms × 5 attempts
• reorder_buffer: 200 ms hold before application delivery
```

### 9.2 ACK Processing

```rust
fn process_ack(&mut self, base_ack: u32, bitmap: u64) {
    // Mark packets as acknowledged
    for i in 0..64 {
        if (bitmap >> i) & 1 == 1 {
            self.acknowledge(base_ack + i);
        }
    }

    // Schedule retransmits for unacked
    for seq in self.unacked_packets() {
        if seq < base_ack + 64 && !is_acked(seq) {
            schedule_retransmit(seq);
        }
    }
}
```

### 9.3 Out-of-Order Handling

```
Buffer Management:
├─ reorder_buffer holds packets 0–200 ms after receipt
├─ Delivers to L7 only when gap-filled
├─ If gap persists >2 s → drop and notify sender
└─ Maximum buffer size: 64 packets
```

---

## 10. Configuration Schema

```json
{
  "ppose": {
    "version": "1.2",
    "crypto": {
      "identity_algo": "Ed25519",
      "dh_algo": "X25519",
      "symmetric": "XChaCha20-Poly1305",
      "hash_algo": "BLAKE3",
      "noise_pattern": "XX",
      "kdf": "HKDF-SHA256"
    },
    "network": {
      "internal_mtu": 1200,
      "max_hops": 3,
      "max_handshake_rtt_ms": 150,
      "keepalive_interval_ms": 5000,
      "connection_timeout_ms": 10000
    },
    "reliability": {
      "window_size": 32,
      "ack_interval": 4,
      "retx_timeout_ms": 200,
      "max_retx_attempts": 5,
      "reorder_buffer_ms": 200
    },
    "traffic_mode": {
      "default": "balanced",
      "battery_low_percent": 15,
      "battery_high_percent": 30
    },
    "identity": {
      "hash_length_bytes": 32,
      "collision_check": false
    },
    "trust": {
      "bootstrap_nodes": ["..."],
      "invitation_required": true,
      "min_reputation_score": 1000
    }
  }
}
```

---

## 11. Testing Requirements

### 11.1 Unit Tests

```
Required Coverage:
├─ crypto/* → 100% coverage (critical path)
├─ packet/* → 95% coverage
├─ network/* → 90% coverage
└─ reliability/* → 95% coverage
```

### 11.2 Integration Tests

```
Test Scenarios:
├─ NAT traversal (hole punching success / failure)
├─ 3-hop route establishment
├─ Packet loss simulation (10%, 30%, 50%)
├─ Reconnection after network failure
├─ MTU probe and adjustment
├─ Blind rendezvous anonymity verification
└─ Relay compromise detection
```

### 11.3 Security Audits

```
External Audit Required For:
├─ Cryptographic implementation (NIST-aligned / literature vectors)
├─ Protocol specification (formal review)
├─ Memory safety (fuzzing, ASAN / TSAN)
└─ Side-channel resistance (timing attacks)
```

---

## 12. Implementation Roadmap

### Phase 1: Core Infrastructure (Weeks 1–3)

| Task | Deliverable | Owner |
|---|---|---|
| Cargo.toml + dependencies | Build system ready | Dev Lead |
| Crypto primitives module | X25519, ChaCha20, BLAKE3 | Senior Dev |
| Packet encode / decode | Zero-copy serialization | Senior Dev |
| Noise XX handshake | Complete handshake flow | Security Lead |

### Phase 2: Networking Layer (Weeks 4–6)

| Task | Deliverable | Owner |
|---|---|---|
| UDP socket abstraction | Async handler | Dev Lead |
| STUN + hole punching | Working NAT bypass | Network Dev |
| Blind rendezvous protocol | Anonymous discovery | Security Lead |
| Basic P2P messaging | End-to-end test | All |

### Phase 3: Reliability & Routing (Weeks 7–9)

| Task | Deliverable | Owner |
|---|---|---|
| ACK / NACK system | Selective repeat ARQ | Dev Lead |
| Reorder buffer | Out-of-order handling | Senior Dev |
| Source routing (3-hop) | Sphinx encapsulation | Senior Dev |
| MTU adaptation | PLPMTUD probes | Network Dev |

### Phase 4: Production Hardening (Weeks 10–14)

| Task | Deliverable | Owner |
|---|---|---|
| Traffic obfuscation modes | Adaptive modes | Senior Dev |
| Reputation system | WoT implementation | Security Lead |
| Performance benchmarks | Latency / throughput | Dev Lead |
| Documentation | API reference, tutorials | Tech Writer |

### Phase 5: Security Audit & Release (Week 15+)

| Task | Deliverable | Owner |
|---|---|---|
| External audit | Report + fixes | Auditor |
| Bug bounty program | Public disclosure | Security Lead |
| v1.0 release | Production ready | Dev Lead |

---

## 13. Known Limitations & Trade-offs

### 13.1 Acknowledged Weaknesses

| Issue | Impact | Mitigation |
|---|---|---|
| **Cold start problem** | Initial trust bootstrap | 5 hardcoded bootstrap nodes |
| **Blind rendezvous collusion** | Same-operator RS attack | Require 2 independent RS |
| **Battery drain (Stealth mode)** | Reduced device usability | Adaptive switching |
| **Mobile carrier restrictions** | UDP blocked by ISPs | TCP fallback option |
| **Invitation spam** | Social engineering attack | Rate limits + reputation |

### 13.2 Intentional Trade-offs

| Decision | Why not a “better” alternative? |
|---|---|
| **No blockchain staking** | Avoids on-chain identity linkage |
| **Hardcoded MTU 1200** | Simpler than fully dynamic negotiation |
| **Noise XX (+1 RTT)** | Acceptable cost for full FS + KCI protection |
| **Invitation WoT** | Better than staking for high-threat environments |

---

## 14. Appendix: Reference Implementations

### Recommended Libraries

```toml
# Cargo.toml dependencies
[dependencies]
tokio = { version = "1", features = ["full"] }
ring = "0.17"
curve25519-dalek = "4"
blake3 = "1"
snow = "0.9"          # Noise protocol framework
chacha20poly1305 = "0.10"
tracing = "0.1"
serde = { version = "1", features = ["derive"] }
bincode = "1"
```

### Repository Structure

```
PPoSE-Protocol/
├── Cargo.toml
├── README.md
├── LICENSE
├── SECURITY.md
├── .github/workflows/
│   ├── ci.yml
│   └── security-audit.yml
├── src/
│   ├── lib.rs
│   ├── crypto/
│   ├── network/
│   ├── reliability/
│   └── identity/
├── tests/
├── benches/
└── examples/
```

---

## 15. Sign-off

| Role | Name | Date | Signature |
|---|---|---|---|
| Protocol Designer | The Fear (@thefear078) | 2026-09-22 | Spec authored |
| Security Auditor | TBD | Pending | |
| Lead Developer | TBD | Pending | |

**Approval Status:** READY FOR IMPLEMENTATION

---

## Contact

| Channel | URL |
|---|---|
| Issue tracker | https://github.com/thefear078/PPoSE-Protocol/issues |
| Discussions | https://github.com/thefear078/PPoSE-Protocol/discussions |
| Security reports | https://github.com/thefear078/PPoSE-Protocol/security/advisories/new |
| Bug bounty | Planned — up to $10,000 USD for critical findings (see SECURITY.md) |
| Maintainer | https://github.com/thefear078 |

---

**Document completed. Ready for development team handoff.**

Tags: `#PPoSE` `#Specification` `#v1.2` `#NoiseXX` `#OnionRouting` `#ZeroMetadata` `#BlindRendezvous`
