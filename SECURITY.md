# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| Spec v1.2-FINAL | Yes (documentation & design) |
| Reference crate (pre-1.0) | Best-effort; treat as experimental |
| &lt; 1.0 releases | Security fixes prioritized before feature work |

## Reporting a vulnerability

**Do not** file public GitHub Issues for security problems.

1. Open a [private GitHub Security Advisory](https://github.com/thefear078/PPoSE-Protocol/security/advisories/new)
2. Include:
   - Affected component (crypto, routing, rendezvous, reliability, etc.)
   - Impact (confidentiality / integrity / availability / metadata)
   - Steps to reproduce or a proof-of-concept where safe
   - Suggested severity (Critical / High / Medium / Low)
3. Allow **up to 90 days** for coordinated disclosure before public discussion

We will acknowledge receipt within **72 hours** when possible.

## Scope (high priority)

- Cryptographic correctness (Noise XX, XChaCha20-Poly1305, X25519, Ed25519, BLAKE3, HKDF)
- Metadata leakage or traffic-analysis breaks against the stated threat model
- Sybil / invitation / reputation bypasses
- Blind rendezvous correlation when RS operators collude contrary to protocol rules
- Memory safety issues in the Rust reference implementation
- Relay compromise that expands attacker knowledge beyond the design envelope

## Out of scope (examples)

- Denial-of-service via raw volumetric flooding without a novel protocol flaw
- Compromised endpoint devices / malware on user machines
- Social engineering of invitation Web-of-Trust humans
- Issues in third-party dependencies already disclosed upstream (report upstream; link here)

## Bug bounty (planned)

Before the v1.0 production release we intend to run a public bug bounty with rewards up to **$10,000 USD** for critical protocol or implementation vulnerabilities. Exact tiers and eligibility will be published in this file when the program opens.

## Threat model summary

PPoSE assumes:

- A **global passive adversary** capable of observing all network links
- **Malicious relays** that may record, drop, or delay traffic
- **Sybil** attempts to flood admission / reputation

Design goals and intentional trade-offs are documented in [docs/SPECIFICATION.md](docs/SPECIFICATION.md) §§1, 7, 13.

## Contact

| Purpose | Channel |
|---|---|
| Security reports | [GitHub Security Advisories](https://github.com/thefear078/PPoSE-Protocol/security/advisories/new) |
| Non-security bugs | [GitHub Issues](https://github.com/thefear078/PPoSE-Protocol/issues) |
| Design discussion | [GitHub Discussions](https://github.com/thefear078/PPoSE-Protocol/discussions) |
| Maintainer | [@thefear078](https://github.com/thefear078) |
