# Security Policy

## Supported versions

| Component | Support |
|---|---|
| Spec v0.2-DRAFT | Design feedback welcome |
| Crate `0.x` | Best-effort; treat as experimental research code |

There is **no stable 1.0 release**. Do not deploy this for high-risk anonymity use cases.

## Reporting a vulnerability

**Do not** open a public issue for security-sensitive bugs.

1. Prefer a [private GitHub Security Advisory](https://github.com/thefear078/PPoSE-Protocol/security/advisories/new).
2. Include component, impact, and a minimal reproduction when safe.
3. Allow reasonable time for a fix before public discussion.

Acknowledgement target: within a few days when maintainers are available.

## Scope

In scope for the **current** codebase:

- Noise XX handshake misuse / transcript bugs
- AEAD nonce reuse or key confusion
- Cleartext metadata regressions in the wire format
- Memory safety issues in Rust code

Out of scope / not claimed:

- “Breaking APT-grade anonymity” — that property is **not claimed**
- Sybil resistance of the invitation sketch
- Traffic-analysis of a multi-hop network that does not exist yet
- Dependency CVEs already disclosed upstream (link the advisory)

## Bug bounty

**None active.** Previous marketing text that mentioned “up to $10,000” was aspirational and has been removed. A bounty will only appear here if funding, scope, and dates are real.

## Contact

| Purpose | Channel |
|---|---|
| Security | [Advisories](https://github.com/thefear078/PPoSE-Protocol/security/advisories/new) |
| Bugs | [Issues](https://github.com/thefear078/PPoSE-Protocol/issues) |
| Design | [Discussions](https://github.com/thefear078/PPoSE-Protocol/discussions) |
