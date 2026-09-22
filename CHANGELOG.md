# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] — 2026-09-22

### Changed

- Spec demoted from “v1.2-FINAL / production-ready / APT-grade / zero-metadata” to **v0.2-DRAFT** with honest threat model
- Cleartext wire header reduced to **8 bytes**; identity hashes removed from the clear
- README badges and bug-bounty promises aligned with reality (no active bounty)
- “Sphinx-like” claims removed until a cited construction exists

### Added

- `docs/THREAT_MODEL.md` — claims vs non-claims
- `docs/PACKET.md` — byte workbook
- Phase 1 implementation: X25519 identity, Noise XX (`snow`), framed UDP, loopback session
- Integration test `tests/udp_loopback.rs` and example `udp_chat`

### Removed

- Soft reputation / WoT presented as security features in README
- Unmeasured latency/battery figures presented as properties

## [0.1.0] — 2026-09-22

### Added

- Initial public docs, branding, and empty crate scaffold
