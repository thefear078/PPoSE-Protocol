# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Public repository documentation (README, SECURITY, CONTRIBUTING, CODE_OF_CONDUCT)
- Formal English specification **PPoSE v1.2-FINAL** (`docs/SPECIFICATION.md`)
- Brand assets: honey / onion-layer motif icon (`assets/logo.png`, `assets/p.png`)
- Rust crate scaffold with module layout for crypto, network, reliability, identity
- GitHub Actions CI workflow (check, test, clippy, fmt)

### Protocol (v1.2)

- Noise XX handshake; XChaCha20-Poly1305; Ed25519 / X25519 / BLAKE3 / HKDF-SHA256
- Fixed 44-byte header; 48-byte per-hop route envelopes; hard internal MTU 1200
- Blind rendezvous, invitation Web-of-Trust, adaptive traffic obfuscation modes

## [0.0.0] — 2026-09-22

### Added

- Initial repository with MIT license
