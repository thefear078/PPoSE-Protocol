# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Invitation Web-of-Trust admission (`src/admission.rs`): Ed25519-signed, time-bounded invitations; `TrustStore` walks chains from trusted roots with a local per-issuer subject cap. Documented as a policy layer, **not** a cryptographic Sybil defense.
- `examples/admission_demo.rs` walkthrough

### Changed

- Cleaned up several clippy-pedantic nits (`let...else`, redundant `continue`, hex-encoding helpers) with no behavior change

## [0.4.0] — 2026-09-22

### Added

- Optional Noise remote-static pinning (`connect_initiator_pinned`)
- PND nested hops (`TYPE=Onion`) — specified construction, **not Sphinx**
- Token rendezvous service (`TYPE=Rendezvous`)
- Cover datagrams (`CoverMode`; TYPE=Data random bodies)
- CLI: `onion-relay`, `rs`, `rs-register`, `rs-lookup`
- Tests: pin, 2-hop onion, rendezvous, header/inner vectors

## [0.3.0] — 2026-09-22

### Added

- Selective-repeat ARQ, inner DATA/ACK frames, fragmentation (1024 B units)
- Loss recovery test (drop one outbound DATA, retransmit)
- IPv4 `TYPE=Forward` wrapper, `ReplayCache`, `Relay` loop
- Relayed Alice↔Bob integration test (end-to-end Noise; relay sees dest IP)
- `ppose` CLI: `keygen`, `listen`, `connect`, `relay`

### Changed

- Spec / threat model labeled **v0.3-DRAFT**; reliability + forwarder documented as implemented
- Session `send` waits for ACKs so one-way messages can retransmit

## [0.2.0] — 2026-09-22

### Changed

- Spec demoted from “v1.2-FINAL / production-ready / APT-grade / zero-metadata” to **v0.2-DRAFT**
- Cleartext wire header reduced to **8 bytes**; identity hashes removed from the clear

### Added

- Threat model, packet workbook, Noise XX UDP loopback session

## [0.1.0] — 2026-09-22

### Added

- Initial public docs, branding, and empty crate scaffold
