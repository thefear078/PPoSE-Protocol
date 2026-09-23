# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Invitation Web-of-Trust admission (`src/admission.rs`): Ed25519-signed, time-bounded invitations; `TrustStore` walks chains from trusted roots with a local per-issuer subject cap. Documented as a policy layer, **not** a cryptographic Sybil defense.
- `examples/admission_demo.rs` walkthrough
- CLI: `ppose listen`/`connect --pin <hex32>` to pin the expected remote Noise static key (fails closed instead of trust-on-first-use), and `--key <hex32>` to load a persistent local identity so a peer's pin survives restarts
- `docs/SECURITY_REVIEW.md`: internal self-review of `src/crypto/*`, `src/onion.rs`, `src/session.rs`, `src/network/*`, `src/reliability/*`, `src/rendezvous.rs`, `src/relay.rs`, `src/admission.rs` — explicitly **not** a substitute for the external review roadmap Phase 7 still calls for
- CLI: `ppose keygen-invite` and `ppose invite <subject> --signer <hex32> [--ttl-secs N]` to generate Invitation Web-of-Trust material, and `ppose listen --admit-root <hex32> [--admit-invite <hex288>]... [--admit-depth N]` to gate accepted connections through `src/admission.rs`'s `TrustStore` — the check runs *after* the Noise XX handshake, on the now-authenticated remote static key, not on an unauthenticated claim. Verified end-to-end manually: an invited identity connects and is admitted, an uninvited one is rejected with a clear error. With no `--admit-root`, `listen` behaves exactly as before (opt-in).
- `examples/cover_measurement.rs`: measures real ACK/DATA/cover wire sizes against the project's actual encoding + a live Noise session — replaces the "unmeasured" size claim in `docs/SPECIFICATION.md` §8 with real numbers
- `tests/cover.rs`: first test coverage at all for `CoverMode`/`set_cover` — confirms a real message still delivers correctly with cover traffic interleaved (cover packets fail to decrypt and are silently dropped; `snow` only advances its receive nonce on success, so no desync)

### Fixed

- `ReplayCache::accept` (`src/network/replay.rs`) did a full `O(n)` sweep on every packet; duplicate detection is now checked per-key (correct on every call) and the reclaiming sweep is throttled to every 64 calls or when at capacity
- Onion relay (`src/onion.rs::OnionRelay::step`) now drops a peeled layer whose next-hop address is the relay's own bound address, preventing a trivial single-hop loop
- `NoiseSession::pin_remote` (`src/crypto/noise.rs`) now uses `subtle::ConstantTimeEq` instead of `!=`; defensive hygiene rather than a fix for an exploitable leak, since both sides were already public key material
- `TrustStore::trust_depth` (`src/admission.rs`) no longer re-runs Ed25519 verification on every stored invitation for every query; only the cheap time window is rechecked, since `ingest` already verifies once before storing and invitations are immutable afterward
- Cover packets were a fixed 72 bytes on the wire regardless of mode (`src/cover.rs`'s 64-byte constant + 8-byte outer header), contradicting the module's own claim of being size-indistinguishable from real traffic; `CoverMode::payload_len_range` now gives a per-packet randomized range instead. Still a hand-picked range, not fit to measured real traffic — noted as open work in `CONTRIBUTING.md`.
- Cover packets also fired at an exact fixed cadence (200ms / 50ms), a pure periodic signal on its own regardless of the size fix; `CoverMode::interval_range` + `UdpSession::schedule_next_cover` now jitter the interval per packet the same way payload length is randomized. Same caveat: a hand-picked range, not measured against real traffic timing.

### Changed

- Cleaned up several clippy-pedantic nits (`let...else`, redundant `continue`, hex-encoding helpers) with no behavior change
- `docs/SPECIFICATION.md` architecture diagram, crypto primitives table, §4.5 onion heading, prior-art table, and limitations table updated — several had gone stale since v0.4 shipped onion/rendezvous/cover (still said "not implemented")

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
