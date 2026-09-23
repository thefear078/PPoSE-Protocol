# Internal security self-review (2026-09-23)

**This is not the external review roadmap Phase 7 asks for.** Phase 7 in
[README.md](../README.md#roadmap) requires independent auditors; nothing
below substitutes for that. This is a documented internal pass over the
`v0.4` + Invitation Web-of-Trust code — what was checked, what looks sound,
and what is worth a human's attention before anyone relies on this for
anything beyond research. See [THREAT_MODEL.md](THREAT_MODEL.md) for the
project's actual security claims; this document does not change any of
them.

## Scope

Read in full: `src/crypto/*`, `src/onion.rs`, `src/session.rs`,
`src/network/*`, `src/reliability/*`, `src/rendezvous.rs`, `src/relay.rs`,
`src/admission.rs`. Checked: nonce/key handling, panics reachable from
untrusted network input, replay/DoS bounds, and dependency choices.
Not done: fuzzing, formal verification, constant-time audit with
instrumentation, or review of `snow`/`x25519-dalek`/`ed25519-dalek`
themselves (treated as trusted, widely-used dependencies).

## What looks sound

- **No hand-rolled primitives.** AEAD, DH, signatures, and the Noise
  handshake are all delegated to vetted crates (`snow`, `chacha20poly1305`,
  `x25519-dalek`, `ed25519-dalek`). The project's own "cite constructions,
  don't cosplay" principle (README §Design principles) is followed in the
  code, not just the docs.
- **No nonce reuse under a fixed key in the onion path.** Each PND layer
  (`src/onion.rs::wrap_layer`) derives its AEAD key from a *fresh* ephemeral
  X25519 DH per layer per message, so even though the 24-byte nonce is only
  drawn from `OsRng` (not a counter), it's never reused under the same key.
- **Secret zeroization is inherited, not missing.** `cargo tree -i zeroize`
  confirms `curve25519-dalek`, `x25519-dalek`, and `ed25519-dalek` all pull
  in `zeroize`; their secret types (`StaticSecret`, `EphemeralSecret`,
  `SigningKey`) zero their own memory on drop. The one caller-responsibility
  gap is already called out in the doc comments: `IdentitySecret::to_bytes`
  / `InviteSigningKey::to_bytes` hand back a plain `[u8; 32]` copy with no
  protection, and say "handle with care" — a caller printing or storing
  that copy (e.g. `ppose keygen`) is on their own, as it should be for a
  CLI debug/bootstrap tool.
- **No panics reachable from untrusted network bytes in non-test code.**
  Grepped every `unwrap()` / `expect()` / `panic!()` in `src/`; the two
  `.expect("key")` calls in `src/reliability/arq.rs` operate on keys
  collected from the same map earlier in the same call with no removal in
  between (a local invariant, not attacker-influenced), and the two
  `.expect(...)` calls in `src/rendezvous.rs` encode fixed-size local data
  (a 32-byte token) that always fits `MAX_DATAGRAM` — both unreachable in
  practice, not just "shouldn't happen."

## Findings (informational — none blocked current use as a research prototype)

1. **Fixed.** `ReplayCache::accept` ran a full `O(n)` `HashMap::retain` scan
   on *every* accepted packet (`src/network/replay.rs`, used by the IPv4
   forwarder, the onion relay, and rendezvous). At the default cap of 4096
   entries this was microseconds and not exploitable, but throughput would
   have degraded linearly if `DEFAULT_CAP` were ever raised. Reworked so the
   duplicate check reads one entry's own timestamp directly (correct on
   every call, independent of sweeps) and the reclaiming sweep now runs
   only every `SWEEP_EVERY` (64) calls or when `cap` is reached — see
   `ttl_correctness_survives_throttled_sweep` and
   `sweep_reclaims_stale_entries_over_many_calls` in that module's tests.
2. **Fixed.** `TrustStore` re-verified every stored invitation's Ed25519
   signature on every `trust_depth` query. (`src/admission.rs`.) Since
   `ingest` already verifies (signature + time window) before an invitation
   is stored, and `Invitation`'s fields are private and never mutated
   afterward, `trust_depth` now only re-checks the cheap time window via
   `Invitation::time_valid` and relies on the one-time signature check from
   ingestion — no repeated Ed25519 verification per query.
3. **Fixed (defensive hygiene, not an exploitable leak).**
   `NoiseSession::pin_remote` used `!=` on `[u8; 32]`, not a constant-time
   comparison. (`src/crypto/noise.rs`.) Both sides of that comparison were
   already public key material — the attacker knows the value they sent,
   and the expected value is the operator's own configuration, not a
   secret being brute-forced — so this was never a practical timing side
   channel. Switched to `subtle::ConstantTimeEq` anyway so the pattern is
   safe to copy if a future refactor reuses it for something that *is*
   secret.
4. **Fixed.** Onion relay forwarded a peeled layer's destination via plain
   `UdpSocket::send_to` with no check that it wasn't the relay's own bound
   address — a malformed or malicious route could loop a relay back into
   itself. (`src/onion.rs::OnionRelay::step`.) Now compared against
   `local_addr()` and dropped on a match. This is a same-address check
   only, not a private/link-local filter — the test suite and CLI examples
   deliberately route through `127.0.0.1`, so a broader filter would have
   broken normal local use. Operators exposing a public onion hop should
   still be aware this is "a dumb proxy, not anonymous" (§5.1) with no
   other destination sanity checking.

## What this review does not cover

Formal protocol security proofs, GPA resistance, rendezvous
operator-independence (§6 of the spec is still explicitly non-normative),
and anything requiring dynamic analysis (fuzzing `decode_outer` /
`decode_inner` / `Invitation::decode` against malformed input would be the
natural next step — none of that was run here).
