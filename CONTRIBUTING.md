# Contributing to PPoSE Protocol

Thanks for helping turn this from a design sketch into something auditable.

## Ground rules

1. Read [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) before proposing stronger security claims.
2. Prefer small, reviewable pull requests.
3. Never commit secrets or real-world identity material.
4. Security-sensitive findings go through [SECURITY.md](SECURITY.md).
5. Do not add marketing badges (“APT-grade”, “zero-metadata”, “FINAL”) without evidence linked in the threat model.

## Development setup

```bash
git clone https://github.com/thefear078/PPoSE-Protocol.git
cd PPoSE-Protocol
rustup update stable
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
cargo run --example udp_chat
```

## What to work on next

| Priority | Area |
|---|---|
| High | Fit cover payload size *and* interval to a real measured traffic distribution (currently hand-picked ranges — see `examples/cover_measurement.rs`, `CoverMode::payload_len_range`/`interval_range`) |
| High | Adopt Sphinx if onion must match literature |
| Low | Formal correlation analysis of rendezvous |
| Low | Wire `src/admission.rs` TrustStore into `rs`/`relay` CLI as an opt-in gate |

## Pull request checklist

- [ ] `cargo test` / `clippy` / `fmt` clean
- [ ] Wire-format changes update `docs/PACKET.md` in the same PR
- [ ] Claim changes update `docs/THREAT_MODEL.md`
- [ ] Commit messages explain *why*

## License

By contributing you agree that your contributions are licensed under the MIT License.
