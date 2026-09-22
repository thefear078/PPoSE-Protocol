# Contributing to PPoSE Protocol

Thanks for helping build **Peer-to-Peer Obfuscated Stateless Exchange**.

## Ground rules

1. Read [docs/SPECIFICATION.md](docs/SPECIFICATION.md) before proposing protocol changes.
2. Prefer small, reviewable pull requests.
3. Never commit secrets, private keys, or real-world identity material.
4. Security-sensitive findings go through [SECURITY.md](SECURITY.md), not public issues.

## Development setup

```bash
git clone https://github.com/thefear078/PPoSE-Protocol.git
cd PPoSE-Protocol
rustup update stable
cargo check
cargo test
cargo clippy -- -D warnings
cargo fmt --check
```

## What to work on

| Area | Notes |
|---|---|
| Spec clarifications | Open a Discussion first for normative wording |
| Crypto / packets | Must include vectors under `tests/crypto_vectors/` |
| Networking | Prefer deterministic tests + documented assumptions |
| Docs / branding | English only in repo text |

Roadmap phases are listed in the README and §12 of the specification.

## Pull request checklist

- [ ] `cargo test` passes
- [ ] `cargo fmt` and `clippy` clean
- [ ] Spec impact noted (link section numbers if behavior changes)
- [ ] No secrets / personal data
- [ ] Commit messages explain *why*

## Code style

- Rust 2021 edition
- Imports at the top of the module (no inline imports)
- Exhaustive `match` on enums / discriminated unions with a `never` default where applicable
- Prefer `tracing` for diagnostics over `println!`

## Commit & PR etiquette

- One logical change per PR when possible
- Reference issues with `Fixes #N` when applicable
- For protocol deltas, include a short “Compatibility” note (breaking / soft / none)

## Community

- Issues: bugs and concrete tasks
- Discussions: design, threat model, roadmap
- Be respectful — see [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)

## License

By contributing you agree that your contributions are licensed under the MIT License (see [LICENSE](LICENSE)).
