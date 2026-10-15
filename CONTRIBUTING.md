# Contributing to rustmistmcp

Thanks for considering a contribution. rustmistmcp is an async Rust Model Context Protocol (MCP) server for the HPE Juniper Mist cloud — part of the [mechub](https://github.com/mechubsec) family of open-source, self-hosted network-security automation tooling. See [README.md](README.md) for what the server does, and `docs/OPERATIONS.md` / `docs/PACKAGING_ACCEPTANCE.md` for how it is packaged and operated.

## Before you start

- Check open issues and PRs first — someone may already be working on it.
- For anything larger than a small fix, open an issue to discuss the approach before writing code. It saves everyone a rewrite.
- This project follows one hard rule across the whole mechub fleet: **deterministic code decides, a model may explain or draft, a human approves.** Nothing you contribute should let an LLM or other model output directly drive a Mist API mutation or a WAN-edge change-set apply. Models may draft, summarize, or explain; deterministic code decides, and every mutating path stays behind the existing plan → digest → approve → apply lifecycle.

## Workspace layout

This is a Cargo workspace (`resolver = "2"`) with two members:

- `crates/rustmistmcp-core` — the Mist operation catalog, authorization/scope models, schema validation, and the catalog-bound `MistClient` contract
- `crates/rustmistmcp` — the binary: CLI, MCP server (tool surface, transports), and the packaging entry point (`--bin rustmistmcp`)

Generic auth, transport, audit, and change-control primitives live upstream in [`mecmcp`](https://github.com/mechubsec/mecmcp), pinned by tag in the workspace `Cargo.toml`. If you find yourself writing generic (non-Mist-specific) auth or transport code here, it probably belongs there instead — see the "Relationship to `mecmcp`" section of the README.

## Build and test

These are the exact commands CI runs (`.github/workflows/ci.yml`):

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --locked
cargo doc --workspace --no-deps --locked
cargo build --release --locked --bin rustmistmcp
```

MSRV check (the workspace declares `rust-version = "1.89"` in `Cargo.toml`; `rust-toolchain.toml` pins the build toolchain to `1.99.0` with the `rustfmt` and `clippy` components):

```sh
rustup toolchain install 1.89.0 --profile minimal
cargo +1.89.0 check --workspace --locked
```

Supply-chain checks (also required in CI, in both `ci.yml` and `security.yml`):

```sh
cargo install --locked cargo-audit cargo-deny
cargo audit
cargo deny check
```

`deny.toml` pins the allowed license set and the only permitted git dependency source (`mechubsec/mecmcp`); a new dependency from anywhere else, or under a license not already on the allow list, will fail this check and needs to be justified in the PR.

### If you touch packaging, scripts, or the systemd unit

Changes under `scripts/`, `packaging/`, the `Dockerfile`, or the systemd unit are also exercised in CI:

```sh
RUSTMISTMCP_BINARY=target/release/rustmistmcp scripts/verify-packaging.sh
scripts/test-lxc-installer.sh
scripts/test-release-policy.sh
shellcheck scripts/*.sh packaging/lxc/install.sh
```

These aren't required for a normal Rust-only change — skip them unless your PR touches those paths.

## Commit and PR conventions

- Match the existing commit style: `type(scope): summary` (`fix:`, `feat:`, `docs:`, `build(deps):`, `chore(release):`, etc.) — see `git log` for examples.
- Keep PRs focused on one change. A bug fix doesn't need a drive-by refactor riding along.
- Fill out the PR template, including the exact commands you ran to verify the change.
- By opening a pull request, you're agreeing your contribution is licensed under this repository's [MIT license](LICENSE).

## Review process

Every pull request goes through a security review and a code review, then an independent test run, before a maintainer merges. Contributors, including anyone with write access, should not merge their own PR. CI (build, test, clippy, fmt, MSRV check, `cargo audit`, `cargo deny`, and gitleaks secret scanning) must be green first.

## Reporting a vulnerability

Please don't open a public issue for a security vulnerability — see [SECURITY.md](SECURITY.md) for how to report one privately.

## Fixtures and test data

Never commit real Mist org/site identifiers, device serials, hostnames, API tokens, or captured live-tenant responses — synthetic or hand-sanitized fixtures only. If you find real data already committed anywhere in this repo, don't add to it — report it privately instead (see [SECURITY.md](SECURITY.md)).
