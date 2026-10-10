# Changelog

All notable user-facing changes are recorded here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

This file starts at 0.2.0. Earlier tags (0.1.0, 0.1.1) predate it and are
recoverable from `git log` and the release tags — noted so the omission is
visible rather than looking like those versions never existed.

## [Unreleased]

### Security

- **Startup reports every loose credential-file mode in one pass** (MEC-2233).
  `mist.json` is checked as a no-secret config (`0640`, so `0600` still
  passes) because it holds an endpoint, an org allowlist, and a credential
  path or environment-variable name, not the API token. The credential file
  named by that profile, `tokens.json`, the audit HMAC key, and the
  approval-digest key are secrets (`0600`). A missing credential file does
  not fail a fresh install that has not created one yet. `tokens.json` stays
  `/var/lib/rustmistmcp/tokens.json`, and the legacy
  `/etc/rustmistmcp/tokens.json` fallback still applies only to that exact
  path. Stdio still does not require the bearer store.
  **Upgrade note:** earlier releases did not check `mist.json`'s mode. An
  install whose profile is group- or world-writable, or world-readable (for
  example `0644`), now refuses to start. Run `chmod 0640
  /etc/rustmistmcp/mist.json` (the startup error names the exact file and
  mode to fix).

### Added

- Official MCP Registry metadata: `server.json` for the stdio container
  invocation, and the `io.modelcontextprotocol.server.name` image label.

### Changed

- The container image is published for `linux/amd64` only; the `linux/arm64`
  build and its QEMU setup are dropped.

### Changed

- **Release tarball and checksum are now uploaded to the GitHub release and
  cosign-signed** (MEC-2158). The CI-built, attested LXC-style release
  archive previously only reached a CI artifact; a new workflow triggered on
  release publication now attaches `*.tar.gz`/`*.sha256` to the release and
  signs the tarball via mecmcp's shared keyless-cosign workflow, matching
  rustjunosmcp's release process.
- **Archive SBOM switched from SPDX to CycloneDX** (MEC-2158), generated via
  `cargo-cyclonedx` instead of `anchore/sbom-action`, for consistency with
  the org-wide SBOM standard (mecmcp's `docs/RELEASE-WORKFLOWS.md`) used by
  every other repo's SBOM job. The SBOM is not yet attached to the GitHub
  release itself; that is blocked on a shared mecmcp workflow landing and
  will follow in a separate change.

- **Re-pinned the `mecmcp-*` crates from `v0.25.0` to `v0.26.0`** (MEC-1236).
  Brings in mecmcp's `Profile` extension hooks for vendor-specific redaction
  rules and a fix for a reachable panic in `mecmcp-redact`'s text redaction
  path. No behavior change in this server; this crate's existing
  denylist-driven redaction coverage already subsumed the local
  Mist-specific rules removed in #147.

### Added

- **Threat model and token-role guidance docs** (#120). `docs/THREAT_MODEL.md`
  documents trust boundaries, security principals, and the blast radius of a
  compromised MCP token, compromised Mist API token, or compromised agent
  against a real Mist org, plus mitigations in place vs. planned.
  `docs/TOKEN_ROLE_GUIDANCE.md` recommends a dedicated, least-privilege Mist
  organization API token over a personal or super-admin token.

### Changed

- **Re-pinned the `mecmcp-*` crates from `v0.23.0` to `v0.24.1`** (MEC-408,
  closes #116). Brings in mecmcp#383 (the human-approver gate:
  `ChangesetCoordinator::approve_change_set` now takes an
  `approver_actor_type: mecmcp_audit::ActorType` and refuses anything but
  `Human`) and mecmcp#395 (`LimitsConfig::default()` now rate-limits by
  default). `mecmcp-transport`'s `test_harness`/`test_client` moved behind a
  `test-util` feature (mecmcp#387); this server's dev-dependency now enables
  it.
- **`approve_mist_change_set` now routes through mecmcp's
  `ChangesetCoordinator::approve_change_set`** instead of writing approval
  state itself. A change set cannot commit until a human-actor-type approver
  echoes back the exact `plan_digest`; an agent or unattributed (stdio)
  caller is refused, and a mismatched digest is refused. `approve_mist_change_set`
  gained a required `plan_digest` argument for this.
- **`--lab-mode` now refuses to start on a non-loopback listener.** Lab mode
  waives the approval gate for every caller that reaches the listener, so it
  is refused fast at startup unless `--host` resolves to loopback
  (`127.0.0.0/8` or `::1`).
- **Container images now publish to `ghcr.io/mechubsec/rustmistmcp`** —
  the repo moved to the mechubsec organization, and images are renamed to
  match. Older tags were copied from the previous name.

### Fixed

- **Stale "read-only" server instructions and dev-guidance wording** (#120).
  The MCP `get_info` instructions string and `CLAUDE.md`'s cloud-control-plane
  guidance called this server read-only after the batch-1 WAN edge
  change-set write lifecycle had already landed. Both now describe the
  plan → approve → apply mutation path.

## [0.3.2] - 2026-09-24

### Added

- **"Did you mean" suggestions for unknown operation IDs** (#99, closes #96).
  An operation ID not in the catalog now returns up to three similar real IDs
  (e.g. `listOrgInventory` -> `getOrgInventory`), and says when a suggestion
  needs a different dispatcher. Nonsense IDs get no suggestions; the threshold
  and cap keep this from becoming an enumeration aid.

### Fixed

- **Response-schema validation no longer rejects real Mist responses** (#100,
  #102, #95). Three vendor-drift cases captured from the live API on
  2026-09-22, each relaxed for *responses only* — requests stay strict:
  - `searchOrgInventory` / `searchOrgDevices` return fractional epoch seconds
    where the spec declares `integer`; responses now accept `number`.
  - `getOrgStats` declares 15 required properties but Mist never sends
    `orggroup_ids`; `required` is dropped for responses.
  - `searchOrgDevices` failed on any non-empty result: removing enum
    constraints erased the `type` discriminator between `oneOf` branches, so
    records matched several. Responses now use `anyOf`.
- **Validation errors name the failing field** (#98, #95). Messages include the
  field path, expected type, and actual value, capped at five errors.
- **`get_mist_operation_schema` describes any catalog operation** (#98, #97).
  Introspection no longer requires the execution grant; tool-level
  authorization still applies.
- **Scope errors say what is actually wrong** (#98, #97). `list_mist_wan_edges`
  given only a `site_id` no longer reports "organization is not configured or
  authorized"; org-not-allowlisted, unknown site, and site-in-unconfigured-org
  are now distinct. `invoke_mist_read`'s description documents that `path` and
  `query` are maps.

### Changed

- **MSRV raised to 1.89** (#94) — family-wide decision.
- Build toolchain 1.98.0 -> 1.98.1 in full (#103): Dockerfile, release
  workflow, OCI smoke script, `rust-toolchain.toml`.
- `clap` 4.6.6 -> 4.6.7, `rustix` 1.1.4 -> 1.1.5; CI actions
  `docker/setup-qemu-action` 4.4.0, `docker/setup-buildx-action` 4.4.1,
  `docker/build-push-action` 7.4.0.


## [0.3.1] - 2026-09-16

### Security

- **rustls 0.23.45, closing RUSTSEC-2026-0285** (#85). TLS 1.3 handshake
  messages accepted across encryption-level boundaries, medium severity, CVSS
  5.3. This server was on 0.23.44, which was still vulnerable. Lockfile-only
  change to 0.23.45, which contains the fix.

### Fixed

- **Audit flags moved to ENTRYPOINT so they cannot be silently lost** (#84).
  Docker replaces CMD entirely when arguments are supplied, but appends to
  ENTRYPOINT. The image carried audit configuration in CMD, so any real
  deployment — which must override `--host` to expose the port — silently lost
  the audit format, redaction rules, and HMAC key. The container started and
  served normally with no indication that the audit log was unkeyed and
  unredacted.
  
  The image now splits CMD and ENTRYPOINT: ENTRYPOINT holds config paths,
  credentials, and security-relevant flags (device-mapping, tokens-file,
  audit-format, audit-redact, audit-hmac-key-file); CMD holds only
  operator-tunable flags (transport, host, port). Operators passing `--host`
  overrides now retain audit configuration. A CI regression test asserts the
  resulting argv contains all three audit flags after a typical override.

- **Dockerfile trailing newline restored** (#88). The file lost its final
  newline in an earlier edit.

### Changed

- Re-pinned the `mecmcp-*` crates from `v0.21.0` to `v0.23.0` via rmcp
  3.4.0 (#87), which renamed `ServerInfo` to `ServerConfig`. Call sites and
  literals updated accordingly.
- `jsonschema` bumped from 0.52.1 to 0.55.0 (#83).
- `toml` bumped from 1.1.4+spec-1.1.0 to 1.1.5+spec-1.1.0 (#79).
- `docker/setup-qemu-action` bumped from 4.2.0 to 4.3.0 in the release workflow (#80).
- `distroless/cc-debian13:nonroot` base image updated to a newer digest (#86).

### Added

- **Packaging documentation** (#77). Added `docs/HOW-TO-SETUP-LXC.md`, which
  documents how to build a rustmistmcp LXC and how to package a CI binary
  without forging BUILD-INFO, completing the setup guides for both Docker and
  LXC deployment methods.

## [0.3.0] - 2026-09-01

### Changed

- **Systemd unit documentation** (mecmcp#354). Added a comment explaining the
  fleet seccomp posture: `SystemCallErrorNumber=EPERM` returns EPERM rather than
  raising SIGSYS and killing the process mid-request, which is what happened to
  rustunifimcp during a change-set state write (mecmcp#351). An EPERM denial is
  silent at the systemd layer and can become visible only if the application
  stops discarding the errno.

### Added (from RC)

- **An approval now binds the preview it was shown.** mecmcp 0.23.0 adds a v5
  approval digest that carries the stored preview's digest, and this server does
  store a preview, so approvals are signed with v5 rather than v4. An approver
  now vouches for the exact preview they saw, not merely for the plan, and the
  coordinator refuses any later write that swaps or drops that preview.

### Changed

- Re-pinned the `mecmcp-*` crates from `v0.21.0` to `v0.23.0`, spanning two
  minors, and updated the pinned upstream revision in the workspace contract
  test from `dbae2e38` to `d61867d7`.
- The apply takes `claim_change_set_for_apply` instead of writing
  `Approved -> Applying` itself. 0.22.0 made the claim the only legal route onto
  that edge -- it does the read and the write under one lock, so two applies
  cannot both read `Approved` and both issue the write -- and the plain
  `update_change_set` this used is now refused outright. `ApplyHandle::None`,
  because a Mist write is synchronous and returns no pollable handle: a crash
  mid-apply leaves an outcome only the service knows, which is what
  `apply_without_handle` records honestly.
- The drift-detection path claims before settling. It wrote `Approved -> Failed`
  directly, which 0.22.0's transition policy refuses; the refusal was swallowed
  into an audit line, so a drifted change set stayed `Approved` and its stale
  approval remained spendable. It now claims first -- nothing has been sent to
  Mist at that point -- which gives the settle a legal `Applying -> Failed` and
  spends the approval, so a drifted plan cannot be retried. That claim uses
  `ApplyHandle::Expected`, the opposite of the apply path, and for the opposite
  reason: the marker decides how a crash is read back, and on this branch
  nothing was sent, so recovering to `Failed` states the truth. Handleless would
  strand a record known not to have run.
- `ChangeSetRecord` literals carry the new `apply_without_handle` field.
- `jsonschema` bumped from 0.50.1 to 0.51.0.
- `toml` bumped from 0.8.23 to 1.1.4+spec-1.1.0, and the workspace-contract
  test now uses `toml::from_str` instead of `str::parse`, as toml 1.x changed
  the `FromStr` implementation on `Value` to stop after the first table header.

### Performance

- **Compiled JSON Schema validators are now cached** (#59). Request and response
  validation previously compiled the schema on every call — roughly 2.2 MB cloned
  from the components registry, then compiled, then dropped. Measured against the
  pinned catalog (1059 operations, 4.6 MB source):

  | stage | before | after |
  |---|---|---|
  | per call, uncached | 63.25 ms | 1.14 us |
  | first call | ~100 ms | ~100 ms |

  **Per-call validation drops from 63 ms to 1 us**, a ~55,000x speedup for cached
  validators. The catalog is immutable once parsed, so compiled validators are
  memoised. Cache misses race harmlessly: concurrent compilations of the same
  schema may occur, with the first insert winning. Compile failures are not cached,
  keeping catalog defects visible rather than frozen.

  The cache key includes operation name, parameter location and name, and for
  responses both status code and media type, ensuring distinct schemas never
  share a cache entry. This addresses the known issue (#59) noted in v0.2.0.

### Fixed

- **Dependabot no longer attempts to bump the git-pinned mecmcp crates** (#69).
  Weekly cargo runs were failing because dependabot advanced the mecmcp-* refs
  from pinned tags to mecmcp main, but the exact version requirements then
  refused the untagged commits. The mecmcp version is deliberately moved by hand
  in a single chore/mecmcp-<version> PR that re-pins every file at once, so
  dependabot is now configured to ignore those crates.

### Security

- **Moved off the yanked chacha20 0.10.1.** The supply-chain gate went red when
  chacha20 0.10.1 was yanked upstream. This is a transitive dependency through
  `rand -> rmcp -> mecmcp-server`, so nothing here selects it directly. The
  lockfile now pins the compatible 0.10.2 release.

### Upgrading

- **A binary-only rollback to a build pinned at mecmcp v0.21.0 will refuse to
  start once any change set has been approved under this one.** A v5 approval
  forces the change-set state file to schema 6, which the v0.21.0 reader does
  not accept -- correctly, since it cannot verify what it cannot parse. Roll the
  state file back with the binary, or restore a pre-upgrade snapshot.

## [0.2.0] - 2026-08-25

### Added

- **SSDF evidence pipeline** (mecmcp#292). Evidence is attributed to the
  applying request rather than to the change set, and receipts name the
  executor. An ambiguous write is reported as ambiguous, not as a failed
  write.

### Changed

- **The embedded catalog is parsed once instead of twice** (#39). It was
  parsed into a `serde_json::Value` to recompute fingerprints and again into
  the typed document. A 4.6 MB document costs roughly ten times its size as a
  `Value` tree, and glibc does not return that arena when the transient parse
  is dropped, so the cost was permanent resident memory:

  | stage | before | after |
  |---|---|---|
  | after `Catalog::embedded()` | 90.3 MB | 45.3 MB |
  | after `relaxed_components()` | 90.3 MB | 63.4 MB |

  **Resident drops 90.3 MB -> 63.4 MB, a 30% cut.**

  **Fingerprint verification moves from startup to the test gate.** Be precise
  about this: 0.1.1 recomputed every operation's `source_fingerprint` on each
  process start, and 0.2.0 does not — `Catalog::embedded` now uses
  `Fingerprints::Trust`. The check still runs, but under `cargo test` / CI, via
  `catalog_fingerprints_are_verified_for_the_embedded_bytes`, which drives the
  same bytes through the verifying `Catalog::from_json` path. It does **not**
  run at startup or during a plain `cargo build`.

  That trade is sound because `include_str!` freezes the catalog into the
  binary at compile time, so a shipped binary's fingerprints cannot drift — but
  operators should not infer a runtime enforcement that no longer exists.
  `Catalog::from_json`, the entry point for bytes of unknown provenance, still
  verifies every one.

- **`mecmcp` 0.11.0 -> 0.19.0.** That is the jump from the v0.1.1 baseline;
  0.17.0 existed only as an untagged intermediate commit.

### Upgrade note — rolling back needs the state file, not just the binary

`mecmcp-changeset` state carries a schema version. v0.1.1 links 0.11.0, whose
reader accepts **v1-v3 only**. 0.2.0 links 0.19.0, which accepts v1-v4 and
**stamps v4 on any write to a store holding a real approval**.

Once this release has written such a store, reinstalling the 0.1.1 binary alone
will not start — it rejects the file with `unsupported changeset state
version 4`. **Roll back with the Proxmox snapshot**, which restores `/var/lib`
along with the binary.
- `rmcp` 3.1.2 -> 3.1.4.
- Toolchain moved to 1.98.0 in full, not just the Dockerfile.
- `jsonschema` 0.37.4 -> 0.50.0, `getrandom` 0.2 -> 0.4.

### Security

- **Tier-2 hardening.** `tokens.json` migrates to `/var/lib` and the systemd
  unit is hardened.
- **The legacy token store is no longer shadowed by an empty one**, and the
  fallback is restricted to the canonical path. Token paths compare
  byte-for-byte rather than by `Path` equality.
- **An advisory scan never prevents startup.** A scan failure previously took
  the server down.
- Packaging probes real egress enforcement rather than implying it.

### Testing

- **Regression coverage for the audit-capture race**, not a behaviour change.
  `v0.1.1` already carried the global-subscriber/thread-local-writer
  implementation; the added guard pins it so the race cannot return. Upgrading
  does not change audit behaviour.
- `scripts/test-release-policy.sh` derives the expected version from
  `Cargo.toml` instead of hardcoding it. It had been pinned to `v0.1.1`, so
  every version bump silently turned both CI workflows red with "RC tag
  version X does not match Cargo version Y".

### Known

- **#59 — every request and response validation clones the whole components
  registry**, roughly 37 ms and 2.2 MB per call. That is the hot-path half of
  the memory story and is *not* addressed here.
