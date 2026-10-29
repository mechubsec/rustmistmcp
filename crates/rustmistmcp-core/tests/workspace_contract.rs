//! Compile-time workspace-manifest contract for the initial crate boundary.

use std::path::Path;

const WORKSPACE_MANIFEST: &str = include_str!("../../../Cargo.toml");
const CORE_MANIFEST: &str = include_str!("../Cargo.toml");
const SERVER_MANIFEST: &str = include_str!("../../rustmistmcp/Cargo.toml");

/// The commit `MECMCP_TAG` must resolve to. Checked against the lockfile so a
/// moved tag cannot silently change the code this server links.
const MECMCP_REVISION: &str = "8557155ed1ecd24e7ae25948d70485f0fc8c8451";
/// The released tag every shared crate is pinned to.
const MECMCP_TAG: &str = "v0.30.1";
/// Lockfile text, for verifying the tag resolved to `MECMCP_REVISION`.
const LOCKFILE: &str = include_str!("../../../Cargo.lock");

#[test]
fn workspace_metadata_lints_and_shared_revision_are_locked() {
    for expected in [
        "members = [\"crates/rustmistmcp-core\", \"crates/rustmistmcp\"]",
        "default-members = [\"crates/rustmistmcp-core\", \"crates/rustmistmcp\"]",
        "resolver = \"2\"",
        "version = \"0.5.0\"",
        "edition = \"2024\"",
        "rust-version = \"1.89\"",
        "license = \"MIT\"",
        "repository = \"https://github.com/mechubsec/rustmistmcp\"",
        "authors = [\"fastrevmd-lab\"]",
        "missing_docs = \"warn\"",
        "unsafe_code = \"forbid\"",
        "all = { level = \"warn\", priority = -1 }",
        "dbg_macro = \"deny\"",
        "todo = \"deny\"",
        "unwrap_used = \"warn\"",
        "lto = \"thin\"",
        "codegen-units = 1",
        "strip = \"symbols\"",
        // mecmcp#90 closed; #91 has not, and it is the reason the shared CLI
        // still spells the profile flag `--device-mapping`.
        "mecmcp#91 (target-neutral auth scope vocabulary) is the remaining open",
    ] {
        assert!(
            WORKSPACE_MANIFEST.contains(expected),
            "workspace manifest is missing `{expected}`"
        );
    }

    for manifest in [CORE_MANIFEST, SERVER_MANIFEST] {
        for expected in [
            "version.workspace = true",
            "edition.workspace = true",
            "rust-version.workspace = true",
            "license.workspace = true",
            "repository.workspace = true",
            "workspace = true",
        ] {
            assert!(
                manifest.contains(expected),
                "package manifest is missing `{expected}`"
            );
        }
    }

    for source_path in [
        Path::new(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs"),
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../rustmistmcp/src/lib.rs"),
    ] {
        assert!(
            source_path.is_file(),
            "workspace library target must exist at {}",
            source_path.display()
        );
    }

    assert_workspace_mecmcp_dependencies_are_pinned(WORKSPACE_MANIFEST);
}

fn assert_workspace_mecmcp_dependencies_are_pinned(manifest: &str) {
    // `toml::from_str`, not `str::parse`. toml 1.x changed what `FromStr` on
    // `Value` does: it now stops after the first table header and reports
    // "unexpected content, expected nothing" at the byte just past
    // `[workspace]`. The manifest is unchanged and still valid TOML; only the
    // entry point moved.
    let manifest: toml::Value =
        toml::from_str(manifest).expect("workspace manifest must be valid TOML");
    let dependencies = manifest["workspace"]["dependencies"]
        .as_table()
        .expect("workspace manifest must contain [workspace.dependencies]");
    let mecmcp_dependencies: Vec<_> = dependencies
        .iter()
        .filter(|(name, _)| name.starts_with("mecmcp-"))
        .collect();

    assert!(
        !mecmcp_dependencies.is_empty(),
        "workspace must declare at least one shared mecmcp dependency"
    );

    for (crate_name, dependency) in mecmcp_dependencies {
        let dependency = dependency
            .as_table()
            .unwrap_or_else(|| panic!("{crate_name} must use an inline dependency table"));
        assert_eq!(
            dependency.get("git").and_then(toml::Value::as_str),
            Some("https://github.com/mechubsec/mecmcp"),
            "{crate_name} must use the approved mecmcp Git source"
        );

        // Tag, not rev, since the family standardised on tags at v0.9.1 — but a
        // tag can be moved, and the original rev pin existed precisely so
        // extension TypeIds could not diverge. The immutability guarantee is
        // preserved by checking the commit the lockfile actually resolved the
        // tag to, below: readable pin, verified resolution.
        assert_eq!(
            dependency.get("tag").and_then(toml::Value::as_str),
            Some(MECMCP_TAG),
            "{crate_name} must use the shared mecmcp tag"
        );
        assert!(
            LOCKFILE.contains(&format!("?tag={MECMCP_TAG}#{MECMCP_REVISION}")),
            "{crate_name}: the lockfile must resolve {MECMCP_TAG} to {MECMCP_REVISION}; \
             a moved tag would otherwise change the code silently"
        );
    }
}

/// Source of the HTTP client, for the test-only constructor gate below.
const CLIENT_SOURCE: &str = include_str!("../src/client.rs");

/// MEC-61: `HttpMistClient::from_test_parts` skips endpoint validation and
/// HTTPS enforcement, so it must never compile into a normal or release build.
#[test]
fn test_only_constructor_is_gated_out_of_normal_builds() {
    let gate = "#[cfg(any(test, feature = \"test-util\"))]";
    let (before, _) = CLIENT_SOURCE
        .split_once("pub fn from_test_parts(")
        .expect("from_test_parts is gone; delete this contract with it");
    assert!(
        before.trim_end().ends_with(gate),
        "from_test_parts must sit directly under `{gate}`"
    );

    let normal_deps = SERVER_MANIFEST
        .split_once("[dev-dependencies]")
        .map_or(SERVER_MANIFEST, |(normal, _)| normal);
    assert!(
        !normal_deps
            .lines()
            .any(|line| line.contains("rustmistmcp-core") && line.contains("test-util")),
        "the server's normal dependency on rustmistmcp-core must not enable test-util"
    );
    assert!(
        !CORE_MANIFEST
            .lines()
            .any(|line| line.trim_start().starts_with("default") && line.contains("test-util")),
        "test-util must not be a default feature"
    );
}
