//! Pins the operator-visible text of every startup refusal to the shared
//! validator's wording, by running the real binary. Only a process boundary
//! can observe how `main` renders a refusal. See mecmcp#358.

use std::process::Command;

#[test]
fn shared_refusal_fixtures_match_expected_stderr() {
    use mecmcp_runtime::cli_validate::testing::{expected_stderr, refusal_fixtures};

    for (args, refusal) in refusal_fixtures() {
        let output = Command::new(env!("CARGO_BIN_EXE_rustmistmcp"))
            .args(&args)
            .output()
            .expect("spawn rustmistmcp");
        assert_eq!(output.status.code(), Some(1), "args: {args:?}");
        assert_eq!(
            String::from_utf8_lossy(&output.stderr).trim_end(),
            expected_stderr(&refusal),
            "args: {args:?}"
        );
    }
}
