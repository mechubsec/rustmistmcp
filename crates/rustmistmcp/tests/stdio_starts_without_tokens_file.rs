//! A container's `ENTRYPOINT` bakes in a fixed `--tokens-file` path so a
//! manually-run HTTP server always stays protected. stdio must still start
//! when that path has nothing mounted there -- the file protects a bearer
//! listener stdio never opens, so a missing tokens file must not block the
//! MCP handshake (MEC-2121). This also exercises the `env` credential
//! source added for the same issue: a stdio catalog deployment injects the
//! Mist API token as an environment variable, not a mounted file.

use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Server {
    child: Child,
    stdin: std::process::ChildStdin,
    stdout: BufReader<std::process::ChildStdout>,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn send(stdin: &mut impl Write, msg: &Value) {
    let line = serde_json::to_string(msg).expect("serialize request");
    writeln!(stdin, "{line}").expect("write to stdin");
    stdin.flush().expect("flush stdin");
}

/// Reads stdout lines until one parses as a JSON-RPC response with the given
/// `id`, or the deadline passes.
fn read_response(stdout: &mut BufReader<std::process::ChildStdout>, id: i64) -> Value {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        assert!(
            Instant::now() < deadline,
            "no response with id={id} within 15s"
        );
        let mut line = String::new();
        let read = stdout.read_line(&mut line).expect("read stdout");
        assert_ne!(read, 0, "server closed stdout before responding");
        let Ok(value) = serde_json::from_str::<Value>(line.trim()) else {
            continue;
        };
        if value.get("id") == Some(&json!(id)) {
            return value;
        }
    }
}

fn initialize(server: &mut Server) {
    send(
        &mut server.stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "stdio-no-tokens-test", "version": "1"}
            }
        }),
    );
    let response = read_response(&mut server.stdout, 1);
    assert!(
        response.get("error").is_none(),
        "initialize failed: {response:?}"
    );
    send(
        &mut server.stdin,
        &json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
    );
}

#[test]
fn stdio_starts_when_tokens_file_flag_points_to_a_missing_path() {
    let directory = tempfile::tempdir().expect("temp dir");

    let credential_path = directory.path().join("mist-api-token");
    std::fs::write(&credential_path, "not-a-live-token").expect("write credential");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&credential_path, std::fs::Permissions::from_mode(0o600))
            .expect("chmod 0600");
    }

    let profile_path = directory.path().join("mist.json");
    std::fs::write(
        &profile_path,
        serde_json::json!({
            "version": 1,
            "endpoint": "https://api.mist.com/",
            "credential": {"type": "file", "path": credential_path},
            "allowed_orgs": ["11111111-1111-1111-1111-111111111111"]
        })
        .to_string(),
    )
    .expect("write profile");

    let missing_tokens_path = directory.path().join("tokens.json");
    assert!(
        !missing_tokens_path.exists(),
        "tokens path must not exist for this test"
    );

    let mut child = Command::new(env!("CARGO_BIN_EXE_rustmistmcp"))
        .args([
            "--device-mapping",
            profile_path.to_str().expect("profile path is UTF-8"),
            "--transport",
            "stdio",
            "--tokens-file",
            missing_tokens_path.to_str().expect("tokens path is UTF-8"),
            "--site-refresh-interval-secs",
            "0",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn rustmistmcp");

    let stdin = child.stdin.take().expect("stdin was piped");
    let stdout = BufReader::new(child.stdout.take().expect("stdout was piped"));
    let mut server = Server {
        child,
        stdin,
        stdout,
    };

    initialize(&mut server);

    send(
        &mut server.stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {}
        }),
    );
    let response = read_response(&mut server.stdout, 2);
    assert!(
        response.get("error").is_none(),
        "tools/list failed over stdio with no tokens file present: {response:?}"
    );

    assert!(
        !missing_tokens_path.exists(),
        "stdio must not create a bearer-token store"
    );
}

#[test]
fn stdio_starts_with_an_env_credential_and_no_tokens_file() {
    let directory = tempfile::tempdir().expect("temp dir");

    let profile_path = directory.path().join("mist.json");
    std::fs::write(
        &profile_path,
        serde_json::json!({
            "version": 1,
            "endpoint": "https://api.mist.com/",
            "credential": {"type": "env", "name": "RUSTMISTMCP_STDIO_TEST_TOKEN"},
            "allowed_orgs": ["11111111-1111-1111-1111-111111111111"]
        })
        .to_string(),
    )
    .expect("write profile");

    let missing_tokens_path = directory.path().join("tokens.json");

    let mut child = Command::new(env!("CARGO_BIN_EXE_rustmistmcp"))
        .args([
            "--device-mapping",
            profile_path.to_str().expect("profile path is UTF-8"),
            "--transport",
            "stdio",
            "--tokens-file",
            missing_tokens_path.to_str().expect("tokens path is UTF-8"),
            "--site-refresh-interval-secs",
            "0",
        ])
        .env("RUSTMISTMCP_STDIO_TEST_TOKEN", "not-a-live-token")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn rustmistmcp");

    let stdin = child.stdin.take().expect("stdin was piped");
    let stdout = BufReader::new(child.stdout.take().expect("stdout was piped"));
    let mut server = Server {
        child,
        stdin,
        stdout,
    };

    initialize(&mut server);

    send(
        &mut server.stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {}
        }),
    );
    let response = read_response(&mut server.stdout, 2);
    assert!(
        response.get("error").is_none(),
        "tools/list failed over stdio with an env credential: {response:?}"
    );
}
