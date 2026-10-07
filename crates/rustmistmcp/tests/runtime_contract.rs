//! Runtime composition contracts for the Mist MCP binary.

use axum::http::StatusCode;
use clap::Parser as _;
use mecmcp_auth::{KnownNames, ScopeSet, TokenStoreFile};
use mecmcp_runtime::cli::{Cli, Transport};
use mecmcp_transport::{CallerScopes, LimitsConfig, ScopePreflight as _};
use rustmistmcp::{
    AuthConfig, KNOWN_TOOLS, LIVE_MIST_BLOCKER, MistHandler, MistScopePreflight, RESTRICTED_TOOLS,
    build_http_router, install_token_reload_handler,
};
use rustmistmcp_core::{
    CredentialSource as MistCredentialSource, MistAction, MistConfig, MistGrant, MistTarget,
};
use std::{collections::BTreeMap, fs, path::Path, process::Command, sync::Arc, time::Duration};

const ORG_ID: &str = "11111111-1111-1111-1111-111111111111";
const OTHER_ORG_ID: &str = "99999999-9999-9999-9999-999999999999";

#[test]
fn upstream_token_commands_now_used() {
    // The mist_token_cmd.rs adapter was deleted per the migration task
    assert!(!Path::new("crates/rustmistmcp/src/mist_token_cmd.rs").exists());
}

fn parse_cli(args: &[&str]) -> Cli {
    Cli::parse_from(std::iter::once("rustmistmcp").chain(args.iter().copied()))
}

fn handler() -> MistHandler {
    MistHandler::blocked(
        "https://api.mist.com/",
        vec![ORG_ID.to_owned()],
        BTreeMap::new(),
    )
    .expect("valid blocked handler")
}

fn privileged_grant() -> MistGrant {
    MistGrant {
        allowed_operations: vec!["getSelf".to_owned()],
        actions: vec![MistAction::PrivilegedRead],
        subjects: vec![MistTarget::org(ORG_ID).expect("target")],
    }
}

fn add_grant_bearing_token(path: &Path, name: &str, grant: MistGrant) {
    let known = KnownNames {
        devices: None,
        tools: KNOWN_TOOLS,
    };
    TokenStoreFile::<MistGrant>::add_with_options(
        path,
        name,
        ScopeSet::Allowlist(vec![format!("org/{ORG_ID}")]),
        ScopeSet::Allowlist(vec!["get_mist_self".to_owned()]),
        None,
        Some(grant),
        None,
        None,
        None,
        None,
        &known,
    )
    .expect("grant-bearing token");
}

async fn post_mcp(
    client: &reqwest::Client,
    base_url: &str,
    session: Option<&str>,
    body: serde_json::Value,
) -> reqwest::Response {
    let mut request = client
        .post(format!("{base_url}/mcp"))
        .header(axum::http::header::HOST, "localhost")
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .header(
            axum::http::header::ACCEPT,
            "application/json, text/event-stream",
        )
        .header("Mcp-Protocol-Version", "2025-06-18");
    if let Some(session) = session {
        request = request.header("mcp-session-id", session);
    }
    request.json(&body).send().await.expect("protocol request")
}

async fn response_json(response: reqwest::Response) -> serde_json::Value {
    let text = response.text().await.expect("response body");
    text.lines()
        .filter_map(|line| line.strip_prefix("data:"))
        .filter_map(|data| serde_json::from_str(data.trim()).ok())
        .find(|value: &serde_json::Value| value.get("id").is_some())
        .unwrap_or_else(|| panic!("missing JSON-RPC response in {text}"))
}

async fn initialize_no_auth_session(client: &reqwest::Client, base_url: &str) -> String {
    let response = post_mcp(
        client,
        base_url,
        None,
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "runtime-contract", "version": "1"}
            }
        }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let session = response
        .headers()
        .get("mcp-session-id")
        .expect("session id")
        .to_str()
        .expect("session str")
        .to_owned();
    let initialized = response_json(response).await;
    assert_eq!(initialized["id"], 1);

    let notification = post_mcp(
        client,
        base_url,
        Some(&session),
        serde_json::json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        }),
    )
    .await;
    assert_eq!(notification.status(), StatusCode::ACCEPTED);
    session
}

#[test]
fn remote_listener_requires_explicit_host_and_origin_policies() {
    // The new validator requires --allow-insecure-bind for 0.0.0.0 listeners
    let missing_insecure_bind = parse_cli(&[
        "--transport",
        "streamable-http",
        "--host",
        "0.0.0.0",
        "--tokens-file",
        "/etc/rustmistmcp/tokens.json",
    ]);
    assert!(
        mecmcp_runtime::cli_validate::validate(&missing_insecure_bind).is_err(),
        "should reject 0.0.0.0 without --allow-insecure-bind"
    );

    let missing_origin = parse_cli(&[
        "--transport",
        "streamable-http",
        "--host",
        "0.0.0.0",
        "--tokens-file",
        "/etc/rustmistmcp/tokens.json",
        "--allow-insecure-bind",
        "--allowed-host",
        "mist.example.test",
    ]);
    assert!(
        mecmcp_runtime::cli_validate::validate(&missing_origin).is_err(),
        "should reject missing --allowed-origin with --allow-insecure-bind"
    );

    let strict_remote = parse_cli(&[
        "--transport",
        "streamable-http",
        "--host",
        "0.0.0.0",
        "--tokens-file",
        "/etc/rustmistmcp/tokens.json",
        "--allow-insecure-bind",
        "--allowed-host",
        "mist.example.test",
        "--allowed-origin",
        "https://client.example.test",
    ]);
    mecmcp_runtime::cli_validate::validate(&strict_remote)
        .expect("strict remote listener with --allow-insecure-bind");

    // Loopback listeners bypass the requirement
    let loopback = parse_cli(&[
        "--transport",
        "streamable-http",
        "--host",
        "127.0.0.1",
        "--tokens-file",
        "/etc/rustmistmcp/tokens.json",
    ]);
    mecmcp_runtime::cli_validate::validate(&loopback).expect("loopback listener");
}

#[test]
fn listener_validation_allows_insecure_bind_bypass() {
    // The new validator still requires --allowed-host even with --allow-insecure-bind
    let insecure_bind_missing_host = parse_cli(&[
        "--transport",
        "streamable-http",
        "--host",
        "0.0.0.0",
        "--tokens-file",
        "/etc/rustmistmcp/tokens.json",
        "--allow-insecure-bind",
    ]);
    assert!(
        mecmcp_runtime::cli_validate::validate(&insecure_bind_missing_host).is_err(),
        "should still require --allowed-host with --allow-insecure-bind"
    );

    // Both flags are needed for 0.0.0.0
    let insecure_bind = parse_cli(&[
        "--transport",
        "streamable-http",
        "--host",
        "0.0.0.0",
        "--tokens-file",
        "/etc/rustmistmcp/tokens.json",
        "--allow-insecure-bind",
        "--allowed-host",
        "mist.example.test",
        "--allowed-origin",
        "https://client.example.test",
    ]);
    mecmcp_runtime::cli_validate::validate(&insecure_bind)
        .expect("allow-insecure-bind with host and origin");
}

#[test]
fn mist_preflight_translates_org_and_site_arguments_to_canonical_targets() {
    let preflight = MistScopePreflight::new(RESTRICTED_TOOLS);
    let target = format!("org/{ORG_ID}");
    let devices = ScopeSet::Allowlist(vec![target]);
    let tools = ScopeSet::Allowlist(vec!["get_mist_org".to_owned()]);
    let caller = CallerScopes {
        token_name: "operator",
        devices: &devices,
        tools: &tools,
    };
    let permitted = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "get_mist_org",
            "arguments": {"org_id": ORG_ID}
        }
    });
    preflight
        .check(
            &serde_json::to_vec(&permitted).expect("request"),
            caller.clone(),
        )
        .expect("canonical org scope permits raw org argument");

    let denied = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "get_mist_org",
            "arguments": {"org_id": OTHER_ORG_ID}
        }
    });
    assert_eq!(
        preflight.check(
            &serde_json::to_vec(&denied).expect("request"),
            caller.clone()
        ),
        Err("insufficient_scope".to_owned())
    );

    let site_devices =
        ScopeSet::Allowlist(vec!["site/22222222-2222-2222-2222-222222222222".to_owned()]);
    let site_tools = ScopeSet::Allowlist(vec!["get_mist_site".to_owned()]);
    let site_caller = CallerScopes {
        token_name: "site-operator",
        devices: &site_devices,
        tools: &site_tools,
    };
    let permitted_site = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "get_mist_site",
            "arguments": {"site_id": "22222222-2222-2222-2222-222222222222"}
        }
    });
    preflight
        .check(
            &serde_json::to_vec(&permitted_site).expect("request"),
            site_caller.clone(),
        )
        .expect("canonical site scope permits raw site argument");
    let denied_site = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/call",
        "params": {
            "name": "get_mist_site",
            "arguments": {"site_id": "33333333-3333-3333-3333-333333333333"}
        }
    });
    assert_eq!(
        preflight.check(
            &serde_json::to_vec(&denied_site).expect("request"),
            site_caller.clone()
        ),
        Err("insufficient_scope".to_owned())
    );

    let dispatcher_tools = ScopeSet::Allowlist(vec!["invoke_mist_read".to_owned()]);
    let dispatcher_caller = CallerScopes {
        token_name: "dispatcher",
        devices: &devices,
        tools: &dispatcher_tools,
    };
    let nested_path_denied = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 5,
        "method": "tools/call",
        "params": {
            "name": "invoke_mist_read",
            "arguments": {
                "operation_id": "getOrg",
                "path": {"org_id": OTHER_ORG_ID},
                "query": {}
            }
        }
    });
    assert_eq!(
        preflight.check(
            &serde_json::to_vec(&nested_path_denied).expect("request"),
            dispatcher_caller
        ),
        Err("insufficient_scope".to_owned())
    );
}

#[test]
fn wildcard_tool_scope_excludes_restricted_reads_at_preflight() {
    let preflight = MistScopePreflight::new(RESTRICTED_TOOLS);
    let devices = ScopeSet::Wildcard;
    let tools = ScopeSet::Wildcard;
    let caller = CallerScopes {
        token_name: "readonly-wildcard",
        devices: &devices,
        tools: &tools,
    };
    let restricted = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "get_mist_self", "arguments": {}}
    });
    assert_eq!(
        preflight.check(
            &serde_json::to_vec(&restricted).expect("request"),
            caller.clone()
        ),
        Err("insufficient_scope".to_owned())
    );
}

#[test]
fn mist_preflight_denies_every_malformed_org_and_site_shape() {
    let preflight = MistScopePreflight::new(RESTRICTED_TOOLS);
    let devices = ScopeSet::Allowlist(vec!["site/22222222-2222-2222-2222-222222222222".to_owned()]);
    let tools = ScopeSet::Allowlist(vec!["invoke_mist_read".to_owned()]);
    let caller = CallerScopes {
        token_name: "malformed-targets",
        devices: &devices,
        tools: &tools,
    };
    let malformed_arguments = [
        serde_json::json!([]),
        serde_json::json!({"path": []}),
        serde_json::json!({"query": 7}),
        serde_json::json!({"org_id": 7}),
        serde_json::json!({"org_id": "not-a-uuid"}),
        serde_json::json!({"site_id": false}),
        serde_json::json!({"site_id": "33333333-3333-3333-3333-333333333333"}),
        serde_json::json!({"path": {"site_id": "not-a-uuid"}}),
        serde_json::json!({"query": {"site_id": ["not", "scalar"]}}),
    ];
    for arguments in malformed_arguments {
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "invoke_mist_read",
                "arguments": arguments
            }
        });
        assert_eq!(
            preflight.check(
                &serde_json::to_vec(&request).expect("request"),
                caller.clone()
            ),
            Err("insufficient_scope".to_owned()),
            "{request}"
        );
    }
}

#[tokio::test]
async fn authenticated_router_uses_strict_bearer_syntax_and_scope_preflight() {
    // Install crypto provider for reqwest
    let _ = rustls::crypto::ring::default_provider().install_default();

    let dir = tempfile::tempdir().expect("temporary directory");
    let path = dir.path().join("tokens.json");
    let known = KnownNames {
        devices: None,
        tools: KNOWN_TOOLS,
    };
    let secret = TokenStoreFile::<MistGrant>::add(
        &path,
        "operator",
        ScopeSet::Allowlist(vec![format!("org/{ORG_ID}")]),
        ScopeSet::Allowlist(vec!["get_mist_org".to_owned()]),
        &known,
    )
    .expect("token");
    let store = Arc::new(TokenStoreFile::<MistGrant>::load(&path).expect("token store"));
    let shutdown = tokio_util::sync::CancellationToken::new();
    let plan = build_http_router(
        handler(),
        AuthConfig::Authenticated(store),
        Vec::new(),
        Vec::new(),
        LimitsConfig::default(),
        false,
        false, // allow_insecure_bind: tests bind loopback, which is exempt
        shutdown,
    )
    .expect("HTTP router");

    let served = mecmcp_transport::test_harness::serve_on_loopback(plan).await;
    let base_url = format!("http://{}", served.address);

    let body = serde_json::to_string(&serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "get_mist_org",
            "arguments": {"org_id": OTHER_ORG_ID}
        }
    }))
    .expect("serialize body");

    let client = reqwest::Client::new();
    let missing = client
        .post(format!("{base_url}/mcp"))
        .header(axum::http::header::HOST, "localhost")
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .header(
            axum::http::header::ACCEPT,
            "application/json, text/event-stream",
        )
        .header("Mcp-Protocol-Version", "2025-06-18")
        .body(body.clone())
        .send()
        .await
        .expect("request");
    assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);

    let malformed = client
        .post(format!("{base_url}/mcp"))
        .header(axum::http::header::HOST, "localhost")
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .header(
            axum::http::header::ACCEPT,
            "application/json, text/event-stream",
        )
        .header("Mcp-Protocol-Version", "2025-06-18")
        .header(
            axum::http::header::AUTHORIZATION,
            // NOT a leading space. This test previously sent " Bearer <secret>",
            // which strict syntax rejects because the empty scheme before the
            // space is not "bearer". That malformation is unrepresentable over
            // real HTTP — the space after the colon is the standard separator
            // and the protocol normalizes it away, so the header arrives valid,
            // authenticates, and fails on scope with 403 instead.
            //
            // A wrong scheme survives the wire and exercises the same strict
            // rejection path, so it is what this asserts now.
            format!("NotBearer {}", secret.expose_secret()),
        )
        .body(body.clone())
        .send()
        .await
        .expect("request");
    assert_eq!(malformed.status(), StatusCode::UNAUTHORIZED);

    let out_of_scope = client
        .post(format!("{base_url}/mcp"))
        .header(axum::http::header::HOST, "localhost")
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .header(
            axum::http::header::ACCEPT,
            "application/json, text/event-stream",
        )
        .header("Mcp-Protocol-Version", "2025-06-18")
        .header(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {}", secret.expose_secret()),
        )
        .body(body)
        .send()
        .await
        .expect("request");
    assert_eq!(out_of_scope.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        out_of_scope
            .headers()
            .get(axum::http::header::WWW_AUTHENTICATE)
            .expect("challenge")
            .to_str()
            .expect("header str"),
        r#"Bearer realm="rustmistmcp", error="insufficient_scope""#
    );
}

#[tokio::test]
async fn unauthenticated_loopback_http_exposes_only_ordinary_tools_and_denies_restricted_calls() {
    // Install crypto provider for reqwest
    let _ = rustls::crypto::ring::default_provider().install_default();

    let shutdown = tokio_util::sync::CancellationToken::new();
    let plan = build_http_router(
        handler(),
        AuthConfig::ExplicitlyUnauthenticated,
        Vec::new(),
        Vec::new(),
        LimitsConfig::default(),
        false,
        false, // allow_insecure_bind: tests bind loopback, which is exempt
        shutdown,
    )
    .expect("HTTP router");

    let served = mecmcp_transport::test_harness::serve_on_loopback(plan).await;
    let base_url = format!("http://{}", served.address);

    let client = reqwest::Client::new();
    let session = initialize_no_auth_session(&client, &base_url).await;

    let list = response_json(
        post_mcp(
            &client,
            &base_url,
            Some(&session),
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/list",
                "params": {}
            }),
        )
        .await,
    )
    .await;
    let names = list["result"]["tools"]
        .as_array()
        .expect("tool list")
        .iter()
        .filter_map(|tool| tool["name"].as_str())
        .collect::<Vec<_>>();
    assert!(names.contains(&"invoke_mist_read"));
    for restricted in RESTRICTED_TOOLS {
        assert!(!names.contains(restricted), "{restricted} must be hidden");
    }

    let ordinary = response_json(
        post_mcp(
            &client,
            &base_url,
            Some(&session),
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "search_mist_operations",
                    "arguments": {"query": "org", "limit": 1}
                }
            }),
        )
        .await,
    )
    .await;
    assert_ne!(ordinary["result"]["isError"], true, "{ordinary}");

    let restricted = response_json(
        post_mcp(
            &client,
            &base_url,
            Some(&session),
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {"name": "get_mist_self", "arguments": {}}
            }),
        )
        .await,
    )
    .await;
    assert_eq!(restricted["result"]["isError"], true, "{restricted}");
    assert!(
        restricted
            .to_string()
            .contains("authenticated caller context"),
        "{restricted}"
    );
}

#[test]
fn token_add_is_local_and_its_file_loads_as_a_mist_grant_store() {
    let dir = tempfile::tempdir().expect("temporary directory");
    let tokens = dir.path().join("tokens.json");
    let missing_config = dir.path().join("must-not-be-read.json");
    let output = Command::new(env!("CARGO_BIN_EXE_rustmistmcp"))
        .args([
            "--device-mapping",
            missing_config.to_str().expect("UTF-8 path"),
            "token",
            "add",
            "--tokens-file",
            tokens.to_str().expect("UTF-8 path"),
            "--name",
            "local-operator",
            "--devices",
            &format!("org/{ORG_ID}"),
            "--tools",
            "get_mist_org",
        ])
        .output()
        .expect("run token command");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!output.stdout.is_empty(), "one-time secret is printed");
    assert!(!missing_config.exists(), "Mist config was not contacted");

    let store = TokenStoreFile::<MistGrant>::load(&tokens).expect("Mist grant token store");
    assert_eq!(store.store().len(), 1);
    assert_eq!(
        store.store().entries()[0].devices,
        ScopeSet::Allowlist(vec![format!("org/{ORG_ID}")])
    );

    let listed = Command::new(env!("CARGO_BIN_EXE_rustmistmcp"))
        .args([
            "token",
            "list",
            "--tokens-file",
            tokens.to_str().expect("UTF-8 path"),
        ])
        .output()
        .expect("list grantless store");
    assert!(
        listed.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&listed.stderr)
    );
    assert!(String::from_utf8_lossy(&listed.stdout).contains("local-operator"));
}

#[test]
fn token_management_accepts_relative_paths_per_upstream() {
    // `token_cmd::run_with_grant` accepts relative paths. Path validation is
    // mecmcp's responsibility now, so this asserts the upstream behaviour
    // rather than one upstream version's behaviour.
    let dir = tempfile::tempdir().expect("temporary directory");
    let output = Command::new(env!("CARGO_BIN_EXE_rustmistmcp"))
        .current_dir(dir.path())
        .args([
            "token",
            "add",
            "--tokens-file",
            "tokens.json",
            "--name",
            "relative-path",
            "--devices",
            &format!("org/{ORG_ID}"),
            "--tools",
            "get_mist_org",
        ])
        .output()
        .expect("run token command");
    assert!(
        output.status.success(),
        "token add should succeed with a relative path, per upstream mecmcp"
    );
    assert!(dir.path().join("tokens.json").exists());
}

#[test]
fn grant_bearing_token_lifecycle_preserves_mist_authority() {
    let dir = tempfile::tempdir().expect("temporary directory");
    let tokens = dir.path().join("tokens.json");
    let grant = privileged_grant();
    add_grant_bearing_token(&tokens, "privileged", grant.clone());
    add_grant_bearing_token(&tokens, "survivor", grant.clone());

    let listed = Command::new(env!("CARGO_BIN_EXE_rustmistmcp"))
        .args([
            "token",
            "list",
            "--tokens-file",
            tokens.to_str().expect("UTF-8 path"),
        ])
        .output()
        .expect("run token list");
    assert!(
        listed.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&listed.stderr)
    );
    let stdout = String::from_utf8_lossy(&listed.stdout);
    assert!(stdout.contains("privileged"), "{stdout}");
    assert!(stdout.contains("survivor"), "{stdout}");
    assert!(!stdout.contains("allowed_operations"), "{stdout}");

    let before = TokenStoreFile::<MistGrant>::load(&tokens).expect("token store");
    let before_digest = before
        .store()
        .entries()
        .iter()
        .find(|entry| entry.name == "privileged")
        .expect("privileged token")
        .digest
        .clone();

    let rotated = Command::new(env!("CARGO_BIN_EXE_rustmistmcp"))
        .args([
            "token",
            "rotate",
            "--tokens-file",
            tokens.to_str().expect("UTF-8 path"),
            "--name",
            "privileged",
        ])
        .output()
        .expect("run token rotate");
    assert!(
        rotated.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&rotated.stderr)
    );
    assert!(!rotated.stdout.is_empty(), "rotated secret is printed once");

    let after_rotate = TokenStoreFile::<MistGrant>::load(&tokens).expect("rotated token store");
    let after_rotate_store = after_rotate.store();
    let privileged = after_rotate_store
        .entries()
        .iter()
        .find(|entry| entry.name == "privileged")
        .expect("privileged token");
    assert_ne!(privileged.digest, before_digest);
    assert_eq!(privileged.grant, Some(grant.clone()));

    let revoked = Command::new(env!("CARGO_BIN_EXE_rustmistmcp"))
        .args([
            "token",
            "revoke",
            "--tokens-file",
            tokens.to_str().expect("UTF-8 path"),
            "--name",
            "privileged",
        ])
        .output()
        .expect("run token revoke");
    assert!(
        revoked.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&revoked.stderr)
    );

    let after_revoke = TokenStoreFile::<MistGrant>::load(&tokens).expect("revoked token store");
    assert!(
        after_revoke
            .store()
            .entries()
            .iter()
            .all(|entry| entry.name != "privileged")
    );
    let after_revoke_store = after_revoke.store();
    let survivor = after_revoke_store
        .entries()
        .iter()
        .find(|entry| entry.name == "survivor")
        .expect("surviving token");
    assert_eq!(survivor.grant, Some(grant));
}

#[test]
fn token_add_to_grant_bearing_store_preserves_existing_grant() {
    let dir = tempfile::tempdir().expect("temporary directory");
    let tokens = dir.path().join("tokens.json");
    let grant = privileged_grant();
    add_grant_bearing_token(&tokens, "privileged", grant.clone());

    let added = Command::new(env!("CARGO_BIN_EXE_rustmistmcp"))
        .args([
            "token",
            "add",
            "--tokens-file",
            tokens.to_str().expect("UTF-8 path"),
            "--name",
            "ordinary-reader",
            "--devices",
            &format!("org/{ORG_ID}"),
            "--tools",
            "get_mist_org",
        ])
        .output()
        .expect("run token add");
    assert!(
        added.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&added.stderr)
    );
    assert!(!added.stdout.is_empty(), "one-time secret is printed");

    let store = TokenStoreFile::<MistGrant>::load(&tokens).expect("token store");
    let token_store = store.store();
    let privileged = token_store
        .entries()
        .iter()
        .find(|entry| entry.name == "privileged")
        .expect("privileged token");
    let ordinary = token_store
        .entries()
        .iter()
        .find(|entry| entry.name == "ordinary-reader")
        .expect("ordinary token");
    assert_eq!(privileged.grant, Some(grant));
    assert_eq!(ordinary.grant, None);
}

#[test]
fn unknown_mist_grant_field_is_refused_without_rewrite() {
    let dir = tempfile::tempdir().expect("temporary directory");
    let tokens = dir.path().join("tokens.json");
    add_grant_bearing_token(&tokens, "privileged", privileged_grant());

    let raw = fs::read_to_string(&tokens).expect("token document");
    let mut document: serde_json::Value = serde_json::from_str(&raw).expect("token document JSON");
    document["tokens"][0]["grant"]
        .as_object_mut()
        .expect("grant object")
        .insert(
            "future_restriction".to_owned(),
            serde_json::json!({"maximum_targets": 1}),
        );
    let doctored = serde_json::to_string_pretty(&document).expect("doctored JSON");
    fs::write(&tokens, &doctored).expect("write doctored token document");

    let output = Command::new(env!("CARGO_BIN_EXE_rustmistmcp"))
        .args([
            "token",
            "list",
            "--tokens-file",
            tokens.to_str().expect("UTF-8 path"),
        ])
        .output()
        .expect("run token list");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("unknown field"), "{stderr}");
    assert!(stderr.contains("future_restriction"), "{stderr}");
    assert_eq!(
        fs::read_to_string(&tokens).expect("unchanged token document"),
        doctored
    );
}

#[cfg(unix)]
#[test]
fn invalid_token_reload_pid_preserves_shared_post_write_behavior() {
    let dir = tempfile::tempdir().expect("temporary directory");
    let tokens = dir.path().join("tokens.json");

    let output = Command::new(env!("CARGO_BIN_EXE_rustmistmcp"))
        .args([
            "token",
            "add",
            "--tokens-file",
            tokens.to_str().expect("UTF-8 path"),
            "--name",
            "written-before-signal",
            "--devices",
            &format!("org/{ORG_ID}"),
            "--tools",
            "get_mist_org",
            "--server-pid",
            "0",
        ])
        .output()
        .expect("run token add");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("server PID must be positive"));

    let store = TokenStoreFile::<MistGrant>::load(&tokens).expect("written token store");
    assert!(
        store
            .store()
            .entries()
            .iter()
            .any(|entry| entry.name == "written-before-signal"),
        "the shared contract writes atomically before requesting reload"
    );
}

#[test]
fn token_adapter_preserves_shared_wildcard_scope_refusal() {
    let dir = tempfile::tempdir().expect("temporary directory");
    let tokens = dir.path().join("tokens.json");
    let mixed = format!("*,org/{ORG_ID}");

    let output = Command::new(env!("CARGO_BIN_EXE_rustmistmcp"))
        .args([
            "token",
            "add",
            "--tokens-file",
            tokens.to_str().expect("UTF-8 path"),
            "--name",
            "mixed-scope",
            "--devices",
            &mixed,
            "--tools",
            "get_mist_org",
        ])
        .output()
        .expect("run token add");
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("invalid devices scope: '*' cannot be mixed with exact names")
    );
    assert!(!tokens.exists());
}

#[cfg(unix)]
#[tokio::test]
async fn sighup_reloads_only_a_valid_token_snapshot() {
    let dir = tempfile::tempdir().expect("temporary directory");
    let path = dir.path().join("tokens.json");
    let known = KnownNames {
        devices: None,
        tools: KNOWN_TOOLS,
    };
    TokenStoreFile::<MistGrant>::add(
        &path,
        "first",
        ScopeSet::Wildcard,
        ScopeSet::Allowlist(vec!["get_mist_org".to_owned()]),
        &known,
    )
    .expect("first token");
    let store = Arc::new(TokenStoreFile::<MistGrant>::load(&path).expect("token store"));
    install_token_reload_handler(store.clone()).expect("SIGHUP handler");

    TokenStoreFile::<MistGrant>::add(
        &path,
        "second",
        ScopeSet::Wildcard,
        ScopeSet::Allowlist(vec!["get_mist_org".to_owned()]),
        &known,
    )
    .expect("second token");
    send_hup();
    wait_for_store_len(&store, 2).await;

    fs::write(&path, b"{not valid json").expect("corrupt token file");
    send_hup();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        store.store().len(),
        2,
        "failed reload retains the last valid snapshot"
    );
}

#[cfg(unix)]
fn send_hup() {
    let pid = rustix::process::Pid::from_raw(std::process::id() as i32).expect("positive pid");
    rustix::process::kill_process(pid, rustix::process::Signal::HUP).expect("send SIGHUP");
}

#[cfg(unix)]
async fn wait_for_store_len(store: &TokenStoreFile<MistGrant>, expected: usize) {
    for _ in 0..50 {
        if store.store().len() == expected {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("token snapshot did not reload to {expected} entries");
}

#[test]
fn example_uses_absolute_operator_paths_and_runtime_is_honest_about_blockers() {
    let raw = include_str!("../../../examples/mist.example.json");
    let config: MistConfig = serde_json::from_str(raw).expect("strict example schema");
    assert_eq!(config.version, 1);
    let MistCredentialSource::File { path } = &config.credential else {
        panic!("example config must use a file credential source");
    };
    assert!(path.is_absolute());
    assert_eq!(path.to_string_lossy(), "/etc/rustmistmcp/mist-api-token");
    // The blocker names the credential, not `mecmcp#90` — that foundation
    // landed, and citing a closed issue would misreport why a call refused.
    assert!(!LIVE_MIST_BLOCKER.contains("mecmcp#90"));
    assert!(LIVE_MIST_BLOCKER.contains("credential"));
    assert!(LIVE_MIST_BLOCKER.contains("/api/v1/self"));
    // Change-set write tools now exist (plan_mist_change and its apply path),
    // even though mecmcp#90 (live outbound Mist client) remains open. The
    // coordinator-gated lifecycle works without a production Mist client.
    assert!(KNOWN_TOOLS.contains(&"plan_mist_change"));
}

#[test]
fn binary_help_preserves_the_shared_runtime_flag_names() {
    let output = Command::new(env!("CARGO_BIN_EXE_rustmistmcp"))
        .arg("--help")
        .output()
        .expect("run --help");
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).expect("UTF-8 help");
    for flag in [
        "--device-mapping",
        "--transport",
        "--tokens-file",
        "--tls-cert",
        "--tls-key",
        "--allowed-host",
        "--allowed-origin",
        "--audit-journald",
    ] {
        assert!(help.contains(flag), "missing shared flag {flag}");
    }
    assert!(help.contains("streamable-http"));
    assert_eq!(parse_cli(&[]).transport, Transport::Stdio);
}

#[test]
fn binary_reports_its_own_name_and_version() {
    // The shared `Cli` carries no version of its own, so parsing it directly
    // made `--version` exit 2. `cli::parse_for` supplies the consumer's
    // identity; release verification used to need hashes because of that gap.
    let output = Command::new(env!("CARGO_BIN_EXE_rustmistmcp"))
        .arg("--version")
        .output()
        .expect("run --version");
    assert!(
        output.status.success(),
        "--version exited {:?}: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    let reported = String::from_utf8(output.stdout).expect("UTF-8 version");
    assert!(
        reported.contains("rustmistmcp"),
        "--version must name the binary, got {reported:?}"
    );
    assert!(
        reported.contains(env!("CARGO_PKG_VERSION")),
        "--version must report {}, got {reported:?}",
        env!("CARGO_PKG_VERSION")
    );
}

/// `--allow-insecure-bind` must reach the transport.
///
/// Regression test for the wiring gap that took the sibling Junos server's
/// production host (LXC 950) down during its 0.20.0 upgrade: the flag was
/// parsed and shown in `--help`, but never converted into an
/// `InsecureBindAcknowledgement`, so mecmcp 0.9.x refused a plaintext
/// off-loopback listener the operator had explicitly asked for.
///
/// Latent in this server — every deployment binds loopback, which is exempt
/// from all four admission checks — so only a test keeps it fixed.
///
/// Three properties make this prove something, each learned by getting the
/// equivalent test wrong first in the sibling repos:
///   * an AUTHENTICATED store, because `UnauthenticatedOffLoopback` is checked
///     before the insecure-bind branch and would otherwise mask it entirely;
///   * a NON-loopback address, because loopback short-circuits every check;
///   * an assertion on `InsecureBindNotAcknowledged` specifically rather than
///     on `Refused` in general.
///
/// Verified by sabotage: remove the conversion in `build_http_router` and this
/// fails; restore it and it passes.
#[tokio::test]
async fn insecure_bind_acknowledgement_reaches_the_transport() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("tokens.json");
    let known = KnownNames {
        devices: None,
        tools: KNOWN_TOOLS,
    };
    TokenStoreFile::<MistGrant>::add(
        &path,
        "operator",
        ScopeSet::Allowlist(vec![format!("org/{ORG_ID}")]),
        ScopeSet::Allowlist(vec!["get_mist_org".to_owned()]),
        &known,
    )
    .expect("token");
    let store = Arc::new(TokenStoreFile::<MistGrant>::load(&path).expect("token store"));
    let shutdown = tokio_util::sync::CancellationToken::new();

    let plan = build_http_router(
        handler(),
        AuthConfig::Authenticated(store),
        Vec::new(),
        Vec::new(),
        LimitsConfig::default(),
        false,
        true, // allow_insecure_bind — the flag under test
        shutdown.clone(),
    )
    .expect("router");

    // 192.0.2.1 is TEST-NET-1: non-loopback and unbindable here. A refusal means
    // the acknowledgement never arrived; a bind failure means it did.
    let error = mecmcp_transport::serve_router(
        plan,
        "192.0.2.1:30030".parse().expect("address"),
        None,
        std::time::Duration::from_millis(50),
    )
    .await
    .expect_err("TEST-NET-1 cannot be bound");

    assert!(
        !matches!(
            error,
            mecmcp_transport::HttpServeError::Refused(
                mecmcp_transport::ListenerRefusal::InsecureBindNotAcknowledged { .. }
            )
        ),
        "refused for want of an insecure-bind acknowledgement despite \
         allow_insecure_bind = true, so the flag never reached the transport: {error:?}"
    );
}
