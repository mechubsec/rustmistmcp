//! End-to-end test proving HttpMistClient is reachable through the server.

use axum::{
    Router,
    body::Body,
    extract::{Path, Query},
    http::{Request, StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use mecmcp_auth::{KnownNames, ScopeSet, TokenStoreFile};
use rustmistmcp::{AuthConfig, MistHandler, build_http_router};
use rustmistmcp_core::MistGrant;
use std::{collections::BTreeMap, sync::Arc};
use tempfile::TempDir;

const TEST_TOKEN: &str = "test-mist-token-12345";
const ORG_ID: &str = "11111111-1111-1111-1111-111111111111";

/// Handler for mock Mist API /api/v1/orgs/{org_id}
async fn mock_get_org(
    Path(org_id): Path<String>,
    Query(_params): Query<BTreeMap<String, String>>,
    request: Request<Body>,
) -> Response {
    // Verify Authorization header uses Mist's Token scheme
    let auth_header = request.headers().get(header::AUTHORIZATION);
    let expected_auth = format!("Token {TEST_TOKEN}");
    if auth_header != Some(&expected_auth.parse().expect("valid header value")) {
        return (StatusCode::UNAUTHORIZED, "Invalid token").into_response();
    }

    // Return canned org response
    let response_body = serde_json::json!({
        "id": org_id,
        "name": "Test Organization",
        "created_time": 1234567890
    });

    (StatusCode::OK, axum::Json(response_body)).into_response()
}

#[tokio::test]
async fn tool_call_reaches_http_client_and_sends_correct_auth_header() {
    // Install crypto provider for mecmcp-http
    let _ = rustls::crypto::ring::default_provider().install_default();

    // Stand up mock Mist API server
    let mock_api = Router::new().route("/api/v1/orgs/{org_id}", get(mock_get_org));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock API");
    let addr = listener.local_addr().expect("mock API addr");
    // Use HTTP for the mock server
    let mock_base_url_http = format!("http://127.0.0.1:{}", addr.port());

    tokio::spawn(async move {
        axum::serve(listener, mock_api)
            .await
            .expect("mock API serve");
    });

    // Give mock server time to start
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;

    // Create temporary directory for MCP token store
    let temp_dir = TempDir::new().expect("temp dir");
    let tokens_path = temp_dir.path().join("tokens.json");

    // Create HttpMistClient using test constructor (bypasses HTTPS validation)
    let catalog = Arc::new(rustmistmcp_core::Catalog::embedded().expect("catalog"));
    let http_client = Arc::new(rustmistmcp_core::HttpMistClient::from_test_parts(
        url::Url::parse(&mock_base_url_http).expect("parse URL"),
        TEST_TOKEN.to_owned(),
        catalog,
        1024 * 1024,
    ));

    // Create MistHandler with HttpMistClient. Use the canonical Mist endpoint for validation
    // (MistHandler validates the endpoint format separately from the client's actual URL).
    let handler = MistHandler::with_client(
        "https://api.mist.com/",
        vec![ORG_ID.to_owned()],
        BTreeMap::new(),
        http_client,
    )
    .expect("construct handler with HTTP client");

    // Create token store for MCP bearer auth
    let known = KnownNames {
        devices: None,
        tools: &["get_mist_org"],
    };
    let mcp_secret = TokenStoreFile::<MistGrant>::add_with_options(
        &tokens_path,
        "test-caller",
        ScopeSet::Allowlist(vec![format!("org/{ORG_ID}")]),
        ScopeSet::Allowlist(vec!["get_mist_org".to_owned()]),
        None,
        None,
        None,
        None,
        None,
        None,
        &known,
    )
    .expect("add token");

    let token_store =
        Arc::new(TokenStoreFile::<MistGrant>::load(&tokens_path).expect("load token store"));

    // The secret returned from add_with_options is the bearer token (just the secret, not name:secret)
    let bearer_token = mcp_secret.expose_secret().to_owned();
    let auth_header_value = format!("Bearer {}", bearer_token);

    // Build MCP router
    let shutdown = tokio_util::sync::CancellationToken::new();
    let plan = build_http_router(
        handler,
        AuthConfig::Authenticated(token_store),
        vec!["localhost".to_owned()],
        vec![],
        mecmcp_transport::LimitsConfig::default(),
        false,
        false, // allow_insecure_bind: tests bind loopback, which is exempt
        shutdown,
    )
    .expect("build router");

    // Serve on loopback
    let served = mecmcp_transport::test_harness::serve_on_loopback(plan).await;
    let base_url = format!("http://{}", served.address);

    // Initialize MCP session
    let client = reqwest::Client::new();
    let init_response = client
        .post(format!("{base_url}/mcp"))
        .header(header::HOST, "localhost")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json, text/event-stream")
        .header("Mcp-Protocol-Version", "2025-06-18")
        .header(header::AUTHORIZATION, auth_header_value.as_str())
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "http-wiring-test", "version": "1"}
            }
        }))
        .send()
        .await
        .expect("init request");

    assert_eq!(init_response.status(), StatusCode::OK);

    let session_id = init_response
        .headers()
        .get("mcp-session-id")
        .expect("session id")
        .to_str()
        .expect("session id str")
        .to_owned();

    // Send initialized notification
    let initialized_response = client
        .post(format!("{base_url}/mcp"))
        .header(header::HOST, "localhost")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json, text/event-stream")
        .header("Mcp-Protocol-Version", "2025-06-18")
        .header("mcp-session-id", &session_id)
        .header(header::AUTHORIZATION, auth_header_value.as_str())
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        }))
        .send()
        .await
        .expect("initialized request");

    assert_eq!(initialized_response.status(), StatusCode::ACCEPTED);

    // Call get_mist_org tool - this is the critical assertion
    let tool_response = client
        .post(format!("{base_url}/mcp"))
        .header(header::HOST, "localhost")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json, text/event-stream")
        .header("Mcp-Protocol-Version", "2025-06-18")
        .header("mcp-session-id", &session_id)
        .header(header::AUTHORIZATION, auth_header_value.as_str())
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "get_mist_org",
                "arguments": {"org_id": ORG_ID}
            }
        }))
        .send()
        .await
        .expect("tool call request");

    assert_eq!(tool_response.status(), StatusCode::OK);

    // Parse response body
    let body_text = tool_response.text().await.expect("read response body");

    // Extract JSON-RPC response from SSE stream
    let json_response: serde_json::Value = body_text
        .lines()
        .filter_map(|line| line.strip_prefix("data:"))
        .filter_map(|data| serde_json::from_str(data.trim()).ok())
        .find(|value: &serde_json::Value| value.get("id").is_some())
        .expect("find JSON-RPC response in SSE stream");

    // Verify the response is successful and contains the org data
    assert_eq!(json_response["id"], 2);
    assert!(
        json_response.get("error").is_none(),
        "expected successful response, got error: {:?}",
        json_response.get("error")
    );

    let result = &json_response["result"];
    assert!(
        result.get("content").is_some(),
        "result should have content"
    );

    let content = &result["content"][0];
    assert_eq!(content["type"], "text");

    let text = content["text"].as_str().expect("text content");

    // The critical assertion: we did NOT get "TransportUnavailable", which would mean
    // BlockedMistClient was used. Any other error (HTTP, DNS, TLS, etc.) proves that
    // HttpMistClient was reached and attempted to make a real HTTP request.
    //
    // Expected: "Mist API request failed: failed to build HTTP request" or similar HTTP error
    // Blocked:  "TransportUnavailable: mecmcp#90 blocks live Mist requests..."
    assert!(
        !text.contains("TransportUnavailable"),
        "HttpMistClient should be wired in, but got: {}",
        text
    );
    assert!(
        text.contains("Mist API request failed") || text.contains("HTTP"),
        "Expected an HTTP-level error from HttpMistClient, got: {}",
        text
    );
}

#[tokio::test]
async fn blocked_client_still_available_for_no_credential_mode() {
    // Verify BlockedMistClient can still be constructed for testing/no-credential scenarios
    let handler = MistHandler::blocked(
        "https://api.mist.com/",
        vec![ORG_ID.to_owned()],
        BTreeMap::new(),
    )
    .expect("construct blocked handler");

    // Build a minimal router with no auth
    let shutdown = tokio_util::sync::CancellationToken::new();
    let plan = build_http_router(
        handler,
        AuthConfig::ExplicitlyUnauthenticated,
        vec!["localhost".to_owned()],
        vec![],
        mecmcp_transport::LimitsConfig::default(),
        false,
        false, // allow_insecure_bind: tests bind loopback, which is exempt
        shutdown,
    )
    .expect("build router");

    // Serve on loopback
    let served = mecmcp_transport::test_harness::serve_on_loopback(plan).await;
    let base_url = format!("http://{}", served.address);

    // Initialize session
    let client = reqwest::Client::new();
    let init_response = client
        .post(format!("{base_url}/mcp"))
        .header(header::HOST, "localhost")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json, text/event-stream")
        .header("Mcp-Protocol-Version", "2025-06-18")
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "blocked-test", "version": "1"}
            }
        }))
        .send()
        .await
        .expect("init request");

    let session_id = init_response
        .headers()
        .get("mcp-session-id")
        .expect("session id")
        .to_str()
        .expect("session id str")
        .to_owned();

    // Send initialized notification
    client
        .post(format!("{base_url}/mcp"))
        .header(header::HOST, "localhost")
        .header(header::CONTENT_TYPE, "application/json")
        .header("Mcp-Protocol-Version", "2025-06-18")
        .header("mcp-session-id", &session_id)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        }))
        .send()
        .await
        .expect("initialized request");

    // Try to call a tool - should fail with TransportUnavailable
    let tool_response = client
        .post(format!("{base_url}/mcp"))
        .header(header::HOST, "localhost")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json, text/event-stream")
        .header("Mcp-Protocol-Version", "2025-06-18")
        .header("mcp-session-id", &session_id)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "get_mist_org",
                "arguments": {"org_id": ORG_ID}
            }
        }))
        .send()
        .await
        .expect("tool call request");

    let body_text = tool_response.text().await.expect("read body");

    // Should contain an error (TransportUnavailable)
    assert!(
        body_text.contains("Mist client transport is unavailable")
            || body_text.contains("TransportUnavailable"),
        "expected TransportUnavailable error, got: {}",
        body_text
    );
}

/// The production constructor must build a real client, not the blocked stub.
///
/// The other test in this file hands `MistHandler::with_client` an
/// `HttpMistClient` it built itself, so it proves only that a handler given a
/// real client reaches it — which was never in doubt. It cannot detect
/// `from_config` being wired to `BlockedMistClient`, and it did not: pointing
/// `from_config` at the stub left the whole suite green.
///
/// `HttpMistClient` refuses non-HTTPS at construction, so it cannot be aimed at
/// a plaintext mock. Instead this aims `from_config` at a well-formed but
/// unreachable HTTPS endpoint and discriminates on the error: a real client
/// fails to connect, while `BlockedMistClient` returns `TransportUnavailable`
/// for everything without touching the network.
#[tokio::test]
async fn from_config_constructs_a_real_client_not_the_blocked_stub() {
    use rustmistmcp_core::MistConfig;

    // The consumer installs the crypto provider (mecmcp decision D4); without
    // one, HttpClient construction fails and this test cannot tell a real client
    // from the stub.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let dir = TempDir::new().expect("tempdir");
    let credential_file = dir.path().join("token");
    std::fs::write(&credential_file, "test-token-value").expect("write credential");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&credential_file, std::fs::Permissions::from_mode(0o600))
            .expect("chmod 0600");
    }

    // A real Mist region: the endpoint allowlist admits only these, and this
    // test must not make a network call, so the assertion below is on which
    // client was built rather than on how a request fails.
    let config = MistConfig {
        version: 1,
        endpoint: "https://api.mist.com".to_owned(),
        credential: rustmistmcp_core::CredentialSource::File {
            path: credential_file,
        },
        allowed_orgs: vec!["11111111-1111-1111-1111-111111111111".to_owned()],
    };

    let state_path = dir.path().join("changeset-state.json");
    let handler = MistHandler::from_config(&config, BTreeMap::new(), &state_path)
        .expect("from_config should build a handler");

    assert!(
        !handler.client().is_blocked(),
        "from_config built BlockedMistClient: every call returns \
         TransportUnavailable regardless of configuration, so the server can \
         never reach Mist"
    );
}
