//! MEC-408: the human-approver gate over HTTP.
//!
//! A change set must not be committable until a human approver echoes back
//! the exact plan digest. These drive `approve_mist_change_set` /
//! `apply_mist_change_set` over the real HTTP transport with two distinct
//! bearer-token principals -- one whose token entry declares
//! `actor_type: human`, one that declares `actor_type: agent` -- because the
//! gate mecmcp enforces (`ChangesetCoordinator::approve_change_set` refusing
//! anything but `mecmcp_audit::ActorType::Human`) only has teeth when the
//! caller identity is server-verified, which stdio never provides.

use async_trait::async_trait;
use axum::http::StatusCode;
use mecmcp_auth::{ActorType, KnownNames, ScopeSet, TokenStoreFile};
use mecmcp_transport::LimitsConfig;
use rustmistmcp::{AuthConfig, KNOWN_TOOLS, MistHandler, build_http_router};
use rustmistmcp_core::{
    MistClient, MistError, MistGrant, MistRequest, MistResponse, MistResponseBody,
};
use std::{collections::BTreeMap, sync::Arc};

const ORG_ID: &str = "11111111-1111-1111-1111-111111111111";
const SITE_ID: &str = "22222222-2222-2222-2222-222222222222";
const NETWORK_ID: &str = "33333333-3333-3333-3333-333333333333";

fn site_map() -> BTreeMap<String, String> {
    BTreeMap::from([(SITE_ID.to_owned(), ORG_ID.to_owned())])
}

/// Answers every read with a fixed object and records nothing that matters here.
struct ScriptedClient {
    object: serde_json::Value,
}

#[async_trait]
impl MistClient for ScriptedClient {
    async fn execute(&self, request: MistRequest) -> Result<MistResponse, MistError> {
        Ok(MistResponse {
            operation_id: request.operation_id,
            status: 200,
            body: MistResponseBody::Json(self.object.clone()),
            cursor: None,
            page: None,
        })
    }
}

fn handler() -> MistHandler {
    let recorder = Arc::new(ScriptedClient {
        object: serde_json::json!({"id": NETWORK_ID, "name": "branch", "vlan_id": 10}),
    });
    MistHandler::with_client(
        "https://api.mist.com/",
        vec![ORG_ID.to_owned()],
        site_map(),
        recorder,
    )
    .expect("handler")
}

/// The write tools this suite exercises. All are in `RESTRICTED_TOOLS`, so a
/// wildcard tools scope would exclude them (see
/// `runtime_contract::wildcard_tool_scope_excludes_restricted_reads_at_preflight`);
/// each token needs them named explicitly.
const WRITE_TOOLS: &[&str] = &[
    "plan_mist_change",
    "approve_mist_change_set",
    "apply_mist_change_set",
    "get_mist_change_set",
];

/// Add a bearer token whose entry declares `actor_type`, mirroring
/// `mecmcp_auth::TokenStoreFile::add_with_options` used elsewhere in this
/// suite for grant-bearing tokens. Devices scope is wildcard: none of these
/// tools' arguments carry `org_id`/`site_id` for `MistScopePreflight` to key
/// on (they address change sets by `object`/`object_id`), so the tools scope
/// is what matters.
fn add_token(
    path: &std::path::Path,
    name: &str,
    actor_type: Option<ActorType>,
) -> mecmcp_auth::TokenSecret {
    let known = KnownNames {
        devices: None,
        tools: KNOWN_TOOLS,
    };
    TokenStoreFile::<MistGrant>::add_with_options(
        path,
        name,
        ScopeSet::Allowlist(vec![format!("org/{ORG_ID}")]),
        ScopeSet::Allowlist(WRITE_TOOLS.iter().map(|s| (*s).to_owned()).collect()),
        None,
        None,
        None,
        None,
        None,
        actor_type,
        None,
        &known,
    )
    .expect("token")
}

async fn post_mcp(
    client: &reqwest::Client,
    base_url: &str,
    secret: &mecmcp_auth::TokenSecret,
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
        .header("Mcp-Protocol-Version", "2025-06-18")
        .header(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {}", secret.expose_secret()),
        );
    if let Some(session) = session {
        request = request.header("mcp-session-id", session);
    }
    request.json(&body).send().await.expect("request")
}

async fn response_json(response: reqwest::Response) -> serde_json::Value {
    let text = response.text().await.expect("response body");
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) {
        return value;
    }
    text.lines()
        .filter_map(|line| line.strip_prefix("data:"))
        .filter_map(|data| serde_json::from_str(data.trim()).ok())
        .find(|value: &serde_json::Value| value.get("id").is_some())
        .unwrap_or_else(|| panic!("missing JSON-RPC response in {text}"))
}

/// Initialize an authenticated MCP session for one bearer-token principal.
/// Each principal gets its own session, matching how a real client would
/// authenticate: the token is presented on every request, including
/// `initialize`.
async fn initialize_session(
    client: &reqwest::Client,
    base_url: &str,
    secret: &mecmcp_auth::TokenSecret,
) -> String {
    let response = post_mcp(
        client,
        base_url,
        secret,
        None,
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 0,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "approver-gate-test", "version": "1"}
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
    response_json(response).await;

    let notification = post_mcp(
        client,
        base_url,
        secret,
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

/// Call a tool and return its parsed JSON envelope, or the error text if the
/// tool call failed.
async fn call_tool(
    client: &reqwest::Client,
    base_url: &str,
    secret: &mecmcp_auth::TokenSecret,
    session: &str,
    id: i64,
    tool: &str,
    arguments: serde_json::Value,
) -> Result<serde_json::Value, String> {
    let response = response_json(
        post_mcp(
            client,
            base_url,
            secret,
            Some(session),
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": id,
                "method": "tools/call",
                "params": {"name": tool, "arguments": arguments}
            }),
        )
        .await,
    )
    .await;
    let result = &response["result"];
    if result["isError"] == true {
        return Err(result.to_string());
    }
    let text = result["content"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("missing text content in {response}"));
    Ok(serde_json::from_str(text).expect("JSON envelope"))
}

/// One principal's bearer secret plus its own authenticated MCP session.
struct Principal {
    secret: mecmcp_auth::TokenSecret,
    session: String,
}

/// Stand up the server with three principals: `owner` plans, `human-approver`
/// carries `actor_type: human`, `agent-approver` carries `actor_type: agent`.
/// Returns `(base_url, client, owner, human, agent)`.
async fn serve_with_principals() -> (String, reqwest::Client, Principal, Principal, Principal) {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("tokens.json");
    let owner_secret = add_token(&path, "owner", None);
    let human_secret = add_token(&path, "human-approver", Some(ActorType::Human));
    let agent_secret = add_token(&path, "agent-approver", Some(ActorType::Agent));
    let store = Arc::new(TokenStoreFile::<MistGrant>::load(&path).expect("token store"));

    let shutdown = tokio_util::sync::CancellationToken::new();
    let plan = build_http_router(
        handler(),
        AuthConfig::Authenticated(store),
        Vec::new(),
        Vec::new(),
        LimitsConfig::default(),
        false,
        false,
        shutdown,
    )
    .expect("HTTP router");
    let served = mecmcp_transport::test_harness::serve_on_loopback(plan).await;
    let base_url = format!("http://{}", served.address);
    // Keep the listener alive for the caller's lifetime.
    std::mem::forget(served);

    let client = reqwest::Client::new();
    let owner_session = initialize_session(&client, &base_url, &owner_secret).await;
    let human_session = initialize_session(&client, &base_url, &human_secret).await;
    let agent_session = initialize_session(&client, &base_url, &agent_secret).await;

    (
        base_url,
        client,
        Principal {
            secret: owner_secret,
            session: owner_session,
        },
        Principal {
            secret: human_secret,
            session: human_session,
        },
        Principal {
            secret: agent_secret,
            session: agent_session,
        },
    )
}

async fn plan_change(
    client: &reqwest::Client,
    base_url: &str,
    owner: &Principal,
) -> (String, String) {
    let planned = call_tool(
        client,
        base_url,
        &owner.secret,
        &owner.session,
        1,
        "plan_mist_change",
        serde_json::json!({
            "object": "network", "verb": "update", "org_id": ORG_ID,
            "object_id": NETWORK_ID, "patch": {"vlan_id": 20}
        }),
    )
    .await
    .expect("plan");
    (
        planned["change_set_id"].as_str().expect("id").to_owned(),
        planned["plan_digest"].as_str().expect("digest").to_owned(),
    )
}

/// The commit path (apply) must fail when nobody has approved -- the plainest
/// form of "not committable without a human approver".
#[tokio::test]
async fn a_change_set_cannot_be_applied_without_approval() {
    let (base_url, client, owner, _human, _agent) = serve_with_principals().await;
    let (change_set_id, _digest) = plan_change(&client, &base_url, &owner).await;

    let applied = call_tool(
        &client,
        &base_url,
        &owner.secret,
        &owner.session,
        2,
        "apply_mist_change_set",
        serde_json::json!({
            "change_set_id": change_set_id, "object": "network", "object_id": NETWORK_ID
        }),
    )
    .await;
    assert!(
        applied.is_err(),
        "apply must refuse an unapproved change set"
    );
}

/// An approver whose token declares `actor_type: agent` cannot satisfy the
/// gate -- mecmcp's house rule is that a human approves, and an agent (or an
/// unattributed caller) must not be able to stand in as the second principal.
#[tokio::test]
async fn an_agent_actor_cannot_approve_a_change_set() {
    let (base_url, client, owner, _human, agent) = serve_with_principals().await;
    let (change_set_id, plan_digest) = plan_change(&client, &base_url, &owner).await;

    let approved = call_tool(
        &client,
        &base_url,
        &agent.secret,
        &agent.session,
        2,
        "approve_mist_change_set",
        serde_json::json!({
            "change_set_id": change_set_id, "plan_digest": plan_digest,
            "object": "network", "object_id": NETWORK_ID
        }),
    )
    .await;
    assert!(
        approved.is_err(),
        "an agent-actor-type approver must be refused"
    );

    let applied = call_tool(
        &client,
        &base_url,
        &owner.secret,
        &owner.session,
        3,
        "apply_mist_change_set",
        serde_json::json!({
            "change_set_id": change_set_id, "object": "network", "object_id": NETWORK_ID
        }),
    )
    .await;
    assert!(
        applied.is_err(),
        "apply must still refuse after a refused approval attempt"
    );
}

/// A human approver who echoes the WRONG plan digest is refused -- approval
/// is bound to the exact plan, not merely to a human clicking approve.
#[tokio::test]
async fn a_human_approver_echoing_the_wrong_digest_is_refused() {
    let (base_url, client, owner, human, _agent) = serve_with_principals().await;
    let (change_set_id, plan_digest) = plan_change(&client, &base_url, &owner).await;
    let wrong_digest = format!(
        "sha256:{}",
        "0".repeat(plan_digest.trim_start_matches("sha256:").len())
    );

    let approved = call_tool(
        &client,
        &base_url,
        &human.secret,
        &human.session,
        2,
        "approve_mist_change_set",
        serde_json::json!({
            "change_set_id": change_set_id, "plan_digest": wrong_digest,
            "object": "network", "object_id": NETWORK_ID
        }),
    )
    .await;
    assert!(
        approved.is_err(),
        "a mismatched plan digest must be refused"
    );
}

/// The success path: a human approver echoes back the exact plan digest, the
/// change set moves to approved, and apply then succeeds.
#[tokio::test]
async fn a_human_approver_echoing_the_correct_digest_lets_the_change_set_commit() {
    let (base_url, client, owner, human, _agent) = serve_with_principals().await;
    let (change_set_id, plan_digest) = plan_change(&client, &base_url, &owner).await;

    let approved = call_tool(
        &client,
        &base_url,
        &human.secret,
        &human.session,
        2,
        "approve_mist_change_set",
        serde_json::json!({
            "change_set_id": change_set_id, "plan_digest": plan_digest,
            "object": "network", "object_id": NETWORK_ID
        }),
    )
    .await
    .expect("a human approver echoing the correct digest must succeed");
    assert_eq!(approved["state"], "approved");

    let applied = call_tool(
        &client,
        &base_url,
        &owner.secret,
        &owner.session,
        3,
        "apply_mist_change_set",
        serde_json::json!({
            "change_set_id": change_set_id, "object": "network", "object_id": NETWORK_ID
        }),
    )
    .await
    .expect("apply must succeed once a human approver has echoed the digest");
    assert_ne!(applied["state"], serde_json::Value::Null, "{applied}");
}
